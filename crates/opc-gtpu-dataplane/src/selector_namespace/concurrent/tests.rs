use super::*;
use crate::selector_namespace::tests::{group, group_with_paa, worker_lease};

async fn pending_once<F: Future>(mut future: Pin<&mut F>) -> bool {
    std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await
}

#[tokio::test]
async fn conflicts_cover_group_parent_paa_and_teid_without_blocking_disjoint_groups() {
    let pool = LeasePool::default();
    let parent = group(1, 1, 0x1001, None);
    let held_groups = [parent.clone()];
    let held = pool.reserve_groups(&held_groups).await.unwrap();
    let child = group_with_paa(
        3,
        1,
        0x2001,
        parent.entries()[0].context().ms_address,
        Some(6),
    );
    let overlap = group(4, 1, 0x1001, None);
    let changed_group = group(1, 1, 0x3001, None);
    for candidate in [child, overlap, changed_group] {
        let candidates = [candidate];
        let mut reservation = Box::pin(pool.reserve_groups(&candidates));
        assert!(pending_once(reservation.as_mut()).await);
    }
    let other_groups = [group(2, 1, 0x4001, None)];
    let other = pool.reserve_groups(&other_groups).await.unwrap();
    drop(other);
    drop(held);
    let _next = pool.reserve_groups(&held_groups).await.unwrap();
}

#[tokio::test]
async fn shared_renewal_waits_for_the_exact_credential_in_a_durable_cas() {
    // With this supported TTL, a full five-second backend window requires
    // renewal. The real SQLite store checks the exact guard expiry at CAS.
    let (authority, backend) = worker_lease::provisioned_authority(Duration::from_secs(10)).await;
    let pool = LeasePool::default();
    let shared = pool.join(&authority).await.unwrap();
    let operation = Arc::new(ConcurrentOperation::new(Arc::clone(&shared)));
    let mut worker = authority.clone();
    worker.concurrent_operation = Some(Arc::clone(&operation));
    let mut writer_lease = worker.acquire_worker_lease().await.unwrap();
    let mut window_lease = worker.acquire_worker_lease().await.unwrap();
    let (record, state) = worker.read_state().await.unwrap();
    backend.hold_cas.store(true, Ordering::SeqCst);
    let mut write = Box::pin(worker.replace_with_lease(record.as_ref(), state, &mut writer_lease));
    tokio::select! {
        () = backend.cas_entered.notified() => {},
        result = &mut write => panic!("write escaped its durable gate: {result:?}"),
    }
    let mut window = Box::pin(worker.mint_backend_mutation_window(&mut window_lease));
    let progress = tokio::time::timeout(Duration::from_secs(1), &mut window).await;
    let renewed_before_cas = progress.is_ok();
    backend.cas_release.notify_one();
    let committed = write.await;
    let window = match progress {
        Ok(result) => result,
        Err(_) => window.await,
    };
    operation.settled();
    let released = pool.leave(&authority, &shared).await;
    assert!(released.is_ok());
    assert!(window.is_ok());
    assert_eq!(
        committed,
        Ok(true),
        "renewal must not invalidate an in-flight fenced write"
    );
    assert!(
        !renewed_before_cas,
        "exact credential renewal must follow durable CAS settlement"
    );
}

#[tokio::test]
async fn overlapping_members_acquire_once_and_only_the_last_member_releases() {
    let (authority, backend) = worker_lease::authority(Duration::from_secs(30)).await;
    let pool = LeasePool::default();
    let acquisitions = backend.acquisitions.load(Ordering::SeqCst);
    let releases = backend.releases.load(Ordering::SeqCst);
    let first = pool.join(&authority).await.unwrap();
    let second = pool.join(&authority).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(
        backend.acquisitions.load(Ordering::SeqCst) - acquisitions,
        1
    );
    pool.leave(&authority, &first).await.unwrap();
    assert_eq!(backend.releases.load(Ordering::SeqCst), releases);
    pool.leave(&authority, &second).await.unwrap();
    assert_eq!(backend.releases.load(Ordering::SeqCst) - releases, 1);
    drop((first, second));
    let next = pool.join(&authority).await.unwrap();
    assert_eq!(
        backend.acquisitions.load(Ordering::SeqCst) - acquisitions,
        2
    );
    pool.leave(&authority, &next).await.unwrap();
}

#[tokio::test]
async fn uncertain_renewal_fences_every_member_without_retrying_the_credential() {
    let (authority, backend) = worker_lease::authority(Duration::from_secs(10)).await;
    let pool = LeasePool::default();
    let shared = pool.join(&authority).await.unwrap();
    let operation = Arc::new(ConcurrentOperation::new(Arc::clone(&shared)));
    let mut worker = authority.clone();
    worker.concurrent_operation = Some(Arc::clone(&operation));
    let mut first = worker.acquire_worker_lease().await.unwrap();
    let mut second = worker.acquire_worker_lease().await.unwrap();
    backend.reject_renewal.store(true, Ordering::SeqCst);
    assert!(worker
        .mint_backend_mutation_window(&mut first)
        .await
        .is_err());
    backend.reject_renewal.store(false, Ordering::SeqCst);
    assert!(worker
        .mint_backend_mutation_window(&mut second)
        .await
        .is_err());
    assert!(worker.acquire_worker_lease().await.is_err());
    assert_eq!(backend.renewals.load(Ordering::SeqCst), 1);
    assert!(shared.lease.lock().await.as_ref().unwrap().timing.is_none());
    operation.settled();
    pool.leave(&authority, &shared).await.unwrap();
}

#[tokio::test]
async fn clock_ambiguity_permanently_invalidates_the_shared_timing() {
    let (authority, _) = worker_lease::authority(Duration::from_secs(30)).await;
    let pool = LeasePool::default();
    let shared = pool.join(&authority).await.unwrap();
    shared
        .lease
        .lock()
        .await
        .as_mut()
        .unwrap()
        .timing
        .as_mut()
        .unwrap()
        .requested_wall = SystemTime::now() + Duration::from_secs(1);
    assert!(shared.check_current().await.is_err());
    assert!(shared.lease.lock().await.as_ref().unwrap().timing.is_none());
    assert!(shared.check_current().await.is_err());
    pool.leave(&authority, &shared).await.unwrap();
}

#[tokio::test]
async fn last_member_release_failure_cannot_report_success() {
    let (authority, backend) = worker_lease::authority(Duration::from_secs(30)).await;
    let concurrent = authority.concurrent_operations();
    backend.reject_release.store(true, Ordering::SeqCst);
    let result = concurrent
        .spawn(vec![group(1, 1, 10, None)], |_| async { Ok(()) })
        .await;
    assert_eq!(result, Err(GtpuSessionSelectorCoordinatorError::Namespace));
    backend.reject_release.store(false, Ordering::SeqCst);
    // Every worker settled before the failed release. A new credential may
    // therefore be acquired; the failed result never became success.
    concurrent
        .spawn(vec![group(1, 1, 10, None)], |_| async { Ok(()) })
        .await
        .unwrap();
}

#[tokio::test]
async fn abandoned_cohort_acquisition_retains_the_exclusive_worker_gate() {
    let (mut authority, backend) = worker_lease::authority(Duration::from_secs(30)).await;
    // Isolate this intentional process-recovery quarantine from other tests.
    authority.storage_scope_commitment = [0xf1; 32];
    let gate = selector_namespace_worker(authority.storage_scope_commitment);
    let pool = LeasePool::default();
    backend.hold_acquire.store(true, Ordering::SeqCst);
    let mut join = Box::pin(pool.join(&authority));
    tokio::select! {
        () = backend.acquire_entered.notified() => {},
        result = &mut join => assert!(result.is_err(), "acquire escaped its acknowledgement gate"),
    }
    drop(join);
    assert_eq!(
        gate.available_permits(),
        0,
        "an abandoned acquire cannot authorize a replacement credential"
    );
}

#[tokio::test]
async fn abandoned_cohort_release_invalidates_ownership_before_any_next_member() {
    let (mut authority, backend) = worker_lease::authority(Duration::from_secs(30)).await;
    authority.storage_scope_commitment = [0xf2; 32];
    let concurrent = authority.concurrent_operations();
    backend.panic_release.store(true, Ordering::SeqCst);
    let result = concurrent
        .spawn(vec![group(1, 1, 10, None)], |_| async { Ok(()) })
        .await;
    assert_eq!(result, Err(GtpuSessionSelectorCoordinatorError::Backend));
    let state = concurrent.pool.lifecycle.lock().await;
    assert!(
        state.as_ref().unwrap().0.is_abandoned(),
        "unexpected release destruction must quarantine the cohort"
    );
}

fn installing_expectation() -> SelectorOperationStampInventoryExpectation {
    SelectorOperationStampInventoryExpectation {
        group: group(1, 1, 10, None),
        device_fingerprint: [1; 32],
        group_fingerprint: [2; 32],
        selector_set_fingerprint: [3; 32],
        desired_fingerprint: [4; 32],
        lifecycle: SelectorOperationStampLifecycleExpectation::Installing {
            pending: SelectorOperationStampCoordinate {
                generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(1).unwrap()),
                nonce: [5; 16],
            },
            terminal: SelectorOperationStampCoordinate {
                generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(2).unwrap()),
                nonce: [6; 16],
            },
            backend_started: true,
        },
        in_flight: None,
    }
}

fn proof_for(expected: &SelectorOperationStampInventoryExpectation) -> Arc<InFlightInstall> {
    let SelectorOperationStampLifecycleExpectation::Installing {
        pending, terminal, ..
    } = expected.lifecycle
    else {
        panic!("expected pending install");
    };
    Arc::new(InFlightInstall {
        live: AtomicBool::new(true),
        group: expected.group_fingerprint,
        device: expected.device_fingerprint,
        selectors: expected.selector_set_fingerprint,
        desired: expected.desired_fingerprint,
        pending,
        terminal,
    })
}

#[test]
fn absent_install_proof_is_exact_live_and_cannot_hide_a_settled_or_present_group() {
    let mut installing = installing_expectation();
    let proof = proof_for(&installing);
    installing.in_flight = Some(Arc::clone(&proof));
    let mut settled = installing.clone();
    settled.group = group(2, 1, 20, None);
    settled.group_fingerprint = [7; 32];
    settled.in_flight = None;
    settled.lifecycle = SelectorOperationStampLifecycleExpectation::Active {
        terminal: proof.terminal,
    };
    let inventory = SelectorOperationStampInventory {
        expectations: vec![installing.clone(), settled],
        summary: [8; 32],
    };
    let projected = inventory.concurrent_projection(&BTreeSet::new()).unwrap();
    assert_eq!(
        projected.expectations.len(),
        1,
        "missing settled authority must remain required"
    );
    let observed = BTreeSet::from([installing.group.id().to_bytes()]);
    assert_eq!(
        inventory
            .concurrent_projection(&observed)
            .unwrap()
            .expectations
            .len(),
        2,
        "present stamps still require the original exact validator"
    );
    for field in 0..8 {
        let mut wrong = installing.clone();
        match field {
            0 => wrong.group_fingerprint[0] ^= 1,
            1 => wrong.device_fingerprint[0] ^= 1,
            2 => wrong.selector_set_fingerprint[0] ^= 1,
            3 => wrong.desired_fingerprint[0] ^= 1,
            _ => {
                let SelectorOperationStampLifecycleExpectation::Installing {
                    pending,
                    terminal,
                    ..
                } = &mut wrong.lifecycle
                else {
                    unreachable!()
                };
                match field {
                    4 => {
                        pending.generation =
                            GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(3).unwrap())
                    }
                    5 => pending.nonce[0] ^= 1,
                    6 => {
                        terminal.generation =
                            GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(3).unwrap())
                    }
                    _ => terminal.nonce[0] ^= 1,
                }
            }
        }
        assert!(!proof.matches(&wrong));
    }
    proof.live.store(false, Ordering::Release);
    assert!(!inventory.concurrent_proofs_are_current());
    assert!(inventory.concurrent_projection(&BTreeSet::new()).is_none());
}

#[test]
fn only_started_unsettled_concurrent_supervisors_quarantine_their_bounded_slots() {
    for (concurrent, started, terminal, retained) in [
        (false, true, false, false),
        (true, false, false, false),
        (true, true, true, false),
        (true, true, false, true),
    ] {
        let process = Arc::new(tokio::sync::Semaphore::new(1));
        let namespace = Arc::new(tokio::sync::Semaphore::new(1));
        drop(SelectorSupervisorSlots {
            process: Some(Arc::clone(&process).try_acquire_owned().unwrap()),
            namespace: Some(Arc::clone(&namespace).try_acquire_owned().unwrap()),
            worker: None,
            started,
            terminal,
            quarantine_on_abnormal: concurrent,
        });
        assert_eq!(process.available_permits(), usize::from(!retained));
        assert_eq!(namespace.available_permits(), usize::from(!retained));
    }
}
