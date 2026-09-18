//! Independent evidence about authority missing from retained Async roots.
//! These controls never open the quarantine gate or manufacture a Raft reply.

use super::*;

async fn lost_majority_authority(all_cold: bool) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let faults = (0..3)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect::<Vec<_>>();
    let result = AssertUnwindSafe(exercise_lost_authority(&mut fleet, &faults, all_cold))
        .catch_unwind()
        .await;
    for index in 0..3 {
        let _ = fleet.close_result(index).await;
    }
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

async fn exercise_lost_authority(fleet: &mut Fleet, faults: &[Arc<AtomicBool>], all_cold: bool) {
    for (index, fault) in faults.iter().enumerate() {
        let fault = Arc::clone(fault);
        fleet
            .open_with_hook(
                index,
                SessionPersistenceMode::Async,
                Some(Arc::new(move || {
                    if fault.load(Ordering::Acquire) {
                        Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
                    } else {
                        Ok(())
                    }
                })),
            )
            .await
            .unwrap();
    }
    fleet.form().await;
    let leader = fleet.leader();
    let survivor = (leader + 1) % 3;
    let majority = [leader, (leader + 2) % 3];
    let provider = provider();
    let request = create_request(fleet.store(leader), 91, &provider).await;
    let outcome = create(fleet.store(leader), &request).await;
    let FencedTransitionMutation::Create { record } = request.mutation() else {
        panic!("synthetic create fixture");
    };
    let key = record.key.clone();
    let owner = record.owner.clone();
    let old = outcome.lease().clone();
    for store in fleet.stores.iter().flatten() {
        assert_recorded(store, &request, &outcome).await;
        store.drain_async_persistence().await.unwrap();
    }
    // Wait for the existing writer to finish its accepted responsibility
    // before injecting failure into the next ordinary generation.
    races::until(
        || {
            fleet.stores.iter().flatten().all(|store| {
                let progress = store.persistence_health().asynchronous.unwrap();
                progress.captured_generation.is_none()
                    && progress.completed_generation == progress.resident_generation
            })
        },
        "prior generations completed",
    )
    .await;
    for index in majority {
        fleet.set_link(index, survivor, false);
        fleet.set_link(survivor, index, false);
    }
    // Select a newer committed generation on the live majority before
    // losing the following tail. The isolated survivor keeps its
    // earlier prefix, so these retained roots actually differ.
    let mut other_key = key.clone();
    other_key.stable_id = Bytes::from_static(b"persisted-majority-prefix")
        .try_into()
        .unwrap();
    let persisted = fleet
        .store(leader)
        .acquire(&other_key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    races::until(
        || {
            majority.iter().all(|index| {
                fleet
                    .store(*index)
                    .inner
                    .private_wal
                    .as_ref()
                    .unwrap()
                    .with_native_read(|state| Ok(state.key_fence_for_test(&other_key)))
                    .unwrap()
                    == persisted.fence().get()
            })
        },
        "majority applied its newer persisted prefix",
    )
    .await;
    for index in majority {
        fleet.store(index).drain_async_persistence().await.unwrap();
    }
    races::until(
        || {
            majority.iter().all(|index| {
                let progress = fleet
                    .store(*index)
                    .persistence_health()
                    .asynchronous
                    .unwrap();
                progress.captured_generation.is_none()
                    && progress.completed_generation == progress.resident_generation
            })
        },
        "differing retained generations completed",
    )
    .await;
    for index in majority {
        faults[index].store(true, Ordering::Release);
    }
    let selected = majority.map(|index| fleet.selector(index));
    // The still-live majority grants increasing real leases while its
    // generation writers are unable to select any of that volatile tail.
    let mut issued = None;
    for _ in 0..8 {
        issued = Some(
            fleet
                .store(leader)
                .acquire(&key, owner.clone(), Duration::from_secs(60))
                .await
                .expect("actual quorum acknowledges the volatile lease"),
        );
    }
    let issued = issued.unwrap();
    assert!(issued.fence() > record.fence);
    assert!(
        fleet.store(leader).delete_fenced(&old).await.is_err(),
        "the acknowledged majority already revoked this predecessor credential"
    );
    races::until(
        || {
            majority.iter().all(|index| {
                fleet
                    .store(*index)
                    .persistence_health()
                    .asynchronous
                    .unwrap()
                    .background_failure
                    .is_some()
            })
        },
        "both majority generation writers report failure",
    )
    .await;
    let missing_fence = |store: &ConsensusSessionStore| {
        store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .with_native_read(|state| Ok(state.key_fence_for_test(&key)))
            .unwrap()
    };
    assert!(
        missing_fence(fleet.store(survivor)) < issued.fence().get(),
        "surviving process never observed the majority's acknowledged authority"
    );
    for (slot, index) in majority.iter().copied().enumerate() {
        assert!(
            fleet.selector(index) == selected[slot],
            "selected root did not advance"
        );
        assert!(
            fleet.close_result(index).await.is_err(),
            "failed drain still joins its owner"
        );
        assert!(
            fleet.selector(index) == selected[slot],
            "shutdown did not persist the tail"
        );
    }
    if all_cold {
        fleet.close(survivor).await;
    }
    for index in majority {
        fleet
            .open(index, SessionPersistenceMode::Async)
            .await
            .unwrap();
    }
    if all_cold {
        fleet
            .open(survivor, SessionPersistenceMode::Async)
            .await
            .unwrap();
    }
    for index in majority {
        fleet.set_link(index, survivor, true);
        fleet.set_link(survivor, index, true);
    }
    for (index, store) in fleet.stores.iter().flatten().enumerate() {
        let retained_other = store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .with_native_read(|state| Ok(state.key_fence_for_test(&other_key)))
            .unwrap();
        assert!(
            retained_other
                == if index == survivor {
                    0
                } else {
                    persisted.fence().get()
                },
            "retained generations differ across the isolated survivor and returning majority"
        );
        assert!(
            missing_fence(store) < issued.fence().get(),
            "no surviving resident or reopened root covers the issued external fence"
        );
        let (next_fence, next_credential) = store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .with_native_read(|state| Ok(state.authority_frontiers_for_test()))
            .unwrap();
        assert!(
            next_fence <= issued.fence().get(),
            "even the retained allocator frontier is not an issued-fence upper bound"
        );
        assert!(
            next_credential <= issued.credential_id(),
            "retained credential allocation cannot revoke the lost tail by incrementing once"
        );
        let retained = store
            .inner
            .private_wal
            .as_ref()
            .unwrap()
            .with_native_read(|state| Ok(state.retained_lease_for_test(&key)))
            .unwrap();
        assert!(
            retained.as_ref() == Some(&old),
            "retained state contains the exact predecessor credential revoked by the lost majority"
        );
    }
    assert!(
        issued.expires_at() > opc_types::Timestamp::now_utc(),
        "the unpersisted external credential is still unexpired"
    );
    // The current SDK correctly withholds authority. This is a safety
    // control proving missing recovery input, never an availability pass.
    for index in majority {
        assert_eq!(
            fleet.store(index).initialize_cluster().await,
            Err(ConsensusSessionStoreOpenError::RecoveryRequired)
        );
        assert!(fleet.store(index).delete_fenced(&issued).await.is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_lagging_survivor_and_retained_majority_lose_issued_fence_evidence() {
    lost_majority_authority(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_all_cold_retained_roots_lose_issued_fence_evidence() {
    lost_majority_authority(true).await;
}
