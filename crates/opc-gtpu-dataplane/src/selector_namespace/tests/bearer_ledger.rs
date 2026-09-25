//! Persisted child-profile bounds, corruption refusal and redaction.

use super::*;
use crate::testkit::GroupedGtpuDataplaneSimulation;
use opc_session_store::EncryptingSessionBackend;

mod concurrent_lifecycle;

type Protected = EncryptingSessionBackend<SqliteSessionBackend, opc_key::MemoryKeyProvider>;

struct Lab<B: SessionBackend + SessionLeaseManager = Protected> {
    authority: GtpuSessionSelectorNamespaceAuthority<B>,
    backend: Arc<GroupedGtpuDataplaneSimulation>,
    parent: GtpuSessionGroup,
    sibling: GtpuSessionGroup,
    child: GtpuSessionGroup,
}

async fn lab(capacity: usize) -> Lab {
    let tenant = TenantId::from_static("bearer-codec-fixture");
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("bearer-fixture-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x68; 32]),
    )
    .unwrap();
    let store = SessionStore::new(EncryptingSessionBackend::new(
        Arc::new(SqliteSessionBackend::in_memory().unwrap()),
        keys,
        "bearer-codec-fixture",
    ));
    lab_with_store(store, tenant, capacity).await
}

async fn lab_with_store<B>(store: SessionStore<B>, tenant: TenantId, capacity: usize) -> Lab<B>
where
    B: ProtectedSessionBackend + Send + Sync + 'static,
{
    let backend = Arc::new(GroupedGtpuDataplaneSimulation::new().unwrap());
    let parent = group(1, 1, 0x1001, None);
    let sibling = group(2, 1, 0x1002, None);
    let child = group_with_paa(
        3,
        1,
        0x1003,
        parent.entries()[0].context().ms_address,
        Some(6),
    );
    let device = backend
        .create_device_with_endpoints(
            crate::CreateGtpDeviceEndpointSetRequest::new(
                crate::CreateGtpDeviceRequest::new("bearer-codec"),
                parent.device_id(),
                crate::GtpuLocalEndpointSet::new(parent.entries()[0].local_outer_address(), None)
                    .unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let rebind = |group: GtpuSessionGroup| {
        let mut context = group.entries()[0].context().clone();
        context.link_ifindex = device.ifindex;
        GtpuSessionGroup::new(
            group.id(),
            group.device_id(),
            vec![GtpuSessionEntry::new(context, group.entries()[0].local_outer_address()).unwrap()],
        )
        .unwrap()
    };
    let parent = rebind(parent);
    let sibling = rebind(sibling);
    let child = rebind(child);
    let authority = GtpuSessionSelectorNamespaceAuthority::provision_protected(
        store,
        SelectorLedgerStorageScope::new(tenant, NetworkFunctionKind::from_static("epdg")),
        backend
            .selector_namespace_bootstrap(parent.device_id())
            .await
            .unwrap(),
        backend.clone(),
        OwnerId::new("bearer-codec-worker").unwrap(),
        SELECTOR_NAMESPACE_MAX_LEASE_TTL,
        capacity,
    )
    .await
    .unwrap();
    for group in [&parent, &sibling] {
        drop(
            authority
                .reconcile_fresh(backend.clone(), group.clone())
                .await
                .unwrap(),
        );
    }
    Lab {
        authority,
        backend,
        parent,
        sibling,
        child,
    }
}

#[tokio::test]
async fn bearer_admission_does_not_repeat_the_same_preflight_snapshot_read() {
    use std::sync::atomic::Ordering;

    let tenant = TenantId::from_static("bearer-read-budget");
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("bearer-read-budget-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x79; 32]),
    )
    .unwrap();
    let raw = Arc::new(super::worker_lease::RenewalBackend::new());
    let store = SessionStore::new(EncryptingSessionBackend::new(
        raw.clone(),
        keys,
        "bearer-read-budget",
    ));
    let lab = lab_with_store(store, tenant, 3).await;
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let reads_before = raw.reads.load(Ordering::SeqCst);
    let writes_before = raw.writes.load(Ordering::SeqCst);
    let child = lab
        .authority
        .reconcile_bearer(
            lab.backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone(),
        )
        .await
        .unwrap();
    let reads = raw.reads.load(Ordering::SeqCst) - reads_before;
    let writes = raw.writes.load(Ordering::SeqCst) - writes_before;
    // Admission, backend-start handoff and activation remain three separate
    // fenced writes, each with exact durable readback. Read amplification
    // excludes setup and explicit post-operation recovery.
    assert_eq!(writes, 3);
    drop(
        lab.authority
            .retire(lab.backend.clone(), child, lab.child)
            .await
            .unwrap(),
    );
    drop(
        lab.authority
            .recover_active(lab.backend, lab.parent)
            .await
            .unwrap(),
    );
    assert_eq!(
        reads, 11,
        "one fresh child repeated a preflight snapshot read"
    );
}

#[tokio::test]
async fn active_recovery_does_not_repeat_the_pre_readback_snapshot() {
    use std::sync::atomic::Ordering;

    let tenant = TenantId::from_static("recovery-read-budget");
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("recovery-read-budget-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x71; 32]),
    )
    .unwrap();
    let raw = Arc::new(super::worker_lease::RenewalBackend::new());
    let store = SessionStore::new(EncryptingSessionBackend::new(
        raw.clone(),
        keys,
        "recovery-read-budget",
    ));
    let lab = lab_with_store(store, tenant, 3).await;
    let reads_before = raw.reads.load(Ordering::SeqCst);
    let writes_before = raw.writes.load(Ordering::SeqCst);
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let reads = raw.reads.load(Ordering::SeqCst) - reads_before;
    let writes = raw.writes.load(Ordering::SeqCst) - writes_before;
    // The recovered authority must remain usable for the exact protected
    // parent/child lifecycle; a dropped read cannot substitute a fake claim.
    let child = lab
        .authority
        .reconcile_bearer(
            lab.backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone(),
        )
        .await
        .unwrap();
    drop(
        lab.authority
            .retire(lab.backend.clone(), child, lab.child)
            .await
            .unwrap(),
    );
    drop(
        lab.authority
            .recover_active(lab.backend, lab.parent)
            .await
            .unwrap(),
    );
    assert_eq!(writes, 0);
    assert_eq!(
        reads, 3,
        "active recovery repeated its pre-readback snapshot"
    );
}

#[tokio::test]
async fn active_recovery_requires_fresh_durable_read_after_backend_readback() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let tenant = TenantId::from_static("recovery-read-failure");
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("recovery-read-failure-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x72; 32]),
    )
    .unwrap();
    let raw = Arc::new(super::worker_lease::RenewalBackend::new());
    let store = SessionStore::new(EncryptingSessionBackend::new(
        raw.clone(),
        keys,
        "recovery-read-failure",
    ));
    let lab = lab_with_store(store, tenant, 3).await;
    let backend = Arc::new(HeldAcknowledgement {
        inner: lab.backend.clone(),
        hold_next: AtomicBool::new(false),
        hold_before_effect: false,
        hold_remove: std::sync::atomic::AtomicBool::new(false),
        read_calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let writes_before = raw.writes.load(Ordering::SeqCst);
    raw.reject_read
        .store(raw.reads.load(Ordering::SeqCst) + 3, Ordering::SeqCst);
    assert!(matches!(
        lab.authority
            .recover_active(backend.clone(), lab.parent.clone())
            .await,
        Err(GtpuSessionSelectorCoordinatorError::Namespace)
    ));
    assert_eq!(
        backend.read_calls.load(Ordering::SeqCst),
        1,
        "the failed durable read must follow exact backend readback"
    );
    assert_eq!(raw.writes.load(Ordering::SeqCst), writes_before);
    // Read-only uncertainty must neither fabricate success nor poison a
    // settled parent or prevent its independent sibling's exact recovery.
    for parent in [lab.parent, lab.sibling] {
        drop(
            lab.authority
                .recover_active(lab.backend.clone(), parent)
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn retained_transition_snapshot_cannot_replace_a_later_active_generation() {
    let lab = lab(3).await;
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let mut lease = lab.authority.acquire_worker_lease().await.unwrap();
    drop(
        lab.authority
            .claim_fresh_bearer_with_lease(
                lab.backend.as_ref(),
                &lab.child,
                Some((&lab.parent, &parent.0)),
                &mut lease,
            )
            .await
            .unwrap(),
    );
    let handoff = lab
        .authority
        .mark_install_backend_started_with_lease(&lab.child, &mut lease)
        .await
        .unwrap();
    let BackendStartHandoff::Transitioned(admission) = handoff else {
        panic!("fresh child must receive one backend handoff");
    };
    let stale_admission = lab
        .authority
        .installing_admission(&lab.child, Some(true))
        .await
        .unwrap();
    let stale_snapshot = lab.authority.read_state().await.unwrap();
    let active = lab
        .authority
        .effect_and_activate_with_lease(
            lab.backend.as_ref(),
            lab.child.clone(),
            admission,
            None,
            &mut lease,
        )
        .await
        .unwrap();
    let settled = lab.authority.read_state().await.unwrap().1.encode();
    assert!(matches!(
        lab.authority
            .transition_phase_from_snapshot_with_lease(
                &stale_admission,
                0,
                None,
                &mut lease,
                Some(stale_snapshot),
            )
            .await,
        Err(GtpuSessionSelectorNamespaceError::StaleGeneration)
    ));
    assert_eq!(
        lab.authority.read_state().await.unwrap().1.encode(),
        settled
    );
    lab.authority.release_worker_lease(lease).await.unwrap();
    drop(
        lab.authority
            .retire(lab.backend.clone(), active, lab.child)
            .await
            .unwrap(),
    );
    drop(
        lab.authority
            .recover_active(lab.backend, lab.parent)
            .await
            .unwrap(),
    );
}

/// Hold one acknowledgement after the simulation has completed its exact
/// effect and released its map lock. No durable or backend authority is forged.
#[derive(Debug)]
struct HeldAcknowledgement {
    inner: Arc<GroupedGtpuDataplaneSimulation>,
    hold_next: std::sync::atomic::AtomicBool,
    hold_before_effect: bool,
    hold_remove: std::sync::atomic::AtomicBool,
    read_calls: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl GtpuDataplaneBackend for HeldAcknowledgement {
    async fn create_device(
        &self,
        request: crate::CreateGtpDeviceRequest,
    ) -> Result<crate::GtpDevice, crate::GtpuError> {
        self.inner.create_device(request).await
    }

    async fn resolve_device(&self, name: &str) -> Result<crate::GtpDevice, crate::GtpuError> {
        self.inner.resolve_device(name).await
    }

    async fn remove_device(&self, device: &crate::GtpDevice) -> Result<(), crate::GtpuError> {
        self.inner.remove_device(device).await
    }

    async fn install_pdp_context(
        &self,
        request: crate::GtpPdpContext,
    ) -> Result<(), crate::GtpuError> {
        self.inner.install_pdp_context(request).await
    }

    async fn remove_pdp_context(
        &self,
        request: crate::RemovePdpContextRequest,
    ) -> Result<(), crate::GtpuError> {
        self.inner.remove_pdp_context(request).await
    }

    async fn probe(&self) -> Result<crate::GtpuProbe, crate::GtpuError> {
        self.inner.probe().await
    }

    async fn acquire_selector_namespace_lease(
        &self,
        request: GtpuSessionSelectorBindingLease,
    ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
        self.inner.acquire_selector_namespace_lease(request).await
    }

    async fn read_pdp_context_group_with_lease(
        &self,
        request: GtpuSessionSelectorReadbackRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
        self.read_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.read_pdp_context_group_with_lease(request).await
    }

    async fn reconcile_pdp_context_group_authorized(
        &self,
        request: GtpuSessionSelectorEffectRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
        let hold = self
            .hold_next
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        if hold && self.hold_before_effect {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let result = self
            .inner
            .reconcile_pdp_context_group_authorized(request)
            .await;
        if hold && !self.hold_before_effect && result.is_ok() {
            self.entered.notify_one();
            self.release.notified().await;
        }
        result
    }

    async fn remove_pdp_context_group_with_lease(
        &self,
        request: GtpuSessionSelectorRemovalRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
        let hold = self
            .hold_remove
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        if hold && self.hold_before_effect {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let result = self
            .inner
            .remove_pdp_context_group_with_lease(request)
            .await;
        if hold && !self.hold_before_effect && result.is_ok() {
            self.entered.notify_one();
            self.release.notified().await;
        }
        result
    }

    async fn authorize_selector_reuse(
        &self,
        request: GtpuSessionSelectorReuseRequest,
    ) -> Result<GtpuSessionSelectorReuseReceipt, crate::GtpuError> {
        self.inner.authorize_selector_reuse(request).await
    }
}

#[tokio::test]
async fn unrelated_child_finishes_before_delayed_effect_acknowledgement() {
    concurrent_child_progress(false, false).await;
}

#[tokio::test]
async fn unrelated_child_finishes_while_exact_install_owner_has_not_published_a_stamp() {
    concurrent_child_progress(true, false).await;
}

#[tokio::test]
async fn dropping_one_observer_retains_its_effect_while_an_unrelated_child_finishes() {
    concurrent_child_progress(true, true).await;
}

async fn concurrent_child_progress(hold_before_effect: bool, cancel_observer: bool) {
    let lab = lab(3).await;
    let concurrent = lab.authority.concurrent_operations();
    let backend = Arc::new(HeldAcknowledgement {
        inner: lab.backend.clone(),
        hold_next: std::sync::atomic::AtomicBool::new(true),
        hold_before_effect,
        hold_remove: std::sync::atomic::AtomicBool::new(false),
        read_calls: std::sync::atomic::AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let parent = lab
        .authority
        .recover_active(backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let sibling = lab
        .authority
        .recover_active(backend.clone(), lab.sibling.clone())
        .await
        .unwrap();
    let mut sibling_context = lab.child.entries()[0].context().clone();
    sibling_context.ms_address = lab.sibling.entries()[0].context().ms_address;
    sibling_context.local_teid = Teid::new(0x2001).unwrap();
    sibling_context.peer_teid = Teid::new(0x2002).unwrap();
    let sibling_child = GtpuSessionGroup::new(
        GtpuSessionGroupId::new([4; 16]).unwrap(),
        lab.sibling.device_id(),
        vec![GtpuSessionEntry::new(
            sibling_context,
            lab.sibling.entries()[0].local_outer_address(),
        )
        .unwrap()],
    )
    .unwrap();
    let mut first = concurrent.reconcile_bearer(
        backend.clone(),
        parent,
        lab.parent.clone(),
        lab.child.clone(),
    );
    tokio::select! {
        () = backend.entered.notified() => {},
        result = &mut first => panic!("first effect escaped its acknowledgement gate: {result:?}"),
    }
    let first = if cancel_observer {
        drop(first);
        None
    } else {
        Some(first)
    };
    let mut second = concurrent.reconcile_bearer(
        backend.clone(),
        sibling,
        lab.sibling.clone(),
        sibling_child.clone(),
    );
    // A progress oracle, not a latency acceptance threshold. Always settle
    // both detached operations before asserting the failed ordering.
    let progress = tokio::time::timeout(Duration::from_secs(1), &mut second).await;
    let independent = progress.is_ok();
    backend.release.notify_one();
    if let Some(first) = first {
        drop(first.await.unwrap());
    }
    drop(match progress {
        Ok(result) => result.unwrap(),
        Err(_) => second.await.unwrap(),
    });
    for group in [lab.parent, lab.sibling, lab.child, sibling_child] {
        drop(
            lab.authority
                .recover_active(backend.clone(), group)
                .await
                .unwrap(),
        );
    }
    assert!(
        independent,
        "an unrelated child must finish before the held effect is released"
    );
}

/// The default gate runs one pair. Explicit profiling repeats remain bounded
/// by the reference ledger's permanent-history capacity. This is a component
/// observation over real file-backed voters, not a packet or kernel benchmark.
#[cfg(target_os = "linux")]
fn selector_profile_snapshot() -> Vec<serde_json::Value> {
    gtpu_selector_duration_snapshot()
        .into_iter()
        .map(|sample| {
            serde_json::json!({
                "phase": sample.phase.as_str(),
                "outcome": sample.outcome.as_str(),
                "count": sample.count,
                "sum_us": sample.sum_microseconds,
                "buckets": sample.bucket_counts,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
async fn selector_profile_step<T>(
    cycle: u8,
    slot: usize,
    boundary: &'static str,
    future: impl Future<Output = Result<T, GtpuSessionSelectorCoordinatorError>>,
) -> Result<T, GtpuSessionSelectorCoordinatorError> {
    use std::io::Write;

    let started = Instant::now();
    let result = future.await;
    let outcome = match &result {
        Ok(_) => "completed",
        Err(GtpuSessionSelectorCoordinatorError::Namespace) => "namespace_error",
        Err(GtpuSessionSelectorCoordinatorError::Backend) => "backend_error",
    };
    let mut evidence = serde_json::json!({
        "cycle": cycle,
        "slot": slot,
        "boundary": boundary,
        "outcome": outcome,
        "elapsed_us": u64::try_from(started.elapsed().as_micros()).unwrap(),
    });
    if result.is_err() {
        evidence["phases"] = serde_json::json!(selector_profile_snapshot());
    }
    writeln!(std::io::stderr(), "selector_component_step={evidence}").unwrap();
    result
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn durable_overlapping_bearer_phase_profile() {
    use opc_session_testkit::authenticated_consumer_fixture::AuthenticatedPreparedFencedTransitionFixture;
    use std::io::Write;

    let cycles = std::env::var("OPC_SELECTOR_PROFILE_CYCLES")
        .map(|value| value.parse::<u8>().expect("numeric cycle count"))
        .unwrap_or(1);
    assert!((1..=100).contains(&cycles));
    let tenant = TenantId::from_static("bearer-durable-profile");
    let remote = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([
        opc_session_store::SessionConsumerTenantNfScope::new(
            tenant.clone(),
            NetworkFunctionKind::from_static("epdg"),
        ),
    ])
    .await
    .unwrap();
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("bearer-profile-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x68; 32]),
    )
    .unwrap();
    let protected = remote
        .open_protected_local_aead(keys, "bearer-durable-profile")
        .await
        .unwrap();
    let lab = lab_with_store(SessionStore::new(protected), tenant, 3).await;
    let before = selector_profile_snapshot();
    let storage_before = remote.local_storage_timing().unwrap().unwrap();
    let mut create_us = Vec::new();
    let mut delete_us = Vec::new();
    let lab_ref = &lab;
    for cycle in 0..cycles {
        let parents = [&lab.parent, &lab.sibling];
        let children: [GtpuSessionGroup; 2] = std::array::from_fn(|index| {
            let mut context = parents[index].entries()[0].context().clone();
            context.local_teid = Teid::new(0x2000 + u32::from(cycle) * 2 + index as u32).unwrap();
            context.peer_teid = Teid::new(0x4000 + u32::from(cycle) * 2 + index as u32).unwrap();
            context.bearer_mark = Some(crate::GtpBearerMark::new(6).unwrap());
            GtpuSessionGroup::new(
                GtpuSessionGroupId::new([3 + cycle * 2 + index as u8; 16]).unwrap(),
                parents[index].device_id(),
                vec![GtpuSessionEntry::new(
                    context,
                    parents[index].entries()[0].local_outer_address(),
                )
                .unwrap()],
            )
            .unwrap()
        });
        let children_ref = &children;
        let parents_ref = &parents;
        let create = |index: usize| async move {
            let started = Instant::now();
            let parent = parents_ref[index].clone();
            let claim = selector_profile_step(
                cycle,
                index,
                "parent_recover",
                lab_ref
                    .authority
                    .recover_active(lab_ref.backend.clone(), parent.clone()),
            )
            .await?;
            let child = selector_profile_step(
                cycle,
                index,
                "create",
                lab_ref.authority.reconcile_bearer(
                    lab_ref.backend.clone(),
                    claim,
                    parent,
                    children_ref[index].clone(),
                ),
            )
            .await?;
            Ok::<_, GtpuSessionSelectorCoordinatorError>((
                child,
                u64::try_from(started.elapsed().as_micros()).unwrap(),
            ))
        };
        let (first, second) = tokio::join!(create(0), create(1));
        // Both owned operations reach a result before a failed observation
        // fails the fixture. A failed run retains its completed step records.
        let first = first.unwrap();
        let second = second.unwrap();
        let claims = [first.0, second.0];
        create_us.extend([first.1, second.1]);
        let remove = |index: usize, claim| async move {
            let started = Instant::now();
            let retired = selector_profile_step(
                cycle,
                index,
                "delete",
                lab_ref.authority.retire(
                    lab_ref.backend.clone(),
                    claim,
                    children_ref[index].clone(),
                ),
            )
            .await?;
            drop(retired);
            Ok::<_, GtpuSessionSelectorCoordinatorError>(
                u64::try_from(started.elapsed().as_micros()).unwrap(),
            )
        };
        let [first, second] = claims;
        let (first, second) = tokio::join!(remove(0, first), remove(1, second));
        delete_us.extend([first.unwrap(), second.unwrap()]);
        for (index, parent) in parents.into_iter().enumerate() {
            drop(
                selector_profile_step(
                    cycle,
                    index,
                    "post_delete_parent_recover",
                    lab.authority
                        .recover_active(lab.backend.clone(), parent.clone()),
                )
                .await
                .unwrap(),
            );
        }
        let evidence = serde_json::json!({
            "cycle": cycle,
            "create_us": &create_us[create_us.len() - 2..],
            "delete_us": &delete_us[delete_us.len() - 2..],
            "phases": selector_profile_snapshot(),
            "storage": remote.local_storage_timing().unwrap().unwrap(),
        });
        writeln!(std::io::stderr(), "selector_component_cycle={evidence}").unwrap();
    }
    let evidence = serde_json::json!({
        "schema": "opc-selector-component-profile-v1",
        "resident_parents": 2,
        "offered_concurrency": 2,
        "cycles": cycles,
        "create_us": create_us,
        "delete_us": delete_us,
        "phases_before": before,
        "phases_after": selector_profile_snapshot(),
        "storage_before": storage_before,
        "storage_after": remote.local_storage_timing().unwrap().unwrap(),
        "limits": ["component_boundary", "in_process_raft_transport", "simulated_dataplane"],
    });
    writeln!(std::io::stderr(), "selector_component_profile={evidence}").unwrap();
    for parent in [&lab.parent, &lab.sibling] {
        let active = lab
            .authority
            .recover_active(lab.backend.clone(), parent.clone())
            .await
            .unwrap();
        drop(
            lab.authority
                .retire(lab.backend.clone(), active, parent.clone())
                .await
                .unwrap(),
        );
    }
    drop(lab);
    remote.shutdown().await.unwrap();
}

#[tokio::test]
async fn child_profile_capacity_counts_full_canonical_atoms_before_mutation() {
    let lab = lab(2).await;
    let before = lab.authority.read_state().await.unwrap().1.encode();
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    assert!(lab
        .authority
        .reconcile_bearer(
            lab.backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone()
        )
        .await
        .is_err());
    assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
    let context = lab.child.entries()[0].context();
    for selector in [
        crate::PdpContextSelector::LocalTeid(
            crate::PdpContextLocalTeidSelector::from_context(context).unwrap(),
        ),
        crate::PdpContextSelector::Uplink(
            crate::PdpContextUplinkSelector::from_context(context).unwrap(),
        ),
    ] {
        assert_eq!(
            lab.backend.read_pdp_context(selector).await.unwrap(),
            crate::PdpContextReadback::Absent
        );
    }
    drop(
        lab.authority
            .recover_active(lab.backend, lab.parent)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn child_profile_persisted_legacy_global_mark_collision_is_rejected() {
    let lab = lab(3).await;
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    drop(
        lab.authority
            .reconcile_bearer(
                lab.backend.clone(),
                parent,
                lab.parent.clone(),
                lab.child.clone(),
            )
            .await
            .unwrap(),
    );
    let legacy = group_with_paa(
        4,
        1,
        0x1004,
        IpAddr::V4(Ipv4Addr::new(10, 23, 0, 99)),
        Some(7),
    );
    let mut context = legacy.entries()[0].context().clone();
    context.link_ifindex = lab.parent.entries()[0].context().link_ifindex;
    let legacy = GtpuSessionGroup::new(
        legacy.id(),
        legacy.device_id(),
        vec![GtpuSessionEntry::new(context, legacy.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap();
    drop(
        lab.authority
            .reconcile_fresh(lab.backend.clone(), legacy.clone())
            .await
            .unwrap(),
    );
    let mut corrupt = lab.authority.read_state().await.unwrap().1;
    assert!(NamespaceState::decode(&corrupt.encode()).is_some());
    let old = CanonicalClaim::from_group(&legacy)
        .with_key(&corrupt.selector_digest_key)
        .unwrap();
    let mut context = legacy.entries()[0].context().clone();
    context.bearer_mark = crate::GtpBearerMark::new(6);
    let overlapping = GtpuSessionGroup::new(
        legacy.id(),
        legacy.device_id(),
        vec![GtpuSessionEntry::new(context, legacy.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap();
    let new = CanonicalClaim::from_group(&overlapping)
        .with_key(&corrupt.selector_digest_key)
        .unwrap();
    let old_atoms = old.selector_atoms(&corrupt.selector_digest_key).unwrap();
    let new_atoms = new.selector_atoms(&corrupt.selector_digest_key).unwrap();
    assert_eq!(old_atoms.difference(&new_atoms).count(), 1);
    assert_eq!(new_atoms.difference(&old_atoms).count(), 1);
    let old_mark = *old_atoms.difference(&new_atoms).next().unwrap();
    let new_mark = *new_atoms.difference(&old_atoms).next().unwrap();
    let owner = corrupt.selectors.remove(&old_mark).unwrap();
    corrupt.selectors.insert(new_mark, owner);
    assert!(corrupt.published_atoms.remove(&old_mark));
    corrupt.published_atoms.insert(new_mark);
    corrupt
        .canonical_desired
        .insert(new.group_fingerprint, Zeroizing::new(new.desired.clone()));
    let GroupState::Active {
        selectors,
        desired,
        atoms,
        ..
    } = corrupt.groups.get_mut(&new.group_fingerprint).unwrap()
    else {
        panic!("fixture must have a live legacy group");
    };
    *selectors = new.selector_set_fingerprint;
    *desired = new.desired_fingerprint;
    *atoms = new_atoms;
    // Every individual descriptor and child relation is internally exact;
    // cross-profile global-mark exclusivity must still reject this record.
    assert!(corrupt.canonical_desired_index_is_exact());
    assert!(corrupt.bearer_relations_are_exact());
    assert!(!corrupt.mark_profiles_are_disjoint());
    assert!(NamespaceState::decode(&corrupt.encode()).is_none());
}

#[tokio::test]
async fn child_profile_persisted_relations_reject_corruption_and_keep_private_data_redacted() {
    let lab = lab(3).await;
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let active = lab
        .authority
        .reconcile_bearer(
            lab.backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone(),
        )
        .await
        .unwrap();
    let state = lab.authority.read_state().await.unwrap().1;
    let encoded = state.encode();
    assert_eq!(&encoded[..7], b"OPCSN18");
    assert_eq!(NamespaceState::decode(&encoded).unwrap().encode(), encoded);
    let child = CanonicalClaim::from_group(&lab.child)
        .with_key(&state.selector_digest_key)
        .unwrap();
    let parent = CanonicalClaim::from_group(&lab.parent)
        .with_key(&state.selector_digest_key)
        .unwrap();
    let sibling = CanonicalClaim::from_group(&lab.sibling)
        .with_key(&state.selector_digest_key)
        .unwrap();
    for owner in [
        child.group_fingerprint,
        sibling.group_fingerprint,
        [0x37; 32],
    ] {
        let mut corrupt = state.clone();
        corrupt
            .bearer_parents
            .insert(child.group_fingerprint, owner);
        assert!(NamespaceState::decode(&corrupt.encode()).is_none());
    }
    let mut missing = state.clone();
    missing.bearer_parents.clear();
    assert!(NamespaceState::decode(&missing.encode()).is_none());
    let mut nested = state.clone();
    nested
        .bearer_parents
        .insert(parent.group_fingerprint, child.group_fingerprint);
    assert!(NamespaceState::decode(&nested.encode()).is_none());
    let mut capacity = state.clone();
    capacity.capacity = 2;
    assert!(NamespaceState::decode(&capacity.encode()).is_none());
    for len in [encoded.len() - 1, encoded.len() - 32, encoded.len() - 64] {
        assert!(NamespaceState::decode(&encoded[..len]).is_none());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(NamespaceState::decode(&extra).is_none());
    let mut downgraded = encoded.clone();
    downgraded[..7].copy_from_slice(b"OPCSN17");
    assert!(NamespaceState::decode(&downgraded).is_none());
    let rendered = format!(
        "{:?} {:?} {:?}",
        active,
        lab.backend,
        lab.backend
            .selector_namespace_bootstrap(lab.parent.device_id())
            .await
            .unwrap()
    );
    for private in [
        "10.23.0.1",
        "192.0.2.10",
        "192.0.2.1",
        "4099",
        "bearer-fixture-key",
    ] {
        assert!(!rendered.contains(private));
    }
    // Terminal history retains the parent relation through an exact byte roundtrip.
    drop(
        lab.authority
            .retire(lab.backend.clone(), active, lab.child.clone())
            .await
            .unwrap(),
    );
    let retired = lab.authority.read_state().await.unwrap().1.encode();
    assert_eq!(NamespaceState::decode(&retired).unwrap().encode(), retired);
    drop(
        lab.authority
            .recover_retired(lab.backend.clone(), lab.child)
            .await
            .unwrap(),
    );
    drop(
        lab.authority
            .recover_active(lab.backend, lab.sibling)
            .await
            .unwrap(),
    );
}
