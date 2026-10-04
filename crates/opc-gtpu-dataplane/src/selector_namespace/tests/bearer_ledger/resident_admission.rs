//! Admission diagnostic over real protected storage, without changing any
//! namespace bound. A requested count is not a claim of admitted residents.

use super::*;
use opc_session_testkit::authenticated_consumer_fixture::AuthenticatedPreparedFencedTransitionFixture;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

fn resident_group(parent: &GtpuSessionGroup, ordinal: usize) -> GtpuSessionGroup {
    let ordinal = u32::try_from(ordinal).unwrap();
    let mut id = [0x91; 16];
    id[12..].copy_from_slice(&ordinal.to_be_bytes());
    let mut context = parent.entries()[0].context().clone();
    context.ms_address = IpAddr::V4(Ipv4Addr::from(0x0a1f_0000 + ordinal));
    context.local_teid = Teid::new(0x10000 + ordinal * 2).unwrap();
    context.peer_teid = Teid::new(0x10001 + ordinal * 2).unwrap();
    GtpuSessionGroup::new(
        GtpuSessionGroupId::new(id).unwrap(),
        parent.device_id(),
        vec![GtpuSessionEntry::new(context, parent.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_resident_admission_profile() {
    let requested = std::env::var("OPC_SELECTOR_ADMISSION_RESIDENTS")
        .map(|value| value.parse::<usize>().expect("numeric resident target"))
        .unwrap_or(8);
    assert!((4..=10_000).contains(&requested));
    let tenant = TenantId::from_static("selector-resident-admission");
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
        opc_key::KeyId::new("selector-resident-admission-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x67; 32]),
    )
    .unwrap();
    let protected = remote
        .open_protected_local_aead(keys, "selector-resident-admission")
        .await
        .unwrap();
    let lab = lab_with_store(SessionStore::new(protected), tenant, 32).await;
    let operations = lab.authority.concurrent_operations();
    let started = Instant::now();
    let storage_before = remote.local_storage_timing().unwrap().unwrap();
    let phases_before = selector_profile_snapshot();
    let current = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut completed = vec![lab.parent.clone(), lab.sibling.clone()];
    let mut samples = Vec::new();
    let mut attempted = 2;
    let mut failed = 0;
    while attempted < requested && failed == 0 {
        let count = (requested - attempted).min(8);
        let barrier = Arc::new(tokio::sync::Barrier::new(count));
        let mut tasks = tokio::task::JoinSet::new();
        for ordinal in attempted..attempted + count {
            let desired = resident_group(&lab.parent, ordinal);
            let operations = operations.clone();
            let backend = lab.backend.clone();
            let barrier = barrier.clone();
            let current = current.clone();
            let peak = peak.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                let active = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(active, Ordering::SeqCst);
                let start = Instant::now();
                let result = operations.reconcile_fresh(backend, desired.clone()).await;
                let elapsed = u64::try_from(start.elapsed().as_micros()).unwrap();
                current.fetch_sub(1, Ordering::SeqCst);
                (desired, result, elapsed)
            });
        }
        attempted += count;
        while let Some(result) = tasks.join_next().await {
            let (desired, result, elapsed) = result.unwrap();
            let outcome = match result {
                Ok(claim) => {
                    drop(claim);
                    completed.push(desired);
                    "completed"
                }
                Err(GtpuSessionSelectorCoordinatorError::Namespace) => {
                    failed += 1;
                    "namespace_error"
                }
                Err(GtpuSessionSelectorCoordinatorError::Backend) => {
                    failed += 1;
                    "backend_error"
                }
            };
            samples.push(serde_json::json!({"outcome": outcome, "elapsed_us": elapsed}));
        }
    }
    assert_eq!(current.load(Ordering::SeqCst), 0);
    let encoded = lab
        .authority
        .store
        .get(&lab.authority.namespace_key)
        .await
        .unwrap()
        .unwrap();
    let state = NamespaceState::decode(encoded.payload.as_bytes()).unwrap();
    let unsettled = state
        .groups
        .values()
        .filter(|group| {
            matches!(
                group,
                GroupState::Installing { .. }
                    | GroupState::Retiring { .. }
                    | GroupState::Poisoned(_)
                    | GroupState::LegacyPoisoned
            )
        })
        .count();
    let capacity_exhausted = matches!(
        state.preflight_fresh_claim(2),
        Err(GtpuSessionSelectorNamespaceError::CapacityExhausted)
    );
    let mut evidence = serde_json::json!({
        "schema": "opc-selector-resident-admission-v1",
        "requested_residents": requested,
        "initial_residents": 2,
        "attempted_residents": attempted,
        "completed_residents": completed.len(),
        "failed_operations": failed,
        "admission_elapsed_us": u64::try_from(started.elapsed().as_micros()).unwrap(),
        "offered_concurrency": 8,
        "peak_observed_operation_overlap": peak.load(Ordering::SeqCst),
        "stopped_offering_after_first_failed_batch": failed != 0,
        "live_groups": state.live_group_count(),
        "unsettled_groups": unsettled,
        "permanent_groups": state.groups.len(),
        "known_selector_atoms": state.selectors.len(),
        "ledger_bytes": encoded.payload.as_bytes().len(),
        "subsequent_fresh_claim_capacity_exhausted": capacity_exhausted,
        "samples": samples,
        "phases_before": phases_before,
        "phases_after": selector_profile_snapshot(),
        "storage_before": storage_before,
        "storage_after": remote.local_storage_timing().unwrap().unwrap(),
        "activity": gtpu_selector_activity_snapshot().into_iter().map(|row| serde_json::json!({
            "phase": row.phase.as_str(), "current": row.current, "peak": row.peak,
        })).collect::<Vec<_>>(),
        "limits": ["admission_diagnostic_only", "in_process_raft_transport", "simulated_dataplane",
                   "no_bearer_rate_or_lifecycle_qualification", "stops_after_first_failed_batch"],
    });
    writeln!(
        std::io::stderr(),
        "selector_resident_admission_before_cleanup={evidence}"
    )
    .unwrap();
    // Recover fresh exact authority for every confirmed installation before
    // retirement. Do not discard records or rotate namespaces after refusal.
    let mut cleanup_failures = 0;
    for batch in completed.chunks(8) {
        let mut tasks = tokio::task::JoinSet::new();
        for desired in batch {
            let desired = desired.clone();
            let operations = operations.clone();
            let backend = lab.backend.clone();
            tasks.spawn(async move {
                let active = operations
                    .recover_active(backend.clone(), desired.clone())
                    .await?;
                operations.retire(backend, active, desired).await
            });
        }
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(retired) => drop(retired),
                Err(_) => cleanup_failures += 1,
            }
        }
    }
    let after = lab
        .authority
        .store
        .get(&lab.authority.namespace_key)
        .await
        .unwrap()
        .unwrap();
    let after = NamespaceState::decode(after.payload.as_bytes()).unwrap();
    evidence["cleanup_failures"] = cleanup_failures.into();
    evidence["live_groups_after_cleanup"] = after.live_group_count().into();
    evidence["permanent_groups_after_cleanup"] = after.groups.len().into();
    writeln!(
        std::io::stderr(),
        "selector_resident_admission_profile={evidence}"
    )
    .unwrap();
    drop(lab);
    remote.shutdown().await.unwrap();
    assert_eq!(
        cleanup_failures, 0,
        "confirmed residents must clean up exactly"
    );
    assert_eq!(
        after.live_group_count(),
        0,
        "unsettled residents remain visible"
    );
    assert_eq!(
        completed.len(),
        requested,
        "requested resident count was not admitted"
    );
    assert_eq!(failed, 0, "admission failures remain failures");
}
