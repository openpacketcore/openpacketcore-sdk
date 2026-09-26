//! Controls for the growing-ledger component profile. Every measured point
//! read observes the same protected record. Recovery still performs its real
//! lease, quorum, exact backend readback and final durable read operations.

use super::*;
use opc_session_testkit::authenticated_consumer_fixture::AuthenticatedPreparedFencedTransitionFixture;
use std::io::Write;

#[tokio::test]
async fn durable_stable_selector_point_read_profile() {
    profile(false).await;
}

#[tokio::test]
async fn durable_stable_selector_recovery_profile() {
    profile(true).await;
}

async fn profile(recovery: bool) {
    let cycles = std::env::var("OPC_SELECTOR_PROFILE_CYCLES")
        .map(|value| value.parse::<u8>().expect("numeric cycle count"))
        .unwrap_or(1);
    assert!((1..=100).contains(&cycles));
    let tenant = TenantId::from_static("selector-stable-read-profile");
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
        opc_key::KeyId::new("selector-stable-read-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x68; 32]),
    )
    .unwrap();
    let protected = remote
        .open_protected_local_aead(keys, "selector-stable-read-profile")
        .await
        .unwrap();
    let lab = lab_with_store(SessionStore::new(protected), tenant, 3).await;
    let operations = lab.authority.concurrent_operations();
    let expected = lab
        .authority
        .store
        .get(&lab.authority.namespace_key)
        .await
        .unwrap()
        .unwrap();
    let composition = if recovery {
        "stable_ledger_concurrent_recovery"
    } else {
        "stable_ledger_point_read"
    };
    let phases_before = selector_profile_snapshot();
    let storage_before = remote.local_storage_timing().unwrap().unwrap();
    let mut elapsed_us = Vec::new();
    for cycle in 0..cycles {
        let (lab, operations, expected) = (&lab, &operations, &expected);
        let member = |slot: usize| async move {
            let started = Instant::now();
            if recovery {
                let group = if slot == 0 { &lab.parent } else { &lab.sibling };
                let result = selector_profile_step(
                    cycle,
                    slot,
                    "stable_parent_recover",
                    operations.recover_active(lab.backend.clone(), group.clone()),
                )
                .await;
                // Return the failure to the pair owner so both owned workers
                // settle before a failed measurement fails the fixture.
                result.map(drop)?;
            } else {
                let observed = lab
                    .authority
                    .store
                    .get(&lab.authority.namespace_key)
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                assert_eq!(observed.as_ref(), Some(expected));
            }
            Ok::<_, GtpuSessionSelectorCoordinatorError>(
                u64::try_from(started.elapsed().as_micros()).unwrap(),
            )
        };
        let (first, second) = tokio::join!(member(0), member(1));
        let evidence = serde_json::json!({
            "cycle": cycle,
            "composition": composition,
            "success": [first.is_ok(), second.is_ok()],
            "elapsed_us": [first.as_ref().ok(), second.as_ref().ok()],
            "phases": selector_profile_snapshot(),
            "storage": remote.local_storage_timing().unwrap().unwrap(),
        });
        writeln!(std::io::stderr(), "selector_stable_read_cycle={evidence}").unwrap();
        elapsed_us.extend([first.unwrap(), second.unwrap()]);
    }
    assert_eq!(
        lab.authority
            .store
            .get(&lab.authority.namespace_key)
            .await
            .unwrap()
            .as_ref(),
        Some(&expected),
        "recovery cannot mutate the exact selector ledger",
    );
    let evidence = serde_json::json!({
        "schema": "opc-selector-stable-read-profile-v1",
        "composition": composition,
        "resident_parents": 2,
        "offered_concurrency": 2,
        "cycles": cycles,
        "ledger_bytes": expected.payload.as_bytes().len(),
        "exact_ledger_unchanged": true,
        "elapsed_us": elapsed_us,
        "phases_before": phases_before,
        "phases_after": selector_profile_snapshot(),
        "storage_before": storage_before,
        "storage_after": remote.local_storage_timing().unwrap().unwrap(),
        "limits": ["component_boundary", "in_process_raft_transport", "simulated_dataplane"],
    });
    writeln!(std::io::stderr(), "selector_stable_read_profile={evidence}").unwrap();
    for parent in [&lab.parent, &lab.sibling] {
        let active = operations
            .recover_active(lab.backend.clone(), parent.clone())
            .await
            .unwrap();
        drop(
            operations
                .retire(lab.backend.clone(), active, parent.clone())
                .await
                .unwrap(),
        );
    }
    drop(lab);
    remote.shutdown().await.unwrap();
}
