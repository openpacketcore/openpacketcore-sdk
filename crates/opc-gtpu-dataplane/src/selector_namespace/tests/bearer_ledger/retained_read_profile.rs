//! Separate protected point reads from decoding at increasing, then unchanged,
//! retained history sizes. History is produced by completed bearer lifecycles;
//! no ledger, receipt, durability rule or production limit is changed.

use super::*;
use opc_session_testkit::authenticated_consumer_fixture::AuthenticatedPreparedFencedTransitionFixture;
use std::io::Write;

#[tokio::test]
async fn durable_retained_selector_read_profile() {
    let cycles = std::env::var("OPC_SELECTOR_PROFILE_CYCLES")
        .map(|value| value.parse::<u8>().expect("numeric sample cycle count"))
        .unwrap_or(1);
    let history_cycles = std::env::var("OPC_SELECTOR_PROFILE_HISTORY_CYCLES")
        .map(|value| value.parse::<u8>().expect("numeric history cycle count"))
        .unwrap_or(1);
    assert!((1..=100).contains(&cycles));
    assert!((1..=50).contains(&history_cycles));
    let tenant = TenantId::from_static("selector-retained-read-profile");
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
        opc_key::KeyId::new("selector-retained-read-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x68; 32]),
    )
    .unwrap();
    let protected = remote
        .open_protected_local_aead(keys, "selector-retained-read-profile")
        .await
        .unwrap();
    let lab = lab_with_store(SessionStore::new(protected), tenant, 3).await;
    let operations = lab.authority.concurrent_operations();
    let mut stages = vec![0, history_cycles / 2, history_cycles];
    stages.dedup();
    let mut seeded = 0;
    for history in stages {
        while seeded < history {
            seed_pair(&lab, &operations, seeded).await;
            seeded += 1;
        }
        let expected = lab
            .authority
            .store
            .get(&lab.authority.namespace_key)
            .await
            .unwrap()
            .unwrap();
        let initial_state = NamespaceState::decode(expected.payload.as_bytes()).unwrap();
        assert_eq!(initial_state.groups.len(), 2 + usize::from(history) * 2);
        assert_eq!(initial_state.encode(), expected.payload.as_bytes());
        let storage_before = remote.local_storage_timing().unwrap().unwrap();
        let mut read_us = Vec::new();
        for _ in 0..cycles {
            let member = || async {
                let started = Instant::now();
                let result = lab.authority.store.get(&lab.authority.namespace_key).await;
                let elapsed = u64::try_from(started.elapsed().as_micros()).unwrap();
                (result, elapsed)
            };
            let (first, second) = tokio::join!(member(), member());
            for (result, elapsed) in [first, second] {
                assert_eq!(result.unwrap().as_ref(), Some(&expected));
                read_us.push(elapsed);
            }
        }
        // Decode after both read futures have settled so synchronous validation
        // cannot inflate its sibling's awaited transport measurement.
        let mut decode_us = Vec::new();
        for _ in 0..usize::from(cycles) * 2 {
            let started = Instant::now();
            let decoded = NamespaceState::decode(expected.payload.as_bytes()).unwrap();
            decode_us.push(u64::try_from(started.elapsed().as_micros()).unwrap());
            assert_eq!(decoded.encode(), expected.payload.as_bytes());
        }
        assert_eq!(
            lab.authority
                .store
                .get(&lab.authority.namespace_key)
                .await
                .unwrap()
                .as_ref(),
            Some(&expected),
        );
        let evidence = serde_json::json!({
            "schema": "opc-selector-retained-read-profile-v1",
            "resident_parents": 2,
            "retained_child_histories": usize::from(history) * 2,
            "permanent_groups": initial_state.groups.len(),
            "known_selector_atoms": initial_state.selectors.len(),
            "ledger_bytes": expected.payload.as_bytes().len(),
            "offered_read_concurrency": 2,
            "cycles": cycles,
            "exact_ledger_unchanged_during_reads": true,
            "read_us": read_us,
            "decode_us": decode_us,
            "storage_before": storage_before,
            "storage_after": remote.local_storage_timing().unwrap().unwrap(),
            "limits": ["component_boundary", "in_process_raft_transport", "simulated_dataplane"],
        });
        writeln!(
            std::io::stderr(),
            "selector_retained_read_profile={evidence}"
        )
        .unwrap();
    }
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

async fn seed_pair<B>(
    lab: &Lab<B>,
    operations: &GtpuSessionSelectorConcurrentNamespace<B>,
    cycle: u8,
) where
    B: ProtectedSessionBackend + Send + Sync + 'static,
{
    let parents = [&lab.parent, &lab.sibling];
    let children: [GtpuSessionGroup; 2] = std::array::from_fn(|index| {
        let mut context = parents[index].entries()[0].context().clone();
        context.local_teid = Teid::new(0x2000 + u32::from(cycle) * 2 + index as u32).unwrap();
        context.peer_teid = Teid::new(0x4000 + u32::from(cycle) * 2 + index as u32).unwrap();
        context.bearer_mark = Some(crate::GtpBearerMark::new(6).unwrap());
        GtpuSessionGroup::new(
            GtpuSessionGroupId::new([3 + cycle * 2 + index as u8; 16]).unwrap(),
            parents[index].device_id(),
            vec![
                GtpuSessionEntry::new(context, parents[index].entries()[0].local_outer_address())
                    .unwrap(),
            ],
        )
        .unwrap()
    });
    let create = |slot: usize| {
        let parents = &parents;
        let children = &children;
        async move {
            let parent = selector_profile_step(
                cycle,
                slot,
                "retained_profile_parent_recover",
                operations.recover_active(lab.backend.clone(), parents[slot].clone()),
            )
            .await?;
            selector_profile_step(
                cycle,
                slot,
                "retained_profile_child_create",
                operations.reconcile_bearer(
                    lab.backend.clone(),
                    parent,
                    parents[slot].clone(),
                    children[slot].clone(),
                ),
            )
            .await
        }
    };
    let (first, second) = tokio::join!(create(0), create(1));
    let (first, second) = (first.unwrap(), second.unwrap());
    let (first, second) = tokio::join!(
        selector_profile_step(
            cycle,
            0,
            "retained_profile_child_retire",
            operations.retire(lab.backend.clone(), first, children[0].clone()),
        ),
        selector_profile_step(
            cycle,
            1,
            "retained_profile_child_retire",
            operations.retire(lab.backend.clone(), second, children[1].clone()),
        ),
    );
    drop((first.unwrap(), second.unwrap()));
}
