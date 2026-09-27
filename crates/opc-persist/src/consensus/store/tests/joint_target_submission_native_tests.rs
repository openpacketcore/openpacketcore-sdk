//! The target-preparation guard enters the existing native accepted-work owner.
//! The actual native command is supported capacity8 BoundedAppend using the
//! same proved record. No store is opened jointly and no target Intent/Apply
//! is claimed: wire10, target ledger admission and apply remain separate gates.
use super::*;
use crate::audit_authority::AuditAuthorityError;
use crate::consensus::audit_mutation::joint_running::tests::prepared_for_store;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use opc_crypto::{ConfigCapacityProfile, ConfigPreparationPool};

#[tokio::test]
async fn joint_submission_guard_survives_native_acceptance_cancellation_and_retained_readback() {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("joint-submission-ownership-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout).unwrap().trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let topology = topology();
    let binding = RetainedConfigBinding::new(topology.clone(), [0x91; 32], [0x92; 32])
        .unwrap()
        .with_capacity_profile(ConfigCapacityProfile::BoundedV1);
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .unwrap();
    let key = AuditKey::new([0x93; 32]).unwrap();
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .unwrap();
    let store =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .unwrap();
    store.initialize_cluster().await.unwrap();
    let formation = tokio::time::Instant::now() + store.inner.operation_timeout;
    store.wait_for_known_leader(formation).await.unwrap();
    assert!(matches!(
        store.local_read_barrier(formation).await,
        ReadBarrierReply::Ready(_)
    ));
    let pool = &store.inner.preparation_admission;
    let foreign = ConfigPreparationPool::bounded_v1();
    let wrong = prepared_for_store(&foreign, store.inner.identity, &key).await;
    assert!(
        matches!(
            store.begin_netconf_target_submission(&wrong),
            Err(AuditAuthorityError::InvalidInput)
        ),
        "JOINT_NATIVE_DESTINATION_POOL"
    );
    drop(wrong);
    let held: Vec<_> = (0..7)
        .map(|_| store.try_reserve_config_preparation().unwrap().unwrap())
        .collect();
    let prepared = prepared_for_store(pool, store.inner.identity, &key).await;
    let original = prepared.encode().unwrap();
    let caller = prepared.command().effect.caller;
    prepared
        .verify_bounded_running(&key, store.inner.identity, caller)
        .unwrap();
    let expected = prepared.bounded_running().unwrap().commit().record.clone();
    let retained_command = prepared.command().clone();
    let ownership = store
        .begin_netconf_target_submission(&prepared)
        .expect("JOINT_STORE_RETAINS_ORIGINAL_GUARD");
    assert!(ownership.is_some(), "JOINT_NATIVE_GUARD_PRESENT");
    assert!(
        store.begin_netconf_target_submission(&prepared).is_err(),
        "one active original attempt"
    );
    let payload = prepared.bounded_running().unwrap();
    let intent = ConfigMutationIntent::BoundedAppend {
        commit: Box::new(payload.commit().clone()),
        resolution: None,
        binding: *payload.binding(),
    };
    // Only deterministic data remains locally when the actual native owner is accepted.
    drop(prepared);
    let hook = Arc::new(config_capacity_accepted_tests::ProposalTestGate::unblocked());
    *store.inner.proposal_test_gate.lock().unwrap() = Some(Arc::clone(&hook));
    let held_apply = Arc::clone(&store.inner.backend.consensus_apply_gate)
        .acquire_owned()
        .await
        .unwrap();
    let mut metrics = store.inner.raft.metrics();
    let before = metrics.borrow().last_log_index.unwrap_or(0);
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    let task_store = store.clone();
    let task = tokio::spawn(async move {
        task_store
            .submit_owned_request_on_local_leader(
                opc_consensus::ConsensusRequestId::from_bytes([0x94; 16]),
                intent,
                ownership,
            )
            .await
    });
    tokio::time::timeout_at(deadline, async {
        loop {
            if metrics
                .borrow_and_update()
                .last_log_index
                .is_some_and(|index| index > before)
                && hook.accepted.load(std::sync::atomic::Ordering::SeqCst) == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("real native accepted log within original deadline");
    assert!(store.inner.backend.load_latest().await.unwrap().is_none());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let retained_after_cancel = pool.try_reserve().is_err();
    drop(held_apply);
    let completed = tokio::time::timeout_at(
        deadline,
        Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let released = pool.try_reserve().expect("JOINT_NATIVE_COMPLETION_RELEASE");
    assert!(
        pool.try_reserve().is_err(),
        "one original releases exactly one slot"
    );
    drop(released);
    drop(completed);
    let readback = store.load_latest().await.unwrap().unwrap();
    assert!(
        readback.record == expected,
        "same encrypted record applied through native store"
    );
    assert_eq!(
        serde_json::to_vec(&retained_command).unwrap(),
        original,
        "native lifecycle never alters target original"
    );
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("joint-payload-test").unwrap(),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("synthetic"),
            opc_key::Zeroizing::new([0x71; 32]),
        )
        .unwrap();
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&readback.record.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let plaintext = opc_crypto::decrypt_envelope(&provider, &aad, &readback.record.encrypted_blob)
        .await
        .unwrap();
    assert_eq!(plaintext.as_slice(), br#"{"enabled":true}"#);
    let retained = rusqlite::Connection::open_with_flags(
        root.join("config.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let rows: i64 = retained
        .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
        .unwrap();
    assert!(
        rows > 0,
        "retained native command rows do not own a process slot"
    );
    drop(retained);
    drop(held);
    let available: Vec<_> = (0..8).map(|_| pool.try_reserve().unwrap()).collect();
    assert!(pool.try_reserve().is_err());
    drop(available);
    store.shutdown().await.unwrap();
    drop(metrics);
    drop(store);
    let reopened = SqliteBackend::reopen_config_authority(options, key)
        .await
        .unwrap();
    assert!(reopened.load_latest().await.unwrap().unwrap().record == expected);
    assert!(
        retained_after_cancel,
        "JOINT_NATIVE_ACCEPTED_OWNER_AFTER_CANCEL"
    );
}
