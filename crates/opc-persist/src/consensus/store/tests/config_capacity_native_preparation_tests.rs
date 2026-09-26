//! Native Durable singleton cancellation controls for both capacity profiles.
//! Legacy retains its original private-pool control; BoundedV1 uses public
//! store admission and an at-limit encrypted input. No fan-out or RSS claim.

use super::*;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use opc_crypto::ConfigCapacityProfile;

#[tokio::test]
async fn config_capacity_957_native_accepted_preparation_survives_caller_cancellation() {
    run_native_cancellation(ConfigCapacityProfile::Legacy).await;
}

#[tokio::test]
async fn config_capacity_957_bounded_native_accepted_preparation_survives_caller_cancellation() {
    run_native_cancellation(ConfigCapacityProfile::BoundedV1).await;
}

async fn run_native_cancellation(profile: ConfigCapacityProfile) {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-preparation-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let topology = topology();
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x69; 32], [0x6A; 32])
            .expect("binding")
            .with_capacity_profile(profile),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("native limits");
    let key = AuditKey::new([0x6B; 32]).expect("audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained backend");
    let store =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("profile-bound native store");
    assert_eq!(store.capacity_profile(), profile);
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton");
    let formation_deadline = tokio::time::Instant::now()
        .checked_add(store.inner.operation_timeout)
        .expect("unchanged formation budget");
    store
        .wait_for_known_leader(formation_deadline)
        .await
        .expect("natural singleton leadership");
    assert!(matches!(
        store.local_read_barrier(formation_deadline).await,
        ReadBarrierReply::Ready(_)
    ));

    let pool = &store.inner.preparation_admission;
    let _other_preparations: Vec<_> = (0..7)
        .map(|_| pool.try_reserve().expect("other preparation"))
        .collect();
    let (mut record, _, _) = sized_attested_commit(32).into_parts();
    let principal = record.principal.clone();
    let aad = opc_key::EnvelopeAad::config(
        opc_types::TenantId::from_static("test"),
        record.version.get(),
        opc_key::ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &principal,
            record.schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-preparation").expect("key ID"),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("test"),
            opc_key::Zeroizing::new([0x6C; 32]),
        )
        .expect("synthetic provider");
    let reservation = if profile == ConfigCapacityProfile::BoundedV1 {
        store
            .try_reserve_config_preparation()
            .expect("public destination admission")
            .expect("bounded store reservation")
    } else {
        pool.try_reserve()
            .expect("original legacy private-pool control")
    };
    let plaintext = if profile == ConfigCapacityProfile::BoundedV1 {
        let bytes =
            serde_json::to_vec(&"x".repeat(1_572_864 - 2)).expect("at-limit synthetic JSON");
        assert_eq!(bytes.len(), 1_572_864);
        bytes
    } else {
        br#"{"synthetic":true}"#.to_vec()
    };
    let encrypted = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        &plaintext,
    )
    .await
    .expect("reserved authenticated encryption");
    record.encrypted_blob = encrypted.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let expected = record.clone();
    let commit =
        AttestedConfigCommit::try_new(record, Vec::new(), encrypted.claim().expect("claim"))
            .expect("reserved attestation");
    drop(encrypted);
    let operation = store
        .prepare_recoverable_commit(
            opc_consensus::ConsensusRequestId::from_bytes([0x6D; 16]),
            commit,
            &principal,
        )
        .expect("prepare exact ordinary operation");
    let handle = operation.recovery_handle().clone();
    assert!(
        pool.try_reserve().is_err(),
        "prepared operation retains its reservation"
    );

    let held_apply = Arc::clone(&store.inner.backend.consensus_apply_gate)
        .acquire_owned()
        .await
        .expect("hold only this fixture's apply boundary");
    let mut metrics = store.inner.raft.metrics();
    let before = metrics.borrow().last_log_index.unwrap_or(0);
    let deadline = tokio::time::Instant::now()
        .checked_add(store.inner.operation_timeout)
        .expect("unchanged operation budget");
    let task_store = store.clone();
    let caller =
        tokio::spawn(async move { task_store.append_prepared_commit_local(operation).await });
    tokio::time::timeout_at(deadline, async {
        loop {
            if metrics
                .borrow_and_update()
                .last_log_index
                .is_some_and(|index| index > before)
            {
                break;
            }
            metrics.changed().await.expect("live engine metrics");
        }
    })
    .await
    .expect("proposal reaches native log within original deadline");
    caller.abort();
    assert!(caller.await.expect_err("cancelled caller").is_cancelled());
    assert!(
        pool.try_reserve().is_err(),
        "accepted work retains capacity after caller cancellation"
    );
    assert!(store
        .inner
        .backend
        .load_latest()
        .await
        .expect("pre-apply read")
        .is_none());
    drop(held_apply);
    let completed = tokio::time::timeout_at(
        deadline,
        Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
            u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS).expect("proposal slots"),
        ),
    )
    .await
    .expect("supervisor completes within original budget")
    .expect("admission remains open");
    let released = pool
        .try_reserve()
        .expect("accepted completion releases preparation");
    assert!(
        pool.try_reserve().is_err(),
        "only one preparation was released"
    );
    drop(released);
    drop(completed);
    let readback = store
        .load_latest()
        .await
        .expect("linearizable readback")
        .expect("committed record");
    assert!(
        readback.record == expected,
        "exact committed encrypted record"
    );
    let decrypted = opc_crypto::decrypt_envelope(&provider, &aad, &readback.record.encrypted_blob)
        .await
        .expect("decrypt exact native committed record");
    assert!(
        decrypted.as_slice() == plaintext.as_slice(),
        "exact logical readback"
    );
    assert!(matches!(
        store
            .lookup_commit_operation(&handle, &principal)
            .await
            .expect("read-only exact recovery"),
        super::super::recovery::ConfigCommitRecoveryOutcome::Committed
    ));
    let retained = rusqlite::Connection::open_with_flags(
        root.join("config.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read retained native log");
    let rows: i64 = retained
        .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
        .expect("retained entry count");
    assert!(rows > 0, "retained entries do not pin preparation capacity");
    drop(retained);
    store.shutdown().await.expect("stop native engine");
    drop(metrics);
    drop(store);
    let reopened = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("retained reopen");
    assert!(
        reopened
            .load_latest()
            .await
            .expect("reopened readback")
            .expect("retained record")
            .record
            == expected,
        "exact retained encrypted record"
    );
}
