use std::str::FromStr;
use std::sync::Arc;

use opc_amf_lite::AmfConfig;
use opc_config_bus::{
    CommitWrite, EncryptingManagedDatastore, ManagedDatastore, StoreErrorCode, StoredConfig,
    StoredRequestFingerprint, StoredRequestMode,
};
use opc_config_bus_consensus::RaftManagedDatastore;
use opc_config_model::{
    ApplyPlan, AuthStrength, ConfigOperation, IdempotencyKey, RequestId, RequestSource,
    RollbackTarget, TransportType, TrustedPrincipal, WorkloadIdentity, YangPath,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_types::{ConfigVersion, TenantId, Timestamp, TxId};

mod config_consensus_common;
use config_consensus_common::ConfigCluster;

type EncryptedConfigStore =
    EncryptingManagedDatastore<AmfConfig, MemoryKeyProvider, RaftManagedDatastore<AmfConfig>>;

fn tx_id(value: &str) -> TxId {
    TxId::from_str(value).expect("fixed transaction ID")
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).expect("fixed timestamp")
}

fn tenant() -> TenantId {
    TenantId::new("restart-lifecycle-tenant").expect("test tenant")
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("restart-lifecycle-writer".to_owned()),
        tenant(),
    )
    .with_auth_strength(AuthStrength::MutualTls)
    .with_roles(["config-admin", "config-auditor"])
    .with_groups(["network-operations"])
}

fn provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("restart-lifecycle-config-key").expect("config key ID"),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0x6D; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert config key");
    provider
}

fn encrypted_store(
    cluster: &ConfigCluster,
    index: usize,
    provider: &Arc<MemoryKeyProvider>,
) -> EncryptedConfigStore {
    let raw = Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
        cluster.stores[index].clone(),
    )));
    EncryptingManagedDatastore::new(raw, Arc::clone(provider))
}

fn config(hostname: &str, capacity: u32) -> AmfConfig {
    AmfConfig {
        hostname: hostname.to_owned(),
        nrf_endpoint: "https://nrf.restart-lifecycle.invalid".to_owned(),
        plmn_id: "00101".to_owned(),
        capacity,
    }
}

fn record(
    tx_id: TxId,
    parent_tx_id: Option<TxId>,
    version: u64,
    committed_at: Timestamp,
    config: AmfConfig,
) -> StoredConfig<AmfConfig> {
    let mut record = StoredConfig::new(
        tx_id,
        ConfigVersion::new(version),
        principal(),
        RequestSource::Replication,
        config,
    );
    record.parent_tx_id = parent_tx_id;
    record.committed_at = committed_at;
    record
}

fn assert_exact_record(expected: &StoredConfig<AmfConfig>, actual: &StoredConfig<AmfConfig>) {
    let StoredConfig {
        tx_id: expected_tx_id,
        parent_tx_id: expected_parent_tx_id,
        version: expected_version,
        committed_at: expected_committed_at,
        principal: expected_principal,
        source: expected_source,
        schema_digest: expected_schema_digest,
        plaintext_digest: expected_plaintext_digest,
        config: expected_config,
        encrypted_blob: expected_encrypted_blob,
        idempotency_key: expected_idempotency_key,
        apply_plan: expected_apply_plan,
        request_fingerprint: expected_request_fingerprint,
        request_id: expected_request_id,
        recovery_required: expected_recovery_required,
        confirmed_deadline: expected_confirmed_deadline,
        rollback_label: expected_rollback_label,
    } = expected;
    let StoredConfig {
        tx_id: actual_tx_id,
        parent_tx_id: actual_parent_tx_id,
        version: actual_version,
        committed_at: actual_committed_at,
        principal: actual_principal,
        source: actual_source,
        schema_digest: actual_schema_digest,
        plaintext_digest: actual_plaintext_digest,
        config: actual_config,
        encrypted_blob: actual_encrypted_blob,
        idempotency_key: actual_idempotency_key,
        apply_plan: actual_apply_plan,
        request_fingerprint: actual_request_fingerprint,
        request_id: actual_request_id,
        recovery_required: actual_recovery_required,
        confirmed_deadline: actual_confirmed_deadline,
        rollback_label: actual_rollback_label,
    } = actual;

    assert_eq!(expected_tx_id, actual_tx_id, "tx_id");
    assert_eq!(expected_parent_tx_id, actual_parent_tx_id, "parent_tx_id");
    assert_eq!(expected_version, actual_version, "version");
    assert_eq!(expected_committed_at, actual_committed_at, "committed_at");
    assert_eq!(expected_principal, actual_principal, "principal");
    assert_eq!(expected_source, actual_source, "source");
    assert_eq!(
        expected_schema_digest, actual_schema_digest,
        "schema_digest"
    );
    assert_eq!(
        expected_plaintext_digest, actual_plaintext_digest,
        "plaintext_digest"
    );
    assert_eq!(expected_config, actual_config, "config");
    assert_eq!(
        expected_encrypted_blob, actual_encrypted_blob,
        "encrypted_blob"
    );
    assert_eq!(
        expected_idempotency_key, actual_idempotency_key,
        "idempotency_key"
    );
    assert_eq!(expected_apply_plan, actual_apply_plan, "apply_plan");
    assert_eq!(
        expected_request_fingerprint, actual_request_fingerprint,
        "request_fingerprint"
    );
    assert_eq!(expected_request_id, actual_request_id, "request_id");
    assert_eq!(
        expected_recovery_required, actual_recovery_required,
        "recovery_required"
    );
    assert_eq!(
        expected_confirmed_deadline, actual_confirmed_deadline,
        "confirmed_deadline"
    );
    assert_eq!(
        expected_rollback_label, actual_rollback_label,
        "rollback_label"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_record_metadata_and_payload_survive_full_consensus_restart_exactly() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let cluster = ConfigCluster::start(temp.path()).await;
    let provider = provider();
    let encrypted = encrypted_store(&cluster, 0, &provider);
    let changed_path = YangPath::new("/amf/hostname").expect("changed path");
    let request_id =
        RequestId::from_str("4ac5b760-d50e-4c09-91ca-b338d46ff269").expect("fixed request ID");
    let mut committed = record(
        tx_id("11111111-1111-4111-8111-111111111111"),
        None,
        1,
        timestamp("2026-07-16T18:30:00Z"),
        config("encrypted-restart-exact", 4_096),
    );
    committed.idempotency_key =
        Some(IdempotencyKey::new("restart-lifecycle-replay").expect("idempotency key"));
    committed.apply_plan = Some(ApplyPlan::default_hot(
        vec![changed_path.clone()],
        Some(RollbackTarget::TxId(committed.tx_id)),
    ));
    committed.request_fingerprint = Some(StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: StoredRequestMode::CommitConfirmed {
            timeout: std::time::Duration::from_secs(300),
        },
        transport: TransportType::NetconfTls,
        changed_paths: vec![changed_path],
        base_version: Some(ConfigVersion::new(0)),
    });
    committed.request_id = Some(request_id);
    committed.recovery_required = true;
    committed.confirmed_deadline = Some(timestamp("2036-07-16T18:30:00Z"));
    committed.rollback_label = Some("restart-lifecycle-rich-record".to_owned());

    encrypted
        .append_commit_write(CommitWrite::new(committed.clone()))
        .await
        .expect("append rich encrypted record");
    let before_restart = encrypted
        .load_latest()
        .await
        .expect("load rich record before restart")
        .expect("rich record before restart");
    assert_eq!(committed.config, before_restart.config);
    assert_eq!(committed.source, before_restart.source);
    assert_eq!(committed.idempotency_key, before_restart.idempotency_key);
    assert_eq!(committed.apply_plan, before_restart.apply_plan);
    assert_eq!(
        committed.request_fingerprint,
        before_restart.request_fingerprint
    );
    assert_eq!(committed.request_id, before_restart.request_id);
    assert!(before_restart.plaintext_digest.is_some());
    assert!(!before_restart.encrypted_blob.is_empty());

    drop(encrypted);
    cluster.shutdown().await;
    drop(cluster);

    let restarted = ConfigCluster::start(temp.path()).await;
    let restarted_encrypted = encrypted_store(&restarted, 1, &provider);
    let after_restart = restarted_encrypted
        .load_latest()
        .await
        .expect("load rich record after restart")
        .expect("rich record after restart");
    assert_exact_record(&before_restart, &after_restart);

    restarted.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_lifecycle_rolls_back_on_replacement_leader_and_survives_restart() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let cluster = ConfigCluster::start(temp.path()).await;
    let provider = provider();
    let initial_store = encrypted_store(&cluster, 0, &provider);
    let stable_tx = tx_id("22222222-2222-4222-8222-222222222222");
    let pending_tx = tx_id("33333333-3333-4333-8333-333333333333");
    let rollback_tx = tx_id("44444444-4444-4444-8444-444444444444");

    let mut stable = record(
        stable_tx,
        None,
        1,
        timestamp("2026-07-16T18:31:00Z"),
        config("stable-parent", 2_048),
    );
    stable.recovery_required = true;
    stable.confirmed_deadline = Some(timestamp("2036-07-16T18:31:00Z"));
    initial_store
        .append_commit_write(CommitWrite::new(stable))
        .await
        .expect("append initially pending stable record");
    initial_store
        .mark_confirmed(stable_tx)
        .await
        .expect("durably confirm stable record");
    initial_store
        .clear_recovery_required(stable_tx)
        .await
        .expect("durably clear stable recovery marker");
    let stable_applied = initial_store
        .load_latest()
        .await
        .expect("load stable record")
        .expect("stable record");
    assert_eq!(stable_tx, stable_applied.tx_id);
    assert!(!stable_applied.recovery_required);
    assert_eq!(None, stable_applied.confirmed_deadline);

    let mut pending = record(
        pending_tx,
        Some(stable_tx),
        2,
        timestamp("2026-07-16T18:32:00Z"),
        config("pending-must-not-survive", 8_192),
    );
    pending.confirmed_deadline = Some(timestamp("2036-07-16T18:32:00Z"));
    initial_store
        .append_commit_write(CommitWrite::new(pending))
        .await
        .expect("append pending record");

    cluster.wait_ready().await;
    let old_leader = cluster.leader();
    let old_status = cluster.stores[old_leader].status();
    cluster.isolate(old_leader);
    let ready_survivor = cluster.wait_for_survivor_leader(old_leader).await;
    let replacement_id = cluster.stores[ready_survivor]
        .status()
        .leader_id
        .expect("replacement leader ID");
    let replacement = cluster
        .stores
        .iter()
        .position(|store| store.status().node_id == replacement_id)
        .expect("replacement leader index");
    let replacement_status = cluster.stores[replacement].status();
    assert_eq!(
        Some(replacement_status.node_id),
        replacement_status.leader_id
    );
    assert_ne!(old_status.node_id, replacement_status.node_id);
    assert!(replacement_status.term > old_status.term);
    let replacement_store = encrypted_store(&cluster, replacement, &provider);

    let pending_on_replacement = replacement_store
        .load_latest()
        .await
        .expect("load pending record on replacement leader")
        .expect("pending record on replacement leader");
    assert_eq!(pending_tx, pending_on_replacement.tx_id);
    assert!(pending_on_replacement.confirmed_deadline.is_some());
    let pending_target_error = match replacement_store
        .load_rollback(RollbackTarget::TxId(pending_tx))
        .await
    {
        Ok(_) => panic!("pending record cannot be a rollback target"),
        Err(error) => error,
    };
    assert_eq!(StoreErrorCode::NotFound, pending_target_error.code);

    let stable_parent = replacement_store
        .load_rollback(RollbackTarget::TxId(stable_tx))
        .await
        .expect("load actual stable parent on replacement leader");
    assert_exact_record(&stable_applied, &stable_parent);
    let mut rollback = record(
        rollback_tx,
        Some(pending_tx),
        3,
        timestamp("2026-07-16T18:33:00Z"),
        stable_parent.config.clone(),
    );
    rollback.recovery_required = true;
    replacement_store
        .append_commit_write(
            CommitWrite::resolving(
                rollback,
                opc_config_bus::ConfirmedCommitResolution::Rollback {
                    pending_tx_id: pending_tx,
                },
            )
            .expect("rollback write shape"),
        )
        .await
        .expect("commit rollback on replacement leader");
    replacement_store
        .clear_recovery_required(rollback_tx)
        .await
        .expect("durably clear rollback recovery marker");
    let rollback_applied = replacement_store
        .load_latest()
        .await
        .expect("load rollback record")
        .expect("rollback record");
    assert_eq!(rollback_tx, rollback_applied.tx_id);
    assert_eq!(stable_parent.config, rollback_applied.config);
    assert_ne!(pending_on_replacement.config, rollback_applied.config);
    assert!(!rollback_applied.recovery_required);
    assert_eq!(None, rollback_applied.confirmed_deadline);

    let stale_confirmation = replacement_store
        .mark_confirmed(pending_tx)
        .await
        .expect_err("rolled-back pending transaction cannot be confirmed");
    assert_eq!(StoreErrorCode::Internal, stale_confirmation.code);
    let after_stale_confirmation = replacement_store
        .load_latest()
        .await
        .expect("load head after stale confirmation")
        .expect("head after stale confirmation");
    assert_exact_record(&rollback_applied, &after_stale_confirmation);

    drop(initial_store);
    drop(replacement_store);
    cluster.shutdown().await;
    drop(cluster);

    let restarted = ConfigCluster::start(temp.path()).await;
    for index in 0..3 {
        let restarted_store = encrypted_store(&restarted, index, &provider);
        let restarted_latest = restarted_store
            .load_latest()
            .await
            .expect("load rollback head after full restart")
            .expect("rollback head after full restart");
        assert_exact_record(&rollback_applied, &restarted_latest);
        let restarted_stable = restarted_store
            .load_rollback(RollbackTarget::TxId(stable_tx))
            .await
            .expect("load confirmed stable metadata after full restart");
        assert_exact_record(&stable_applied, &restarted_stable);
        let pending_error = match restarted_store
            .load_rollback(RollbackTarget::TxId(pending_tx))
            .await
        {
            Ok(_) => panic!("rolled-back pending record remains unavailable after restart"),
            Err(error) => error,
        };
        assert_eq!(StoreErrorCode::NotFound, pending_error.code);
    }

    restarted.shutdown().await;
}
