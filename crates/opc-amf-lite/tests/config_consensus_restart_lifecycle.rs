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
use config_consensus_common::{ConfigCluster, ConfigClusterLifecycleError, ConfigNodeLifecycle};

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

fn assert_exact_history(expected: &[StoredConfig<AmfConfig>], actual: &[StoredConfig<AmfConfig>]) {
    assert_eq!(expected.len(), actual.len(), "history length");
    for (expected_record, actual_record) in expected.iter().zip(actual) {
        assert_exact_record(expected_record, actual_record);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableReopenEvidenceError {
    EmptyExpectedHistory,
    EmptyReopenedHistory,
    HistoryMismatch,
}

fn records_match_exactly(
    expected: &StoredConfig<AmfConfig>,
    actual: &StoredConfig<AmfConfig>,
) -> bool {
    expected.tx_id == actual.tx_id
        && expected.parent_tx_id == actual.parent_tx_id
        && expected.version == actual.version
        && expected.committed_at == actual.committed_at
        && expected.principal == actual.principal
        && expected.source == actual.source
        && expected.schema_digest == actual.schema_digest
        && expected.plaintext_digest == actual.plaintext_digest
        && expected.config == actual.config
        && expected.encrypted_blob == actual.encrypted_blob
        && expected.idempotency_key == actual.idempotency_key
        && expected.apply_plan == actual.apply_plan
        && expected.request_fingerprint == actual.request_fingerprint
        && expected.request_id == actual.request_id
        && expected.recovery_required == actual.recovery_required
        && expected.confirmed_deadline == actual.confirmed_deadline
        && expected.rollback_label == actual.rollback_label
}

fn verify_nonempty_exact_reopened_history(
    expected: &[StoredConfig<AmfConfig>],
    actual: &[StoredConfig<AmfConfig>],
) -> Result<(), DurableReopenEvidenceError> {
    if expected.is_empty() {
        return Err(DurableReopenEvidenceError::EmptyExpectedHistory);
    }
    if actual.is_empty() {
        return Err(DurableReopenEvidenceError::EmptyReopenedHistory);
    }
    if expected.len() != actual.len()
        || expected
            .iter()
            .zip(actual)
            .any(|(expected_record, actual_record)| {
                !records_match_exactly(expected_record, actual_record)
            })
    {
        return Err(DurableReopenEvidenceError::HistoryMismatch);
    }
    Ok(())
}

#[test]
fn durable_reopen_evidence_rejects_fresh_empty_state() {
    let expected = [record(
        tx_id("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        None,
        1,
        timestamp("2026-07-16T18:59:00Z"),
        config("must-exist-on-reopened-disk", 512),
    )];
    assert_eq!(
        Err(DurableReopenEvidenceError::EmptyReopenedHistory),
        verify_nonempty_exact_reopened_history(&expected, &[])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_record_metadata_and_payload_survive_full_consensus_restart_exactly() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let mut cluster = ConfigCluster::start(temp.path()).await;
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
    cluster.shutdown().await.expect("shutdown config cluster");
    drop(cluster);

    let mut restarted = ConfigCluster::start(temp.path()).await;
    let restarted_encrypted = encrypted_store(&restarted, 1, &provider);
    let after_restart = restarted_encrypted
        .load_latest()
        .await
        .expect("load rich record after restart")
        .expect("rich record after restart");
    assert_exact_record(&before_restart, &after_restart);

    restarted
        .shutdown()
        .await
        .expect("shutdown restarted config cluster");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_parent_appends_have_one_state_machine_winner() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let mut cluster = ConfigCluster::start(temp.path()).await;
    let provider = provider();
    let genesis_tx = tx_id("55555555-5555-4555-8555-555555555555");
    let contender_a_tx = tx_id("66666666-6666-4666-8666-666666666666");
    let contender_b_tx = tx_id("77777777-7777-4777-8777-777777777777");
    let writer_a = encrypted_store(&cluster, 0, &provider);
    let writer_b = encrypted_store(&cluster, 1, &provider);

    writer_a
        .append_commit_write(CommitWrite::new(record(
            genesis_tx,
            None,
            1,
            timestamp("2026-07-16T18:34:00Z"),
            config("lineage-genesis", 1_024),
        )))
        .await
        .expect("append lineage genesis");
    cluster.wait_ready().await;

    let contender_a = record(
        contender_a_tx,
        Some(genesis_tx),
        2,
        timestamp("2026-07-16T18:35:00Z"),
        config("lineage-contender-a", 2_048),
    );
    let contender_b = record(
        contender_b_tx,
        Some(genesis_tx),
        2,
        timestamp("2026-07-16T18:36:00Z"),
        config("lineage-contender-b", 4_096),
    );

    let (result_a, result_b) = tokio::join!(
        writer_a.append_commit_write(CommitWrite::new(contender_a)),
        writer_b.append_commit_write(CommitWrite::new(contender_b)),
    );
    let (winner_tx, loser_tx) = match (result_a, result_b) {
        (Ok(()), Err(error)) => {
            assert_eq!(StoreErrorCode::Internal, error.code);
            (contender_a_tx, contender_b_tx)
        }
        (Err(error), Ok(())) => {
            assert_eq!(StoreErrorCode::Internal, error.code);
            (contender_b_tx, contender_a_tx)
        }
        (Ok(()), Ok(())) => panic!("same-parent contenders must not both apply"),
        (Err(error_a), Err(error_b)) => {
            panic!("one same-parent contender must apply: {error_a}; {error_b}")
        }
    };

    cluster.wait_ready().await;
    for index in 0..3 {
        let reader = encrypted_store(&cluster, index, &provider);
        let history = reader
            .load_since(ConfigVersion::INITIAL, 4)
            .await
            .expect("load converged config history");
        assert_eq!(2, history.len());
        assert_eq!(genesis_tx, history[0].tx_id);
        assert_eq!(None, history[0].parent_tx_id);
        assert_eq!(ConfigVersion::new(1), history[0].version);
        assert_eq!(winner_tx, history[1].tx_id);
        assert_eq!(Some(genesis_tx), history[1].parent_tx_id);
        assert_eq!(ConfigVersion::new(2), history[1].version);
        assert!(history.iter().all(|record| record.tx_id != loser_tx));
    }

    cluster.shutdown().await.expect("shutdown config cluster");
    for node in 0..3 {
        assert_eq!(
            ConfigNodeLifecycle::Shutdown,
            cluster.node_lifecycle(node).expect("final node lifecycle")
        );
    }
    cluster
        .shutdown()
        .await
        .expect("final shutdown must not stop an engine twice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopped_follower_reopens_same_disk_and_rejoins_live_encrypted_lineage() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let mut cluster = ConfigCluster::start(temp.path()).await;
    let provider = provider();
    let genesis_tx = tx_id("88888888-8888-4888-8888-888888888888");
    let outage_tx = tx_id("99999999-9999-4999-8999-999999999999");
    let rejoined_tx = tx_id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let leader = cluster.leader();
    let stopped_follower = (0..3)
        .find(|node| *node != leader)
        .expect("follower to stop");
    let survivors = (0..3)
        .filter(|node| *node != stopped_follower)
        .collect::<Vec<_>>();
    let stopped_identity = cluster.stores[stopped_follower].status().node_id;
    let stopped_database = cluster.database_path(stopped_follower);
    assert_eq!(
        ConfigClusterLifecycleError::InvalidState {
            expected: ConfigNodeLifecycle::Stopped,
            actual: ConfigNodeLifecycle::Running,
        },
        cluster
            .reopen_node_disconnected(stopped_follower)
            .await
            .expect_err("a running identity cannot be reopened")
    );

    let genesis = record(
        genesis_tx,
        None,
        1,
        timestamp("2026-07-16T19:00:00Z"),
        config("PAYLOAD-CANARY-REJOIN-GENESIS-0xA1", 1_024),
    );
    encrypted_store(&cluster, leader, &provider)
        .append_commit_write(CommitWrite::new(genesis))
        .await
        .expect("append encrypted genesis");
    cluster.wait_ready().await;
    assert!(stopped_database.is_file(), "follower database must exist");
    let pre_stop_status = cluster.stores[stopped_follower].status();
    assert!(pre_stop_status.applied_index.is_some_and(|index| index > 0));
    assert!(pre_stop_status
        .committed_index
        .is_some_and(|index| index > 0));
    let pre_stop_history = encrypted_store(&cluster, stopped_follower, &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load follower-local history before stop");
    assert_eq!(1, pre_stop_history.len());
    assert_eq!(genesis_tx, pre_stop_history[0].tx_id);

    cluster
        .stop_node(stopped_follower)
        .await
        .expect("stop actual follower engine");
    assert_eq!(
        ConfigNodeLifecycle::Stopped,
        cluster
            .node_lifecycle(stopped_follower)
            .expect("stopped lifecycle")
    );
    assert!(cluster
        .node_transport_is_disconnected(stopped_follower)
        .await
        .expect("stopped transport state"));
    assert_eq!(
        ConfigClusterLifecycleError::InvalidState {
            expected: ConfigNodeLifecycle::Running,
            actual: ConfigNodeLifecycle::Stopped,
        },
        cluster
            .stop_node(stopped_follower)
            .await
            .expect_err("the stopped engine cannot be stopped twice")
    );
    assert!(cluster.stores[stopped_follower]
        .probe_durable_readiness()
        .await
        .is_err());
    let (first_survivor_ready, second_survivor_ready) = tokio::join!(
        cluster.stores[survivors[0]].probe_durable_readiness(),
        cluster.stores[survivors[1]].probe_durable_readiness(),
    );
    first_survivor_ready.expect("first survivor remains durable-ready");
    second_survivor_ready.expect("second survivor remains durable-ready");

    let mut outage = record(
        outage_tx,
        Some(genesis_tx),
        2,
        timestamp("2026-07-16T19:01:00Z"),
        config("PAYLOAD-CANARY-REJOIN-OUTAGE-0xB2", 2_048),
    );
    outage.idempotency_key =
        Some(IdempotencyKey::new("single-rejoin-outage").expect("idempotency key"));
    outage.rollback_label = Some("single-rejoin-outage-head".to_owned());
    encrypted_store(&cluster, survivors[0], &provider)
        .append_commit_write(CommitWrite::new(outage))
        .await
        .expect("surviving quorum appends while follower is stopped");
    let outage_head = encrypted_store(&cluster, survivors[1], &provider)
        .load_latest()
        .await
        .expect("surviving quorum reads while follower is stopped")
        .expect("outage head");
    assert_eq!(outage_tx, outage_head.tx_id);
    assert_eq!(Some(genesis_tx), outage_head.parent_tx_id);
    assert_eq!(ConfigVersion::new(2), outage_head.version);
    assert_eq!(
        Some("single-rejoin-outage-head"),
        outage_head.rollback_label.as_deref()
    );

    cluster
        .reopen_node_disconnected(stopped_follower)
        .await
        .expect("reopen same disk with transport disconnected");
    assert_eq!(
        ConfigNodeLifecycle::ReopenedDisconnected,
        cluster
            .node_lifecycle(stopped_follower)
            .expect("disconnected reopened lifecycle")
    );
    assert!(cluster
        .node_transport_is_disconnected(stopped_follower)
        .await
        .expect("reopened transport state"));
    assert_eq!(
        ConfigClusterLifecycleError::InvalidState {
            expected: ConfigNodeLifecycle::Stopped,
            actual: ConfigNodeLifecycle::ReopenedDisconnected,
        },
        cluster
            .reopen_node_disconnected(stopped_follower)
            .await
            .expect_err("one stable identity cannot be opened twice")
    );
    let disconnected_status = cluster.stores[stopped_follower].status();
    assert_eq!(
        stopped_identity, disconnected_status.node_id,
        "same stable node identity must reopen"
    );
    assert_eq!(
        pre_stop_status.applied_index,
        disconnected_status.applied_index
    );
    assert_eq!(
        pre_stop_status.committed_index,
        disconnected_status.committed_index
    );
    assert!(!disconnected_status.admitted);
    assert_eq!(stopped_database, cluster.database_path(stopped_follower));
    let disconnected_history = encrypted_store(&cluster, stopped_follower, &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load disconnected same-disk history");
    verify_nonempty_exact_reopened_history(&pre_stop_history, &disconnected_history)
        .expect("same-disk state must exist before network catch-up");
    assert!(disconnected_history
        .iter()
        .all(|record| record.tx_id != outage_tx));
    assert!(cluster.stores[stopped_follower]
        .probe_durable_readiness()
        .await
        .is_err());

    cluster
        .reconnect_node(stopped_follower)
        .await
        .expect("reconnect and re-admit reopened follower");
    assert_eq!(
        ConfigNodeLifecycle::Running,
        cluster
            .node_lifecycle(stopped_follower)
            .expect("reconnected lifecycle")
    );
    cluster.wait_ready().await;

    let caught_up_history = encrypted_store(&cluster, survivors[0], &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load survivor history after follower rejoin");
    assert_eq!(2, caught_up_history.len());
    assert_eq!(genesis_tx, caught_up_history[0].tx_id);
    assert_eq!(None, caught_up_history[0].parent_tx_id);
    assert_eq!(outage_tx, caught_up_history[1].tx_id);
    assert_eq!(Some(genesis_tx), caught_up_history[1].parent_tx_id);
    for node in 0..3 {
        let replica_history = encrypted_store(&cluster, node, &provider)
            .load_since(ConfigVersion::INITIAL, 8)
            .await
            .expect("load caught-up replica history");
        assert_exact_history(&caught_up_history, &replica_history);
    }

    let mut continued = record(
        rejoined_tx,
        Some(outage_tx),
        3,
        timestamp("2026-07-16T19:02:00Z"),
        config("PAYLOAD-CANARY-REJOIN-CONTINUED-0xC3", 4_096),
    );
    continued.idempotency_key =
        Some(IdempotencyKey::new("single-rejoin-continued").expect("idempotency key"));
    continued.rollback_label = Some("single-rejoin-continued-head".to_owned());
    encrypted_store(&cluster, stopped_follower, &provider)
        .append_commit_write(CommitWrite::new(continued))
        .await
        .expect("rejoined follower forwards continued commit");
    let continued_head = encrypted_store(&cluster, survivors[1], &provider)
        .load_latest()
        .await
        .expect("read continued commit from survivor")
        .expect("continued head");
    assert_eq!(rejoined_tx, continued_head.tx_id);
    assert_eq!(Some(outage_tx), continued_head.parent_tx_id);
    assert_eq!(ConfigVersion::new(3), continued_head.version);
    cluster.wait_ready().await;

    let complete_history = encrypted_store(&cluster, stopped_follower, &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load complete history from rejoined follower");
    assert_eq!(3, complete_history.len());
    for node in 0..3 {
        let replica_history = encrypted_store(&cluster, node, &provider)
            .load_since(ConfigVersion::INITIAL, 8)
            .await
            .expect("load complete replica history");
        assert_exact_history(&complete_history, &replica_history);
    }

    for plaintext in [
        b"PAYLOAD-CANARY-REJOIN-GENESIS-0xA1".as_slice(),
        b"PAYLOAD-CANARY-REJOIN-OUTAGE-0xB2".as_slice(),
        b"PAYLOAD-CANARY-REJOIN-CONTINUED-0xC3".as_slice(),
    ] {
        assert!(cluster.captured_frames().iter().all(|frame| !frame
            .windows(plaintext.len())
            .any(|window| window == plaintext)));
    }

    cluster.shutdown().await.expect("shutdown config cluster");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_lifecycle_rolls_back_on_replacement_leader_and_survives_restart() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let mut cluster = ConfigCluster::start(temp.path()).await;
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
    cluster.shutdown().await.expect("shutdown config cluster");
    drop(cluster);

    let mut restarted = ConfigCluster::start(temp.path()).await;
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

    restarted
        .shutdown()
        .await
        .expect("shutdown restarted config cluster");
}
