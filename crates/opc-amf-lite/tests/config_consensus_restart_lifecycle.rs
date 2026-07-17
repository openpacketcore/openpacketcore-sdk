use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

mod config_consensus_common;
use config_consensus_common::{
    cluster_transition_timeout, ConfigCluster, ConfigClusterLifecycleError, ConfigNodeLifecycle,
};

type EncryptedConfigStore =
    EncryptingManagedDatastore<AmfConfig, MemoryKeyProvider, RaftManagedDatastore<AmfConfig>>;

const PROCESS_CRASH_CHILD_MODE_ENV: &str = "OPC_CONFIG_PROCESS_CRASH_CHILD_MODE";
const PROCESS_CRASH_CHILD_ROOT_ENV: &str = "OPC_CONFIG_PROCESS_CRASH_CHILD_ROOT";
const PROCESS_CRASH_CHILD_MODE: &str = "config-consensus-process-crash-v1";
const PROCESS_CRASH_EVIDENCE_FILE: &str = "process-crash-ready.sha256";
const PROCESS_CRASH_EVIDENCE_STAGING_FILE: &str = "process-crash-ready.sha256.part";
const PROCESS_CRASH_GENESIS_CANARY: &str = "PROCESS-CRASH-GENESIS-MUST-NOT-PERSIST-0xE1";
const PROCESS_CRASH_PAYLOAD_CANARY: &str = "PROCESS-CRASH-PAYLOAD-MUST-NOT-PERSIST-0xE2";

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

fn assert_plaintext_canaries_absent_from_bytes(location: &str, bytes: &[u8], canaries: &[&[u8]]) {
    for canary in canaries {
        assert!(
            !bytes.windows(canary.len()).any(|window| window == *canary),
            "plaintext canary reached {location}"
        );
    }
}

fn assert_plaintext_canaries_absent_from_tree(path: &Path, canaries: &[&[u8]]) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("read config artifact directory") {
            assert_plaintext_canaries_absent_from_tree(
                &entry.expect("config artifact entry").path(),
                canaries,
            );
        }
        return;
    }
    let bytes = std::fs::read(path).expect("read config artifact");
    assert_plaintext_canaries_absent_from_bytes(&path.display().to_string(), &bytes, canaries);
}

#[derive(serde::Serialize)]
struct ExactStoredConfigEvidence<'a> {
    tx_id: &'a TxId,
    parent_tx_id: &'a Option<TxId>,
    version: &'a ConfigVersion,
    committed_at: &'a Timestamp,
    principal: &'a TrustedPrincipal,
    source: &'a RequestSource,
    schema_digest: &'a SchemaDigest,
    plaintext_digest: &'a Option<[u8; 32]>,
    config: &'a AmfConfig,
    encrypted_blob: &'a [u8],
    idempotency_key: &'a Option<IdempotencyKey>,
    apply_plan: &'a Option<ApplyPlan>,
    request_fingerprint: &'a Option<StoredRequestFingerprint>,
    request_id: &'a Option<RequestId>,
    recovery_required: bool,
    confirmed_deadline: &'a Option<Timestamp>,
    rollback_label: &'a Option<String>,
}

fn exact_record_evidence_digest(record: &StoredConfig<AmfConfig>) -> [u8; 32] {
    let StoredConfig {
        tx_id,
        parent_tx_id,
        version,
        committed_at,
        principal,
        source,
        schema_digest,
        plaintext_digest,
        config,
        encrypted_blob,
        idempotency_key,
        apply_plan,
        request_fingerprint,
        request_id,
        recovery_required,
        confirmed_deadline,
        rollback_label,
    } = record;
    let evidence = ExactStoredConfigEvidence {
        tx_id,
        parent_tx_id,
        version,
        committed_at,
        principal,
        source,
        schema_digest,
        plaintext_digest,
        config,
        encrypted_blob,
        idempotency_key,
        apply_plan,
        request_fingerprint,
        request_id,
        recovery_required: *recovery_required,
        confirmed_deadline,
        rollback_label,
    };
    let encoded = serde_json::to_vec(&evidence).expect("serialize exact process-crash record");
    Sha256::digest(encoded).into()
}

fn process_crash_genesis_record() -> StoredConfig<AmfConfig> {
    record(
        tx_id("c2500001-2500-4250-8250-000000000001"),
        None,
        1,
        timestamp("2026-07-17T05:00:00Z"),
        config(PROCESS_CRASH_GENESIS_CANARY, 8_192),
    )
}

fn process_crash_rich_record() -> StoredConfig<AmfConfig> {
    let parent_tx_id = tx_id("c2500001-2500-4250-8250-000000000001");
    let rich_tx_id = tx_id("c2500002-2500-4250-8250-000000000002");
    let changed_path = YangPath::new("/amf/hostname").expect("changed path");
    let mut rich = record(
        rich_tx_id,
        Some(parent_tx_id),
        2,
        timestamp("2026-07-17T05:01:00Z"),
        config(PROCESS_CRASH_PAYLOAD_CANARY, 16_384),
    );
    rich.idempotency_key = Some(
        IdempotencyKey::new("process-crash-rich-record").expect("process-crash idempotency key"),
    );
    rich.apply_plan = Some(ApplyPlan::default_hot(
        vec![changed_path.clone()],
        Some(RollbackTarget::TxId(parent_tx_id)),
    ));
    rich.request_fingerprint = Some(StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: StoredRequestMode::CommitConfirmed {
            timeout: Duration::from_secs(600),
        },
        transport: TransportType::NetconfTls,
        changed_paths: vec![changed_path],
        base_version: Some(ConfigVersion::new(1)),
    });
    rich.request_id = Some(
        RequestId::from_str("c2500003-2500-4250-8250-000000000003")
            .expect("process-crash request ID"),
    );
    rich.recovery_required = true;
    rich.confirmed_deadline = Some(timestamp("2036-07-17T05:01:00Z"));
    rich.rollback_label = Some("process-crash-rich-record".to_owned());
    rich
}

fn assert_process_crash_rich_record(actual: &StoredConfig<AmfConfig>) {
    let expected = process_crash_rich_record();
    assert_eq!(expected.tx_id, actual.tx_id, "process-crash tx_id");
    assert_eq!(
        expected.parent_tx_id, actual.parent_tx_id,
        "process-crash parent_tx_id"
    );
    assert_eq!(expected.version, actual.version, "process-crash version");
    assert_eq!(
        expected.committed_at, actual.committed_at,
        "process-crash committed_at"
    );
    assert_eq!(
        expected.principal, actual.principal,
        "process-crash principal"
    );
    assert_eq!(expected.source, actual.source, "process-crash source");
    assert_eq!(
        expected.schema_digest, actual.schema_digest,
        "process-crash schema_digest"
    );
    assert_eq!(expected.config, actual.config, "process-crash config");
    assert_eq!(
        expected.idempotency_key, actual.idempotency_key,
        "process-crash idempotency_key"
    );
    assert_eq!(
        expected.apply_plan, actual.apply_plan,
        "process-crash apply_plan"
    );
    assert_eq!(
        expected.request_fingerprint, actual.request_fingerprint,
        "process-crash request_fingerprint"
    );
    assert_eq!(
        expected.request_id, actual.request_id,
        "process-crash request_id"
    );
    assert_eq!(
        expected.recovery_required, actual.recovery_required,
        "process-crash recovery_required"
    );
    assert_eq!(
        expected.confirmed_deadline, actual.confirmed_deadline,
        "process-crash confirmed_deadline"
    );
    assert_eq!(
        expected.rollback_label, actual.rollback_label,
        "process-crash rollback_label"
    );
    assert!(
        actual.plaintext_digest.is_some(),
        "process-crash plaintext digest must survive"
    );
    assert!(
        !actual.encrypted_blob.is_empty(),
        "process-crash ciphertext must survive"
    );
}

fn process_crash_child_deadline() -> Duration {
    let transition = cluster_transition_timeout();
    transition.saturating_add(transition)
}

fn publish_process_crash_evidence(root: &Path, digest: [u8; 32]) {
    let staging = root.join(PROCESS_CRASH_EVIDENCE_STAGING_FILE);
    let published = root.join(PROCESS_CRASH_EVIDENCE_FILE);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .expect("create process-crash evidence staging file");
    file.write_all(&digest)
        .expect("write process-crash evidence digest");
    file.sync_all().expect("sync process-crash evidence digest");
    drop(file);
    std::fs::rename(staging, published).expect("publish process-crash evidence digest");
}

struct KillOnDropChild {
    child: Child,
}

impl KillOnDropChild {
    fn spawn(root: &Path) -> Self {
        let executable = std::env::current_exe().expect("config lifecycle test executable");
        let child = Command::new(executable)
            .args([
                "--exact",
                "unclean_process_restart_child",
                "--test-threads=1",
            ])
            .env(PROCESS_CRASH_CHILD_MODE_ENV, PROCESS_CRASH_CHILD_MODE)
            .env(PROCESS_CRASH_CHILD_ROOT_ENV, root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn process-crash child");
        Self { child }
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("poll process-crash child")
    }

    fn kill(&mut self) {
        self.child.kill().expect("kill process-crash child");
    }
}

impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

async fn wait_for_process_crash_evidence(child: &mut KillOnDropChild, path: &Path) -> [u8; 32] {
    tokio::time::timeout(process_crash_child_deadline(), async {
        loop {
            match std::fs::read(path) {
                Ok(bytes) => {
                    return bytes
                        .try_into()
                        .expect("process-crash evidence must contain exactly one SHA-256 digest")
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => panic!("process-crash evidence could not be read"),
            }
            if let Some(status) = child.try_wait() {
                panic!("process-crash child exited before readiness: {status}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("process-crash child readiness deadline")
}

async fn wait_for_process_crash_exit(child: &mut KillOnDropChild) -> ExitStatus {
    tokio::time::timeout(cluster_transition_timeout(), async {
        loop {
            if let Some(status) = child.try_wait() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("process-crash child exit deadline")
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

#[test]
fn unclean_process_restart_child() {
    if std::env::var_os(PROCESS_CRASH_CHILD_MODE_ENV).as_deref()
        != Some(OsStr::new(PROCESS_CRASH_CHILD_MODE))
    {
        return;
    }
    let root = std::env::var_os(PROCESS_CRASH_CHILD_ROOT_ENV)
        .map(std::path::PathBuf::from)
        .expect("process-crash child root environment");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("process-crash child Tokio runtime");
    runtime.block_on(async move {
        let cluster = ConfigCluster::start(&root).await;
        let provider = provider();
        let encrypted = encrypted_store(&cluster, 0, &provider);
        encrypted
            .append_commit_write(CommitWrite::new(process_crash_genesis_record()))
            .await
            .expect("append process-crash genesis");
        encrypted
            .append_commit_write(CommitWrite::new(process_crash_rich_record()))
            .await
            .expect("append process-crash rich record");
        let committed = encrypted
            .load_latest()
            .await
            .expect("read process-crash rich record")
            .expect("process-crash rich record");
        assert_process_crash_rich_record(&committed);
        publish_process_crash_evidence(&root, exact_record_evidence_digest(&committed));
        std::future::pending::<()>().await;
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_record_survives_unclean_process_restart_exactly() {
    let temp = tempfile::tempdir().expect("process-crash config cluster tempdir");
    let evidence_path = temp.path().join(PROCESS_CRASH_EVIDENCE_FILE);
    let mut child = KillOnDropChild::spawn(temp.path());
    let pre_crash_digest = wait_for_process_crash_evidence(&mut child, &evidence_path).await;

    child.kill();
    let status = wait_for_process_crash_exit(&mut child).await;
    assert!(
        !status.success(),
        "process-crash child must terminate uncleanly"
    );

    let mut restarted = ConfigCluster::start(temp.path()).await;
    let provider = provider();
    let mut exact_reference = None;
    for index in 0..3 {
        let restored = encrypted_store(&restarted, index, &provider)
            .load_latest()
            .await
            .expect("read process-crash record after restart")
            .expect("process-crash record after restart");
        assert_process_crash_rich_record(&restored);
        assert_eq!(
            pre_crash_digest,
            exact_record_evidence_digest(&restored),
            "restarted replica must recover the exact pre-crash record"
        );
        if let Some(reference) = exact_reference.as_ref() {
            assert_exact_record(reference, &restored);
        } else {
            exact_reference = Some(restored);
        }
    }

    restarted
        .shutdown()
        .await
        .expect("shutdown process-crash recovery cluster");
    drop(restarted);
    assert_plaintext_canaries_absent_from_tree(
        temp.path(),
        &[
            PROCESS_CRASH_GENESIS_CANARY.as_bytes(),
            PROCESS_CRASH_PAYLOAD_CANARY.as_bytes(),
        ],
    );
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
    let genesis_tx = tx_id("11111111-2222-4333-8444-555555555555");
    let stable_tx = tx_id("22222222-2222-4222-8222-222222222222");
    let confirm_tx = tx_id("33333333-3333-4333-8333-333333333333");
    let pending_rollback_tx = tx_id("44444444-4444-4444-8444-444444444444");
    let rollback_tx = tx_id("55555555-4444-4555-8666-777777777777");
    let plaintext_canaries = [
        b"PAYLOAD-CANARY-LEADER-GENESIS-0xD1".as_slice(),
        b"PAYLOAD-CANARY-LEADER-STABLE-0xD2".as_slice(),
        b"PAYLOAD-CANARY-LEADER-CONFIRM-0xD3".as_slice(),
        b"PAYLOAD-CANARY-LEADER-PENDING-0xD4".as_slice(),
    ];

    encrypted_store(&cluster, 0, &provider)
        .append_commit_write(CommitWrite::new(record(
            genesis_tx,
            None,
            1,
            timestamp("2026-07-16T18:30:00Z"),
            config("PAYLOAD-CANARY-LEADER-GENESIS-0xD1", 1_024),
        )))
        .await
        .expect("append encrypted genesis record");
    encrypted_store(&cluster, 0, &provider)
        .append_commit_write(CommitWrite::new(record(
            stable_tx,
            Some(genesis_tx),
            2,
            timestamp("2026-07-16T18:31:00Z"),
            config("PAYLOAD-CANARY-LEADER-STABLE-0xD2", 2_048),
        )))
        .await
        .expect("append encrypted stable record");
    let mut confirm_pending = record(
        confirm_tx,
        Some(stable_tx),
        3,
        timestamp("2026-07-16T18:32:00Z"),
        config("PAYLOAD-CANARY-LEADER-CONFIRM-0xD3", 4_096),
    );
    confirm_pending.confirmed_deadline = Some(timestamp("2036-07-16T18:32:00Z"));
    encrypted_store(&cluster, 0, &provider)
        .append_commit_write(CommitWrite::new(confirm_pending))
        .await
        .expect("append encrypted pending-confirm record");

    cluster.wait_ready().await;
    let stopped_leader = cluster.leader();
    let stopped_identity = cluster.stores[stopped_leader].status().node_id;
    let stopped_database = cluster.database_path(stopped_leader);
    let pre_stop_status = cluster.stores[stopped_leader].status();
    assert_eq!(Some(pre_stop_status.node_id), pre_stop_status.leader_id);
    assert!(pre_stop_status.applied_index.is_some_and(|index| index > 0));
    assert!(pre_stop_status
        .committed_index
        .is_some_and(|index| index > 0));
    let pre_stop_history = encrypted_store(&cluster, stopped_leader, &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load leader-local history before stop");
    assert_eq!(3, pre_stop_history.len());
    assert_eq!(genesis_tx, pre_stop_history[0].tx_id);
    assert_eq!(stable_tx, pre_stop_history[1].tx_id);
    assert_eq!(confirm_tx, pre_stop_history[2].tx_id);
    assert!(pre_stop_history[2].confirmed_deadline.is_some());
    assert!(!pre_stop_history[2].recovery_required);

    cluster
        .stop_node(stopped_leader)
        .await
        .expect("stop actual current leader engine");
    assert_eq!(
        ConfigNodeLifecycle::Stopped,
        cluster
            .node_lifecycle(stopped_leader)
            .expect("stopped leader lifecycle")
    );
    assert!(cluster
        .node_transport_is_disconnected(stopped_leader)
        .await
        .expect("stopped leader transport state"));
    assert!(cluster.stores[stopped_leader]
        .probe_durable_readiness()
        .await
        .is_err());

    let ready_survivor = cluster.wait_for_survivor_leader(stopped_leader).await;
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
    assert_ne!(pre_stop_status.node_id, replacement_status.node_id);
    assert!(replacement_status.term > pre_stop_status.term);
    let replacement_store = encrypted_store(&cluster, replacement, &provider);

    let pending_on_replacement = replacement_store
        .load_latest()
        .await
        .expect("load pending-confirm record on replacement leader")
        .expect("pending-confirm record on replacement leader");
    assert_exact_record(&pre_stop_history[2], &pending_on_replacement);
    let pending_target_error = match replacement_store
        .load_rollback(RollbackTarget::TxId(confirm_tx))
        .await
    {
        Ok(_) => panic!("pending-confirm record cannot be a rollback target"),
        Err(error) => error,
    };
    assert_eq!(StoreErrorCode::NotFound, pending_target_error.code);

    let stable_parent_before_confirmation = replacement_store
        .load_rollback(RollbackTarget::Previous)
        .await
        .expect("load exact parent of the latest stable record");
    assert_exact_record(&pre_stop_history[0], &stable_parent_before_confirmation);
    assert_ne!(confirm_tx, stable_parent_before_confirmation.tx_id);

    replacement_store
        .mark_confirmed(confirm_tx)
        .await
        .expect("durably confirm through replacement authority");
    let confirmed = replacement_store
        .load_latest()
        .await
        .expect("load confirmed record on replacement leader")
        .expect("confirmed record on replacement leader");
    let mut expected_confirmed = pre_stop_history[2].clone();
    expected_confirmed.confirmed_deadline = None;
    assert_exact_record(&expected_confirmed, &confirmed);
    let stable_parent_after_confirmation = replacement_store
        .load_rollback(RollbackTarget::Previous)
        .await
        .expect("load exact parent after replacement confirmation");
    assert_exact_record(&pre_stop_history[1], &stable_parent_after_confirmation);

    let mut pending_rollback = record(
        pending_rollback_tx,
        Some(confirm_tx),
        4,
        timestamp("2026-07-16T18:33:00Z"),
        config("PAYLOAD-CANARY-LEADER-PENDING-0xD4", 8_192),
    );
    pending_rollback.recovery_required = true;
    pending_rollback.confirmed_deadline = Some(timestamp("2036-07-16T18:33:00Z"));
    replacement_store
        .append_commit_write(CommitWrite::new(pending_rollback))
        .await
        .expect("append rollback candidate through replacement authority");
    let fenced_pending = replacement_store
        .load_latest()
        .await
        .expect("load fenced rollback candidate")
        .expect("fenced rollback candidate");
    assert_eq!(pending_rollback_tx, fenced_pending.tx_id);
    assert!(fenced_pending.recovery_required);
    assert!(fenced_pending.confirmed_deadline.is_some());
    replacement_store
        .clear_recovery_required(pending_rollback_tx)
        .await
        .expect("durably clear pending recovery marker through replacement authority");
    let published_pending = replacement_store
        .load_latest()
        .await
        .expect("load published rollback candidate")
        .expect("published rollback candidate");
    let mut expected_published_pending = fenced_pending.clone();
    expected_published_pending.recovery_required = false;
    assert_exact_record(&expected_published_pending, &published_pending);

    let pending_rollback_error = match replacement_store
        .load_rollback(RollbackTarget::TxId(pending_rollback_tx))
        .await
    {
        Ok(_) => panic!("published pending record still cannot be a rollback target"),
        Err(error) => error,
    };
    assert_eq!(StoreErrorCode::NotFound, pending_rollback_error.code);
    let previous_while_pending = replacement_store
        .load_rollback(RollbackTarget::Previous)
        .await
        .expect("pending head must not replace the exact stable-parent selector");
    assert_exact_record(&pre_stop_history[1], &previous_while_pending);
    assert_ne!(pending_rollback_tx, previous_while_pending.tx_id);

    let mut rollback = record(
        rollback_tx,
        Some(pending_rollback_tx),
        5,
        timestamp("2026-07-16T18:34:00Z"),
        confirmed.config.clone(),
    );
    rollback.recovery_required = true;
    replacement_store
        .append_commit_write(
            CommitWrite::resolving(
                rollback,
                opc_config_bus::ConfirmedCommitResolution::Rollback {
                    pending_tx_id: pending_rollback_tx,
                },
            )
            .expect("rollback write shape"),
        )
        .await
        .expect("commit rollback on replacement leader");
    let fenced_rollback = replacement_store
        .load_latest()
        .await
        .expect("load fenced rollback record")
        .expect("fenced rollback record");
    assert_eq!(rollback_tx, fenced_rollback.tx_id);
    assert!(fenced_rollback.recovery_required);
    assert_eq!(None, fenced_rollback.confirmed_deadline);
    replacement_store
        .clear_recovery_required(rollback_tx)
        .await
        .expect("durably clear rollback recovery marker");
    let rollback_applied = replacement_store
        .load_latest()
        .await
        .expect("load rollback record")
        .expect("rollback record");
    let mut expected_rollback = fenced_rollback;
    expected_rollback.recovery_required = false;
    assert_exact_record(&expected_rollback, &rollback_applied);
    assert_eq!(expected_confirmed.config, rollback_applied.config);
    assert_ne!(published_pending.config, rollback_applied.config);

    let stale_confirmation = replacement_store
        .mark_confirmed(pending_rollback_tx)
        .await
        .expect_err("rolled-back pending transaction cannot be confirmed");
    assert_eq!(StoreErrorCode::Internal, stale_confirmation.code);
    let after_stale_confirmation = replacement_store
        .load_latest()
        .await
        .expect("load head after stale confirmation")
        .expect("head after stale confirmation");
    assert_exact_record(&rollback_applied, &after_stale_confirmation);

    drop(replacement_store);
    let survivor_history = encrypted_store(&cluster, replacement, &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load replacement history before stopped leader rejoins");
    assert_eq!(5, survivor_history.len());
    assert_eq!(genesis_tx, survivor_history[0].tx_id);
    assert_eq!(stable_tx, survivor_history[1].tx_id);
    assert_eq!(confirm_tx, survivor_history[2].tx_id);
    assert_eq!(pending_rollback_tx, survivor_history[3].tx_id);
    assert_eq!(rollback_tx, survivor_history[4].tx_id);
    let expected_history = vec![
        pre_stop_history[0].clone(),
        pre_stop_history[1].clone(),
        expected_confirmed,
        expected_published_pending,
        expected_rollback,
    ];
    assert_exact_history(&expected_history, &survivor_history);

    cluster
        .reopen_node_disconnected(stopped_leader)
        .await
        .expect("reopen stopped leader from the same disk while disconnected");
    assert_eq!(
        ConfigNodeLifecycle::ReopenedDisconnected,
        cluster
            .node_lifecycle(stopped_leader)
            .expect("reopened leader lifecycle")
    );
    assert!(cluster
        .node_transport_is_disconnected(stopped_leader)
        .await
        .expect("reopened leader transport state"));
    let disconnected_status = cluster.stores[stopped_leader].status();
    assert_eq!(stopped_identity, disconnected_status.node_id);
    assert!(!disconnected_status.admitted);
    assert_eq!(stopped_database, cluster.database_path(stopped_leader));
    let disconnected_history = encrypted_store(&cluster, stopped_leader, &provider)
        .load_since(ConfigVersion::INITIAL, 8)
        .await
        .expect("load disconnected stopped-leader history");
    verify_nonempty_exact_reopened_history(&pre_stop_history, &disconnected_history)
        .expect("stopped leader must reopen its exact non-empty pre-stop history");
    assert!(disconnected_history
        .iter()
        .all(|record| record.tx_id != pending_rollback_tx && record.tx_id != rollback_tx));
    assert!(cluster.stores[stopped_leader]
        .probe_durable_readiness()
        .await
        .is_err());

    cluster
        .reconnect_node(stopped_leader)
        .await
        .expect("reconnect and re-admit stopped leader");
    assert_eq!(
        ConfigNodeLifecycle::Running,
        cluster
            .node_lifecycle(stopped_leader)
            .expect("rejoined leader lifecycle")
    );
    cluster.wait_ready().await;
    for node in 0..3 {
        let converged = encrypted_store(&cluster, node, &provider)
            .load_since(ConfigVersion::INITIAL, 8)
            .await
            .expect("load converged post-rejoin history");
        assert_exact_history(&survivor_history, &converged);
    }
    let first_campaign_frames = cluster.captured_frames();
    assert!(!first_campaign_frames.is_empty());
    for (index, frame) in first_campaign_frames.iter().enumerate() {
        assert_plaintext_canaries_absent_from_bytes(
            &format!("shared consensus frame {index}"),
            frame,
            &plaintext_canaries,
        );
    }

    cluster.shutdown().await.expect("shutdown config cluster");
    drop(cluster);

    let mut restarted = ConfigCluster::start(temp.path()).await;
    for index in 0..3 {
        let restarted_store = encrypted_store(&restarted, index, &provider);
        let restarted_history = restarted_store
            .load_since(ConfigVersion::INITIAL, 8)
            .await
            .expect("load exact history after full rebuild");
        assert_exact_history(&survivor_history, &restarted_history);
        assert_eq!(None, restarted_history[2].confirmed_deadline);
        assert!(!restarted_history[2].recovery_required);
        assert!(restarted_history[3].confirmed_deadline.is_some());
        assert!(!restarted_history[3].recovery_required);
        assert_eq!(None, restarted_history[4].confirmed_deadline);
        assert!(!restarted_history[4].recovery_required);
        assert!(restarted_history
            .iter()
            .all(|record| record.plaintext_digest.is_some() && !record.encrypted_blob.is_empty()));
        let restarted_latest = restarted_store
            .load_latest()
            .await
            .expect("load rollback head after full rebuild")
            .expect("rollback head after full rebuild");
        assert_exact_record(&rollback_applied, &restarted_latest);
        let pending_error = match restarted_store
            .load_rollback(RollbackTarget::TxId(pending_rollback_tx))
            .await
        {
            Ok(_) => panic!("rolled-back pending record remains unavailable after rebuild"),
            Err(error) => error,
        };
        assert_eq!(StoreErrorCode::NotFound, pending_error.code);
    }

    let rebuilt_frames = restarted.captured_frames();
    assert!(!rebuilt_frames.is_empty());
    for (index, frame) in rebuilt_frames.iter().enumerate() {
        assert_plaintext_canaries_absent_from_bytes(
            &format!("rebuilt shared consensus frame {index}"),
            frame,
            &plaintext_canaries,
        );
    }
    restarted
        .shutdown()
        .await
        .expect("shutdown restarted config cluster");
    drop(restarted);
    assert_plaintext_canaries_absent_from_tree(temp.path(), &plaintext_canaries);
}
