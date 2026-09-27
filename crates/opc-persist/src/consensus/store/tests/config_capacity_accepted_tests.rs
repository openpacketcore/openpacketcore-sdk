//! Eight actual native accepted operations, separate from eight bare reservations.
//! This singleton fixture controls only submission ordering and native apply.
//! It is not transport, whole-memory, snapshot-overlap or power-loss evidence.

use super::*;
use crate::{
    AuditKey, PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};
use opc_crypto::ConfigCapacityProfile;

/// Opt-in, per-store test hook. Production builds contain neither it nor its call.
pub(crate) struct ProposalTestGate {
    permits: Arc<tokio::sync::Semaphore>,
    arrived: tokio::sync::watch::Sender<usize>,
    pub(crate) accepted: std::sync::atomic::AtomicUsize,
}

impl ProposalTestGate {
    pub(crate) async fn enter(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ()> {
        self.arrived.send_modify(|count| *count += 1);
        tokio::time::timeout_at(deadline, Arc::clone(&self.permits).acquire_owned())
            .await
            .map_err(|_| ())?
            .map_err(|_| ())
    }
}

struct AcceptedWitness {
    record: CommitRecord,
    aad: opc_key::EnvelopeAad,
    plaintext: Vec<u8>,
    handle: ConfigCommitRecoveryHandle,
}

#[tokio::test]
async fn config_capacity_957_eight_native_accepted_operations_survive_cancellation_and_reopen() {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-eight-accepted-")
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
        RetainedConfigBinding::new(topology.clone(), [0x75; 32], [0x76; 32])
            .expect("binding")
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("unchanged native limits");
    let key = AuditKey::new([0x77; 32]).expect("audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained backend");
    let store = ConsensusConfigStore::open(
        topology.clone(),
        backend,
        root.join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("profile-bound native store");
    ready(&store).await;
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-eight-accepted").expect("key ID"),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("test"),
            opc_key::Zeroizing::new([0x78; 32]),
        )
        .expect("synthetic provider");
    let mut operations = Vec::with_capacity(8);
    let mut witnesses = Vec::with_capacity(8);
    let mut parent = None;
    for ordinal in 0..8_u8 {
        let reservation = store
            .try_reserve_config_preparation()
            .expect("public destination admission")
            .expect("bounded owner before input allocation");
        let (mut record, _, _) = sized_attested_commit(32).into_parts();
        record.parent_tx_id = parent;
        record.version = opc_types::ConfigVersion::new(u64::from(ordinal) + 1);
        let aad = opc_key::EnvelopeAad::config(
            opc_types::TenantId::from_static("test"),
            record.version.get(),
            opc_key::ConfigAad::new(
                record.tx_id,
                record.parent_tx_id,
                record.committed_at,
                &record.principal,
                record.schema_digest,
                "running",
            )
            .expect("synthetic chain AAD"),
        );
        let plaintext =
            serde_json::to_vec(&char::from(b'a' + ordinal).to_string().repeat(1_572_864 - 2))
                .expect("distinct at-limit JSON");
        assert_eq!(plaintext.len(), 1_572_864);
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
        parent = Some(record.tx_id);
        let expected = record.clone();
        let commit = AttestedConfigCommit::try_new(
            record,
            Vec::new(),
            encrypted.claim().expect("one-shot claim"),
        )
        .expect("reserved attestation");
        drop(encrypted);
        let operation = store
            .prepare_recoverable_commit(
                opc_consensus::ConsensusRequestId::from_bytes([0x80 + ordinal; 16]),
                commit,
                &expected.principal,
            )
            .expect("prepare exact successor once");
        witnesses.push(AcceptedWitness {
            record: expected,
            aad,
            plaintext,
            handle: operation.recovery_handle().clone(),
        });
        operations.push(operation);
    }
    let mut metrics = store.inner.raft.metrics();
    let before = metrics.borrow().last_log_index.expect("initialized log");
    require_full_preparation_pool(&store);
    assert_eq!(metrics.borrow().last_log_index, Some(before));
    assert!(store
        .inner
        .backend
        .load_latest()
        .await
        .expect("pre-proposal native state")
        .is_none());

    let hook = Arc::new(ProposalTestGate {
        permits: Arc::new(tokio::sync::Semaphore::new(0)),
        arrived: tokio::sync::watch::channel(0).0,
        accepted: std::sync::atomic::AtomicUsize::new(0),
    });
    *store
        .inner
        .proposal_test_gate
        .lock()
        .expect("test hook lock") = Some(Arc::clone(&hook));
    let mut arrivals = hook.arrived.subscribe();
    let held_apply = Arc::clone(&store.inner.backend.consensus_apply_gate)
        .acquire_owned()
        .await
        .expect("hold actual native apply");
    store
        .inner
        .durable_progress
        .append_observed_from
        .set(std::time::Instant::now())
        .expect("enable this store's append observations once");
    let observed_from = tokio::time::Instant::now();
    let deadline = observed_from + store.inner.operation_timeout;
    let mut callers = Vec::with_capacity(8);
    for (index, operation) in operations.into_iter().enumerate() {
        let task_store = store.clone();
        callers.push(tokio::spawn(async move {
            task_store.append_prepared_commit_local(operation).await
        }));
        tokio::time::timeout_at(deadline, async {
            loop {
                if *arrivals.borrow_and_update() == index + 1 {
                    break;
                }
                arrivals
                    .changed()
                    .await
                    .expect("live preflight observation");
            }
        })
        .await
        .expect("actual quorum and command preflight within original deadline");
        println!(
            "CONFIG_CAPACITY_EIGHT_PREFLIGHT ordinal={} elapsed_ms={}",
            index + 1,
            observed_from.elapsed().as_millis()
        );
    }
    assert_eq!(*arrivals.borrow(), 8);
    assert_eq!(metrics.borrow().last_log_index, Some(before));
    require_full_preparation_pool(&store);
    // FIFO admission holds one permit only through client_write_ff. It orders
    // the prepared chain without serializing accepted-work completion.
    hook.permits.add_permits(1);
    let mut last_observed = None;
    let logged = tokio::time::timeout_at(deadline, async {
        loop {
            let current = metrics.borrow_and_update().last_log_index;
            if current != last_observed {
                println!(
                    "CONFIG_CAPACITY_EIGHT_LOG entries={} handed_off={} elapsed_ms={}",
                    current.unwrap_or(before).saturating_sub(before),
                    hook.accepted.load(std::sync::atomic::Ordering::SeqCst),
                    observed_from.elapsed().as_millis()
                );
                last_observed = current;
            }
            if current == Some(before + 8) {
                break;
            }
            metrics.changed().await.expect("live native engine metrics");
        }
    })
    .await;
    println!("CONFIG_CAPACITY_EIGHT_NATIVE_STAGE handed_off={} logged={} callers_finished={} available_proposal_permits={} elapsed_ms={} deadline_met={}", hook.accepted.load(std::sync::atomic::Ordering::SeqCst), metrics.borrow().last_log_index.unwrap_or(before).saturating_sub(before), callers.iter().filter(|caller| caller.is_finished()).count(), store.inner.proposal_admission.available_permits(), observed_from.elapsed().as_millis(), logged.is_ok());
    logged.expect("all eight operations reach the real native log within original deadline");
    assert!(metrics
        .borrow()
        .last_applied
        .is_some_and(|log| log.index <= before));
    assert!(callers.iter().all(|caller| !caller.is_finished()));
    for caller in callers {
        caller.abort();
        assert!(caller
            .await
            .expect_err("cancelled original caller")
            .is_cancelled());
    }
    require_full_preparation_pool(&store);
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        0,
        "CONFIG_CAPACITY_EIGHT_PROPOSAL_RED: all eight accepted owners outlive callers"
    );
    assert!(store
        .inner
        .backend
        .load_latest()
        .await
        .expect("held-apply native state")
        .is_none());
    drop(held_apply);
    let completed = tokio::time::timeout_at(
        deadline,
        Arc::clone(&store.inner.proposal_admission).acquire_many_owned(8),
    )
    .await
    .expect("all eight accepted supervisors resolve inside original deadline")
    .expect("proposal admission remains open");
    drop(completed);
    let recovered_slots: Vec<_> = (0..8)
        .map(|_| {
            store
                .try_reserve_config_preparation()
                .expect("completed work releases every reservation")
                .expect("bounded reusable slot")
        })
        .collect();
    require_full_preparation_pool(&store);
    verify_records_and_handles(&store, &provider, &witnesses).await;
    drop(recovered_slots);
    store.shutdown().await.expect("native shutdown");
    drop(arrivals);
    drop(metrics);
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("reopen exact original retained authority");
    let reopened =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("reopen original native engine");
    ready(&reopened).await;
    verify_records_and_handles(&reopened, &provider, &witnesses).await;
    reopened.shutdown().await.expect("reopened native shutdown");
    println!("CONFIG_CAPACITY_EIGHT_ACCEPTED logical_bytes=1572864 prepared=8 accepted=8 cancelled=8 committed=8 exact_recovery=true retained_reopen=true owner_conservation=true full_memory_bound=false");
}

async fn ready(store: &ConsensusConfigStore) {
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    store
        .initialize_cluster()
        .await
        .expect("admitted singleton");
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    store
        .wait_for_known_leader(deadline)
        .await
        .expect("natural singleton leadership");
    assert!(matches!(
        store.local_read_barrier(deadline).await,
        ReadBarrierReply::Ready(_)
    ));
}

fn require_full_preparation_pool(store: &ConsensusConfigStore) {
    let error = store.try_reserve_config_preparation().expect_err(
        "CONFIG_CAPACITY_EIGHT_OWNER_RED: the ninth reservation must be refused while all eight owners are live",
    );
    assert!(matches!(error.kind(), PersistErrorKind::Unavailable));
}

async fn verify_records_and_handles(
    store: &ConsensusConfigStore,
    provider: &opc_key::MemoryKeyProvider,
    expected: &[AcceptedWitness],
) {
    let before = store.inner.raft.metrics().borrow().last_log_index;
    let records = store
        .load_since(opc_types::ConfigVersion::new(0), 8)
        .await
        .expect("linearizable full native chain");
    assert_eq!(records.len(), expected.len());
    for (actual, expected) in records.iter().zip(expected) {
        assert!(
            actual.record == expected.record,
            "exact native encrypted successor"
        );
        let plaintext =
            opc_crypto::decrypt_envelope(provider, &expected.aad, &actual.record.encrypted_blob)
                .await
                .expect("decrypt exact native successor");
        assert!(
            plaintext.as_slice() == expected.plaintext.as_slice(),
            "exact logical successor"
        );
        assert!(matches!(
            store
                .lookup_commit_operation(&expected.handle, &expected.record.principal)
                .await
                .expect("read-only original-handle recovery"),
            ConfigCommitRecoveryOutcome::Committed
        ));
    }
    assert_eq!(
        store.inner.raft.metrics().borrow().last_log_index,
        before,
        "read-only recovery appends no proposal"
    );
}
