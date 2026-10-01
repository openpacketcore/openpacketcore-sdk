//! Real disk-backed automatic submission and public recovery-encoder lifetimes.
//! Engine-internal payloads are deliberately outside the staging inventory.

use super::*;
use crate::audit_authority::{
    AuditAdmission, AuditCaller, AuditLedgerLimits, AuditOperationReceipt, AuditPrivacyKey,
};
use crate::consensus::capacity_observation::working_buffers::*;
use crate::{
    AuditKey, PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};
use opc_crypto::ConfigCapacityProfile;
use std::sync::{Condvar, Mutex};
use std::task::Poll;

const GUARD: Duration = Duration::from_secs(10);

async fn native_store() -> (ConsensusConfigStore, tempfile::TempDir) {
    open_store(BTreeMap::new(), true).await
}

async fn open_store(
    peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
    initialize: bool,
) -> (ConsensusConfigStore, tempfile::TempDir) {
    let scratch = std::env::var_os("TMPDIR").expect("explicit disk scratch");
    let root = tempfile::Builder::new()
        .prefix("work-")
        .tempdir_in(scratch)
        .unwrap();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout).unwrap().trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let node = ConsensusNodeId::new(1).unwrap();
    let identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes(
            *uuid::Uuid::new_v4()
                .as_bytes()
                .repeat(2)
                .first_chunk::<32>()
                .unwrap(),
        ),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xB9; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let mut members = BTreeSet::from([node]);
    members.extend(peers.keys());
    let topology = ConfigConsensusTopology::try_new(identity, node, members).unwrap();
    let options = RetainedConfigOptions::new(
        root.path().join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0xBA; 32], [0xBB; 32])
            .unwrap()
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .unwrap();
    let backend =
        SqliteBackend::provision_config_authority(options, AuditKey::new([0xBC; 32]).unwrap())
            .await
            .unwrap();
    let store = ConsensusConfigStore::open(topology, backend, root.path().join("snapshots"), peers)
        .await
        .unwrap();
    if initialize {
        store.initialize_cluster().await.unwrap();
        let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
        store.wait_for_known_leader(deadline).await.unwrap();
        assert!(matches!(
            store.local_read_barrier(deadline).await,
            ReadBarrierReply::Ready(_)
        ));
    }
    (store, root)
}

async fn commit(store: &ConsensusConfigStore) -> AttestedConfigCommit {
    let reservation = store.try_reserve_config_preparation().unwrap().unwrap();
    let (mut record, _, _) = super::tests::sized_attested_commit(32).into_parts();
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
        .unwrap(),
    );
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("working-buffer-test").unwrap(),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("test"),
            opc_key::Zeroizing::new([0xBD; 32]),
        )
        .unwrap();
    let plaintext = serde_json::to_vec(&"x".repeat(4094)).unwrap();
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        &plaintext,
    )
    .await
    .unwrap();
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    AttestedConfigCommit::try_new(record, Vec::new(), envelope.claim().unwrap()).unwrap()
}

fn commit_bytes(commit: &PreparedConfigCommit) -> usize {
    std::mem::size_of::<PreparedConfigCommit>()
        + commit.record.encrypted_blob.capacity()
        + commit.record.principal.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.audit.capacity() * std::mem::size_of::<AuditRecord>()
        + commit
            .audit
            .iter()
            .map(|audit| {
                audit.yang_path.capacity()
                    + audit.previous_value.as_ref().map_or(0, String::capacity)
                    + audit.new_value.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}

async fn ordinary(cancel: bool) {
    let (store, root) = native_store().await;
    let commit = commit(&store).await;
    let expected = commit.record().clone();
    let request = opc_consensus::ConsensusRequestId::new();
    let prepared = store
        .prepare_recoverable_commit(request, commit, &expected.principal)
        .unwrap();
    let ConfigMutationIntent::BoundedAppend { commit, .. } = prepared.capacity_intent() else {
        panic!("public bounded fixture");
    };
    let original_bytes = commit_bytes(commit);
    // The public preparation compacts metadata. The actual ordinary retry clone
    // has its own Box/nested allocations, which this independent oracle sizes.
    let clone_bytes = commit_bytes(&commit.clone());
    let census = Arc::new(WorkingBufferCensus::default());
    let registration = census
        .observe_source(store.inner.identity, store.inner.local_node_id, None)
        .unwrap();
    let held_admission = store
        .inner
        .proposal_admission
        .clone()
        .acquire_many_owned(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS as u32)
        .await
        .unwrap();
    let held_apply = store
        .inner
        .backend
        .consensus_apply_gate
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let mut entered = store.inner.durable_progress.apply_entered.subscribe();
    let mut response_loss = store
        .inner
        .durable_progress
        .accepted_response_loss
        .subscribe();
    let mut applied = store.inner.durable_progress.subscribe_applied();
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    let mut caller = Some(Box::pin(store.append_prepared_commit(prepared)));
    let pending =
        std::future::poll_fn(|cx| Poll::Ready(caller.as_mut().unwrap().as_mut().poll(cx))).await;
    let waiting = census.with_current_capture(|capture| capture.sample());
    drop(held_admission);
    tokio::time::timeout_at(deadline, async {
        tokio::select! {
            result = caller.as_mut().unwrap().as_mut() => panic!("held native apply completed: {result:?}"),
            result = entered.changed() => result.unwrap(),
        }
    }).await.unwrap();
    let accepted = census.with_current_capture(|capture| capture.sample());
    let committed = store
        .inner
        .raft
        .with_raft_state(|state| state.committed)
        .await
        .unwrap()
        .unwrap();
    if cancel {
        drop(caller.take());
    }
    let cancelled = census.with_current_capture(|capture| capture.sample());
    tokio::time::timeout_at(deadline, store.inner.raft.shutdown())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout_at(deadline, response_loss.wait_for(Option::is_some))
        .await
        .unwrap()
        .unwrap();
    // A stopped core cannot route another accepted attempt. Await the genuine
    // automatic loop's unchanged failure path, while the older storage owner
    // remains live behind held_apply. No two-copy maximum is inferred here.
    let result = if let Some(caller) = caller.take() {
        Some(tokio::time::timeout_at(deadline, caller).await.unwrap())
    } else {
        None
    };
    drop(caller);
    let after_response = census.with_current_capture(|capture| capture.sample());
    let held_permits = store.inner.proposal_admission.available_permits();
    drop(held_apply);
    tokio::time::timeout(GUARD, applied.wait_for(|value| *value >= committed.index))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(GUARD, store.shutdown())
        .await
        .unwrap()
        .unwrap();
    let readback = store.inner.backend.load_latest().await.unwrap().unwrap();
    let clean = census.with_current_capture(|capture| capture.sample());
    drop(registration);
    drop(store);
    root.close().unwrap();
    assert!(pending.is_pending());
    assert_eq!(readback.record, expected);
    assert!(
        clean.owners.is_empty() && clean.bytes == 0,
        "actual native cleanup completed"
    );
    eprintln!(
        "CAPACITY_WORKING_CLEANUP native cancel={cancel} owners={} bytes={}",
        clean.owners.len(),
        clean.bytes
    );
    assert!(waiting.issues.complete() && accepted.issues.complete() && clean.issues.complete());
    assert_eq!(
        waiting.owners.len(),
        2,
        "CAPACITY_WORKING_ORIGINAL_RED: automatic route original plus real local clone"
    );
    assert_eq!(
        waiting.bytes,
        original_bytes + clone_bytes,
        "CAPACITY_WORKING_EXTENT_RED"
    );
    assert_eq!(
        accepted.owners.len(),
        1,
        "CAPACITY_WORKING_ACCEPTED_ORIGINAL_RED"
    );
    assert_eq!(accepted.bytes, original_bytes);
    assert_eq!(
        accepted.engine_transfers, 1,
        "engine ownership is an explicit exclusion"
    );
    assert_eq!(held_permits, DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1);
    assert!(after_response.owners.is_empty());
    if cancel {
        assert!(cancelled.owners.is_empty(), "CAPACITY_WORKING_CANCEL_RED");
    }
    if let Some(result) = result {
        assert!(result.is_err_and(|error| matches!(error.kind(), PersistErrorKind::OutcomeUnknown)));
    }
    eprintln!("CAPACITY_WORKING_NATIVE cancel={cancel} waiting_owners={} waiting_bytes={} accepted_originals={} engine_transfers={} after_response={} clean={}", waiting.owners.len(), waiting.bytes, accepted.owners.len(), accepted.engine_transfers, after_response.owners.len(), clean.owners.len());
}

#[tokio::test]
async fn capacity_working_buffers_auto_route_accepted_cancellation() {
    ordinary(true).await;
}

#[tokio::test]
async fn capacity_working_buffers_auto_route_response_loss_cleanup() {
    ordinary(false).await;
}

struct EncoderGate {
    arrived: Mutex<Option<tokio::sync::oneshot::Sender<WorkingBufferOwner>>>,
    release: Mutex<bool>,
    condition: Condvar,
    local_started: tokio::sync::Notify,
}
impl EncoderGate {
    fn open(&self) {
        *self.release.lock().unwrap() = true;
        self.condition.notify_all();
    }
}
impl WorkingBufferObserver for EncoderGate {
    fn observe(&self, stage: WorkingBufferStage, owner: WorkingBufferOwner) {
        if stage == WorkingBufferStage::Retained && owner.kind == WorkingBufferKind::LocalAttempt {
            self.local_started.notify_one();
        }
        if stage == WorkingBufferStage::RecoveryReady {
            if let Some(sender) = self.arrived.lock().unwrap().take() {
                let _ = sender.send(owner);
            }
            let released = self
                .condition
                .wait_timeout_while(self.release.lock().unwrap(), GUARD, |released| !*released)
                .unwrap();
            assert!(*released.0, "bounded encoder barrier release");
        }
    }
}

fn applied(admission: AuditAdmission) -> AuditOperationReceipt {
    match admission {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("real audit admission: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capacity_working_buffers_public_encoder_overlaps_actual_submission() {
    let (store, root) = native_store().await;
    let privacy = AuditPrivacyKey::new([0xBE; 32]).unwrap();
    store
        .initialize_audit_authority(&privacy, AuditLedgerLimits::new(6, 2).unwrap())
        .await
        .unwrap();
    let commit = commit(&store).await;
    let expected = commit.record().clone();
    let event = event(&expected.principal);
    let prepared = store
        .prepare_audited_commit(&privacy, &event, commit, Duration::from_secs(60))
        .unwrap();
    let fields = prepared.command().weak_fields();
    let crate::consensus::audit_mutation::AuditedConfigEffect::BoundedAppend { commit, .. } =
        &prepared.command().effect
    else {
        panic!("bounded audited effect");
    };
    let prepared_bytes =
        std::mem::size_of::<crate::consensus::audit_mutation::AuditedMutationFields>()
            + commit_bytes(commit);
    let caller = AuditCaller::project(&privacy, "test", &expected.principal).unwrap();
    let receipt = applied(store.admit_audit_operation(prepared.handle(), caller).await);
    let other_preparations: Vec<_> = (0..7)
        .map(|_| store.try_reserve_config_preparation().unwrap().unwrap())
        .collect();
    assert!(store.try_reserve_config_preparation().is_err());
    let (arrived_tx, mut arrived_rx) = tokio::sync::oneshot::channel();
    let gate = Arc::new(EncoderGate {
        arrived: Mutex::new(Some(arrived_tx)),
        release: Mutex::new(false),
        condition: Condvar::new(),
        local_started: tokio::sync::Notify::new(),
    });
    let census = Arc::new(WorkingBufferCensus::default());
    let registration = census
        .observe_source(
            store.inner.identity,
            store.inner.local_node_id,
            Some(gate.clone()),
        )
        .unwrap();
    let enrollment = registration.observe_recovery(&prepared).unwrap();
    let (finished_tx, mut finished_rx) = tokio::sync::oneshot::channel();
    let held_apply = store
        .inner
        .backend
        .consensus_apply_gate
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let held_admission = store
        .inner
        .proposal_admission
        .clone()
        .acquire_many_owned(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS as u32)
        .await
        .unwrap();
    let mut entered = store.inner.durable_progress.apply_entered.subscribe();
    let mut applied_watch = store.inner.durable_progress.subscribe_applied();
    let (
        waiting,
        overlap,
        after_cancel,
        after_return,
        ready,
        second_encode_refused,
        committed,
        encoded,
    ) = tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let encoder = scope.spawn(|| {
                let _ = finished_tx.send(prepared.encode());
            });
            let result = tokio::runtime::Handle::current().block_on(async {
            // A removed hook yields ordinary completion, so controls still run
            // real submission and cleanup before the named detection assertion.
            let mut early = None;
            let ready = tokio::select! {
                ready = &mut arrived_rx => ready.ok(),
                encoded = &mut finished_rx => { early = Some(encoded.unwrap()); None },
            };
            let second_encode_refused = prepared.encode().is_err();
            let mut submission = Some(Box::pin(store.submit_audited_mutation(&prepared, &receipt, caller)));
            tokio::time::timeout(GUARD, async {
                tokio::select! {
                    value = submission.as_mut().unwrap().as_mut() => panic!("held admission completed: {value:?}"),
                    _ = gate.local_started.notified() => {},
                }
            }).await.unwrap();
            let waiting = census.with_current_capture(|capture| capture.sample());
            drop(held_admission);
            tokio::time::timeout(GUARD, async {
                tokio::select! {
                    value = submission.as_mut().unwrap().as_mut() => panic!("held audited apply completed: {value:?}"),
                    value = entered.changed() => value.unwrap(),
                }
            }).await.unwrap();
            let overlap = census.with_current_capture(|capture| capture.sample());
            let committed = store.inner.raft.with_raft_state(|state| state.committed).await.unwrap().unwrap();
            drop(submission.take());
            let after_cancel = census.with_current_capture(|capture| capture.sample());
            gate.open();
            let encoded = match early { Some(value) => value, None => finished_rx.await.unwrap() }.unwrap();
            let after_return = census.with_current_capture(|capture| capture.sample());
            (waiting, overlap, after_cancel, after_return, ready, second_encode_refused, committed, encoded)
        });
            gate.open();
            encoder.join().unwrap();
            result
        })
    });
    drop(held_apply);
    tokio::time::timeout(
        GUARD,
        applied_watch.wait_for(|value| *value >= committed.index),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(GUARD, store.shutdown())
        .await
        .unwrap()
        .unwrap();
    let readback = store.inner.backend.load_latest().await.unwrap().unwrap();
    let decoded = crate::consensus::PreparedAuditedMutation::decode(&encoded).unwrap();
    let same = decoded == prepared;
    drop(decoded);
    drop(enrollment);
    drop(prepared);
    let reservation_released = store.try_reserve_config_preparation().is_ok();
    drop(other_preparations);
    let clean = census.with_current_capture(|capture| capture.sample());
    drop(registration);
    drop(store);
    root.close().unwrap();
    assert!(
        clean.owners.is_empty() && clean.bytes == 0,
        "actual cleanup before detector"
    );
    assert!(
        fields.upgrade().is_none(),
        "observer enrollment does not pin actual command fields"
    );
    assert_eq!(readback.record, expected);
    assert!(same && reservation_released);
    eprintln!(
        "CAPACITY_WORKING_CLEANUP encoder owners={} bytes={}",
        clean.owners.len(),
        clean.bytes
    );
    assert!(overlap.issues.complete() && clean.issues.complete());
    let outputs: Vec<_> = overlap
        .owners
        .iter()
        .filter(|owner| owner.kind == WorkingBufferKind::RecoveryOutput)
        .collect();
    assert_eq!(
        outputs.len(),
        1,
        "CAPACITY_WORKING_ENCODER_RED: actual encoder Vec overlaps accepted submission"
    );
    assert_eq!(
        waiting.owners.len(),
        3,
        "actual two aliased attempts plus encoder"
    );
    assert_eq!(
        waiting.bytes,
        prepared_bytes + encoded.capacity(),
        "CAPACITY_WORKING_ALIAS_RED: audited clones share original allocations"
    );
    assert_eq!(outputs[0].bytes, encoded.capacity());
    assert_eq!(ready.unwrap().bytes, encoded.capacity());
    assert!(
        second_encode_refused,
        "original encoding flag remains held until return"
    );
    assert_eq!(after_cancel.owners.len(), 1);
    assert_eq!(after_cancel.bytes, encoded.capacity());
    assert!(
        after_return.owners.is_empty(),
        "returned output is caller-owned even while still live"
    );
    assert_eq!(after_return.caller_transfers, 1);
    assert_eq!(overlap.engine_transfers, 1);
    eprintln!("CAPACITY_WORKING_ENCODER overlap_owners={} overlap_bytes={} output_capacity={} after_cancel={} after_return={} clean={}", overlap.owners.len(), overlap.bytes, encoded.capacity(), after_cancel.owners.len(), after_return.owners.len(), clean.owners.len());
}

fn event(principal: &str) -> crate::ManagementAuditEventRecord {
    crate::ManagementAuditEventRecord::try_new(
        [0xBF; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        "test",
        principal,
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("working-buffer-test"),
    )
    .unwrap()
}

struct ReserveBlocked(Mutex<Option<std::sync::mpsc::Sender<usize>>>);
impl WorkingBufferObserver for ReserveBlocked {
    fn observe(&self, _: WorkingBufferStage, _: WorkingBufferOwner) {}
    fn allocation_blocked(&self, bytes: usize) {
        if let Some(sender) = self.0.lock().unwrap().take() {
            sender.send(bytes).unwrap();
        }
    }
}

#[tokio::test]
async fn capacity_working_buffers_recovery_reserve_growth_and_early_unregister() {
    use std::io::Write;
    let (store, root) = native_store().await;
    let value = commit(&store).await;
    let privacy = AuditPrivacyKey::new([0xC1; 32]).unwrap();
    let event = event(&value.record().principal);
    let prepared = store
        .prepare_audited_commit(&privacy, &event, value, Duration::from_secs(60))
        .unwrap();
    let census = Arc::new(WorkingBufferCensus::default());
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let registration = census
        .observe_source(
            store.inner.identity,
            store.inner.local_node_id,
            Some(Arc::new(ReserveBlocked(Mutex::new(Some(blocked_tx))))),
        )
        .unwrap();
    let enrollment = registration.observe_recovery(&prepared).unwrap();
    // The production wrapper is active before the public encoder's first
    // reservation/count pass. No payload or preparation clone is made here.
    let mut output = RecoveryOutput::start(&prepared);
    drop(enrollment);
    let active_unregistered = census.with_current_capture(|capture| capture.sample());
    let (worker, at_block) = census.with_current_capture(|capture| {
        let worker = std::thread::spawn(move || {
            output.try_reserve_exact(107).unwrap();
            output
        });
        let at_block = blocked_rx.recv_timeout(GUARD).unwrap();
        let sample = capture.sample();
        assert_eq!(sample.owners.len(), 1);
        assert_eq!(sample.bytes, 0);
        (worker, at_block)
    });
    let mut output = worker.join().unwrap();
    let reserved = census.with_current_capture(|capture| capture.sample());
    output.write_all(&[0x41; 300]).unwrap();
    let grown = census.with_current_capture(|capture| capture.sample());
    let unregistered = census.with_current_capture(|capture| capture.sample());
    let encoded = output.finish().unwrap();
    let transferred = census.with_current_capture(|capture| capture.sample());
    drop(prepared);
    drop(registration);
    store.shutdown().await.unwrap();
    drop(store);
    root.close().unwrap();
    assert!(transferred.owners.is_empty());
    eprintln!(
        "CAPACITY_WORKING_CLEANUP reserve owners={} bytes={}",
        transferred.owners.len(),
        transferred.bytes
    );
    assert_eq!(
        at_block, 0,
        "CAPACITY_WORKING_RESERVE_RED: actual Vec reserve waits for capture"
    );
    assert!(reserved.bytes >= 107);
    assert_eq!(active_unregistered.bytes, 0);
    assert!(
        active_unregistered.issues.early_recovery_unregister,
        "CAPACITY_WORKING_BEGIN_RED: encode enrollment is active before allocation"
    );
    assert_eq!(grown.bytes, encoded.capacity());
    assert!(grown.bytes >= 300);
    assert!(
        unregistered.issues.early_recovery_unregister,
        "CAPACITY_WORKING_UNREGISTER_RED"
    );
    assert_eq!(
        unregistered.bytes,
        encoded.capacity(),
        "early unregister does not hide actual output"
    );
    assert_eq!(transferred.caller_transfers, 1);
}

#[tokio::test]
async fn capacity_working_buffers_recovery_enrollment_rejects_wrong_authority_and_aliases() {
    let (store, root) = native_store().await;
    let value = commit(&store).await;
    let privacy = AuditPrivacyKey::new([0xC2; 32]).unwrap();
    let event = event(&value.record().principal);
    let prepared = store
        .prepare_audited_commit(&privacy, &event, value, Duration::from_secs(60))
        .unwrap();
    let alias = prepared.clone();
    let census = Arc::new(WorkingBufferCensus::default());
    let wrong_identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0xC3; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xC4; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let wrong = census
        .observe_source(wrong_identity, store.inner.local_node_id, None)
        .unwrap();
    assert!(wrong.observe_recovery(&prepared).is_none());
    let rejected = census.with_current_capture(|capture| capture.sample());
    drop(wrong);
    let census = Arc::new(WorkingBufferCensus::default());
    let registration = census
        .observe_source(store.inner.identity, store.inner.local_node_id, None)
        .unwrap();
    let enrollment = registration.observe_recovery(&prepared).unwrap();
    let duplicate = registration.observe_recovery(&alias).unwrap();
    let bytes = prepared.encode().unwrap();
    let ambiguous = census.with_current_capture(|capture| capture.sample());
    drop((enrollment, duplicate));
    let stale = census.with_current_capture(|capture| capture.sample());
    // Re-encoding after explicit unenrollment is excluded, not attributed to a
    // stale command address. Borrow enrollment cannot survive command reuse.
    assert_eq!(bytes, prepared.encode().unwrap());
    let after = census.with_current_capture(|capture| capture.sample());
    drop((prepared, alias, registration));
    store.shutdown().await.unwrap();
    drop(store);
    root.close().unwrap();
    assert!(rejected.issues.mismatched_identity);
    assert!(ambiguous.issues.ambiguous_source);
    assert!(stale.recovery_enrollments == 0 && stale.owners.is_empty());
    assert!(after.owners.is_empty() && after.caller_transfers == 0);
}

#[derive(Debug)]
struct HeldForward {
    node: ConsensusNodeId,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    completed: tokio::sync::watch::Sender<usize>,
}

#[async_trait]
impl ConsensusPeer for HeldForward {
    fn node_id(&self) -> ConsensusNodeId {
        self.node
    }
    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        request.validate()?;
        if request.family != ConsensusRpcFamily::ForwardMutation {
            return Err(ConsensusPeerError::Protocol);
        }
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        let result = encode_config_wire_for_profile(
            ConfigCapacityProfile::BoundedV1,
            &ForwardMutationReply::Unavailable,
        )
        .unwrap();
        self.completed.send_modify(|value| *value += 1);
        Ok(ConsensusWireResponse { result: Ok(result) })
    }
}

#[tokio::test]
async fn capacity_working_buffers_forward_supervisor_keeps_cancelled_attempt_during_retry() {
    let (completed_tx, mut completed_rx) = tokio::sync::watch::channel(0);
    let peer = Arc::new(HeldForward {
        node: ConsensusNodeId::new(2).unwrap(),
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
        completed: completed_tx,
    });
    let other = Arc::new(HeldForward {
        node: ConsensusNodeId::new(3).unwrap(),
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
        completed: peer.completed.clone(),
    });
    let peers = BTreeMap::from([
        (peer.node, peer.clone() as Arc<dyn ConsensusPeer>),
        (other.node, other as Arc<dyn ConsensusPeer>),
    ]);
    // The real production forwarding function and its supervisor are exercised;
    // this controlled peer fixture makes no multi-node consensus-runtime claim.
    let (store, root) = open_store(peers, false).await;
    let prepared = store.prepare_capacity_commit(commit(&store).await).unwrap();
    let ownership = store
        .commit_submission(prepared.evidence, prepared.reservation)
        .unwrap();
    let intent = ConfigMutationIntent::prepared_append(
        prepared.commit,
        prepared.resolution,
        prepared.binding,
    );
    let census = Arc::new(WorkingBufferCensus::default());
    let registration = census
        .observe_source(store.inner.identity, store.inner.local_node_id, None)
        .unwrap();
    let request_id = opc_consensus::ConsensusRequestId::new();
    let original = LocalIntent::new(&store, request_id, intent).unwrap();
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    for _ in 0..2 {
        let request = original.forward_owned(ForwardedBudget::from_deadline(deadline).unwrap());
        let mut attempt =
            Box::pin(store.call_mutation_peer(peer.node, request, deadline, ownership.clone()));
        tokio::time::timeout_at(deadline, async {
            tokio::select! {
                result = &mut attempt => panic!("held forwarding completed: {result:?}"),
                permit = peer.entered.acquire() => permit.unwrap().forget(),
            }
        })
        .await
        .unwrap();
        drop(attempt);
    }
    let overlap = census.with_current_capture(|capture| capture.sample());
    drop(original);
    drop(ownership);
    let cancelled = census.with_current_capture(|capture| capture.sample());
    peer.release.add_permits(2);
    tokio::time::timeout_at(deadline, completed_rx.wait_for(|value| *value == 2))
        .await
        .unwrap()
        .unwrap();
    // This single-thread runtime completes each awakened supervisor's
    // synchronous request/ownership drop before polling this notification.
    let clean = census.with_current_capture(|capture| capture.sample());
    drop(registration);
    store.shutdown().await.unwrap();
    drop(store);
    root.close().unwrap();
    assert!(clean.owners.is_empty() && clean.bytes == 0);
    eprintln!(
        "CAPACITY_WORKING_CLEANUP forwarding owners={} bytes={}",
        clean.owners.len(),
        clean.bytes
    );
    assert!(overlap.issues.complete() && cancelled.issues.complete() && clean.issues.complete());
    assert_eq!(
        overlap.owners.len(),
        3,
        "CAPACITY_WORKING_FORWARD_RED: original and two actual overlapping attempts"
    );
    assert_eq!(
        cancelled.owners.len(),
        2,
        "cancelled callers leave real supervised forwarding owners"
    );
    assert!(cancelled
        .owners
        .iter()
        .all(|owner| owner.kind == WorkingBufferKind::ForwardAttempt
            && owner.request == Some(request_id)));
    assert_eq!(overlap.bytes, cancelled.bytes / 2 * 3);
}
