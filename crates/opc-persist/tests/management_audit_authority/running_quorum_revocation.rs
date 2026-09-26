//! A real three-voter quorum wait at the final Running admission boundary.
//! The peer delays genuine follower replies; it never fabricates a read proof.

use super::*;
use crate::audit_authority::{continuity::*, *};
use crate::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile,
};
use opc_consensus::engine::raft::{AppendEntriesRequest, AppendEntriesResponse};
use opc_key::{ConfigAad, EnvelopeAad};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use std::sync::Mutex;
use tokio::sync::{watch, Barrier, Semaphore};

const TENANT: &str = "synthetic-quorum-revocation";
const PRINCIPAL: &str = "spiffe://test.invalid/tenant/synthetic-quorum-revocation/operator";
const LIFETIME: Duration = Duration::from_secs(60);
const WAIT: Duration = DURABLE_CONSENSUS_OPERATION_TIMEOUT;

#[derive(Default)]
struct Checkpoint(Mutex<Option<AuditCheckpoint>>);

#[async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        let mut current = self.0.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(AuditCheckpointAdvance::Applied)
    }
}

#[derive(Clone, Debug, Default)]
struct GateObservation {
    live_calls: usize,
    entered_before_admission: usize,
    held: BTreeMap<ConsensusNodeId, tokio::task::Id>,
    valid_replies: usize,
    repeated_target: bool,
    unexpected_permit_count: bool,
}

struct QuorumGate {
    proposal_admission: Arc<Semaphore>,
    armed: AtomicBool,
    released: watch::Sender<bool>,
    observed: watch::Sender<GateObservation>,
    pair: Barrier,
}

impl QuorumGate {
    fn new(proposal_admission: Arc<Semaphore>) -> Arc<Self> {
        Arc::new(Self {
            proposal_admission,
            armed: AtomicBool::new(false),
            released: watch::channel(false).0,
            observed: watch::channel(GateObservation::default()).0,
            pair: Barrier::new(2),
        })
    }

    fn enter(self: &Arc<Self>, target: ConsensusNodeId, task: tokio::task::Id) -> ReadCall {
        // Latch this before any await in the transport. An older read's second
        // reply must not become part of the later admission round.
        let armed = self.armed.load(Ordering::Acquire);
        let permits = self.proposal_admission.available_permits();
        let held = armed && permits == DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1;
        self.observed.send_modify(|state| {
            state.live_calls += 1;
            if armed && !held {
                state.entered_before_admission += 1;
            }
            if armed
                && permits != DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS
                && permits != DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1
            {
                state.unexpected_permit_count = true;
            }
        });
        ReadCall {
            gate: self.clone(),
            target,
            task,
            held,
        }
    }

    fn release(&self) {
        self.released.send_replace(true);
    }

    async fn wait_held(&self) {
        let mut receiver = self.observed.subscribe();
        receiver
            .wait_for(|state| state.held.len() == 2)
            .await
            .unwrap();
    }

    async fn wait_drained(&self) {
        let mut receiver = self.observed.subscribe();
        receiver
            .wait_for(|state| state.live_calls == 0)
            .await
            .unwrap();
    }
}

struct ReleaseOnDrop(Arc<QuorumGate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct ReadCall {
    gate: Arc<QuorumGate>,
    target: ConsensusNodeId,
    task: tokio::task::Id,
    held: bool,
}

impl ReadCall {
    async fn deliver(&self, response: &ConsensusWireResponse) {
        let mut release = self.gate.released.subscribe();
        // Openraft 7104baa creates two fresh tasks per three-voter read, and
        // may otherwise finish on the first reply. Pair genuine replies from
        // the first SDK read onward, before either can return. Thus even a
        // late prior task has latched its phase before the next read begins.
        tokio::select! {
            _ = self.gate.pair.wait() => {}
            _ = release.wait_for(|released| *released) => return,
        }
        if !self.held || *release.borrow() {
            return;
        }
        let valid = response.result.as_ref().is_ok_and(|payload| {
            matches!(
                decode_config_wire_for_profile::<
                    Result<AppendEntriesResponse<ConsensusNodeId>, RaftError<ConsensusNodeId>>,
                >(payload, RetainedConfigProfile::NetconfTargetsV1),
                Ok(Ok(AppendEntriesResponse::Success))
            )
        });
        self.gate.observed.send_modify(|state| {
            state.repeated_target |= state.held.insert(self.target, self.task).is_some();
            state.valid_replies += usize::from(valid);
        });
        let _ = release.wait_for(|released| *released).await;
    }
}

impl Drop for ReadCall {
    fn drop(&mut self) {
        // Cancellation of a real RPC releases the observation too. A timeout
        // is never counted as a successful typed admission refusal.
        self.gate
            .observed
            .send_modify(|state| state.live_calls -= 1);
    }
}

#[derive(Default)]
struct StreamTasks {
    last_nonempty: Option<tokio::task::Id>,
    nonempty: Vec<tokio::task::Id>,
    empty: Vec<tokio::task::Id>,
}

struct NativePeer {
    target: ConsensusNodeId,
    handler: Mutex<Option<Arc<dyn ConsensusRpcHandler>>>,
    tasks: Mutex<StreamTasks>,
    gate: Mutex<Option<Arc<QuorumGate>>>,
}

impl NativePeer {
    fn new(target: ConsensusNodeId) -> Self {
        Self {
            target,
            handler: Mutex::new(None),
            tasks: Mutex::new(StreamTasks::default()),
            gate: Mutex::new(None),
        }
    }

    fn replication_task(&self) -> tokio::task::Id {
        self.tasks
            .lock()
            .unwrap()
            .last_nonempty
            .expect("PINNED_QUORUM_SETUP: real nonempty replication on each path")
    }

    fn attach(&self, gate: Arc<QuorumGate>) {
        let tasks = self.tasks.lock().unwrap();
        assert!(tasks.last_nonempty.is_some());
        assert!(
            tasks.empty.iter().all(|task| tasks.nonempty.contains(task)),
            "PINNED_QUORUM_SETUP: no unpaired read before native membership formation"
        );
        drop(tasks);
        *self.gate.lock().unwrap() = Some(gate);
    }
}

impl fmt::Debug for NativePeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativePeer")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ConsensusPeer for NativePeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let call = if request.family == ConsensusRpcFamily::AppendEntries {
            let rpc: AppendEntriesRequest<ConfigRaftTypeConfig> = decode_config_wire_for_profile(
                &request.payload,
                RetainedConfigProfile::NetconfTargetsV1,
            )
            .map_err(|_| ConsensusPeerError::Rejected)?;
            let task = tokio::task::try_id().ok_or(ConsensusPeerError::Unavailable)?;
            let fresh = {
                let mut tasks = self.tasks.lock().unwrap();
                if rpc.entries.is_empty() {
                    if !tasks.empty.contains(&task) {
                        tasks.empty.push(task);
                    }
                    tasks.last_nonempty != Some(task)
                } else {
                    tasks.last_nonempty = Some(task);
                    if !tasks.nonempty.contains(&task) {
                        tasks.nonempty.push(task);
                    }
                    false
                }
            };
            // Read quorum probes and replication heartbeats have identical
            // wire fields. The pinned engine uses persistent replication tasks
            // and fresh read tasks. Never infer this distinction from bytes.
            let gate = self.gate.lock().unwrap().clone();
            gate.filter(|gate| fresh && !*gate.released.borrow())
                .map(|gate| gate.enter(self.target, task))
        } else {
            None
        };
        let handler = self
            .handler
            .lock()
            .unwrap()
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        let response = handler.handle(request.sender, request).await;
        if let Some(call) = call {
            call.deliver(&response).await;
        }
        Ok(response)
    }
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x73; 32]).unwrap()
}

fn caller() -> AuditCaller {
    AuditCaller::project(&privacy(), TENANT, PRINCIPAL).unwrap()
}

fn event(request: u8, tx: Option<TxId>) -> ManagementAuditEventRecord {
    let tx = tx.map(|tx| tx.to_string());
    ManagementAuditEventRecord::try_new(
        [request; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        TENANT,
        PRINCIPAL,
        if request == 1 {
            ManagementAuditTransportCode::Internal
        } else {
            ManagementAuditTransportCode::NetconfSsh
        },
        if request == 1 {
            ManagementAuditOperationCode::Exec
        } else {
            ManagementAuditOperationCode::Replace
        },
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/synthetic:configuration"],
        tx.as_deref(),
    )
    .unwrap()
}

fn applied(value: AuditAdmission) -> AuditOperationReceipt {
    match value {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("native setup requires an authenticated original: {other:?}"),
    }
}

async fn wait_applied(store: &ConsensusConfigStore, index: u64) -> bool {
    let mut metrics = store.inner.raft.metrics();
    tokio::time::timeout(WAIT, async {
        loop {
            if metrics
                .borrow()
                .last_applied
                .as_ref()
                .is_some_and(|log| log.index >= index)
            {
                return true;
            }
            if metrics.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false)
}

type TableRows = Vec<Vec<rusqlite::types::Value>>;

async fn rows(store: &ConsensusConfigStore) -> rusqlite::Result<Vec<TableRows>> {
    let conn = store.inner.backend.conn();
    let conn = conn.lock().await;
    let tx = conn.unchecked_transaction()?;
    [
        "config_raft_log",
        "config_raft_machine",
        "config_raft_request_outcomes",
        "config_raft_management_audit",
        "config_history",
        "config_netconf_profile",
        "config_netconf_targets",
        "config_netconf_lifecycle",
    ]
    .into_iter()
    .map(|table| {
        let mut query = tx.prepare(&format!("SELECT * FROM {table} ORDER BY 1"))?;
        let columns = query.column_count();
        let selected = query.query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
        })?;
        selected.collect::<rusqlite::Result<Vec<_>>>()
    })
    .collect()
}

#[tokio::test]
async fn running_replacement_revocation_during_native_quorum_is_definite_and_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let nodes = [1, 2, 3].map(|node| ConfigConsensusNodeId::new(node).unwrap());
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x71; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x72; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let mut paths = BTreeMap::new();
    for source in 0..3 {
        for (target, node) in nodes.iter().enumerate() {
            if source != target {
                paths.insert((source, target), Arc::new(NativePeer::new(*node)));
            }
        }
    }
    let checkpoint = Arc::new(Checkpoint::default());
    let mut stores = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        let topology =
            ConfigConsensusTopology::try_new(identity, *node, nodes.into_iter().collect()).unwrap();
        let backend = SqliteBackend::provision_config_authority(
            RetainedConfigOptions::new(
                directory.path().join(format!("node-{index}.sqlite")),
                RetainedConfigBinding::new(topology.clone(), [0x74; 32], [index as u8 + 1; 32])
                    .unwrap()
                    .with_profile(RetainedConfigProfile::NetconfTargetsV1),
                RetainedConfigDurability::Ephemeral,
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap(),
            AuditKey::new([0x75; 32]).unwrap(),
        )
        .await
        .unwrap();
        let peers = (0..3)
            .filter(|target| *target != index)
            .map(|target| {
                let peer: Arc<dyn ConsensusPeer> = paths[&(index, target)].clone();
                (nodes[target], peer)
            })
            .collect();
        let policy = AuditContinuityPolicy::new(
            AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x76; 32]).unwrap()]).unwrap(),
            checkpoint.clone(),
            1,
            1,
        )
        .unwrap();
        stores.push(
            ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                directory.path().join(format!("snapshots-{index}")),
                peers,
                policy,
            )
            .await
            .unwrap(),
        );
    }
    for ((_, target), peer) in &paths {
        *peer.handler.lock().unwrap() = Some(stores[*target].rpc_handler());
    }
    let initialized = tokio::join!(
        stores[0].initialize_cluster(),
        stores[1].initialize_cluster(),
        stores[2].initialize_cluster(),
    );
    initialized.0.unwrap();
    initialized.1.unwrap();
    initialized.2.unwrap();
    let leader_id = stores
        .iter()
        .find_map(|store| store.status().leader_id)
        .unwrap();
    let leader = nodes.iter().position(|node| *node == leader_id).unwrap();
    let store = &stores[leader];
    let initial_index = store.status().applied_index.unwrap();
    for member in &stores {
        assert!(wait_applied(member, initial_index).await);
    }
    let gate = QuorumGate::new(store.inner.proposal_admission.clone());
    let release_on_drop = ReleaseOnDrop(gate.clone());
    let mut stream_tasks = BTreeMap::new();
    for target in 0..3 {
        if target != leader {
            let peer = &paths[&(leader, target)];
            stream_tasks.insert(target, peer.replication_task());
            peer.attach(gate.clone());
        }
    }
    // initialize_cluster uses membership and compatibility observations, not
    // an Openraft quorum read. Pairing is installed before the first real read.
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(96, 32).unwrap())
        .await
        .unwrap();
    let device = store
        .prepare_netconf_device(&privacy(), &event(1, None), LIFETIME)
        .await
        .unwrap();
    let intent = applied(
        store
            .admit_netconf_target_local(device.mutation(), caller())
            .await,
    );
    let result = applied(
        store
            .submit_netconf_target_local(device.mutation(), &intent, caller())
            .await,
    );
    store
        .complete_required_audit_outcome(&result, caller())
        .await
        .unwrap();
    let device = store
        .claim_netconf_device_owner(&device, &result, caller())
        .await
        .unwrap();
    let session = store.open_netconf_session(&device, caller()).await.unwrap();
    let frozen = store.read_netconf_running_edit(&session).await.unwrap();
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-quorum-revocation-key").unwrap(),
            opc_key::KeyPurpose::Config,
            TenantId::new(TENANT).unwrap(),
            zeroize::Zeroizing::new([0x77; 32]),
        )
        .unwrap();
    let plaintext = b"synthetic original Running replacement";
    let mut record = CommitRecord {
        tx_id: TxId::new(),
        parent_tx_id: frozen.tx_id(),
        version: ConfigVersion::new(frozen.running_base_version() + 1),
        committed_at: Timestamp::now_utc(),
        principal: PRINCIPAL.into(),
        source: crate::CommitSource::Netconf,
        schema_digest: SchemaDigest::from_bytes([0x78; 32]),
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: Vec::new(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let aad = EnvelopeAad::config(
        TenantId::new(TENANT).unwrap(),
        record.version.get(),
        ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            "running",
        )
        .unwrap(),
    );
    let envelope = opc_crypto::encrypt_attested_envelope(&provider, &aad, plaintext)
        .await
        .unwrap();
    record.encrypted_blob = envelope.encoded().to_vec();
    let tx_id = record.tx_id;
    let attested =
        AttestedConfigCommit::try_new(record, Vec::new(), envelope.claim().unwrap()).unwrap();
    let prepared = store
        .prepare_netconf_running_replacement(
            &session,
            &frozen,
            attested,
            &privacy(),
            &event(2, Some(tx_id)),
            LIFETIME,
        )
        .await
        .unwrap();
    let encoded_original = prepared.encode().unwrap();
    let before_index = store.status().applied_index.unwrap();
    let before_term = store.status().term;
    let before_log = store.inner.raft.metrics().borrow().last_log_index;
    let mut before = Vec::new();
    for member in &stores {
        assert!(wait_applied(member, before_index).await);
        before.push(rows(member).await.unwrap());
    }
    let before_checkpoint = checkpoint.0.lock().unwrap().clone();
    assert_eq!(
        store.inner.proposal_admission.available_permits(),
        DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
        "PINNED_QUORUM_SETUP: this admission is the sole proposal owner"
    );
    // Arm only this call; no other task submits writes or reads in this phase.
    gate.armed.store(true, Ordering::Release);
    let pending_store = store.clone();
    let retained_owner = session.clone();
    let retained_original = prepared.clone();
    let mut pending = tokio::spawn(async move {
        pending_store
            .admit_netconf_running_replacement_local(&retained_owner, &retained_original, caller())
            .await
    });
    let reached = tokio::time::timeout(WAIT, gate.wait_held()).await.is_ok();
    let still_pending = !pending.is_finished();
    let held_observation = gate.observed.borrow().clone();
    let held_permits = store.inner.proposal_admission.available_permits();
    let held_log = store.inner.raft.metrics().borrow().last_log_index;
    session.invalidate();
    gate.release();

    // Always release and join before assertions, including failed setup and
    // removal controls. Do not infer an atomic refusal from an elapsed timer.
    let completion = tokio::time::timeout(WAIT, &mut pending).await;
    if completion.is_err() {
        pending.abort();
        let _ = pending.await;
    }
    let drained = tokio::time::timeout(WAIT, gate.wait_drained())
        .await
        .is_ok();
    let absent = store
        .lookup_audit_operation(prepared.handle(), caller())
        .await;
    let head = store.load_latest().await;
    let after_log = store.inner.raft.metrics().borrow().last_log_index;
    let after_term = store.status().term;
    let after_leader = store.status().leader_id;
    let streams_unchanged = stream_tasks.iter().all(|(target, task)| {
        paths[&(leader, *target)]
            .tasks
            .lock()
            .unwrap()
            .last_nonempty
            == Some(*task)
    });
    let shutdown = tokio::join!(
        stores[0].shutdown(),
        stores[1].shutdown(),
        stores[2].shutdown(),
    );
    for peer in paths.values() {
        peer.handler.lock().unwrap().take();
    }
    // Read persisted rows only after all native nodes have joined. The result
    // cannot merely precede a delayed append or state-machine effect.
    let mut after = Vec::new();
    for member in &stores {
        after.push(rows(member).await);
    }
    let after_checkpoint = checkpoint.0.lock().unwrap().clone();
    let returned_permits = store.inner.proposal_admission.available_permits();
    drop(release_on_drop);

    assert!(reached && still_pending, "PINNED_QUORUM_WAIT_REACHED");
    assert!(drained, "PINNED_QUORUM_REPLIES_DRAINED");
    shutdown.0.unwrap();
    shutdown.1.unwrap();
    shutdown.2.unwrap();
    assert_eq!(held_observation.live_calls, 2);
    assert_eq!(held_observation.held.len(), 2);
    assert_eq!(
        held_observation.valid_replies, 2,
        "PINNED_QUORUM_REAL_REPLIES"
    );
    assert_eq!(held_observation.entered_before_admission, 4);
    assert!(!held_observation.repeated_target);
    assert!(!held_observation.unexpected_permit_count);
    assert_eq!(held_permits, DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1);
    assert_eq!(held_log, before_log, "PINNED_QUORUM_BEFORE_ENQUEUE");
    assert!(streams_unchanged, "PINNED_QUORUM_STABLE_STREAM_TASKS");
    assert_eq!(after_term, before_term, "PINNED_QUORUM_STABLE_TERM");
    assert_eq!(after_leader, Some(leader_id));
    for (target, task) in &held_observation.held {
        let index = nodes.iter().position(|node| node == target).unwrap();
        assert_ne!(*task, stream_tasks[&index]);
    }
    let held_tasks: Vec<_> = held_observation.held.values().collect();
    assert_ne!(held_tasks[0], held_tasks[1], "PINNED_QUORUM_FRESH_TASKS");
    assert_eq!(returned_permits, DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS);
    let outcome = completion
        .expect("PINNED_QUORUM_COMPLETION: original deadline is unchanged")
        .expect("PINNED_QUORUM_COMPLETION: admission task joins");
    assert!(
        matches!(
            outcome,
            AuditAdmission::Rejected(AuditAuthorityError::BindingMismatch)
        ),
        "RUNNING_QUORUM_REVOCATION_DEFINITE: {outcome:?}"
    );
    assert_eq!(after_log, before_log, "RUNNING_QUORUM_NO_LOG");
    for (actual, original) in after.into_iter().zip(before) {
        assert_eq!(
            actual.unwrap(),
            original,
            "RUNNING_QUORUM_NO_INTENT_OR_EFFECT"
        );
    }
    assert!(
        absent.unwrap().is_none(),
        "RUNNING_QUORUM_NO_ORIGINAL_INTENT"
    );
    assert!(head.unwrap().is_none(), "RUNNING_QUORUM_EMPTY_HISTORY");
    assert_eq!(after_checkpoint, before_checkpoint);
    assert_eq!(prepared.encode().unwrap(), encoded_original);
    assert!(session.require_active().is_err());
}
