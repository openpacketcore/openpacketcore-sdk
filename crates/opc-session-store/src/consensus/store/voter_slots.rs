//! Fixed incarnation profile; every consensus effect remains owned by Openraft.

use super::super::raft_adapter::{decode_and_bind_sender, encode_engine_result};
use super::*;
use opc_consensus::engine::{
    error::{InstallSnapshotError, RaftError},
    raft::{InstallSnapshotRequest, InstallSnapshotResponse},
    Snapshot, SnapshotMeta, Vote,
};
use opc_consensus::engine::{
    raft::{AppendEntriesRequest, AppendEntriesResponse, VoteRequest},
    EntryPayload,
};
use opc_consensus::voter_slots::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) type SessionVoterAdmission =
    VoterAdmission<RaftVoterResponseFence<SessionRaftTypeConfig>>;
pub(crate) type SessionVoterTransport =
    VoterTransport<RaftVoterResponseFence<SessionRaftTypeConfig>>;

pub(super) struct SessionVoterSetup {
    pub(super) genesis: VoterSlotTable,
    pub(super) initial: VoterSlotTable,
    pub(super) local: SessionConsensusNodeId,
    pub(super) resolver: Arc<dyn VoterPeerResolver>,
}

pub(super) struct SessionVoterProfile {
    pub(super) admission: Arc<SessionVoterAdmission>,
    pub(super) transport: Arc<SessionVoterTransport>,
    pub(super) core: crate::sqlite::consensus::SqliteConsensusCore,
    incoming: tokio::sync::Mutex<Option<IncomingSnapshot>>,
}

// One coordinator owns accepted work through completion. This cache is keyed
// by the exact operation, Prepare cut and leader vote; retries never resubmit
// a Marker whose client_write is still pending, or restart a snapshot's prefix.
#[derive(Default)]
struct ReplacementProgress {
    key: Option<([u8; 32], VoterSlotLogId, Vote<SessionConsensusNodeId>)>,
    marker: Option<VoterSlotLogId>,
    snapshot_requested: bool,
    snapshot: Option<SnapshotDelivery>,
    retry_delay: Duration,
}

impl ReplacementProgress {
    fn select(&mut self, operation: &VoterReplacementRecord, vote: Vote<SessionConsensusNodeId>) {
        let key = (
            operation.attestation.request_digest,
            operation.evidence.prepare,
            vote,
        );
        if self.key != Some(key) {
            *self = Self {
                key: Some(key),
                ..Self::default()
            };
        }
    }

    fn backoff(&mut self) -> Duration {
        self.retry_delay = if self.retry_delay.is_zero() {
            Duration::from_millis(200)
        } else {
            (self.retry_delay * 2).min(Duration::from_secs(5))
        };
        self.retry_delay
    }
}

struct SnapshotDelivery {
    artifact: Snapshot<SessionRaftTypeConfig>,
    evidence: VoterSnapshotEvidence,
    offset: u64,
    finishing: bool,
}

struct IncomingSnapshot {
    source: SessionConsensusNodeId,
    vote: Vote<SessionConsensusNodeId>,
    meta: SnapshotMeta<SessionConsensusNodeId, EmptyNode>,
    replacement: Option<[u8; 32]>,
    offset: u64,
    data: Box<super::super::snapshot::SessionSnapshotFile>,
}

#[derive(Debug, Serialize, Deserialize)]
enum ControlRequest {
    LossProbe {
        target: SessionConsensusNodeId,
        request_digest: [u8; 32],
        nonce: [u8; 32],
    },
    SnapshotInstalled {
        request_digest: [u8; 32],
        evidence: VoterSnapshotEvidence,
    },
    AppliedMarker {
        request_digest: [u8; 32],
        marker: VoterSlotLogId,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum ControlReply {
    LossProbe {
        nonce: [u8; 32],
        result: Result<(), VoterReplacementError>,
    },
    SnapshotInstalled(VoterSnapshotEvidence),
    AppliedMarker(VoterSlotLogId),
}

impl SessionVoterProfile {
    async fn control(
        &self,
        store: &ConsensusSessionStore,
        request: ControlRequest,
    ) -> Result<ControlReply, VoterReplacementError> {
        match request {
            ControlRequest::LossProbe { target, nonce, .. } => {
                let result = if target == store.inner.local_node_id {
                    Err(VoterReplacementError::TargetStillLive)
                } else {
                    self.admission.check_target_absent(target)
                };
                Ok(ControlReply::LossProbe { nonce, result })
            }
            ControlRequest::SnapshotInstalled {
                request_digest,
                evidence,
            } => {
                let local = store.inner.local_node_id;
                let state = Reader(self.core.clone()).read_voter_slot_state().await?;
                let operation = state
                    .table()
                    .replacement
                    .as_ref()
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                let selected = state
                    .table()
                    .slots
                    .iter()
                    .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                if operation.attestation.request_digest != request_digest
                    || selected.member.identity.node_id() != local
                {
                    return Err(VoterReplacementError::InvalidTransition);
                }
                let snapshot = Reader(self.core.clone())
                    .snapshot()?
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                let cut = snapshot
                    .0
                    .last_log_id
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                let observed = VoterSnapshotEvidence {
                    cut: VoterSlotLogId {
                        term: cut.leader_id.term,
                        index: cut.index,
                    },
                    snapshot_id: snapshot.0.snapshot_id,
                    digest: snapshot.2,
                };
                if observed != evidence {
                    return Err(VoterReplacementError::InvalidTransition);
                }
                Ok(ControlReply::SnapshotInstalled(observed))
            }
            ControlRequest::AppliedMarker {
                request_digest,
                marker,
            } => {
                let local = store.inner.local_node_id;
                let state = Reader(self.core.clone()).read_voter_slot_state().await?;
                let operation = state
                    .table()
                    .replacement
                    .as_ref()
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                let selected = state
                    .table()
                    .slots
                    .iter()
                    .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
                    .ok_or(VoterReplacementError::InvalidTransition)?;
                let applied = operation.attestation.request_digest == request_digest
                    && selected.member.identity.node_id() == local
                    && operation.phase >= VoterReplacementPhase::LearnerAdded
                    && Reader(self.core.clone()).before(0)?.0.is_some_and(|cut| {
                        cut.leader_id.term == marker.term && cut.index >= marker.index
                    });
                if !applied {
                    return Err(VoterReplacementError::InvalidTransition);
                }
                Ok(ControlReply::AppliedMarker(marker))
            }
        }
    }
    pub(super) async fn new(
        local: SessionConsensusNodeId,
        core: crate::sqlite::consensus::SqliteConsensusCore,
        resolver: Arc<dyn VoterPeerResolver>,
    ) -> Result<Arc<Self>, ConsensusSessionStoreOpenError> {
        let admission = SessionVoterAdmission::new(local, Arc::new(Reader(core.clone())))
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        #[cfg(target_os = "linux")]
        core.private_wal
            .as_ref()
            .ok_or(ConsensusSessionStoreOpenError::StorageUnavailable)?
            .attach_voter_admission(&admission)
            .map_err(|_| ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration)?;
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/session-consensus/fixed-incarnation-durable/v1\0");
        digest.update(crate::sqlite::consensus::voter_slots::COMMAND_VERSION.to_be_bytes());
        digest.update(SESSION_CONSENSUS_SCHEMA_VERSION.to_be_bytes());
        let transport = SessionVoterTransport::new(
            local,
            admission.clone(),
            resolver,
            digest.finalize().into(),
        );
        Ok(Arc::new(Self {
            admission,
            transport,
            core,
            incoming: tokio::sync::Mutex::new(None),
        }))
    }

    pub(super) fn application_admitted(&self, raft: &SessionRaft) -> bool {
        if !self.admission.local_voting_admitted() {
            return false;
        }
        let Ok(state) = self.admission.durable_view() else {
            return false;
        };
        let metrics = raft.metrics().borrow().clone();
        let membership = metrics.membership_config;
        let Some(cut) = *membership.log_id() else {
            return false;
        };
        let mut table = state.table().clone();
        table
            .observe_membership(
                membership.membership().get_joint_config(),
                &membership.nodes().map(|(node, _)| *node).collect(),
                VoterSlotLogId {
                    term: cut.leader_id.term,
                    index: cut.index,
                },
            )
            .is_ok()
            && table == *state.table()
    }

    async fn wait_candidate_ack(
        &self,
        raft: &SessionRaft,
        local: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> Result<(), VoterReplacementError> {
        if self.admission.local_voting_admitted() {
            return Ok(());
        }
        let is_voter = raft
            .with_raft_state(move |state| {
                state
                    .membership_state
                    .effective()
                    .membership()
                    .voter_ids()
                    .any(|node| node == local)
            })
            .await
            .map_err(|_| VoterReplacementError::Unavailable)?;
        if !is_voter {
            return Ok(());
        }
        let mut changed = self.core.applied_progress.subscribe();
        loop {
            // Never await admission's serial coordinator while holding the
            // incoming request guard; publication has its own independent task.
            let state = Reader(self.core.clone()).read_voter_slot_state().await?;
            if state.table().slots.iter().any(|slot| {
                slot.member.identity.node_id() == local && slot.phase == VoterSlotPhase::Voting
            }) {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, changed.changed())
                .await
                .map_err(|_| VoterReplacementError::Deadline)?
                .map_err(|_| VoterReplacementError::Unavailable)?;
        }
    }

    pub(super) async fn receive_snapshot(
        self: &Arc<Self>,
        store: &ConsensusSessionStore,
        source: SessionConsensusNodeId,
        rpc: InstallSnapshotRequest<SessionRaftTypeConfig>,
        replacement: Option<[u8; 32]>,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusWireResponse, VoterReplacementError> {
        let admission_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        if admission_budget.is_zero() {
            return Err(VoterReplacementError::Deadline);
        }
        let unavailable = |_| VoterReplacementError::Unavailable;
        let current_vote = store
            .inner
            .raft
            .with_raft_state(|state| *state.vote_ref())
            .await
            .map_err(unavailable)?;
        if rpc.vote < current_vote {
            let result: Result<_, RaftError<SessionConsensusNodeId, InstallSnapshotError>> =
                Ok(InstallSnapshotResponse { vote: current_vote });
            return Ok(
                encode_engine_result(&result).map_or_else(rejected, |payload| {
                    SessionConsensusWireResponse {
                        result: Ok(payload),
                    }
                }),
            );
        }
        let mut incoming = self.incoming.lock().await;
        if rpc.offset == 0
            && incoming.as_ref().is_none_or(|assembly| {
                assembly.source != source
                    || assembly.vote != rpc.vote
                    || assembly.meta != rpc.meta
                    || assembly.replacement != replacement
            })
        {
            // A new authenticated transfer owns a new file; stale chunks cannot
            // finish a predecessor leader's transfer.
            *incoming = Some(IncomingSnapshot {
                source,
                vote: rpc.vote,
                meta: rpc.meta.clone(),
                replacement,
                offset: 0,
                data: store
                    .inner
                    .raft
                    .begin_receiving_snapshot()
                    .await
                    .map_err(|_| VoterReplacementError::Unavailable)?,
            });
        }
        let assembly = incoming
            .as_mut()
            .ok_or(VoterReplacementError::InvalidTransition)?;
        if assembly.source != source
            || assembly.vote != rpc.vote
            || assembly.meta != rpc.meta
            || assembly.replacement != replacement
            || assembly.offset < rpc.offset
        {
            return Err(VoterReplacementError::InvalidTransition);
        }
        let next = rpc
            .offset
            .checked_add(rpc.data.len() as u64)
            .filter(|length| *length <= super::super::snapshot::SNAPSHOT_ENVELOPE_MAX_BYTES)
            .ok_or(VoterReplacementError::InvalidTransition)?;
        if rpc.offset < assembly.offset {
            if next > assembly.offset || (rpc.done && next != assembly.offset) {
                return Err(VoterReplacementError::InvalidTransition);
            }
            // The receiver already verifies overlapping writes without
            // modifying accepted bytes; it is deliberately not readable yet.
            tokio::io::AsyncSeekExt::seek(&mut assembly.data, std::io::SeekFrom::Start(rpc.offset))
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            let replay = assembly.data.write_all(&rpc.data).await;
            tokio::io::AsyncSeekExt::seek(
                &mut assembly.data,
                std::io::SeekFrom::Start(assembly.offset),
            )
            .await
            .map_err(|_| VoterReplacementError::Unavailable)?;
            replay.map_err(|_| VoterReplacementError::InvalidTransition)?;
        } else {
            assembly
                .data
                .write_all(&rpc.data)
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            assembly.offset = next;
        }
        if !rpc.done {
            let result: Result<_, RaftError<SessionConsensusNodeId, InstallSnapshotError>> =
                Ok(InstallSnapshotResponse { vote: current_vote });
            return Ok(
                encode_engine_result(&result).map_or_else(rejected, |payload| {
                    SessionConsensusWireResponse {
                        result: Ok(payload),
                    }
                }),
            );
        }
        let mut assembly = incoming.take().ok_or(VoterReplacementError::Unavailable)?;
        drop(incoming);
        let mut inspected = storage::inspect_voter_snapshot(
            &store.inner.terminal_recovery_handoff_consumer,
            &mut assembly.data,
            &assembly.meta,
            deadline,
        )
        .await
        .map_err(|_| VoterReplacementError::InvalidTransition)?;
        let table = inspected.table.clone();
        assembly.data = inspected
            .data
            .take()
            .ok_or(VoterReplacementError::Unavailable)?;
        if table.is_retired(source)
            || table
                .replacement
                .as_ref()
                .map(|operation| operation.attestation.request_digest)
                != replacement
        {
            return Err(VoterReplacementError::UnauthorizedReplacement);
        }
        let members = assembly
            .meta
            .last_membership
            .nodes()
            .map(|(node, _)| *node)
            .collect();
        let raft = store.inner.raft.clone();
        // Inspection and accepted installation remain owned if the chunk's
        // caller times out. Give the verified artifact its own admission budget.
        let deadline = tokio::time::Instant::now() + admission_budget;
        let response = self
            .admission
            .run_snapshot(table, members, deadline, move || async move {
                // The caller may time out while the engine still installs.
                // Keep the verified namespace artifact with that owned call.
                let _inspected = inspected;
                Ok(raft
                    .install_full_snapshot(
                        assembly.vote,
                        Snapshot {
                            meta: assembly.meta,
                            snapshot: assembly.data,
                        },
                    )
                    .await)
            })
            .await?;
        let result: Result<
            InstallSnapshotResponse<SessionConsensusNodeId>,
            RaftError<SessionConsensusNodeId, InstallSnapshotError>,
        > = response.map(Into::into).map_err(RaftError::Fatal);
        self.wait_candidate_ack(&store.inner.raft, store.inner.local_node_id, deadline)
            .await?;
        Ok(
            encode_engine_result(&result).map_or_else(rejected, |payload| {
                SessionConsensusWireResponse {
                    result: Ok(payload),
                }
            }),
        )
    }
}

impl ConsensusSessionStore {
    /// Open the explicit Durable fixed-slot incarnation profile from a fresh installation.
    ///
    /// The resolver must prove both current workload credentials and the selected
    /// incarnation key on every channel. Legacy transports cannot enable this
    /// profile. The capability remains unadvertised until end-to-end qualification.
    pub async fn open_with_voter_slots_and_integrity(
        topology: ValidatedQuorumTopology,
        initial: VoterSlotTable,
        local: SessionConsensusNodeId,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        resolver: Arc<dyn VoterPeerResolver>,
        snapshot_integrity: super::super::SnapshotIntegrityPolicy,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        let genesis = topology
            .voter_slot_genesis()
            .cloned()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        initial
            .validate_successor_of(&genesis)
            .map_err(|_| ConsensusSessionStoreOpenError::InvalidTopology)?;
        let selected = initial
            .slots
            .iter()
            .find(|slot| slot.member.identity.node_id() == local)
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let local_genesis = topology
            .local_consensus_node_id()
            .and_then(|node| VoterSlotIdentity::from_node_id(node).ok())
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        if selected.member.identity.slot() != local_genesis.slot() {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        if initial != genesis
            && (selected.phase != VoterSlotPhase::Pending
                || initial.replacement.as_ref().is_none_or(|operation| {
                    operation.phase != VoterReplacementPhase::Prepared
                        || operation.attestation.slot != selected.member.identity.slot()
                }))
        {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        if backend.fenced_transition_profile != crate::FencedTransitionV2Profile::V2
            || topology.roster_attestation_trust_root().is_some()
        {
            return Err(ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration);
        }
        for member in &initial.current_configuration().members {
            let route = resolver
                .resolve(member)
                .map_err(|_| ConsensusSessionStoreOpenError::PeerSetMismatch)?;
            if route.member != *member || route.peer.node_id() != member.identity.node_id() {
                return Err(ConsensusSessionStoreOpenError::PeerSetMismatch);
            }
        }
        Self::open_fixed_quorum_inner(
            topology,
            backend,
            super::super::SnapshotDirectory::from_path(snapshot_dir),
            BTreeMap::new(),
            Arc::new(SystemClock),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            snapshot_integrity,
            SessionPersistenceMode::Durable,
            Some(SessionVoterSetup {
                genesis,
                initial,
                local,
                resolver,
            }),
        )
        .await
    }

    /// Read one atomically published bounded table and provisional intent.
    pub async fn voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        Reader(profile.core.clone()).read_voter_slot_state().await
    }

    /// Resolve an accepted request using current controller authorization and a
    /// fresh quorum read. Accepted claims are not revalidated against a later
    /// credential rotation or expiry. An absent bounded receipt returns `None`.
    pub async fn voter_replacement_status(
        &self,
        authority: &VoterReplacementAuthorization,
        authenticated_controller: &str,
        slot: SlotId,
        request_id: opc_consensus::ConsensusRequestId,
        request_digest: [u8; 32],
    ) -> Result<Option<VoterSlotDurableState>, VoterReplacementError> {
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        authority.authorize_slot(
            self.inner.storage_identity.cluster_id(),
            slot,
            authenticated_controller,
        )?;
        if !profile.admission.local_voting_admitted() {
            return Err(VoterReplacementError::Unavailable);
        }
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        tokio::time::timeout_at(deadline, self.inner.raft.ensure_linearizable())
            .await
            .map_err(|_| VoterReplacementError::Deadline)?
            .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?;
        let state = Reader(profile.core.clone()).state_until(deadline).await?;
        let retained = state
            .table()
            .replacement
            .as_ref()
            .filter(|operation| {
                operation.attestation.slot == slot && operation.attestation.request_id == request_id
            })
            .map(|operation| operation.attestation.request_digest)
            .or_else(|| {
                state
                    .table()
                    .slots
                    .iter()
                    .find(|record| record.member.identity.slot() == slot)
                    .and_then(|record| record.last_result.as_ref())
                    .filter(|result| result.request_id == request_id)
                    .map(|result| result.request_digest)
            });
        match retained {
            Some(digest) if digest == request_digest => Ok(Some(state)),
            Some(_) => Err(VoterReplacementError::IdempotencyConflict),
            None => Ok(None),
        }
    }

    /// Commit an authenticated loss selection, then let the store resume its bounded phases.
    /// Returns the durable Pending/result record after Prepare applies. Deadline
    /// ambiguity is `OutcomeUnknown`; status and exact retained retries resolve it.
    /// No application activation or scope lease is required for this control path.
    pub async fn replace_voter(
        &self,
        verified: VerifiedVoterReplacement,
    ) -> Result<VoterSlotDurableState, VoterReplacementError> {
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        verified.ensure_fresh()?;
        let request = verified.request().clone();
        profile
            .transport
            .validate_candidate_route(&request)
            .map_err(|_| VoterReplacementError::UnauthorizedReplacement)?;
        let state = self.voter_slot_state().await?;
        let retained = state
            .table()
            .replacement
            .as_ref()
            .filter(|operation| operation.attestation.request_id == request.attestation.request_id)
            .map(|operation| operation.attestation.request_digest)
            .or_else(|| {
                state
                    .table()
                    .slots
                    .iter()
                    .filter_map(|slot| slot.last_result.as_ref())
                    .find(|result| result.request_id == request.attestation.request_id)
                    .map(|result| result.request_digest)
            });
        if let Some(digest) = retained {
            return if digest == request.attestation.request_digest {
                Ok(state)
            } else {
                Err(VoterReplacementError::IdempotencyConflict)
            };
        }
        if state.intent().is_some() {
            return Err(VoterReplacementError::ReplacementInProgress);
        }
        if let Some(operation) = &state.table().replacement {
            if operation.attestation.slot != request.attestation.slot {
                return Err(VoterReplacementError::ReplacementInProgress);
            }
            if operation.phase >= VoterReplacementPhase::Fenced {
                return Err(VoterReplacementError::ReplacementPastFence);
            }
        }
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        let probe_store = self.clone();
        let probe_request = request.clone();
        let store = self.clone();
        let proposed = request.clone();
        profile
            .admission
            .run_leader_intent(
                request,
                deadline,
                move || async move {
                    probe_store.probe_loss(&probe_request, deadline).await?;
                    verified.ensure_fresh()
                },
                move || async move {
                    store
                        .write_slot_control(VoterSlotControl::Begin(Box::new(proposed)))
                        .await
                        .map(|_| ())
                },
            )
            .await?;
        self.voter_slot_state().await
    }

    async fn write_slot_control(
        &self,
        control: VoterSlotControl,
    ) -> Result<LogId<SessionConsensusNodeId>, VoterReplacementError> {
        let request_id = match &control {
            VoterSlotControl::Begin(request) => request.attestation.request_id,
            VoterSlotControl::Advance { request_id, .. }
            | VoterSlotControl::Marker { request_id, .. } => *request_id,
        };
        let command = SessionConsensusCommand {
            schema_version: crate::sqlite::consensus::voter_slots::COMMAND_VERSION,
            identity: self.inner.storage_identity,
            request_id,
            logical_time: self.inner.clock.now_utc(),
            intent: SessionMutationIntent::VoterSlotControl(
                control
                    .encode()
                    .map_err(|_| VoterReplacementError::InvalidTransition)?,
            ),
        };
        let result = self
            .inner
            .raft
            .client_write(command)
            .await
            .map_err(|_| VoterReplacementError::OutcomeUnknown)?;
        match result.data.result {
            Ok(SessionMutationOutcome::VoterSlotControl(Ok(()))) => Ok(result.log_id),
            Ok(SessionMutationOutcome::VoterSlotControl(Err(error))) => Err(error),
            _ => Err(VoterReplacementError::InvalidTransition),
        }
    }

    async fn slot_control_call(
        &self,
        target: SessionConsensusNodeId,
        request: &ControlRequest,
        deadline: tokio::time::Instant,
    ) -> Result<ControlReply, VoterReplacementError> {
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        let wire = SessionConsensusWireRequest::try_new(
            self.inner.storage_identity,
            self.inner.local_node_id,
            SessionConsensusRpcFamily::TopologyAdmissionBarrier,
            encode_bounded(request).map_err(|_| VoterReplacementError::InvalidTransition)?,
        )
        .map_err(|_| VoterReplacementError::InvalidTransition)?;
        let response = tokio::time::timeout_at(
            deadline,
            profile.transport.peer(target).call_with_timeout(
                wire,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            ),
        )
        .await
        .map_err(|_| VoterReplacementError::Unavailable)?
        .map_err(|_| VoterReplacementError::Unavailable)?;
        let result: Result<ControlReply, VoterReplacementError> = decode_bounded(
            &response
                .result
                .map_err(|_| VoterReplacementError::Unavailable)?,
        )
        .map_err(|_| VoterReplacementError::InvalidTransition)?;
        result
    }

    async fn probe_loss(
        &self,
        request: &VoterReplacementRequest,
        deadline: tokio::time::Instant,
    ) -> Result<(), VoterReplacementError> {
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        let target = VoterSlotIdentity::new(
            request.attestation.slot,
            request.attestation.expected_incarnation,
        )
        .node_id();
        if target == self.inner.local_node_id {
            return Err(VoterReplacementError::TargetStillLive);
        }
        profile.admission.check_target_absent(target)?;
        let state = self.voter_slot_state().await?;
        let configuration = state.table().current_configuration();
        let voters: BTreeSet<_> = configuration
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect();
        let nonce = rand::random();
        let probe_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(2));
        let mut jobs = tokio::task::JoinSet::new();
        for peer in voters
            .iter()
            .copied()
            .chain(std::iter::once(target))
            .collect::<BTreeSet<_>>()
        {
            if peer == self.inner.local_node_id || state.table().is_retired(peer) {
                continue;
            }
            let store = self.clone();
            let digest = request.attestation.request_digest;
            jobs.spawn(async move {
                (
                    peer,
                    store
                        .slot_control_call(
                            peer,
                            &ControlRequest::LossProbe {
                                target,
                                request_digest: digest,
                                nonce,
                            },
                            probe_deadline,
                        )
                        .await,
                )
            });
        }
        let mut survivors = usize::from(
            voters.contains(&self.inner.local_node_id) && profile.admission.local_voting_admitted(),
        );
        while let Some(reply) = jobs.join_next().await {
            match reply {
                Ok((
                    _,
                    Ok(ControlReply::LossProbe {
                        nonce: echoed,
                        result: Err(VoterReplacementError::TargetStillLive),
                    }),
                )) if echoed == nonce => return Err(VoterReplacementError::TargetStillLive),
                Ok((
                    peer,
                    Ok(ControlReply::LossProbe {
                        nonce: echoed,
                        result: Ok(()),
                    }),
                )) if echoed == nonce && peer != target && voters.contains(&peer) => survivors += 1,
                _ => {}
            }
        }
        // Count fresh target-key evidence even if its typed reply was refused.
        profile.admission.check_target_absent(target)?;
        if survivors < voters.len() / 2 + 1 {
            return Err(VoterReplacementError::NoSurvivingQuorum);
        }
        Ok(())
    }

    async fn drive_slot_replacement(
        &self,
        progress: &mut ReplacementProgress,
    ) -> Result<(), VoterReplacementError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        let cut = tokio::time::timeout_at(deadline, self.inner.raft.ensure_linearizable())
            .await
            .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?
            .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?;
        if let Some(cut) = cut {
            tokio::time::timeout_at(
                deadline,
                self.inner
                    .raft
                    .wait(None)
                    .applied_index_at_least(Some(cut.index), "replacement inherited prefix"),
            )
            .await
            .map_err(|_| VoterReplacementError::Deadline)?
            .map_err(|_| VoterReplacementError::Unavailable)?;
        }
        loop {
            let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
            let state = self.voter_slot_state().await?;
            let Some(operation) = state.table().replacement.clone() else {
                *progress = ReplacementProgress::default();
                return Ok(());
            };
            let vote = self
                .inner
                .raft
                .with_raft_state(|state| *state.vote_ref())
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            if !vote.is_committed() || vote.leader_id.voted_for() != Some(self.inner.local_node_id)
            {
                return Err(VoterReplacementError::NoSurvivingQuorum);
            }
            progress.select(&operation, vote);
            if operation.phase > VoterReplacementPhase::Prepared {
                progress.snapshot = None;
            }
            let advance = |step| VoterSlotControl::Advance {
                request_id: operation.attestation.request_id,
                request_digest: operation.attestation.request_digest,
                step,
            };
            let target = VoterSlotIdentity::new(
                operation.attestation.slot,
                operation
                    .attestation
                    .expected_incarnation
                    .next()
                    .map_err(|_| VoterReplacementError::IncarnationExhausted)?,
            )
            .node_id();
            match operation.phase {
                VoterReplacementPhase::Prepared => {
                    let retained: BTreeSet<_> = operation
                        .predecessor
                        .members
                        .iter()
                        .map(|member| member.identity.node_id())
                        .chain(std::iter::once(target))
                        .collect();
                    let obsolete = self
                        .inner
                        .raft
                        .with_raft_state(move |state| {
                            state
                                .membership_state
                                .effective()
                                .nodes()
                                .map(|(node, _)| *node)
                                .filter(|node| !retained.contains(node))
                                .collect::<BTreeSet<_>>()
                        })
                        .await
                        .map_err(|_| VoterReplacementError::Unavailable)?;
                    if !obsolete.is_empty() {
                        self.inner
                            .raft
                            .change_membership(
                                opc_consensus::engine::ChangeMembers::RemoveNodes(obsolete),
                                false,
                            )
                            .await
                            .map_err(|_| VoterReplacementError::OutcomeUnknown)?;
                    }
                    let evidence = self
                        .deliver_initial_snapshot(target, &operation, vote, progress)
                        .await?;
                    self.write_slot_control(advance(VoterReplacementStep::RecordSnapshot(
                        evidence,
                    )))
                    .await?;
                }
                VoterReplacementPhase::SnapshotInstalled => {
                    self.inner
                        .raft
                        .add_learner(target, EmptyNode {}, false)
                        .await
                        .map_err(|_| VoterReplacementError::OutcomeUnknown)?;
                }
                VoterReplacementPhase::LearnerAdded | VoterReplacementPhase::CaughtUp => {
                    let term = self
                        .inner
                        .raft
                        .with_raft_state(|state| state.vote_ref().leader_id.term)
                        .await
                        .map_err(|_| VoterReplacementError::Unavailable)?;
                    if operation.phase == VoterReplacementPhase::CaughtUp
                        && operation
                            .evidence
                            .caught_up
                            .is_some_and(|marker| marker.term == term)
                    {
                        self.write_slot_control(advance(VoterReplacementStep::Fence))
                            .await?;
                    } else {
                        let marker = if let Some(marker) = progress.marker {
                            marker
                        } else {
                            // This future stays owned until the engine resolves it.
                            // A caller deadline never authorizes another submission.
                            let marker = self
                                .write_slot_control(VoterSlotControl::Marker {
                                    request_id: operation.attestation.request_id,
                                    request_digest: operation.attestation.request_digest,
                                })
                                .await?;
                            let marker = VoterSlotLogId {
                                term: marker.leader_id.term,
                                index: marker.index,
                            };
                            progress.marker = Some(marker);
                            marker
                        };
                        match self
                            .slot_control_call(
                                target,
                                &ControlRequest::AppliedMarker {
                                    request_digest: operation.attestation.request_digest,
                                    marker,
                                },
                                deadline,
                            )
                            .await?
                        {
                            ControlReply::AppliedMarker(observed) if observed == marker => {}
                            _ => return Err(VoterReplacementError::InvalidTransition),
                        }
                        self.write_slot_control(advance(VoterReplacementStep::RecordCaughtUp(
                            marker,
                        )))
                        .await?;
                    }
                }
                VoterReplacementPhase::Fenced | VoterReplacementPhase::Joint => {
                    // No candidate RPC or catch-up barrier is permitted after Fence.
                    // The unchanged majority can complete both original denominators.
                    let members: BTreeSet<_> = operation
                        .successor
                        .members
                        .iter()
                        .map(|member| member.identity.node_id())
                        .collect();
                    self.inner
                        .raft
                        .change_membership(members, false)
                        .await
                        .map_err(|_| VoterReplacementError::OutcomeUnknown)?;
                }
                VoterReplacementPhase::Uniform => {
                    self.write_slot_control(advance(VoterReplacementStep::Finalize))
                        .await?;
                }
            }
        }
    }

    async fn deliver_initial_snapshot(
        &self,
        target: SessionConsensusNodeId,
        operation: &VoterReplacementRecord,
        vote: Vote<SessionConsensusNodeId>,
        progress: &mut ReplacementProgress,
    ) -> Result<VoterSnapshotEvidence, VoterReplacementError> {
        if progress.snapshot.is_none() {
            let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
            let mut snapshot = loop {
                let mut metrics = self.inner.raft.metrics();
                if let Some(snapshot) = self
                    .inner
                    .raft
                    .get_snapshot()
                    .await
                    .map_err(|_| VoterReplacementError::Unavailable)?
                {
                    if snapshot
                        .meta
                        .last_log_id
                        .is_some_and(|cut| cut.index >= operation.evidence.prepare.index)
                    {
                        break snapshot;
                    }
                }
                if !progress.snapshot_requested {
                    self.inner
                        .raft
                        .trigger()
                        .snapshot()
                        .await
                        .map_err(|_| VoterReplacementError::Unavailable)?;
                    progress.snapshot_requested = true;
                }
                tokio::time::timeout_at(deadline, metrics.changed())
                    .await
                    .map_err(|_| VoterReplacementError::Deadline)?
                    .map_err(|_| VoterReplacementError::Unavailable)?;
            };
            let cut = snapshot
                .meta
                .last_log_id
                .ok_or(VoterReplacementError::InvalidTransition)?;
            let (_, digest, _) = storage::verify_snapshot_envelope_reader(&mut snapshot.snapshot)
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            let evidence = VoterSnapshotEvidence {
                cut: VoterSlotLogId {
                    term: cut.leader_id.term,
                    index: cut.index,
                },
                snapshot_id: snapshot.meta.snapshot_id.clone(),
                digest,
            };
            progress.snapshot = Some(SnapshotDelivery {
                artifact: snapshot,
                evidence,
                offset: 0,
                finishing: false,
            });
        }
        let delivery = progress
            .snapshot
            .as_mut()
            .ok_or(VoterReplacementError::Unavailable)?;
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        let peer = profile.transport.peer(target);
        // A lost final reply may still have installed the artifact. Confirm it
        // before resending anything, using the same retained ID and digest.
        if delivery.finishing {
            let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
            if matches!(self.slot_control_call(target, &ControlRequest::SnapshotInstalled {
                request_digest: operation.attestation.request_digest,
                evidence: delivery.evidence.clone(),
            }, deadline).await, Ok(ControlReply::SnapshotInstalled(ref installed)) if *installed == delivery.evidence)
            {
                return Ok(delivery.evidence.clone());
            }
        }
        loop {
            // Recheck the actual engine vote and committed operation before
            // each chunk. Losing leadership or supersession discards this work
            // only when the coordinator observes that different operation key.
            let current_vote = self
                .inner
                .raft
                .with_raft_state(|state| *state.vote_ref())
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            let state = self.voter_slot_state().await?;
            if current_vote != vote
                || state.table().replacement.as_ref().is_none_or(|current| {
                    current.attestation.request_digest != operation.attestation.request_digest
                        || current.evidence.prepare != operation.evidence.prepare
                        || current.phase != VoterReplacementPhase::Prepared
                })
            {
                return Err(VoterReplacementError::NoSurvivingQuorum);
            }
            let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
            tokio::io::AsyncSeekExt::seek(
                &mut delivery.artifact.snapshot,
                std::io::SeekFrom::Start(delivery.offset),
            )
            .await
            .map_err(|_| VoterReplacementError::Unavailable)?;
            let mut bytes = vec![0_u8; 128 * 1024];
            let read = delivery
                .artifact
                .snapshot
                .read(&mut bytes)
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            bytes.truncate(read);
            let done = read == 0;
            delivery.finishing = done;
            let rpc = InstallSnapshotRequest::<SessionRaftTypeConfig> {
                vote,
                meta: delivery.artifact.meta.clone(),
                offset: delivery.offset,
                data: bytes,
                done,
            };
            let request = SessionConsensusWireRequest::try_new(
                self.inner.storage_identity,
                self.inner.local_node_id,
                SessionConsensusRpcFamily::InstallSnapshot,
                encode_bounded(&rpc).map_err(|_| VoterReplacementError::InvalidTransition)?,
            )
            .map_err(|_| VoterReplacementError::InvalidTransition)?;
            let response = tokio::time::timeout_at(
                deadline,
                peer.call_with_timeout(
                    request,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                ),
            )
            .await
            .map_err(|_| VoterReplacementError::Deadline)?
            .map_err(|_| VoterReplacementError::Unavailable)?;
            let payload = match response.result {
                Ok(payload) => payload,
                // A restarted receiver can definitively lack its assembly.
                // Only that rejection restarts the retained artifact; transport
                // loss and unknown outcomes keep the acknowledged offset.
                Err(opc_consensus::ConsensusPeerError::Rejected) => {
                    delivery.offset = 0;
                    delivery.finishing = false;
                    return Err(VoterReplacementError::InvalidTransition);
                }
                Err(_) => return Err(VoterReplacementError::Unavailable),
            };
            let result: Result<
                InstallSnapshotResponse<SessionConsensusNodeId>,
                RaftError<SessionConsensusNodeId, InstallSnapshotError>,
            > = decode_bounded(&payload).map_err(|_| VoterReplacementError::InvalidTransition)?;
            if result.map_err(|_| VoterReplacementError::Unavailable)?.vote > vote {
                return Err(VoterReplacementError::NoSurvivingQuorum);
            }
            delivery.offset += read as u64;
            if done {
                break;
            }
        }
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        match self
            .slot_control_call(
                target,
                &ControlRequest::SnapshotInstalled {
                    request_digest: operation.attestation.request_digest,
                    evidence: delivery.evidence.clone(),
                },
                deadline,
            )
            .await?
        {
            ControlReply::SnapshotInstalled(installed) if installed == delivery.evidence => {
                Ok(installed)
            }
            _ => Err(VoterReplacementError::InvalidTransition),
        }
    }
}

pub(super) fn start_coordinator(store: &ConsensusSessionStore) {
    let Some(profile) = &store.inner.voter_profile else {
        return;
    };
    let mut applied = profile.core.applied_progress.subscribe();
    let weak = Arc::downgrade(&store.inner);
    let mut metrics = store.inner.raft.metrics();
    tokio::spawn(async move {
        let mut progress = ReplacementProgress::default();
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if metrics.borrow().running_state.is_err() {
                return;
            }
            let store = ConsensusSessionStore { inner };
            let leader = metrics.borrow().current_leader == Some(store.inner.local_node_id);
            let pending = if leader {
                match store.voter_slot_state().await {
                    Ok(state) => {
                        if state.table().replacement.is_some() {
                            true
                        } else {
                            progress = ReplacementProgress::default();
                            false
                        }
                    }
                    // A transient publication interval cannot discard an
                    // outstanding Marker or acknowledged snapshot progress.
                    Err(_) => true,
                }
            } else {
                progress = ReplacementProgress::default();
                false
            };
            if pending {
                // Individual probes/chunks have deadlines. Never cancel a
                // submitted write or a progressing transfer at a whole-pass
                // deadline: its result is owned by this one coordinator.
                let _ = store.drive_slot_replacement(&mut progress).await;
            }
            drop(store);
            if pending {
                // Our own apply notifications must not turn an error into a
                // tight retry loop. Candidate recovery is checked at this cap.
                tokio::time::sleep(progress.backoff()).await;
            } else {
                tokio::select! {
                    changed = applied.changed() => if changed.is_err() { return; },
                    changed = metrics.changed() => if changed.is_err() { return; },
                }
            }
        }
    });
}

pub(super) async fn handle(
    service: &SessionConsensusService,
    proof: VerifiedVoterRpc,
    request: SessionConsensusWireRequest,
) -> SessionConsensusWireResponse {
    let Some(profile) = service.store.inner.voter_profile.clone() else {
        return rejected(SessionConsensusPeerError::ScopeMismatch);
    };
    let evidence = match profile.transport.authenticate(proof, &request) {
        Ok(evidence) => evidence,
        Err(error) => return rejected(error),
    };
    let sender = request.sender;
    // Decode and bind the proved leader request once, before choosing its gate.
    let append: Option<AppendEntriesRequest<SessionRaftTypeConfig>> =
        if request.family == SessionConsensusRpcFamily::AppendEntries {
            match decode_and_bind_sender(&request.payload, sender) {
                Ok(rpc) => Some(rpc),
                Err(error) => return rejected(error),
            }
        } else {
            None
        };
    let snapshot: Option<InstallSnapshotRequest<SessionRaftTypeConfig>> =
        if request.family == SessionConsensusRpcFamily::InstallSnapshot {
            match decode_and_bind_sender(&request.payload, sender) {
                Ok(rpc) => Some(rpc),
                Err(error) => return rejected(error),
            }
        } else {
            None
        };
    let admission = if let Some(rpc) = &append {
        VoterPeerRequest::AppendEntries {
            term: rpc.vote.leader_id.term,
        }
    } else if let Some(rpc) = &snapshot {
        VoterPeerRequest::InstallSnapshot {
            term: rpc.vote.leader_id.term,
        }
    } else {
        VoterPeerRequest::Other
    };
    let store = service.store.clone();
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    // The proof binds its claimed replacement to these exact payload bytes.
    // An initial Prepare can introduce the digest before this follower applies it.
    let proof_replacement = evidence.binding().replacement_digest;
    let result = profile
        .admission
        .clone()
        .run_peer_request(sender, admission, deadline, move || async move {
            let state = profile.admission.durable_view()?;
            let sender_voting = state.table().slots.iter().any(|slot| {
                slot.member.identity.node_id() == sender && slot.phase == VoterSlotPhase::Voting
            });
            if request.family != SessionConsensusRpcFamily::TopologyAdmissionBarrier
                && !sender_voting
            {
                return Err(VoterReplacementError::UnauthorizedReplacement);
            }
            match request.family {
                SessionConsensusRpcFamily::AppendEntries => {
                    let mut rpc = append.ok_or(VoterReplacementError::UnauthorizedReplacement)?;
                    let original_last = rpc.entries.last().map(|entry| entry.log_id);
                    let before = rpc.entries.first().map_or(0, |entry| entry.log_id.index);
                    let AppendAdmissionState {
                        state,
                        snapshot,
                        applied,
                        mut projected,
                    } = Reader(profile.core.clone())
                        .append_state(before, deadline)
                        .await?;
                    if state.table().slots.iter().any(|slot| {
                        slot.member.identity.node_id() == store.inner.local_node_id
                            && slot.phase == VoterSlotPhase::Pending
                    }) {
                        let prepare = state
                            .table()
                            .replacement
                            .as_ref()
                            .ok_or(VoterReplacementError::InvalidTransition)?
                            .evidence
                            .prepare;
                        let installed = snapshot.is_some_and(|snapshot| {
                            snapshot
                                .0
                                .last_log_id
                                .is_some_and(|cut| cut.index >= prepare.index)
                        });
                        if !installed {
                            return Err(VoterReplacementError::InvalidTransition);
                        }
                    }
                    let mut intent = None;
                    let mut prefix = rpc.entries.len();
                    for (offset, entry) in rpc.entries.iter().enumerate() {
                        if applied.is_some_and(|cut| entry.log_id.index <= cut.index) {
                            continue;
                        }
                        if let EntryPayload::Normal(command) = &entry.payload {
                            if command.identity != store.inner.storage_identity {
                                return Err(VoterReplacementError::InvalidTransition);
                            }
                            if let SessionMutationIntent::VoterSlotControl(bytes) = &command.intent
                            {
                                if command.schema_version
                                    != crate::sqlite::consensus::voter_slots::COMMAND_VERSION
                                {
                                    return Err(VoterReplacementError::InvalidTransition);
                                }
                                let control = VoterSlotControl::decode(bytes)
                                    .map_err(|_| VoterReplacementError::InvalidTransition)?;
                                if let VoterSlotControl::Begin(wanted) = control {
                                    wanted.validate()?;
                                    if proof_replacement.is_some_and(|digest| {
                                        digest != wanted.attestation.request_digest
                                            && state.table().replacement.as_ref().is_none_or(
                                                |operation| {
                                                    operation.attestation.request_digest != digest
                                                },
                                            )
                                    }) {
                                        return Err(VoterReplacementError::UnauthorizedReplacement);
                                    }
                                    let mut proposed = projected.clone();
                                    if proposed
                                        .apply_control(
                                            &VoterSlotControl::Begin(wanted.clone()),
                                            VoterSlotLogId {
                                                term: entry.log_id.leader_id.term,
                                                index: entry.log_id.index,
                                            },
                                        )
                                        .is_ok()
                                        && proposed != projected
                                    {
                                        intent = Some(*wanted);
                                        prefix = offset + 1;
                                        break;
                                    }
                                }
                            }
                        }
                        crate::sqlite::consensus::voter_slots::project_entry(
                            &mut projected,
                            entry,
                            store.inner.storage_identity,
                        )
                        .map_err(|_| VoterReplacementError::InvalidTransition)?;
                    }
                    rpc.entries.truncate(prefix);
                    let accepted_last = rpc
                        .entries
                        .last()
                        .map(|entry| entry.log_id)
                        .or(rpc.prev_log_id);
                    let raft = store.inner.raft.clone();
                    let mut response = if let Some(intent) = intent {
                        profile
                            .admission
                            .run_intent(
                                intent,
                                VoterIntentOrigin::ReplicatedAppend,
                                deadline,
                                move || async move { Ok(raft.append_entries(rpc).await) },
                            )
                            .await?
                    } else {
                        raft.append_entries(rpc).await
                    };
                    profile
                        .wait_candidate_ack(&store.inner.raft, store.inner.local_node_id, deadline)
                        .await?;
                    if original_last != accepted_last
                        && matches!(response, Ok(AppendEntriesResponse::Success))
                    {
                        response = Ok(AppendEntriesResponse::PartialSuccess(accepted_last));
                    }
                    Ok(
                        encode_engine_result(&response).map_or_else(rejected, |payload| {
                            SessionConsensusWireResponse {
                                result: Ok(payload),
                            }
                        }),
                    )
                }
                SessionConsensusRpcFamily::Vote => {
                    if !profile.admission.local_voting_admitted() {
                        return Err(VoterReplacementError::UnauthorizedReplacement);
                    }
                    let state = profile.admission.durable_view()?;
                    if !state.table().slots.iter().any(|slot| {
                        slot.member.identity.node_id() == sender
                            && slot.phase == VoterSlotPhase::Voting
                    }) {
                        return Err(VoterReplacementError::UnauthorizedReplacement);
                    }
                    let rpc: VoteRequest<SessionConsensusNodeId> =
                        decode_and_bind_sender(&request.payload, sender)
                            .map_err(|_| VoterReplacementError::UnauthorizedReplacement)?;
                    Ok(
                        encode_engine_result(&store.inner.raft.vote(rpc).await).map_or_else(
                            rejected,
                            |payload| SessionConsensusWireResponse {
                                result: Ok(payload),
                            },
                        ),
                    )
                }
                SessionConsensusRpcFamily::InstallSnapshot => {
                    let rpc = snapshot.ok_or(VoterReplacementError::UnauthorizedReplacement)?;
                    profile
                        .receive_snapshot(&store, sender, rpc, proof_replacement, deadline)
                        .await
                }
                SessionConsensusRpcFamily::TopologyAdmissionBarrier => {
                    let control = decode_bounded(&request.payload)
                        .map_err(|_| VoterReplacementError::InvalidTransition)?;
                    let response = profile.control(&store, control).await;
                    Ok(encode_bounded(&response).map_or_else(
                        |_| rejected(SessionConsensusPeerError::Protocol),
                        |payload| SessionConsensusWireResponse {
                            result: Ok(payload),
                        },
                    ))
                }
                SessionConsensusRpcFamily::LeadershipTransfer => {
                    if !profile.admission.local_voting_admitted() {
                        return Err(VoterReplacementError::UnauthorizedReplacement);
                    }
                    let rpc: opc_consensus::engine::raft::TransferLeaderRequest<
                        SessionConsensusNodeId,
                    > = decode_and_bind_sender(&request.payload, sender)
                        .map_err(|_| VoterReplacementError::UnauthorizedReplacement)?;
                    Ok(encode_engine_result(
                        &store.inner.raft.handle_leadership_transfer(rpc).await,
                    )
                    .map_or_else(rejected, |payload| {
                        SessionConsensusWireResponse {
                            result: Ok(payload),
                        }
                    }))
                }
                // Application/activation families are composed in the following
                // capability slice. No legacy scope bypass is granted here.
                _ => Err(VoterReplacementError::IncompatibleProfile),
            }
        })
        .await;
    match result {
        Ok(response) => response,
        Err(
            VoterReplacementError::UnauthorizedReplacement
            | VoterReplacementError::StaleIncarnation
            | VoterReplacementError::IncompatibleProfile,
        ) => rejected(SessionConsensusPeerError::ScopeMismatch),
        Err(VoterReplacementError::Deadline | VoterReplacementError::OutcomeUnknown) => {
            rejected(SessionConsensusPeerError::Timeout)
        }
        Err(_) => rejected(SessionConsensusPeerError::Rejected),
    }
}

fn rejected(error: SessionConsensusPeerError) -> SessionConsensusWireResponse {
    SessionConsensusWireResponse { result: Err(error) }
}

struct Reader(crate::sqlite::consensus::SqliteConsensusCore);

struct AppendAdmissionState {
    state: VoterSlotDurableState,
    snapshot: Option<crate::sqlite::consensus::CurrentSnapshot>,
    applied: Option<LogId<SessionConsensusNodeId>>,
    projected: VoterSlotTable,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionVoterStateReader")
            .finish_non_exhaustive()
    }
}
#[async_trait]
impl VoterSlotStateReader for Reader {
    async fn read_voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        #[cfg(target_os = "linux")]
        {
            self.wal()?
                .native_voter_slot_state()
                .map_err(|_| VoterReplacementError::Unavailable)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _core = &self.0;
            Err(VoterReplacementError::IncompatibleProfile)
        }
    }
}

impl Reader {
    async fn state_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<VoterSlotDurableState, VoterReplacementError> {
        #[cfg(target_os = "linux")]
        {
            self.wal()?
                .with_durable_voter_slots_until(deadline, |native| native.voter_slot_state())
                .await
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::TimedOut {
                        VoterReplacementError::Deadline
                    } else {
                        VoterReplacementError::Unavailable
                    }
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = deadline;
            Err(VoterReplacementError::IncompatibleProfile)
        }
    }

    async fn append_state(
        &self,
        end: u64,
        deadline: tokio::time::Instant,
    ) -> Result<AppendAdmissionState, VoterReplacementError> {
        #[cfg(target_os = "linux")]
        {
            self.wal()?
                .with_durable_voter_slots_until(deadline, |native| {
                    let (applied, projected) = native.voter_slots_before(end)?;
                    Ok(AppendAdmissionState {
                        state: native.voter_slot_state()?,
                        snapshot: native.business.current_snapshot(),
                        applied,
                        projected,
                    })
                })
                .await
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::TimedOut {
                        VoterReplacementError::Deadline
                    } else {
                        VoterReplacementError::Unavailable
                    }
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (end, deadline);
            Err(VoterReplacementError::IncompatibleProfile)
        }
    }

    #[cfg(target_os = "linux")]
    fn wal(&self) -> Result<&Arc<crate::sqlite::consensus::wal::Wal>, VoterReplacementError> {
        self.0
            .private_wal
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)
    }

    fn before(
        &self,
        end: u64,
    ) -> Result<(Option<LogId<SessionConsensusNodeId>>, VoterSlotTable), VoterReplacementError>
    {
        #[cfg(target_os = "linux")]
        {
            self.wal()?
                .native_voter_slots_before(end)
                .map_err(|_| VoterReplacementError::Unavailable)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = end;
            Err(VoterReplacementError::IncompatibleProfile)
        }
    }

    fn snapshot(
        &self,
    ) -> Result<Option<crate::sqlite::consensus::CurrentSnapshot>, VoterReplacementError> {
        #[cfg(target_os = "linux")]
        {
            self.wal()?
                .native_voter_snapshot()
                .map_err(|_| VoterReplacementError::Unavailable)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(VoterReplacementError::IncompatibleProfile)
        }
    }
}
