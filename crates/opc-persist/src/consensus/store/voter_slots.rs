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

#[cfg(test)]
mod tests;

pub(crate) type ConfigVoterAdmission = VoterAdmission<RaftVoterResponseFence<ConfigRaftTypeConfig>>;
pub(crate) type ConfigVoterTransport = VoterTransport<RaftVoterResponseFence<ConfigRaftTypeConfig>>;

pub(super) struct ConfigVoterSetup {
    pub(super) initial: VoterSlotTable,
    pub(super) resolver: Arc<dyn VoterPeerResolver>,
}

pub(super) struct ConfigVoterProfile {
    pub(super) admission: Arc<ConfigVoterAdmission>,
    pub(super) transport: Arc<ConfigVoterTransport>,
    core: super::super::sqlite::ConfigConsensusCore,
    incoming: tokio::sync::Mutex<Option<IncomingSnapshot>>,
}

// One coordinator owns accepted work through completion. This cache is keyed
// by the exact operation, Prepare cut and leader vote; retries never resubmit
// a Marker whose client_write is still pending, or restart a snapshot's prefix.
#[derive(Default)]
struct ReplacementProgress {
    key: Option<([u8; 32], VoterSlotLogId, Vote<ConsensusNodeId>)>,
    marker: Option<VoterSlotLogId>,
    snapshot_requested: bool,
    snapshot: Option<SnapshotDelivery>,
    retry_delay: Duration,
}

impl ReplacementProgress {
    fn select(&mut self, operation: &VoterReplacementRecord, vote: Vote<ConsensusNodeId>) {
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
    artifact: Snapshot<ConfigRaftTypeConfig>,
    evidence: VoterSnapshotEvidence,
    offset: u64,
    finishing: bool,
}

struct IncomingSnapshot {
    source: ConsensusNodeId,
    vote: Vote<ConsensusNodeId>,
    meta: SnapshotMeta<ConsensusNodeId, EmptyNode>,
    replacement: Option<[u8; 32]>,
    offset: u64,
    data: Box<super::super::snapshot_file::ConfigSnapshotFile>,
}

#[derive(Debug, Serialize, Deserialize)]
enum ControlRequest {
    LossProbe {
        target: ConsensusNodeId,
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
enum ControlReply {
    LossProbe {
        nonce: [u8; 32],
        result: Result<(), VoterReplacementError>,
    },
    SnapshotInstalled(VoterSnapshotEvidence),
    AppliedMarker(VoterSlotLogId),
}

impl ConfigVoterProfile {
    async fn control(
        &self,
        store: &ConsensusConfigStore,
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
                let identity = self.core.identity;
                let members = self.core.expected_members.clone();
                let observed = self
                    .core
                    .run_sqlite(move |conn| {
                        let state = super::super::sqlite::voter_slots::read_sync(conn)?
                            .ok_or_else(|| {
                                super::super::sqlite::invalid_data("missing config voter state")
                            })?;
                        let operation = state.table().replacement.as_ref().ok_or_else(|| {
                            super::super::sqlite::invalid_data("missing config replacement")
                        })?;
                        let selected = state
                            .table()
                            .slots
                            .iter()
                            .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
                            .ok_or_else(|| {
                                super::super::sqlite::invalid_data("missing config slot")
                            })?;
                        if operation.attestation.request_digest != request_digest
                            || selected.member.identity.node_id() != local
                        {
                            return Err(super::super::sqlite::invalid_data(
                                "config candidate binding mismatch",
                            ));
                        }
                        let snapshot = super::super::sqlite::read_current_snapshot_sync(
                            conn, identity, &members,
                        )?
                        .ok_or_else(|| {
                            super::super::sqlite::invalid_data(
                                "initial config snapshot not installed",
                            )
                        })?;
                        let cut = snapshot.0.last_log_id.ok_or_else(|| {
                            super::super::sqlite::invalid_data("config snapshot has no cut")
                        })?;
                        Ok(VoterSnapshotEvidence {
                            cut: VoterSlotLogId {
                                term: cut.leader_id.term,
                                index: cut.index,
                            },
                            snapshot_id: snapshot.0.snapshot_id,
                            digest: snapshot.2,
                        })
                    })
                    .await
                    .map_err(|_| VoterReplacementError::InvalidTransition)?;
                if observed != evidence {
                    return Err(VoterReplacementError::InvalidTransition);
                }
                Ok(ControlReply::SnapshotInstalled(observed))
            }
            ControlRequest::AppliedMarker {
                request_digest,
                marker,
            } => {
                let identity = self.core.identity;
                let local = store.inner.local_node_id;
                let applied = self
                    .core
                    .run_sqlite(move |conn| {
                        let state = super::super::sqlite::voter_slots::read_sync(conn)?
                            .ok_or_else(|| {
                                super::super::sqlite::invalid_data("missing config voter state")
                            })?;
                        let operation = state.table().replacement.as_ref().ok_or_else(|| {
                            super::super::sqlite::invalid_data("missing config replacement")
                        })?;
                        let selected = state
                            .table()
                            .slots
                            .iter()
                            .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
                            .ok_or_else(|| {
                                super::super::sqlite::invalid_data("missing config slot")
                            })?;
                        let applied = super::super::sqlite::read_applied_sync(conn, identity)?;
                        Ok(operation.attestation.request_digest == request_digest
                            && selected.member.identity.node_id() == local
                            && operation.phase >= VoterReplacementPhase::LearnerAdded
                            && applied.is_some_and(|cut| {
                                cut.leader_id.term == marker.term && cut.index >= marker.index
                            }))
                    })
                    .await
                    .map_err(|_| VoterReplacementError::Unavailable)?;
                if !applied {
                    return Err(VoterReplacementError::InvalidTransition);
                }
                Ok(ControlReply::AppliedMarker(marker))
            }
        }
    }
    pub(super) async fn new(
        local: ConsensusNodeId,
        core: super::super::sqlite::ConfigConsensusCore,
        resolver: Arc<dyn VoterPeerResolver>,
        compatibility: opc_consensus::ConsensusCompatibility,
    ) -> Result<Arc<Self>, ConfigConsensusOpenError> {
        let admission = ConfigVoterAdmission::new(local, Arc::new(Reader(core.clone())))
            .await
            .map_err(|_| ConfigConsensusOpenError::DurableIdentityMismatch)?;
        core.voter_admission
            .set(Arc::downgrade(&admission))
            .map_err(|_| ConfigConsensusOpenError::InvalidRuntimeConfiguration)?;
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/config-consensus/fixed-incarnation-durable/v1\0");
        digest.update(compatibility);
        digest.update(super::super::types::VOTER_SLOT_CONFIG_COMMAND_VERSION.to_be_bytes());
        digest.update(super::super::types::CONFIG_CONSENSUS_STORAGE_VERSION.to_be_bytes());
        digest.update(super::super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION.to_be_bytes());
        let transport =
            ConfigVoterTransport::new(local, admission.clone(), resolver, digest.finalize().into());
        Ok(Arc::new(Self {
            admission,
            transport,
            core,
            incoming: tokio::sync::Mutex::new(None),
        }))
    }

    pub(super) fn application_admitted(&self, raft: &ConfigRaft) -> bool {
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
        raft: &ConfigRaft,
        local: ConsensusNodeId,
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
        let mut changed = self.core.durable_progress.subscribe_applied();
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

    async fn receive_snapshot(
        self: &Arc<Self>,
        store: &ConsensusConfigStore,
        source: ConsensusNodeId,
        rpc: InstallSnapshotRequest<ConfigRaftTypeConfig>,
        replacement: Option<[u8; 32]>,
        deadline: tokio::time::Instant,
    ) -> Result<ConsensusWireResponse, VoterReplacementError> {
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
            let result: Result<_, RaftError<ConsensusNodeId, InstallSnapshotError>> =
                Ok(InstallSnapshotResponse { vote: current_vote });
            return Ok(
                encode_engine_result(&result).map_or_else(rejected, |payload| {
                    ConsensusWireResponse {
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
            .filter(|length| *length <= storage::SNAPSHOT_MAX_BYTES + 1024)
            .ok_or(VoterReplacementError::InvalidTransition)?;
        if rpc.offset < assembly.offset {
            if next > assembly.offset || (rpc.done && next != assembly.offset) {
                return Err(VoterReplacementError::InvalidTransition);
            }
            let mut retained = vec![0; rpc.data.len()];
            tokio::io::AsyncSeekExt::seek(&mut assembly.data, std::io::SeekFrom::Start(rpc.offset))
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            let read = assembly.data.read_exact(&mut retained).await;
            tokio::io::AsyncSeekExt::seek(
                &mut assembly.data,
                std::io::SeekFrom::Start(assembly.offset),
            )
            .await
            .map_err(|_| VoterReplacementError::Unavailable)?;
            read.map_err(|_| VoterReplacementError::Unavailable)?;
            if retained != rpc.data {
                return Err(VoterReplacementError::InvalidTransition);
            }
        } else {
            assembly
                .data
                .write_all(&rpc.data)
                .await
                .map_err(|_| VoterReplacementError::Unavailable)?;
            assembly.offset = next;
        }
        if !rpc.done {
            let result: Result<_, RaftError<ConsensusNodeId, InstallSnapshotError>> =
                Ok(InstallSnapshotResponse { vote: current_vote });
            return Ok(
                encode_engine_result(&result).map_or_else(rejected, |payload| {
                    ConsensusWireResponse {
                        result: Ok(payload),
                    }
                }),
            );
        }
        let mut assembly = incoming.take().ok_or(VoterReplacementError::Unavailable)?;
        drop(incoming);
        let table = storage::inspect_voter_snapshot(
            &self.core,
            &mut assembly.data,
            &assembly.meta,
            deadline,
        )
        .await
        .map_err(|_| VoterReplacementError::InvalidTransition)?;
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
            InstallSnapshotResponse<ConsensusNodeId>,
            RaftError<ConsensusNodeId, InstallSnapshotError>,
        > = response.map(Into::into).map_err(RaftError::Fatal);
        self.wait_candidate_ack(&store.inner.raft, store.inner.local_node_id, deadline)
            .await?;
        Ok(
            encode_engine_result(&result).map_or_else(rejected, |payload| ConsensusWireResponse {
                result: Ok(payload),
            }),
        )
    }
}

impl ConsensusConfigStore {
    /// Open the explicit Durable fixed-slot incarnation profile from a fresh installation.
    ///
    /// The resolver must prove both current workload credentials and the selected
    /// incarnation key on every channel. Legacy transports cannot enable this
    /// profile. The capability remains unadvertised until end-to-end qualification.
    pub async fn open_with_voter_slots(
        initial: VoterSlotTable,
        local: ConsensusNodeId,
        backend: SqliteBackend,
        snapshot_dir: impl Into<PathBuf>,
        resolver: Arc<dyn VoterPeerResolver>,
    ) -> Result<Self, ConfigConsensusOpenError> {
        let topology = ConfigConsensusTopology::for_voter_slots(&initial, local)
            .map_err(|_| ConfigConsensusOpenError::InvalidRuntimeConfiguration)?;
        let peers = initial
            .current_configuration()
            .members
            .iter()
            .filter(|member| member.identity.node_id() != local)
            .map(|member| {
                let route = resolver
                    .resolve(member)
                    .map_err(|_| ConfigConsensusOpenError::PeerSetMismatch)?;
                if route.member != *member || route.peer.node_id() != member.identity.node_id() {
                    return Err(ConfigConsensusOpenError::PeerSetMismatch);
                }
                Ok((member.identity.node_id(), route.peer))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Self::open_internal(
            topology,
            backend,
            snapshot_dir.into(),
            peers,
            Arc::new(SystemConfigConsensusClock),
            DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
            None,
            None,
            Some(ConfigVoterSetup { initial, resolver }),
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
            self.inner.identity.cluster_id(),
            slot,
            authenticated_controller,
        )?;
        if !profile.admission.local_voting_admitted() {
            return Err(VoterReplacementError::Unavailable);
        }
        tokio::time::timeout(
            self.inner.operation_timeout,
            self.inner.raft.ensure_linearizable(),
        )
        .await
        .map_err(|_| VoterReplacementError::Deadline)?
        .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?;
        let state = self.voter_slot_state().await?;
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
    ) -> Result<LogId<ConsensusNodeId>, VoterReplacementError> {
        let request_id = match &control {
            VoterSlotControl::Begin(request) => request.attestation.request_id,
            VoterSlotControl::Advance { request_id, .. }
            | VoterSlotControl::Marker { request_id, .. } => *request_id,
        };
        let command = super::super::ConfigConsensusCommand {
            schema_version: super::super::types::VOTER_SLOT_CONFIG_COMMAND_VERSION,
            identity: self.inner.identity,
            request_id,
            logical_time: self.inner.clock.now_utc(),
            intent: ConfigMutationIntent::VoterSlotControl(
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
            Ok(()) => Ok(result.log_id),
            Err(super::super::ConfigMutationFailure::VoterReplacement(error)) => Err(error),
            Err(_) => Err(VoterReplacementError::InvalidTransition),
        }
    }

    async fn slot_control_call(
        &self,
        target: ConsensusNodeId,
        request: &ControlRequest,
        deadline: tokio::time::Instant,
    ) -> Result<ControlReply, VoterReplacementError> {
        let profile = self
            .inner
            .voter_profile
            .as_ref()
            .ok_or(VoterReplacementError::IncompatibleProfile)?;
        let wire = ConsensusWireRequest::try_new(
            self.inner.identity,
            self.inner.local_node_id,
            ConsensusRpcFamily::TopologyAdmissionBarrier,
            encode_config_wire(request).map_err(|_| VoterReplacementError::InvalidTransition)?,
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
        let result: Result<ControlReply, VoterReplacementError> = decode_config_wire(
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
        target: ConsensusNodeId,
        operation: &VoterReplacementRecord,
        vote: Vote<ConsensusNodeId>,
        progress: &mut ReplacementProgress,
    ) -> Result<VoterSnapshotEvidence, VoterReplacementError> {
        if progress.snapshot.is_none() {
            let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
            let snapshot = loop {
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
            let (_, digest, _) = storage::verify_snapshot_envelope(snapshot.snapshot.path())
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
            let rpc = InstallSnapshotRequest::<ConfigRaftTypeConfig> {
                vote,
                meta: delivery.artifact.meta.clone(),
                offset: delivery.offset,
                data: bytes,
                done,
            };
            let request = ConsensusWireRequest::try_new(
                self.inner.identity,
                self.inner.local_node_id,
                ConsensusRpcFamily::InstallSnapshot,
                encode_config_wire(&rpc).map_err(|_| VoterReplacementError::InvalidTransition)?,
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
                InstallSnapshotResponse<ConsensusNodeId>,
                RaftError<ConsensusNodeId, InstallSnapshotError>,
            > = decode_config_wire(&payload)
                .map_err(|_| VoterReplacementError::InvalidTransition)?;
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

pub(super) fn start_coordinator(store: &ConsensusConfigStore) {
    if store.inner.voter_profile.is_none() {
        return;
    }
    let mut applied = store.inner.durable_progress.subscribe_applied();
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
            let store = ConsensusConfigStore { inner };
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
    service: &ConfigConsensusService,
    proof: VerifiedVoterRpc,
    request: ConsensusWireRequest,
) -> ConsensusWireResponse {
    let Some(profile) = service.store.inner.voter_profile.clone() else {
        return rejected(ConsensusPeerError::ScopeMismatch);
    };
    let evidence = match profile.transport.authenticate(proof, &request) {
        Ok(evidence) => evidence,
        Err(error) => return rejected(error),
    };
    let sender = request.sender;
    // Decode and bind the proved leader request once, before choosing its gate.
    let append: Option<AppendEntriesRequest<ConfigRaftTypeConfig>> =
        if request.family == ConsensusRpcFamily::AppendEntries {
            match decode_and_bind_sender(&request.payload, sender) {
                Ok(rpc) => Some(rpc),
                Err(error) => return rejected(error),
            }
        } else {
            None
        };
    let snapshot: Option<InstallSnapshotRequest<ConfigRaftTypeConfig>> =
        if request.family == ConsensusRpcFamily::InstallSnapshot {
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
            if request.family != ConsensusRpcFamily::TopologyAdmissionBarrier && !sender_voting {
                return Err(VoterReplacementError::UnauthorizedReplacement);
            }
            match request.family {
                ConsensusRpcFamily::AppendEntries => {
                    let mut rpc = append.ok_or(VoterReplacementError::UnauthorizedReplacement)?;
                    let original_last = rpc.entries.last().map(|entry| entry.log_id);
                    let state = Reader(profile.core.clone()).read_voter_slot_state().await?;
                    if state.table().slots.iter().any(|slot| {
                        slot.member.identity.node_id() == store.inner.local_node_id
                            && slot.phase == VoterSlotPhase::Pending
                    }) {
                        let identity = profile.core.identity;
                        let members = profile.core.expected_members.clone();
                        let prepare = state
                            .table()
                            .replacement
                            .as_ref()
                            .ok_or(VoterReplacementError::InvalidTransition)?
                            .evidence
                            .prepare;
                        let installed = profile
                            .core
                            .run_sqlite(move |conn| {
                                Ok(super::super::sqlite::read_current_snapshot_sync(
                                    conn, identity, &members,
                                )?
                                .is_some_and(|snapshot| {
                                    snapshot
                                        .0
                                        .last_log_id
                                        .is_some_and(|cut| cut.index >= prepare.index)
                                }))
                            })
                            .await
                            .map_err(|_| VoterReplacementError::Unavailable)?;
                        if !installed {
                            return Err(VoterReplacementError::InvalidTransition);
                        }
                    }
                    let mut intent = None;
                    let mut prefix = rpc.entries.len();
                    let identity = profile.core.identity;
                    let before = rpc.entries.first().map_or(0, |entry| entry.log_id.index);
                    let (applied, mut projected) = profile
                        .core
                        .run_sqlite(move |conn| {
                            Ok((
                                super::super::sqlite::read_applied_sync(conn, identity)?,
                                super::super::sqlite::voter_slots::projected_before_sync(
                                    conn, identity, before,
                                )?,
                            ))
                        })
                        .await
                        .map_err(|_| VoterReplacementError::Unavailable)?;
                    for (offset, entry) in rpc.entries.iter().enumerate() {
                        if applied.is_some_and(|cut| entry.log_id.index <= cut.index) {
                            continue;
                        }
                        if let EntryPayload::Normal(command) = &entry.payload {
                            command
                                .validate(store.inner.identity)
                                .map_err(|_| VoterReplacementError::InvalidTransition)?;
                            if let ConfigMutationIntent::VoterSlotControl(bytes) = &command.intent {
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
                        super::super::sqlite::voter_slots::project_entry(&mut projected, entry)
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
                            ConsensusWireResponse {
                                result: Ok(payload),
                            }
                        }),
                    )
                }
                ConsensusRpcFamily::Vote => {
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
                    let rpc: VoteRequest<ConsensusNodeId> =
                        decode_and_bind_sender(&request.payload, sender)
                            .map_err(|_| VoterReplacementError::UnauthorizedReplacement)?;
                    Ok(
                        encode_engine_result(&store.inner.raft.vote(rpc).await).map_or_else(
                            rejected,
                            |payload| ConsensusWireResponse {
                                result: Ok(payload),
                            },
                        ),
                    )
                }
                ConsensusRpcFamily::InstallSnapshot => {
                    let rpc = snapshot.ok_or(VoterReplacementError::UnauthorizedReplacement)?;
                    profile
                        .receive_snapshot(&store, sender, rpc, proof_replacement, deadline)
                        .await
                }
                ConsensusRpcFamily::TopologyAdmissionBarrier => {
                    let control = decode_config_wire(&request.payload)
                        .map_err(|_| VoterReplacementError::InvalidTransition)?;
                    let response = profile.control(&store, control).await;
                    Ok(encode_config_wire(&response).map_or_else(
                        |_| rejected(ConsensusPeerError::Protocol),
                        |payload| ConsensusWireResponse {
                            result: Ok(payload),
                        },
                    ))
                }
                _ => {
                    if request.family == ConsensusRpcFamily::LeadershipTransfer
                        && !profile.admission.local_voting_admitted()
                    {
                        return Err(VoterReplacementError::UnauthorizedReplacement);
                    }
                    let mut request = request;
                    request.identity = store.inner.identity;
                    let service = ConfigConsensusService {
                        store: store.clone(),
                    };
                    Ok(service
                        .handle_admitted(sender, request, Some(store.inner.compatibility.digest()))
                        .await)
                }
            }
        })
        .await;
    match result {
        Ok(response) => response,
        Err(
            VoterReplacementError::UnauthorizedReplacement
            | VoterReplacementError::StaleIncarnation
            | VoterReplacementError::IncompatibleProfile,
        ) => rejected(ConsensusPeerError::ScopeMismatch),
        Err(VoterReplacementError::Deadline | VoterReplacementError::OutcomeUnknown) => {
            rejected(ConsensusPeerError::Timeout)
        }
        Err(_) => rejected(ConsensusPeerError::Rejected),
    }
}

fn rejected(error: ConsensusPeerError) -> ConsensusWireResponse {
    ConsensusWireResponse { result: Err(error) }
}

struct Reader(super::super::sqlite::ConfigConsensusCore);
impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigVoterStateReader")
            .finish_non_exhaustive()
    }
}
#[async_trait]
impl VoterSlotStateReader for Reader {
    async fn read_voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        self.0
            .run_sqlite(super::super::sqlite::voter_slots::read_sync)
            .await
            .map_err(|_| VoterReplacementError::Unavailable)?
            .ok_or(VoterReplacementError::IncompatibleProfile)
    }
}

impl super::super::sqlite::ConfigConsensusCore {
    pub(crate) fn notify_voter_slots(&self) {
        if let Some(runtime) = self
            .voter_admission
            .get()
            .and_then(std::sync::Weak::upgrade)
        {
            runtime.notify_durable_changed();
        }
    }
}
