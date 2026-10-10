//! Unanimous activation of the exact scope authority and child-batch profile.

use super::*;
use crate::membership::{SessionTopologyTransitionDigest, SessionTopologyTransitionId};
use crate::scope_authority::{scope_profile_digest, ScopeProfileActivation};
use crate::scope_storage::{profile_key, ScopeRow};
use crate::sqlite::consensus::TerminalMembershipOutcome;

const PROBE_DOMAIN: [u8; 8] = *b"opc-sp-4";
const REPLY_DOMAIN: [u8; 8] = *b"opc-sr-4";
pub(super) const READ_BARRIER_DOMAIN: [u8; 8] = *b"opc-sb-4";

pub(super) fn is_scope_command(intent: &SessionMutationIntent) -> bool {
    matches!(
        intent,
        SessionMutationIntent::ScopeAuthority(_)
            | SessionMutationIntent::ScopeBatch(_)
            | SessionMutationIntent::ScopeBatchCancel(_)
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeProfileProbe {
    scope_profile_probe: [u8; 8],
    profile_digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScopeProfileReply {
    scope_profile_reply: [u8; 8],
    profile_digest: Option<[u8; 32]>,
}

pub(super) fn request_id(scope: SessionConsensusIdentity) -> SessionConsensusRequestId {
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/scope-profile/activation/4\0");
    hash.update(scope.cluster_id().as_bytes());
    hash.update(scope.configuration_id().as_bytes());
    hash.update(scope.configuration_epoch().get().to_be_bytes());
    hash.update(scope_profile_digest());
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize()[..16]);
    SessionConsensusRequestId::from_bytes(id)
}

impl ConsensusSessionStore {
    /// Scope traffic can cross the transition's admission latch while the
    /// activated predecessor still owns application authority. Its replicated
    /// Fence, rather than the long learner-catch-up barrier, drains old stamps.
    /// A durable Abort restores that authority before learner cleanup finishes.
    pub(super) async fn require_scope_traffic_authority_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        if self.exact_membership_is_admitted() {
            return self
                .require_application_traffic_authority_before(deadline)
                .await;
        }
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            || self.inner.retirement.is_started()
            || !self.inner.persistence_protocol.is_active()
            || !self.engine_is_running_in_local_scope()
            || self.local_scope_profile().is_none()
        {
            return Err(consensus_unavailable());
        }
        tokio::time::timeout_at(deadline, async {
            let expected = self.current_scope()?;
            let (scope, applied) = self
                .inner
                .backend
                .consensus_membership_scope_snapshot(self.inner.storage_identity)
                .await
                .map_err(|_| consensus_unavailable())?;
            let desired_members = match scope.pending.as_ref() {
                Some(pending) if pending.transition_start_log_index != 0 => {
                    &pending.desired_members
                }
                Some(_) => return Err(consensus_unavailable()),
                None => {
                    let terminal = scope
                        .terminal
                        .as_ref()
                        .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
                        .ok_or_else(consensus_unavailable)?;
                    let cleanup = terminal
                        .abort_cleanup
                        .as_ref()
                        .ok_or_else(consensus_unavailable)?;
                    // A retained abort cannot open an unrelated staging latch.
                    let _staged_request = self
                        .inner
                        .topology_coordinator
                        .staged_request(
                            SessionTopologyTransitionId::from_bytes(terminal.transition_id),
                            SessionTopologyTransitionDigest::from_bytes(terminal.transition_digest),
                        )
                        .map_err(|_| consensus_unavailable())?;
                    &cleanup.desired_members
                }
            };
            if scope.current_identity != expected.0
                || scope.current_members != expected.1
                || scope.application_authority_epoch != expected.0.configuration_epoch()
                || scope.application_authority_members != expected.1
                || !matches!(
                    membership::classify_applied_membership(
                        &applied,
                        &scope.current_members,
                        desired_members
                    ),
                    membership::AppliedMembershipShape::CurrentUniform
                        | membership::AppliedMembershipShape::Learners
                )
                || !self.scope_profile_matches(expected.0, &expected.1).await?
            {
                return Err(consensus_unavailable());
            }
            if !matches!(
                self.operator_recovery_gate_before(deadline).await,
                OperatorRecoveryGate::Clear
            ) || self.current_scope()? != expected
                || self.inner.retirement.is_started()
                || !self.inner.persistence_protocol.is_active()
                || !self.engine_is_running_in_local_scope()
            {
                return Err(consensus_unavailable());
            }
            Ok(())
        })
        .await
        .map_err(|_| consensus_unavailable())?
    }

    pub(super) async fn require_scope_read_authority_before(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.require_scope_traffic_authority_before(deadline)
            .await?;
        if self.current_scope()?.0 != scope.consensus_identity() {
            return Err(consensus_unavailable());
        }
        Ok(())
    }

    pub(super) async fn admit_scope_read_before(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<Option<ConsumerScopeAdmission>, StoreError> {
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum {
            return self
                .admit_consumer_scope(scope, deadline)
                .await
                .map(Some)
                .map_err(|_| consensus_unavailable());
        }
        self.require_scope_read_authority_before(scope, deadline)
            .await?;
        Ok(None)
    }

    pub(super) async fn scope_read_barrier_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, LinearizableBarrierFailure> {
        #[cfg(any(test, feature = "test-control"))]
        self.inner
            .scope_read_barriers_for_test
            .fetch_add(1, Ordering::Relaxed);
        self.linearizable_barrier_with_scope_admission_before(
            deadline,
            self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum,
        )
        .await
    }

    /// Activate the exact scope authority and child-batch profile for the current
    /// voter configuration. Initial activation requires every voter; later
    /// requests use the durable certificate and ordinary quorum availability
    /// across configuration changes. Membership transitions durably certify
    /// each joining voter before carrying activation into the successor.
    /// Scope services call this prerequisite automatically. Call it explicitly
    /// at startup to complete activation before the first scope operation.
    pub async fn activate_scope_profile(&self) -> Result<(), StoreError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        tokio::time::timeout_at(deadline, self.ensure_scope_profile_before(deadline))
            .await
            .map_err(|_| consensus_unavailable())?
    }

    pub(super) fn local_scope_profile(&self) -> Option<[u8; 32]> {
        #[cfg(test)]
        if !self.inner.scope_profile_supported.load(Ordering::Acquire) {
            return None;
        }
        (self.persistence_mode() == SessionPersistenceMode::Durable
            && self.inner.backend.consensus_log_entry_max_bytes()
                >= crate::scope_batch::MAX_SCOPE_BATCH_COMMAND_BYTES
            && SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
                >= crate::scope_batch::MAX_SCOPE_BATCH_COMMAND_BYTES)
            .then(scope_profile_digest)
    }

    pub(super) fn scope_profile_probe_reply(&self, probe: ScopeProfileProbe) -> ScopeProfileReply {
        ScopeProfileReply {
            scope_profile_reply: REPLY_DOMAIN,
            profile_digest: self.local_scope_profile().filter(|profile| {
                probe.scope_profile_probe == PROBE_DOMAIN && probe.profile_digest == *profile
            }),
        }
    }

    pub(super) async fn scope_profile_matches(
        &self,
        identity: SessionConsensusIdentity,
        voters: &BTreeSet<SessionConsensusNodeId>,
    ) -> Result<bool, StoreError> {
        let key = profile_key(identity.cluster_id()).map_err(|_| consensus_unavailable())?;
        let row = self
            .inner
            .backend
            .consensus_scope_record(self.inner.storage_identity, key)
            .await?;
        Ok(matches!(row, Some(ScopeRow::Activation(certificate))
            if certificate.matches(identity, fenced_transition_voter_set_digest(identity, voters))))
    }

    pub(super) async fn activated_scope_profile_is_current(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<bool, StoreError> {
        self.require_scope_traffic_authority_before(deadline)
            .await?;
        let expected = self.current_scope()?;
        if self.local_scope_profile().is_none() || !expected.1.contains(&self.inner.local_node_id) {
            return Ok(false);
        }
        let active = self.scope_profile_matches(expected.0, &expected.1).await?;
        self.require_scope_traffic_authority_before(deadline)
            .await?;
        Ok(active && self.current_scope()? == expected)
    }

    /// Initial activation is one cluster-level prerequisite. Successful scope
    /// mutations thereafter each use one command and normal quorum availability.
    pub(super) async fn ensure_scope_profile_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.require_scope_traffic_authority_before(deadline)
            .await?;
        if self.activated_scope_profile_is_current(deadline).await? {
            return Ok(());
        }
        self.activate_capability_before(deadline, CapabilityActivationKind::ScopeProfileV4)
            .await
    }

    pub(super) async fn require_scope_profile_after_read_admit(
        &self,
        read_admit: &LinearizableReadAdmit<SessionConsensusNodeId>,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionCapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.inner
            .read_barrier
            .revalidate(read_admit, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let expected = self.current_scope()?;
        let profile = self.local_scope_profile().ok_or_else(unsupported)?;
        if !expected.1.contains(&self.inner.local_node_id) {
            return Err(unsupported());
        }
        if let Some(applied_log_index) = self
            .inner
            .backend
            .consensus_capability_activation_applied_index(
                self.inner.storage_identity,
                expected.0,
                expected.1.clone(),
                CapabilityActivationKind::ScopeProfileV4,
            )
            .await?
        {
            if self.current_scope()? != expected || !self.exact_membership_is_admitted() {
                return Err(consensus_unavailable());
            }
            return Ok(FencedTransitionCapabilityAdmission::Activated { applied_log_index });
        }
        let (scope, _) = self
            .inner
            .backend
            .consensus_membership_scope_snapshot(self.inner.storage_identity)
            .await
            .map_err(|_| consensus_unavailable())?;
        if scope.pending.is_some() {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        // Every voter, including one unnecessary for the current majority,
        // must answer the exact independent wire/profile probe.
        let probes = expected
            .1
            .iter()
            .copied()
            .filter(|member| *member != self.inner.local_node_id)
            .map(|member| async move {
                let reply = self
                    .call_peer::<_, ScopeProfileReply>(
                        member,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &ScopeProfileProbe {
                            scope_profile_probe: PROBE_DOMAIN,
                            profile_digest: profile,
                        },
                        deadline,
                    )
                    .await
                    .map_err(|_| consensus_unavailable())?;
                if reply.scope_profile_reply != REPLY_DOMAIN
                    || reply.profile_digest != Some(profile)
                {
                    return Err(unsupported());
                }
                Ok(())
            });
        for result in futures_util::future::join_all(probes).await {
            result?;
        }
        if self.current_scope()? != expected || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(FencedTransitionCapabilityAdmission::FreshUnanimous)
    }

    pub(super) fn scope_profile_activation(
        scope: SessionConsensusIdentity,
        voters: [u8; 32],
    ) -> SessionMutationIntent {
        SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
            scope, voters,
        )))
    }
}

fn unsupported() -> StoreError {
    StoreError::CapabilityNotSupported("scope_store_profile_v4".into())
}
