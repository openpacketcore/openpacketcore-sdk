//! Unanimous activation of the exact scope authority and child-batch profile.

use super::*;
use crate::scope_lease::{scope_profile_digest, ScopeProfileActivation};
use crate::scope_storage::{profile_key, ScopeRow};

const PROBE_DOMAIN: [u8; 8] = *b"opc-sp-2";
const REPLY_DOMAIN: [u8; 8] = *b"opc-sr-2";

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
    hash.update(b"openpacketcore/scope-profile/activation/2\0");
    hash.update(scope.cluster_id().as_bytes());
    hash.update(scope.configuration_id().as_bytes());
    hash.update(scope.configuration_epoch().get().to_be_bytes());
    hash.update(scope_profile_digest());
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize()[..16]);
    SessionConsensusRequestId::from_bytes(id)
}

impl ConsensusSessionStore {
    /// Activate the exact scope lease and child-batch profile for the current
    /// voter configuration. Initial activation requires every voter; later
    /// requests use the durable certificate and ordinary quorum availability
    /// until a configuration change requires every new voter to answer again.
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

    pub(super) async fn activated_scope_profile_is_current(&self) -> Result<bool, StoreError> {
        self.require_exact_membership_admission()?;
        let expected = self.current_scope()?;
        if self.local_scope_profile().is_none() || !expected.1.contains(&self.inner.local_node_id) {
            return Ok(false);
        }
        let active = self.scope_profile_matches(expected.0, &expected.1).await?;
        Ok(active && self.current_scope()? == expected && self.exact_membership_is_admitted())
    }

    /// Initial activation is one cluster-level prerequisite. Successful scope
    /// mutations thereafter each use one command and normal quorum availability.
    pub(super) async fn ensure_scope_profile_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if self.activated_scope_profile_is_current().await? {
            return Ok(());
        }
        self.activate_capability_before(deadline, CapabilityActivationKind::ScopeProfileV2)
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
                CapabilityActivationKind::ScopeProfileV2,
            )
            .await?
        {
            if self.current_scope()? != expected || !self.exact_membership_is_admitted() {
                return Err(consensus_unavailable());
            }
            return Ok(FencedTransitionCapabilityAdmission::Activated { applied_log_index });
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
    StoreError::CapabilityNotSupported("scope_store_profile_v2".into())
}
