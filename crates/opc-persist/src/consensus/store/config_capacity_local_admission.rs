//! Process-local evidence for one owned immutable admission input. This is not
//! serializable, public authority, a capacity reservation or a received proof.

use super::{
    config_command_fits_replication_budget, config_command_revision,
    preflight_config_command_replication_budget, ConfigMutationIntent, ConsensusConfigStore,
    ForwardMutationRejection, ForwardMutationRequest, ForwardedBudget,
};
use crate::consensus::ConfigConsensusCommand;
use crate::PersistError;
use opc_consensus::ConsensusRequestId;
use opc_crypto::ConfigCapacityProfile;
use std::sync::Arc;

/// Fields are private to this module: no caller can replace the admitted ID or
/// intent, attach evidence to another value, or mutate a shared audited effect.
/// The borrowed store pins its immutable identity, profile and audit key without
/// adding a second ciphertext, reservation or storage owner.
pub(super) struct LocalIntent<'a> {
    store: &'a ConsensusConfigStore,
    request_id: ConsensusRequestId,
    intent: ConfigMutationIntent,
}

impl<'a> LocalIntent<'a> {
    pub(super) fn new(
        store: &'a ConsensusConfigStore,
        request_id: ConsensusRequestId,
        intent: ConfigMutationIntent,
    ) -> Result<Self, PersistError> {
        #[cfg(all(test, target_os = "linux"))]
        let _cost_scope = super::config_capacity_cost_observation::Scope::ingress(request_id);
        // Preserve the original input/proof/size refusals before admission or
        // deadline creation. Structural validation stays after the read barrier.
        intent.validate_capacity(
            store.inner.identity,
            store.inner.backend.audit_key(),
            store.capacity_profile(),
        )?;
        preflight_config_command_replication_budget(
            store.inner.identity,
            request_id,
            &intent,
            store.mode(),
        )
        .map_err(ForwardMutationRejection::into_persist_error)?;
        Ok(Self {
            store,
            request_id,
            intent,
        })
    }

    pub(super) fn into_local(self, budget: ForwardedBudget) -> LocalMutation<'a> {
        LocalMutation {
            origin: Some(self.store),
            request: ForwardMutationRequest {
                request_id: self.request_id,
                intent: self.intent,
                compatibility: self.store.peer_compatibility(),
                budget,
            },
        }
    }

    pub(super) fn local(&self, budget: ForwardedBudget) -> LocalMutation<'a> {
        LocalMutation {
            origin: Some(self.store),
            request: self.forward(budget),
        }
    }

    pub(super) fn forward(&self, budget: ForwardedBudget) -> ForwardMutationRequest {
        // Exactly the existing retry/forward clone. No process-local evidence
        // crosses a wire; the receiver independently authenticates and sizes it.
        ForwardMutationRequest {
            request_id: self.request_id,
            intent: self.intent.clone(),
            compatibility: self.store.peer_compatibility(),
            budget,
        }
    }
}

pub(super) struct LocalMutation<'a> {
    origin: Option<&'a ConsensusConfigStore>,
    request: ForwardMutationRequest,
}

impl LocalMutation<'_> {
    pub(super) fn received(request: ForwardMutationRequest) -> Self {
        Self {
            origin: None,
            request,
        }
    }

    pub(super) fn validate(
        self,
        store: &ConsensusConfigStore,
    ) -> Result<CheckedLocalMutation<'_>, ForwardMutationRejection> {
        #[cfg(all(test, target_os = "linux"))]
        let _cost_scope =
            super::config_capacity_cost_observation::Scope::local_apply(self.request.request_id);
        let reuse = if let Some(origin) = self.origin {
            // Store clones share this exact immutable authority. Even another
            // authority with equal-looking fields cannot consume this input.
            if !Arc::ptr_eq(&origin.inner, &store.inner) {
                return Err(ForwardMutationRejection::InvalidCommand);
            }
            origin.capacity_profile() == ConfigCapacityProfile::BoundedV1
                && match &self.request.intent {
                    ConfigMutationIntent::BoundedAppend { .. } => true,
                    ConfigMutationIntent::AuditedMutation(command) => matches!(
                        &command.effect,
                        crate::consensus::audit_mutation::AuditedConfigEffect::BoundedAppend { .. }
                    ),
                    _ => false,
                }
        } else {
            false
        };
        if !reuse {
            // Received requests and Legacy retain the original receiver checks
            // and rejection mapping before permit/read-barrier acquisition.
            self.request
                .intent
                .validate_capacity(
                    store.inner.identity,
                    store.inner.backend.audit_key(),
                    store.capacity_profile(),
                )
                .map_err(|_| ForwardMutationRejection::InvalidCommand)?;
            preflight_config_command_replication_budget(
                store.inner.identity,
                self.request.request_id,
                &self.request.intent,
                store.mode(),
            )?;
        }
        Ok(CheckedLocalMutation {
            store,
            request: self.request,
            reuse,
        })
    }
}

pub(super) struct CheckedLocalMutation<'a> {
    store: &'a ConsensusConfigStore,
    request: ForwardMutationRequest,
    reuse: bool,
}

impl CheckedLocalMutation<'_> {
    pub(super) fn finalize(
        self,
        logical_time: opc_types::Timestamp,
    ) -> Result<ConfigConsensusCommand, ForwardMutationRejection> {
        let profile = self.store.capacity_profile();
        let command = ConfigConsensusCommand {
            schema_version: config_command_revision(self.store.mode()),
            identity: self.store.inner.identity,
            request_id: self.request.request_id,
            logical_time,
            intent: self.request.intent,
        };
        // This observation spans only synchronous finalized-command admission.
        #[cfg(all(test, target_os = "linux"))]
        let cost_scope =
            super::config_capacity_cost_observation::Scope::finalized(command.request_id);
        if self.reuse {
            // The same maximum-framing probe, exact owned intent/request ID,
            // authority profile and record-proof key already succeeded. The
            // current clock does not change that probe. Keep structural scope,
            // revision, record, audit and resolution checks at their original
            // post-barrier position; never promote an earlier structural refusal.
            command
                .validate(self.store.inner.identity)
                .map_err(|_| ForwardMutationRejection::InvalidCommand)?;
            if command.schema_version > config_command_revision(profile) {
                return Err(ForwardMutationRejection::InvalidCommand);
            }
        } else {
            command
                .validate_for_profile(
                    self.store.inner.identity,
                    self.store.inner.backend.audit_key(),
                    self.store.mode(),
                )
                .map_err(|_| ForwardMutationRejection::InvalidCommand)?;
        }
        if profile != ConfigCapacityProfile::BoundedV1
            && !config_command_fits_replication_budget(&command, profile)
        {
            return Err(ForwardMutationRejection::CommandTooLarge);
        }
        #[cfg(all(test, target_os = "linux"))]
        drop(cost_scope);
        Ok(command)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "config_capacity_local_admission_tests.rs"]
mod tests;
