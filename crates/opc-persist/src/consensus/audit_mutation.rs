//! Closed configuration effects bound into a management operation by the SDK.

use serde::{Deserialize, Serialize};

use super::{ConfigMutationIntent, PreparedConfigCommit};
use crate::audit_authority::ledger::{authenticate, verify};
use crate::audit_authority::{AuditAuthorityError, AuditOperationHandle};
use crate::{AuditKey, ConfirmedCommitResolution};

const MUTATION_DOMAIN: &[u8] = b"openpacketcore/management-audit/config-mutation/v1\0";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum AuditedConfigEffect {
    Append {
        commit: Box<PreparedConfigCommit>,
        resolution: Option<ConfirmedCommitResolution>,
    },
    Confirm {
        tx_id: opc_types::TxId,
    },
    RollbackPoint {
        tx_id: opc_types::TxId,
        label: Option<super::types::ValidatedRollbackLabel>,
    },
}

impl AuditedConfigEffect {
    pub(crate) fn intent(&self) -> ConfigMutationIntent {
        match self {
            Self::Append {
                commit,
                resolution: Some(resolution),
            } => ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: commit.clone(),
                resolution: *resolution,
            },
            Self::Append {
                commit,
                resolution: None,
            } => ConfigMutationIntent::AppendCommit(commit.clone()),
            Self::Confirm { tx_id } => ConfigMutationIntent::MarkConfirmed { tx_id: *tx_id },
            Self::RollbackPoint { tx_id, label } => ConfigMutationIntent::CreateRollbackPoint {
                tx_id: *tx_id,
                label: label.clone(),
            },
        }
    }

    pub(crate) fn digest(&self, key: &AuditKey) -> Result<[u8; 32], AuditAuthorityError> {
        authenticate(key, MUTATION_DOMAIN, self)
    }

    pub(crate) fn verify(
        &self,
        key: &AuditKey,
        expected: &[u8; 32],
    ) -> Result<(), AuditAuthorityError> {
        verify(key, MUTATION_DOMAIN, self, expected)
    }

    pub(crate) fn updates_existing_records(&self) -> bool {
        matches!(
            self,
            Self::Confirm { .. }
                | Self::RollbackPoint { .. }
                | Self::Append {
                    resolution: Some(_),
                    ..
                }
        )
    }
}

/// One exact encrypted configuration mutation and its opaque audit handle.
///
/// Constructed only by the configuration authority. Retain this value and its
/// handle before admission; reuse them after response loss. Preparation grants
/// no authority to submit without an acknowledged intent receipt. Configuration
/// plaintext, authentication credentials and audit signing keys are not retained.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAuditedMutation {
    pub(crate) handle: AuditOperationHandle,
    pub(crate) effect: AuditedConfigEffect,
}

impl PreparedAuditedMutation {
    /// Exact handle whose intent must be durably admitted before submission.
    pub fn handle(&self) -> &AuditOperationHandle {
        &self.handle
    }

    /// Encode for protected caller recovery storage, never diagnostics.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        let encoded = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if encoded.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(encoded)
    }

    /// Decode bounded, untrusted recovery data. Submission authenticates every field.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)
    }

    pub(crate) fn verify_effect(&self, key: &AuditKey) -> Result<(), AuditAuthorityError> {
        self.effect.verify(
            key,
            &self
                .handle
                .body
                .mutation
                .ok_or(AuditAuthorityError::BindingMismatch)?,
        )
    }
}

impl std::fmt::Debug for PreparedAuditedMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedAuditedMutation(<redacted>)")
    }
}
