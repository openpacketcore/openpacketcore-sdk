//! Closed configuration effects bound into a management operation by the SDK.

use serde::{Deserialize, Serialize};

use super::{ConfigMutationIntent, PreparedConfigCommit};
use crate::audit_authority::{AuditAuthorityError, AuditOperationHandle};
use crate::{AuditKey, ConfirmedCommitResolution};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

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
    /// Reserved index 3; the legacy recovery decoder cannot admit it.
    #[allow(dead_code)] // No public preparation path selects the bounded profile yet.
    #[serde(skip_deserializing)]
    BoundedAppend {
        #[serde(serialize_with = "super::types::record_encoding::serialize_commit")]
        commit: Box<PreparedConfigCommit>,
        binding: super::capacity_record::CapacityRecordBinding,
        resolution: Option<ConfirmedCommitResolution>,
    },
}

impl AuditedConfigEffect {
    pub(super) const fn minimum_command_version(&self) -> u16 {
        if matches!(self, Self::BoundedAppend { .. }) {
            8
        } else {
            5
        }
    }

    pub(crate) fn intent(&self) -> ConfigMutationIntent {
        match self {
            Self::BoundedAppend {
                commit,
                binding,
                resolution,
            } => ConfigMutationIntent::BoundedAppend {
                commit: commit.clone(),
                binding: *binding,
                resolution: *resolution,
            },
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
        Ok(effect_authenticator(self, key)?
            .finalize()
            .into_bytes()
            .into())
    }

    pub(crate) fn verify(
        &self,
        key: &AuditKey,
        expected: &[u8; 32],
    ) -> Result<(), AuditAuthorityError> {
        effect_authenticator(self, key)?
            .verify_slice(expected)
            .map_err(|_| AuditAuthorityError::BindingMismatch)
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
                | Self::BoundedAppend {
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
        if !matches!(self.effect, AuditedConfigEffect::BoundedAppend { .. }) {
            let encoded =
                serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
            if encoded.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
                return Err(AuditAuthorityError::InvalidInput);
            }
            return Ok(encoded);
        }
        let mut count =
            super::encoding::ByteCount::new(super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES);
        super::encoding::to_writer(&mut count, self)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(count.bytes)
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        super::encoding::to_writer(&mut encoded, self)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
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

// Preserve the original domain, big-endian JSON length, bytes and inclusive
// 16 MiB ceiling, without retaining the complete expanded ciphertext array.
fn effect_authenticator(
    effect: &AuditedConfigEffect,
    key: &AuditKey,
) -> Result<Hmac<Sha256>, AuditAuthorityError> {
    let mut count =
        super::encoding::ByteCount::new(crate::audit_authority::ledger::MAX_STATE_BYTES);
    super::encoding::to_writer(&mut count, effect)
        .map_err(|_| AuditAuthorityError::InvalidInput)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| AuditAuthorityError::KeyUnavailable)?;
    mac.update(MUTATION_DOMAIN);
    mac.update(&(count.bytes as u64).to_be_bytes());
    super::encoding::digest_json(&mut mac, effect)
        .map_err(|_| AuditAuthorityError::InvalidInput)?;
    Ok(mac)
}

impl std::fmt::Debug for PreparedAuditedMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedAuditedMutation(<redacted>)")
    }
}
