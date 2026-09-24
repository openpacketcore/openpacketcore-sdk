//! Closed configuration effects bound into a management operation by the SDK.

use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::preparation::{PreparationOwnership, SubmissionOwnership};
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
    /// A new final variant preserves all legacy effect bytes and indices.
    BoundedAppend {
        commit: Box<PreparedConfigCommit>,
        binding: super::capacity_record::CapacityRecordBinding,
        resolution: Option<ConfirmedCommitResolution>,
    },
}

impl AuditedConfigEffect {
    pub(super) fn minimum_command_version(&self) -> u16 {
        if matches!(self, Self::BoundedAppend { .. }) {
            8
        } else {
            5
        }
    }

    pub(super) fn verify_capacity(
        &self,
        identity: super::ConfigConsensusIdentity,
        key: &AuditKey,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<Option<super::capacity_record::RecoveredRecordCapacity>, crate::PersistError> {
        use opc_crypto::ConfigCapacityProfile;
        if !matches!(
            profile,
            ConfigCapacityProfile::Legacy | ConfigCapacityProfile::BoundedV1
        ) {
            return Err(crate::PersistError::corrupt_blob());
        }
        match self {
            Self::BoundedAppend {
                commit, binding, ..
            } => binding
                .recover(&commit.record, identity, key, profile)
                .map(Some),
            Self::Append { .. } if profile != ConfigCapacityProfile::Legacy => {
                Err(crate::PersistError::corrupt_blob())
            }
            _ => Ok(None),
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
                | Self::BoundedAppend {
                    resolution: Some(_),
                    ..
                }
        )
    }
}

// Preserve the existing serde struct name, field order and deny-unknown rule.
// Only these deterministic fields enter a command or retained log entry.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "PreparedAuditedMutation", deny_unknown_fields)]
pub(crate) struct AuditedMutationFields {
    pub(crate) handle: AuditOperationHandle,
    pub(crate) effect: AuditedConfigEffect,
}

#[derive(Clone, PartialEq)]
pub(crate) struct AuditedConfigCommand(Arc<AuditedMutationFields>);

impl std::ops::Deref for AuditedConfigCommand {
    type Target = AuditedMutationFields;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl std::ops::DerefMut for AuditedConfigCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

impl Serialize for AuditedConfigCommand {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuditedConfigCommand {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        AuditedMutationFields::deserialize(deserializer).map(|fields| Self(Arc::new(fields)))
    }
}

impl AuditedConfigCommand {
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

impl std::fmt::Debug for AuditedConfigCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditedConfigCommand(<redacted>)")
    }
}

/// One exact encrypted configuration mutation and its opaque audit handle.
///
/// Constructed only by the configuration authority. Retain this value and its
/// handle before admission; reuse them after response loss. Preparation grants
/// no authority to submit without an acknowledged intent receipt. Configuration
/// plaintext, authentication credentials and audit signing keys are not retained.
/// Clones share immutable ciphertext and preparation ownership. Generic serde
/// output belongs to the caller; it is not SDK preparation storage. Use
/// [`Self::encode`] for the bounded SDK recovery encoder. Generic decoding does
/// not grant a store reservation; use that store's reserved decode entrypoint
/// when its capacity profile requires one.
#[derive(Clone)]
pub struct PreparedAuditedMutation {
    command: AuditedConfigCommand,
    preparation: Option<Arc<PreparationOwnership>>,
}

impl PartialEq for PreparedAuditedMutation {
    fn eq(&self, other: &Self) -> bool {
        self.command == other.command
    }
}

impl Serialize for PreparedAuditedMutation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.command.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PreparedAuditedMutation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            command: AuditedConfigCommand::deserialize(deserializer)?,
            preparation: None,
        })
    }
}

impl PreparedAuditedMutation {
    pub(crate) fn new(
        handle: AuditOperationHandle,
        effect: AuditedConfigEffect,
        preparation: Option<Arc<PreparationOwnership>>,
    ) -> Self {
        Self {
            command: AuditedConfigCommand(Arc::new(AuditedMutationFields { handle, effect })),
            preparation,
        }
    }

    pub(crate) fn command(&self) -> &AuditedConfigCommand {
        &self.command
    }

    pub(crate) fn attach_preparation(&mut self, preparation: Arc<PreparationOwnership>) {
        self.preparation = Some(preparation);
    }

    pub(crate) fn begin_submission(
        &self,
        pool: &opc_crypto::ConfigPreparationPool,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<SubmissionOwnership, AuditAuthorityError> {
        if profile == opc_crypto::ConfigCapacityProfile::Legacy && self.preparation.is_none() {
            return Ok(None);
        }
        let preparation = self
            .preparation
            .as_ref()
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let needs_evidence = matches!(
            self.command.effect,
            AuditedConfigEffect::Append { .. } | AuditedConfigEffect::BoundedAppend { .. }
        );
        if profile != opc_crypto::ConfigCapacityProfile::Legacy
            && !preparation.belongs_to(pool, profile, needs_evidence)
        {
            return Err(AuditAuthorityError::InvalidInput);
        }
        preparation.try_submit().map(|guard| Some(Arc::new(guard)))
    }

    /// Exact handle whose intent must be durably admitted before submission.
    pub fn handle(&self) -> &AuditOperationHandle {
        &self.command.handle
    }

    /// Encode for protected caller recovery storage, never diagnostics.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        let _encoding = self
            .preparation
            .as_ref()
            .map(PreparationOwnership::try_encode)
            .transpose()?;
        // Count the exact JSON before reserving output. In particular, a byte
        // array's decimal expansion must not allocate first and reject later.
        let mut counter = RecoverySizeCounter(0);
        serde_json::to_writer(&mut counter, self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(counter.0)
            .map_err(|_| AuditAuthorityError::Unavailable)?;
        serde_json::to_writer(&mut encoded, self).map_err(|_| AuditAuthorityError::InvalidInput)?;
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
        self.command.verify_effect(key)
    }
}

struct RecoverySizeCounter(usize);

impl std::io::Write for RecoverySizeCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES.saturating_sub(self.0)
        {
            return Err(std::io::Error::other(
                "configuration recovery encoding exceeds capacity",
            ));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Debug for PreparedAuditedMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedAuditedMutation(<redacted>)")
    }
}
