//! Closed configuration effects bound into a management operation by the SDK.

use std::sync::Arc;

#[path = "audit_copy.rs"]
mod target_copy;
use target_copy::TargetCopyBindingV1;

#[path = "joint_target_payload.rs"]
pub(super) mod joint_running;

#[path = "target_recovery.rs"]
mod target_recovery;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::preparation::{PreparationOwnership, SubmissionOwnership};
#[cfg(test)]
use super::ConfigMutationIntent;
use super::PreparedConfigCommit;
use crate::audit_authority::ledger::{authenticate, verify};
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

    #[cfg(test)]
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
        #[cfg(all(test, target_os = "linux"))]
        let _effect_scope =
            super::store::config_capacity_cost_observation::EffectScope::enter(&self.handle);
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

// Preserve the audit authority's exact domain, big-endian length and canonical
// JSON transcript without retaining a second expanded JSON buffer beside a
// prepared value. The input is a closed immutable effect, not a caller-supplied
// serializer. All legacy effects keep their original MACs and 16MiB ceiling.
fn effect_authenticator(
    effect: &AuditedConfigEffect,
    key: &AuditKey,
) -> Result<Hmac<Sha256>, AuditAuthorityError> {
    let mut length = EffectSizeCounter::default();
    super::config_capacity_json::to_writer(&mut length, effect)
        .map_err(|_| AuditAuthorityError::InvalidInput)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| AuditAuthorityError::KeyUnavailable)?;
    mac.update(MUTATION_DOMAIN);
    mac.update(&(length.bytes as u64).to_be_bytes());
    let mut writer = EffectMacWriter {
        mac,
        remaining: length.bytes,
        chunk: [0; 8192],
        used: 0,
        #[cfg(all(test, target_os = "linux"))]
        writes: 0,
    };
    super::config_capacity_json::to_writer(&mut writer, effect)
        .map_err(|_| AuditAuthorityError::InvalidInput)?;
    if writer.remaining != 0 {
        return Err(AuditAuthorityError::InvalidInput);
    }
    std::io::Write::flush(&mut writer).map_err(|_| AuditAuthorityError::InvalidInput)?;
    #[cfg(all(test, target_os = "linux"))]
    super::store::config_capacity_cost_observation::effect_serialized(
        length.bytes,
        length.writes,
        writer.writes,
    );
    Ok(writer.mac)
}

#[derive(Default)]
struct EffectSizeCounter {
    bytes: usize,
    #[cfg(all(test, target_os = "linux"))]
    writes: usize,
}

impl std::io::Write for EffectSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(all(test, target_os = "linux"))]
        {
            self.writes += 1;
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|length| *length <= crate::audit_authority::ledger::MAX_STATE_BYTES)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct EffectMacWriter {
    mac: Hmac<Sha256>,
    remaining: usize,
    chunk: [u8; 8192],
    used: usize,
    #[cfg(all(test, target_os = "linux"))]
    writes: usize,
}

impl std::io::Write for EffectMacWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(all(test, target_os = "linux"))]
        {
            self.writes += 1;
        }
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let mut pending = bytes;
        while !pending.is_empty() {
            let count = pending.len().min(self.chunk.len() - self.used);
            self.chunk[self.used..self.used + count].copy_from_slice(&pending[..count]);
            self.used += count;
            pending = &pending[count..];
            if self.used == self.chunk.len() {
                self.flush()?;
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.mac.update(&self.chunk[..self.used]);
        self.used = 0;
        Ok(())
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

// Admission and application use distinct, append-only phase tags inside the
// allocated target-command family. The signed effect itself is unchanged.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetAuditCommandV1 {
    Admit(TargetMutationCommand),
    Apply(TargetMutationCommand),
    EmptyCommit(Box<crate::audit_authority::PreparedNetconfEmptyCommit>),
    // Append-only phase 3 of the unreleased target format; old phase bytes stay fixed.
    RetireCleanup(TargetMutationCommand),
}

impl TargetAuditCommandV1 {
    pub(super) fn minimum_command_version(&self) -> u16 {
        match self {
            Self::Admit(prepared) | Self::Apply(prepared) | Self::RetireCleanup(prepared)
                if prepared.bounded_running().is_some() =>
            {
                10
            }
            _ => 9,
        }
    }

    pub(super) fn bounded_running(&self) -> Option<&joint_running::BoundedRunningPayload> {
        match self {
            Self::Admit(prepared) | Self::Apply(prepared) if prepared.effect.action.0 == 16 => {
                prepared.bounded_running()
            }
            _ => None,
        }
    }

    pub(crate) fn handle(&self) -> &AuditOperationHandle {
        match self {
            Self::Admit(prepared) | Self::Apply(prepared) | Self::RetireCleanup(prepared) => {
                prepared.handle()
            }
            Self::EmptyCommit(prepared) => prepared.handle(),
        }
    }

    // Used both by the committing producer and by post-submit lookup. A general
    // handle lookup cannot substitute for the retained command description.
    pub(crate) fn lookup_receipt(
        &self,
        ledger: &crate::audit_authority::ledger::LedgerState,
        key: &AuditKey,
        caller: crate::audit_authority::AuditCaller,
    ) -> Result<Option<crate::audit_authority::AuditOperationReceipt>, AuditAuthorityError> {
        match self {
            Self::Admit(prepared) | Self::Apply(prepared) | Self::RetireCleanup(prepared) => {
                prepared.verify_retained(key, ledger.identity, caller)?;
                let receipt = ledger.lookup(key, prepared.handle(), caller)?;
                if receipt.is_some()
                    && ledger
                        .recover_target(key, prepared.handle(), caller)?
                        .command()
                        != prepared
                {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                Ok(receipt)
            }
            Self::EmptyCommit(prepared) => ledger.lookup_empty_commit(key, prepared, caller),
        }
    }

    pub(crate) fn read_back_receipt(
        &self,
        proof: &crate::audit_authority::receipt::AuthenticatedAuditReceipt,
        key: &AuditKey,
        identity: crate::ConfigConsensusIdentity,
        caller: crate::audit_authority::AuditCaller,
    ) -> Result<crate::audit_authority::AuditOperationReceipt, AuditAuthorityError> {
        match self {
            Self::EmptyCommit(prepared) => {
                proof.read_back_empty_commit(key, identity, prepared, caller)
            }
            Self::Admit(prepared) | Self::Apply(prepared) | Self::RetireCleanup(prepared) => {
                let receipt = proof.read_back(key, identity, prepared.handle(), caller)?;
                if let crate::audit_authority::AuditOperationState::TargetV1(result) =
                    receipt.state()
                {
                    prepared.validate_result(result)?;
                }
                Ok(receipt)
            }
        }
    }
}

const TARGET_MUTATION_DOMAIN: &[u8] = b"openpacketcore/management-audit/netconf-target/v1\0";

// Fixed RFC 019 action codes. They are numbers in both JSON and postcard; this
// type cannot decode an unallocated tag, and adding a Rust variant cannot
// renumber an existing action.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub(crate) struct TargetActionV1(u8);

impl TryFrom<u8> for TargetActionV1 {
    type Error = AuditAuthorityError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 16 {
            Ok(Self(value))
        } else {
            Err(AuditAuthorityError::InvalidInput)
        }
    }
}

impl From<TargetActionV1> for u8 {
    fn from(value: TargetActionV1) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TargetExpectationV1 {
    Running {
        version: u64,
    },
    Candidate {
        generation: crate::audit_authority::CandidateGeneration,
    },
    Startup {
        revision: crate::audit_authority::StartupRevision,
    },
    Lifecycle {
        state_digest: [u8; 32],
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TargetSourceV1 {
    Running {
        version: u64,
        schema: opc_types::SchemaDigest,
        ciphertext_digest: [u8; 32],
    },
    Candidate {
        generation: crate::audit_authority::CandidateGeneration,
        schema: opc_types::SchemaDigest,
        ciphertext_digest: [u8; 32],
    },
    Startup {
        revision: crate::audit_authority::StartupRevision,
        schema: opc_types::SchemaDigest,
        ciphertext_digest: [u8; 32],
    },
    CandidateFallback {
        generation: crate::audit_authority::CandidateGeneration,
        running_version: u64,
        schema: opc_types::SchemaDigest,
        ciphertext_digest: [u8; 32],
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetLockExpectationV1 {
    // Fixed running/candidate/startup slots: 0/1/2. None means the exact
    // observed unowned incarnation, never permission to ignore a current lock.
    pub(crate) datastore: u8,
    pub(crate) incarnation: u64,
    pub(crate) session: Option<[u8; 16]>,
    // Authenticated requesting session is separate from the observed lock owner.
    pub(crate) requester: [u8; 16],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetEncryptedBlobV1 {
    pub(crate) schema: opc_types::SchemaDigest,
    pub(crate) plaintext_digest: [u8; 32],
    pub(crate) encrypted_blob: Vec<u8>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TargetPayloadV1 {
    Target(TargetEncryptedBlobV1),
    Running {
        #[serde(deserialize_with = "target_commit_input::deserialize")]
        commit: Box<PreparedConfigCommit>,
        confirmation_ownership: Option<TargetEncryptedBlobV1>,
    },
    ProviderCopy {
        #[serde(deserialize_with = "target_commit_input::deserialize")]
        commit: Box<PreparedConfigCommit>,
        confirmation_ownership: Option<TargetEncryptedBlobV1>,
        binding: TargetCopyBindingV1,
    },
    // Proposed joint payload tag 3. Old target9 decoders reject this tag before
    // reading its contents. Only the distinct strict joint input admits it.
    #[serde(skip_deserializing)]
    BoundedRunning(joint_running::BoundedRunningPayload),
}

impl TargetPayloadV1 {
    pub(super) fn ordinary_running(&self) -> Option<&PreparedConfigCommit> {
        match self {
            Self::Running {
                commit,
                confirmation_ownership: None,
            } => Some(commit),
            Self::BoundedRunning(payload) => Some(payload.commit()),
            _ => None,
        }
    }

    pub(super) fn from_prepared_running(
        prepared: super::capacity_record::PreparedCapacityCommit,
    ) -> Result<(Self, Option<Arc<PreparationOwnership>>), AuditAuthorityError> {
        if prepared.resolution.is_some() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if prepared.binding.is_some() {
            joint_running::BoundedRunningPayload::from_prepared(prepared)
                .map(|(payload, owner)| (Self::BoundedRunning(payload), Some(owner)))
        } else {
            // Legacy profiles do not require a capacity reservation. Their
            // deterministic payload fields and bytes remain exactly unchanged.
            let ownership = prepared
                .reservation
                .map(|reservation| PreparationOwnership::new(reservation, prepared.evidence));
            Ok((
                Self::Running {
                    commit: Box::new(prepared.commit),
                    confirmation_ownership: None,
                },
                ownership,
            ))
        }
    }

    pub(crate) fn running(
        &self,
    ) -> Option<(&PreparedConfigCommit, Option<&TargetEncryptedBlobV1>)> {
        match self {
            Self::Running {
                commit,
                confirmation_ownership,
            }
            | Self::ProviderCopy {
                commit,
                confirmation_ownership,
                ..
            } => Some((commit, confirmation_ownership.as_ref())),
            Self::Target(_) | Self::BoundedRunning(_) => None,
        }
    }

    pub(crate) fn matches_source_digest(&self, digest: &[u8]) -> bool {
        match self {
            Self::Running { commit, .. } => commit.record.plaintext_digest == digest,
            Self::ProviderCopy { binding, .. } => binding.matches_source_digest(digest),
            Self::Target(_) | Self::BoundedRunning(_) => false,
        }
    }
}

impl TargetEffectV1 {
    pub(crate) async fn bind_provider_copy(
        &mut self,
        provider: &dyn opc_key::KeyProvider,
        source: &TargetEncryptedBlobV1,
    ) -> Result<(), AuditAuthorityError> {
        if !matches!(self.action.0, 6 | 9 | 11 | 12 | 14 | 15) {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let Some(TargetPayloadV1::Running { commit, .. }) = &self.encrypted_payload else {
            return Err(AuditAuthorityError::BindingMismatch);
        };
        let binding = TargetCopyBindingV1::prepare(provider, source, commit).await?;
        binding.validate(self.source.as_ref(), commit)?;
        let Some(TargetPayloadV1::Running {
            commit,
            confirmation_ownership,
        }) = self.encrypted_payload.take()
        else {
            return Err(AuditAuthorityError::BindingMismatch);
        };
        self.encrypted_payload = Some(TargetPayloadV1::ProviderCopy {
            commit,
            confirmation_ownership,
            binding,
        });
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TargetResolutionV1 {
    Activate {
        #[serde(
            deserialize_with = "crate::audit_authority::continuity::checkpoint::deserialize_target_checkpoint"
        )]
        checkpoint: crate::audit_authority::continuity::AuditCheckpoint,
    },
    BeginDevice {
        previous: Option<[u8; 16]>,
    },
    AcquireLock {
        session: [u8; 16],
    },
    ReleaseLock {
        session: [u8; 16],
    },
    InstallPending {
        pending: crate::audit_authority::NetconfPendingConfirmation,
        rollback_parent: opc_types::TxId,
        rollback_version: u64,
        original_deadline: i64,
        owner_session: [u8; 16],
        persistent: bool,
    },
    ResolvePending {
        pending: crate::audit_authority::NetconfPendingConfirmation,
        original_deadline: i64,
    },
    EndSession {
        session: [u8; 16],
    },
    RebootRecovery {
        previous_device: [u8; 16],
        pending: Option<crate::audit_authority::NetconfPendingConfirmation>,
        original_deadline: Option<i64>,
    },
}

/// This order is RFC 019's closed pre-effect binding. It never asserts that an
/// effect happened. Only the authenticated applied receipt can do that.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetEffectV1 {
    pub(crate) format: u16,
    #[serde(with = "crate::audit_authority::target_identity")]
    pub(crate) authority: crate::ConfigConsensusIdentity,
    pub(crate) profile_incarnation: [u8; 16],
    pub(crate) device_incarnation: [u8; 16],
    #[serde(with = "crate::audit_authority::target_caller")]
    pub(crate) caller: crate::audit_authority::AuditCaller,
    pub(crate) request: crate::audit_authority::AuditToken,
    pub(crate) action: TargetActionV1,
    pub(crate) destination: TargetExpectationV1,
    pub(crate) source: Option<TargetSourceV1>,
    pub(crate) lock: Option<TargetLockExpectationV1>,
    pub(crate) expires_at: i64,
    pub(crate) encrypted_payload: Option<TargetPayloadV1>,
    pub(crate) resolution: Option<TargetResolutionV1>,
}

impl TargetEffectV1 {
    fn validate(&self, handle: &AuditOperationHandle) -> Result<(), AuditAuthorityError> {
        self.validate_for_capacity(handle, opc_crypto::ConfigCapacityProfile::Legacy)
    }

    fn validate_for_capacity(
        &self,
        handle: &AuditOperationHandle,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<(), AuditAuthorityError> {
        let bounded = matches!(
            self.encrypted_payload,
            Some(TargetPayloadV1::BoundedRunning(_))
        );
        match profile {
            opc_crypto::ConfigCapacityProfile::Legacy if !bounded => {}
            opc_crypto::ConfigCapacityProfile::BoundedV1 if bounded && self.action.0 == 16 => {}
            _ => return Err(AuditAuthorityError::BindingMismatch),
        }
        use crate::{
            ManagementAuditOutcomeCode as Outcome, ManagementAuditTransportCode as Transport,
        };
        let bad = AuditAuthorityError::BindingMismatch;
        if self.format != 1
            || self.authority != handle.body.identity
            || self.profile_incarnation == [0; 16]
            || self.device_incarnation == [0; 16]
            || self.caller != handle.body.binding.caller
            || self.caller != handle.body.event.caller
            || self.request != handle.body.binding.request
            || self.request != handle.body.event.request
            || self.expires_at != handle.body.expires_at
            || handle.body.mutation.is_none()
            || handle.body.event.outcome != Outcome::Intent
            || !matches!(
                handle.body.event.transport,
                Transport::NetconfSsh | Transport::NetconfTls | Transport::Internal
            )
            || (handle.body.event.transport == Transport::Internal
                && !matches!(self.action.0, 0 | 1 | 11 | 12 | 13 | 14))
        {
            return Err(bad);
        }
        let running = |version: u64| version <= i64::MAX as u64;
        match self.destination {
            TargetExpectationV1::Running { version } if running(version) => {}
            TargetExpectationV1::Candidate { generation }
                if generation.authority() == self.authority && generation.get() < u64::MAX => {}
            TargetExpectationV1::Startup { revision }
                if revision.authority() == self.authority && revision.get() < u64::MAX => {}
            TargetExpectationV1::Lifecycle { state_digest } if state_digest != [0; 32] => {}
            _ => return Err(bad),
        }
        if let Some(source) = &self.source {
            let (scope_ok, digest) = match source {
                TargetSourceV1::Running {
                    version,
                    ciphertext_digest,
                    ..
                } => (running(*version) && *version > 0, ciphertext_digest),
                TargetSourceV1::Candidate {
                    generation,
                    ciphertext_digest,
                    ..
                } => (
                    generation.authority() == self.authority && generation.get() > 0,
                    ciphertext_digest,
                ),
                TargetSourceV1::Startup {
                    revision,
                    ciphertext_digest,
                    ..
                } => (
                    revision.authority() == self.authority && revision.get() > 0,
                    ciphertext_digest,
                ),
                TargetSourceV1::CandidateFallback {
                    generation,
                    running_version,
                    ciphertext_digest,
                    ..
                } => (
                    generation.authority() == self.authority
                        && running(*running_version)
                        && *running_version > 0,
                    ciphertext_digest,
                ),
            };
            if !scope_ok || *digest == [0; 32] {
                return Err(bad);
            }
        }
        if self.lock.as_ref().is_some_and(|lock| {
            lock.datastore > 2
                || lock.requester == [0; 16]
                || lock.session == Some([0; 16])
                || (lock.session.is_some() && lock.incarnation == 0)
        }) {
            return Err(bad);
        }
        if let Some(payload) = &self.encrypted_payload {
            match payload {
                TargetPayloadV1::Target(blob) => blob.validate()?,
                TargetPayloadV1::BoundedRunning(payload) => payload.validate()?,
                TargetPayloadV1::Running {
                    commit,
                    confirmation_ownership,
                }
                | TargetPayloadV1::ProviderCopy {
                    commit,
                    confirmation_ownership,
                    ..
                } => {
                    if let TargetPayloadV1::ProviderCopy { binding, .. } = payload {
                        binding.validate(self.source.as_ref(), commit)?;
                    }
                    commit
                        .validate()
                        .map_err(|_| AuditAuthorityError::InvalidInput)?;
                    if let Some(blob) = confirmation_ownership {
                        blob.validate()?;
                    }
                }
            }
        }
        // These are structural requirements only. Current authoritative versions,
        // ownership, locks, source content and deadlines are rechecked by apply.
        let candidate = matches!(self.destination, TargetExpectationV1::Candidate { .. });
        let startup = matches!(self.destination, TargetExpectationV1::Startup { .. });
        let running = matches!(self.destination, TargetExpectationV1::Running { .. });
        let lifecycle = matches!(self.destination, TargetExpectationV1::Lifecycle { .. });
        let target_payload = matches!(self.encrypted_payload, Some(TargetPayloadV1::Target(_)));
        let running_payload = matches!(
            self.encrypted_payload,
            Some(TargetPayloadV1::Running { .. } | TargetPayloadV1::ProviderCopy { .. })
        );
        let no_payload = self.encrypted_payload.is_none();
        let no_resolution = self.resolution.is_none();
        let resolving = matches!(
            self.resolution,
            Some(TargetResolutionV1::ResolvePending { .. })
        );
        let valid_action = match self.action.0 {
            0 => {
                lifecycle
                    && no_payload
                    && matches!(self.resolution, Some(TargetResolutionV1::Activate { .. }))
            }
            1 => {
                lifecycle
                    && no_payload
                    && matches!(
                        self.resolution,
                        Some(TargetResolutionV1::BeginDevice { .. })
                    )
            }
            2 => {
                lifecycle
                    && no_payload
                    && self.lock.is_some()
                    && matches!(
                        self.resolution,
                        Some(TargetResolutionV1::AcquireLock { .. })
                    )
            }
            3 => {
                lifecycle
                    && no_payload
                    && self.lock.is_some()
                    && matches!(
                        self.resolution,
                        Some(TargetResolutionV1::ReleaseLock { .. })
                    )
            }
            4 => candidate && target_payload && no_resolution,
            5 => candidate && no_payload && no_resolution && self.source.is_none(),
            6 => {
                running
                    && running_payload
                    && matches!(self.source, Some(TargetSourceV1::Candidate { .. }))
                    && (no_resolution || resolving)
            }
            7 => startup && target_payload && no_resolution,
            8 => startup && no_payload && no_resolution && self.source.is_none(),
            9 => {
                running
                    && running_payload
                    && matches!(self.source, Some(TargetSourceV1::Candidate { .. }))
                    && matches!(
                        self.resolution,
                        Some(TargetResolutionV1::InstallPending { .. })
                    )
            }
            10 => lifecycle && no_payload && resolving,
            11 | 12 => running && running_payload && resolving,
            13 => {
                lifecycle
                    && no_payload
                    && matches!(self.resolution, Some(TargetResolutionV1::EndSession { .. }))
            }
            14 => {
                matches!(
                    self.resolution,
                    Some(TargetResolutionV1::RebootRecovery { .. })
                ) && ((running && running_payload) || (lifecycle && no_payload))
            }
            15 => running && running_payload && self.source.is_some() && no_resolution,
            16 => {
                no_resolution
                    && self.lock.as_ref().is_some_and(|lock| lock.datastore == 0)
                    && matches!((&self.destination, &self.source,
                        self.encrypted_payload.as_ref().and_then(TargetPayloadV1::ordinary_running)),
                    (TargetExpectationV1::Running { version }, source, Some(commit))
                    if *version == handle.body.binding.base_version
                        && version.checked_add(1) == Some(commit.record.version.get())
                        && commit.record.confirmed_deadline.is_none()
                        && match source {
                            None => *version == 0 && commit.record.parent_tx_id.is_none(),
                            Some(TargetSourceV1::Running { version: source_version, .. }) =>
                                *version > 0 && source_version == version && commit.record.parent_tx_id.is_some(),
                            _ => false,
                        })
                    && matches!(
                        handle.body.event.operation,
                        crate::ManagementAuditOperationCode::Create
                            | crate::ManagementAuditOperationCode::Update
                            | crate::ManagementAuditOperationCode::Replace
                            | crate::ManagementAuditOperationCode::Delete
                    )
            }
            _ => false,
        };
        if !valid_action {
            return Err(bad);
        }
        Ok(())
    }
}

impl TargetEffectV1 {
    pub(crate) fn encryption_store_kind(
        &self,
        schema: opc_types::SchemaDigest,
        target: u8,
    ) -> Result<String, AuditAuthorityError> {
        use sha2::{Digest, Sha256};
        let name = match target {
            0 => "candidate",
            1 => "startup",
            2 => "confirmation",
            _ => return Err(AuditAuthorityError::InvalidInput),
        };
        let binding = serde_json::to_vec(&(
            self.format,
            self.authority,
            self.profile_incarnation,
            self.device_incarnation,
            self.caller,
            self.request,
            self.action,
            &self.destination,
            &self.source,
            &self.lock,
            self.expires_at,
            &self.resolution,
            schema,
            target,
        ))
        .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/config-netconf/target-aad/v1\0");
        digest.update(binding);
        use std::fmt::Write;
        let mut store_kind = format!("netconf-{name}-v1-");
        for byte in digest.finalize() {
            write!(&mut store_kind, "{byte:02x}").map_err(|_| AuditAuthorityError::InvalidInput)?;
        }
        Ok(store_kind)
    }
}

impl TargetEncryptedBlobV1 {
    pub(crate) fn validate(&self) -> Result<(), AuditAuthorityError> {
        if self.encrypted_blob.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&self.encrypted_blob)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        if envelope.nonce.len() != envelope.algorithm.nonce_len()
            || envelope.ciphertext_and_tag.len() < opc_key::AEAD_TAG_LEN
        {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let (aad, key_id) = opc_key::decode_bound_aad(envelope.aad)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let opc_key::EnvelopeMetadata::Config(metadata) = aad.metadata() else {
            return Err(AuditAuthorityError::BindingMismatch);
        };
        if key_id != envelope.key_id || metadata.schema_digest() != &self.schema {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }
}

// Preserve target9 serde name, field order, and strict handle decoding. These
// fields, including any capacity proof, contain no process-local slot owner.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "PreparedTargetMutation", deny_unknown_fields)]
pub(crate) struct TargetMutationFields {
    #[serde(deserialize_with = "crate::audit_authority::ledger::deserialize_target_handle")]
    pub(crate) handle: AuditOperationHandle,
    pub(crate) effect: TargetEffectV1,
}

#[derive(Clone, PartialEq)]
pub(crate) struct TargetMutationCommand(Arc<TargetMutationFields>);

impl std::ops::Deref for TargetMutationCommand {
    type Target = TargetMutationFields;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl std::ops::DerefMut for TargetMutationCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

impl Serialize for TargetMutationCommand {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TargetMutationCommand {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        TargetMutationFields::deserialize(deserializer).map(|fields| Self(Arc::new(fields)))
    }
}

impl std::fmt::Debug for TargetMutationCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TargetMutationCommand(<redacted>)")
    }
}

impl TargetMutationCommand {
    pub(in crate::consensus) fn verify_for_mode(
        &self,
        key: &AuditKey,
        identity: super::ConfigConsensusIdentity,
        caller: crate::audit_authority::AuditCaller,
        mode: super::RetainedConfigMode,
    ) -> Result<(), AuditAuthorityError> {
        self.handle.verify(key, identity, caller)?;
        if mode == super::RetainedConfigMode::NetconfRunningV1 {
            if !joint_running::allows_native(self) {
                return Err(AuditAuthorityError::BindingMismatch);
            }
            self.verify_retained(key, identity, caller)
        } else {
            self.verify_effect(key)
        }
    }

    pub(crate) fn handle(&self) -> &AuditOperationHandle {
        &self.handle
    }

    // Generic legacy encoding retains its target9 representation and fence.
    // Retained commands use the separate authenticated, bounded internal codec.
    pub(crate) fn encode_legacy(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        self.effect.validate(&self.handle)?;
        let bytes = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(bytes)
    }
    pub(super) fn bounded_running(&self) -> Option<&joint_running::BoundedRunningPayload> {
        match &self.effect.encrypted_payload {
            Some(TargetPayloadV1::BoundedRunning(payload)) => Some(payload),
            _ => None,
        }
    }

    pub(super) fn verify_bounded_running(
        &self,
        key: &AuditKey,
        identity: super::ConfigConsensusIdentity,
        caller: crate::audit_authority::AuditCaller,
    ) -> Result<super::capacity_record::RecoveredRecordCapacity, AuditAuthorityError> {
        self.effect
            .validate_for_capacity(&self.handle, opc_crypto::ConfigCapacityProfile::BoundedV1)?;
        self.handle.verify(key, identity, caller)?;
        verify(
            key,
            TARGET_MUTATION_DOMAIN,
            &self.effect,
            &self
                .handle
                .body
                .mutation
                .ok_or(AuditAuthorityError::BindingMismatch)?,
        )?;
        let payload = self
            .bounded_running()
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        payload
            .binding()
            .recover(
                &payload.commit().record,
                identity,
                key,
                opc_crypto::ConfigCapacityProfile::BoundedV1,
            )
            .map_err(|_| AuditAuthorityError::BindingMismatch)
    }

    pub(crate) fn validate_result(
        &self,
        result: crate::audit_authority::NetconfTargetResult,
    ) -> Result<(), AuditAuthorityError> {
        use crate::audit_authority::NetconfAppliedOutcome as Outcome;
        let bad = AuditAuthorityError::BindingMismatch;
        result.validate_for(&self.handle)?;
        if result.profile_incarnation() != self.effect.profile_incarnation {
            return Err(bad);
        }
        let matches = match (u8::from(self.effect.action), result.outcome()) {
            (0 | 1, Outcome::Lifecycle { incarnation }) => {
                incarnation.value == self.effect.device_incarnation
            }
            (2 | 3, Outcome::Lifecycle { incarnation }) => {
                incarnation.value == self.handle.body.nonce
            }
            (4 | 5, Outcome::Candidate { generation }) => {
                matches!(self.effect.destination, TargetExpectationV1::Candidate { generation: expected }
                    if expected.checked_next()? == generation)
            }
            (7 | 8, Outcome::Startup { revision }) => {
                matches!(self.effect.destination, TargetExpectationV1::Startup { revision: expected }
                    if expected.checked_next()? == revision)
            }
            (
                6,
                Outcome::Promoted {
                    running_version,
                    retired_generation,
                },
            ) => {
                matches!((&self.effect.source, self.effect.encrypted_payload.as_ref().and_then(TargetPayloadV1::running), &self.effect.destination),
                    (Some(TargetSourceV1::Candidate { generation, .. }),
                     Some((commit, None)),
                     TargetExpectationV1::Running { version })
                    if generation.checked_next()? == retired_generation
                        && *version == self.handle.body.binding.base_version
                        && version.checked_add(1) == Some(running_version)
                        && commit.record.version.get() == running_version
                        && commit.record.confirmed_deadline.is_none()
                        && matches!(self.effect.resolution, None | Some(TargetResolutionV1::ResolvePending { .. })))
            }
            (15, Outcome::CopiedRunning { running_version }) => {
                matches!((self.effect.encrypted_payload.as_ref().and_then(TargetPayloadV1::running), &self.effect.destination),
                    (Some((commit, None)),
                     TargetExpectationV1::Running { version })
                    if *version == self.handle.body.binding.base_version
                        && version.checked_add(1) == Some(running_version)
                        && commit.record.version.get() == running_version
                        && commit.record.confirmed_deadline.is_none()
                        && self.effect.resolution.is_none())
            }
            (
                16,
                Outcome::RunningReplaced {
                    tx_id,
                    running_version,
                    plaintext_digest,
                },
            ) => {
                matches!((self.effect.encrypted_payload.as_ref().and_then(TargetPayloadV1::ordinary_running), &self.effect.destination),
                    (Some(commit), TargetExpectationV1::Running { version })
                    if *version == self.handle.body.binding.base_version
                        && version.checked_add(1) == Some(running_version)
                        && commit.record.tx_id == tx_id
                        && commit.record.version.get() == running_version
                        && commit.record.plaintext_digest.as_slice() == plaintext_digest.as_slice()
                        && commit.record.confirmed_deadline.is_none()
                        && self.effect.resolution.is_none())
            }
            (
                9,
                Outcome::Tentative {
                    running_version,
                    retired_generation,
                    pending,
                },
            ) => {
                matches!((&self.effect.source, self.effect.encrypted_payload.as_ref().and_then(TargetPayloadV1::running), &self.effect.destination, &self.effect.resolution),
                    (Some(TargetSourceV1::Candidate { generation, .. }),
                     Some((commit, Some(_))),
                     TargetExpectationV1::Running { version },
                     Some(TargetResolutionV1::InstallPending { pending: token, rollback_parent, rollback_version, original_deadline, .. }))
                    if generation.checked_next()? == retired_generation && *token == pending
                        && *version == self.handle.body.binding.base_version
                        && version.checked_add(1) == Some(running_version)
                        && commit.record.version.get() == running_version
                        && *rollback_version == *version && commit.record.parent_tx_id == Some(*rollback_parent)
                        && commit.record.confirmed_deadline.is_some_and(|d| d.as_offset_datetime().unix_timestamp() == *original_deadline))
            }
            (10, Outcome::Confirmed { pending }) => {
                matches!(self.effect.resolution, Some(TargetResolutionV1::ResolvePending { pending: token, .. }) if token == pending)
            }
            (
                11 | 12 | 14,
                Outcome::RolledBack {
                    running_version,
                    pending,
                },
            ) => {
                let token_matches = match self.effect.resolution {
                    Some(TargetResolutionV1::ResolvePending { pending: token, .. }) => {
                        token == pending
                    }
                    Some(TargetResolutionV1::RebootRecovery {
                        pending: Some(token),
                        ..
                    }) => token == pending,
                    _ => false,
                };
                token_matches
                    && matches!((&self.effect.destination, self.effect.encrypted_payload.as_ref().and_then(TargetPayloadV1::running)),
                    (TargetExpectationV1::Running { version }, Some((commit, None)))
                    if *version == self.handle.body.binding.base_version
                        && version.checked_add(1) == Some(running_version)
                        && commit.record.version.get() == running_version && commit.record.confirmed_deadline.is_none())
            }
            (13, Outcome::Lifecycle { incarnation }) => {
                matches!(self.effect.resolution, Some(TargetResolutionV1::EndSession { session })
                    if session == incarnation.value)
            }
            // No result may stand in for a different action or pending identity.
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(bad)
        }
    }

    pub(crate) fn verify_effect(&self, key: &AuditKey) -> Result<(), AuditAuthorityError> {
        self.effect.validate(&self.handle)?;
        self.handle
            .verify(key, self.effect.authority, self.effect.caller)?;
        verify(
            key,
            TARGET_MUTATION_DOMAIN,
            &self.effect,
            &self
                .handle
                .body
                .mutation
                .ok_or(AuditAuthorityError::BindingMismatch)?,
        )
    }
}

/// Closed NETCONF target effect and its original authenticated operation handle.
///
/// Clones share immutable command bytes and the same preparation reservation.
/// Native commands and retained logs carry only deterministic fields. Generic
/// decoding grants no slot, session, Intent receipt, or effect authority; the
/// store's reserved recovery decoder authenticates and owns bounded originals.
#[derive(Clone)]
pub struct PreparedTargetMutation {
    command: TargetMutationCommand,
    preparation: Option<Arc<PreparationOwnership>>,
}

impl PartialEq for PreparedTargetMutation {
    fn eq(&self, other: &Self) -> bool {
        self.command == other.command
    }
}

impl Serialize for PreparedTargetMutation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.command.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PreparedTargetMutation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            command: TargetMutationCommand::deserialize(deserializer)?,
            preparation: None,
        })
    }
}

impl PreparedTargetMutation {
    pub(crate) fn new(
        handle: AuditOperationHandle,
        effect: TargetEffectV1,
        preparation: Option<Arc<PreparationOwnership>>,
    ) -> Self {
        Self {
            command: TargetMutationCommand(Arc::new(TargetMutationFields { handle, effect })),
            preparation,
        }
    }

    pub(crate) fn command(&self) -> &TargetMutationCommand {
        &self.command
    }

    pub(in crate::consensus) fn from_native_command(command: TargetMutationCommand) -> Self {
        Self {
            command,
            preparation: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_command(command: TargetMutationCommand) -> Self {
        Self {
            command,
            preparation: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn command_mut(&mut self) -> &mut TargetMutationCommand {
        &mut self.command
    }

    pub(super) fn bounded_running(&self) -> Option<&joint_running::BoundedRunningPayload> {
        self.command.bounded_running()
    }

    pub(super) fn verify_bounded_running(
        &self,
        key: &AuditKey,
        identity: super::ConfigConsensusIdentity,
        caller: crate::audit_authority::AuditCaller,
    ) -> Result<super::capacity_record::RecoveredRecordCapacity, AuditAuthorityError> {
        self.command.verify_bounded_running(key, identity, caller)
    }

    pub(crate) fn begin_submission(
        &self,
        pool: &opc_crypto::ConfigPreparationPool,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<SubmissionOwnership, AuditAuthorityError> {
        match (profile, self.bounded_running()) {
            (opc_crypto::ConfigCapacityProfile::Legacy, None) => match &self.preparation {
                None => Ok(None),
                // Legacy has no destination capacity pool contract. Preserve
                // an optional real owner as ordinary audited submission does.
                Some(owner) => owner.try_submit().map(|guard| Some(Arc::new(guard))),
            },
            (opc_crypto::ConfigCapacityProfile::BoundedV1, Some(_)) => {
                let owner = self
                    .preparation
                    .as_ref()
                    .ok_or(AuditAuthorityError::InvalidInput)?;
                // SUBMISSION_TARGET_POOL: proof bytes cannot grant destination admission.
                if !owner.belongs_to(pool, profile, true) {
                    return Err(AuditAuthorityError::InvalidInput);
                }
                // SUBMISSION_TARGET_GUARD: every alias shares this one active attempt.
                owner.try_submit().map(|guard| Some(Arc::new(guard)))
            }
            _ => Err(AuditAuthorityError::InvalidInput),
        }
    }

    /// Original operation to retain before admission or possible response loss.
    pub fn handle(&self) -> &AuditOperationHandle {
        self.command.handle()
    }

    /// Encode opaque protected recovery data, never diagnostic output.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        if self.bounded_running().is_some() {
            self.command.effect.validate_for_capacity(
                self.handle(),
                opc_crypto::ConfigCapacityProfile::BoundedV1,
            )?;
            let _encoding = self
                .preparation
                .as_ref()
                .ok_or(AuditAuthorityError::InvalidInput)?
                .try_encode()?;
            let mut size = RecoverySizeCounter(0);
            serde_json::to_writer(&mut size, self)
                .map_err(|_| AuditAuthorityError::InvalidInput)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(size.0)
                .map_err(|_| AuditAuthorityError::Unavailable)?;
            serde_json::to_writer(&mut bytes, self)
                .map_err(|_| AuditAuthorityError::InvalidInput)?;
            return Ok(bytes);
        }
        self.command.encode_legacy()
    }

    /// Decode bounded recovery data. This validates representation only; it does
    /// not authenticate the supplied effect or mint a capability for it.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        #[cfg(test)]
        joint_running::tests::retained_recovery::observe_legacy_decode();
        if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)?;
        value.command.effect.validate(value.handle())?;
        Ok(value)
    }

    pub(crate) fn validate_result(
        &self,
        result: crate::audit_authority::NetconfTargetResult,
    ) -> Result<(), AuditAuthorityError> {
        self.command.validate_result(result)
    }

    pub(crate) fn verify_effect(&self, key: &AuditKey) -> Result<(), AuditAuthorityError> {
        self.command.verify_effect(key)
    }
}

impl std::fmt::Debug for PreparedTargetMutation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedTargetMutation(<redacted>)")
    }
}

// The new target format rejects unknown nested fields while preserving the
// original running commit/audit codecs and serialized field order.
mod target_commit_input {
    use super::*;
    use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Box<PreparedConfigCommit>, D::Error> {
        Commit::deserialize(deserializer).map(Box::new)
    }

    #[derive(Deserialize)]
    #[serde(remote = "PreparedConfigCommit", deny_unknown_fields)]
    struct Commit {
        #[serde(with = "Record")]
        record: crate::CommitRecord,
        #[serde(deserialize_with = "audit_entries")]
        audit: Vec<crate::AuditRecord>,
    }

    #[derive(Deserialize)]
    #[serde(remote = "crate::CommitRecord", deny_unknown_fields)]
    struct Record {
        tx_id: TxId,
        parent_tx_id: Option<TxId>,
        version: ConfigVersion,
        committed_at: Timestamp,
        principal: String,
        source: crate::CommitSource,
        schema_digest: SchemaDigest,
        plaintext_digest: Vec<u8>,
        encrypted_blob: Vec<u8>,
        rollback_point: bool,
        confirmed_deadline: Option<Timestamp>,
    }

    fn audit_entries<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<crate::AuditRecord>, D::Error> {
        #[derive(Deserialize)]
        struct Item(#[serde(with = "Entry")] crate::AuditRecord);
        Vec::<Item>::deserialize(deserializer)
            .map(|entries| entries.into_iter().map(|item| item.0).collect())
    }

    #[derive(Deserialize)]
    #[serde(remote = "crate::AuditRecord", deny_unknown_fields)]
    struct Entry {
        tx_id: TxId,
        sequence: u32,
        yang_path: String,
        op_type: crate::AuditOpType,
        previous_value: Option<String>,
        new_value: Option<String>,
        redaction_applied: bool,
        previous_hash: [u8; 32],
        entry_hmac: [u8; 32],
    }
}

impl TargetEffectV1 {
    /// Seal an SDK-prepared effect with the same domain used by verification.
    pub(crate) fn digest(&self, key: &AuditKey) -> Result<[u8; 32], AuditAuthorityError> {
        authenticate(key, TARGET_MUTATION_DOMAIN, self)
    }
}

impl TargetEffectV1 {
    pub(crate) async fn bind_target_plaintext(
        &mut self,
        tenant: opc_types::TenantId,
        replacement: crate::audit_authority::NetconfTargetReplacement<'_>,
    ) -> Result<(), AuditAuthorityError> {
        use opc_key::{ConfigAad, EnvelopeAad};
        use sha2::{Digest, Sha256};
        let bad = AuditAuthorityError::InvalidInput;
        if self.encrypted_payload.is_some()
            || replacement.plaintext.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES
        {
            return Err(bad);
        }
        // Validate the existing config-only or V2 wrapper without interpreting
        // or normalizing configuration values. Model validation stays upstream.
        target_copy::configuration_bytes(replacement.plaintext)?;
        let (slot, next) = match self.destination {
            TargetExpectationV1::Candidate { generation } if self.action.0 == 4 => {
                (0, generation.checked_next()?.get())
            }
            TargetExpectationV1::Startup { revision } if self.action.0 == 7 => {
                (1, revision.checked_next()?.get())
            }
            _ => return Err(bad),
        };
        let aad = EnvelopeAad::config(
            tenant,
            next,
            ConfigAad::new(
                opc_types::TxId::new(),
                None,
                opc_types::Timestamp::now_utc(),
                "netconf-required-audit",
                replacement.schema,
                self.encryption_store_kind(replacement.schema, slot)?,
            )
            .map_err(|_| bad)?,
        );
        let encrypted = opc_crypto::encrypt_attested_envelope(
            replacement.provider,
            &aad,
            replacement.plaintext,
        )
        .await
        .map_err(|_| AuditAuthorityError::Unavailable)?;
        let blob = TargetEncryptedBlobV1 {
            schema: replacement.schema,
            plaintext_digest: Sha256::digest(replacement.plaintext).into(),
            encrypted_blob: encrypted.encoded().to_vec(),
        };
        blob.validate()?;
        self.encrypted_payload = Some(TargetPayloadV1::Target(blob));
        Ok(())
    }
}

// Reuse the strict existing wrapper parser inside the audit preparation modules.
pub(super) fn target_copy_configuration_bytes(
    plaintext: &[u8],
) -> Result<&[u8], AuditAuthorityError> {
    target_copy::configuration_bytes(plaintext)
}
