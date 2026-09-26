//! Closed configuration effects bound into a management operation by the SDK.

use serde::{Deserialize, Serialize};

#[path = "audit_copy.rs"]
mod target_copy;
use target_copy::TargetCopyBindingV1;

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

// Admission and application use distinct, append-only phase tags inside the
// allocated target-command family. The signed effect itself is unchanged.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetAuditCommandV1 {
    Admit(PreparedTargetMutation),
    Apply(PreparedTargetMutation),
    EmptyCommit(crate::audit_authority::PreparedNetconfEmptyCommit),
}

impl TargetAuditCommandV1 {
    pub(crate) fn handle(&self) -> &AuditOperationHandle {
        match self {
            Self::Admit(prepared) | Self::Apply(prepared) => prepared.handle(),
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
            Self::Admit(prepared) | Self::Apply(prepared) => {
                prepared.verify_effect(key)?;
                let receipt = ledger.lookup(key, prepared.handle(), caller)?;
                if receipt.is_some()
                    && ledger.recover_target(key, prepared.handle(), caller)? != *prepared
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
            Self::Admit(prepared) | Self::Apply(prepared) => {
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
}

impl TargetPayloadV1 {
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
            Self::Target(_) => None,
        }
    }

    pub(crate) fn matches_source_digest(&self, digest: &[u8]) -> bool {
        match self {
            Self::Running { commit, .. } => commit.record.plaintext_digest == digest,
            Self::ProviderCopy { binding, .. } => binding.matches_source_digest(digest),
            Self::Target(_) => false,
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
                    && matches!((&self.destination, &self.source, &self.encrypted_payload),
                    (TargetExpectationV1::Running { version }, source,
                     Some(TargetPayloadV1::Running { commit, confirmation_ownership: None }))
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

/// Closed NETCONF target effect and the original authenticated operation handle.
///
/// The full retained-target submission profile is not enabled by decoding this
/// value. Decoded recovery data is untrusted until the authority verifies its
/// handle, effect binding, caller and current retained ownership. This type has
/// no public constructor from caller-asserted ciphertext or applied results.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTargetMutation {
    #[serde(deserialize_with = "crate::audit_authority::ledger::deserialize_target_handle")]
    pub(crate) handle: AuditOperationHandle,
    pub(crate) effect: TargetEffectV1,
}

impl PreparedTargetMutation {
    /// Original operation to retain before admission or possible response loss.
    pub fn handle(&self) -> &AuditOperationHandle {
        &self.handle
    }

    /// Encode opaque protected recovery data, never diagnostic output.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        self.effect.validate(&self.handle)?;
        let bytes = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(bytes)
    }

    /// Decode bounded recovery data. This validates representation only; it does
    /// not authenticate the supplied effect or mint a capability for it.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)?;
        value.effect.validate(&value.handle)?;
        Ok(value)
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
                matches!((&self.effect.encrypted_payload, &self.effect.destination),
                    (Some(TargetPayloadV1::Running { commit, confirmation_ownership: None }),
                     TargetExpectationV1::Running { version })
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
