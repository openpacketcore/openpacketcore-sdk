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

// Admission and application use distinct, append-only phase tags inside the
// allocated target-command family. The signed effect itself is unchanged.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetAuditCommandV1 {
    Admit(PreparedTargetMutation),
    Apply(PreparedTargetMutation),
}

impl TargetAuditCommandV1 {
    pub(crate) fn prepared(&self) -> &PreparedTargetMutation {
        match self {
            Self::Admit(prepared) | Self::Apply(prepared) => prepared,
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
        if value <= 15 {
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
        commit: Box<PreparedConfigCommit>,
        confirmation_ownership: Option<TargetEncryptedBlobV1>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum TargetResolutionV1 {
    Activate {
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
                && !matches!(self.action.0, 0 | 1 | 12 | 13 | 14))
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
                } => {
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
            Some(TargetPayloadV1::Running { .. })
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
            _ => false,
        };
        if !valid_action {
            return Err(bad);
        }
        Ok(())
    }
}

impl TargetEncryptedBlobV1 {
    fn validate(&self) -> Result<(), AuditAuthorityError> {
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
