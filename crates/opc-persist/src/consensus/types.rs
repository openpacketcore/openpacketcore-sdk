//! Config state-machine commands built on the shared consensus substrate.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use opc_consensus::{ConsensusEntryDigest, ConsensusIdentity};
use opc_crypto::CryptoEnvelopeV1;
use opc_types::{Timestamp, TxId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::PersistError;
use crate::types::{extract_tenant, AuditRecord, CommitRecord};

pub use opc_consensus::{
    ConsensusClusterId as ConfigConsensusClusterId,
    ConsensusConfigurationEpoch as ConfigConsensusConfigurationEpoch,
    ConsensusConfigurationId as ConfigConsensusConfigurationId,
    ConsensusEntryDigest as ConfigConsensusEntryDigest,
    ConsensusIdentity as ConfigConsensusIdentity,
    ConsensusIdentityError as ConfigConsensusIdentityError,
    ConsensusNodeId as ConfigConsensusNodeId, ConsensusRequestId as ConfigConsensusRequestId,
};

/// Current config command revision. This is deliberately independent of the
/// shared transport, durable-storage, and snapshot revisions.
pub const CONFIG_CONSENSUS_COMMAND_VERSION: u16 = 1;
/// Current SQLite authority schema revision.
pub const CONFIG_CONSENSUS_STORAGE_VERSION: u16 = 1;
/// Current config snapshot envelope revision.
pub const CONFIG_CONSENSUS_SNAPSHOT_VERSION: u16 = 1;
/// Current config-specific RPC payload revision.
pub const CONFIG_CONSENSUS_WIRE_VERSION: u16 = 1;

/// Maximum configured voter count admitted by the config consensus adapter.
pub const CONFIG_CONSENSUS_MAX_MEMBERS: usize = 9;

const COMMAND_DIGEST_DOMAIN: &[u8] = b"openpacketcore/config-consensus/command/v1\0";
const OUTCOME_DIGEST_DOMAIN: &[u8] = b"openpacketcore/config-consensus/outcome/v1\0";
const REDACTED_AUDIT_VALUE: &str = "\"<redacted>\"";
const AUDIT_PATH_TOKEN_DOMAIN: &[u8] = b"openpacketcore/config-consensus/audit-path/v1\0";
const AUDIT_PATH_TOKEN_PREFIX: &str = "hmac-sha256:";
pub(crate) const CONFIG_PRINCIPAL_MAX_BYTES: usize = 16 * 1024;
pub(crate) const CONFIG_AUDIT_RECORDS_MAX: usize = 16_384;
pub(crate) const CONFIG_AUDIT_PATH_MAX_BYTES: usize = 8 * 1024;
pub(crate) const CONFIG_ROLLBACK_LABEL_MAX_BYTES: usize = 128;

/// Immutable scope and exact voter set for one config consensus node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigConsensusTopology {
    identity: ConfigConsensusIdentity,
    local_node_id: ConfigConsensusNodeId,
    members: BTreeSet<ConfigConsensusNodeId>,
}

impl ConfigConsensusTopology {
    /// Validate one fixed, bounded voter configuration.
    pub fn try_new(
        identity: ConfigConsensusIdentity,
        local_node_id: ConfigConsensusNodeId,
        members: BTreeSet<ConfigConsensusNodeId>,
    ) -> Result<Self, ConfigConsensusTopologyError> {
        if members.is_empty()
            || members.len() > CONFIG_CONSENSUS_MAX_MEMBERS
            || !members.contains(&local_node_id)
            || (members.len() > 1 && (members.len() < 3 || members.len().is_multiple_of(2)))
        {
            return Err(ConfigConsensusTopologyError::InvalidMembers);
        }
        Ok(Self {
            identity,
            local_node_id,
            members,
        })
    }

    /// Bound cluster/configuration/epoch identity.
    pub const fn identity(&self) -> ConfigConsensusIdentity {
        self.identity
    }

    /// Canonical local Openraft node ID.
    pub const fn local_node_id(&self) -> ConfigConsensusNodeId {
        self.local_node_id
    }

    /// Exact configured voters.
    pub fn members(&self) -> &BTreeSet<ConfigConsensusNodeId> {
        &self.members
    }
}

/// Fail-closed topology validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigConsensusTopologyError {
    /// Voters were empty, even, oversized, too small for HA, or omitted self.
    #[error("invalid config consensus voter configuration")]
    InvalidMembers,
    /// Recovery approval omitted a path or supplied an invalid checksum.
    #[error("invalid legacy config recovery approval")]
    InvalidLegacyRecoveryApproval,
}

/// Explicit disposition of the legacy log suffix that cannot be proven committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyConfigTailDisposition {
    /// Replace legacy authority with the operator-approved applied snapshot and
    /// discard every unprovable appended suffix in the target database.
    DiscardUnknownAppendedSuffix,
}

/// Operator approval binding one exact legacy applied snapshot to recovery.
///
/// Debug output intentionally reveals neither the path, checksum, nor
/// transaction identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovedLegacyConfigRecovery {
    snapshot_path: PathBuf,
    expected_sha256: [u8; 32],
    authoritative_tx_id: opc_types::TxId,
    authoritative_version: opc_types::ConfigVersion,
    disposition: LegacyConfigTailDisposition,
}

impl ApprovedLegacyConfigRecovery {
    /// Bind an offline SQLite snapshot, externally verified checksum, exact
    /// applied chain head, and explicit unknown-tail discard decision.
    pub fn new(
        snapshot_path: impl Into<PathBuf>,
        expected_sha256: [u8; 32],
        authoritative_tx_id: opc_types::TxId,
        authoritative_version: opc_types::ConfigVersion,
        disposition: LegacyConfigTailDisposition,
    ) -> Result<Self, ConfigConsensusTopologyError> {
        let snapshot_path = snapshot_path.into();
        if snapshot_path.as_os_str().is_empty() || expected_sha256 == [0; 32] {
            return Err(ConfigConsensusTopologyError::InvalidLegacyRecoveryApproval);
        }
        Ok(Self {
            snapshot_path,
            expected_sha256,
            authoritative_tx_id,
            authoritative_version,
            disposition,
        })
    }

    pub(crate) fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub(crate) const fn expected_sha256(&self) -> [u8; 32] {
        self.expected_sha256
    }

    pub(crate) const fn authoritative_tx_id(&self) -> opc_types::TxId {
        self.authoritative_tx_id
    }

    pub(crate) const fn authoritative_version(&self) -> opc_types::ConfigVersion {
        self.authoritative_version
    }

    pub(crate) const fn disposition(&self) -> LegacyConfigTailDisposition {
        self.disposition
    }
}

impl std::fmt::Debug for ApprovedLegacyConfigRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovedLegacyConfigRecovery")
            .field("snapshot_path", &"<redacted>")
            .field("expected_sha256", &"<redacted>")
            .field("authoritative_tx_id", &"<redacted>")
            .field("authoritative_version", &self.authoritative_version)
            .field("disposition", &self.disposition)
            .finish()
    }
}

/// Clock port used only by the current leader when constructing a command.
///
/// Followers never call this port: the selected value is committed in the
/// command and applied monotonically by every replica.
pub trait ConfigConsensusClock: Send + Sync + std::fmt::Debug {
    /// Observe wall time for the next proposal.
    fn now_utc(&self) -> Timestamp;
}

/// Production UTC clock.
#[derive(Debug, Default)]
pub struct SystemConfigConsensusClock;

impl ConfigConsensusClock for SystemConfigConsensusClock {
    fn now_utc(&self) -> Timestamp {
        Timestamp::now_utc()
    }
}

/// A commit whose payload is already an authenticated AEAD envelope and whose
/// audit values are already redacted and HMAC-finalized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PreparedConfigCommit {
    /// Encrypted configuration and deterministic commit metadata.
    pub(crate) record: CommitRecord,
    /// Bounded, redacted, finalized audit chain.
    pub(crate) audit: Vec<AuditRecord>,
}

impl PreparedConfigCommit {
    /// Finalize the audit chain before the command crosses into Openraft.
    ///
    /// Every audit value is masked, even when it is not classified as secret,
    /// so no configuration value can enter a Raft log or wire frame. The audit
    /// key is used here and is never retained by the command or state machine.
    pub(crate) fn prepare(
        record: CommitRecord,
        mut audit: Vec<AuditRecord>,
        audit_key: &crate::types::AuditKey,
    ) -> Result<Self, PersistError> {
        validate_record_representability(&record)?;
        if audit.len() > CONFIG_AUDIT_RECORDS_MAX {
            return Err(PersistError::constraint_violation(
                "config audit record count exceeds durable limit",
            ));
        }
        let audit_count =
            u32::try_from(audit.len()).map_err(|_| PersistError::audit_chain_broken())?;
        let tenant = extract_tenant(&record.principal);
        let mut previous_hash = [0_u8; 32];
        for (expected_sequence, entry) in audit.iter_mut().enumerate() {
            if entry.tx_id != record.tx_id
                || usize::try_from(entry.sequence).ok() != Some(expected_sequence)
            {
                return Err(PersistError::audit_chain_broken());
            }
            entry.yang_path = tokenize_audit_path(&entry.yang_path, audit_key)?;
            if entry.previous_value.is_some() {
                entry.previous_value = Some(REDACTED_AUDIT_VALUE.to_owned());
                entry.redaction_applied = true;
            }
            if entry.new_value.is_some() {
                entry.new_value = Some(REDACTED_AUDIT_VALUE.to_owned());
                entry.redaction_applied = true;
            }
            entry.previous_hash = previous_hash;
            entry.entry_hmac =
                entry.calculate_hmac_with_audit_count(audit_key, &tenant, audit_count);
            previous_hash = entry.entry_hmac;
        }
        Ok(Self { record, audit })
    }

    /// Validate envelope and finalized audit structure without key access.
    pub(crate) fn validate(&self) -> Result<(), PersistError> {
        validate_record_representability(&self.record)?;
        if self.audit.len() > CONFIG_AUDIT_RECORDS_MAX {
            return Err(PersistError::constraint_violation(
                "config audit record count exceeds durable limit",
            ));
        }
        let mut previous_hash = [0_u8; 32];
        for (expected_sequence, entry) in self.audit.iter().enumerate() {
            if entry.tx_id != self.record.tx_id
                || usize::try_from(entry.sequence).ok() != Some(expected_sequence)
                || entry.previous_hash != previous_hash
                || entry
                    .previous_value
                    .as_deref()
                    .is_some_and(|value| value != REDACTED_AUDIT_VALUE)
                || entry
                    .new_value
                    .as_deref()
                    .is_some_and(|value| value != REDACTED_AUDIT_VALUE)
                || (entry.previous_value.is_some() || entry.new_value.is_some())
                    && !entry.redaction_applied
                || !audit_path_is_safe(&entry.yang_path)
            {
                return Err(PersistError::audit_chain_broken());
            }
            previous_hash = entry.entry_hmac;
        }
        Ok(())
    }
}

/// High-level deterministic mutation carried by a normal Openraft entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum ConfigMutationIntent {
    /// Append one encrypted configuration and its finalized audit history.
    AppendCommit(Box<PreparedConfigCommit>),
    /// Permanently confirm a pending commit.
    MarkConfirmed { tx_id: TxId },
    /// Mark an existing transaction as a rollback point.
    CreateRollbackPoint {
        tx_id: TxId,
        label: Option<ValidatedRollbackLabel>,
    },
}

/// Canonical rollback label validated before it can enter a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValidatedRollbackLabel(pub(crate) String);

impl ValidatedRollbackLabel {
    pub(crate) fn try_new(value: String) -> Result<Self, PersistError> {
        if value.is_empty()
            || value.len() > CONFIG_ROLLBACK_LABEL_MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(PersistError::constraint_violation(
                "rollback label is not canonically representable",
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Application command stored in Openraft's durable log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ConfigConsensusCommand {
    /// Exact command schema.
    pub(crate) schema_version: u16,
    /// Cluster/configuration/epoch scope.
    pub(crate) identity: ConfigConsensusIdentity,
    /// Durable request identity for response-loss replay.
    pub(crate) request_id: ConfigConsensusRequestId,
    /// Leader-observed time, selected before proposal and committed as input.
    pub(crate) logical_time: Timestamp,
    /// Deterministic config mutation.
    pub(crate) intent: ConfigMutationIntent,
}

impl ConfigConsensusCommand {
    /// Digest the command bytes for request-ID collision detection.
    pub(crate) fn payload_digest(&self) -> Result<[u8; 32], PersistError> {
        let bytes = serde_json::to_vec(&(self.schema_version, self.identity, &self.intent))
            .map_err(|_| PersistError::inconsistent_state("config consensus encoding failed"))?;
        let mut hasher = Sha256::new();
        hasher.update(OUTCOME_DIGEST_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    /// Chain one applied command to its predecessor and deterministic time.
    pub(crate) fn calculate_applied_digest(
        &self,
        sequence: u64,
        previous: ConfigConsensusEntryDigest,
        effective_time: Timestamp,
    ) -> Result<ConfigConsensusEntryDigest, PersistError> {
        let bytes = serde_json::to_vec(&(sequence, previous, effective_time, self))
            .map_err(|_| PersistError::inconsistent_state("config consensus digest failed"))?;
        let mut hasher = Sha256::new();
        hasher.update(COMMAND_DIGEST_DOMAIN);
        hasher.update(bytes);
        Ok(ConsensusEntryDigest::from_bytes(hasher.finalize().into()))
    }

    /// Validate scope, schema, and encrypted command contents.
    pub(crate) fn validate(&self, identity: ConsensusIdentity) -> Result<(), PersistError> {
        if self.schema_version != CONFIG_CONSENSUS_COMMAND_VERSION || self.identity != identity {
            return Err(PersistError::inconsistent_state(
                "config consensus command scope mismatch",
            ));
        }
        match &self.intent {
            ConfigMutationIntent::AppendCommit(commit) => commit.validate()?,
            ConfigMutationIntent::MarkConfirmed { .. } => {}
            ConfigMutationIntent::CreateRollbackPoint { label, .. } => {
                if label
                    .as_ref()
                    .is_some_and(|label| ValidatedRollbackLabel::try_new(label.0.clone()).is_err())
                {
                    return Err(PersistError::constraint_violation(
                        "rollback label is not canonically representable",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Stable application rejection persisted in request outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ConfigMutationFailure {
    /// A referenced transaction or rollback target does not exist.
    NotFound,
    /// A uniqueness, lineage, label, or version invariant was rejected.
    Conflict,
    /// The caller reused a durable request ID for a different payload.
    RequestIdCollision,
    /// The sealed command or audit chain was malformed.
    InvalidInput,
}

impl ConfigMutationFailure {
    pub(crate) fn into_persist_error(self) -> PersistError {
        match self {
            Self::NotFound => PersistError::rollback_not_found(),
            Self::Conflict => {
                PersistError::constraint_violation("config consensus mutation conflict")
            }
            Self::RequestIdCollision => PersistError::request_id_collision(),
            Self::InvalidInput => PersistError::corrupt_blob(),
        }
    }
}

/// Persisted result returned after durable quorum commit and local apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConfigConsensusResponse {
    /// Deterministic mutation result.
    pub(crate) result: Result<(), ConfigMutationFailure>,
    /// Monotonic admitted application sequence.
    pub(crate) sequence: u64,
    /// Digest of the application chain at this command.
    pub(crate) digest: Option<ConfigConsensusEntryDigest>,
    /// Monotonic committed logical time.
    pub(crate) logical_time: Option<Timestamp>,
    /// Openraft log index that applied the original request.
    pub(crate) raft_log_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConfigWirePayload<T> {
    revision: u16,
    value: T,
}

pub(crate) fn encode_config_wire<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, opc_consensus::ConsensusCodecError> {
    #[derive(Serialize)]
    struct BorrowedConfigWirePayload<'a, T: ?Sized> {
        revision: u16,
        value: &'a T,
    }
    opc_consensus::encode_bounded(&BorrowedConfigWirePayload {
        revision: CONFIG_CONSENSUS_WIRE_VERSION,
        value,
    })
}

pub(crate) fn decode_config_wire<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, opc_consensus::ConsensusCodecError> {
    let payload: ConfigWirePayload<T> = opc_consensus::decode_bounded(bytes)?;
    if payload.revision != CONFIG_CONSENSUS_WIRE_VERSION {
        return Err(opc_consensus::ConsensusCodecError::Decode);
    }
    Ok(payload.value)
}

impl ConfigConsensusResponse {
    pub(crate) fn into_result(self) -> Result<(), PersistError> {
        self.result
            .map_err(ConfigMutationFailure::into_persist_error)
    }
}

/// Validate that the config payload is a structurally valid AEAD envelope.
pub(crate) fn validate_encrypted_record(record: &CommitRecord) -> Result<(), PersistError> {
    if record.plaintext_digest.len() != 32 || record.encrypted_blob.is_empty() {
        return Err(PersistError::corrupt_blob());
    }
    let envelope = CryptoEnvelopeV1::decode(&record.encrypted_blob)
        .map_err(|_| PersistError::corrupt_blob())?;
    if envelope.nonce.len() != envelope.algorithm.nonce_len()
        || envelope.aad.is_empty()
        || envelope.ciphertext_and_tag.len() < opc_key::AEAD_TAG_LEN
    {
        return Err(PersistError::corrupt_blob());
    }
    let (aad, bound_key_id) =
        opc_key::decode_bound_aad(&envelope.aad).map_err(|_| PersistError::corrupt_blob())?;
    let opc_key::EnvelopeMetadata::Config(metadata) = aad.metadata() else {
        return Err(PersistError::corrupt_blob());
    };
    if bound_key_id != envelope.key_id
        || aad.purpose() != opc_key::KeyPurpose::Config
        || aad.version() != record.version.get()
        || metadata.tx_id() != &record.tx_id
        || metadata.parent_tx_id() != record.parent_tx_id.as_ref()
        || metadata.committed_at() != &record.committed_at
        || metadata.principal() != record.principal
        || metadata.schema_digest() != &record.schema_digest
    {
        return Err(PersistError::corrupt_blob());
    }
    Ok(())
}

fn validate_record_representability(record: &CommitRecord) -> Result<(), PersistError> {
    if record.version.get() == 0
        || record.version.get() > i64::MAX as u64
        || record.principal.is_empty()
        || record.principal.len() > CONFIG_PRINCIPAL_MAX_BYTES
        || record.principal.chars().any(char::is_control)
    {
        return Err(PersistError::constraint_violation(
            "config record is not representable by durable storage",
        ));
    }
    validate_encrypted_record(record)
}

pub(crate) fn tokenize_audit_path(
    path: &str,
    audit_key: &crate::types::AuditKey,
) -> Result<String, PersistError> {
    if path.is_empty()
        || path.len() > CONFIG_AUDIT_PATH_MAX_BYTES
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return Err(PersistError::constraint_violation(
            "audit YANG path is not canonically representable",
        ));
    }
    let mut output = String::with_capacity(path.len());
    let mut remainder = path;
    while let Some(open) = remainder.find('[') {
        output.push_str(&remainder[..open + 1]);
        remainder = &remainder[open + 1..];
        let close = remainder.find(']').ok_or_else(|| {
            PersistError::constraint_violation("audit YANG predicate is malformed")
        })?;
        let predicate = &remainder[..close];
        let (key, raw_value) = predicate.split_once('=').ok_or_else(|| {
            PersistError::constraint_violation("audit YANG predicate is malformed")
        })?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.'))
        {
            return Err(PersistError::constraint_violation(
                "audit YANG predicate key is malformed",
            ));
        }
        let raw_value = raw_value.trim();
        let quote = raw_value.as_bytes().first().copied().ok_or_else(|| {
            PersistError::constraint_violation("audit YANG predicate value is malformed")
        })?;
        if !matches!(quote, b'\'' | b'\"')
            || raw_value.len() < 2
            || raw_value.as_bytes().last().copied() != Some(quote)
        {
            return Err(PersistError::constraint_violation(
                "audit YANG predicate value is malformed",
            ));
        }
        let value = &raw_value[1..raw_value.len() - 1];
        if value.is_empty()
            || value.as_bytes().contains(&quote)
            || value.chars().any(char::is_control)
        {
            return Err(PersistError::constraint_violation(
                "audit YANG predicate value is malformed",
            ));
        }
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(audit_key.as_bytes())
            .map_err(|_| PersistError::audit_chain_broken())?;
        mac.update(AUDIT_PATH_TOKEN_DOMAIN);
        mac.update(&(key.len() as u32).to_be_bytes());
        mac.update(key.as_bytes());
        mac.update(&(value.len() as u32).to_be_bytes());
        mac.update(value.as_bytes());
        let token = mac.finalize().into_bytes();
        write!(output, "{key}='{AUDIT_PATH_TOKEN_PREFIX}")
            .map_err(|_| PersistError::audit_chain_broken())?;
        for byte in token {
            write!(output, "{byte:02x}").map_err(|_| PersistError::audit_chain_broken())?;
        }
        output.push_str("']");
        remainder = &remainder[close + 1..];
    }
    if remainder.contains(']') {
        return Err(PersistError::constraint_violation(
            "audit YANG predicate is malformed",
        ));
    }
    output.push_str(remainder);
    if output.len() > CONFIG_AUDIT_PATH_MAX_BYTES {
        return Err(PersistError::constraint_violation(
            "tokenized audit YANG path exceeds durable limit",
        ));
    }
    Ok(output)
}

pub(crate) fn audit_path_is_safe(path: &str) -> bool {
    if path.is_empty()
        || path.len() > CONFIG_AUDIT_PATH_MAX_BYTES
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return false;
    }
    let mut remainder = path;
    while let Some(open) = remainder.find('[') {
        remainder = &remainder[open + 1..];
        let Some(close) = remainder.find(']') else {
            return false;
        };
        let predicate = &remainder[..close];
        let Some((key, value)) = predicate.split_once('=') else {
            return false;
        };
        let key = key.trim();
        let value = value.trim();
        let expected_len = 1 + AUDIT_PATH_TOKEN_PREFIX.len() + 64 + 1;
        if key.is_empty()
            || value.len() != expected_len
            || !value.starts_with(&format!("'{AUDIT_PATH_TOKEN_PREFIX}"))
            || !value.ends_with('\'')
            || !value[1 + AUDIT_PATH_TOKEN_PREFIX.len()..value.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return false;
        }
        remainder = &remainder[close + 1..];
    }
    !remainder.contains(']')
}

/// Shared transport peer used by config consensus.
pub type ConfigConsensusPeer = dyn opc_consensus::ConsensusPeer;

/// Shared authenticated inbound handler used by config consensus.
pub type ConfigConsensusRpcHandler = dyn opc_consensus::ConsensusRpcHandler;

/// Reference-counted clock port accepted by constructors.
pub type SharedConfigConsensusClock = Arc<dyn ConfigConsensusClock>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_rejects_even_and_missing_self_membership() {
        let cluster = ConfigConsensusClusterId::new("config-types-test").expect("cluster");
        let epoch = ConfigConsensusConfigurationEpoch::new(1).expect("epoch");
        let identity = ConfigConsensusIdentity::new(
            cluster,
            ConfigConsensusConfigurationId::from_bytes([1; 32]),
            epoch,
        );
        let one = ConfigConsensusNodeId::new(1).expect("node");
        let two = ConfigConsensusNodeId::new(2).expect("node");
        assert!(ConfigConsensusTopology::try_new(identity, one, [one].into()).is_ok());
        assert_eq!(
            ConfigConsensusTopology::try_new(identity, one, [one, two].into()),
            Err(ConfigConsensusTopologyError::InvalidMembers)
        );
        assert_eq!(
            ConfigConsensusTopology::try_new(identity, one, [two].into()),
            Err(ConfigConsensusTopologyError::InvalidMembers)
        );
    }

    #[test]
    fn audit_predicates_are_tokenized_and_bounds_fail_closed() {
        let key = crate::types::AuditKey::new([0x43; 32]).expect("audit key");
        let sensitive = "/interfaces/interface[name='supi-001010123456789']/config/enabled";
        let tokenized = tokenize_audit_path(sensitive, &key).expect("tokenized path");
        assert!(audit_path_is_safe(&tokenized));
        assert!(!tokenized.contains("supi-001010123456789"));
        assert_eq!(
            tokenized,
            tokenize_audit_path(sensitive, &key).expect("deterministic token")
        );
        assert!(tokenize_audit_path("/interfaces/interface[name='unterminated]", &key).is_err());
        assert!(
            ValidatedRollbackLabel::try_new("x".repeat(CONFIG_ROLLBACK_LABEL_MAX_BYTES)).is_ok()
        );
        assert!(
            ValidatedRollbackLabel::try_new("x".repeat(CONFIG_ROLLBACK_LABEL_MAX_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn config_wire_revision_is_independent_and_exact() {
        let current = encode_config_wire(&7_u64).expect("current wire");
        assert_eq!(
            7,
            decode_config_wire::<u64>(&current).expect("current reader")
        );
        let future = opc_consensus::encode_bounded(&ConfigWirePayload {
            revision: CONFIG_CONSENSUS_WIRE_VERSION + 1,
            value: 7_u64,
        })
        .expect("future fixture");
        assert!(decode_config_wire::<u64>(&future).is_err());

        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-command-revision-test").expect("cluster"),
            ConfigConsensusConfigurationId::from_bytes([0xA4; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        );
        let future_command = ConfigConsensusCommand {
            schema_version: CONFIG_CONSENSUS_COMMAND_VERSION + 1,
            identity,
            request_id: ConfigConsensusRequestId::from_bytes([0xA5; 16]),
            logical_time: Timestamp::now_utc(),
            intent: ConfigMutationIntent::MarkConfirmed { tx_id: TxId::new() },
        };
        assert!(future_command.validate(identity).is_err());
    }
}
