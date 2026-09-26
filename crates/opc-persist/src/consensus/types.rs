//! Config state-machine commands built on the shared consensus substrate.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use opc_consensus::{ConsensusEntryDigest, ConsensusIdentity};
use opc_crypto::CryptoEnvelopeRef;
use opc_types::{Timestamp, TxId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::PersistError;
use crate::types::{extract_tenant, AuditRecord, CommitRecord, ConfirmedCommitResolution};

pub use opc_consensus::{
    ConsensusClusterId as ConfigConsensusClusterId,
    ConsensusConfigurationEpoch as ConfigConsensusConfigurationEpoch,
    ConsensusConfigurationId as ConfigConsensusConfigurationId,
    ConsensusEntryDigest as ConfigConsensusEntryDigest,
    ConsensusIdentity as ConfigConsensusIdentity,
    ConsensusIdentityError as ConfigConsensusIdentityError,
    ConsensusNodeId as ConfigConsensusNodeId, ConsensusRequestId as ConfigConsensusRequestId,
};

pub(crate) const LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION: u16 = 1;
pub(crate) const ATOMIC_CONFIG_CONSENSUS_COMMAND_VERSION: u16 = 2;
/// Current config command revision. This is deliberately independent of the
/// shared transport, durable-storage, and snapshot revisions.
///
/// Revision 2 added atomic commit-confirmed resolution and recovery-fence
/// clearing. Revision 3 adds an inline named rollback point to an appended
/// encrypted record. Revision 4 adds authenticated history retention. Revision 5
/// adds the replicated management ledger and audited configuration effects.
/// Revision 6 adds authenticated signing transitions, export acknowledgements
/// and checkpoint-protected retention. Revision 7 separates verified-export
/// retention authority from required mutation checkpoint advancement. Older
/// commands remain readable under their original
/// semantics so existing durable logs can be replayed after upgrade.
pub const CONFIG_CONSENSUS_COMMAND_VERSION: u16 = 7;
/// Current SQLite authority schema revision.
pub const CONFIG_CONSENSUS_STORAGE_VERSION: u16 = 5;
/// Current config snapshot envelope revision.
pub const CONFIG_CONSENSUS_SNAPSHOT_VERSION: u16 = 5;
/// Current config-specific RPC payload revision.
///
/// Revision 7 carries the revision-7 command admission contract. Peers require
/// an exact match and do not negotiate a downgrade.
pub const CONFIG_CONSENSUS_WIRE_VERSION: u16 = 7;

/// The opt-in profile has distinct on-disk and snapshot revisions. Existing
/// constants and legacy encodings remain unchanged; there is no migration.
pub(crate) const fn config_storage_revision(profile: opc_crypto::ConfigCapacityProfile) -> u16 {
    match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => CONFIG_CONSENSUS_STORAGE_VERSION,
        opc_crypto::ConfigCapacityProfile::BoundedV1 => 6,
        _ => 0,
    }
}

pub(crate) const fn config_snapshot_revision(profile: opc_crypto::ConfigCapacityProfile) -> u16 {
    match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => CONFIG_CONSENSUS_SNAPSHOT_VERSION,
        opc_crypto::ConfigCapacityProfile::BoundedV1 => 6,
        _ => 0,
    }
}

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
/// Complete postcard command minus one envelope's byte content. Its length
/// prefix, record proof, audit handle and all other framing remain charged.
pub(super) const CONFIG_CAPACITY_V1_METADATA_BYTES: usize = 192 * 1024;

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

mod config_capacity_record_encoding;

/// A commit whose payload is already an authenticated AEAD envelope and whose
/// audit values are already redacted and HMAC-finalized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PreparedConfigCommit {
    /// Encrypted configuration and deterministic commit metadata.
    #[serde(serialize_with = "config_capacity_record_encoding::serialize")]
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
    #[cfg(test)]
    pub(crate) fn prepare(
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        audit_key: &crate::types::AuditKey,
    ) -> Result<Self, PersistError> {
        Self::prepare_for_profile(
            record,
            audit,
            audit_key,
            opc_crypto::ConfigCapacityProfile::Legacy,
        )
    }

    /// Use the authority's immutable profile for the early necessary bound.
    /// Full command metadata admission still follows finalized preparation.
    pub(crate) fn prepare_for_profile(
        record: CommitRecord,
        mut audit: Vec<AuditRecord>,
        audit_key: &crate::types::AuditKey,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<Self, PersistError> {
        preflight_preparation_capacity(&record, &audit, audit.capacity(), profile, audit_key)?;
        super::capacity_record::preflight_envelope_for_profile(&record.encrypted_blob, profile)?;
        validate_record_representability(&record)?;
        if audit.len() > CONFIG_AUDIT_RECORDS_MAX {
            return Err(PersistError::constraint_violation(
                "config audit record count exceeds durable limit",
            ));
        }
        let audit_count =
            u32::try_from(audit.len()).map_err(|_| PersistError::audit_chain_broken())?;
        #[cfg(test)]
        config_capacity_audit_preparation_tests::observe_start();
        preflight_finalized_audit_size(&audit, audit_key, profile)?;
        let tenant = extract_tenant(&record.principal);
        let mut previous_hash = [0_u8; 32];
        for (expected_sequence, entry) in audit.iter_mut().enumerate() {
            if entry.tx_id != record.tx_id
                || usize::try_from(entry.sequence).ok() != Some(expected_sequence)
            {
                return Err(PersistError::audit_chain_broken());
            }
            entry.yang_path = tokenize_audit_path(&entry.yang_path, audit_key)?;
            #[cfg(test)]
            config_capacity_audit_preparation_tests::observe_path(entry.yang_path.capacity());
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

// A necessary preparation check against the proposed entire-operation allowance.
// Keep room for all transferred owners and the emitted audit replacement bytes
// simultaneously; original fields still exist while each replacement is built.
// This is not a sufficient whole-operation budget: validation temporaries,
// allocator rounding, caller allocations and later phases remain separate.
fn preflight_preparation_capacity(
    record: &CommitRecord,
    audit: &[AuditRecord],
    audit_capacity: usize,
    profile: opc_crypto::ConfigCapacityProfile,
    audit_key: &crate::types::AuditKey,
) -> Result<(), PersistError> {
    match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => return Ok(()),
        opc_crypto::ConfigCapacityProfile::BoundedV1 => {}
        _ => return Err(PersistError::corrupt_blob()),
    }
    const PREPARATION_NECESSARY_MAX_BYTES: usize = 32 * 1024 * 1024;
    let too_large = || {
        PersistError::constraint_violation("config preparation allocation exceeds working limit")
    };
    // This includes the record and Vec/String control blocks. The audit
    // backing allocation includes initialized and unused element capacity;
    // only initialized elements own nested String allocations.
    let mut owned_bytes = std::mem::size_of::<PreparedConfigCommit>();
    let mut charge = |bytes: usize| -> Result<(), PersistError> {
        owned_bytes = owned_bytes
            .checked_add(bytes)
            .filter(|total| *total <= PREPARATION_NECESSARY_MAX_BYTES)
            .ok_or_else(too_large)?;
        Ok(())
    };
    // Preparation retains these owners while later SDK recovery encoding
    // creates its output. Leave the encoder's existing maximum output extent
    // inside the same allowance before admitting input capacity. A ciphertext
    // length is insufficient: the recovery JSON represents bytes as decimal
    // array elements. This necessary headroom is not a whole-operation bound;
    // allocator overhead and concurrent later phases still need qualification.
    charge(super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES)?;
    charge(record.encrypted_blob.capacity())?;
    charge(record.plaintext_digest.capacity())?;
    charge(record.principal.capacity())?;
    charge(
        audit_capacity
            .checked_mul(std::mem::size_of::<AuditRecord>())
            .ok_or_else(too_large)?,
    )?;
    for entry in audit {
        charge(entry.yang_path.capacity())?;
        if let Some(value) = &entry.previous_value {
            charge(value.capacity())?;
        }
        if let Some(value) = &entry.new_value {
            charge(value.capacity())?;
        }
    }
    // The header KeyId copy and canonical AAD output coexist with transferred
    // input owners during validation. Inspect their encoded extents before
    // invoking any allocating decoder. This necessary byte floor does not
    // qualify parser scratch, decoded-owner capacities or the whole operation.
    let (header_key_bytes, aad_bytes) =
        CryptoEnvelopeRef::encoded_metadata_lengths(&record.encrypted_blob)
            .map_err(|_| PersistError::corrupt_blob())?;
    charge(header_key_bytes)?;
    charge(aad_bytes)?;
    // Keep a second principal-sized allowance for decoded scalar contents.
    // Reserved strings are copied while the original record stays live.
    // Parser scratch, nested raw values, allocator rounding and tenant
    // extraction still need separate accounting; this is not a peak bound.
    charge(record.principal.len())?;
    // Count with the existing bounded emitter before validation or output
    // allocation. Charge every new output while conservatively retaining all
    // old inputs; do not subtract the raw path before its replacement exists.
    for entry in audit {
        validate_audit_path_input(&entry.yang_path)?;
        let mut finalized_bytes = AuditPathByteCount(0);
        write_tokenized_audit_path(&entry.yang_path, audit_key, &mut finalized_bytes)?;
        charge(finalized_bytes.0)?;
        if entry.previous_value.is_some() {
            charge(REDACTED_AUDIT_VALUE.len())?;
        }
        if entry.new_value.is_some() {
            charge(REDACTED_AUDIT_VALUE.len())?;
        }
    }
    Ok(())
}

// Count the finalized vector before replacing any path. Its necessary bound
// is the Legacy command ceiling or the bounded profile's metadata ceiling.
// Complete command metadata and resource admission remain separate checks.
// No legacy command that fitted its original fence acquires a smaller bound.
fn preflight_finalized_audit_size(
    audit: &[AuditRecord],
    audit_key: &crate::types::AuditKey,
    profile: opc_crypto::ConfigCapacityProfile,
) -> Result<(), PersistError> {
    let limit = match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => {
            opc_consensus::DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES
        }
        opc_crypto::ConfigCapacityProfile::BoundedV1 => CONFIG_CAPACITY_V1_METADATA_BYTES,
        _ => return Err(PersistError::corrupt_blob()),
    };
    // Postcard string sizing depends only on byte length. This static ASCII
    // placeholder avoids allocating each finalized path merely to count it.
    static PATH_BYTES: [u8; CONFIG_AUDIT_PATH_MAX_BYTES] = [b'x'; CONFIG_AUDIT_PATH_MAX_BYTES];
    let mut total = audit_component_encoded_size(&audit.len())?;
    for entry in audit {
        validate_audit_path_input(&entry.yang_path)?;
        let mut path_bytes = AuditPathByteCount(0);
        write_tokenized_audit_path(&entry.yang_path, audit_key, &mut path_bytes)?;
        let path = std::str::from_utf8(&PATH_BYTES[..path_bytes.0])
            .map_err(|_| PersistError::audit_chain_broken())?;
        let probe = FinalizedAuditSizeProbe {
            tx_id: &entry.tx_id,
            sequence: entry.sequence,
            yang_path: path,
            op_type: &entry.op_type,
            previous_value: entry.previous_value.as_ref().map(|_| REDACTED_AUDIT_VALUE),
            new_value: entry.new_value.as_ref().map(|_| REDACTED_AUDIT_VALUE),
            redaction_applied: entry.redaction_applied
                || entry.previous_value.is_some()
                || entry.new_value.is_some(),
            // Postcard writes every u8 as one byte. Hash contents cannot change
            // their encoded size; the real chain is produced only after admission.
            previous_hash: &entry.previous_hash,
            entry_hmac: &entry.entry_hmac,
        };
        total = total
            .checked_add(audit_component_encoded_size(&probe)?)
            .filter(|bytes| *bytes <= limit)
            .ok_or_else(|| {
                PersistError::constraint_violation("config audit exceeds command byte limit")
            })?;
    }
    Ok(())
}

// Match AuditRecord's field order and representation. The boundary fixture
// compares this admission with the actual finalized vector's postcard size.
#[derive(Serialize)]
struct FinalizedAuditSizeProbe<'a> {
    tx_id: &'a TxId,
    sequence: u32,
    yang_path: &'a str,
    op_type: &'a crate::types::AuditOpType,
    previous_value: Option<&'a str>,
    new_value: Option<&'a str>,
    redaction_applied: bool,
    previous_hash: &'a [u8; 32],
    entry_hmac: &'a [u8; 32],
}

fn audit_component_encoded_size(value: &impl Serialize) -> Result<usize, PersistError> {
    let mut counter = opc_consensus::AppendEntriesBatchAccumulator::new();
    counter.consider(value).map_err(|_| {
        PersistError::constraint_violation("config audit cannot be sized for admission")
    })?;
    Ok(counter.serialized_entry_bytes())
}

fn validate_confirmed_resolution(
    record: &CommitRecord,
    resolution: ConfirmedCommitResolution,
) -> Result<(), PersistError> {
    if record.parent_tx_id != Some(resolution.pending_tx_id())
        || record.confirmed_deadline.is_some()
    {
        return Err(PersistError::constraint_violation(
            "confirmed resolution does not match a non-pending successor",
        ));
    }
    Ok(())
}

fn validate_rollback_point_label(
    label: Option<&ValidatedRollbackLabel>,
) -> Result<(), PersistError> {
    if label.is_some_and(|label| crate::types::validate_rollback_label(label.as_str()).is_err()) {
        return Err(PersistError::constraint_violation(
            "rollback label is not canonically representable",
        ));
    }
    Ok(())
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
    /// Resolve the exact pending head and append its successor atomically.
    ///
    /// New intents stay after every revision-1 variant because postcard uses
    /// declaration order in config RPC/Openraft replication payloads. Durable
    /// JSON rows retain their named revision-1 variant shapes separately.
    ResolveConfirmedAndAppend {
        /// Encrypted successor and finalized audit history.
        commit: Box<PreparedConfigCommit>,
        /// Exact pending-parent decision.
        resolution: ConfirmedCommitResolution,
    },
    /// Clear the config-bus recovery fence marker on one durable record.
    ClearRecoveryRequired { tx_id: TxId },
    /// Explicit acknowledged-prefix retention under exact-head authority.
    RetainHistory(super::ConfigHistoryRetention),
    /// Purpose-separated management ledger, with no configuration version change.
    /// Indirection keeps unrelated intents small; serde retains the original
    /// variant index, JSON name and payload bytes.
    ManagementAudit(Box<super::audit::AuditCommand>),
    /// Exact configuration effect and recoverable audit outcome, applied atomically.
    AuditedMutation(super::audit_mutation::AuditedConfigCommand),
    /// Append with a size proof issued from the paired encryption evidence.
    /// This stays last: legacy postcard indices and durable JSON are unchanged.
    BoundedAppend {
        commit: Box<PreparedConfigCommit>,
        binding: super::capacity_record::CapacityRecordBinding,
        resolution: Option<ConfirmedCommitResolution>,
    },
}

impl ConfigMutationIntent {
    pub(super) fn minimum_command_version(&self) -> u16 {
        match self {
            Self::AppendCommit(_)
            | Self::MarkConfirmed { .. }
            | Self::CreateRollbackPoint { .. } => LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION,
            Self::ResolveConfirmedAndAppend { .. } | Self::ClearRecoveryRequired { .. } => {
                ATOMIC_CONFIG_CONSENSUS_COMMAND_VERSION
            }
            Self::RetainHistory(_) => 4,
            Self::BoundedAppend { .. } => 8,
            Self::AuditedMutation(prepared) => prepared.effect.minimum_command_version(),
            Self::ManagementAudit(command) => match command.as_ref() {
                super::audit::AuditCommand::Initialize { .. }
                | super::audit::AuditCommand::Intent(_)
                | super::audit::AuditCommand::Reject(_)
                | super::audit::AuditCommand::Terminal(_) => 5,
                super::audit::AuditCommand::AcknowledgeExport(_) => 7,
                _ => 6,
            },
        }
    }

    pub(super) fn prepared_append(
        commit: PreparedConfigCommit,
        resolution: Option<ConfirmedCommitResolution>,
        binding: Option<super::capacity_record::CapacityRecordBinding>,
    ) -> Self {
        match (binding, resolution) {
            (Some(binding), resolution) => Self::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution,
            },
            (None, Some(resolution)) => Self::ResolveConfirmedAndAppend {
                commit: Box::new(commit),
                resolution,
            },
            (None, None) => Self::AppendCommit(Box::new(commit)),
        }
    }

    /// Enforce the admitted authority's profile without trusting the incoming
    /// command revision or its record proof to select that profile.
    pub(super) fn validate_capacity(
        &self,
        identity: ConfigConsensusIdentity,
        key: &crate::AuditKey,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        use opc_crypto::ConfigCapacityProfile;
        if !matches!(
            profile,
            ConfigCapacityProfile::Legacy | ConfigCapacityProfile::BoundedV1
        ) {
            return Err(PersistError::corrupt_blob());
        }
        match self {
            Self::BoundedAppend {
                commit, binding, ..
            } => binding.verify(&commit.record, identity, key, profile),
            Self::AppendCommit(_) | Self::ResolveConfirmedAndAppend { .. }
                if profile != ConfigCapacityProfile::Legacy =>
            {
                Err(PersistError::corrupt_blob())
            }
            Self::AuditedMutation(prepared) => prepared
                .effect
                .verify_capacity(identity, key, profile)
                .map(|_| ()),
            _ => Ok(()),
        }
    }

    /// Charge the actual complete encoding, excluding only the single
    /// encrypted record's byte content. No-envelope commands charge all bytes.
    /// The received proof or revision cannot select the admitted profile.
    pub(super) fn metadata_fits_profile(
        &self,
        complete_bytes: usize,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> bool {
        match profile {
            opc_crypto::ConfigCapacityProfile::Legacy => return true,
            opc_crypto::ConfigCapacityProfile::BoundedV1 => {}
            _ => return false,
        }
        let envelope_bytes = match self {
            Self::AppendCommit(commit)
            | Self::ResolveConfirmedAndAppend { commit, .. }
            | Self::BoundedAppend { commit, .. } => commit.record.encrypted_blob.len(),
            Self::AuditedMutation(prepared) => match &prepared.effect {
                super::audit_mutation::AuditedConfigEffect::Append { commit, .. }
                | super::audit_mutation::AuditedConfigEffect::BoundedAppend { commit, .. } => {
                    commit.record.encrypted_blob.len()
                }
                super::audit_mutation::AuditedConfigEffect::Confirm { .. }
                | super::audit_mutation::AuditedConfigEffect::RollbackPoint { .. } => 0,
            },
            Self::MarkConfirmed { .. }
            | Self::CreateRollbackPoint { .. }
            | Self::ClearRecoveryRequired { .. }
            | Self::RetainHistory(_)
            | Self::ManagementAudit(_) => 0,
        };
        complete_bytes
            .checked_sub(envelope_bytes)
            .is_some_and(|bytes| bytes <= CONFIG_CAPACITY_V1_METADATA_BYTES)
    }

    fn inline_rollback_label(&self) -> Result<Option<String>, PersistError> {
        match self {
            Self::AppendCommit(commit)
            | Self::ResolveConfirmedAndAppend { commit, .. }
            | Self::BoundedAppend { commit, .. } => {
                crate::types::config_rollback_label(&commit.record.principal)
            }
            Self::MarkConfirmed { .. }
            | Self::CreateRollbackPoint { .. }
            | Self::ClearRecoveryRequired { .. }
            | Self::RetainHistory(_)
            | Self::ManagementAudit(_)
            | Self::AuditedMutation(_) => Ok(None),
        }
    }
}

/// Canonical rollback label validated before it can enter a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValidatedRollbackLabel(pub(crate) String);

impl ValidatedRollbackLabel {
    pub(crate) fn try_new(value: String) -> Result<Self, PersistError> {
        crate::types::validate_rollback_label(&value)?;
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
        // Legacy intents retain their revision-1 digest across the coordinated
        // upgrade. A caller that lost the old leader's response can therefore
        // resubmit the same durable request ID through a newer binary and
        // receive the stored outcome instead of a false collision.
        let semantic_revision = self.intent.minimum_command_version();
        let mut hasher = Sha256::new();
        hasher.update(OUTCOME_DIGEST_DOMAIN);
        crate::consensus::config_capacity_json::to_writer(
            ConfigDigestWriter(&mut hasher),
            &(semantic_revision, self.identity, &self.intent),
        )
        .map_err(|_| PersistError::inconsistent_state("config consensus encoding failed"))?;
        Ok(hasher.finalize().into())
    }

    /// Chain one applied command to its predecessor and deterministic time.
    pub(crate) fn calculate_applied_digest(
        &self,
        sequence: u64,
        previous: ConfigConsensusEntryDigest,
        effective_time: Timestamp,
    ) -> Result<ConfigConsensusEntryDigest, PersistError> {
        let mut hasher = Sha256::new();
        hasher.update(COMMAND_DIGEST_DOMAIN);
        crate::consensus::config_capacity_json::to_writer(
            ConfigDigestWriter(&mut hasher),
            &(sequence, previous, effective_time, self),
        )
        .map_err(|_| PersistError::inconsistent_state("config consensus digest failed"))?;
        Ok(ConsensusEntryDigest::from_bytes(hasher.finalize().into()))
    }

    /// Validate scope, schema, and encrypted command contents.
    pub(crate) fn validate(&self, identity: ConsensusIdentity) -> Result<(), PersistError> {
        // Bound the new record's framing before the general record/AAD or
        // principal projection decoders can allocate from untrusted lengths.
        match &self.intent {
            ConfigMutationIntent::BoundedAppend {
                commit, binding, ..
            } => {
                binding.validate(&commit.record)?;
            }
            ConfigMutationIntent::AuditedMutation(prepared) => {
                if let super::audit_mutation::AuditedConfigEffect::BoundedAppend {
                    commit,
                    binding,
                    ..
                } = &prepared.effect
                {
                    binding.validate(&commit.record)?;
                }
            }
            _ => {}
        }
        let has_inline_rollback_label = self.intent.inline_rollback_label()?.is_some();
        let supported_revision = match self.schema_version {
            LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION => {
                self.intent.minimum_command_version() == LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION
                    && !has_inline_rollback_label
            }
            ATOMIC_CONFIG_CONSENSUS_COMMAND_VERSION => {
                self.intent.minimum_command_version() <= ATOMIC_CONFIG_CONSENSUS_COMMAND_VERSION
                    && !has_inline_rollback_label
            }
            3 => self.intent.minimum_command_version() <= 3,
            4 => self.intent.minimum_command_version() <= 4,
            5 => self.intent.minimum_command_version() <= 5,
            6 => self.intent.minimum_command_version() <= 6,
            CONFIG_CONSENSUS_COMMAND_VERSION => {
                self.intent.minimum_command_version() <= CONFIG_CONSENSUS_COMMAND_VERSION
            }
            8 => self.intent.minimum_command_version() <= 8,
            _ => false,
        };
        if !supported_revision || self.identity != identity {
            return Err(PersistError::inconsistent_state(
                "config consensus command scope or revision mismatch",
            ));
        }
        match &self.intent {
            ConfigMutationIntent::AppendCommit(commit) => commit.validate()?,
            ConfigMutationIntent::ResolveConfirmedAndAppend { commit, resolution } => {
                commit.validate()?;
                validate_confirmed_resolution(&commit.record, *resolution)?;
            }
            ConfigMutationIntent::BoundedAppend {
                commit, resolution, ..
            } => {
                commit.validate()?;
                if let Some(resolution) = resolution {
                    validate_confirmed_resolution(&commit.record, *resolution)?;
                }
            }
            ConfigMutationIntent::RetainHistory(retention) => retention.validate()?,
            ConfigMutationIntent::ManagementAudit(_) => {}
            ConfigMutationIntent::AuditedMutation(prepared) => {
                // The outer revision check accounts for the effect's revision.
                // Preserve the inner validation order without materializing a
                // second owned intent and copying its complete encrypted record.
                match &prepared.effect {
                    super::audit_mutation::AuditedConfigEffect::Append { commit, resolution } => {
                        crate::types::config_rollback_label(&commit.record.principal)?;
                        commit.validate()?;
                        if let Some(resolution) = resolution {
                            validate_confirmed_resolution(&commit.record, *resolution)?;
                        }
                    }
                    super::audit_mutation::AuditedConfigEffect::BoundedAppend {
                        commit,
                        resolution,
                        ..
                    } => {
                        crate::types::config_rollback_label(&commit.record.principal)?;
                        commit.validate()?;
                        if let Some(resolution) = resolution {
                            validate_confirmed_resolution(&commit.record, *resolution)?;
                        }
                    }
                    super::audit_mutation::AuditedConfigEffect::Confirm { .. } => {}
                    super::audit_mutation::AuditedConfigEffect::RollbackPoint { label, .. } => {
                        validate_rollback_point_label(label.as_ref())?;
                    }
                }
            }
            ConfigMutationIntent::ClearRecoveryRequired { .. } => {}
            ConfigMutationIntent::MarkConfirmed { .. } => {}
            ConfigMutationIntent::CreateRollbackPoint { label, .. } => {
                validate_rollback_point_label(label.as_ref())?;
            }
        }
        Ok(())
    }

    pub(super) fn validate_for_profile(
        &self,
        identity: ConfigConsensusIdentity,
        key: &crate::AuditKey,
        profile: opc_crypto::ConfigCapacityProfile,
    ) -> Result<(), PersistError> {
        match profile {
            opc_crypto::ConfigCapacityProfile::Legacy => {}
            opc_crypto::ConfigCapacityProfile::BoundedV1 => {
                // The same borrowed preflight covers local/forwarded proposals
                // and received/retained entries, before structural helpers or
                // native WAL effects. The largest leader-selected framing is
                // included even when this particular entry uses smaller IDs.
                super::store::preflight_received_config_command(self, profile)?;
            }
            _ => return Err(PersistError::corrupt_blob()),
        }
        self.validate(identity)?;
        if self.schema_version > config_command_revision(profile) {
            return Err(PersistError::corrupt_blob());
        }
        self.intent.validate_capacity(identity, key, profile)
    }
}

pub(super) fn config_command_revision(profile: opc_crypto::ConfigCapacityProfile) -> u16 {
    match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => CONFIG_CONSENSUS_COMMAND_VERSION,
        opc_crypto::ConfigCapacityProfile::BoundedV1 => 8,
        _ => 0,
    }
}

// Feed the identical canonical JSON into the digest without retaining an
// expanded JSON command allocation alongside the encrypted record.
struct ConfigDigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for ConfigDigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
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
    /// Retained canonical history has reached its admitted bound.
    HistoryFull,
    /// Pending resolution or rollback references still protect the prefix.
    HistoryProtected,
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
            Self::HistoryFull => PersistError::config_history_full(),
            Self::HistoryProtected => PersistError::config_history_protected(),
        }
    }
}

#[cfg(test)]
mod config_capacity_wire_tests;

#[cfg(test)]
mod config_capacity_command_layout_tests;

#[cfg(test)]
mod config_capacity_tokenization_tests;

#[cfg(test)]
mod config_capacity_audit_preparation_tests;

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
    /// Authenticated audit state from the same transaction, if this command
    /// concerned a retained operation. Not a second read or client assertion.
    pub(crate) audit_receipt: Option<crate::audit_authority::receipt::AuthenticatedAuditReceipt>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConfigWirePayload<T> {
    revision: u16,
    value: T,
}

pub(crate) const fn config_wire_revision(profile: opc_crypto::ConfigCapacityProfile) -> u16 {
    match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => CONFIG_CONSENSUS_WIRE_VERSION,
        opc_crypto::ConfigCapacityProfile::BoundedV1 => 8,
        _ => 0, // An unknown profile cannot silently acquire legacy admission.
    }
}

#[cfg(test)]
pub(crate) fn encode_config_wire<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, opc_consensus::ConsensusCodecError> {
    encode_config_wire_for_profile(opc_crypto::ConfigCapacityProfile::Legacy, value)
}

pub(crate) fn encode_config_wire_for_profile<T: Serialize + ?Sized>(
    profile: opc_crypto::ConfigCapacityProfile,
    value: &T,
) -> Result<Vec<u8>, opc_consensus::ConsensusCodecError> {
    #[derive(Serialize)]
    struct BorrowedConfigWirePayload<'a, T: ?Sized> {
        revision: u16,
        value: &'a T,
    }
    opc_consensus::encode_bounded(&BorrowedConfigWirePayload {
        revision: config_wire_revision(profile),
        value,
    })
}

// Validate the profile discriminator before asking the payload to deserialize.
// This keeps a mismatched peer from allocating its command or snapshot chunk
// before the immutable configuration profile has been checked.
struct CheckedConfigWire<T, const REVISION: u16>(T);

impl<'de, T: serde::Deserialize<'de>, const REVISION: u16> serde::Deserialize<'de>
    for CheckedConfigWire<T, REVISION>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<T, const REVISION: u16>(std::marker::PhantomData<T>);
        impl<'de, T: serde::Deserialize<'de>, const REVISION: u16> serde::de::Visitor<'de>
            for Visitor<T, REVISION>
        {
            type Value = CheckedConfigWire<T, REVISION>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an exact configuration wire profile")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut fields: A,
            ) -> Result<Self::Value, A::Error> {
                let revision: u16 = fields.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("missing configuration wire profile")
                })?;
                if revision != REVISION {
                    return Err(serde::de::Error::custom(
                        "configuration wire profile mismatch",
                    ));
                }
                let value = fields.next_element()?.ok_or_else(|| {
                    serde::de::Error::custom("missing configuration wire payload")
                })?;
                Ok(CheckedConfigWire(value))
            }
        }
        deserializer.deserialize_struct(
            "ConfigWirePayload",
            &["revision", "value"],
            Visitor::<T, REVISION>(std::marker::PhantomData),
        )
    }
}

#[cfg(test)]
pub(crate) fn decode_config_wire<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, opc_consensus::ConsensusCodecError> {
    decode_config_wire_for_profile(opc_crypto::ConfigCapacityProfile::Legacy, bytes)
}

pub(crate) fn decode_config_wire_for_profile<T: serde::de::DeserializeOwned>(
    profile: opc_crypto::ConfigCapacityProfile,
    bytes: &[u8],
) -> Result<T, opc_consensus::ConsensusCodecError> {
    match profile {
        opc_crypto::ConfigCapacityProfile::Legacy => opc_consensus::decode_bounded::<
            CheckedConfigWire<T, CONFIG_CONSENSUS_WIRE_VERSION>,
        >(bytes)
        .map(|payload| payload.0),
        opc_crypto::ConfigCapacityProfile::BoundedV1 => {
            opc_consensus::decode_bounded::<CheckedConfigWire<T, 8>>(bytes).map(|payload| payload.0)
        }
        _ => Err(opc_consensus::ConsensusCodecError::Decode),
    }
}

impl ConfigConsensusResponse {
    pub(crate) fn into_result(self) -> Result<(), PersistError> {
        self.result
            .map_err(ConfigMutationFailure::into_persist_error)
    }
}

/// Immutable encrypted-record fields shared by commands and borrowed SQL rows.
/// Mutable retention/rollback projections are authenticated separately. A view
/// carries no attestation or mutation authority by itself.
#[derive(Clone, Copy)]
pub(super) struct ConfigRecordView<'a> {
    pub(super) tx_id: TxId,
    pub(super) parent_tx_id: Option<TxId>,
    pub(super) version: opc_types::ConfigVersion,
    pub(super) committed_at: Timestamp,
    pub(super) principal: &'a str,
    pub(super) schema_digest: opc_types::SchemaDigest,
    pub(super) plaintext_digest: &'a [u8],
    pub(super) encrypted_blob: &'a [u8],
}

impl<'a> From<&'a CommitRecord> for ConfigRecordView<'a> {
    fn from(record: &'a CommitRecord) -> Self {
        Self {
            tx_id: record.tx_id,
            parent_tx_id: record.parent_tx_id,
            version: record.version,
            committed_at: record.committed_at,
            principal: &record.principal,
            schema_digest: record.schema_digest,
            plaintext_digest: &record.plaintext_digest,
            encrypted_blob: &record.encrypted_blob,
        }
    }
}

/// Validate that the config payload is a structurally valid AEAD envelope.
pub(crate) fn validate_encrypted_record(record: &CommitRecord) -> Result<(), PersistError> {
    validate_encrypted_record_view(ConfigRecordView::from(record))
}

/// Validate while ciphertext remains borrowed from the same immutable command
/// or SQL row that consumes the result. No borrowed data escapes this call.
pub(super) fn validate_encrypted_record_view(
    record: ConfigRecordView<'_>,
) -> Result<(), PersistError> {
    if record.plaintext_digest.len() != 32 || record.encrypted_blob.is_empty() {
        return Err(PersistError::corrupt_blob());
    }
    let envelope = CryptoEnvelopeRef::decode(record.encrypted_blob)
        .map_err(|_| PersistError::corrupt_blob())?;
    if envelope.nonce.len() != envelope.algorithm.nonce_len()
        || envelope.aad.is_empty()
        || envelope.ciphertext_and_tag.len() < opc_key::AEAD_TAG_LEN
    {
        return Err(PersistError::corrupt_blob());
    }
    let (aad, bound_key_id) =
        opc_key::decode_bound_aad(envelope.aad).map_err(|_| PersistError::corrupt_blob())?;
    let opc_key::EnvelopeMetadata::Config(metadata) = aad.metadata() else {
        return Err(PersistError::corrupt_blob());
    };
    #[cfg(test)]
    config_capacity_aad_working_tests::observe_decoded_principal(metadata.principal().len());
    #[cfg(test)]
    let _decoded_owners = super::config_capacity_simultaneous_working_tests::decoded_owners(
        &aad,
        &envelope.key_id,
        &bound_key_id,
    );
    if bound_key_id != envelope.key_id
        || aad.purpose() != opc_key::KeyPurpose::Config
        || aad.version() != record.version.get()
        || aad.tenant().as_str() != extract_tenant(record.principal)
        || metadata.tx_id() != &record.tx_id
        || metadata.parent_tx_id() != record.parent_tx_id.as_ref()
        || metadata.committed_at() != &record.committed_at
        || !crate::types::config_principal_matches_aad(record.principal, metadata.principal())
        || metadata.schema_digest() != &record.schema_digest
    {
        return Err(PersistError::corrupt_blob());
    }
    Ok(())
}

fn validate_record_representability(record: &CommitRecord) -> Result<(), PersistError> {
    validate_record_metadata_view(ConfigRecordView::from(record))?;
    validate_encrypted_record(record)
}

pub(super) fn validate_record_metadata_view(
    record: ConfigRecordView<'_>,
) -> Result<(), PersistError> {
    if record.version.get() > i64::MAX as u64
        || record.principal.is_empty()
        || record.principal.len() > CONFIG_PRINCIPAL_MAX_BYTES
        || record.principal.chars().any(char::is_control)
        || !crate::types::config_principal_metadata_is_valid(record.principal)
    {
        return Err(PersistError::constraint_violation(
            "config record is not representable by durable storage",
        ));
    }
    Ok(())
}

pub(crate) fn tokenize_audit_path(
    path: &str,
    audit_key: &crate::types::AuditKey,
) -> Result<String, PersistError> {
    validate_audit_path_input(path)?;
    #[cfg(test)]
    config_capacity_tokenization_tests::observe_capacity(0);
    // Count the exact emitted bytes with the same immutable input and emitter.
    // Reject expansion before allocating its output, then reserve only its exact
    // successful length. Ordinary String growth can otherwise exceed the field
    // limit even for an accepted final path.
    let mut counted = AuditPathByteCount(0);
    write_tokenized_audit_path(path, audit_key, &mut counted)?;
    let mut output = String::new();
    output
        .try_reserve_exact(counted.0)
        .map_err(|_| PersistError::unavailable())?;
    write_tokenized_audit_path(path, audit_key, &mut output)?;
    #[cfg(test)]
    config_capacity_tokenization_tests::observe_capacity(output.capacity());
    if output.len() > CONFIG_AUDIT_PATH_MAX_BYTES {
        return Err(tokenized_path_too_large());
    }
    Ok(output)
}

fn validate_audit_path_input(path: &str) -> Result<(), PersistError> {
    if path.is_empty()
        || path.len() > CONFIG_AUDIT_PATH_MAX_BYTES
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return Err(PersistError::constraint_violation(
            "audit YANG path is not canonically representable",
        ));
    }
    Ok(())
}

struct AuditPathByteCount(usize);

impl std::fmt::Write for AuditPathByteCount {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0 = self
            .0
            .checked_add(value.len())
            .filter(|bytes| *bytes <= CONFIG_AUDIT_PATH_MAX_BYTES)
            .ok_or(std::fmt::Error)?;
        Ok(())
    }
}

fn tokenized_path_too_large() -> PersistError {
    PersistError::constraint_violation("tokenized audit YANG path exceeds durable limit")
}

fn write_tokenized_audit_path(
    path: &str,
    audit_key: &crate::types::AuditKey,
    output: &mut impl std::fmt::Write,
) -> Result<(), PersistError> {
    let mut remainder = path;
    while let Some(open) = remainder.find('[') {
        output
            .write_str(&remainder[..open + 1])
            .map_err(|_| tokenized_path_too_large())?;
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
            .map_err(|_| tokenized_path_too_large())?;
        for byte in token {
            write!(output, "{byte:02x}").map_err(|_| tokenized_path_too_large())?;
        }
        output
            .write_str("']")
            .map_err(|_| tokenized_path_too_large())?;
        remainder = &remainder[close + 1..];
    }
    if remainder.contains(']') {
        return Err(PersistError::constraint_violation(
            "audit YANG predicate is malformed",
        ));
    }
    output
        .write_str(remainder)
        .map_err(|_| tokenized_path_too_large())?;
    Ok(())
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
    use std::str::FromStr;

    #[derive(Serialize)]
    enum LegacyConfigMutationIntent<'a> {
        AppendCommit(&'a PreparedConfigCommit),
        MarkConfirmed {
            tx_id: TxId,
        },
        CreateRollbackPoint {
            tx_id: TxId,
            label: Option<&'a ValidatedRollbackLabel>,
        },
    }

    #[derive(Serialize)]
    struct LegacyConfigConsensusCommand<'a> {
        schema_version: u16,
        identity: ConfigConsensusIdentity,
        request_id: ConfigConsensusRequestId,
        logical_time: Timestamp,
        intent: LegacyConfigMutationIntent<'a>,
    }

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
        assert!(ValidatedRollbackLabel::try_new(
            "x".repeat(crate::CONFIG_ROLLBACK_LABEL_MAX_BYTES)
        )
        .is_ok());
        assert!(ValidatedRollbackLabel::try_new(
            "x".repeat(crate::CONFIG_ROLLBACK_LABEL_MAX_BYTES + 1)
        )
        .is_err());
    }

    #[test]
    fn config_wire_revision_is_independent_and_exact() {
        assert_eq!(7, CONFIG_CONSENSUS_WIRE_VERSION);
        let current = encode_config_wire(&7_u64).expect("current wire");
        assert_eq!(
            7,
            decode_config_wire::<u64>(&current).expect("current reader")
        );
        let legacy = opc_consensus::encode_bounded(&ConfigWirePayload {
            revision: CONFIG_CONSENSUS_WIRE_VERSION - 1,
            value: 7_u64,
        })
        .expect("legacy fixture");
        assert!(decode_config_wire::<u64>(&legacy).is_err());
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
        // Revision 8 is understood structurally for the closed bounded profile,
        // but the same command remains inadmissible to a legacy authority.
        assert!(future_command
            .validate_for_profile(
                identity,
                &crate::AuditKey::new([0xA6; 32]).expect("synthetic key"),
                opc_crypto::ConfigCapacityProfile::Legacy,
            )
            .is_err());
        let unsupported_command = ConfigConsensusCommand {
            schema_version: config_command_revision(opc_crypto::ConfigCapacityProfile::BoundedV1)
                + 1,
            ..future_command
        };
        assert!(unsupported_command.validate(identity).is_err());
    }

    #[test]
    fn history_retention_rejects_downgrade_and_invalid_received_bounds() {
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-history-revision-test").expect("cluster"),
            ConfigConsensusConfigurationId::from_bytes([0xC3; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        );
        let retention = crate::ConfigHistoryRetention::new(
            TxId::new(),
            opc_types::ConfigVersion::new(6),
            opc_types::ConfigVersion::new(3),
            opc_types::ConfigVersion::new(4),
            crate::ConfigHistoryLimits::new(4, 1_048_576).expect("limits"),
        )
        .expect("retention decision");
        let mut command = ConfigConsensusCommand {
            schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
            identity,
            request_id: ConfigConsensusRequestId::from_bytes([0xC4; 16]),
            logical_time: Timestamp::now_utc(),
            intent: ConfigMutationIntent::RetainHistory(retention.clone()),
        };
        assert!(command.validate(identity).is_ok());
        for schema_version in 1..4 {
            command.schema_version = schema_version;
            assert!(command.validate(identity).is_err());
        }
        command.schema_version = 4;
        assert!(command.validate(identity).is_ok());
        let original_digest = command.payload_digest().expect("revision-four digest");
        command.schema_version = CONFIG_CONSENSUS_COMMAND_VERSION;
        assert_eq!(
            original_digest,
            command.payload_digest().expect("current digest")
        );
        let original = serde_json::to_value(retention).expect("received decision");
        for limits in [
            serde_json::json!({"max_records": 1, "max_bytes": 1_048_576}),
            serde_json::json!({"max_records": 4, "max_bytes": 0}),
            serde_json::json!({"max_records": 1_000_001, "max_bytes": 1_048_576}),
            serde_json::json!({"max_records": 4, "max_bytes": 1_073_741_825}),
        ] {
            let mut received = original.clone();
            received["limits"] = limits;
            // Deserialization cannot bypass constructor-level admission.
            command.intent = ConfigMutationIntent::RetainHistory(
                serde_json::from_value(received).expect("typed received command"),
            );
            assert!(command.validate(identity).is_err());
        }
        let mut unknown = original;
        unknown["implicit_acknowledgement"] = serde_json::json!(true);
        assert!(serde_json::from_value::<crate::ConfigHistoryRetention>(unknown).is_err());
    }

    #[test]
    fn management_audit_requires_revision_five_without_reinterpreting_old_commands() {
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("management-audit-revision-test").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0xC5; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let mut command = ConfigConsensusCommand {
            schema_version: 5,
            identity,
            request_id: ConfigConsensusRequestId::from_bytes([0xC6; 16]),
            logical_time: Timestamp::now_utc(),
            intent: ConfigMutationIntent::ManagementAudit(Box::new(
                super::super::audit::AuditCommand::Initialize {
                    projection: crate::audit_authority::AuditToken::from_keyed_projection(
                        [0xC7; 32],
                    )
                    .unwrap(),
                    limits: crate::audit_authority::AuditLedgerLimits::new(3, 1).unwrap(),
                },
            )),
        };
        assert!(command.validate(identity).is_ok());
        for revision in 1..5 {
            command.schema_version = revision;
            assert!(command.validate(identity).is_err());
        }
        command.intent = ConfigMutationIntent::ManagementAudit(Box::new(
            super::super::audit::AuditCommand::InitializeWithContinuity {
                projection: crate::audit_authority::AuditToken::from_keyed_projection([0xC7; 32])
                    .unwrap(),
                limits: crate::audit_authority::AuditLedgerLimits::new(3, 1).unwrap(),
                initial_epoch: 1,
            },
        ));
        for revision in 1..6 {
            command.schema_version = revision;
            assert!(command.validate(identity).is_err());
        }
        command.schema_version = 6;
        assert!(command.validate(identity).is_ok());
        let keys = crate::audit_authority::continuity::AuditKeyRing::new(vec![
            crate::audit_authority::continuity::AuditSigningKey::new(1, [0x93; 32]).unwrap(),
        ])
        .unwrap();
        let checkpoint = crate::audit_authority::continuity::AuditCheckpoint::issue(
            &keys,
            crate::audit_authority::continuity::checkpoint::CheckpointBody {
                version: 1,
                identity,
                sequence: 0,
                root_anchor: [0; 32],
                anchor: [0; 32],
                epoch_at_sequence: 1,
                signing_epoch: 1,
                acknowledged_export: [0x94; 32],
            },
        )
        .unwrap();
        command.intent = ConfigMutationIntent::ManagementAudit(Box::new(
            super::super::audit::AuditCommand::AcknowledgeExport(checkpoint),
        ));
        for revision in 1..7 {
            command.schema_version = revision;
            assert!(command.validate(identity).is_err());
        }
        command.schema_version = 7;
        assert!(command.validate(identity).is_ok());
    }

    #[test]
    fn older_persisted_commands_decode_but_cannot_claim_newer_intents() {
        assert_eq!(7, CONFIG_CONSENSUS_COMMAND_VERSION);
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-command-v1-replay-test").expect("cluster"),
            ConfigConsensusConfigurationId::from_bytes([0xB1; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        );
        let request_id = ConfigConsensusRequestId::from_bytes([0xB2; 16]);
        let tx_id = TxId::new();
        let encoded = serde_json::to_vec(&LegacyConfigConsensusCommand {
            schema_version: LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION,
            identity,
            request_id,
            logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").expect("fixed timestamp"),
            intent: LegacyConfigMutationIntent::MarkConfirmed { tx_id },
        })
        .expect("persisted revision-one command fixture");
        let replayed: ConfigConsensusCommand =
            serde_json::from_slice(&encoded).expect("current reader decodes revision-one command");
        assert!(replayed.validate(identity).is_ok());
        let mut current_retry = replayed.clone();
        current_retry.schema_version = CONFIG_CONSENSUS_COMMAND_VERSION;
        assert!(current_retry.validate(identity).is_ok());
        assert_eq!(
            replayed.payload_digest().expect("revision-one digest"),
            current_retry
                .payload_digest()
                .expect("current retry digest")
        );

        let legacy_clear = ConfigConsensusCommand {
            schema_version: LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION,
            identity,
            request_id: ConfigConsensusRequestId::from_bytes([0xB3; 16]),
            logical_time: Timestamp::now_utc(),
            intent: ConfigMutationIntent::ClearRecoveryRequired { tx_id },
        };
        assert_eq!(
            ATOMIC_CONFIG_CONSENSUS_COMMAND_VERSION,
            legacy_clear.intent.minimum_command_version()
        );
        assert!(legacy_clear.validate(identity).is_err());

        let pending_tx_id = TxId::new();
        let successor = PreparedConfigCommit {
            record: CommitRecord {
                tx_id: TxId::new(),
                parent_tx_id: Some(pending_tx_id),
                version: opc_types::ConfigVersion::new(2),
                committed_at: Timestamp::from_str("2026-01-01T00:00:01Z").expect("fixed timestamp"),
                principal: "spiffe://test.invalid/tenant/test/config".to_owned(),
                source: crate::types::CommitSource::CommitConfirmedRestore,
                schema_digest: opc_types::SchemaDigest::from_bytes([0xB4; 32]),
                plaintext_digest: vec![0xB5; 32],
                encrypted_blob: vec![0xB6; 32],
                rollback_point: false,
                confirmed_deadline: None,
            },
            audit: Vec::new(),
        };
        let legacy_resolution = ConfigConsensusCommand {
            schema_version: LEGACY_CONFIG_CONSENSUS_COMMAND_VERSION,
            identity,
            request_id: ConfigConsensusRequestId::from_bytes([0xB7; 16]),
            logical_time: Timestamp::now_utc(),
            intent: ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: Box::new(successor),
                resolution: ConfirmedCommitResolution::Confirm { pending_tx_id },
            },
        };
        assert_eq!(
            ATOMIC_CONFIG_CONSENSUS_COMMAND_VERSION,
            legacy_resolution.intent.minimum_command_version()
        );
        assert!(legacy_resolution.validate(identity).is_err());
    }

    #[test]
    fn revision_one_intents_retain_their_pre_resolution_wire_shapes() {
        let prepared = PreparedConfigCommit {
            record: CommitRecord {
                tx_id: TxId::new(),
                parent_tx_id: None,
                version: opc_types::ConfigVersion::new(1),
                committed_at: Timestamp::from_str("2026-01-01T00:00:00Z").expect("fixed timestamp"),
                principal: "spiffe://test.invalid/tenant/test/config".to_owned(),
                source: crate::types::CommitSource::Gnmi,
                schema_digest: opc_types::SchemaDigest::from_bytes([0xA6; 32]),
                plaintext_digest: vec![0xA7; 32],
                encrypted_blob: vec![0xA8; 32],
                rollback_point: false,
                confirmed_deadline: None,
            },
            audit: Vec::new(),
        };
        let legacy =
            opc_consensus::encode_bounded(&LegacyConfigMutationIntent::AppendCommit(&prepared))
                .expect("legacy append fixture");
        let current =
            opc_consensus::encode_bounded(&ConfigMutationIntent::AppendCommit(Box::new(prepared)))
                .expect("current append fixture");
        assert_eq!(legacy, current);

        let tx_id = TxId::new();
        let legacy =
            opc_consensus::encode_bounded(&LegacyConfigMutationIntent::MarkConfirmed { tx_id })
                .expect("legacy confirmation fixture");
        let current = opc_consensus::encode_bounded(&ConfigMutationIntent::MarkConfirmed { tx_id })
            .expect("current confirmation fixture");
        assert_eq!(legacy, current);

        let label = ValidatedRollbackLabel::try_new("release-candidate".to_owned())
            .expect("rollback label");
        let legacy =
            opc_consensus::encode_bounded(&LegacyConfigMutationIntent::CreateRollbackPoint {
                tx_id,
                label: Some(&label),
            })
            .expect("legacy rollback-point fixture");
        let current = opc_consensus::encode_bounded(&ConfigMutationIntent::CreateRollbackPoint {
            tx_id,
            label: Some(label),
        })
        .expect("current rollback-point fixture");
        assert_eq!(legacy, current);
    }
}

#[cfg(test)]
mod config_capacity_input_capacity_tests;

#[cfg(test)]
mod config_capacity_aad_working_tests;
