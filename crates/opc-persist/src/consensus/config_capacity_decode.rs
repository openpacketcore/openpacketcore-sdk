//! Allocation limits for the closed bounded-profile mutation schema.
//!
//! These builders are deliberately separate from legacy serde decoding. No
//! attacker-controlled size hint reaches an unchecked collection. The only
//! variable owners are the record strings/bytes, audit vector/strings and
//! rollback label; all other mutation fields are fixed-size closed types.
//! Reservations must already be held by callers. This bounds decoded buffers,
//! not transport ownership, validation scratch or a complete operation peak.

use std::fmt;

use opc_crypto::{ConfigCapacityProfile, CONFIG_CAPACITY_V1_ENVELOPE_BYTES};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::audit_mutation::{AuditedConfigEffect, PreparedAuditedMutation};
use super::capacity_record::CapacityRecordBinding;
use super::types::{
    ConfigMutationIntent, PreparedConfigCommit, ValidatedRollbackLabel,
    CONFIG_AUDIT_PATH_MAX_BYTES, CONFIG_CAPACITY_V1_METADATA_BYTES, CONFIG_PRINCIPAL_MAX_BYTES,
};
use crate::audit_authority::{AuditAuthorityError, AuditOperationHandle};
use crate::{AuditRecord, CommitRecord, ConfirmedCommitResolution};

// Every finalized audit record necessarily contains two 32-byte hashes in the
// command metadata. This loose count ceiling cannot reject a command admitted
// by the existing aggregate metadata limit, and does not depend on Vec growth.
const AUDIT_ITEMS: usize = CONFIG_CAPACITY_V1_METADATA_BYTES / 64;
const REDACTED_VALUE_BYTES: usize = b"\"<redacted>\"".len();
const JSON_STRING_BYTES: usize = 6 * CONFIG_PRINCIPAL_MAX_BYTES;

fn invalid<E: de::Error>() -> E {
    E::custom("configuration decoding exceeds admitted capacity")
}

pub(super) struct Text<const MAX: usize>(String);

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for TextVisitor<MAX> {
            type Value = Text<MAX>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded configuration text")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(invalid());
                }
                let mut text = String::new();
                text.try_reserve_exact(value.len())
                    .map_err(|_| invalid::<E>())?;
                text.push_str(value);
                Ok(Text(text))
            }
        }
        deserializer.deserialize_str(TextVisitor::<MAX>)
    }
}

// A binary count is checked against the schema limit before this helper.
// For a stream without a count, live capacity is at most one quantum beyond
// its initialized length and never above that limit. Reallocation can retain
// old and new backing stores at once; resource accounting must charge both.
// These are decoder buffers, not a complete operation or engine queue bound.
fn reserve_next<T, E: de::Error>(
    values: &mut Vec<T>,
    limit: usize,
    hint: Option<usize>,
    quantum: usize,
) -> Result<(), E> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    let target = hint.unwrap_or_else(|| values.len().saturating_add(quantum).min(limit));
    let additional = target
        .checked_sub(values.len())
        .filter(|additional| *additional > 0 && target <= limit)
        .ok_or_else(invalid::<E>)?;
    values.try_reserve_exact(additional).map_err(|_| invalid())
}

struct Bytes<const MAX: usize>(Vec<u8>);

impl<'de, const MAX: usize> Deserialize<'de> for Bytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for BytesVisitor<MAX> {
            type Value = Bytes<MAX>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded configuration byte array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let hint = input.size_hint();
                let extent = hint.unwrap_or(MAX);
                if extent > MAX {
                    return Err(invalid());
                }
                let mut bytes = Vec::new();
                while let Some(byte) = input.next_element::<u8>()? {
                    if bytes.len() == extent {
                        return Err(invalid());
                    }
                    // Postcard supplies its exact admitted count. JSON has
                    // no hint, so reserve bounded increments rather than the
                    // maximum envelope for every small retained record.
                    reserve_next::<_, A::Error>(&mut bytes, extent, hint, 4 * 1024)?;
                    bytes.push(byte);
                }
                Ok(Bytes(bytes))
            }
        }
        deserializer.deserialize_seq(BytesVisitor::<MAX>)
    }
}

#[derive(Deserialize)]
#[serde(rename = "CommitRecord")]
struct RecordFields {
    tx_id: TxId,
    parent_tx_id: Option<TxId>,
    version: ConfigVersion,
    committed_at: Timestamp,
    principal: Text<CONFIG_PRINCIPAL_MAX_BYTES>,
    source: crate::types::CommitSource,
    schema_digest: SchemaDigest,
    plaintext_digest: Bytes<32>,
    encrypted_blob: Bytes<CONFIG_CAPACITY_V1_ENVELOPE_BYTES>,
    rollback_point: bool,
    confirmed_deadline: Option<Timestamp>,
}

impl From<RecordFields> for CommitRecord {
    fn from(value: RecordFields) -> Self {
        Self {
            tx_id: value.tx_id,
            parent_tx_id: value.parent_tx_id,
            version: value.version,
            committed_at: value.committed_at,
            principal: value.principal.0,
            source: value.source,
            schema_digest: value.schema_digest,
            plaintext_digest: value.plaintext_digest.0,
            encrypted_blob: value.encrypted_blob.0,
            rollback_point: value.rollback_point,
            confirmed_deadline: value.confirmed_deadline,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "AuditRecord")]
struct AuditFields {
    tx_id: TxId,
    sequence: u32,
    yang_path: Text<CONFIG_AUDIT_PATH_MAX_BYTES>,
    op_type: crate::types::AuditOpType,
    previous_value: Option<Text<REDACTED_VALUE_BYTES>>,
    new_value: Option<Text<REDACTED_VALUE_BYTES>>,
    redaction_applied: bool,
    previous_hash: [u8; 32],
    entry_hmac: [u8; 32],
}

impl From<AuditFields> for AuditRecord {
    fn from(value: AuditFields) -> Self {
        Self {
            tx_id: value.tx_id,
            sequence: value.sequence,
            yang_path: value.yang_path.0,
            op_type: value.op_type,
            previous_value: value.previous_value.map(|value| value.0),
            new_value: value.new_value.map(|value| value.0),
            redaction_applied: value.redaction_applied,
            previous_hash: value.previous_hash,
            entry_hmac: value.entry_hmac,
        }
    }
}

struct Audit(Vec<AuditRecord>);

impl<'de> Deserialize<'de> for Audit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AuditVisitor;
        impl<'de> Visitor<'de> for AuditVisitor {
            type Value = Audit;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded finalized configuration audit")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Audit, A::Error> {
                let hint = input.size_hint();
                let extent = hint.unwrap_or(AUDIT_ITEMS);
                if extent > AUDIT_ITEMS {
                    return Err(invalid());
                }
                let mut audit = Vec::new();
                let mut encoded_bytes = 0usize;
                while let Some(fields) = input.next_element::<AuditFields>()? {
                    if audit.len() == extent {
                        return Err(invalid());
                    }
                    let record = AuditRecord::from(fields);
                    // A fresh sizing accumulator for each record avoids its
                    // unrelated 64-entry replication batching stop rule.
                    let mut encoded = opc_consensus::AppendEntriesBatchAccumulator::new();
                    encoded
                        .consider(&record)
                        .map_err(|_| invalid::<A::Error>())?;
                    encoded_bytes = encoded_bytes
                        .checked_add(encoded.serialized_entry_bytes())
                        .filter(|bytes| *bytes <= CONFIG_CAPACITY_V1_METADATA_BYTES)
                        .ok_or_else(invalid::<A::Error>)?;
                    reserve_next::<_, A::Error>(&mut audit, extent, hint, 16)?;
                    audit.push(record);
                }
                Ok(Audit(audit))
            }
        }
        deserializer.deserialize_seq(AuditVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename = "PreparedConfigCommit")]
pub(super) struct Prepared {
    record: RecordFields,
    audit: Audit,
}

impl From<Prepared> for PreparedConfigCommit {
    fn from(value: Prepared) -> Self {
        Self {
            record: value.record.into(),
            audit: value.audit.0,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "AuditedConfigEffect")]
enum Effect {
    Append {
        commit: Box<Prepared>,
        resolution: Option<ConfirmedCommitResolution>,
    },
    Confirm {
        tx_id: TxId,
    },
    RollbackPoint {
        tx_id: TxId,
        label: Option<Text<{ crate::CONFIG_ROLLBACK_LABEL_MAX_BYTES }>>,
    },
    BoundedAppend {
        commit: Box<Prepared>,
        binding: CapacityRecordBinding,
        resolution: Option<ConfirmedCommitResolution>,
    },
}

impl From<Effect> for AuditedConfigEffect {
    fn from(value: Effect) -> Self {
        match value {
            Effect::Append { commit, resolution } => Self::Append {
                commit: Box::new((*commit).into()),
                resolution,
            },
            Effect::Confirm { tx_id } => Self::Confirm { tx_id },
            Effect::RollbackPoint { tx_id, label } => Self::RollbackPoint {
                tx_id,
                label: label.map(|value| ValidatedRollbackLabel(value.0)),
            },
            Effect::BoundedAppend {
                commit,
                binding,
                resolution,
            } => Self::BoundedAppend {
                commit: Box::new((*commit).into()),
                binding,
                resolution,
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "PreparedAuditedMutation", deny_unknown_fields)]
pub(super) struct Audited {
    handle: AuditOperationHandle,
    effect: Effect,
}

impl From<Audited> for PreparedAuditedMutation {
    fn from(value: Audited) -> Self {
        Self::new(value.handle, value.effect.into(), None)
    }
}

// Variant order and field order exactly mirror the canonical schema. Fixed
// audit/retention types contain no caller-controlled strings or collections.
#[derive(Deserialize)]
#[serde(rename = "ConfigMutationIntent")]
pub(super) enum Intent {
    AppendCommit(Box<Prepared>),
    MarkConfirmed {
        tx_id: TxId,
    },
    CreateRollbackPoint {
        tx_id: TxId,
        label: Option<Text<{ crate::CONFIG_ROLLBACK_LABEL_MAX_BYTES }>>,
    },
    ResolveConfirmedAndAppend {
        commit: Box<Prepared>,
        resolution: ConfirmedCommitResolution,
    },
    ClearRecoveryRequired {
        tx_id: TxId,
    },
    RetainHistory(super::ConfigHistoryRetention),
    ManagementAudit(Box<super::audit::AuditCommand>),
    AuditedMutation(Box<Audited>),
    BoundedAppend {
        commit: Box<Prepared>,
        binding: CapacityRecordBinding,
        resolution: Option<ConfirmedCommitResolution>,
    },
}

impl From<Intent> for ConfigMutationIntent {
    fn from(value: Intent) -> Self {
        match value {
            Intent::AppendCommit(commit) => Self::AppendCommit(Box::new((*commit).into())),
            Intent::MarkConfirmed { tx_id } => Self::MarkConfirmed { tx_id },
            Intent::CreateRollbackPoint { tx_id, label } => Self::CreateRollbackPoint {
                tx_id,
                label: label.map(|value| ValidatedRollbackLabel(value.0)),
            },
            Intent::ResolveConfirmedAndAppend { commit, resolution } => {
                Self::ResolveConfirmedAndAppend {
                    commit: Box::new((*commit).into()),
                    resolution,
                }
            }
            Intent::ClearRecoveryRequired { tx_id } => Self::ClearRecoveryRequired { tx_id },
            Intent::RetainHistory(value) => Self::RetainHistory(value),
            Intent::ManagementAudit(value) => Self::ManagementAudit(value),
            Intent::AuditedMutation(value) => {
                let prepared = PreparedAuditedMutation::from(*value);
                Self::AuditedMutation(prepared.command().clone())
            }
            Intent::BoundedAppend {
                commit,
                binding,
                resolution,
            } => Self::BoundedAppend {
                commit: Box::new((*commit).into()),
                binding,
                resolution,
            },
        }
    }
}

// serde_json may fill string scratch before invoking a typed visitor. Bound
// each raw string's encoded extent in a nonallocating scan first. Six bytes
// per Unicode escape covers every valid representation of the largest field;
// the real parser still checks escapes, UTF-8, syntax, depth and trailing data.
fn json_string_preflight(bytes: &[u8]) -> Result<(), AuditAuthorityError> {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index] != b'"' {
            if bytes[index] == b'\\' {
                index += 1;
            }
            index += 1;
            if index - start > JSON_STRING_BYTES {
                return Err(AuditAuthorityError::InvalidInput);
            }
        }
        if index >= bytes.len() {
            return Err(AuditAuthorityError::InvalidInput);
        }
        index += 1;
    }
    Ok(())
}

pub(super) fn recovery(
    bytes: &[u8],
    profile: ConfigCapacityProfile,
) -> Result<PreparedAuditedMutation, AuditAuthorityError> {
    match profile {
        ConfigCapacityProfile::Legacy => PreparedAuditedMutation::decode(bytes),
        ConfigCapacityProfile::BoundedV1 => {
            if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
                return Err(AuditAuthorityError::InvalidInput);
            }
            json_string_preflight(bytes)?;
            serde_json::from_slice::<Audited>(bytes)
                .map(Into::into)
                .map_err(|_| AuditAuthorityError::InvalidInput)
        }
        _ => Err(AuditAuthorityError::InvalidInput),
    }
}

#[cfg(test)]
#[path = "config_capacity_decode_tests.rs"]
mod tests;

pub(super) mod engine;

#[cfg(test)]
#[path = "config_capacity_decode_allocation_tests.rs"]
mod allocation_tests;
