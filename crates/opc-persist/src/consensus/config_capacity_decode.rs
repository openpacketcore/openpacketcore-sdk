//! Bounded representation decoders, without store or wire admission.
//!
//! These private builders do not authenticate a command. No network, recovery
//! or retained-log reader calls them. Those entry points keep their legacy
//! decoders, including rejection of the reserved bounded append tags.

use std::{fmt, marker::PhantomData};

use opc_crypto::CONFIG_CAPACITY_V1_ENVELOPE_BYTES;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::audit_mutation::AuditedConfigEffect;
use super::capacity_record::CapacityRecordBinding;
use super::types::{
    ConfigMutationIntent, PreparedConfigCommit, ValidatedRollbackLabel,
    CONFIG_AUDIT_PATH_MAX_BYTES, CONFIG_CAPACITY_V1_METADATA_BYTES, CONFIG_PRINCIPAL_MAX_BYTES,
};
use super::{ConfigConsensusCommand, PreparedAuditedMutation};
use crate::{AuditRecord, CommitRecord, ConfirmedCommitResolution};

pub(super) mod engine;

fn invalid<E: de::Error>() -> E {
    E::custom("configuration representation exceeds capacity")
}

pub(super) struct Text<const MAX: usize>(pub(super) String);

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
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
                let mut owned = String::new();
                owned
                    .try_reserve_exact(value.len())
                    .map_err(|_| invalid::<E>())?;
                owned.push_str(value);
                Ok(Text(owned))
            }
        }
        input.deserialize_str(TextVisitor::<MAX>)
    }
}

pub(super) struct Bytes<const MAX: usize>(pub(super) Vec<u8>);

impl<'de, const MAX: usize> Deserialize<'de> for Bytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct ByteVisitor<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for ByteVisitor<MAX> {
            type Value = Bytes<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded numeric byte array")
            }
            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(invalid());
                }
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(value.len())
                    .map_err(|_| invalid::<E>())?;
                owned.extend_from_slice(value);
                Ok(Bytes(owned))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                if input.size_hint().is_some_and(|count| count > MAX) {
                    return Err(invalid());
                }
                let mut owned = Vec::new();
                while let Some(byte) = input.next_element::<u8>()? {
                    if owned.len() == MAX {
                        return Err(invalid());
                    }
                    if owned.len() == owned.capacity() {
                        let additional = (MAX - owned.len()).min(4096);
                        owned
                            .try_reserve_exact(additional)
                            .map_err(|_| invalid::<A::Error>())?;
                    }
                    owned.push(byte);
                }
                Ok(Bytes(owned))
            }
        }
        if input.is_human_readable() {
            input.deserialize_seq(ByteVisitor::<MAX>)
        } else {
            // Postcard first checks the borrowed extent; no declared count
            // reaches an owning allocation before the independent field bound.
            input.deserialize_bytes(ByteVisitor::<MAX>)
        }
    }
}

pub(super) struct List<T, const MAX: usize>(pub(super) Vec<T>);

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for List<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct ListVisitor<T, const MAX: usize>(PhantomData<T>, bool);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for ListVisitor<T, MAX> {
            type Value = List<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded configuration collection")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                // Postcard suppresses a declared count when it exceeds the
                // remaining bytes. Every element in this schema occupies at
                // least one byte, so that absence is a truncated binary list.
                if (self.1 && input.size_hint().is_none())
                    || input.size_hint().is_some_and(|count| count > MAX)
                {
                    return Err(invalid());
                }
                let mut owned = Vec::new();
                while owned.len() < MAX {
                    let Some(value) = input.next_element()? else {
                        return Ok(List(owned));
                    };
                    if owned.len() == owned.capacity() {
                        owned
                            .try_reserve_exact((MAX - owned.len()).min(16))
                            .map_err(|_| invalid::<A::Error>())?;
                    }
                    owned.push(value);
                }
                // Never deserialize an owning T past the count bound. This
                // seed rejects as soon as the format reports another element.
                if input.next_element_seed(RejectElement)?.is_some() {
                    return Err(invalid());
                }
                Ok(List(owned))
            }
        }
        let binary = !input.is_human_readable();
        input.deserialize_seq(ListVisitor::<T, MAX>(PhantomData, binary))
    }
}

struct RejectElement;
impl<'de> de::DeserializeSeed<'de> for RejectElement {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(invalid())
    }
}

#[derive(Deserialize)]
#[serde(rename = "CommitRecord")]
struct Record {
    tx_id: opc_types::TxId,
    parent_tx_id: Option<opc_types::TxId>,
    version: opc_types::ConfigVersion,
    committed_at: opc_types::Timestamp,
    principal: Text<CONFIG_PRINCIPAL_MAX_BYTES>,
    source: crate::types::CommitSource,
    schema_digest: opc_types::SchemaDigest,
    plaintext_digest: Bytes<32>,
    encrypted_blob: Bytes<CONFIG_CAPACITY_V1_ENVELOPE_BYTES>,
    rollback_point: bool,
    confirmed_deadline: Option<opc_types::Timestamp>,
}

impl From<Record> for CommitRecord {
    fn from(value: Record) -> Self {
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
    tx_id: opc_types::TxId,
    sequence: u32,
    yang_path: Text<CONFIG_AUDIT_PATH_MAX_BYTES>,
    op_type: crate::types::AuditOpType,
    previous_value: Option<Text<12>>,
    new_value: Option<Text<12>>,
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
            previous_value: value.previous_value.map(|v| v.0),
            new_value: value.new_value.map(|v| v.0),
            redaction_applied: value.redaction_applied,
            previous_hash: value.previous_hash,
            entry_hmac: value.entry_hmac,
        }
    }
}

struct Audit(Vec<AuditRecord>);
impl<'de> Deserialize<'de> for Audit {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        // Two fixed hashes per item already consume 64 metadata bytes. The
        // independent aggregate check prevents many individually valid fields
        // from retaining more than the command's admitted metadata budget.
        struct AuditVisitor(bool);
        impl<'de> Visitor<'de> for AuditVisitor {
            type Value = Audit;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded finalized audit metadata")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Audit, A::Error> {
                const MAX: usize = CONFIG_CAPACITY_V1_METADATA_BYTES / 64;
                if (self.0 && input.size_hint().is_none())
                    || input.size_hint().is_some_and(|count| count > MAX)
                {
                    return Err(invalid());
                }
                let mut records = Vec::new();
                let mut bytes = 0usize;
                while records.len() < MAX {
                    let Some(value) = input.next_element::<AuditFields>()? else {
                        return Ok(Audit(records));
                    };
                    let record = AuditRecord::from(value);
                    let mut count = opc_consensus::AppendEntriesBatchAccumulator::new();
                    count.consider(&record).map_err(|_| invalid::<A::Error>())?;
                    bytes = bytes
                        .checked_add(count.serialized_entry_bytes())
                        .filter(|bytes| *bytes <= CONFIG_CAPACITY_V1_METADATA_BYTES)
                        .ok_or_else(invalid::<A::Error>)?;
                    if records.len() == records.capacity() {
                        records
                            .try_reserve_exact((MAX - records.len()).min(16))
                            .map_err(|_| invalid::<A::Error>())?;
                    }
                    records.push(record);
                }
                input.next_element_seed(RejectElement)?;
                Ok(Audit(records))
            }
        }
        let binary = !input.is_human_readable();
        input.deserialize_seq(AuditVisitor(binary))
    }
}

#[derive(Deserialize)]
#[serde(rename = "PreparedConfigCommit")]
struct Prepared {
    record: Record,
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
        tx_id: opc_types::TxId,
    },
    RollbackPoint {
        tx_id: opc_types::TxId,
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
                label: label.map(|v| ValidatedRollbackLabel(v.0)),
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
struct Audited {
    handle: crate::audit_authority::AuditOperationHandle,
    effect: Effect,
}
impl From<Audited> for PreparedAuditedMutation {
    fn from(value: Audited) -> Self {
        Self {
            handle: value.handle,
            effect: value.effect.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "ConfigMutationIntent")]
enum Intent {
    AppendCommit(Box<Prepared>),
    MarkConfirmed {
        tx_id: opc_types::TxId,
    },
    CreateRollbackPoint {
        tx_id: opc_types::TxId,
        label: Option<Text<{ crate::CONFIG_ROLLBACK_LABEL_MAX_BYTES }>>,
    },
    ResolveConfirmedAndAppend {
        commit: Box<Prepared>,
        resolution: ConfirmedCommitResolution,
    },
    ClearRecoveryRequired {
        tx_id: opc_types::TxId,
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
                label: label.map(|v| ValidatedRollbackLabel(v.0)),
            },
            Intent::ResolveConfirmedAndAppend { commit, resolution } => {
                Self::ResolveConfirmedAndAppend {
                    commit: Box::new((*commit).into()),
                    resolution,
                }
            }
            Intent::ClearRecoveryRequired { tx_id } => Self::ClearRecoveryRequired { tx_id },
            Intent::RetainHistory(value) => Self::RetainHistory(value),
            Intent::ManagementAudit(value) => Self::ManagementAudit(*value),
            Intent::AuditedMutation(value) => Self::AuditedMutation((*value).into()),
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

#[derive(Deserialize)]
#[serde(rename = "ConfigConsensusCommand")]
pub(super) struct Command {
    schema_version: u16,
    identity: super::ConfigConsensusIdentity,
    request_id: super::ConfigConsensusRequestId,
    logical_time: opc_types::Timestamp,
    intent: Intent,
}
impl From<Command> for ConfigConsensusCommand {
    fn from(value: Command) -> Self {
        Self {
            schema_version: value.schema_version,
            identity: value.identity,
            request_id: value.request_id,
            logical_time: value.logical_time,
            intent: value.intent.into(),
        }
    }
}

// Bound serde_json's unescaping scratch before invoking any typed visitor.
// Six raw bytes per decoded UTF-8 byte conservatively covers Unicode escapes,
// including surrogate pairs. The real parser still owns syntax and UTF-8.
pub(super) fn json_preflight(bytes: &[u8]) -> Result<(), ()> {
    if bytes.len() > super::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
        return Err(());
    }
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
            if index - start > 6 * CONFIG_PRINCIPAL_MAX_BYTES {
                return Err(());
            }
        }
        if index >= bytes.len() {
            return Err(());
        }
        index += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
