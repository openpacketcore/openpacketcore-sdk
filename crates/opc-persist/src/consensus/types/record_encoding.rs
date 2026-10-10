//! Preserve the existing record bytes while borrowing the encrypted byte slice.

use crate::CommitRecord;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

/// Preserve the reserved enum index without enabling its unqualified reader.
pub(in crate::consensus) fn reject_reserved_commit<'de, D: serde::Deserializer<'de>>(
    _deserializer: D,
) -> Result<Box<super::PreparedConfigCommit>, D::Error> {
    Err(serde::de::Error::custom(
        "unknown variant `BoundedAppend` in the active configuration profile",
    ))
}

struct Bytes<'a>(&'a [u8]);
impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

fn serialize<S: Serializer>(record: &CommitRecord, serializer: S) -> Result<S::Ok, S::Error> {
    // Exhaustive destructuring makes a newly added field an explicit encoding
    // decision. Names/order match CommitRecord's original derived serializer.
    let CommitRecord {
        tx_id,
        parent_tx_id,
        version,
        committed_at,
        principal,
        source,
        schema_digest,
        plaintext_digest,
        encrypted_blob,
        rollback_point,
        confirmed_deadline,
    } = record;
    let mut fields = serializer.serialize_struct("CommitRecord", 11)?;
    fields.serialize_field("tx_id", tx_id)?;
    fields.serialize_field("parent_tx_id", parent_tx_id)?;
    fields.serialize_field("version", version)?;
    fields.serialize_field("committed_at", committed_at)?;
    fields.serialize_field("principal", principal)?;
    fields.serialize_field("source", source)?;
    fields.serialize_field("schema_digest", schema_digest)?;
    fields.serialize_field("plaintext_digest", plaintext_digest)?;
    fields.serialize_field("encrypted_blob", &Bytes(encrypted_blob))?;
    fields.serialize_field("rollback_point", rollback_point)?;
    fields.serialize_field("confirmed_deadline", confirmed_deadline)?;
    fields.end()
}

pub(in crate::consensus) fn serialize_commit<S: Serializer>(
    commit: &super::PreparedConfigCommit,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    #[serde(rename = "PreparedConfigCommit")]
    struct Borrowed<'a> {
        #[serde(serialize_with = "serialize")]
        record: &'a CommitRecord,
        audit: &'a [crate::AuditRecord],
    }
    Borrowed {
        record: &commit.record,
        audit: &commit.audit,
    }
    .serialize(serializer)
}
