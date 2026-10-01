//! Preserve the closed record encoding while passing the encrypted payload as
//! one borrowed byte slice. Postcard can count/copy it without a Serde call per
//! byte; serde_json retains the same array of unsigned decimal integers.

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::CommitRecord;

struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

pub(super) fn serialize<S: Serializer>(
    record: &CommitRecord,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // Exhaustive destructuring forces an explicit encoding decision when the
    // shared record gains a field. Names and order match its derived encoder;
    // compatibility tests use that original encoder as an independent oracle.
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
    let mut record = serializer.serialize_struct("CommitRecord", 11)?;
    record.serialize_field("tx_id", tx_id)?;
    record.serialize_field("parent_tx_id", parent_tx_id)?;
    record.serialize_field("version", version)?;
    record.serialize_field("committed_at", committed_at)?;
    record.serialize_field("principal", principal)?;
    record.serialize_field("source", source)?;
    record.serialize_field("schema_digest", schema_digest)?;
    record.serialize_field("plaintext_digest", plaintext_digest)?;
    record.serialize_field("encrypted_blob", &Bytes(encrypted_blob))?;
    record.serialize_field("rollback_point", rollback_point)?;
    record.serialize_field("confirmed_deadline", confirmed_deadline)?;
    record.end()
}

#[cfg(test)]
#[path = "config_capacity_record_encoding_tests.rs"]
mod tests;
