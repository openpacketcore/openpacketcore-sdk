//! Resident metadata for selected, file-backed rows. Constructors are private
//! to native admission/relocation. Deserialization can only produce resident
//! values; a persisted digest cannot manufacture a cold row or its source.

use super::*;
use serde::ser::{SerializeStruct, Serializer};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

/// A range can be constructed only after complete generation admission or
/// exact expected readback. It pins the immutable selected prefix, never a
/// pathname. The input reservation remains attached until all bytes drop.
#[derive(Clone)]
pub(super) struct SelectedRange {
    source: Arc<prefix::VerifiedPrefix>,
    offset: u64,
    length: u32,
}

pub(super) struct SelectedBytes {
    bytes: Vec<u8>,
    _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl SelectedBytes {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SelectedRange {
    pub(super) fn new(
        source: Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
        maximum: usize,
    ) -> io::Result<Self> {
        if length == 0
            || length as usize > maximum
            || offset
                .checked_add(u64::from(length))
                .is_none_or(|end| end > source.identity().length)
        {
            return Err(invalid("native selected row extent invalid"));
        }
        Ok(Self {
            source,
            offset,
            length,
        })
    }

    pub(super) fn read(&self, check: &impl Fn() -> io::Result<()>) -> io::Result<SelectedBytes> {
        check()?;
        let memory =
            crate::consensus::verified_snapshot::VerificationMemory::reserve(self.length as usize)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.length as usize)
            .map_err(|_| invalid("native selected row input allocation failed"))?;
        bytes.resize(self.length as usize, 0);
        self.source.read_exact_at(self.offset, &mut bytes)?;
        check()?;
        Ok(SelectedBytes {
            bytes,
            _memory: memory,
        })
    }
}

pub(super) enum RowBytes<'a> {
    Resident(&'a [u8]),
    Selected(SelectedBytes),
}

impl RowBytes<'_> {
    pub(super) fn bytes(&self) -> &[u8] {
        match self {
            Self::Resident(bytes) => bytes,
            Self::Selected(bytes) => bytes.bytes(),
        }
    }
}

pub(super) fn authority_binding(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<[u8; 32]> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"OPC-native-resident-authority-v1\0");
    serde_json::to_writer(&mut writer, &(identity, members))
        .map_err(|_| invalid("native resident authority cannot encode"))?;
    Ok(writer.0.finalize().into())
}

#[derive(Clone)]
pub(super) struct ColdReceipt {
    source: Arc<prefix::VerifiedPrefix>,
    range: cold::ReceiptRange,
    // Bind every resident scalar and complete external key to the admitted
    // content. A cloned row with an altered scalar cannot reuse that digest.
    binding: [u8; 32],
    content: [u8; 32],
    response: generation::facts::Response,
}

struct HashWriter(Sha256);
impl io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn receipt_binding(key: &impl Serialize, row: &NativeReceipt) -> io::Result<[u8; 32]> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"OPC-native-resident-receipt-binding-v1\0");
    serde_json::to_writer(
        &mut writer,
        &(key, row.ordinal, row.payload_digest, row.retained_until),
    )
    .map_err(|_| invalid("native resident receipt binding cannot encode"))?;
    Ok(writer.0.finalize().into())
}

impl Serialize for NativeReceipt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.cold.is_some() {
            return Err(serde::ser::Error::custom(
                "native cold receipt requires an outside-owner read",
            ));
        }
        // Preserve the OPCNAT01/02 JSON/postcard field order exactly. The
        // resident/cold representation is never part of either wire format.
        let mut row = serializer.serialize_struct("NativeReceipt", 4)?;
        row.serialize_field("ordinal", &self.ordinal)?;
        row.serialize_field("payload_digest", &self.payload_digest)?;
        row.serialize_field("retained_until", &self.retained_until)?;
        row.serialize_field("response", &self.response)?;
        row.end()
    }
}

pub(super) trait RowFingerprint {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]>;
}

impl RowFingerprint for NativeKeyState {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        changes::fingerprint(table, key, self)
    }
}
impl RowFingerprint for NativeGenericReceipt {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        changes::fingerprint(table, key, self)
    }
}
impl RowFingerprint for ReplicationEntry {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        changes::fingerprint(table, key, self)
    }
}
impl RowFingerprint for NativeReceipt {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        let Some(cold) = &self.cold else {
            return changes::fingerprint(table, key, self);
        };
        if table != 1 || self.response.is_some() || receipt_binding(key, self)? != cold.binding {
            return Err(invalid("native cold receipt resident binding differs"));
        }
        Ok(cold.content)
    }
}

impl NativeReceipt {
    pub(super) fn relocation_allocation_bytes() -> usize {
        SharedRow::<Self>::relocated_allocation_bytes() + std::mem::size_of::<ColdReceipt>()
    }

    pub(super) fn retained(&self) -> bool {
        self.response.is_some() || self.cold.is_some()
    }

    pub(super) fn response_facts(&self) -> io::Result<Option<generation::facts::Response>> {
        if let Some(cold) = &self.cold {
            if self.response.is_some() {
                return Err(invalid("native receipt has two representations"));
            }
            Ok(Some(cold.response))
        } else {
            self.response
                .as_deref()
                .map(generation::facts::Response::of)
                .transpose()
        }
    }

    pub(super) fn cold_range(&self) -> Option<(Arc<prefix::VerifiedPrefix>, cold::ReceiptRange)> {
        self.cold
            .as_ref()
            .map(|cold| (Arc::clone(&cold.source), cold.range))
    }

    pub(super) fn cold_read_order(&self) -> Option<(usize, u64)> {
        self.cold
            .as_ref()
            .map(|cold| (cold.source.source_order(), cold.range.offset()))
    }

    /// Called only for a complete catalog row or an exact expected-readback
    /// relocation. The source pins the selected bytes; caller-owned keys and
    /// metadata contain no allocation borrowed from a decoder reservation.
    pub(super) fn from_admitted_range(
        id: FencedTransitionV2RequestId,
        facts: generation::facts::Row<generation::facts::Receipt>,
        source: Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
    ) -> io::Result<Self> {
        let range = cold::ReceiptRange::new(offset, length)?;
        if offset
            .checked_add(u64::from(length))
            .is_none_or(|end| end > source.identity().length)
        {
            return Err(invalid("native cold receipt exceeds selected prefix"));
        }
        let mut row = Self {
            ordinal: facts.facts.ordinal,
            payload_digest: facts.facts.payload_digest,
            retained_until: facts.facts.retained_until,
            response: None,
            cold: None,
        };
        if let Some(response) = facts.facts.response {
            row.cold = Some(Box::new(ColdReceipt {
                source,
                range,
                binding: receipt_binding(&id, &row)?,
                content: facts.content,
                response,
            }));
        } else if changes::fingerprint(1, &id, &row)? != facts.content {
            return Err(invalid("native admitted receipt tombstone differs"));
        }
        Ok(row)
    }

    pub(super) fn matches_decoded(
        &self,
        id: FencedTransitionV2RequestId,
        decoded: &Self,
    ) -> io::Result<bool> {
        if decoded.cold.is_some() {
            return Err(invalid(
                "native decoded receipt contains a cold certificate",
            ));
        }
        if self.ordinal != decoded.ordinal
            || self.payload_digest != decoded.payload_digest
            || self.retained_until != decoded.retained_until
        {
            return Ok(false);
        }
        if self.cold.is_some() {
            Ok(self.row_fingerprint(1, &id)? == changes::fingerprint(1, &id, decoded)?)
        } else {
            Ok(self.response == decoded.response)
        }
    }
}
