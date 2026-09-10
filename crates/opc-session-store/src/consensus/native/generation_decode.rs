//! Allocation preflight for arbitrary persisted generation rows. This is a
//! deliberately closed, versioned vocabulary, separate from expected readback.
//! The preflight borrows strings/payloads, visits no recursive model and creates
//! no Vec. It is not semantic admission: the original complete typed decoder,
//! canonical comparison and native predicates still run after reservation.

use super::*;
use crate::model::{
    StateClass, OWNER_ID_MAX_BYTES, SESSION_KEY_TYPE_MAX_BYTES, STABLE_ID_MAX_BYTES,
    STATE_TYPE_MAX_BYTES,
};
use crate::record::SessionPayloadEncoding;

#[path = "generation_json.rs"]
pub(super) mod json;

// The metadata in this closed shape includes the roster event's two records
// and separate current authority. Identifier constructors have their original
// 128-byte ceilings; canonical RFC3339 timestamps fit well within 64 bytes.
// This covers decoded metadata, its constructors and validation worklists.
const METADATA: usize = 64 * 1024;

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    // Only scalars, fixed arrays, borrowed slices and unit enums are passed to
    // this method. No owning/string/collection/recursive model is deserialized.
    fn scalar<T: Deserialize<'a>>(&mut self) -> io::Result<T> {
        let (value, rest) = postcard::take_from_bytes(self.rest)
            .map_err(|_| invalid("native generation borrowed row invalid"))?;
        self.rest = rest;
        Ok(value)
    }

    fn string(&mut self, maximum: usize) -> io::Result<()> {
        let value: &str = self.scalar()?;
        if value.len() > maximum {
            return Err(invalid("native generation string exceeds model bound"));
        }
        Ok(())
    }

    fn timestamp(&mut self) -> io::Result<()> {
        self.string(64)
    }

    fn key(&mut self) -> io::Result<()> {
        self.string(128)?; // TenantId
        self.string(64)?; // NfKind
        self.string(SESSION_KEY_TYPE_MAX_BYTES)?;
        let stable: &[u8] = self.scalar()?;
        if stable.len() > STABLE_ID_MAX_BYTES {
            return Err(invalid("native generation stable ID exceeds model bound"));
        }
        Ok(())
    }

    fn record(&mut self) -> io::Result<usize> {
        self.key()?;
        self.scalar::<u64>()?; // generation
        self.string(OWNER_ID_MAX_BYTES)?;
        self.scalar::<u64>()?; // fence
        self.scalar::<StateClass>()?;
        self.string(STATE_TYPE_MAX_BYTES)?;
        if self.scalar::<bool>()? {
            self.timestamp()?;
        }
        let payload: &[u8] = self.scalar()?;
        // Materialized records already have this original backend bound.
        // Raw Raft conflict bodies use their distinct 16MiB JSON row bound.
        if payload.len() > crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES {
            return Err(invalid(
                "native generation materialized payload exceeds model bound",
            ));
        }
        self.scalar::<SessionPayloadEncoding>()?;
        Ok(payload.len())
    }

    fn lease(&mut self) -> io::Result<()> {
        self.key()?;
        self.string(OWNER_ID_MAX_BYTES)?;
        self.scalar::<u64>()?;
        self.timestamp()?;
        self.timestamp()?;
        self.scalar::<u64>()?;
        Ok(())
    }

    fn lease_effect(&mut self, tag: u32) -> io::Result<()> {
        // Postcard's versioned ReplicationOp enum order is locked by the
        // independent serializer oracle tests below. Reject all other variants
        // before any recursive/full ReplicationOp deserialization can occur.
        if !matches!(tag, 3 | 4 | 5) {
            return Err(invalid("native generation lease effect shape invalid"));
        }
        self.key()?;
        self.string(OWNER_ID_MAX_BYTES)?;
        self.scalar::<u64>()?; // fence
        self.scalar::<u64>()?; // credential
        if tag != 5 {
            self.scalar::<std::time::Duration>()?;
            self.timestamp()?;
        }
        Ok(())
    }

    fn mutation_effect(&mut self, tag: u32) -> io::Result<usize> {
        match tag {
            0 => {
                self.key()?;
                self.scalar::<Option<u64>>()?;
                self.scalar::<u64>()?;
                self.timestamp()?;
                self.record()
            }
            tag @ (1 | 2) => {
                self.key()?;
                self.string(OWNER_ID_MAX_BYTES)?;
                self.scalar::<u64>()?;
                if tag == 2 {
                    self.scalar::<std::time::Duration>()?;
                    self.timestamp()?;
                }
                Ok(0)
            }
            _ => Err(invalid("native generation mutation effect shape invalid")),
        }
    }

    fn roster_effect(&mut self, tag: u32) -> io::Result<usize> {
        self.key()?;
        let mut payload = self.record()?;
        if tag == 6 {
            let successor = match self.scalar::<u32>()? {
                0 => self.record()?,
                1 | 2 => 0,
                _ => {
                    return Err(invalid(
                        "native roster notification successor shape invalid",
                    ))
                }
            };
            payload = payload
                .checked_add(successor)
                .ok_or_else(|| invalid("native roster notification payload overflow"))?;
        } else if tag != 8 {
            return Err(invalid("native roster notification effect shape invalid"));
        }
        self.string(OWNER_ID_MAX_BYTES)?;
        self.scalar::<u64>()?; // current fence
        self.scalar::<u64>()?; // current credential
        self.timestamp()?; // exact current acquisition
        self.timestamp()?; // exact current expiry
        Ok(payload)
    }

    fn ordinary_error(&mut self) -> io::Result<()> {
        fn tag(value: StoreError) -> io::Result<u32> {
            let mut bytes = [0; 32];
            let bytes = postcard::to_slice(&value, &mut bytes)
                .map_err(|_| invalid("native ordinary error tag cannot encode"))?;
            postcard::take_from_bytes::<u32>(bytes)
                .map(|(tag, _)| tag)
                .map_err(|_| invalid("native ordinary error tag invalid"))
        }
        let actual = self.scalar::<u32>()?;
        for error in [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::TopologyAuthorityRevoked,
            StoreError::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry,
            StoreError::LeaseHeld,
            StoreError::LeaseExpired,
            StoreError::SessionRecordReserved,
            StoreError::FencedTransitionRequestExpired,
            StoreError::FencedTransitionStorageExhausted,
        ] {
            if actual == tag(error)? {
                return Ok(());
            }
        }
        if actual == tag(StoreError::InvalidKey(String::new()))? {
            return self.string(1024);
        }
        if actual == tag(StoreError::PayloadTooLarge { actual: 0, max: 0 })? {
            self.scalar::<usize>()?;
            self.scalar::<usize>()?;
            return Ok(());
        }
        Err(invalid("native ordinary error requires its command codec"))
    }

    fn ordinary_result(&mut self) -> io::Result<usize> {
        match self.scalar::<u32>()? {
            0 => match self.scalar::<u32>()? {
                0 => match self.scalar::<u32>()? {
                    0 => Ok(0),
                    1 => {
                        if self.scalar::<bool>()? {
                            self.record()
                        } else {
                            Ok(0)
                        }
                    }
                    _ => Err(invalid("native ordinary CAS result tag invalid")),
                },
                1 => {
                    if self.scalar::<bool>()? {
                        self.record()
                    } else {
                        Ok(0)
                    }
                }
                2 => {
                    self.lease()?;
                    Ok(0)
                }
                3 => Ok(0),
                _ => Err(invalid(
                    "native generic result requires its versioned command codec",
                )),
            },
            1 => {
                self.ordinary_error()?;
                Ok(0)
            }
            _ => Err(invalid("native ordinary result tag invalid")),
        }
    }

    fn end(self, payload: usize) -> io::Result<usize> {
        if !self.rest.is_empty() {
            return Err(invalid("native generation borrowed row has trailing bytes"));
        }
        payload
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(METADATA))
            .ok_or_else(|| invalid("native generation borrowed row reservation overflow"))
    }
}

fn key_scratch(bytes: &[u8]) -> io::Result<usize> {
    let mut row = Cursor { rest: bytes };
    row.key()?;
    let mut payload = 0;
    if row.scalar::<bool>()? {
        if row.scalar::<bool>()? {
            payload = row.record()?;
        }
        if row.scalar::<bool>()? {
            row.string(OWNER_ID_MAX_BYTES)?;
            row.scalar::<u64>()?; // fence
            row.scalar::<u64>()?; // credential
            if row.scalar::<bool>()? {
                row.timestamp()?;
            }
            row.scalar::<i64>()?; // original physical expiry, retained on release
            row.timestamp()?;
            row.scalar::<bool>()?;
        }
        row.scalar::<u64>()?;
        row.scalar::<bool>()?;
    }
    row.end(payload)
}

fn notification_scratch(bytes: &[u8]) -> io::Result<usize> {
    let mut row = Cursor { rest: bytes };
    row.scalar::<u64>()?;
    row.string(crate::backend::REPLICATION_TX_ID_MAX_BYTES)?;
    let tag = row.scalar::<u32>()?;
    let payload = if tag == 7 {
        if row.scalar::<usize>()? != 2 {
            return Err(invalid(
                "native generation notification batch shape invalid",
            ));
        }
        let lease = row.scalar::<u32>()?;
        if !matches!(lease, 3 | 4) {
            return Err(invalid(
                "native generation notification lease shape invalid",
            ));
        }
        row.lease_effect(lease)?;
        let mutation = row.scalar::<u32>()?;
        row.mutation_effect(mutation)?
    } else if matches!(tag, 6 | 8) {
        row.roster_effect(tag)?
    } else if matches!(tag, 3 | 4 | 5) {
        row.lease_effect(tag)?;
        0
    } else {
        row.mutation_effect(tag)?
    };
    row.timestamp()?;
    row.end(payload)
}

fn generic_scratch(bytes: &[u8]) -> io::Result<usize> {
    generic_scratch_format(bytes, Format::V3)
}

fn generic_scratch_format(bytes: &[u8], format: Format) -> io::Result<usize> {
    request_scratch(bytes, format, true)
}

fn request_scratch(bytes: &[u8], format: Format, optional: bool) -> io::Result<usize> {
    let mut row = Cursor { rest: bytes };
    row.scalar::<SessionConsensusRequestId>()?;
    let mut payload = 0;
    if !optional || row.scalar::<bool>()? {
        let kind = if format == Format::V2 {
            0
        } else {
            row.scalar::<u32>()?
        };
        if kind > 1 {
            return Err(invalid("native request receipt variant invalid"));
        }
        row.scalar::<[u8; 32]>()?;
        let has_response = if kind == 1 {
            row.timestamp()?;
            row.scalar::<bool>()?
        } else {
            true
        };
        if has_response {
            if kind == 0 {
                payload = row.ordinary_result()?;
            } else {
                // V1 can retain only one fenced result or one bounded error.
                // Reject arbitrary generic records/batches before allocation.
                match row.scalar::<u32>()? {
                    0 => {
                        if row.scalar::<u32>()? != 4 {
                            return Err(invalid("native V1 outcome tag invalid"));
                        }
                        row.lease()?;
                        row.scalar::<u64>()?;
                        match row.scalar::<u32>()? {
                            0..=2 => {}
                            3 => row.timestamp()?,
                            _ => return Err(invalid("native V1 mutation result tag invalid")),
                        }
                        row.timestamp()?;
                        row.timestamp()?;
                    }
                    1 => row.ordinary_error()?,
                    _ => return Err(invalid("native V1 result tag invalid")),
                }
            }
            row.scalar::<u64>()?;
            row.scalar::<Option<SessionConsensusEntryDigest>>()?;
            if row.scalar::<bool>()? {
                row.timestamp()?;
            }
            row.scalar::<u64>()?;
        }
    }
    row.end(payload)
}

fn decode_generic(
    bytes: &[u8],
    format: Format,
) -> io::Result<(SessionConsensusRequestId, Option<NativeGenericReceipt>)> {
    if format == Format::V2 {
        let (id, row): (SessionConsensusRequestId, Option<NativeOrdinaryReceipt>) =
            binary::decode(bytes)?;
        Ok((id, row.map(NativeGenericReceipt::Ordinary)))
    } else {
        binary::decode(bytes)
    }
}

// These concrete closed validators allow no decoded object, reference or
// callback to outlive scratch ownership. Cold reconstruction will retain only
// separately charged compact metadata/ranges, and keys need their own resident
// ownership when that reader is integrated. Input bytes are charged by Input.
pub(super) fn verify_key(
    bytes: &[u8],
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    inspect_key(bytes, frontiers, check).map(|_| ())
}

pub(super) fn inspect_key(
    bytes: &[u8],
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(facts::KeyId, Option<facts::Row<facts::Key>>)> {
    inspect_key_format(bytes, Format::V3, frontiers, check)
}

pub(super) fn inspect_key_format(
    bytes: &[u8],
    format: Format,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(facts::KeyId, Option<facts::Row<facts::Key>>)> {
    check()?;
    let _memory = VerificationMemory::reserve(key_scratch(bytes)?)?;
    let (key, row): (SessionKey, Option<NativeKeyState>) = binary::decode(bytes)?;
    if let Some(row) = &row {
        if row.reserved && format != Format::V4 {
            return Err(invalid(
                "native legacy generation cannot contain roster reservations",
            ));
        }
        validation::validate_key(&key, row, frontiers)?;
    }
    let id = facts::KeyId::of(&key)?;
    let facts = row
        .as_ref()
        .map(|row| -> io::Result<_> {
            Ok(facts::Row {
                content: changes::fingerprint(0, &key, row)?,
                facts: facts::Key::of(&key, row, format)?,
            })
        })
        .transpose()?;
    drop(row);
    drop(key);
    check()?;
    Ok((id, facts))
}

pub(super) struct OwnedKey {
    key: SessionKey,
    row: NativeKeyState,
    _memory: VerificationMemory,
}

impl OwnedKey {
    pub(super) fn into_resident(self) -> (SessionKey, NativeKeyState) {
        (self.key, self.row)
    }
}

pub(super) fn owned_key(
    bytes: &[u8],
    expected_id: facts::KeyId,
    expected: facts::Row<facts::Key>,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<OwnedKey> {
    check()?;
    let memory = VerificationMemory::reserve(key_scratch(bytes)?)?;
    let (decoded_key, decoded): (SessionKey, Option<NativeKeyState>) = binary::decode(bytes)?;
    let decoded = decoded.ok_or_else(|| invalid("native resident key selected a tombstone"))?;
    if decoded.reserved && expected.facts.format != Format::V4 {
        return Err(invalid(
            "native legacy generation cannot contain roster reservations",
        ));
    }
    validation::validate_key(&decoded_key, &decoded, frontiers)?;
    if facts::KeyId::of(&decoded_key)? != expected_id
        || changes::fingerprint(0, &decoded_key, &decoded)? != expected.content
    {
        return Err(invalid("native resident key differs from admitted catalog"));
    }
    let key = owned::key(&decoded_key)?;
    let row = NativeKeyState {
        record: decoded.record.as_ref().map(owned::record).transpose()?,
        // NativeLease now contains only independently cloned owner text and
        // scalars, including the nullable legacy acquisition marker.
        lease: decoded.lease.clone(),
        fence: decoded.fence,
        reserved: decoded.reserved,
    };
    drop(decoded);
    drop(decoded_key);
    check()?;
    Ok(OwnedKey {
        key,
        row,
        _memory: memory,
    })
}

pub(super) fn verify_notification(
    bytes: &[u8],
    sequence: u64,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    inspect_notification(bytes, sequence, frontiers, check).map(|_| ())
}

pub(in crate::consensus::native) fn inspect_notification(
    bytes: &[u8],
    sequence: u64,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<facts::Row<facts::Notification>> {
    check()?;
    let _memory = VerificationMemory::reserve(notification_scratch(bytes)?)?;
    let row: ReplicationEntry = binary::decode(bytes)?;
    // The original complete semantic validator remains authoritative.
    validation::validate_notification(&row, sequence, frontiers)?;
    let facts = facts::Row {
        content: changes::fingerprint(3, &row.sequence, &row)?,
        facts: facts::Notification {
            sequence: row.sequence,
            timestamp: row.timestamp,
        },
    };
    drop(row);
    check()?;
    Ok(facts)
}

pub(in crate::consensus::native) struct OwnedNotification {
    entry: ReplicationEntry,
    _memory: VerificationMemory,
}

impl OwnedNotification {
    pub(in crate::consensus::native) fn entry(&self) -> &ReplicationEntry {
        &self.entry
    }
}

pub(in crate::consensus::native) fn owned_notification(
    bytes: &[u8],
    sequence: u64,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<OwnedNotification> {
    check()?;
    let memory = VerificationMemory::reserve(notification_scratch(bytes)?)?;
    let decoded: ReplicationEntry = binary::decode(bytes)?;
    validation::validate_notification(&decoded, sequence, frontiers)?;
    // Independent copies of all carried payloads are below the six-times-sum
    // scratch bound. The copy performs no envelope parse or canonical encode.
    let entry = owned::notification(&decoded)?;
    drop(decoded);
    check()?;
    Ok(OwnedNotification {
        entry,
        _memory: memory,
    })
}

pub(super) fn verify_generic(
    bytes: &[u8],
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    inspect_generic(bytes, frontiers, check).map(|_| ())
}

// Full images omit the generation's optional-row marker. Share the same
// borrowed shape check and reservation before decoding either binary version.
pub(in crate::consensus::native) fn full_generic(
    bytes: &[u8],
    format: Format,
    frontiers: &NativeFrontiers,
) -> io::Result<(SessionConsensusRequestId, NativeGenericReceipt)> {
    let _memory = VerificationMemory::reserve(request_scratch(bytes, format, false)?)?;
    let (id, row) = if format == Format::V2 {
        let (id, row): (SessionConsensusRequestId, NativeOrdinaryReceipt) = binary::decode(bytes)?;
        (id, NativeGenericReceipt::Ordinary(row))
    } else {
        binary::decode(bytes)?
    };
    validation::validate_generic(&id, &row, frontiers)?;
    Ok((id, row))
}

pub(super) fn inspect_generic(
    bytes: &[u8],
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(
    SessionConsensusRequestId,
    Option<facts::Row<facts::Request>>,
)> {
    inspect_generic_format(bytes, Format::V3, frontiers, check)
}

pub(super) fn inspect_generic_format(
    bytes: &[u8],
    format: Format,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(
    SessionConsensusRequestId,
    Option<facts::Row<facts::Request>>,
)> {
    check()?;
    let _memory = VerificationMemory::reserve(generic_scratch_format(bytes, format)?)?;
    let (id, row) = decode_generic(bytes, format)?;
    if let Some(row) = &row {
        validation::validate_generic(&id, row, frontiers)?;
    }
    let facts = row
        .as_ref()
        .map(|row| -> io::Result<_> {
            Ok(facts::Row {
                content: changes::fingerprint(2, &id, row)?,
                facts: facts::Request::of(row, format)?,
            })
        })
        .transpose()?;
    drop(row);
    check()?;
    Ok((id, facts))
}

pub(super) fn owned_generic(
    bytes: &[u8],
    expected_id: SessionConsensusRequestId,
    expected: facts::Row<facts::Request>,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<NativeGenericReceipt> {
    check()?;
    let format = expected.facts.format;
    let _memory = VerificationMemory::reserve(generic_scratch_format(bytes, format)?)?;
    let (id, decoded) = decode_generic(bytes, format)?;
    let decoded =
        decoded.ok_or_else(|| invalid("native resident request receipt selected a removal"))?;
    validation::validate_generic(&id, &decoded, frontiers)?;
    if id != expected_id || changes::fingerprint(2, &id, &decoded)? != expected.content {
        return Err(invalid(
            "native resident request receipt differs from admitted catalog",
        ));
    }
    let row = decoded.owned_copy()?;
    drop(decoded);
    check()?;
    Ok(row)
}

pub(super) fn verify_log(
    bytes: &[u8],
    index: u64,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    inspect_log(bytes, index, identity, members, check).map(|_| ())
}

pub(in crate::consensus::native) fn inspect_log(
    bytes: &[u8],
    index: u64,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<facts::Row<facts::Log>> {
    check()?;
    let bytes_to_reserve = json::log_scratch(bytes)?;
    let _memory = VerificationMemory::reserve(bytes_to_reserve)?;
    let row = crate::sqlite::consensus::decode_consensus_log_entry(bytes)?;
    if row.log_id.index != index {
        return Err(invalid("native generation log index differs"));
    }
    log::NativeLog::validate_entry_context(&row, identity, members)?;
    let membership = match &row.payload {
        EntryPayload::Membership(value) => Some(facts::membership(value)?),
        _ => None,
    };
    let facts = facts::Row {
        content: log::fingerprint(index, bytes),
        facts: facts::Log {
            id: row.log_id,
            membership,
        },
    };
    drop(row);
    check()?;
    Ok(facts)
}

pub(in crate::consensus::native) struct OwnedLog {
    entry: Entry<SessionRaftTypeConfig>,
    _memory: VerificationMemory,
}

impl OwnedLog {
    pub(in crate::consensus::native) fn entry(&self) -> &Entry<SessionRaftTypeConfig> {
        &self.entry
    }
    pub(in crate::consensus::native) fn into_parts(
        self,
    ) -> (Entry<SessionRaftTypeConfig>, VerificationMemory) {
        (self.entry, self._memory)
    }
}

/// One closed decoder and an explicit independent copy. No decoded payload
/// or Bytes backing escapes its scratch owner. After dropping that model,
/// the retained copy keeps the remaining reservation until its final owner
/// check; only the adapter's caller-output boundary releases it.
pub(in crate::consensus::native) fn owned_log(
    bytes: &[u8],
    index: u64,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<OwnedLog> {
    check()?;
    let scratch = json::log_scratch(bytes)?;
    let mut memory = VerificationMemory::reserve(scratch)?;
    let decoded = crate::sqlite::consensus::decode_consensus_log_entry(bytes)?;
    if decoded.log_id.index != index {
        return Err(invalid("native owned log index differs"));
    }
    log::NativeLog::validate_entry_context(&decoded, identity, members)?;
    // The original peak includes two raw widths for retained models and a
    // separate maximum of canonical encoding/envelope validation. Those
    // codec temporaries are gone before this independent byte copy, which
    // performs no envelope parse, including for retained conflict bodies.
    let entry = owned::entry(&decoded)?;
    let retained = scratch::log_owned(&entry)?;
    drop(decoded);
    check()?;
    memory.shrink_to(retained)?;
    Ok(OwnedLog {
        entry,
        _memory: memory,
    })
}

#[cfg(test)]
#[path = "generation_decode_tests.rs"]
mod tests;
