//! Bounded native image, including every retained log payload. The enclosing
//! WAL selector binds the file digest before this decoder is entered. Every
//! count and item length is checked before allocating its corresponding data.

use super::*;
use opc_consensus::engine::Vote;
use std::io::{Read, Write};

pub(super) mod binary;
mod legacy;

const LEGACY_MAGIC: &[u8; 8] = b"OPCNAT01";
const V2_MAGIC: &[u8; 8] = b"OPCNAT02";
// This version freezes the postcard field/variant order of the native rows.
// Changing that layout requires another discriminator and explicit reader.
const V3_MAGIC: &[u8; 8] = b"OPCNAT03";
const MAGIC: &[u8; 8] = b"OPCNAT04";
const MAX_ITEMS: usize = 1_048_576;
const MAX_HEADER: usize = 64 * 1024;
const MAX_ITEM: usize = 2 * crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    root: [u8; 32],
    wal_sequence: u64,
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    frontiers: NativeFrontiers,
    vote: Option<Vote<SessionConsensusNodeId>>,
    committed: Option<LogId<SessionConsensusNodeId>>,
    purged: Option<LogId<SessionConsensusNodeId>>,
    keys: usize,
    receipts: usize,
    generic_receipts: usize,
    notifications: usize,
    logs: usize,
}

fn write_item(writer: &mut impl Write, item: &impl Serialize, limit: usize) -> io::Result<()> {
    let bytes = serde_json::to_vec(item).map_err(|_| invalid("native image item cannot encode"))?;
    write_bytes(writer, &bytes, limit)
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8], limit: usize) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(invalid("native image item exceeds bound"));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| invalid("native image item exceeds length encoding"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)
}

fn read_bytes(reader: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > limit {
        return Err(invalid("native image item length invalid"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_item<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    limit: usize,
) -> io::Result<T> {
    serde_json::from_slice(&read_bytes(reader, limit)?)
        .map_err(|_| invalid("native image item invalid"))
}

fn write_row(writer: &mut impl Write, item: &impl Serialize, legacy: bool) -> io::Result<()> {
    if legacy {
        return write_item(writer, item, MAX_ITEM);
    }
    let bytes =
        postcard::to_allocvec(item).map_err(|_| invalid("native binary row cannot encode"))?;
    write_bytes(writer, &bytes, MAX_ITEM)
}

fn read_row<T: serde::de::DeserializeOwned + Serialize>(
    reader: &mut impl Read,
    legacy: bool,
) -> io::Result<T> {
    if legacy {
        return read_item(reader, MAX_ITEM);
    }
    binary::decode(&read_bytes(reader, MAX_ITEM)?)
}

impl NativeStorage {
    pub(crate) fn write_image(
        &self,
        writer: &mut impl Write,
        root: [u8; 32],
        wal_sequence: u64,
    ) -> io::Result<()> {
        self.write_image_with_snapshot(writer, root, wal_sequence, None)
    }

    pub(crate) fn write_image_with_snapshot(
        &self,
        writer: &mut impl Write,
        root: [u8; 32],
        wal_sequence: u64,
        snapshot: Option<&crate::sqlite::consensus::CurrentSnapshot>,
    ) -> io::Result<()> {
        self.write_version(writer, root, wal_sequence, snapshot, 4)
    }

    #[cfg(test)]
    pub(crate) fn write_legacy_image_for_test(
        &self,
        writer: &mut impl Write,
        root: [u8; 32],
        wal_sequence: u64,
    ) -> io::Result<()> {
        self.write_version(writer, root, wal_sequence, None, 1)
    }

    #[cfg(test)]
    pub(crate) fn write_legacy_v2_image_for_test(
        &self,
        writer: &mut impl Write,
        root: [u8; 32],
        wal_sequence: u64,
    ) -> io::Result<()> {
        self.write_version(writer, root, wal_sequence, None, 2)
    }

    #[cfg(test)]
    pub(crate) fn write_legacy_v3_image_for_test(
        &self,
        writer: &mut impl Write,
        root: [u8; 32],
        wal_sequence: u64,
    ) -> io::Result<()> {
        self.write_version(writer, root, wal_sequence, None, 3)
    }

    fn write_version(
        &self,
        writer: &mut impl Write,
        root: [u8; 32],
        wal_sequence: u64,
        snapshot: Option<&crate::sqlite::consensus::CurrentSnapshot>,
        version: u8,
    ) -> io::Result<()> {
        self.business.require_legacy_roster_absent()?;
        self.validate_image()?;
        if version < 4 && self.business.frontiers.v1_activation.is_some() {
            return Err(invalid("native V1 state requires full image format four"));
        }
        if version < 3 && self.business.receipts.len() > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            return Err(invalid(
                "native history exceeds the legacy image receipt bound",
            ));
        }
        let mut frontiers = self.business.frontiers.clone();
        if let Some(snapshot) = snapshot {
            self.validate_snapshot(snapshot)?;
            frontiers.current_snapshot = Some(snapshot.clone());
        }
        validate_snapshot_root(frontiers.current_snapshot.as_ref(), root)?;
        let header = Header {
            root,
            wal_sequence,
            identity: self.business.identity,
            members: self.business.members.clone(),
            frontiers,
            vote: self.log.vote,
            committed: self.log.committed,
            purged: self.log.purged,
            keys: self.business.keys.len(),
            receipts: self.business.receipts.len(),
            generic_receipts: self.business.generic_receipts.len(),
            notifications: self.business.notifications.len(),
            logs: self.log.entries.len(),
        };
        let legacy = version == 1;
        writer.write_all(match version {
            1 => LEGACY_MAGIC,
            2 => V2_MAGIC,
            3 => V3_MAGIC,
            _ => MAGIC,
        })?;
        write_item(writer, &header, MAX_HEADER)?;
        for (key, row) in &self.business.keys {
            if version < 3 {
                write_row(writer, &(key, legacy::Key::from_current(key, row)?), legacy)?;
            } else {
                write_row(writer, &(key, row), false)?;
            }
        }
        for item in &self.business.receipts {
            write_row(writer, &item, legacy)?;
        }
        for (id, row) in &self.business.generic_receipts {
            if version < 4 {
                let NativeGenericReceipt::Ordinary(row) = &**row else {
                    return Err(invalid("native V1 receipt requires full image format four"));
                };
                write_row(writer, &(id, row), legacy)?;
            } else {
                write_row(writer, &(id, row), false)?;
            }
        }
        for item in &self.business.notifications {
            write_row(writer, item, legacy)?;
        }
        for item in self.log.entries.values() {
            write_bytes(
                writer,
                &item.resident()?.encoded,
                crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
            )?;
        }
        Ok(())
    }

    pub(crate) fn read_image(
        reader: &mut impl Read,
        root: [u8; 32],
        wal_sequence: u64,
        identity: SessionConsensusIdentity,
    ) -> io::Result<Self> {
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        let version = if &magic == LEGACY_MAGIC {
            1
        } else if &magic == V2_MAGIC {
            2
        } else if &magic == V3_MAGIC {
            3
        } else if &magic == MAGIC {
            4
        } else {
            return Err(invalid("native image discriminator differs"));
        };
        let legacy = version == 1;
        let header: Header = read_item(reader, MAX_HEADER)?;
        if header.frontiers.roster_v1_namespace || header.frontiers.roster_v2_activation.is_some() {
            return Err(invalid(
                "native full image carries an unsupported roster context",
            ));
        }
        if version < 4 && header.frontiers.v1_activation.is_some() {
            return Err(invalid(
                "native legacy image carries an unsupported V1 context",
            ));
        }
        if header.root != root
            || header.wal_sequence != wal_sequence
            || header.identity != identity
            || !matches!(header.members.len(), 3 | 5)
            || [header.keys, header.generic_receipts, header.notifications]
                .into_iter()
                .any(|count| count > MAX_ITEMS)
            || header.receipts
                > if version < 3 {
                    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                } else {
                    crate::fenced_transition::FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES
                }
            || header.logs > log::MAX_RETAINED_LOG_ENTRIES
        {
            return Err(invalid("native image identity or cardinality differs"));
        }
        let mut image = Self::empty(header.identity, header.members)?;
        image.business.frontiers = header.frontiers;
        image.log.vote = header.vote;
        image.log.committed = header.committed;
        image.log.purged = header.purged;
        for _ in 0..header.keys {
            let (key, value) = if version < 3 {
                let (key, value): (SessionKey, legacy::Key) = read_row(reader, legacy)?;
                let value = SharedRow::new(value.into_current(&key)?);
                (key, value)
            } else {
                read_row(reader, false)?
            };
            if image.business.keys.insert(key, value).is_some() {
                return Err(invalid("native image repeats a key"));
            }
        }
        for _ in 0..header.receipts {
            let (id, value) = read_row(reader, legacy)?;
            if image.business.receipts.insert(id, value).is_some() {
                return Err(invalid("native image repeats a receipt"));
            }
        }
        for _ in 0..header.generic_receipts {
            let (id, value) = if legacy {
                let (id, value): (SessionConsensusRequestId, NativeOrdinaryReceipt) =
                    read_row(reader, true)?;
                (id, SharedRow::new(NativeGenericReceipt::Ordinary(value)))
            } else {
                let format = if version < 4 {
                    generation::Format::V2
                } else {
                    generation::Format::V3
                };
                let (id, value) = generation::decode::full_generic(
                    &read_bytes(reader, MAX_ITEM)?,
                    format,
                    &image.business.frontiers,
                )?;
                (id, SharedRow::new(value))
            };
            if image.business.generic_receipts.insert(id, value).is_some() {
                return Err(invalid("native image repeats a generic receipt"));
            }
        }
        for _ in 0..header.notifications {
            image
                .business
                .notifications
                .push_back(read_row(reader, legacy)?);
        }
        for _ in 0..header.logs {
            let encoded = read_bytes(
                reader,
                crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
            )?;
            let entry = crate::sqlite::consensus::decode_consensus_log_entry(&encoded)?;
            if image
                .log
                .entries
                .insert(
                    entry.log_id.index,
                    SharedRow::new(log::NativeLogEntry::new(encoded.into(), entry)),
                )
                .is_some()
            {
                return Err(invalid("native image repeats a log index"));
            }
        }
        let mut trailing = [0; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(invalid("native image contains trailing bytes"));
        }
        image.validate_image()?;
        validate_snapshot_root(image.business.frontiers.current_snapshot.as_ref(), root)?;
        image.business.admit_business()?;
        image.log.admit(&image.business)?;
        Ok(image)
    }

    pub(crate) fn validate_snapshot(
        &self,
        snapshot: &crate::sqlite::consensus::CurrentSnapshot,
    ) -> io::Result<()> {
        self.business.validate_snapshot(snapshot)?;
        let Some(applied) = snapshot.0.last_log_id else {
            return Ok(());
        };
        // A later local envelope can cover the same installed cut. Its
        // filename/checksum are distinct, while the original source still
        // supplies the exact missing LogId and membership witnesses.
        if self
            .log
            .entries
            .get(&applied.index)
            .is_none_or(|entry| entry.id() != applied)
            && !(self.log.entries.get(&applied.index).is_none()
                && self
                    .business
                    .snapshot_origin
                    .as_ref()
                    .is_some_and(|origin| origin.matches_snapshot_lineage(snapshot)))
        {
            return Err(invalid(
                "native snapshot applied lineage differs from retained log",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_image(&self) -> io::Result<()> {
        self.log.validate(&self.business)?;
        if let Some(snapshot) = &self.business.frontiers.current_snapshot {
            self.validate_snapshot(snapshot)?;
        }
        self.business.validate_full_business()?;
        Ok(())
    }
}

impl NativeState {
    pub(crate) fn validate_snapshot(
        &self,
        snapshot: &crate::sqlite::consensus::CurrentSnapshot,
    ) -> io::Result<()> {
        validation::validate_snapshot(snapshot, &self.frontiers, self.snapshot_origin.as_deref())
    }
}

pub(crate) fn snapshot_prefix(root: [u8; 32]) -> String {
    let digest = root
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("native-{digest}-")
}

pub(super) fn validate_snapshot_root(
    snapshot: Option<&crate::sqlite::consensus::CurrentSnapshot>,
    root: [u8; 32],
) -> io::Result<()> {
    validate_snapshot_root_with_origin(snapshot, root, None)
}

pub(super) fn validate_snapshot_root_with_origin(
    snapshot: Option<&crate::sqlite::consensus::CurrentSnapshot>,
    root: [u8; 32],
    origin: Option<&NativeSnapshotAuthority>,
) -> io::Result<()> {
    if snapshot.is_some_and(|snapshot| {
        !snapshot.0.snapshot_id.starts_with(&snapshot_prefix(root))
            && !origin.is_some_and(|origin| origin.matches_snapshot(snapshot))
    }) {
        return Err(invalid("native snapshot generation binding differs"));
    }
    Ok(())
}
