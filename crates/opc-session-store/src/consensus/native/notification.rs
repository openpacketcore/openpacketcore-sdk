//! Selected notification payloads keep only their exact append-only sequence
//! and timestamp resident. Serialization is transparent for resident rows and
//! explicitly rejects unresolved selected rows.

use super::*;
use resident::{RowFingerprint, SelectedBytes, SelectedRange};
use serde::{Deserializer, Serializer};
use std::io::Write;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct NativeNotification {
    body: Body,
}

#[derive(Clone)]
enum Body {
    Resident(Box<ReplicationEntry>),
    Selected(Box<SelectedNotification>),
}

#[derive(Clone)]
struct SelectedNotification {
    range: SelectedRange,
    row: generation::facts::Row<generation::facts::Notification>,
}

pub(super) enum ReadNotification<'a> {
    Resident(&'a ReplicationEntry),
    Selected(generation::decode::OwnedNotification),
}

impl ReadNotification<'_> {
    pub(super) fn entry(&self) -> &ReplicationEntry {
        match self {
            Self::Resident(row) => row,
            Self::Selected(row) => row.entry(),
        }
    }
}

impl NativeNotification {
    pub(super) fn relocation_allocation_bytes() -> usize {
        SharedRow::<Self>::relocated_allocation_bytes()
            + std::mem::size_of::<SelectedNotification>()
    }

    pub(super) fn new(row: ReplicationEntry) -> Self {
        Self {
            body: Body::Resident(Box::new(row)),
        }
    }

    pub(super) fn sequence(&self) -> u64 {
        match &self.body {
            Body::Resident(row) => row.sequence,
            Body::Selected(row) => row.row.facts.sequence,
        }
    }

    pub(super) fn timestamp(&self) -> Timestamp {
        match &self.body {
            Body::Resident(row) => row.timestamp,
            Body::Selected(row) => row.row.facts.timestamp,
        }
    }

    pub(super) fn resident(&self) -> io::Result<&ReplicationEntry> {
        match &self.body {
            Body::Resident(row) => Ok(row),
            Body::Selected(_) => Err(invalid(
                "native selected notification requires an outside-owner read",
            )),
        }
    }

    pub(super) fn from_admitted_range(
        row: generation::facts::Row<generation::facts::Notification>,
        source: Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
    ) -> io::Result<Self> {
        if row.facts.sequence == 0 {
            return Err(invalid("native selected notification sequence invalid"));
        }
        let range = SelectedRange::new(source, offset, length, generation::MAX_ITEM)?;
        Ok(Self {
            body: Body::Selected(Box::new(SelectedNotification { range, row })),
        })
    }

    pub(super) fn validate(&self, sequence: u64, frontiers: &NativeFrontiers) -> io::Result<()> {
        if self.sequence() != sequence
            || frontiers
                .logical_time
                .is_none_or(|now| self.timestamp() > now)
        {
            return Err(invalid("native selected notification frontier differs"));
        }
        if let Body::Resident(row) = &self.body {
            validation::validate_notification(row, sequence, frontiers)?;
        }
        Ok(())
    }

    fn selected_bytes(
        row: &SelectedNotification,
        frontiers: &NativeFrontiers,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<SelectedBytes> {
        let bytes = row.range.read(check)?;
        let actual = generation::decode::inspect_notification(
            bytes.bytes(),
            row.row.facts.sequence,
            frontiers,
            check,
        )?;
        if actual.content != row.row.content
            || actual.facts.sequence != row.row.facts.sequence
            || actual.facts.timestamp != row.row.facts.timestamp
        {
            return Err(invalid(
                "native selected notification differs from admitted row",
            ));
        }
        Ok(bytes)
    }

    pub(super) fn read(
        &self,
        frontiers: &NativeFrontiers,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<ReadNotification<'_>> {
        match &self.body {
            Body::Resident(row) => Ok(ReadNotification::Resident(row)),
            Body::Selected(row) => {
                let bytes = Self::selected_bytes(row, frontiers, check)?;
                generation::decode::owned_notification(
                    bytes.bytes(),
                    row.row.facts.sequence,
                    frontiers,
                    check,
                )
                .map(ReadNotification::Selected)
            }
        }
    }

    pub(super) fn write_binary(
        &self,
        writer: &mut dyn Write,
        frontiers: &NativeFrontiers,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        match &self.body {
            Body::Resident(row) => {
                changes::notification_payload(row)?;
                generation::write_binary(writer, &**row)
            }
            Body::Selected(row) => {
                let bytes = Self::selected_bytes(row, frontiers, check)?;
                generation::write_bytes(writer, bytes.bytes(), generation::MAX_ITEM)
            }
        }
    }
}

impl Serialize for NativeNotification {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.resident()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NativeNotification {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ReplicationEntry::deserialize(deserializer).map(Self::new)
    }
}

impl RowFingerprint for NativeNotification {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        if table != 3 {
            return Err(invalid("native notification fingerprint table differs"));
        }
        match &self.body {
            Body::Resident(row) => changes::fingerprint(table, key, &**row),
            Body::Selected(row) => {
                if changes::fingerprint(table, key, &())?
                    != changes::fingerprint(table, &row.row.facts.sequence, &())?
                {
                    return Err(invalid("native selected notification key differs"));
                }
                Ok(row.row.content)
            }
        }
    }
}
