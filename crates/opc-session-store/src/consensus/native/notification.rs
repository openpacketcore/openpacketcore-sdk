//! Selected notification payloads keep only their exact append-only sequence
//! and timestamp resident. Serialization is transparent for resident rows and
//! explicitly rejects unresolved selected rows.

use super::*;
use resident::{RowFingerprint, SelectedBytes, SelectedRange};
use serde::{Deserializer, Serializer};
use std::io::Write;
use std::num::NonZeroU64;
use std::ops::Deref;
use std::sync::Arc;

/// The persistent vector shares immutable chunks. Keep selected metadata in
/// those chunks without another Arc and Box per historical notification.
/// Resident bodies remain shared when a captured chunk must be copied.
#[derive(Clone)]
pub(super) struct NotificationRow {
    value: NativeNotification,
    revision: NonZeroU64,
}

impl NotificationRow {
    pub(super) fn new(value: NativeNotification) -> io::Result<Self> {
        Ok(Self {
            value,
            revision: shared::issue_revision()?,
        })
    }

    pub(super) fn ptr_eq(&self, other: &Self) -> bool {
        self.revision == other.revision
    }

    // Only exact expected readback can produce a selected replacement. Its
    // publication keeps the captured logical revision, like SharedRow.
    pub(super) fn relocated(&self, value: NativeNotification) -> Self {
        Self {
            value,
            revision: self.revision,
        }
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.get()
    }
}

impl Deref for NotificationRow {
    type Target = NativeNotification;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Serialize for NotificationRow {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NotificationRow {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        Self::new(NativeNotification::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
pub(super) struct NativeNotification {
    body: Body,
}

#[derive(Clone)]
enum Body {
    Resident(Arc<ReplicationEntry>),
    Selected(SelectedNotification),
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
    #[cfg(any(test, feature = "test-control"))]
    pub(super) fn is_selected_for_test(&self) -> bool {
        matches!(self.body, Body::Selected(_))
    }

    pub(super) fn new(row: ReplicationEntry) -> Self {
        Self {
            body: Body::Resident(Arc::new(row)),
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
            body: Body::Selected(SelectedNotification { range, row }),
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
                let bytes = row.range.read(check)?;
                generation::decode::owned_notification(bytes.bytes(), row.row, frontiers, check)
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
