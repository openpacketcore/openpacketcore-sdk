//! Bounded physical locators; malformed keys are never repaired or truncated.
use crate::{scope_authority::ScopeNamespace, scope_storage};
use std::fmt;

/// Canonical keys precede malformed keys within each reserved kind. Native
/// malformed keys are bounded by StableId; SQLite uses its retained rowid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum LocatorKind {
    Canonical = 0,
    NativeKnown = 1,
    NativeUnknown = 2,
    SqliteKnown = 3,
    SqliteUnknown = 4,
}
impl LocatorKind {
    pub(crate) fn decode(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::Canonical,
            1 => Self::NativeKnown,
            2 => Self::NativeUnknown,
            3 => Self::SqliteKnown,
            4 => Self::SqliteUnknown,
            _ => return None,
        })
    }
    pub(crate) fn accepts_length(self, length: usize) -> bool {
        match self {
            Self::Canonical => length == 64,
            Self::NativeKnown => (32..64).contains(&length),
            Self::NativeUnknown => (1..=64).contains(&length),
            Self::SqliteKnown | Self::SqliteUnknown => length == 8,
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InventoryPosition {
    pub(crate) kind: u8,
    pub(crate) locator: LocatorKind,
    pub(crate) bytes: Vec<u8>,
}
impl fmt::Debug for InventoryPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InventoryPosition(<redacted>)")
    }
}
impl InventoryPosition {
    pub(crate) fn valid_shape(&self) -> bool {
        self.kind <= 1 && self.locator.accepts_length(self.bytes.len())
    }
    pub(crate) fn valid_namespace(&self, namespace: &ScopeNamespace) -> bool {
        if !self.valid_shape() {
            return false;
        }
        match self.locator {
            LocatorKind::Canonical | LocatorKind::NativeKnown => {
                scope_storage::namespace_prefix(namespace)
                    .is_ok_and(|prefix| self.bytes.starts_with(&prefix))
            }
            LocatorKind::NativeUnknown | LocatorKind::SqliteKnown | LocatorKind::SqliteUnknown => {
                true
            }
        }
    }
    pub(crate) fn logical_key(&self) -> Option<&[u8]> {
        (self.locator == LocatorKind::Canonical && self.bytes.len() == 64)
            .then(|| &self.bytes[32..])
    }
    pub(crate) fn sqlite(kind: u8, known: bool, rowid: i64) -> Self {
        // Flip the sign bit so byte ordering follows every signed rowid,
        // including i64::MIN. No sentinel rowid can hide a physical row.
        let bytes = ((rowid as u64) ^ (1_u64 << 63)).to_be_bytes().to_vec();
        Self {
            kind,
            locator: if known {
                LocatorKind::SqliteKnown
            } else {
                LocatorKind::SqliteUnknown
            },
            bytes,
        }
    }
    pub(crate) fn rowid(&self) -> Option<i64> {
        if !matches!(
            self.locator,
            LocatorKind::SqliteKnown | LocatorKind::SqliteUnknown
        ) {
            return None;
        }
        let bytes: [u8; 8] = self.bytes.as_slice().try_into().ok()?;
        Some((u64::from_be_bytes(bytes) ^ (1_u64 << 63)) as i64)
    }
}
