//! Explicit pre-epoch row layout. Old positional discriminators never decode
//! a different field order or silently discard an exact retirement tag.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BeforeEpoch {
    record: Option<StoredSessionRecord>,
    lease: Option<NativeLease>,
    fence: u64,
    reserved: bool,
}

impl BeforeEpoch {
    pub(super) fn into_current(self) -> NativeKeyState {
        NativeKeyState {
            record: self.record,
            lease: self.lease,
            fence: self.fence,
            reserved: self.reserved,
            retired_epoch: None,
        }
    }

    pub(super) fn from_current(row: &NativeKeyState) -> io::Result<Self> {
        if row.retired_epoch.is_some() {
            return Err(invalid("legacy native row cannot carry a retirement epoch"));
        }
        Ok(Self {
            record: row.record.clone(),
            lease: row.lease.clone(),
            fence: row.fence,
            reserved: row.reserved,
        })
    }
}
