//! Typed log bodies become selected ranges only after durable publication.
//! The compact form retains exact ID, content and fully decoded membership
//! facts. Its private authority binding prevents reuse in a different scope.

use super::*;
use crate::consensus::native::resident::{authority_binding, RowBytes, SelectedRange};

#[derive(Clone)]
pub(crate) struct NativeLogEntry {
    body: Body,
}

#[derive(Clone)]
enum Body {
    Resident(Box<ResidentLog>),
    Selected(Box<SelectedLog>),
}

#[derive(Clone)]
pub(in crate::consensus::native) struct ResidentLog {
    pub(in crate::consensus::native) encoded: Bytes,
    pub(in crate::consensus::native) entry: Entry<SessionRaftTypeConfig>,
}

#[derive(Clone)]
struct SelectedLog {
    range: SelectedRange,
    row: generation::facts::Row<generation::facts::Log>,
    authority: [u8; 32],
}

impl NativeLogEntry {
    pub(in crate::consensus::native) fn relocation_allocation_bytes() -> usize {
        SharedRow::<Self>::relocated_allocation_bytes() + std::mem::size_of::<SelectedLog>()
    }

    pub(in crate::consensus::native) fn new(
        encoded: Bytes,
        entry: Entry<SessionRaftTypeConfig>,
    ) -> Self {
        Self {
            body: Body::Resident(Box::new(ResidentLog { encoded, entry })),
        }
    }

    pub(crate) fn id(&self) -> LogId<SessionConsensusNodeId> {
        match &self.body {
            Body::Resident(row) => row.entry.log_id,
            Body::Selected(row) => row.row.facts.id,
        }
    }

    pub(in crate::consensus::native) fn resident(&self) -> io::Result<&ResidentLog> {
        match &self.body {
            Body::Resident(row) => Ok(row),
            Body::Selected(_) => Err(invalid(
                "native selected log requires an outside-owner read",
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn encoded_for_test(&self) -> io::Result<&[u8]> {
        Ok(&self.resident()?.encoded)
    }

    #[cfg(test)]
    pub(in crate::consensus::native) fn resident_mut(&mut self) -> io::Result<&mut ResidentLog> {
        match &mut self.body {
            Body::Resident(row) => Ok(row),
            Body::Selected(_) => Err(invalid("native selected log has no resident payload")),
        }
    }

    pub(in crate::consensus::native) fn is_cold(&self) -> bool {
        matches!(self.body, Body::Selected(_))
    }

    pub(in crate::consensus::native) fn content(&self, index: u64) -> io::Result<[u8; 32]> {
        if self.id().index != index {
            return Err(invalid("native log key differs from its exact ID"));
        }
        Ok(match &self.body {
            Body::Resident(row) => fingerprint(index, &row.encoded),
            Body::Selected(row) => row.row.content,
        })
    }

    pub(in crate::consensus::native) fn matches_bytes(
        &self,
        index: u64,
        bytes: &[u8],
    ) -> io::Result<bool> {
        match &self.body {
            Body::Resident(row) => {
                Ok(row.entry.log_id.index == index && row.encoded.as_ref() == bytes)
            }
            Body::Selected(_) => Ok(self.content(index)? == fingerprint(index, bytes)),
        }
    }

    pub(in crate::consensus::native) fn membership(&self) -> io::Result<Option<[u8; 32]>> {
        match &self.body {
            Body::Resident(row) => match &row.entry.payload {
                EntryPayload::Membership(value) => generation::facts::membership(value).map(Some),
                _ => Ok(None),
            },
            Body::Selected(row) => Ok(row.row.facts.membership),
        }
    }

    pub(in crate::consensus::native) fn from_admitted_range(
        row: generation::facts::Row<generation::facts::Log>,
        source: std::sync::Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<Self> {
        sql::validate_log_id(&row.facts.id)?;
        let range = SelectedRange::new(
            source,
            offset,
            length,
            sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
        )?;
        Ok(Self {
            body: Body::Selected(Box::new(SelectedLog {
                range,
                row,
                authority: authority_binding(identity, members)?,
            })),
        })
    }

    pub(in crate::consensus::native) fn validate_context(
        &self,
        index: u64,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<()> {
        if self.id().index != index {
            return Err(invalid("native retained log key differs"));
        }
        sql::validate_log_id(&self.id())?;
        match &self.body {
            Body::Resident(row) => {
                let decoded = sql::decode_consensus_log_entry(&row.encoded)?;
                if decoded != row.entry {
                    return Err(invalid("native retained raw/typed log row differs"));
                }
                NativeLog::validate_entry_context(&decoded, identity, members)
            }
            Body::Selected(row) => {
                if row.authority != authority_binding(identity, members)? {
                    return Err(invalid("native selected log authority differs"));
                }
                Ok(())
            }
        }
    }

    /// Outside State only. Every selected byte range runs the complete
    /// arbitrary-byte codec, then compares all fixed facts and exact content.
    pub(in crate::consensus::native) fn read_bytes(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<RowBytes<'_>> {
        match &self.body {
            Body::Resident(row) => Ok(RowBytes::Resident(&row.encoded)),
            Body::Selected(row) => {
                self.validate_context(row.row.facts.id.index, identity, members)?;
                let input = row.range.read(check)?;
                let actual = generation::decode::inspect_log(
                    input.bytes(),
                    row.row.facts.id.index,
                    identity,
                    members,
                    check,
                )?;
                if actual.content != row.row.content
                    || actual.facts.id != row.row.facts.id
                    || actual.facts.membership != row.row.facts.membership
                {
                    return Err(invalid("native selected log differs from admitted row"));
                }
                Ok(RowBytes::Selected(input))
            }
        }
    }

    pub(in crate::consensus::native) fn validate_full(
        &self,
        index: u64,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.is_cold() {
            self.validate_context(index, identity, members)?;
            self.read_bytes(identity, members, check)?;
            Ok(())
        } else {
            scratch::log(self, check, || {
                self.validate_context(index, identity, members)
            })
        }
    }
}
