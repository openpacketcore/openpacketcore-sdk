//! Typed log bodies become selected ranges only after durable publication.
//! The compact form retains exact ID, content and fully decoded membership
//! facts. Its private authority binding prevents reuse in a different scope.

use super::*;
use crate::consensus::native::resident::{authority_binding, RowBytes, SelectedRange};

#[path = "export.rs"]
mod export;

#[derive(Clone)]
pub(crate) struct NativeLogEntry {
    body: Body,
    slots: bool,
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
    projection: Option<Arc<voter_slots::AdmittedProjection>>,
    projection_reclaimed: bool,
}

impl NativeLogEntry {
    #[cfg(test)]
    pub(in crate::consensus::native) fn slot_projection_bytes_for_test(&self) -> usize {
        match &self.body {
            Body::Selected(row) => row
                .projection
                .as_ref()
                .map_or(0, |projection| projection._memory.reserved_bytes_for_test()),
            Body::Resident(_) => 0,
        }
    }

    pub(in crate::consensus::native) fn is_slot_control(&self) -> bool {
        match &self.body {
            Body::Resident(row) => {
                matches!(&row.entry.payload, EntryPayload::Normal(command) if matches!(command.intent, SessionMutationIntent::VoterSlotControl(_)))
            }
            Body::Selected(row) => row.row.facts.slot_control,
        }
    }

    pub(in crate::consensus::native) fn slot_projection(
        &self,
        anchor: SessionConsensusIdentity,
    ) -> io::Result<Option<std::borrow::Cow<'_, voter_slots::Projection>>> {
        if !self.slots {
            return Err(invalid("native slot projection requires its profile"));
        }
        match &self.body {
            Body::Resident(row) => Ok(voter_slots::Projection::from_entry(&row.entry, anchor)?
                .map(std::borrow::Cow::Owned)),
            Body::Selected(row) => {
                if row.projection_reclaimed {
                    return Err(invalid(
                        "native applied slot projection cannot be reused as unapplied",
                    ));
                }
                Ok(row
                    .projection
                    .as_ref()
                    .map(|projection| std::borrow::Cow::Borrowed(&projection.value)))
            }
        }
    }
    pub(in crate::consensus::native) fn has_slot_projection(&self) -> bool {
        matches!(&self.body, Body::Selected(row) if row.projection.is_some())
    }

    // Preparation runs outside State. The immutable range, content, authority
    // and logical revision are unchanged; old captures retain their projection.
    pub(in crate::consensus::native) fn without_slot_projection(&self) -> io::Result<Self> {
        let Body::Selected(row) = &self.body else {
            return Err(invalid(
                "native projection retirement requires a selected row",
            ));
        };
        let mut row = row.clone();
        row.projection = None;
        row.projection_reclaimed = true;
        Ok(Self {
            body: Body::Selected(row),
            slots: self.slots,
        })
    }

    pub(in crate::consensus::native) fn relocation_allocation_bytes() -> usize {
        SharedRow::<Self>::relocated_allocation_bytes() + std::mem::size_of::<SelectedLog>()
    }

    #[cfg(test)]
    pub(in crate::consensus::native) fn new(
        encoded: Bytes,
        entry: Entry<SessionRaftTypeConfig>,
    ) -> Self {
        Self::new_with_profile(encoded, entry, false)
    }

    pub(in crate::consensus::native) fn new_with_profile(
        encoded: Bytes,
        entry: Entry<SessionRaftTypeConfig>,
        slots: bool,
    ) -> Self {
        Self {
            body: Body::Resident(Box::new(ResidentLog { encoded, entry })),
            slots,
        }
    }

    pub(in crate::consensus::native) fn slot_profile(&self) -> bool {
        self.slots
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

    pub(in crate::consensus::native) fn cold_read_order(&self) -> Option<(usize, u64)> {
        match &self.body {
            Body::Resident(_) => None,
            Body::Selected(row) => Some(row.range.cold_read_order()),
        }
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

    #[cfg(test)]
    pub(in crate::consensus::native) fn from_admitted_range(
        row: generation::facts::Row<generation::facts::Log>,
        source: std::sync::Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<Self> {
        Self::from_admitted_range_with_profile(
            row, source, offset, length, identity, members, false, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::consensus::native) fn from_admitted_range_with_profile(
        row: generation::facts::Row<generation::facts::Log>,
        source: std::sync::Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        slots: bool,
        applied: Option<LogId<SessionConsensusNodeId>>,
    ) -> io::Result<Self> {
        sql::validate_log_id(&row.facts.id)?;
        let range = SelectedRange::new(
            source,
            offset,
            length,
            sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
        )?;
        let projection_reclaimed = slots
            && (row.facts.slot_control || row.facts.membership.is_some())
            && applied.is_some_and(|cut| row.facts.id.index <= cut.index);
        let projection = if slots
            && !projection_reclaimed
            && (row.facts.slot_control || row.facts.membership.is_some())
        {
            let bytes = range.read(&|| Ok(()))?;
            let owned = generation::decode::owned_selected_log_profile(
                bytes.bytes(),
                row,
                identity,
                members,
                true,
                &|| Ok(()),
            )?;
            voter_slots::AdmittedProjection::from_entry(owned.entry(), identity)?
        } else {
            None
        };
        Ok(Self {
            slots,
            body: Body::Selected(Box::new(SelectedLog {
                range,
                row,
                authority: authority_binding(identity, members)?,
                projection,
                projection_reclaimed,
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
                NativeLog::validate_entry_profile(&decoded, identity, members, self.slots)
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
                let actual = generation::decode::inspect_log_profile(
                    input.bytes(),
                    row.row.facts.id.index,
                    identity,
                    members,
                    self.slots,
                    check,
                )?;
                if actual.content != row.row.content
                    || actual.facts.id != row.row.facts.id
                    || actual.facts.membership != row.row.facts.membership
                    || actual.facts.slot_control != row.row.facts.slot_control
                {
                    return Err(invalid("native selected log differs from admitted row"));
                }
                Ok(RowBytes::Selected(input))
            }
        }
    }

    /// Outside State only. Decode selected bytes once, retaining all admitted
    /// content, exact ID, membership and authority comparisons before copying.
    pub(in crate::consensus::native) fn read_owned(
        &self,
        index: u64,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<generation::decode::OwnedLog> {
        match &self.body {
            Body::Resident(row) => generation::decode::owned_log_profile(
                &row.encoded,
                index,
                identity,
                members,
                self.slots,
                check,
            ),
            Body::Selected(row) => {
                self.validate_context(index, identity, members)?;
                let input = row.range.read(check)?;
                generation::decode::owned_selected_log_profile(
                    input.bytes(),
                    row.row,
                    identity,
                    members,
                    self.slots,
                    check,
                )
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
