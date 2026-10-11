//! The committed table belongs to native business publication. The provisional
//! cut belongs to native log publication, and names its exact retained Begin.
//! Both are covered by the WAL operation and selected-generation commitments.

use super::*;
use opc_consensus::voter_slots::*;

pub(crate) const COMMAND_VERSION: u16 = crate::sqlite::consensus::voter_slots::COMMAND_VERSION;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Table {
    pub(super) genesis: Arc<VoterSlotTable>,
    pub(super) current: VoterSlotTable,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TableWire {
    genesis: Vec<u8>,
    current: Vec<u8>,
}

impl Serialize for Table {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        TableWire {
            genesis: encode_voter_slot_table(&self.genesis).map_err(serde::ser::Error::custom)?,
            current: encode_voter_slot_table(&self.current).map_err(serde::ser::Error::custom)?,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Table {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let wire = TableWire::deserialize(decoder)?;
        let genesis = decode_voter_slot_table(&wire.genesis).map_err(serde::de::Error::custom)?;
        let current = decode_voter_slot_table(&wire.current).map_err(serde::de::Error::custom)?;
        current
            .validate_successor_of(&genesis)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            genesis: Arc::new(genesis),
            current,
        })
    }
}

pub(super) fn cut(id: LogId<SessionConsensusNodeId>) -> VoterSlotLogId {
    VoterSlotLogId {
        term: id.leader_id.term,
        index: id.index,
    }
}

/// Small authority-bearing rows stay decoded when ordinary log bodies become
/// selected ranges. Native WAL publication therefore never does disk I/O while
/// projecting an unapplied membership/control prefix under the owner mutex.
#[derive(Clone)]
pub(super) enum Projection {
    Control(SessionConsensusIdentity, VoterSlotControl),
    Membership(opc_consensus::engine::Membership<SessionConsensusNodeId, EmptyNode>),
}

pub(super) struct AdmittedProjection {
    pub(super) value: Projection,
    pub(super) _memory: crate::consensus::verified_snapshot::VerificationMemory,
}

impl AdmittedProjection {
    pub(super) fn from_entry(
        entry: &Entry<SessionRaftTypeConfig>,
        anchor: SessionConsensusIdentity,
    ) -> io::Result<Option<Arc<Self>>> {
        use crate::consensus::verified_snapshot::VerificationMemory;
        use std::mem::size_of;
        // Account for the concrete projection Arc and its cache-index tree
        // entry (including slack in imbl's 16-entry index nodes). Variable
        // strings are bounded by their canonical control bytes; membership
        // allocation follows the actual node/configuration counts.
        let fixed = size_of::<Self>()
            + size_of::<[usize; 8]>()
            + 32 * size_of::<(u64, SharedRow<log::NativeLogEntry>)>();
        let membership_bytes =
            |membership: &opc_consensus::engine::Membership<SessionConsensusNodeId, EmptyNode>| {
                membership.get_joint_config().len() * size_of::<BTreeSet<SessionConsensusNodeId>>()
                    + 8 * size_of::<(SessionConsensusNodeId, usize)>()
                        * (membership.nodes().count()
                            + membership
                                .get_joint_config()
                                .iter()
                                .map(BTreeSet::len)
                                .sum::<usize>())
            };
        let allowance = match &entry.payload {
            EntryPayload::Normal(command) => match &command.intent {
                SessionMutationIntent::VoterSlotControl(bytes) => {
                    size_of::<VoterReplacementRequest>() + bytes.len()
                }
                _ => return Ok(None),
            },
            EntryPayload::Membership(membership) => membership_bytes(membership),
            EntryPayload::Blank => return Ok(None),
        };
        let mut memory = VerificationMemory::reserve(fixed + allowance)?;
        let Some(value) = Projection::from_entry(entry, anchor)? else {
            return Ok(None);
        };
        let variable = match &value {
            Projection::Control(_, VoterSlotControl::Begin(request)) => {
                size_of::<VoterReplacementRequest>()
                    + request.attestation.candidate_spiffe_id.capacity()
                    + request.attestation.controller_spiffe_id.capacity()
            }
            Projection::Control(
                _,
                VoterSlotControl::Advance {
                    step: VoterReplacementStep::RecordSnapshot(evidence),
                    ..
                },
            ) => evidence.snapshot_id.capacity(),
            Projection::Control(_, _) => 0,
            Projection::Membership(membership) => membership_bytes(membership),
        };
        memory.shrink_to(fixed + variable)?;
        Ok(Some(Arc::new(Self {
            value,
            _memory: memory,
        })))
    }
}

impl Projection {
    pub(super) fn from_entry(
        entry: &Entry<SessionRaftTypeConfig>,
        anchor: SessionConsensusIdentity,
    ) -> io::Result<Option<Self>> {
        match &entry.payload {
            EntryPayload::Normal(command) => Ok(control(command, anchor)?
                .filter(|control| !matches!(control, VoterSlotControl::Marker { .. }))
                .map(|control| Self::Control(anchor, control))),
            EntryPayload::Membership(membership) => Ok(Some(Self::Membership(membership.clone()))),
            EntryPayload::Blank => Ok(None),
        }
    }

    pub(super) fn apply(
        &self,
        table: &mut VoterSlotTable,
        log: LogId<SessionConsensusNodeId>,
        anchor: SessionConsensusIdentity,
    ) -> io::Result<()> {
        match self {
            Self::Control(identity, control) => {
                if *identity != anchor {
                    return Err(invalid("native slot projection anchor differs"));
                }
                let _ = table.apply_control(control, cut(log));
            }
            Self::Membership(membership) => {
                table
                    .observe_membership(
                        membership.get_joint_config(),
                        &membership.nodes().map(|(id, _)| *id).collect(),
                        cut(log),
                    )
                    .map_err(|_| invalid("native projected slot membership invalid"))?;
            }
        }
        Ok(())
    }

    pub(super) fn begin(&self) -> Option<&VoterReplacementRequest> {
        match self {
            Self::Control(_, VoterSlotControl::Begin(request)) => Some(request),
            _ => None,
        }
    }
}

impl NativeStorage {
    pub(crate) fn has_voter_slots(&self) -> bool {
        self.business.frontiers.voter_slots.is_some()
    }

    #[cfg(test)]
    pub(crate) fn empty_with_voter_slots(initial: VoterSlotTable) -> io::Result<Self> {
        Self::empty_with_voter_slot_binding(initial.clone(), initial)
    }

    pub(crate) fn empty_with_voter_slot_binding(
        genesis: VoterSlotTable,
        initial: VoterSlotTable,
    ) -> io::Result<Self> {
        let seed = crate::sqlite::consensus::voter_slots::Seed::with_initial(genesis, initial)?;
        if !initial_binding(&seed.initial, &seed.genesis) {
            return Err(invalid(
                "native fresh slot binding must be genesis or a selected Pending candidate",
            ));
        }
        let identity = seed.identity()?;
        let members = seed.members();
        let business = NativeState::empty_with_slots(
            identity,
            members,
            None,
            Some(Table {
                genesis: Arc::new(seed.genesis),
                current: seed.initial,
            }),
        )?;
        let mut log = log::NativeLog::default();
        log.admit(&business)?;
        Ok(Self { business, log })
    }

    /// A reader captures the durable WAL publication before resolving cold rows.
    /// Metrics and the immutable SQL seed never provide these admission facts.
    pub(crate) fn voter_slot_state(&self) -> io::Result<VoterSlotDurableState> {
        self.log.slot_state(&self.business)
    }

    /// Reopening retains the immutable genesis anchor while membership may
    /// already describe a later incarnation or an unfinished joint transition.
    pub(crate) fn validate_voter_slot_open(&self) -> io::Result<()> {
        validate_frontiers(
            self.business.identity,
            &self.business.members,
            &self.business.frontiers,
        )?;
        self.log.validate_slot_intent(&self.business)
    }

    pub(crate) fn voter_slots_before(
        &self,
        end: u64,
    ) -> io::Result<(Option<LogId<SessionConsensusNodeId>>, VoterSlotTable)> {
        Ok((
            self.business.applied(),
            self.log
                .slots_before(&self.business, end)?
                .ok_or_else(|| invalid("native voter-slot profile missing"))?,
        ))
    }
}

impl log::NativeLog {
    pub(super) fn slot_state(&self, state: &NativeState) -> io::Result<VoterSlotDurableState> {
        let table = state
            .frontiers
            .voter_slots
            .as_ref()
            .ok_or_else(|| invalid("native store is not a voter-slot profile"))?
            .current
            .clone();
        let intent = self
            .slot_intent
            .filter(|id| {
                state
                    .applied()
                    .is_none_or(|applied| id.index > applied.index)
            })
            .map(|id| -> io::Result<VoterSlotIntent> {
                let row = self
                    .entries
                    .get(&id.index)
                    .filter(|row| row.id() == id)
                    .ok_or_else(|| invalid("native provisional cut lacks exact log row"))?;
                let projection = row.slot_projection(state.identity)?;
                let request = projection
                    .as_deref()
                    .and_then(Projection::begin)
                    .ok_or_else(|| invalid("native provisional cut is not Prepare"))?;
                Ok(VoterSlotIntent {
                    log_id: cut(id),
                    request: request.clone(),
                })
            })
            .transpose()?;
        VoterSlotDurableState::restore(table, intent)
            .map_err(|_| invalid("native provisional state invalid"))
    }

    /// Checked simulation of real unapplied entries. It grants no authority.
    pub(super) fn slots_before(
        &self,
        state: &NativeState,
        end: u64,
    ) -> io::Result<Option<VoterSlotTable>> {
        let Some(table) = &state.frontiers.voter_slots else {
            return Ok(None);
        };
        let mut projected = table.current.clone();
        let start = state.applied().map_or(0, |id| id.index + 1);
        if start < end {
            for (_, row) in self.entries.range(start..end) {
                if let Some(projection) = row.slot_projection(state.identity)? {
                    projection.apply(&mut projected, row.id(), state.identity)?;
                }
            }
        }
        Ok(Some(projected))
    }

    pub(super) fn validate_slot_intent(&self, state: &NativeState) -> io::Result<()> {
        if state.frontiers.voter_slots.is_none() {
            return if self.slot_intent.is_none() {
                Ok(())
            } else {
                Err(invalid("legacy native profile carries an intent"))
            };
        }
        let durable = self.slot_state(state)?;
        let mut projected = durable.table().clone();
        let start = state.applied().map_or(0, |id| id.index + 1);
        for (_, row) in self.entries.range(start..) {
            let before = projected.clone();
            let projection = row.slot_projection(state.identity)?;
            let begin = projection
                .as_deref()
                .is_some_and(|projection| projection.begin().is_some());
            if let Some(projection) = projection {
                projection.apply(&mut projected, row.id(), state.identity)?;
            }
            if begin && projected != before && self.slot_intent != Some(row.id()) {
                return Err(invalid("native Prepare lacks its durable provisional cut"));
            }
        }
        Ok(())
    }
}

pub(super) fn control(
    command: &SessionConsensusCommand,
    anchor: SessionConsensusIdentity,
) -> io::Result<Option<VoterSlotControl>> {
    let SessionMutationIntent::VoterSlotControl(bytes) = &command.intent else {
        return Ok(None);
    };
    if command.schema_version != COMMAND_VERSION || command.identity != anchor {
        return Err(invalid("native slot command profile differs"));
    }
    VoterSlotControl::decode(bytes)
        .map(Some)
        .map_err(|_| invalid("native slot command invalid"))
}

pub(crate) fn project(
    table: &mut VoterSlotTable,
    entry: &Entry<SessionRaftTypeConfig>,
    anchor: SessionConsensusIdentity,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => {
            if let Some(control) = control(command, anchor)? {
                // Valid stale CAS and phase refusals are deterministic NoEffect.
                let _ = table.apply_control(&control, cut(entry.log_id));
            }
        }
        EntryPayload::Membership(membership) => {
            table
                .observe_membership(
                    membership.get_joint_config(),
                    &membership.nodes().map(|(id, _)| *id).collect(),
                    cut(entry.log_id),
                )
                .map_err(|_| invalid("native projected slot membership invalid"))?;
        }
        EntryPayload::Blank => {}
    }
    Ok(())
}

pub(super) fn known_node(table: &VoterSlotTable, node: SessionConsensusNodeId) -> bool {
    VoterSlotIdentity::from_node_id(node)
        .ok()
        .is_some_and(|id| {
            table.slots.iter().any(|slot| {
                slot.member.identity.slot() == id.slot()
                    && id.incarnation() <= slot.member.identity.incarnation()
            })
        })
}

pub(super) fn validate_frontiers(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    let Some(bound) = &frontiers.voter_slots else {
        return Ok(());
    };
    let table = &bound.current;
    if bound.genesis.revision != 1
        || bound.genesis.replacement.is_some()
        || bound.genesis.slots.iter().any(|slot| {
            slot.retired_through != 0
                || slot.last_result.is_some()
                || slot.phase != VoterSlotPhase::Voting
        })
        || bound
            .genesis
            .current_configuration()
            .identity(
                bound.genesis.cluster_instance,
                bound.genesis.manifest_digest,
            )
            .map_err(|_| invalid("native slot genesis identity invalid"))?
            != identity
        || bound
            .genesis
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect::<BTreeSet<_>>()
            != *members
    {
        return Err(invalid("native slot genesis differs from immutable anchor"));
    }
    table
        .validate_successor_of(&bound.genesis)
        .map_err(|_| invalid("native slot table regressed from genesis"))?;
    encode_voter_slot_table(table).map_err(|_| invalid("native committed slots invalid"))?;
    let slots: BTreeSet<_> = members
        .iter()
        .map(|node| VoterSlotIdentity::from_node_id(*node).map(|id| id.slot()))
        .collect::<Result<_, _>>()
        .map_err(|_| invalid("native slot anchor invalid"))?;
    if table.cluster_instance != identity.cluster_id()
        || slots
            != table
                .slots
                .iter()
                .map(|slot| slot.member.identity.slot())
                .collect()
        || frontiers.async_recovery.is_some()
    {
        return Err(invalid("native slot profile anchor differs"));
    }
    if let Some(applied) = frontiers.applied {
        VoterSlotDurableState::new(table.clone())
            .and_then(|mut state| state.publish_applied(table.clone(), cut(applied)))
            .map_err(|_| invalid("native slot table exceeds applied cut"))?;
        let mut checked = table.clone();
        checked
            .observe_membership(
                frontiers.membership.membership().get_joint_config(),
                &frontiers.membership.nodes().map(|(id, _)| *id).collect(),
                cut(*frontiers
                    .membership
                    .log_id()
                    .as_ref()
                    .ok_or_else(|| invalid("native slot membership cut missing"))?),
            )
            .map_err(|_| invalid("native applied slot membership invalid"))?;
        if checked != *table {
            return Err(invalid("native membership phase was not published"));
        }
    } else if !initial_binding(table, &bound.genesis) || frontiers.membership.log_id().is_some() {
        return Err(invalid(
            "native unapplied slot binding is not a selected Pending candidate",
        ));
    }
    Ok(())
}

fn initial_binding(table: &VoterSlotTable, genesis: &VoterSlotTable) -> bool {
    table == genesis
        || table.replacement.as_ref().is_some_and(|operation| {
            operation.phase == VoterReplacementPhase::Prepared
                && table
                    .slots
                    .iter()
                    .find(|slot| slot.member.identity.slot() == operation.attestation.slot)
                    .is_some_and(|slot| slot.phase == VoterSlotPhase::Pending)
        })
}
