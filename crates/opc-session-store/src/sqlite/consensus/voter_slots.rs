//! Immutable cold profile seed and portable snapshot projection. Once opened,
//! the native owner is the only live authority for the table and log intent.

use super::*;
use opc_consensus::voter_slots::*;

#[cfg(target_os = "linux")]
pub(crate) type Admission = VoterAdmission<RaftVoterResponseFence<SessionRaftTypeConfig>>;

pub(crate) const COMMAND_VERSION: u16 = 2;

const TABLE: &str = "consensus_voter_slots";
const SCHEMA: &str = "CREATE TABLE consensus_voter_slots (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile_version INTEGER NOT NULL CHECK (profile_version = 1),
    genesis BLOB NOT NULL CHECK (typeof(genesis) = 'blob' AND length(genesis) BETWEEN 1 AND 65536),
    state BLOB NOT NULL CHECK (typeof(state) = 'blob' AND length(state) BETWEEN 1 AND 131072)
)";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Seed {
    pub(crate) genesis: VoterSlotTable,
    pub(crate) initial: VoterSlotTable,
}

impl Seed {
    pub(crate) fn genesis(genesis: VoterSlotTable) -> io::Result<Self> {
        encode_voter_slot_table(&genesis)
            .map_err(|_| invalid_data("invalid native voter-slot genesis"))?;
        if genesis.revision != 1
            || genesis.replacement.is_some()
            || genesis.slots.iter().any(|slot| {
                slot.phase != VoterSlotPhase::Voting
                    || slot.retired_through != 0
                    || slot.last_result.is_some()
            })
        {
            return Err(invalid_data("native voter-slot seed is not genesis"));
        }
        Ok(Self {
            initial: genesis.clone(),
            genesis,
        })
    }

    pub(crate) fn with_initial(
        genesis: VoterSlotTable,
        initial: VoterSlotTable,
    ) -> io::Result<Self> {
        let mut seed = Self::genesis(genesis)?;
        initial
            .validate_successor_of(&seed.genesis)
            .map_err(|_| invalid_data("native initial slot binding regressed"))?;
        seed.initial = initial;
        Ok(seed)
    }

    pub(crate) fn identity(&self) -> io::Result<SessionConsensusIdentity> {
        self.genesis
            .current_configuration()
            .identity(self.genesis.cluster_instance, self.genesis.manifest_digest)
            .map_err(|_| invalid_data("native voter-slot genesis identity invalid"))
    }

    pub(crate) fn members(&self) -> BTreeSet<SessionConsensusNodeId> {
        self.genesis
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect()
    }
}

pub(crate) fn read_seed(conn: &Connection) -> io::Result<Option<Seed>> {
    if !table_exists(conn, TABLE).map_err(db_error)? {
        return Ok(None);
    }
    let count: u64 = conn
        .query_row("SELECT COUNT(*) FROM consensus_voter_slots", [], |row| {
            row.get(0)
        })
        .map_err(db_error)?;
    let (version, length): (u64, u64) = conn.query_row("SELECT profile_version, length(genesis) FROM consensus_voter_slots WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?))).map_err(db_error)?;
    if count != 1 || version != 1 || !(1..=65536).contains(&length) {
        return Err(invalid_data("native voter-slot seed format differs"));
    }
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT genesis FROM consensus_voter_slots WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let genesis = decode_voter_slot_table(&bytes)
        .map_err(|_| invalid_data("native voter-slot seed corrupt"))?;
    let state = read_state_present(conn)?;
    Seed::with_initial(genesis, state.table().clone()).map(Some)
}

/// Called inside the ordinary identity transaction, before any schema upkeep.
/// A known legacy root cannot acquire this marker, and a legacy opener cannot
/// admit it. Rejecting either path leaves the complete root unchanged.
pub(super) fn initialize(
    conn: &Connection,
    identity_exists: bool,
    selected: Option<&Seed>,
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    profile: ConsensusAuthorityProfile,
) -> Result<(), SessionConsensusStorageError> {
    let stored = read_seed(conn).map_err(|_| SessionConsensusStorageError::CorruptState)?;
    match (selected, stored) {
        (None, None) => Ok(()),
        (Some(selected), Some(stored))
            if selected.genesis == stored.genesis
                && selected.identity().ok() == Some(identity)
                && selected.members() == *members
                && profile == ConsensusAuthorityProfile::FixedImmutable =>
        {
            Ok(())
        }
        (Some(selected), None)
            if !identity_exists
                && selected.identity().ok() == Some(identity)
                && selected.members() == *members
                && profile == ConsensusAuthorityProfile::FixedImmutable =>
        {
            conn.execute_batch(SCHEMA)
                .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
            let bytes = encode_voter_slot_table(&selected.genesis)
                .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
            let state = VoterSlotDurableState::new(selected.initial.clone())
                .and_then(|state| state.encode())
                .map_err(|_| SessionConsensusStorageError::InvalidIdentity)?;
            conn.execute("INSERT INTO consensus_voter_slots (singleton, profile_version, genesis, state) VALUES (1, 1, ?1, ?2)", params![bytes, state]).map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
            Ok(())
        }
        (Some(_), Some(_)) => Err(SessionConsensusStorageError::IdentityMismatch),
        _ => Err(SessionConsensusStorageError::SchemaVersionMismatch),
    }
}

fn read_state_present(conn: &Connection) -> io::Result<VoterSlotDurableState> {
    let length: u64 = conn
        .query_row(
            "SELECT length(state) FROM consensus_voter_slots WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if !(1..=131072).contains(&length) {
        return Err(invalid_data("native voter-slot projection exceeds bound"));
    }
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT state FROM consensus_voter_slots WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    VoterSlotDurableState::decode(&bytes)
        .map_err(|_| invalid_data("native voter-slot projection corrupt"))
}

pub(crate) fn read_state(conn: &Connection) -> io::Result<Option<VoterSlotDurableState>> {
    if read_seed(conn)?.is_none() {
        return Ok(None);
    }
    read_state_present(conn).map(Some)
}

/// Export/install only, on a disposable image or inside the install transaction.
/// Live admission never queries this projection.
pub(crate) fn write_state(
    conn: &Connection,
    genesis: &VoterSlotTable,
    state: &VoterSlotDurableState,
) -> io::Result<()> {
    let seed = read_seed(conn)?.ok_or_else(|| invalid_data("native voter-slot profile absent"))?;
    if seed.genesis != *genesis {
        return Err(invalid_data("native voter-slot projection genesis differs"));
    }
    state
        .table()
        .validate_successor_of(genesis)
        .map_err(|_| invalid_data("native voter-slot projection regressed"))?;
    let bytes = state
        .encode()
        .map_err(|_| invalid_data("native voter-slot projection invalid"))?;
    let changed = conn
        .execute(
            "UPDATE consensus_voter_slots SET state = ?1 WHERE singleton = 1",
            [bytes],
        )
        .map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data(
            "native voter-slot projection singleton absent",
        ));
    }
    Ok(())
}

pub(crate) fn preflight(
    conn: &Connection,
    selected: Option<&Seed>,
) -> Result<bool, SessionConsensusStorageError> {
    let retained = read_seed(conn).map_err(|_| SessionConsensusStorageError::CorruptState)?;
    match (selected, retained.as_ref()) {
        (None, None) => Ok(false),
        (Some(selected), Some(retained)) if selected.genesis == retained.genesis => Ok(true),
        (Some(_), None)
            if !table_exists(conn, "consensus_identity")
                .map_err(|_| SessionConsensusStorageError::CorruptState)? =>
        {
            Ok(true)
        }
        _ => Err(SessionConsensusStorageError::SchemaVersionMismatch),
    }
}

pub(crate) fn cut(id: LogId<SessionConsensusNodeId>) -> VoterSlotLogId {
    VoterSlotLogId {
        term: id.leader_id.term,
        index: id.index,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn engine_cut(id: VoterSlotLogId) -> LogId<SessionConsensusNodeId> {
    // The pinned single-term-leader engine discards the node argument, just
    // as its own LeaderId::to_committed does. Only term and index are evidence.
    LogId::new(
        opc_consensus::engine::CommittedLeaderId::new(id.term, SessionConsensusNodeId::default()),
        id.index,
    )
}

pub(crate) fn known_node(table: &VoterSlotTable, node: SessionConsensusNodeId) -> bool {
    VoterSlotIdentity::from_node_id(node)
        .ok()
        .is_some_and(|id| {
            table.slots.iter().any(|slot| {
                slot.member.identity.slot() == id.slot()
                    && id.incarnation() <= slot.member.identity.incarnation()
            })
        })
}

/// Historical membership is evidence, never current voting permission. Every
/// configuration preserves the enrolled slot denominator and bounded incarnations.
pub(crate) fn historical_membership(
    table: &VoterSlotTable,
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    let expected: BTreeSet<_> = table
        .slots
        .iter()
        .map(|slot| slot.member.identity.slot())
        .collect();
    let configs = membership.membership().get_joint_config();
    let membership_id = membership
        .log_id()
        .ok_or_else(|| invalid_data("voter-slot historical membership cut absent"))?;
    if !(1..=2).contains(&configs.len())
        || membership.nodes().count() > expected.len() + 1
        || membership
            .nodes()
            .any(|(node, _)| !known_node(table, *node))
        || configs.iter().any(|config| {
            config.len() != expected.len()
                || config
                    .iter()
                    .filter_map(|node| {
                        VoterSlotIdentity::from_node_id(*node)
                            .ok()
                            .map(|id| id.slot())
                    })
                    .collect::<BTreeSet<_>>()
                    != expected
                || config
                    .iter()
                    .any(|node| membership.membership().get_node(node).is_none())
        })
    {
        return Err(invalid_data("voter-slot historical membership invalid"));
    }
    validate_log_id(&membership_id)?;
    Ok(())
}

pub(crate) fn current_membership(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
) -> io::Result<()> {
    let state = read_state(conn)?.ok_or_else(|| invalid_data("voter-slot profile missing"))?;
    let applied = read_applied_sync(conn, identity)?;
    if is_pristine_membership(membership) && applied.is_none() {
        if state.table().revision == 1
            || state
                .table()
                .replacement
                .as_ref()
                .is_some_and(|operation| operation.phase == VoterReplacementPhase::Prepared)
        {
            return Ok(());
        }
        return Err(invalid_data("unapplied voter-slot binding invalid"));
    }
    historical_membership(state.table(), membership)?;
    let membership_id = membership
        .log_id()
        .ok_or_else(|| invalid_data("voter membership cut absent"))?;
    let applied = applied.ok_or_else(|| invalid_data("voter membership lacks applied cut"))?;
    ensure_log_id_not_after(
        &membership_id,
        &applied,
        "voter membership exceeds applied cut",
    )?;
    let mut durable = VoterSlotDurableState::new(state.table().clone())
        .map_err(|_| invalid_data("voter table invalid"))?;
    durable
        .publish_applied(state.table().clone(), cut(applied))
        .map_err(|_| invalid_data("voter table exceeds applied cut"))?;
    let mut projected = state.table().clone();
    projected
        .observe_membership(
            membership.membership().get_joint_config(),
            &membership.nodes().map(|(node, _)| *node).collect(),
            cut(membership_id),
        )
        .map_err(|_| invalid_data("voter membership differs from committed phase"))?;
    if projected != *state.table() {
        return Err(invalid_data("voter membership phase not applied"));
    }
    Ok(())
}

pub(crate) fn snapshot_metadata(
    table: &VoterSlotTable,
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
) -> io::Result<()> {
    if is_pristine_membership(&meta.last_membership) && meta.last_log_id.is_none() {
        return Ok(());
    }
    historical_membership(table, &meta.last_membership)?;
    let membership_id = meta
        .last_membership
        .log_id()
        .ok_or_else(|| invalid_data("voter snapshot membership cut absent"))?;
    ensure_log_id_not_after(
        &membership_id,
        meta.last_log_id
            .as_ref()
            .ok_or_else(|| invalid_data("voter snapshot cut absent"))?,
        "voter snapshot membership exceeds cut",
    )
}

pub(crate) fn validate_command(
    command: &SessionConsensusCommand,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    if let SessionMutationIntent::VoterSlotControl(bytes) = &command.intent {
        if command.schema_version != COMMAND_VERSION || command.identity != identity {
            return Err(invalid_data("voter command profile differs"));
        }
        VoterSlotControl::decode(bytes).map_err(|_| invalid_data("voter control corrupt"))?;
        return Ok(());
    }
    validate_command_for_log(command, identity)
}

pub(crate) fn project_entry(
    table: &mut VoterSlotTable,
    entry: &Entry<SessionRaftTypeConfig>,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Blank => {}
        EntryPayload::Normal(command) => {
            validate_command(command, identity)?;
            if let SessionMutationIntent::VoterSlotControl(bytes) = &command.intent {
                let control = VoterSlotControl::decode(bytes)
                    .map_err(|_| invalid_data("voter control corrupt"))?;
                let _ = table.apply_control(&control, cut(entry.log_id));
            } else if fixed_profile_intent_changes_topology(&command.intent) {
                return Err(invalid_data(
                    "voter profile forbids dynamic topology control",
                ));
            }
        }
        EntryPayload::Membership(membership) => {
            table
                .observe_membership(
                    membership.get_joint_config(),
                    &membership.nodes().map(|(node, _)| *node).collect(),
                    cut(entry.log_id),
                )
                .map_err(|_| invalid_data("voter projected membership invalid"))?;
        }
    }
    Ok(())
}

fn read_row(
    row: &rusqlite::Row<'_>,
    identity: SessionConsensusIdentity,
) -> io::Result<Entry<SessionRaftTypeConfig>> {
    let epoch: i64 = row.get(0).map_err(db_error)?;
    let term: u64 = row.get(1).map_err(db_error)?;
    let index: u64 = row.get(2).map_err(db_error)?;
    let bytes = match row.get_ref(3).map_err(db_error)? {
        rusqlite::types::ValueRef::Blob(bytes) | rusqlite::types::ValueRef::Text(bytes) => bytes,
        _ => return Err(invalid_data("voter log row is not encoded bytes")),
    };
    if bytes.len() > SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES {
        return Err(invalid_data("voter log row exceeds bound"));
    }
    validate_epoch(epoch, identity)?;
    let entry = decode_consensus_log_entry(bytes)?;
    validate_log_id(&entry.log_id)?;
    if entry.log_id.leader_id.term != term || entry.log_id.index != index {
        return Err(invalid_data("voter log row identity differs"));
    }
    if let EntryPayload::Normal(command) = &entry.payload {
        validate_command(command, identity)?;
    }
    Ok(entry)
}

/// Strict, detached-image scan used by snapshot install and native conversion.
/// The live WAL never uses this SQL projection as admission authority.
pub(super) fn visit_range(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    options: LogRangeReadOptions,
    mut visit: impl FnMut(Entry<SessionRaftTypeConfig>),
) -> io::Result<()> {
    let state = read_state(conn)?.ok_or_else(|| invalid_data("voter slot state missing"))?;
    let applied = read_applied_sync(conn, identity)?;
    let mut projected = state.table().clone();
    let prefix = applied.map_or(0, |cut| cut.index.saturating_add(1));
    let mut pending = None;
    let mut statement = conn.prepare("SELECT configuration_epoch,term,log_index,entry_json FROM consensus_log WHERE log_index >= ?1 ORDER BY log_index").map_err(db_error)?;
    let mut rows = statement
        .query([prefix.min(options.start)])
        .map_err(db_error)?;
    let mut previous =
        read_purged_sync(conn, identity)?.filter(|cut| cut.index < prefix.min(options.start));
    let mut expected = previous
        .map_or(0, |id| id.index + 1)
        .max(prefix.min(options.start));
    let mut returned = 0;
    let mut batch = options
        .append_entries_batch
        .then(AppendEntriesBatchAccumulator::new);
    let mut first = true;
    while let Some(row) = rows.next().map_err(db_error)? {
        let entry = read_row(row, identity)?;
        if first && options.recovery_profile.scans_physical_retained_suffix() && previous.is_none()
        {
            expected = entry.log_id.index;
        }
        if entry.log_id.index != expected {
            return Err(invalid_data("voter log range contains hole"));
        }
        if let Some(previous) = previous {
            ensure_log_id_not_after(&previous, &entry.log_id, "voter log order regressed")?;
        }
        if applied.is_none_or(|cut| entry.log_id.index > cut.index) {
            let before = projected.clone();
            project_entry(&mut projected, &entry, identity)?;
            if let EntryPayload::Normal(command) = &entry.payload {
                if let SessionMutationIntent::VoterSlotControl(bytes) = &command.intent {
                    if matches!(
                        VoterSlotControl::decode(bytes),
                        Ok(VoterSlotControl::Begin(_))
                    ) && projected != before
                    {
                        if pending.replace(cut(entry.log_id)).is_some() {
                            return Err(invalid_data("multiple voter intents retained"));
                        }
                        if state
                            .intent()
                            .is_none_or(|intent| intent.log_id != cut(entry.log_id))
                        {
                            return Err(invalid_data("voter intent missing its cut"));
                        }
                    }
                }
            }
        } else if let EntryPayload::Membership(membership) = &entry.payload {
            historical_membership(
                state.table(),
                &StoredMembership::new(Some(entry.log_id), membership.clone()),
            )?;
        }
        previous = Some(entry.log_id);
        expected = entry
            .log_id
            .index
            .checked_add(1)
            .ok_or_else(|| invalid_data("voter log exhausted"))?;
        first = false;
        if entry.log_id.index < options.start {
            continue;
        }
        if options.end.is_some_and(|end| entry.log_id.index >= end)
            || options.limit.is_some_and(|limit| returned >= limit)
        {
            break;
        }
        let decision = batch
            .as_mut()
            .map(|batch| {
                batch
                    .consider(&entry)
                    .map_err(|_| invalid_data("voter log batch exceeds bound"))
            })
            .transpose()?;
        match decision {
            Some(AppendEntriesBatchDecision::StopBefore) => break,
            Some(AppendEntriesBatchDecision::IncludeAndStop) => {
                visit(entry);
                break;
            }
            _ => {
                visit(entry);
                returned += 1;
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_full(
    conn: &Connection,
    identity: SessionConsensusIdentity,
) -> io::Result<()> {
    let state = read_state(conn)?.ok_or_else(|| invalid_data("voter state absent"))?;
    if let Some(intent) = state.intent() {
        if read_applied_sync(conn, identity)?
            .is_some_and(|applied| intent.log_id.index <= applied.index)
        {
            return Err(invalid_data("voter intent is applied"));
        }
        let entry = conn.query_row("SELECT configuration_epoch,term,log_index,entry_json FROM consensus_log WHERE log_index=?1", [intent.log_id.index], |row| Ok(read_row(row, identity))).map_err(db_error)??;
        let EntryPayload::Normal(command) = &entry.payload else {
            return Err(invalid_data("voter intent row displaced"));
        };
        let SessionMutationIntent::VoterSlotControl(bytes) = &command.intent else {
            return Err(invalid_data("voter intent command displaced"));
        };
        if cut(entry.log_id) != intent.log_id
            || VoterSlotControl::decode(bytes).ok()
                != Some(VoterSlotControl::Begin(Box::new(intent.request.clone())))
        {
            return Err(invalid_data("voter intent request differs"));
        }
    }
    let start = logical_log_start(conn, identity, 0)?;
    visit_range(
        conn,
        identity,
        LogRangeReadOptions {
            start,
            end: None,
            limit: None,
            append_entries_batch: false,
            recovery_profile: LogRangeRecoveryProfile::Strict,
        },
        |_| {},
    )?;
    validate_retained_durable_log_sync(conn, identity, |_| Ok(()))
}
