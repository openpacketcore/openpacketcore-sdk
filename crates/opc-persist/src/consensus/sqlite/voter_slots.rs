//! Transaction-owned slot state. Runtime fencing precedes these storage callbacks.

use super::*;
use crate::consensus::ConfigConsensusCommand;
use opc_consensus::voter_slots::*;

pub(super) fn cut(log: LogId<ConsensusNodeId>) -> VoterSlotLogId {
    VoterSlotLogId {
        term: log.leader_id.term,
        index: log.index,
    }
}

pub(crate) fn read_sync(conn: &Connection) -> io::Result<Option<VoterSlotDurableState>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT state FROM config_raft_voter_slots WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    bytes
        .map(|bytes| {
            VoterSlotDurableState::decode(&bytes)
                .map_err(|_| invalid_data("invalid durable config voter slots"))
        })
        .transpose()
}

pub(super) fn write_sync(conn: &Connection, state: &VoterSlotDurableState) -> io::Result<()> {
    let bytes = state
        .encode()
        .map_err(|_| invalid_data("invalid durable config voter slots"))?;
    conn.execute(
        "INSERT OR REPLACE INTO config_raft_voter_slots (singleton, state) VALUES (1, ?1)",
        [bytes],
    )
    .map_err(db_error)?;
    Ok(())
}

pub(super) fn initialize_sync(
    conn: &Connection,
    initial: Option<&VoterSlotTable>,
) -> io::Result<()> {
    if let Some(initial) = initial {
        write_sync(
            conn,
            &VoterSlotDurableState::new(initial.clone())
                .map_err(|_| invalid_data("invalid initial config voter slots"))?,
        )?;
    }
    Ok(())
}

pub(super) fn validate_profile_sync(
    conn: &Connection,
    initial: Option<&VoterSlotTable>,
) -> Result<(), ConfigConsensusStorageError> {
    match (
        read_sync(conn).map_err(|_| ConfigConsensusStorageError::CorruptState)?,
        initial,
    ) {
        (None, None) => Ok(()),
        (Some(current), Some(initial)) => {
            current
                .table()
                .validate_successor_of(initial)
                .map_err(|_| ConfigConsensusStorageError::IdentityMismatch)?;
            let identity = initial
                .current_configuration()
                .identity(initial.cluster_instance, initial.manifest_digest)
                .map_err(|_| ConfigConsensusStorageError::IdentityMismatch)?;
            validate_intent_log_sync(conn, identity, &current)
                .map_err(|_| ConfigConsensusStorageError::CorruptState)
        }
        _ => Err(ConfigConsensusStorageError::IdentityMismatch),
    }
}

// A decoded intent alone is not restart evidence. It must name an exact retained
// log record, and every effective unapplied Begin must have that durable fence.
// Replay only the unapplied suffix, retaining a now-no-effect intent until its
// own entry is applied or durably displaced by the engine.
fn validate_intent_log_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    state: &VoterSlotDurableState,
) -> io::Result<()> {
    let start = read_applied_sync(conn, identity)?.map_or(Ok(0), |cut| {
        cut.index
            .checked_add(1)
            .ok_or_else(|| invalid_data("config applied index exhausted"))
    })?;
    let mut statement = conn.prepare("SELECT term, log_index, entry_json FROM config_raft_log WHERE log_index >= ?1 ORDER BY log_index").map_err(db_error)?;
    let rows = statement
        .query_map([checked_i64(start)?], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(db_error)?;
    let mut projected = state.table().clone();
    let mut found = false;
    for row in rows {
        let (term, index, bytes) = row.map_err(db_error)?;
        if bytes.len() > CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(invalid_data("config voter log entry exceeds bound"));
        }
        let entry: Entry<ConfigRaftTypeConfig> = decode_json(&bytes)?;
        if entry.log_id.index != checked_u64(index)?
            || entry.log_id.leader_id.term != checked_u64(term)?
        {
            return Err(invalid_data("config voter intent log identity mismatch"));
        }
        match entry.payload {
            EntryPayload::Normal(command) => {
                if let ConfigMutationIntent::VoterSlotControl(bytes) = command.intent {
                    let control = VoterSlotControl::decode(&bytes)
                        .map_err(|_| invalid_data("invalid config voter control"))?;
                    let exact = match &control {
                        VoterSlotControl::Begin(request) => state.intent().is_some_and(|intent| {
                            intent.log_id == cut(entry.log_id) && intent.request == **request
                        }),
                        _ => false,
                    };
                    found |= exact;
                    let before = projected.clone();
                    let applied = projected.apply_control(&control, cut(entry.log_id));
                    if matches!(control, VoterSlotControl::Begin(_))
                        && applied.is_ok()
                        && projected != before
                        && !exact
                    {
                        return Err(invalid_data(
                            "config voter Prepare lacks its durable intent",
                        ));
                    }
                }
            }
            EntryPayload::Membership(membership) => {
                projected
                    .observe_membership(
                        membership.get_joint_config(),
                        &membership.nodes().map(|(node, _)| *node).collect(),
                        cut(entry.log_id),
                    )
                    .map_err(|_| invalid_data("invalid projected config membership"))?;
            }
            EntryPayload::Blank => {}
        }
    }
    if state.intent().is_some() != found {
        return Err(invalid_data(
            "config voter intent lacks its retained Prepare",
        ));
    }
    Ok(())
}

/// Durable historic entries may name retired IDs; admission never uses this predicate.
pub(super) fn historical_node(table: &VoterSlotTable, node: ConsensusNodeId) -> bool {
    let Ok(id) = VoterSlotIdentity::from_node_id(node) else {
        return false;
    };
    table.slots.iter().any(|slot| {
        slot.member.identity.slot() == id.slot()
            && id.incarnation() <= slot.member.identity.incarnation()
    })
}

pub(super) fn validate_membership_sync(
    conn: &Connection,
    membership: &StoredMembership<ConsensusNodeId, EmptyNode>,
    expected: &BTreeSet<ConsensusNodeId>,
    historical: bool,
) -> io::Result<()> {
    let Some(state) = read_sync(conn)? else {
        return validate_fixed_membership(membership, expected);
    };
    let table = state.table();
    let nodes: BTreeSet<_> = membership.nodes().map(|(node, _)| *node).collect();
    if historical {
        let slots: BTreeSet<_> = table
            .slots
            .iter()
            .map(|slot| slot.member.identity.slot())
            .collect();
        let configs = membership.membership().get_joint_config();
        if configs.is_empty()
            || configs.len() > 2
            || nodes.len() > 2 * slots.len()
            || !nodes.iter().all(|node| {
                historical_node(table, *node)
                    || state
                        .intent()
                        .is_some_and(|intent| intent.request.candidate.identity.node_id() == *node)
            })
        {
            return Err(invalid_data("invalid historic config voter membership"));
        }
        for voters in configs {
            let voter_slots = voters
                .iter()
                .map(|node| VoterSlotIdentity::from_node_id(*node).map(|id| id.slot()))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(|_| invalid_data("invalid historic config voter identity"))?;
            if voters.len() != slots.len() || voter_slots != slots || !voters.is_subset(&nodes) {
                return Err(invalid_data("historic config voter denominator changed"));
            }
        }
        return Ok(());
    }
    let log = membership
        .log_id()
        .ok_or_else(|| invalid_data("config voter membership has no cut"))?;
    let mut proposed = table.clone();
    proposed
        .observe_membership(membership.membership().get_joint_config(), &nodes, cut(log))
        .map_err(|_| invalid_data("unauthorized fixed config membership"))?;
    if &proposed != table {
        return Err(invalid_data(
            "config membership disagrees with applied voter slots",
        ));
    }
    Ok(())
}

/// Project the bounded control state through the actual preceding durable log.
/// Read one log body at a time; application rows and intent ownership stay unchanged.
pub(crate) fn projected_before_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    end: u64,
) -> io::Result<VoterSlotTable> {
    let mut table = read_sync(conn)?
        .ok_or_else(|| invalid_data("missing config voter slots"))?
        .table()
        .clone();
    let start = read_applied_sync(conn, identity)?.map_or(Ok(0), |cut| {
        cut.index
            .checked_add(1)
            .ok_or_else(|| invalid_data("config applied index exhausted"))
    })?;
    let mut statement = conn.prepare("SELECT term, log_index, entry_json FROM config_raft_log WHERE log_index >= ?1 AND log_index < ?2 ORDER BY log_index").map_err(db_error)?;
    let rows = statement
        .query_map(params![checked_i64(start)?, checked_i64(end)?], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(db_error)?;
    for row in rows {
        let (term, index, bytes) = row.map_err(db_error)?;
        if bytes.len() > CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(invalid_data("config voter log entry exceeds bound"));
        }
        let entry: Entry<ConfigRaftTypeConfig> = decode_json(&bytes)?;
        if entry.log_id.index != checked_u64(index)?
            || entry.log_id.leader_id.term != checked_u64(term)?
        {
            return Err(invalid_data("config voter intent log identity mismatch"));
        }
        project_entry(&mut table, &entry)?;
    }
    Ok(table)
}

pub(crate) fn project_entry(
    table: &mut VoterSlotTable,
    entry: &Entry<ConfigRaftTypeConfig>,
) -> io::Result<()> {
    match &entry.payload {
        EntryPayload::Normal(command) => {
            if let ConfigMutationIntent::VoterSlotControl(bytes) = &command.intent {
                let control = VoterSlotControl::decode(bytes)
                    .map_err(|_| invalid_data("invalid config voter control"))?;
                // A validly encoded CAS refusal is an ordinary no-effect entry.
                let _ = table.apply_control(&control, cut(entry.log_id));
            }
        }
        EntryPayload::Membership(membership) => table
            .observe_membership(
                membership.get_joint_config(),
                &membership.nodes().map(|(node, _)| *node).collect(),
                cut(entry.log_id),
            )
            .map_err(|_| invalid_data("invalid projected config membership"))?,
        EntryPayload::Blank => {}
    }
    Ok(())
}

pub(super) fn append_sync(
    conn: &Connection,
    entry: &Entry<ConfigRaftTypeConfig>,
) -> io::Result<()> {
    let EntryPayload::Normal(command) = &entry.payload else {
        return Ok(());
    };
    let ConfigMutationIntent::VoterSlotControl(bytes) = &command.intent else {
        return Ok(());
    };
    let mut state = read_sync(conn)?
        .ok_or_else(|| invalid_data("voter controls require the config incarnation profile"))?;
    let control = VoterSlotControl::decode(bytes)
        .map_err(|_| invalid_data("invalid config voter control"))?;
    if let VoterSlotControl::Begin(request) = control {
        let prefix = projected_before_sync(conn, command.identity, entry.log_id.index)?;
        let mut proposed = prefix.clone();
        if proposed
            .apply_control(&VoterSlotControl::Begin(request.clone()), cut(entry.log_id))
            .is_err()
            || proposed == prefix
        {
            return Ok(());
        }
        state
            .append_intent_after_prefix(
                VoterSlotIntent {
                    log_id: cut(entry.log_id),
                    request: *request,
                },
                &prefix,
            )
            .map_err(|_| invalid_data("config voter intent was not admitted"))?;
        write_sync(conn, &state)?;
    }
    Ok(())
}

pub(crate) fn check_fences_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    entries: &[Entry<ConfigRaftTypeConfig>],
    runtime: Option<&super::super::store::voter_slots::ConfigVoterAdmission>,
) -> io::Result<()> {
    if read_sync(conn)?.is_none() {
        return Ok(());
    }
    let Some(first) = entries.first() else {
        return Ok(());
    };
    let mut projected = projected_before_sync(conn, identity, first.log_id.index)?;
    for entry in entries {
        let control = match &entry.payload {
            EntryPayload::Normal(ConfigConsensusCommand {
                intent: ConfigMutationIntent::VoterSlotControl(bytes),
                ..
            }) => Some(
                VoterSlotControl::decode(bytes)
                    .map_err(|_| invalid_data("invalid config voter control"))?,
            ),
            _ => None,
        };
        if let Some(VoterSlotControl::Begin(request)) = control.as_ref() {
            let mut proposed = projected.clone();
            if proposed
                .apply_control(&VoterSlotControl::Begin(request.clone()), cut(entry.log_id))
                .is_ok()
                && proposed != projected
                && !runtime.is_some_and(|runtime| runtime.intent_fence_acknowledged(request))
            {
                return Err(invalid_data(
                    "config voter append lacks acknowledged engine fence",
                ));
            }
        }
        project_entry(&mut projected, entry)?;
    }
    Ok(())
}

pub(super) fn truncate_sync(conn: &Connection, index: u64) -> io::Result<()> {
    if let Some(mut state) = read_sync(conn)? {
        state.truncate_from(index);
        write_sync(conn, &state)?;
    }
    Ok(())
}

pub(super) fn apply_control_sync(
    conn: &Connection,
    bytes: &[u8],
    log: LogId<ConsensusNodeId>,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let mut state = read_sync(conn)?
        .ok_or_else(|| invalid_data("voter controls require the config incarnation profile"))?;
    let control = VoterSlotControl::decode(bytes)
        .map_err(|_| invalid_data("invalid config voter control"))?;
    let mut table = state.table().clone();
    let result = table
        .apply_control(&control, cut(log))
        .map_err(ConfigMutationFailure::VoterReplacement);
    state
        .publish_applied(table, cut(log))
        .map_err(|_| invalid_data("invalid config voter publication"))?;
    write_sync(conn, &state)?;
    Ok(result)
}

pub(super) fn apply_membership_sync(
    conn: &Connection,
    membership: &StoredMembership<ConsensusNodeId, EmptyNode>,
) -> io::Result<()> {
    if let Some(mut state) = read_sync(conn)? {
        let log = membership
            .log_id()
            .ok_or_else(|| invalid_data("config voter membership has no cut"))?;
        let mut table = state.table().clone();
        table
            .observe_membership(
                membership.membership().get_joint_config(),
                &membership.nodes().map(|(node, _)| *node).collect(),
                cut(log),
            )
            .map_err(|_| invalid_data("unauthorized config membership transition"))?;
        state
            .publish_applied(table, cut(log))
            .map_err(|_| invalid_data("invalid config voter publication"))?;
        write_sync(conn, &state)?;
    }
    Ok(())
}

pub(super) fn publish_applied_sync(
    conn: &Connection,
    log: LogId<ConsensusNodeId>,
) -> io::Result<()> {
    if let Some(mut state) = read_sync(conn)? {
        state
            .publish_applied(state.table().clone(), cut(log))
            .map_err(|_| invalid_data("invalid config voter publication"))?;
        write_sync(conn, &state)?;
    }
    Ok(())
}

pub(super) fn strip_intent_sync(conn: &Connection) -> io::Result<()> {
    if let Some(state) = read_sync(conn)? {
        write_sync(
            conn,
            &VoterSlotDurableState::new(state.table().clone())
                .map_err(|_| invalid_data("invalid config voter snapshot"))?,
        )?;
    }
    Ok(())
}

pub(super) fn install_snapshot_sync(
    destination: &Connection,
    source: &Connection,
    log: Option<LogId<ConsensusNodeId>>,
) -> io::Result<()> {
    match (read_sync(destination)?, read_sync(source)?) {
        (None, None) => Ok(()),
        (Some(mut current), Some(incoming)) if incoming.intent().is_none() => {
            let log = log.ok_or_else(|| invalid_data("config voter snapshot has no cut"))?;
            current
                .publish_snapshot(incoming.table().clone(), cut(log))
                .map_err(|_| invalid_data("config voter snapshot regressed"))?;
            write_sync(destination, &current)
        }
        _ => Err(invalid_data("config voter snapshot profile mismatch")),
    }
}
