//! Profile-aware SQL oracles. Mutation bytes stay exact; replay policies are
//! independently derived from the committed commands rather than mutation trees.
use super::*;
use crate::{ReplicationCommandBoundary, ReplicationReplayPolicy};

fn inner(intent: &SessionMutationIntent) -> &SessionMutationIntent {
    match intent {
        SessionMutationIntent::Authorized { mutation, .. } => inner(mutation),
        _ => intent,
    }
}

// Index once: complete retained-journal comparisons include the original
// full windows, so a per-row search through every command and row is quadratic.
#[derive(Clone, Copy)]
struct SourcePolicy {
    command: [u8; 16],
    native_prunes: bool,
    sqlite_prunes: bool,
}

fn expected_policies(
    commands: &[Entry<SessionRaftTypeConfig>],
    journal: &[crate::ReplicationEntry],
) -> BTreeMap<u64, (ReplicationReplayPolicy, ReplicationReplayPolicy)> {
    let mut sources = BTreeMap::new();
    for entry in commands {
        let EntryPayload::Normal(command) = &entry.payload else {
            continue;
        };
        let intent = inner(&command.intent);
        let ordinary = matches!(
            intent,
            SessionMutationIntent::CompareAndSet(_)
                | SessionMutationIntent::DeleteFenced(_)
                | SessionMutationIntent::RefreshTtl { .. }
                | SessionMutationIntent::AcquireLease { .. }
                | SessionMutationIntent::RenewLease { .. }
                | SessionMutationIntent::ReleaseLease(_)
        );
        let v1 = matches!(
            intent,
            SessionMutationIntent::FencedTransition(_)
                | SessionMutationIntent::ActivateFencedTransition { .. }
        );
        let policy = SourcePolicy {
            command: *command.request_id.as_bytes(),
            native_prunes: ordinary || v1,
            sqlite_prunes: ordinary,
        };
        let mut bind = |bytes| {
            sources
                .entry(
                    crate::ReplicationTxId::from_request_bytes(bytes)
                        .as_str()
                        .to_owned(),
                )
                .or_insert(policy);
        };
        if let SessionMutationIntent::FencedTransitionV2Batch(requests) = intent {
            for request in requests {
                bind(fenced_transition_v2_outer_request_id(request.request_id()));
            }
        } else {
            bind(*command.request_id.as_bytes());
        }
    }
    let mut groups = BTreeMap::new();
    for row in journal {
        let source = *sources
            .get(row.tx_id.as_str())
            .expect("every compared row has a committed source command");
        groups
            .entry(source.command)
            .or_insert_with(|| (source, Vec::new()))
            .1
            .push(row.sequence);
    }
    let mut result = BTreeMap::new();
    for (source, sequences) in groups.into_values() {
        let sqlite = if source.sqlite_prunes {
            ReplicationReplayPolicy::prune_expired()
        } else {
            ReplicationReplayPolicy::preserve()
        };
        let base_native = if source.native_prunes {
            ReplicationReplayPolicy::prune_and_retire()
        } else {
            ReplicationReplayPolicy::preserve()
        };
        for (position, sequence) in sequences.iter().enumerate() {
            let mut native = base_native;
            native.command = if sequences.len() == 1 {
                ReplicationCommandBoundary::Single
            } else if position == 0 {
                ReplicationCommandBoundary::Start {
                    id: source.command,
                    following_entries: (sequences.len() - 1).try_into().unwrap(),
                }
            } else {
                ReplicationCommandBoundary::Continue {
                    id: source.command,
                    remaining_entries: (sequences.len() - position - 1).try_into().unwrap(),
                }
            };
            let mut sqlite = sqlite;
            sqlite.command = native.command;
            assert!(result.insert(*sequence, (native, sqlite)).is_none());
        }
    }
    result
}

fn assert_entries_with_context(
    native: &[crate::ReplicationEntry],
    sqlite: &[crate::ReplicationEntry],
    commands: &[Entry<SessionRaftTypeConfig>],
    journal: &[crate::ReplicationEntry],
) {
    assert_eq!(
        native.len(),
        sqlite.len(),
        "exact application notification count"
    );
    let expected = expected_policies(commands, journal);
    for (native, sqlite) in native.iter().zip(sqlite) {
        native.validate().unwrap();
        sqlite.validate().unwrap();
        let (native_policy, sqlite_policy) = expected[&sqlite.sequence];
        assert_eq!(
            native.replay_policy, native_policy,
            "native policy follows its source command"
        );
        assert_eq!(
            sqlite.replay_policy, sqlite_policy,
            "SQL policy follows its source command"
        );
        let mut projected = sqlite.clone();
        projected.replay_policy = native_policy;
        assert_eq!(
            encode_json(native).unwrap(),
            encode_json(&projected).unwrap(),
            "exact notification mutations, transaction identity, sequence and committed time"
        );
    }
}

pub(super) fn notifications(
    native: &[crate::ReplicationEntry],
    sqlite: &[crate::ReplicationEntry],
    commands: &[Entry<SessionRaftTypeConfig>],
) {
    assert_entries_with_context(native, sqlite, commands, sqlite);
}

fn commands(conn: &Connection) -> Vec<Entry<SessionRaftTypeConfig>> {
    let mut statement = conn
        .prepare("SELECT entry_json FROM consensus_log ORDER BY log_index")
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|row| serde_json::from_slice(&row.unwrap()).unwrap())
        .collect()
}

fn journal(conn: &Connection) -> Vec<crate::ReplicationEntry> {
    let mut statement = conn
        .prepare("SELECT entry_json FROM session_replication_log ORDER BY sequence")
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|row| serde_json::from_str(&row.unwrap()).unwrap())
        .collect()
}

pub(super) fn page(
    native: &[crate::ReplicationEntry],
    sqlite: &[crate::ReplicationEntry],
    conn: &Connection,
) {
    assert_entries_with_context(native, sqlite, &commands(conn), &journal(conn));
}

pub(super) fn table(native: &Connection, sqlite: &Connection, table: &str) {
    table_with_source(native, sqlite, table, sqlite);
}

pub(super) fn table_with_source(
    native: &Connection,
    sqlite: &Connection,
    table: &str,
    source: &Connection,
) {
    if table != "session_replication_log" {
        assert_eq!(
            ordinary::rows(native, table),
            ordinary::rows(sqlite, table),
            "exact physical table {table}"
        );
        return;
    }
    let sqlite_journal = journal(sqlite);
    assert_entries_with_context(
        &journal(native),
        &sqlite_journal,
        &commands(source),
        &sqlite_journal,
    );
    let sql = "SELECT sequence, tx_id, timestamp FROM session_replication_log ORDER BY sequence";
    let cells = |conn: &Connection| {
        conn.prepare(sql)
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    assert_eq!(
        cells(native),
        cells(sqlite),
        "exact physical journal columns"
    );
}
