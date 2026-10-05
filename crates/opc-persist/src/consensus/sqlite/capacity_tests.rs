use super::*;
use crate::consensus::capacity_tests::support::*;
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};

#[test]
fn ordinary_and_audited_append_classification_preserves_history_and_audit_requirements() {
    use crate::consensus::audit_mutation::AuditedConfigEffect;
    use crate::ConfirmedCommitResolution;

    for (resolution, updates) in [
        (None, false),
        (
            Some(ConfirmedCommitResolution::Confirm {
                pending_tx_id: parent(),
            }),
            true,
        ),
        (
            Some(ConfirmedCommitResolution::Rollback {
                pending_tx_id: parent(),
            }),
            true,
        ),
    ] {
        let commit = Box::new(prepared());
        let legacy = match resolution {
            None => ConfigMutationIntent::AppendCommit(commit.clone()),
            Some(resolution) => ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: commit.clone(),
                resolution,
            },
        };
        let bounded = bounded_command(false, resolution).intent;
        for intent in [legacy, bounded] {
            assert_eq!(updates_existing_records(&intent), updates);
            assert!(requires_audit(&intent));
        }
        let legacy_effect = AuditedConfigEffect::Append { commit, resolution };
        let ConfigMutationIntent::AuditedMutation(bounded) =
            bounded_command(true, resolution).intent
        else {
            unreachable!()
        };
        for effect in [legacy_effect, bounded.effect] {
            assert_eq!(effect.updates_existing_records(), updates);
            let intent =
                ConfigMutationIntent::AuditedMutation(super::super::PreparedAuditedMutation {
                    handle: handle(Some(&effect)),
                    effect,
                });
            // The audited dispatcher owns its chain refresh and ledger checks.
            assert!(!updates_existing_records(&intent));
            assert!(!requires_audit(&intent));
        }
    }
    for (intent, audit) in [
        (ConfigMutationIntent::MarkConfirmed { tx_id: tx() }, true),
        (
            ConfigMutationIntent::CreateRollbackPoint {
                tx_id: tx(),
                label: None,
            },
            true,
        ),
        (
            ConfigMutationIntent::ClearRecoveryRequired { tx_id: tx() },
            false,
        ),
    ] {
        assert!(updates_existing_records(&intent));
        assert_eq!(requires_audit(&intent), audit);
    }
}

#[tokio::test]
async fn bounded_apply_append_and_replay_refuse_before_any_effect() {
    let directory = tempfile::tempdir().unwrap();
    let backend =
        SqliteBackend::open_with_audit_key(directory.path().join("bounded.sqlite"), true, 0, key())
            .await
            .unwrap();
    let shared = backend.conn();
    let conn = shared.lock().await;
    let node = ConsensusNodeId::new(1).unwrap();
    let members = BTreeSet::from([node]);
    initialize_schema(
        &conn,
        identity(),
        &members,
        &key(),
        None,
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    for audited in [false, true] {
        for revision in [7, 8] {
            let mut command = bounded_command(audited, None);
            command.schema_version = revision;
            let entry = Entry::<ConfigRaftTypeConfig> {
                log_id: LogId::new(CommittedLeaderId::new(1, node), 0),
                payload: EntryPayload::Normal(command),
            };
            let before = conn.total_changes();
            let append =
                append_logs_sync(&conn, identity(), &members, std::slice::from_ref(&entry))
                    .unwrap_err();
            assert_eq!(append.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                append.to_string(),
                "invalid encrypted config consensus command"
            );
            let apply =
                apply_entries_sync(&conn, &key(), identity(), &members, vec![entry.clone()])
                    .unwrap_err();
            assert_eq!(apply.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                apply.to_string(),
                "invalid encrypted config consensus command"
            );
            assert_eq!(conn.total_changes(), before);
            assert_eq!(last_log_sync(&conn, identity()).unwrap(), None);
            assert_eq!(read_applied_sync(&conn, identity()).unwrap(), None);
            let count: i64 = conn
                .query_row("SELECT count(*) FROM config_history", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);

            // Inject untrusted retained bytes directly, bypassing admission to
            // exercise the real replay reader's existing unknown-kind failure.
            conn.execute("INSERT INTO config_raft_log(log_index, configuration_epoch, term, entry_json) VALUES (0,1,1,?1)",
                [serde_json::to_vec(&entry).unwrap()]).unwrap();
            let before = conn.total_changes();
            let error =
                read_log_range_sync(&conn, identity(), &members, 0, None, None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "config consensus decoding failed");
            assert_eq!(conn.total_changes(), before);
            conn.execute("DELETE FROM config_raft_log", []).unwrap();
        }
    }
}
