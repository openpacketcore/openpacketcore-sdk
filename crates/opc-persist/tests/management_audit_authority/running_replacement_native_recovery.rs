//! Retained target rejection through the real native apply transaction.
//! Raft is stopped before fault injection; this does not test fatal-core restart.

use super::*;
use crate::audit_authority::ledger::LedgerState;
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::TargetAuditCommandV1;
use crate::consensus::sqlite::{self, SqliteWorkCancellation};
use crate::consensus::{
    ConfigConsensusCommand, ConfigConsensusRequestId, ConfigConsensusResponse,
    ConfigMutationFailure, ConfigMutationIntent, ConfigRaftTypeConfig, RetainedConfigMode,
};
use opc_consensus::engine::{Entry, EntryPayload, LogId};
use rusqlite::hooks::{Action, AuthAction, AuthContext, Authorization};
use rusqlite::{types::Value, Connection};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const MODE: RetainedConfigMode = RetainedConfigMode::NetconfTargetsV1;
const REQUEST_BYTES: [u8; 16] = [0xE9; 16];
type AuthorityImage = Vec<(String, Vec<Vec<Value>>)>;

fn durability() -> RetainedConfigDurability {
    RetainedConfigDurability::Durable {
        min_free_bytes: 128 * 1024 * 1024,
    }
}

fn require_disk_scratch() {
    let scratch = std::env::var_os("TMPDIR").expect("explicit private disk TMPDIR");
    let output = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(scratch)
        .output()
        .expect("fixture filesystem detector");
    assert!(output.status.success());
    let filesystem = std::str::from_utf8(&output.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
}

fn assert_durable(conn: &Connection) {
    assert!(crate::schema::verify_wal_mode(conn).expect("native WAL"));
    assert!(crate::schema::verify_synchronous_extra(conn).expect("native Durable"));
}

// Compare every value in every actual application table, including history
// authenticators and retained frontiers. No capacity-mode table is invented.
fn authority_image(conn: &Connection) -> AuthorityImage {
    let tables = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .expect("actual native schema")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("native table names")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("complete native table names");
    for required in [
        "config_history",
        "config_raft_management_audit",
        "config_raft_request_outcomes",
        "config_raft_machine",
        "config_raft_applied",
        "config_raft_committed",
        "config_netconf_profile",
        "config_netconf_targets",
        "config_netconf_lifecycle",
    ] {
        assert!(tables.iter().any(|table| table == required));
    }
    tables
        .into_iter()
        .map(|table| {
            let quoted = table.replace('"', "\"\"");
            let mut query = conn
                .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))
                .expect("complete native table");
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<rusqlite::Result<Vec<Value>>>()
                })
                .expect("complete native rows")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("all native row values");
            (table, rows)
        })
        .collect()
}

fn configuration_image(conn: &Connection) -> AuthorityImage {
    authority_image(conn)
        .into_iter()
        .filter(|(table, _)| {
            !matches!(
                table.as_str(),
                "config_raft_log"
                    | "config_raft_vote"
                    | "config_raft_applied"
                    | "config_raft_committed"
                    | "config_raft_purged"
                    | "config_raft_machine"
                    | "config_raft_request_outcomes"
                    | "config_raft_snapshot"
                    | "config_raft_management_audit"
            )
        })
        .collect()
}

fn saved_bytes(conn: &Connection, index: u64) -> Vec<u8> {
    conn.query_row(
        "SELECT entry_json FROM config_raft_log WHERE log_index=?1",
        [i64::try_from(index).expect("fixture log index")],
        |row| row.get(0),
    )
    .expect("exact original committed entry bytes")
}

struct Native {
    options: RetainedConfigOptions,
    topology: ConfigConsensusTopology,
    key: AuditKey,
    keys: Arc<AuditKeyRing>,
}

impl Native {
    fn ledger(&self, conn: &Connection) -> LedgerState {
        crate::consensus::audit::read_with_keys_sync(
            conn,
            &self.key,
            Some(&self.keys),
            self.topology.identity(),
        )
        .expect("root MAC, target authority and continuity validation")
        .expect("initialized retained audit ledger")
    }

    fn original(&self, conn: &Connection, handle: &AuditOperationHandle) -> AuditOperationReceipt {
        self.ledger(conn)
            .lookup(&self.key, handle, caller())
            .expect("authenticate exact original caller/handle")
            .expect("retained original")
    }

    fn apply_saved(
        &self,
        conn: &Connection,
        index: u64,
    ) -> std::io::Result<ConfigConsensusResponse> {
        let entries = sqlite::read_log_range_sync(
            conn,
            self.topology.identity(),
            self.topology.members(),
            index,
            Some(index + 1),
            Some(1),
            MODE,
        )?;
        assert_eq!(entries.len(), 1, "one decoded original native entry");
        let mut responses = sqlite::apply_entries_cancellable_sync(
            conn,
            self.topology.identity(),
            self.topology.members(),
            entries,
            &SqliteWorkCancellation::audit_test(),
            &self.key,
            Some(&self.keys),
            MODE,
        )?;
        assert_eq!(responses.len(), 1, "one native apply response");
        Ok(responses.remove(0))
    }
}

async fn assert_head(
    store: &ConsensusConfigStore,
    provider: &opc_key::MemoryKeyProvider,
    record: &CommitRecord,
    plaintext: &[u8],
) {
    let actual = store
        .load_latest()
        .await
        .expect("authenticated Running read")
        .expect("seeded Running");
    assert_eq!(
        &actual.record, record,
        "TARGET_REJECTION_NATIVE_EXACT_HISTORY"
    );
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&actual.record.encrypted_blob)
        .expect("original encrypted envelope");
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).expect("original AAD");
    let decoded = opc_crypto::decrypt_envelope(provider, &aad, &actual.record.encrypted_blob)
        .await
        .expect("authenticated original plaintext");
    assert_eq!(
        decoded.as_slice(),
        plaintext,
        "TARGET_REJECTION_NATIVE_READBACK"
    );
}

#[tokio::test]
async fn target_rejection_native_outcome_fault_rolls_back_replays_and_reopens() {
    require_disk_scratch();
    let f = Fixture::new_with_durability(durability()).await;
    let session = f.session().await;
    let empty = f.store.read_netconf_running_edit(&session).await.unwrap();
    let seed = f
        .prepare(&session, &empty, 2, b"retained original Running")
        .await;
    drop(empty);
    let seed_receipt = f.apply(&session, &seed).await;
    f.settle(&seed_receipt).await;
    let seed_record = record(&seed).clone();
    f.assert_head(&seed_record, b"retained original Running")
        .await;
    drop(seed);

    let frozen = f.store.read_netconf_running_edit(&session).await.unwrap();
    let prepared = f
        .prepare(&session, &frozen, 3, b"must never replace Running")
        .await;
    drop(frozen);
    let encoded_original = prepared.encode().expect("actual original recovery bytes");
    let original_handle = prepared.handle().clone();
    f.checkpoint.pause.store(true, Ordering::Release);
    let submitting_store = f.store.clone();
    let submitting_session = session.clone();
    let original = prepared.clone();
    let pending = tokio::spawn(async move {
        submitting_store
            .admit_netconf_running_replacement_local(&submitting_session, &original, caller())
            .await
    });
    tokio::time::timeout(WAIT, f.checkpoint.entered.notified())
        .await
        .unwrap();
    let lease = f.lock(&session, 4).await;
    f.checkpoint.release.notify_one();
    let intent = applied(tokio::time::timeout(WAIT, pending).await.unwrap().unwrap());
    assert_eq!(intent.state(), AuditOperationState::Intent);
    f.store
        .checkpoint_audit_tail()
        .await
        .expect("independent original Intent checkpoint");

    let Fixture {
        store,
        device,
        checkpoint,
        provider,
        dir,
    } = f;
    let backend = store.inner.backend.clone();
    let topology = ConfigConsensusTopology::try_new(
        store.inner.identity,
        store.inner.local_node_id,
        BTreeSet::from([store.inner.local_node_id]),
    )
    .unwrap();
    let native = Native {
        options: RetainedConfigOptions::new(
            dir.path().join("authority.sqlite"),
            backend
                .retained_binding
                .as_ref()
                .expect("retained target binding")
                .clone(),
            durability(),
            64 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap(),
        topology,
        key: backend.audit_key().clone(),
        keys: backend
            .management_audit_keys()
            .expect("real authority signing keys"),
    };
    let logical_time = store.inner.clock.now_utc();
    store
        .shutdown()
        .await
        .expect("join real Raft and storage workers before native fault");
    drop(store);
    drop(device);
    drop(session);
    drop(lease);
    let identity = native.topology.identity();
    let request = ConfigConsensusRequestId::from_bytes(REQUEST_BYTES);

    let (before, effects, entry_bytes, index, previous_applied, previous_machine, anchor) = {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert_durable(&conn);
        let committed = sqlite::read_committed_sync(&conn, identity)
            .unwrap()
            .unwrap();
        assert_eq!(
            sqlite::read_applied_sync(&conn, identity).unwrap(),
            Some(committed)
        );
        let last_index: u64 = conn
            .query_row("SELECT MAX(log_index) FROM config_raft_log", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(last_index, committed.index, "no uncommitted setup suffix");
        let index = committed.index + 1;
        let entry = Entry::<ConfigRaftTypeConfig> {
            log_id: LogId::new(committed.leader_id, index),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: 9,
                identity,
                request_id: request,
                logical_time,
                intent: ConfigMutationIntent::ManagementAudit(Box::new(
                    AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(
                        prepared.command().clone(),
                    ))),
                )),
            }),
        };
        let prior: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM config_raft_request_outcomes WHERE request_id=?1",
                [request.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(prior, 0, "fresh native request identity");
        sqlite::append_logs_sync(
            &conn,
            identity,
            native.topology.members(),
            std::slice::from_ref(&entry),
            MODE,
        )
        .expect("real target9 durable WAL append");
        sqlite::save_committed_sync(&conn, identity, Some(entry.log_id), MODE)
            .expect("native original committed frontier");
        drop(entry);
        let before = authority_image(&conn);
        let effects = configuration_image(&conn);
        let entry_bytes = saved_bytes(&conn, index);
        let previous_applied = sqlite::read_applied_sync(&conn, identity).unwrap();
        let previous_machine = sqlite::read_machine_sync(&conn, identity).unwrap();
        let anchor = native.ledger(&conn).target_anchor;
        let original = native.original(&conn, &original_handle);
        assert_eq!(original.state(), AuditOperationState::Intent);
        assert!(!original.terminal_recorded());

        // The stopped authority owns this connection and exactly one saved
        // request is applied. Hooks observe real SQLite work; neither returns
        // a fake SDK outcome nor changes a stored row or command.
        let ledger_updates = Arc::new(AtomicUsize::new(0));
        let denials = Arc::new(AtomicUsize::new(0));
        let writes_before_denial = Arc::new(AtomicUsize::new(0));
        let observed = ledger_updates.clone();
        conn.update_hook(Some(
            move |action: Action, database: &str, table: &str, _: i64| {
                if database == "main"
                    && table == "config_raft_management_audit"
                    && action == Action::SQLITE_UPDATE
                {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
            },
        ))
        .expect("native update observation");
        let observed = ledger_updates.clone();
        let denied = denials.clone();
        let preceding = writes_before_denial.clone();
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::Insert { table_name } if table_name == "config_raft_request_outcomes") {
                let writes = observed.load(Ordering::SeqCst);
                if writes > 0 {
                    preceding.store(writes, Ordering::SeqCst);
                    denied.fetch_add(1, Ordering::SeqCst);
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        })).expect("native authorizer fault");
        let result = native.apply_saved(&conn, index);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .expect("remove scoped authorizer");
        conn.update_hook(None::<fn(Action, &str, &str, i64)>)
            .expect("remove scoped observation");
        assert_eq!(
            ledger_updates.load(Ordering::SeqCst),
            1,
            "TARGET_REJECTION_NATIVE_REAL_LEDGER_UPDATE"
        );
        assert_eq!(
            writes_before_denial.load(Ordering::SeqCst),
            1,
            "TARGET_REJECTION_NATIVE_FAULT_AFTER_LEDGER"
        );
        assert_eq!(
            denials.load(Ordering::SeqCst),
            1,
            "TARGET_REJECTION_NATIVE_ACTUAL_INSERT_DENIAL"
        );
        let error = result.expect_err("actual SQLite authorization fault aborts apply");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(conn.is_autocommit(), "failed native transaction is closed");
        eprintln!(
            "TARGET_REJECTION_NATIVE_FAULT_REACHED ledger_updates=1 outcome_insert_denials=1"
        );
        assert_eq!(
            authority_image(&conn),
            before,
            "TARGET_REJECTION_NATIVE_OUTER_ROLLBACK"
        );
        assert_eq!(
            native.original(&conn, &original_handle).state(),
            AuditOperationState::Intent
        );
        assert_eq!(
            sqlite::read_applied_sync(&conn, identity).unwrap(),
            previous_applied
        );
        assert_eq!(
            sqlite::read_machine_sync(&conn, identity).unwrap(),
            previous_machine
        );
        assert_eq!(
            sqlite::read_committed_sync(&conn, identity)
                .unwrap()
                .unwrap()
                .index,
            index
        );
        (
            before,
            effects,
            entry_bytes,
            index,
            previous_applied,
            previous_machine,
            anchor,
        )
    };
    // All original runtime owners, guarded connections, and the backend are
    // released before native retained-file admission is reacquired.
    drop(backend);
    let backend =
        SqliteBackend::reopen_config_authority(native.options.clone(), native.key.clone())
            .await
            .expect("durable reopen of committed but unapplied target Apply");
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert_durable(&conn);
        assert_eq!(
            authority_image(&conn),
            before,
            "TARGET_REJECTION_NATIVE_REOPENED_ROLLBACK"
        );
        assert_eq!(
            saved_bytes(&conn, index),
            entry_bytes,
            "TARGET_REJECTION_NATIVE_EXACT_SAVED_BYTES"
        );
        assert_eq!(
            sqlite::read_applied_sync(&conn, identity).unwrap(),
            previous_applied
        );
        assert_eq!(
            native.original(&conn, &original_handle).state(),
            AuditOperationState::Intent
        );
        let response = native
            .apply_saved(&conn, index)
            .expect("replay the exact original native entry");
        assert_eq!(response.result, Err(ConfigMutationFailure::Conflict));
        assert_eq!(response.sequence, previous_machine.0 + 1);
        assert_eq!(response.raft_log_index, index);
        let receipt = response
            .audit_receipt
            .as_ref()
            .expect("actual applied audit proof")
            .read_back(&native.key, identity, &original_handle, caller())
            .expect("authenticate exact original rejection proof");
        assert_eq!(
            receipt.state(),
            AuditOperationState::Rejected,
            "TARGET_REJECTION_NATIVE_REPLAY_REJECTED"
        );
        assert!(!receipt.terminal_recorded());
        assert_eq!(
            native.original(&conn, &original_handle).state(),
            AuditOperationState::Rejected
        );
        assert!(
            native.ledger(&conn).target_anchor == anchor,
            "rejection preserves last successful target anchor"
        );
        assert_eq!(
            configuration_image(&conn),
            effects,
            "TARGET_REJECTION_NATIVE_NO_CONFIGURATION_OR_LOCK_EFFECT"
        );
        assert_eq!(saved_bytes(&conn, index), entry_bytes);
        assert_eq!(
            sqlite::read_applied_sync(&conn, identity)
                .unwrap()
                .unwrap()
                .index,
            index
        );
        eprintln!("TARGET_REJECTION_NATIVE_REPLAY_REJECTED original_bytes=true authenticated_receipt=true");
    }
    drop(backend);

    // Reopen once more through the real SDK authority. The independent
    // checkpoint remains a separate owner and the rejection still owes its
    // terminal record and covering checkpoint; no receipt is fabricated.
    let backend =
        SqliteBackend::reopen_config_authority(native.options.clone(), native.key.clone())
            .await
            .expect("retained rejection survives a second close/reopen");
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert_durable(&conn);
        let receipt = native.original(&conn, &original_handle);
        assert_eq!(receipt.state(), AuditOperationState::Rejected);
        assert!(!receipt.terminal_recorded());
        assert_eq!(configuration_image(&conn), effects);
    }
    let policy = AuditContinuityPolicy::new(
        AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x52; 32]).unwrap()]).unwrap(),
        checkpoint.clone(),
        1,
        1,
    )
    .unwrap();
    let store = ConsensusConfigStore::open_with_audit_continuity(
        native.topology.clone(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
        policy,
    )
    .await
    .expect("real reopened target authority");
    store.initialize_cluster().await.unwrap();
    let recovered = crate::audit_authority::PreparedTargetMutation::decode(&encoded_original)
        .expect("actual original encoded preparation");
    assert_eq!(recovered.handle(), &original_handle);
    assert_eq!(
        store
            .recover_netconf_target(&original_handle, caller())
            .await
            .unwrap()
            .unwrap(),
        recovered
    );
    let receipt = store
        .lookup_audit_operation(&original_handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.state(),
        AuditOperationState::Rejected,
        "TARGET_REJECTION_NATIVE_PUBLIC_REOPENED_ORIGINAL"
    );
    assert!(!receipt.terminal_recorded());
    assert_eq!(
        applied(
            store
                .submit_netconf_target_local(&recovered, &receipt, caller())
                .await
        )
        .state(),
        receipt.state()
    );
    assert_head(
        &store,
        &provider,
        &seed_record,
        b"retained original Running",
    )
    .await;
    store
        .complete_required_audit_outcome(&receipt, caller())
        .await
        .expect("truthful original rejection terminal and independent checkpoint");
    let terminal = store
        .lookup_audit_operation(&original_handle, caller())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(terminal.state(), AuditOperationState::Rejected);
    assert!(
        terminal.terminal_recorded(),
        "TARGET_REJECTION_NATIVE_TERMINAL"
    );
    let observed_checkpoint = checkpoint.load(identity).await.unwrap().unwrap();
    observed_checkpoint
        .verify(&native.keys, identity)
        .expect("authenticate independent checkpoint");
    assert!(
        observed_checkpoint.sequence() >= terminal.sequence,
        "TARGET_REJECTION_NATIVE_CHECKPOINT_COVERS_TERMINAL"
    );
    {
        let shared = store.inner.backend.conn();
        let conn = shared.lock().await;
        assert_durable(&conn);
        assert_eq!(configuration_image(&conn), effects);
        let ledger = native.ledger(&conn);
        assert!(ledger.target_anchor == anchor);
        let operation = ledger
            .operations
            .iter()
            .find(|operation| operation.handle == original_handle)
            .unwrap();
        assert!(operation.terminal_recorded);
        assert!(!ledger.mutation_outcome_needs_checkpoint(operation));
    }
    assert_head(
        &store,
        &provider,
        &seed_record,
        b"retained original Running",
    )
    .await;
    store.shutdown().await.unwrap();
    drop(store);
    let backend =
        SqliteBackend::reopen_config_authority(native.options.clone(), native.key.clone())
            .await
            .expect("retained terminal and checkpoint survive final close/reopen");
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert_durable(&conn);
        assert_eq!(configuration_image(&conn), effects);
        let retained = native.original(&conn, &original_handle);
        assert_eq!(retained.state(), AuditOperationState::Rejected);
        assert!(
            retained.terminal_recorded(),
            "TARGET_REJECTION_NATIVE_REOPENED_TERMINAL"
        );
        let ledger = native.ledger(&conn);
        let retained_checkpoint = ledger
            .continuity
            .as_ref()
            .unwrap()
            .checkpoint
            .as_ref()
            .unwrap();
        retained_checkpoint.verify(&native.keys, identity).unwrap();
        assert!(retained_checkpoint.sequence() >= retained.sequence);
        assert!(observed_checkpoint.sequence() >= retained.sequence);
        assert!(ledger.target_anchor == anchor);
    }
    drop(backend);
    eprintln!("TARGET_REJECTION_NATIVE_COMPLETE rejected=true readback=true terminal=true checkpoint=true reopened=true");
    drop(dir);
}
