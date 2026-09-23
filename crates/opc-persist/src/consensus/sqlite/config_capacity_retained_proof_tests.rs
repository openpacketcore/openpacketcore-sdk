//! Native disk WAL/EXTRA tests for the private retained format and body copy.
//! These exercise storage below the closed proposal gate, not a running larger
//! profile, authenticated multi-node transfer or complete resource qualification.

#![cfg(target_os = "linux")]

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::history::{ConfigHistoryLimits, ConfigHistoryRetention};
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusRequestId, ConfigConsensusTopology,
};
use crate::{
    AttestedConfigCommit, CommitRecord, ConfigStore, ConfirmedCommitResolution,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_crypto::{CONFIG_CAPACITY_V1_LOGICAL_BYTES, CONFIG_CAPACITY_V1_REPLAY_BYTES};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

struct Fixture {
    backend: SqliteBackend,
    options: RetainedConfigOptions,
    topology: ConfigConsensusTopology,
    key: AuditKey,
    root: PathBuf,
}

fn tx_id(version: u64) -> TxId {
    TxId::from_uuid(uuid::Uuid::from_u128(0xE500 + u128::from(version)))
}

fn framed_plaintext(logical: usize, replay: usize) -> Vec<u8> {
    let mut config = vec![b'q'; logical];
    config[0] = b'"';
    config[logical - 1] = b'"';
    if replay == 0 {
        return config;
    }
    let mut framed = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":".to_vec();
    framed.extend_from_slice(&config);
    framed.extend_from_slice(b",\"idempotency_key\":\"");
    let padding = replay
        .checked_sub(framed.len() - logical + 2)
        .expect("framing budget");
    framed.resize(framed.len() + padding, b'r');
    framed.extend_from_slice(b"\"}");
    assert_eq!(framed.len(), logical + replay);
    framed
}

fn append_intent(
    fixture: &Fixture,
    version: u64,
    logical: usize,
    replay: usize,
    pending: bool,
    resolution: Option<ConfirmedCommitResolution>,
) -> ConfigMutationIntent {
    let committed_at = Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time");
    let parent_tx_id = (version > 1).then(|| tx_id(version - 1));
    let principal = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config";
    let schema_digest = SchemaDigest::from_bytes([0xE6; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        opc_key::ConfigAad::new(
            tx_id(version),
            parent_tx_id,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("retained-capacity-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xE7; 32]),
    );
    let plaintext = framed_plaintext(logical, replay);
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        &plaintext,
        [u8::try_from(version).expect("fixture nonce"); 12],
    )
    .expect("genuine bounded encryption");
    let record = CommitRecord {
        tx_id: tx_id(version),
        parent_tx_id,
        version: ConfigVersion::new(version),
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: pending
            .then(|| Timestamp::from_str("2026-01-01T00:01:00Z").expect("synthetic deadline")),
    };
    let attested =
        AttestedConfigCommit::try_new(record, Vec::new(), envelope.claim().expect("paired claim"))
            .expect("paired exact record");
    let binding = CapacityRecordBinding::issue(
        &attested,
        fixture.topology.identity(),
        &fixture.key,
        PROFILE,
    )
    .expect("exact scoped retained proof");
    let (record, audit, _) = attested.into_parts();
    ConfigMutationIntent::prepared_append(
        super::super::types::PreparedConfigCommit::prepare(record, audit, &fixture.key)
            .expect("prepared commit"),
        resolution,
        Some(binding),
    )
}

fn entry(
    fixture: &Fixture,
    index: u64,
    intent: ConfigMutationIntent,
) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(1, fixture.topology.local_node_id()),
            index,
        ),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: 8,
            identity: fixture.topology.identity(),
            request_id: ConfigConsensusRequestId::from_bytes(
                [u8::try_from(index).expect("fixture request ordinal"); 16],
            ),
            logical_time: Timestamp::from_str("2026-01-01T00:00:01Z")
                .expect("synthetic apply time"),
            intent,
        }),
    }
}

async fn fixture(profile: ConfigCapacityProfile) -> Fixture {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-retained-proof-")
        .tempdir_in(scratch)
        .expect("private retained fixture")
        .keep();
    let fs = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(fs.status.success());
    let fs = std::str::from_utf8(&fs.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!fs.is_empty() && !matches!(fs, "tmpfs" | "ramfs"));
    let node = ConsensusNodeId::new(1).expect("synthetic voter");
    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xE8; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xE9; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).expect("topology");
    let binding = RetainedConfigBinding::new(topology.clone(), [0xEA; 32], [0xEB; 32])
        .expect("binding")
        .with_capacity_profile(profile);
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("unchanged native durability limits");
    let key = AuditKey::new([0xEC; 32]).expect("synthetic audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained authority below the closed store-open gate");
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert!(crate::schema::verify_wal_mode(&conn).expect("native WAL"));
        assert!(crate::schema::verify_synchronous_extra(&conn).expect("native Durable"));
        super::super::history::validate_access_for_profile_sync(
            &conn,
            &key,
            true,
            profile,
            &SqliteWorkCancellation::new(),
        )
        .expect("profile-bound empty history");
    }
    Fixture {
        backend,
        options,
        topology,
        key,
        root,
    }
}

async fn apply(
    fixture: &Fixture,
    entries: Vec<Entry<ConfigRaftTypeConfig>>,
) -> Vec<ConfigConsensusResponse> {
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    validate_entry_capacities(&entries, fixture.topology.identity(), &fixture.key, PROFILE)
        .expect("pre-WAL admission");
    append_logs_sync(
        &conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        &entries,
    )
    .expect("native log append");
    save_committed_sync(
        &conn,
        fixture.topology.identity(),
        entries.last().map(|entry| entry.log_id),
    )
    .expect("committed prefix");
    apply_entries_cancellable_sync(
        &conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        entries,
        &SqliteWorkCancellation::new(),
        &fixture.key,
        None,
        PROFILE,
    )
    .expect("atomic native apply")
}

async fn initialize(fixture: &Fixture) {
    let membership = Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(1, fixture.topology.local_node_id()),
            0,
        ),
        payload: EntryPayload::Membership(Membership::new(
            vec![fixture.topology.members().clone()],
            fixture.topology.members().clone(),
        )),
    };
    assert!(apply(fixture, vec![membership]).await[0].result.is_ok());
}

fn counts(conn: &Connection) -> [i64; 4] {
    [
        "config_history",
        "config_raft_capacity_records",
        "config_raft_request_outcomes",
        "config_lifecycle_audit",
    ]
    .map(|table| {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("durable count")
    })
}

fn authority_digest(conn: &Connection) -> [u8; 32] {
    use rusqlite::types::ValueRef;
    let mut digest = Sha256::new();
    for table in [
        "config_history",
        "audit_trail",
        "config_lifecycle_audit",
        "rollback_labels",
        "config_raft_identity",
        "config_raft_vote",
        "config_raft_log",
        "config_raft_applied",
        "config_raft_committed",
        "config_raft_purged",
        "config_raft_machine",
        "config_raft_membership",
        "config_raft_request_outcomes",
        "config_raft_snapshot",
        "config_raft_management_audit",
        "config_raft_history_retention",
        "config_raft_capacity_records",
        "consensus_retained_binding",
    ] {
        digest.update(table.as_bytes());
        if !table_exists(conn, table).expect("authority table") {
            digest.update([0]);
            continue;
        }
        digest.update([1]);
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("authority query");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("authority rows");
        while let Some(row) = rows.next().expect("authority row") {
            digest.update([0xFF]);
            for column in 0..columns {
                match row.get_ref(column).expect("authority value") {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(value) => {
                        digest.update([1]);
                        digest.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        digest.update([2]);
                        digest.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) | ValueRef::Blob(value) => {
                        digest.update([
                            if matches!(
                                row.get_ref(column).expect("authority type"),
                                ValueRef::Text(_)
                            ) {
                                3
                            } else {
                                4
                            },
                        ]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value);
                    }
                }
            }
        }
    }
    digest.finalize().into()
}

#[tokio::test]
async fn config_capacity_957_native_retained_at_limit_preserves_record_and_profile_on_reopen() {
    let legacy = fixture(ConfigCapacityProfile::Legacy).await;
    {
        let shared = legacy.backend.conn();
        let conn = shared.lock().await;
        assert!(!table_exists(&conn, "config_raft_capacity_records").expect("legacy schema"));
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT state_json FROM config_raft_history_retention",
                [],
                |row| row.get(0),
            )
            .expect("legacy history state");
        let state: serde_json::Value = serde_json::from_slice(&bytes).expect("legacy state JSON");
        assert_eq!(state["format_version"], 1);
        assert!(state.get("capacity_profile").is_none());
        assert!(super::super::history::validate_access_for_profile_sync(
            &conn,
            &legacy.key,
            true,
            PROFILE,
            &SqliteWorkCancellation::new()
        )
        .is_err());
    }
    let fixture = fixture(PROFILE).await;
    initialize(&fixture).await;
    let intent = append_intent(
        &fixture,
        1,
        CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        CONFIG_CAPACITY_V1_REPLAY_BYTES,
        false,
        None,
    );
    let expected = match &intent {
        ConfigMutationIntent::BoundedAppend { commit, .. } => commit.record.clone(),
        _ => unreachable!("bounded fixture"),
    };
    assert!(apply(&fixture, vec![entry(&fixture, 1, intent)]).await[0]
        .result
        .is_ok());
    assert!(
        fixture
            .backend
            .load_latest()
            .await
            .expect("native read")
            .expect("head")
            .record
            == expected,
        "exact at-limit atomic readback"
    );
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        assert_eq!(counts(&conn)[..2], [1, 1]);
        assert_eq!(
            conn.query_row(
                "SELECT length(binding) FROM config_raft_capacity_records",
                [],
                |row| row.get::<_, i64>(0)
            )
            .expect("proof width"),
            44
        );
        assert!(super::super::history::validate_access_for_profile_sync(
            &conn,
            &fixture.key,
            true,
            ConfigCapacityProfile::Legacy,
            &SqliteWorkCancellation::new()
        )
        .is_err());
    }
    drop(fixture.backend);
    let reopened = SqliteBackend::reopen_config_authority(fixture.options, fixture.key)
        .await
        .expect("same native retained authority");
    assert!(
        reopened
            .load_latest()
            .await
            .expect("retained read")
            .expect("head")
            .record
            == expected,
        "exact retained at-limit readback"
    );
}

#[tokio::test]
async fn config_capacity_957_native_bad_or_missing_or_orphan_proof_rejects_even_negative_reads() {
    let fixture = fixture(PROFILE).await;
    initialize(&fixture).await;
    assert!(apply(
        &fixture,
        vec![entry(
            &fixture,
            1,
            append_intent(&fixture, 1, 128, 0, false, None)
        )]
    )
    .await[0]
        .result
        .is_ok());
    for mutation in 0..3 {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let proof: Vec<u8> = conn
            .query_row(
                "SELECT binding FROM config_raft_capacity_records",
                [],
                |row| row.get(0),
            )
            .expect("original proof");
        let state: (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT state_json, state_hmac FROM config_raft_history_retention",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("original state");
        match mutation {
            0 => {
                conn.execute("DELETE FROM config_raft_capacity_records", [])
                    .expect("remove required proof");
            }
            1 => {
                let mut changed = proof.clone();
                changed[43] ^= 1;
                conn.execute(
                    "UPDATE config_raft_capacity_records SET binding = ?1",
                    [changed],
                )
                .expect("alter proof tag");
                // Deliberately give the test writer a valid history MAC. It
                // cannot substitute for the separate immutable record proof.
                super::super::history::refresh_sync(
                    &conn,
                    &fixture.key,
                    true,
                    &SqliteWorkCancellation::new(),
                )
                .expect("reseal test history")
                .expect("unchanged history limits");
            }
            2 => {
                conn.execute_batch("PRAGMA foreign_keys = OFF")
                    .expect("test corruption setup");
                conn.execute(
                    "INSERT INTO config_raft_capacity_records (tx_id, binding) VALUES (?1, ?2)",
                    params![[0xED_u8; 16].as_slice(), &proof],
                )
                .expect("orphan proof");
                conn.execute_batch("PRAGMA foreign_keys = ON")
                    .expect("restore connection enforcement");
            }
            _ => unreachable!(),
        }
        let before = counts(&conn);
        drop(conn);
        drop(shared);
        assert!(
            fixture.backend.load_latest().await.is_err(),
            "invalid retained proof must refuse reads"
        );
        assert!(
            fixture
                .backend
                .load_since(ConfigVersion::new(u64::MAX), 0)
                .await
                .is_err(),
            "negative query must still authenticate all retained proof rows"
        );
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        assert_eq!(counts(&conn), before, "rejection has no durable effects");
        conn.execute("DELETE FROM config_raft_capacity_records", [])
            .expect("restore exact proof set");
        conn.execute(
            "INSERT INTO config_raft_capacity_records (tx_id, binding) VALUES (?1, ?2)",
            params![tx_id(1).as_uuid().as_bytes().as_slice(), proof],
        )
        .expect("restore proof");
        conn.execute(
            "UPDATE config_raft_history_retention SET state_json = ?1, state_hmac = ?2",
            params![state.0, state.1],
        )
        .expect("restore exact authenticated state");
        drop(conn);
        drop(shared);
        assert!(fixture
            .backend
            .load_latest()
            .await
            .expect("restored read")
            .is_some());
    }
}

#[tokio::test]
async fn config_capacity_957_native_history_full_rolls_back_proof_record_and_confirmation() {
    let fixture = fixture(PROFILE).await;
    initialize(&fixture).await;
    let entries = vec![
        entry(&fixture, 1, append_intent(&fixture, 1, 128, 0, false, None)),
        entry(&fixture, 2, append_intent(&fixture, 2, 128, 0, true, None)),
    ];
    assert!(apply(&fixture, entries)
        .await
        .iter()
        .all(|response| response.result.is_ok()));
    let limits =
        ConfigHistoryLimits::new(2, 8 * 1024 * 1024).expect("unchanged public history limits");
    let retention = ConfigHistoryRetention::new(
        tx_id(2),
        ConfigVersion::new(2),
        ConfigVersion::new(1),
        ConfigVersion::new(1),
        limits,
    )
    .expect("retain both records");
    assert!(apply(
        &fixture,
        vec![entry(
            &fixture,
            3,
            ConfigMutationIntent::RetainHistory(retention)
        )]
    )
    .await[0]
        .result
        .is_ok());
    let successor = append_intent(
        &fixture,
        3,
        128,
        0,
        false,
        Some(ConfirmedCommitResolution::Confirm {
            pending_tx_id: tx_id(2),
        }),
    );
    assert!(matches!(
        apply(&fixture, vec![entry(&fixture, 4, successor)]).await[0].result,
        Err(ConfigMutationFailure::HistoryFull)
    ));
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_eq!(counts(&conn)[..2], [2, 2]);
    let confirmed: Option<String> = conn
        .query_row(
            "SELECT confirmed_at FROM config_history WHERE tx_id = ?1",
            [tx_id(2).as_uuid().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("pending parent");
    assert!(
        confirmed.is_none(),
        "failed successor cannot confirm its parent"
    );
    assert_eq!(counts(&conn)[3], 0, "failed lifecycle audit is rolled back");
    super::super::history::validate_access_for_profile_sync(
        &conn,
        &fixture.key,
        true,
        PROFILE,
        &SqliteWorkCancellation::new(),
    )
    .expect("atomic failure leaves valid history");
}

#[tokio::test]
async fn config_capacity_957_native_snapshot_body_keeps_proofs_after_retention_and_outcome_removal()
{
    let fixture = fixture(PROFILE).await;
    initialize(&fixture).await;
    let entries = (1..=3)
        .map(|version| {
            entry(
                &fixture,
                version,
                append_intent(&fixture, version, 128, 0, false, None),
            )
        })
        .collect();
    assert!(apply(&fixture, entries)
        .await
        .iter()
        .all(|response| response.result.is_ok()));
    let retention = ConfigHistoryRetention::new(
        tx_id(3),
        ConfigVersion::new(3),
        ConfigVersion::new(1),
        ConfigVersion::new(2),
        ConfigHistoryLimits::new(3, 8 * 1024 * 1024).expect("limits"),
    )
    .expect("acknowledged first record");
    assert!(apply(
        &fixture,
        vec![entry(
            &fixture,
            4,
            ConfigMutationIntent::RetainHistory(retention)
        )]
    )
    .await[0]
        .result
        .is_ok());
    let raw = fixture.root.join("capacity-body.sqlite");
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    assert_eq!(counts(&conn)[..2], [2, 2]);
    // A storage-level independence check, not a simulated expiry-window run:
    // neither a Raft entry nor a retained ordinary outcome supplies this proof.
    conn.execute("DELETE FROM config_raft_request_outcomes", [])
        .expect("remove separate ordinary recovery evidence");
    let (last_log_id, last_membership) = build_snapshot_database_cancellable_sync(
        &conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        &fixture.key,
        PROFILE,
        &raw,
        &Arc::new(SqliteWorkCancellation::new()),
    )
    .expect("pinned native snapshot body");
    drop(conn);
    drop(shared);
    let meta = SnapshotMeta {
        last_log_id,
        last_membership,
        snapshot_id: "synthetic-capacity-body".to_owned(),
    };
    let source = validate_snapshot_database_sync(
        &raw,
        fixture.topology.identity(),
        fixture.topology.members(),
        &fixture.key,
        PROFILE,
        &meta,
        &Arc::new(SqliteWorkCancellation::new()),
    )
    .expect("authenticated body");
    assert_eq!(counts(&source), [2, 2, 0, 0]);
    assert_eq!(
        source
            .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row
                .get::<_, i64>(0))
            .expect("stripped log"),
        0
    );
    drop(source);
    let destination = fixture_empty_destination(&fixture).await;
    let legacy_destination = self::fixture(ConfigCapacityProfile::Legacy).await;
    let shared = destination.backend.conn();
    let conn = shared.lock().await;
    let before = authority_digest(&conn);
    {
        let corrupted = Connection::open(&raw).expect("native body corruption fixture");
        let proof: Vec<u8> = corrupted
            .query_row(
                "SELECT binding FROM config_raft_capacity_records WHERE tx_id = ?1",
                [tx_id(2).as_uuid().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("first retained proof");
        corrupted
            .execute(
                "DELETE FROM config_raft_capacity_records WHERE tx_id = ?1",
                [tx_id(2).as_uuid().as_bytes().as_slice()],
            )
            .expect("remove required snapshot proof");
        assert!(install_snapshot_database_cancellable_sync(
            &conn,
            destination.topology.identity(),
            destination.topology.members(),
            &destination.key,
            PROFILE,
            &raw,
            &meta,
            "synthetic-body.opc",
            [0xEE; 32],
            std::fs::metadata(&raw).expect("body size").len(),
            &Arc::new(SqliteWorkCancellation::new()),
        )
        .is_err());
        assert_eq!(
            authority_digest(&conn),
            before,
            "a missing source proof must reject before destination effects"
        );
        corrupted
            .execute(
                "INSERT INTO config_raft_capacity_records (tx_id, binding) VALUES (?1, ?2)",
                params![tx_id(2).as_uuid().as_bytes().as_slice(), proof],
            )
            .expect("restore exact source proof");
    }
    {
        let legacy_shared = legacy_destination.backend.conn();
        let legacy_conn = legacy_shared.lock().await;
        let legacy_before = authority_digest(&legacy_conn);
        assert!(install_snapshot_database_cancellable_sync(
            &legacy_conn,
            legacy_destination.topology.identity(),
            legacy_destination.topology.members(),
            &legacy_destination.key,
            PROFILE,
            &raw,
            &meta,
            "synthetic-body.opc",
            [0xEE; 32],
            std::fs::metadata(&raw).expect("body size").len(),
            &Arc::new(SqliteWorkCancellation::new()),
        )
        .is_err());
        assert_eq!(
            authority_digest(&legacy_conn),
            legacy_before,
            "a caller-selected profile cannot promote destination authority"
        );
    }
    install_snapshot_database_cancellable_sync(
        &conn,
        destination.topology.identity(),
        destination.topology.members(),
        &destination.key,
        PROFILE,
        &raw,
        &meta,
        "synthetic-body.opc",
        [0xEE; 32],
        std::fs::metadata(&raw).expect("body size").len(),
        &Arc::new(SqliteWorkCancellation::new()),
    )
    .expect("atomic native body installation");
    assert_eq!(counts(&conn), [2, 2, 0, 0]);
    assert!(table_exists(&conn, "consensus_retained_binding").expect("local authority preserved"));
    // The lower database installer does not choose a Raft commit frontier.
    // Supply this fixture's independently recorded committed source frontier.
    save_committed_sync(&conn, destination.topology.identity(), meta.last_log_id)
        .expect("recorded source frontier");
    drop(conn);
    drop(shared);
    let retained = destination
        .backend
        .load_since(ConfigVersion::new(1), 2)
        .await
        .expect("restored retained page");
    assert_eq!(retained.len(), 2);
    assert_eq!(
        retained[0].record.parent_tx_id,
        Some(tx_id(1)),
        "original AEAD parent survives prefix pruning"
    );
    drop(destination.backend);
    let reopened = SqliteBackend::reopen_config_authority(destination.options, destination.key)
        .await
        .expect("installed native body retained reopen");
    assert_eq!(
        reopened
            .load_latest()
            .await
            .expect("restored read")
            .expect("head")
            .record
            .version,
        ConfigVersion::new(3)
    );
    // This is a database-body test. The synthetic receipt does not qualify a
    // snapshot footer, chunked transport or a running larger-profile store.
}

async fn fixture_empty_destination(source: &Fixture) -> Fixture {
    let destination = fixture(PROFILE).await;
    assert!(destination.topology.identity() == source.topology.identity());
    destination
}
