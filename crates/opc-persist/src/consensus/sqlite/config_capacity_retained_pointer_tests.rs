//! Retained validation work and lineage checks on synthetic SQLite WAL files.
//! This exercises the actual durable-log validator, not a running consensus
//! cluster or a retained-store reopen/latency qualification.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::types::PreparedConfigCommit;
use crate::consensus::{ConfigConsensusCommand, ConfigConsensusRequestId};
use crate::{AttestedConfigCommit, CommitRecord};
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_crypto::{CONFIG_CAPACITY_V1_LOGICAL_BYTES, CONFIG_CAPACITY_V1_REPLAY_BYTES};
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use std::cell::RefCell;

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const MODE: RetainedConfigMode = RetainedConfigMode::BoundedV1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DecodeCounts {
    by_index: [usize; 3],
    other: usize,
}

struct DecodeObservation {
    counts: DecodeCounts,
    cancel_after_index: Option<(u64, Arc<SqliteWorkCancellation>)>,
}

thread_local! {
    static DECODES: RefCell<Option<DecodeObservation>> = const { RefCell::new(None) };
}

// Called only after the real row decoder and its SQL/JSON consistency check.
// No payload, key, connection or decoded owner is retained by the observer.
pub(super) fn row_decoded(index: u64) {
    DECODES.with(|current| {
        let mut current = current.borrow_mut();
        let Some(observation) = current.as_mut() else {
            return;
        };
        if let Some(count) = observation
            .counts
            .by_index
            .get_mut(usize::try_from(index).unwrap_or(usize::MAX))
        {
            *count += 1;
        } else {
            observation.counts.other += 1;
        }
        if observation
            .cancel_after_index
            .as_ref()
            .is_some_and(|(expected, _)| *expected == index)
        {
            let (_, cancellation) = observation.cancel_after_index.take().unwrap();
            assert!(cancellation.cancel_before_commit());
        }
    });
}

fn count_decodes<T>(
    cancel_after_index: Option<(u64, Arc<SqliteWorkCancellation>)>,
    action: impl FnOnce() -> T,
) -> (T, DecodeCounts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DECODES.with(|current| *current.borrow_mut() = None);
        }
    }
    DECODES.with(|current| {
        let mut current = current.borrow_mut();
        assert!(
            current.is_none(),
            "one synchronous validation per observation"
        );
        *current = Some(DecodeObservation {
            counts: DecodeCounts::default(),
            cancel_after_index,
        });
    });
    let _reset = Reset;
    let result = action();
    let counts = DECODES.with(|current| current.borrow().as_ref().unwrap().counts);
    (result, counts)
}

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0xA1; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xA2; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn node(value: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(value).unwrap()
}

fn members() -> BTreeSet<ConsensusNodeId> {
    BTreeSet::from([node(1)])
}

fn log_id(index: u64) -> LogId<ConsensusNodeId> {
    LogId::new(CommittedLeaderId::new(1, node(1)), index)
}

fn blank(index: u64) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Blank,
    }
}

fn audit_key() -> AuditKey {
    AuditKey::new([0xA3; 32]).unwrap()
}

struct Fixture {
    conn: Connection,
    key: AuditKey,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(entries: &[Entry<ConfigRaftTypeConfig>]) -> Self {
        let directory = tempfile::tempdir().expect("private synthetic WAL directory");
        let conn = Connection::open(directory.path().join("log.sqlite")).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=EXTRA;")
            .unwrap();
        assert!(crate::schema::verify_wal_mode(&conn).unwrap());
        assert!(crate::schema::verify_synchronous_extra(&conn).unwrap());
        conn.execute_batch(CONFIG_RAFT_SCHEMA).unwrap();
        let key = audit_key();
        validate_entry_capacities(entries, identity(), &key, MODE)
            .expect("authentic bounded fixture before native append");
        append_logs_sync(&conn, identity(), &members(), entries, MODE)
            .expect("actual native log append");
        Self {
            conn,
            key,
            _directory: directory,
        }
    }

    fn blanks(count: u64) -> Self {
        Self::new(&(0..count).map(blank).collect::<Vec<_>>())
    }

    fn pointer(&self, table: &'static str, pointer: Option<LogId<ConsensusNodeId>>) {
        if let Some(pointer) = pointer {
            save_log_pointer(&self.conn, table, identity(), &pointer).unwrap();
        } else {
            self.conn
                .execute(&format!("DELETE FROM {table}"), [])
                .unwrap();
        }
    }

    fn snapshot(&self, pointer: Option<LogId<ConsensusNodeId>>) {
        let Some(pointer) = pointer else {
            self.conn
                .execute("DELETE FROM config_raft_snapshot", [])
                .unwrap();
            return;
        };
        save_current_snapshot_sync(
            &self.conn,
            identity(),
            &members(),
            &SnapshotMeta {
                last_log_id: Some(pointer),
                last_membership: StoredMembership::new(
                    Some(log_id(0)),
                    Membership::new(vec![members()], members()),
                ),
                snapshot_id: "synthetic-retained-pointer".to_owned(),
            },
            "snapshot-test.opc",
            [0xA4; 32],
            128,
        )
        .unwrap();
    }

    fn validate(&self) -> io::Result<()> {
        self.validate_with(false, &SqliteWorkCancellation::new())
    }

    fn validate_with(
        &self,
        allow_detached_snapshot: bool,
        cancellation: &SqliteWorkCancellation,
    ) -> io::Result<()> {
        validate_durable_log_state_sync(
            &self.conn,
            identity(),
            &members(),
            &self.key,
            MODE,
            allow_detached_snapshot,
            cancellation,
        )
    }

    fn raw(&self, index: u64) -> Vec<u8> {
        self.conn
            .query_row(
                "SELECT entry_json FROM config_raft_log WHERE log_index=?1",
                [checked_i64(index).unwrap()],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn replace_entry(&self, index: u64, entry: &Entry<ConfigRaftTypeConfig>) {
        self.conn
            .execute(
                "UPDATE config_raft_log SET entry_json=?1 WHERE log_index=?2",
                params![
                    serde_json::to_vec(entry).unwrap(),
                    checked_i64(index).unwrap()
                ],
            )
            .unwrap();
    }
}

struct BoundedEntry {
    entry: Entry<ConfigRaftTypeConfig>,
    record: CommitRecord,
    plaintext: Vec<u8>,
    handle: KeyHandle,
    aad: EnvelopeAad,
}

fn bounded_entry(index: u64, logical: usize, replay: usize) -> BoundedEntry {
    let mut config = vec![b'q'; logical];
    config[0] = b'"';
    config[logical - 1] = b'"';
    let plaintext = if replay == 0 {
        config
    } else {
        let mut framed = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":".to_vec();
        framed.extend_from_slice(&config);
        framed.extend_from_slice(b",\"idempotency_key\":\"");
        let padding = replay.checked_sub(framed.len() - logical + 2).unwrap();
        framed.resize(framed.len() + padding, b'r');
        framed.extend_from_slice(b"\"}");
        framed
    };
    assert_eq!(plaintext.len(), logical + replay);
    let committed_at = Timestamp::from_str("2026-01-01T00:00:00Z").unwrap();
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0xA500 + u128::from(index)));
    let principal = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config";
    let schema_digest = SchemaDigest::from_bytes([0xA6; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        1,
        ConfigAad::new(
            tx_id,
            None,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .unwrap(),
    );
    let handle = KeyHandle::new(
        KeyId::new("synthetic-retained-pointer-key").unwrap(),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xA7; 32]),
    );
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        &plaintext,
        [u8::try_from(index).unwrap(); 12],
    )
    .expect("real bounded AEAD encryption and one-shot capacity evidence");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let attested =
        AttestedConfigCommit::try_new(record.clone(), Vec::new(), envelope.claim().unwrap())
            .expect("claim paired with the exact record");
    let evidence = attested.capacity_evidence().unwrap();
    assert_eq!(evidence.logical_bytes(), logical);
    assert_eq!(evidence.replay_bytes(), replay);
    let key = audit_key();
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key, PROFILE)
        .expect("authenticated capacity record for the independent scope");
    let (prepared_record, audit, _) = attested.into_parts();
    let prepared = PreparedConfigCommit::prepare(prepared_record, audit, &key).unwrap();
    BoundedEntry {
        entry: Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: 8,
                identity: identity(),
                request_id: ConfigConsensusRequestId::from_bytes(
                    [u8::try_from(index).unwrap(); 16],
                ),
                logical_time: committed_at,
                intent: ConfigMutationIntent::prepared_append(prepared, None, Some(binding)),
            }),
        },
        record,
        plaintext,
        handle,
        aad,
    }
}

fn assert_invalid(result: io::Result<()>) {
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

fn assert_invalid_message(result: io::Result<()>, expected: &str) {
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), expected);
}

#[test]
fn retained_pointer_validation_decodes_each_authenticated_row_once() {
    let bounded = bounded_entry(
        1,
        CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        CONFIG_CAPACITY_V1_REPLAY_BYTES,
    );
    let membership = Entry {
        log_id: log_id(0),
        payload: EntryPayload::Membership(Membership::new(vec![members()], members())),
    };
    let entries = [membership, bounded.entry.clone(), blank(2)];
    let fixture = Fixture::new(&entries);
    fixture.pointer("config_raft_applied", Some(log_id(1)));
    fixture.pointer("config_raft_committed", Some(log_id(1)));
    let before: Vec<_> = (0..3).map(|index| fixture.raw(index)).collect();
    let mut observed = Vec::new();
    for snapshot in [None, Some(log_id(1))] {
        fixture.snapshot(snapshot);
        // Repeating independent calls must still validate every retained row.
        for _ in 0..2 {
            let (result, counts) = count_decodes(None, || fixture.validate());
            result.expect("complete authenticated durable-log validation");
            observed.push(counts);
        }
    }

    // All byte, lineage, independent decode and authentication assertions run
    // before the work detector, including in the tests-first/control state.
    assert_eq!(
        read_applied_sync(&fixture.conn, identity()).unwrap(),
        Some(log_id(1))
    );
    assert_eq!(
        read_committed_sync(&fixture.conn, identity()).unwrap(),
        Some(log_id(1))
    );
    for (index, entry) in entries.iter().enumerate() {
        let raw = fixture.raw(u64::try_from(index).unwrap());
        assert!(raw == before[index], "durable validation is read-only");
        assert!(
            raw == serde_json::to_vec(entry).unwrap(),
            "independent canonical bytes"
        );
        let decoded: Entry<ConfigRaftTypeConfig> = serde_json::from_slice(&raw).unwrap();
        validate_entry(&decoded, identity(), &members(), MODE).unwrap();
        validate_entry_capacities(
            std::slice::from_ref(&decoded),
            identity(),
            &fixture.key,
            MODE,
        )
        .unwrap();
        assert_eq!(decoded.log_id, entry.log_id);
        if index == 1 {
            let EntryPayload::Normal(command) = decoded.payload else {
                panic!("authenticated bounded command")
            };
            let ConfigMutationIntent::BoundedAppend {
                commit, binding, ..
            } = command.intent
            else {
                panic!("authenticated bounded append")
            };
            assert!(
                commit.record == bounded.record,
                "exact authenticated record readback"
            );
            binding
                .verify(&commit.record, identity(), &fixture.key, PROFILE)
                .unwrap();
            let plaintext = opc_crypto::decrypt_envelope_with_handle(
                &bounded.handle,
                &bounded.aad,
                &commit.record.encrypted_blob,
            )
            .expect("AEAD authentication after exact byte readback");
            assert!(
                plaintext.as_slice() == bounded.plaintext.as_slice(),
                "exact authenticated plaintext readback"
            );
            assert_eq!(
                Sha256::digest(plaintext.as_slice()).as_slice(),
                commit.record.plaintext_digest
            );
        }
    }
    assert_eq!(
        observed,
        vec![
            DecodeCounts {
                by_index: [1, 1, 1],
                other: 0
            };
            4
        ],
        "RETAINED_POINTER_SINGLE_DECODE: each retained row is decoded once per complete validation"
    );
}

#[test]
fn retained_pointer_validation_matches_distinct_pointer_indices() {
    let fixture = Fixture::blanks(3);
    for snapshot in 0..3 {
        for applied in 0..3 {
            for committed in applied..3 {
                fixture.snapshot(Some(log_id(snapshot)));
                fixture.pointer("config_raft_applied", Some(log_id(applied)));
                fixture.pointer("config_raft_committed", Some(log_id(committed)));
                fixture
                    .validate()
                    .expect("all three pointer slots match their exact retained rows");
            }
        }
    }
}

#[test]
fn retained_pointer_validation_requires_exact_applied_and_committed_ids() {
    for (table, message) in [
        (
            "config_raft_applied",
            "config consensus applied pointer lacks log or snapshot lineage",
        ),
        (
            "config_raft_committed",
            "config consensus committed pointer lacks durable lineage",
        ),
    ] {
        let fixture = Fixture::blanks(3);
        fixture.pointer(table, Some(log_id(1)));
        fixture
            .validate()
            .expect("exact pointer is covered by its retained row");
        for mismatch in [LogId::new(CommittedLeaderId::new(2, node(1)), 1), log_id(3)] {
            fixture.pointer(table, Some(mismatch));
            assert_invalid_message(fixture.validate(), message);
        }
        // The pinned single-term-leader mode identifies committed leaders by
        // term alone. A different constructor node is the same committed ID.
        let equivalent = LogId::new(CommittedLeaderId::new(1, node(2)), 1);
        assert_eq!(equivalent, log_id(1));
        fixture.pointer(table, Some(equivalent));
        fixture
            .validate()
            .expect("equivalent committed ID is covered");
    }
}

#[test]
fn retained_pointer_validation_checks_snapshot_conflicts_and_index_domain() {
    let fixture = Fixture::blanks(3);
    fixture.pointer("config_raft_applied", Some(log_id(1)));
    fixture.pointer("config_raft_committed", Some(log_id(1)));
    let equivalent = LogId::new(CommittedLeaderId::new(1, node(2)), 1);
    assert_eq!(equivalent, log_id(1));
    fixture.snapshot(Some(equivalent));
    fixture
        .validate()
        .expect("equivalent snapshot ID is covered");
    fixture.snapshot(Some(LogId::new(CommittedLeaderId::new(2, node(1)), 1)));
    assert_invalid_message(
        fixture.validate(),
        "config consensus snapshot conflicts with durable log",
    );
    fixture.snapshot(Some(log_id(3)));
    fixture
        .validate()
        .expect("absent snapshot row permits a complete unpurged prefix");
    for count in [0, 3] {
        let fixture = Fixture::blanks(count);
        fixture.snapshot(Some(log_id(u64::try_from(i64::MAX).unwrap() + 1)));
        assert_invalid(fixture.validate());
    }
}

#[test]
fn retained_pointer_validation_preserves_empty_log_lineage_fallbacks() {
    let current = Some(log_id(1));
    let older = Some(log_id(0));
    // Snapshot presence and exact pointer coverage are separate existing rules.
    // An older snapshot here deliberately isolates the purged-pointer fallback.
    let cases = [
        (None, None, None, None, false, true),
        (current, current, current, None, false, true),
        (current, current, None, None, false, true),
        (current, None, current, None, false, true),
        (older, current, current, current, false, true),
        (older, None, current, current, false, true),
        (None, current, current, current, false, false),
        (None, current, current, current, true, true),
        (None, current, current, None, false, false),
        (None, current, current, None, true, true),
        (None, None, current, None, true, false),
    ];
    for (snapshot, applied, committed, purged, allow_detached, accepted) in cases {
        let fixture = Fixture::blanks(0);
        fixture.snapshot(snapshot);
        fixture.pointer("config_raft_applied", applied);
        fixture.pointer("config_raft_committed", committed);
        fixture.pointer("config_raft_purged", purged);
        let result = fixture.validate_with(allow_detached, &SqliteWorkCancellation::new());
        if accepted {
            result.expect("existing empty-log lineage fallback");
        } else {
            assert_invalid(result);
        }
    }

    // The existing detached-snapshot allowance can cover a mismatching applied
    // row; committed may then use that exact applied pointer. It must not cover
    // a committed-only pointer or waive a snapshot conflict.
    let fixture = Fixture::blanks(3);
    let detached = LogId::new(CommittedLeaderId::new(2, node(1)), 1);
    fixture.pointer("config_raft_applied", Some(detached));
    fixture.pointer("config_raft_committed", Some(detached));
    fixture
        .validate_with(true, &SqliteWorkCancellation::new())
        .unwrap();
    assert_invalid(fixture.validate());
    fixture.pointer("config_raft_applied", None);
    assert_invalid(fixture.validate_with(true, &SqliteWorkCancellation::new()));
    fixture.snapshot(Some(detached));
    assert_invalid_message(
        fixture.validate_with(true, &SqliteWorkCancellation::new()),
        "config consensus snapshot conflicts with durable log",
    );
}

#[test]
fn retained_pointer_validation_preserves_pointer_ordering() {
    for (purged, applied, committed) in [
        (None, Some(log_id(2)), Some(log_id(1))),
        (
            None,
            Some(LogId::new(CommittedLeaderId::new(2, node(1)), 1)),
            Some(log_id(1)),
        ),
        (Some(log_id(2)), Some(log_id(1)), None),
        (Some(log_id(2)), None, Some(log_id(1))),
    ] {
        let fixture = Fixture::blanks(3);
        fixture.pointer("config_raft_purged", purged);
        fixture.pointer("config_raft_applied", applied);
        fixture.pointer("config_raft_committed", committed);
        assert_invalid_message(
            fixture.validate(),
            "config consensus durable log pointers are inconsistent",
        );
    }
    let fixture = Fixture::blanks(3);
    let equivalent = LogId::new(CommittedLeaderId::new(1, node(2)), 1);
    assert_eq!(equivalent, log_id(1));
    fixture.pointer("config_raft_applied", Some(equivalent));
    fixture.pointer("config_raft_committed", Some(log_id(1)));
    fixture
        .validate()
        .expect("equivalent IDs preserve pointer ordering");
}

#[test]
fn retained_pointer_validation_rejects_pointed_and_unpointed_corruption() {
    for index in [1, 2] {
        for fault in [
            "json",
            "term",
            "index",
            "epoch",
            "identity",
            "schema",
            "membership",
        ] {
            let fixture = Fixture::blanks(3);
            fixture.pointer("config_raft_applied", Some(log_id(1)));
            fixture.pointer("config_raft_committed", Some(log_id(1)));
            fixture.snapshot(Some(log_id(1)));
            fixture.validate().unwrap();
            let mut corrupt = blank(index);
            match fault {
                "json" => {
                    fixture
                        .conn
                        .execute(
                            "UPDATE config_raft_log SET entry_json=?1 WHERE log_index=?2",
                            params![b"{".as_slice(), checked_i64(index).unwrap()],
                        )
                        .unwrap();
                }
                "term" => {
                    fixture
                        .conn
                        .execute(
                            "UPDATE config_raft_log SET term=2 WHERE log_index=?1",
                            [checked_i64(index).unwrap()],
                        )
                        .unwrap();
                }
                "epoch" => {
                    fixture
                        .conn
                        .execute(
                            "UPDATE config_raft_log SET configuration_epoch=2 WHERE log_index=?1",
                            [checked_i64(index).unwrap()],
                        )
                        .unwrap();
                }
                "index" => {
                    corrupt.log_id.index += 1;
                    fixture.replace_entry(index, &corrupt);
                }
                "identity" | "schema" => {
                    let mut command = ConfigConsensusCommand {
                        schema_version: 8,
                        identity: identity(),
                        request_id: ConfigConsensusRequestId::from_bytes([0xA8; 16]),
                        logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
                        intent: ConfigMutationIntent::MarkConfirmed {
                            tx_id: TxId::from_uuid(uuid::Uuid::from_u128(0xA9)),
                        },
                    };
                    if fault == "identity" {
                        command.identity = ConsensusIdentity::new(
                            opc_consensus::ConsensusClusterId::from_bytes([0xAA; 32]),
                            identity().configuration_id(),
                            identity().configuration_epoch(),
                        );
                    } else {
                        command.schema_version = u16::MAX;
                    }
                    corrupt.payload = EntryPayload::Normal(command);
                    fixture.replace_entry(index, &corrupt);
                }
                "membership" => {
                    let foreign = BTreeSet::from([node(1), node(2)]);
                    corrupt.payload =
                        EntryPayload::Membership(Membership::new(vec![foreign.clone()], foreign));
                    fixture.replace_entry(index, &corrupt);
                }
                _ => unreachable!(),
            }
            assert_invalid(fixture.validate());
        }
    }
}

#[test]
fn retained_pointer_validation_authenticates_pointed_and_unpointed_bounded_entries() {
    for index in [1, 2] {
        let bounded = bounded_entry(index, 256, 0);
        let mut entries = [blank(0), blank(1), blank(2)];
        entries[usize::try_from(index).unwrap()] = bounded.entry.clone();
        let fixture = Fixture::new(&entries);
        fixture.pointer("config_raft_applied", Some(log_id(1)));
        fixture.pointer("config_raft_committed", Some(log_id(1)));
        fixture.validate().unwrap();
        for (key, mode) in [
            (AuditKey::new([0xAB; 32]).unwrap(), MODE),
            (audit_key(), RetainedConfigMode::Legacy),
        ] {
            assert_invalid(validate_durable_log_state_sync(
                &fixture.conn,
                identity(),
                &members(),
                &key,
                mode,
                false,
                &SqliteWorkCancellation::new(),
            ));
        }
        let mut tampered = bounded.entry.clone();
        let EntryPayload::Normal(command) = &mut tampered.payload else {
            panic!("bounded command")
        };
        let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut command.intent else {
            panic!("bounded append")
        };
        *commit.record.encrypted_blob.last_mut().unwrap() ^= 1;
        validate_entry(&tampered, identity(), &members(), MODE)
            .expect("structural checks alone do not authenticate ciphertext");
        fixture.replace_entry(index, &tampered);
        assert_invalid_message(fixture.validate(), "invalid config capacity command");
        assert!(
            fixture.raw(index) == serde_json::to_vec(&tampered).unwrap(),
            "validation does not repair tampered bytes"
        );
        fixture.replace_entry(index, &bounded.entry);
        fixture
            .validate()
            .expect("restored authentic record still validates");
    }
}

#[test]
fn retained_pointer_validation_preserves_holes_and_snapshot_purge_floors() {
    let fixture = Fixture::blanks(3);
    fixture
        .conn
        .execute("DELETE FROM config_raft_log WHERE log_index=1", [])
        .unwrap();
    assert_invalid_message(
        fixture.validate(),
        "persisted config consensus log contains a hole",
    );

    let fixture = Fixture::blanks(3);
    fixture
        .conn
        .execute("DELETE FROM config_raft_log WHERE log_index=0", [])
        .unwrap();
    assert_invalid_message(
        fixture.validate(),
        "persisted config consensus log is detached from its floor",
    );

    let fixture = Fixture::blanks(3);
    fixture.snapshot(Some(log_id(1)));
    fixture.pointer("config_raft_purged", Some(log_id(1)));
    assert_invalid_message(
        fixture.validate(),
        "persisted config consensus log crosses purged floor",
    );
    fixture
        .conn
        .execute("DELETE FROM config_raft_log WHERE log_index<=1", [])
        .unwrap();
    fixture.validate().expect("exact purged suffix floor");
    fixture.pointer("config_raft_purged", None);
    fixture
        .validate()
        .expect("exact snapshot-only suffix floor");
    fixture.snapshot(Some(log_id(0)));
    assert_invalid_message(
        fixture.validate(),
        "persisted config consensus log is detached from its floor",
    );
}

#[test]
fn retained_pointer_validation_honors_cancellation_before_and_during_scan() {
    let fixture = Fixture::blanks(3);
    fixture.snapshot(Some(log_id(1)));
    fixture.pointer("config_raft_applied", Some(log_id(1)));
    fixture.pointer("config_raft_committed", Some(log_id(1)));
    let before: Vec<_> = (0..3).map(|index| fixture.raw(index)).collect();

    let cancelled = SqliteWorkCancellation::new();
    assert!(cancelled.cancel_before_commit());
    let (result, counts) = count_decodes(None, || fixture.validate_with(false, &cancelled));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        counts,
        DecodeCounts::default(),
        "cancelled before any row decode"
    );

    let cancellation = Arc::new(SqliteWorkCancellation::new());
    let (result, counts) = count_decodes(Some((0, cancellation.clone())), || {
        fixture.validate_with(false, &cancellation)
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        counts.by_index[0], 1,
        "cancel at the first mandatory scan row"
    );
    assert_eq!(
        counts.by_index[2], 0,
        "the later unpointed row is never decoded"
    );
    assert_eq!(counts.other, 0);
    assert_eq!(
        (0..3).map(|index| fixture.raw(index)).collect::<Vec<_>>(),
        before
    );
    fixture
        .validate()
        .expect("cancellation did not mutate durable state");
}
