//! Native append-floor ownership and rollback on synthetic disk-backed WALs.
//! Samples borrow actual owners synchronously and retain scalar extents only.
//! This component control does not qualify a whole-operation memory bound.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::types::PreparedConfigCommit;
use crate::consensus::{ConfigConsensusCommand, ConfigConsensusRequestId};
use crate::{AttestedConfigCommit, CommitRecord};
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use std::cell::RefCell;

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const MODE: RetainedConfigMode = RetainedConfigMode::BoundedV1;

#[derive(Clone, Copy, Debug, Default)]
struct Outputs {
    count: usize,
    bytes: usize,
    initialized: usize,
}

impl Outputs {
    fn borrow(outputs: &[Vec<u8>]) -> Self {
        Self {
            count: outputs.len(),
            bytes: outputs.iter().map(Vec::capacity).sum(),
            initialized: outputs.iter().map(Vec::len).sum(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RowSample {
    index: u64,
    ciphertext_capacity: usize,
    ciphertext_len: usize,
    completed: Outputs,
    order: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct Receipt {
    decoded: RowSample,
    decodes: usize,
    ready: Outputs,
    ready_order: usize,
    inserted: usize,
    floor_scopes: usize,
    cancellation_observed: bool,
}

struct Observation {
    receipt: Receipt,
    floor: Option<Outputs>,
    order: usize,
    cancel_after_insert: Option<Arc<SqliteWorkCancellation>>,
}

thread_local! {
    static OBSERVATION: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

// Keeping this immutable borrow in the scope proves that the scalar output
// extents remain current while the real previous-row decoder owns its DTO.
pub(super) struct FloorScope<'a> {
    _outputs: Option<&'a Vec<Vec<u8>>>,
}

impl<'a> FloorScope<'a> {
    pub(super) fn enter(outputs: Option<&'a Vec<Vec<u8>>>) -> Self {
        OBSERVATION.with_borrow_mut(|observation| {
            if let Some(observation) = observation {
                assert!(observation.floor.is_none());
                observation.floor =
                    Some(outputs.map_or(Outputs::default(), |v| Outputs::borrow(v)));
                observation.receipt.floor_scopes += 1;
            }
        });
        Self { _outputs: outputs }
    }
}

impl Drop for FloorScope<'_> {
    fn drop(&mut self) {
        OBSERVATION.with_borrow_mut(|observation| {
            if let Some(observation) = observation {
                assert!(observation.floor.take().is_some());
                observation.receipt.floor_scopes -= 1;
            }
        });
    }
}

pub(super) fn row_decoded(entry: &Entry<ConfigRaftTypeConfig>) {
    OBSERVATION.with_borrow_mut(|observation| {
        let Some(observation) = observation else {
            return;
        };
        let Some(completed) = observation.floor else {
            return;
        };
        let EntryPayload::Normal(command) = &entry.payload else {
            return;
        };
        let ConfigMutationIntent::BoundedAppend { commit, .. } = &command.intent else {
            return;
        };
        observation.order += 1;
        observation.receipt.decodes += 1;
        observation.receipt.decoded = RowSample {
            index: entry.log_id.index,
            ciphertext_capacity: commit.record.encrypted_blob.capacity(),
            ciphertext_len: commit.record.encrypted_blob.len(),
            completed,
            order: observation.order,
        };
    });
}

pub(super) fn outputs_ready(outputs: &[Vec<u8>]) {
    OBSERVATION.with_borrow_mut(|observation| {
        if let Some(observation) = observation {
            observation.order += 1;
            observation.receipt.ready = Outputs::borrow(outputs);
            observation.receipt.ready_order = observation.order;
        }
    });
}

pub(super) fn inserted(_: u64) {
    OBSERVATION.with_borrow_mut(|observation| {
        if let Some(observation) = observation {
            observation.receipt.inserted += 1;
            if let Some(cancellation) = observation.cancel_after_insert.take() {
                assert!(cancellation.cancel_before_commit());
                observation.receipt.cancellation_observed = cancellation.is_cancelled();
            }
        }
    });
}

struct Registration;

impl Registration {
    fn start(cancel_after_insert: Option<Arc<SqliteWorkCancellation>>) -> Self {
        OBSERVATION.with_borrow_mut(|slot| {
            assert!(slot.is_none(), "one synchronous append observation");
            *slot = Some(Observation {
                receipt: Receipt::default(),
                floor: None,
                order: 0,
                cancel_after_insert,
            });
        });
        Self
    }

    fn finish(self) -> Receipt {
        OBSERVATION.with_borrow_mut(|slot| {
            let observation = slot.take().unwrap();
            assert!(
                observation.floor.is_none(),
                "final native floor borrow drained"
            );
            assert_eq!(observation.receipt.floor_scopes, 0);
            observation.receipt
        })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        OBSERVATION.with_borrow_mut(|slot| *slot = None);
    }
}

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0xD1; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xD2; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn node(value: u64) -> ConsensusNodeId {
    ConsensusNodeId::new(value).unwrap()
}

fn members() -> BTreeSet<ConsensusNodeId> {
    BTreeSet::from([node(1)])
}

fn key() -> AuditKey {
    AuditKey::new([0xD3; 32]).unwrap()
}

fn bounded_entry(index: u64, size: usize) -> Entry<ConfigRaftTypeConfig> {
    let tx_id = TxId::new();
    let committed_at = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
    let schema_digest = SchemaDigest::from_bytes([0xD4; 32]);
    let principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
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
        KeyId::new("native-append-floor").unwrap(),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xD5; 32]),
    );
    let mut plaintext = vec![b'x'; size];
    plaintext[0] = b'"';
    plaintext[size - 1] = b'"';
    let mut nonce = [0xD6; 12];
    nonce[0] = index as u8;
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle, &aad, &plaintext, nonce,
    )
    .unwrap();
    let attested = AttestedConfigCommit::try_new(
        CommitRecord {
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
        },
        Vec::new(),
        envelope.claim().unwrap(),
    )
    .unwrap();
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE).unwrap();
    let (record, audit, _) = attested.into_parts();
    let commit = PreparedConfigCommit::prepare(record, audit, &key()).unwrap();
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, node(1)), index),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: 8,
            identity: identity(),
            request_id: ConfigConsensusRequestId::from_bytes([index as u8; 16]),
            logical_time: committed_at,
            intent: ConfigMutationIntent::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution: None,
            },
        }),
    }
}

fn digest(entry: &Entry<ConfigRaftTypeConfig>) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(entry).unwrap()).into()
}

struct Fixture {
    conn: Connection,
    directory: tempfile::TempDir,
    previous: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let scratch = std::env::var_os("TMPDIR")
            .or_else(|| {
                (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                    .then(|| std::env::var_os("RUNNER_TEMP"))
                    .flatten()
            })
            .expect("explicit disk scratch root");
        let directory = tempfile::Builder::new()
            .prefix("native-append-floor-")
            .tempdir_in(scratch)
            .unwrap();
        let filesystem = std::process::Command::new("findmnt")
            .args(["-n", "-o", "FSTYPE", "-T"])
            .arg(directory.path())
            .output()
            .unwrap();
        assert!(filesystem.status.success());
        let filesystem = std::str::from_utf8(&filesystem.stdout).unwrap().trim();
        assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
        let conn = Connection::open(directory.path().join("append.sqlite")).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=EXTRA;")
            .unwrap();
        assert!(crate::schema::verify_wal_mode(&conn).unwrap());
        assert!(crate::schema::verify_synchronous_extra(&conn).unwrap());
        conn.execute_batch(CONFIG_RAFT_SCHEMA).unwrap();
        let entry = bounded_entry(0, 262_144);
        validate_entry_capacities(std::slice::from_ref(&entry), identity(), &key(), MODE).unwrap();
        append_logs_sync(
            &conn,
            identity(),
            &members(),
            std::slice::from_ref(&entry),
            MODE,
        )
        .unwrap();
        let previous = digest(&entry);
        drop(entry);
        Self {
            conn,
            directory,
            previous,
        }
    }

    fn count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
            .unwrap()
    }

    fn finish(self, expected: &[[u8; 32]]) {
        let Self {
            conn,
            directory,
            previous,
        } = self;
        assert!(conn.is_autocommit(), "no pending native transaction");
        conn.close().unwrap();
        let reopened = Connection::open(directory.path().join("append.sqlite")).unwrap();
        let rows =
            read_log_range_sync(&reopened, identity(), &members(), 0, None, None, MODE).unwrap();
        assert_eq!(rows.len(), expected.len() + 1);
        assert_eq!(
            digest(&rows[0]),
            previous,
            "exact original previous durable row"
        );
        for (entry, expected) in rows[1..].iter().zip(expected) {
            assert_eq!(&digest(entry), expected, "exact original appended row");
            validate_entry_capacities(std::slice::from_ref(entry), identity(), &key(), MODE)
                .unwrap();
        }
        drop(rows);
        reopened.close().unwrap();
        drop(directory);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Success,
    CancelAfterInsert,
    RejectEncoding,
}

struct Outcome {
    receipt: Receipt,
    error: Option<(io::ErrorKind, String)>,
    attempted_rows: usize,
}

fn run(case: Case) -> Outcome {
    let fixture = Fixture::new();
    let size = if case == Case::RejectEncoding {
        opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES
    } else {
        131_072
    };
    let source = bounded_entry(1, size);
    let count = if case == Case::RejectEncoding { 13 } else { 2 };
    let entries: Vec<_> = (1..=count)
        .map(|index| {
            let mut entry = source.clone();
            entry.log_id.index = index;
            entry
        })
        .collect();
    drop(source);
    validate_entry_capacities(&entries, identity(), &key(), MODE).unwrap();
    // Only fixed-size digest witnesses survive into the actual append.
    let expected: Vec<_> = entries.iter().map(digest).collect();
    let cancellation = Arc::new(SqliteWorkCancellation::new());
    let observation =
        Registration::start((case == Case::CancelAfterInsert).then(|| cancellation.clone()));
    let result = append_logs_cancellable_sync(
        &fixture.conn,
        identity(),
        &members(),
        &entries,
        &cancellation,
        MODE,
    );
    let receipt = observation.finish();
    let error = result.err().map(|error| (error.kind(), error.to_string()));
    assert!(
        fixture.conn.is_autocommit(),
        "native success or rollback completed"
    );
    let attempted_rows = fixture.count();
    let retained = if case == Case::Success {
        count as usize
    } else {
        1
    };
    if case != Case::Success {
        // The failed transaction must release its write lock and permit a
        // genuine subsequent append through the unchanged native path.
        append_logs_sync(&fixture.conn, identity(), &members(), &entries[..1], MODE).unwrap();
    }
    drop(entries);
    drop(cancellation);
    fixture.finish(&expected[..retained]);
    OBSERVATION.with_borrow(|slot| assert!(slot.is_none()));
    println!(
        "CAPACITY_NATIVE_FLOOR_CLEANUP original_inputs_dropped=true floor_scopes=0 native_closed=true reopened=true exact_rows=true attempted_rows={attempted_rows}"
    );
    Outcome {
        receipt,
        error,
        attempted_rows,
    }
}

#[test]
fn capacity_native_append_floor_previous_row_retires_before_completed_outputs() {
    let outcome = run(Case::Success);
    assert!(outcome.error.is_none());
    assert_eq!(outcome.attempted_rows, 3);
    assert_eq!(
        outcome.receipt.decodes, 1,
        "real prior-row decoder was reached"
    );
    let row = outcome.receipt.decoded;
    assert_eq!(row.index, 0);
    assert!(row.ciphertext_len > 262_144);
    assert!(row.ciphertext_capacity >= row.ciphertext_len);
    assert_eq!(
        outcome.receipt.ready.count, 2,
        "actual completed append outputs"
    );
    assert!(outcome.receipt.ready.bytes >= outcome.receipt.ready.initialized);
    assert!(outcome.receipt.ready.initialized > 262_144);
    println!(
        "CAPACITY_NATIVE_FLOOR_OWNERS prior_ciphertext_capacity={} simultaneous_completed_outputs={} simultaneous_json_capacity={} final_outputs={} final_json_capacity={}",
        row.ciphertext_capacity, row.completed.count, row.completed.bytes,
        outcome.receipt.ready.count, outcome.receipt.ready.bytes
    );
    assert!(
        row.completed.count == 0
            && row.completed.bytes == 0
            && row.order < outcome.receipt.ready_order,
        "CAPACITY_NATIVE_FLOOR_OVERLAP_RED: the previous decoded row must retire before completed append outputs"
    );
}

#[test]
fn capacity_native_append_floor_cancellation_rolls_back_partial_rows() {
    let outcome = run(Case::CancelAfterInsert);
    assert_eq!(
        outcome.error.as_ref().map(|error| error.0),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(
        outcome.attempted_rows, 1,
        "the successful first insert rolled back"
    );
    assert_eq!(outcome.receipt.inserted, 1);
    assert!(outcome.receipt.cancellation_observed);
    assert_eq!(outcome.receipt.ready.count, 2);
    assert_eq!(outcome.receipt.decodes, 1);
}

#[test]
fn capacity_native_append_floor_encoding_failure_releases_transaction() {
    let outcome = run(Case::RejectEncoding);
    assert_eq!(
        outcome.error,
        Some((
            io::ErrorKind::InvalidData,
            "config consensus log append exceeds aggregate byte limit".to_owned()
        ))
    );
    assert_eq!(outcome.attempted_rows, 1);
    assert_eq!(outcome.receipt.inserted, 0);
    assert_eq!(outcome.receipt.ready.count, 0);
}

#[test]
fn capacity_native_append_floor_preserves_full_previous_row_validation() {
    for corruption in [
        "epoch",
        "term",
        "index",
        "ciphertext",
        "trailing",
        "membership",
    ] {
        let fixture = Fixture::new();
        let original: Vec<u8> = fixture
            .conn
            .query_row(
                "SELECT entry_json FROM config_raft_log WHERE log_index=0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        match corruption {
            "epoch" => {
                fixture
                    .conn
                    .execute("UPDATE config_raft_log SET configuration_epoch=2", [])
                    .unwrap();
            }
            "term" => {
                fixture
                    .conn
                    .execute("UPDATE config_raft_log SET term=2", [])
                    .unwrap();
            }
            _ => {
                let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
                let encoded = match corruption {
                    "index" => {
                        value["log_id"]["index"] = 99.into();
                        serde_json::to_vec(&value).unwrap()
                    }
                    "ciphertext" => {
                        value["payload"]["Normal"]["intent"]["BoundedAppend"]["commit"]["record"]
                            ["encrypted_blob"][0] = 256.into();
                        serde_json::to_vec(&value).unwrap()
                    }
                    "trailing" => {
                        let mut bytes = original.clone();
                        bytes.extend_from_slice(b" true");
                        bytes
                    }
                    "membership" => serde_json::to_vec(&Entry::<ConfigRaftTypeConfig> {
                        log_id: LogId::new(CommittedLeaderId::new(1, node(1)), 0),
                        payload: EntryPayload::Membership(Membership::new(
                            vec![(1..=10).map(node).collect::<BTreeSet<_>>()],
                            (),
                        )),
                    })
                    .unwrap(),
                    _ => unreachable!(),
                };
                fixture
                    .conn
                    .execute("UPDATE config_raft_log SET entry_json=?1", [&encoded])
                    .unwrap();
            }
        }
        let next = bounded_entry(1, 4096);
        let error = append_logs_sync(
            &fixture.conn,
            identity(),
            &members(),
            std::slice::from_ref(&next),
            MODE,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{corruption}");
        assert!(fixture.conn.is_autocommit());
        assert_eq!(fixture.count(), 1, "{corruption}: no partial append");
        fixture
            .conn
            .execute(
                "UPDATE config_raft_log SET configuration_epoch=1, term=1, entry_json=?1",
                [&original],
            )
            .unwrap();
        append_logs_sync(
            &fixture.conn,
            identity(),
            &members(),
            std::slice::from_ref(&next),
            MODE,
        )
        .unwrap();
        let expected = digest(&next);
        drop(next);
        drop(original);
        fixture.finish(&[expected]);
    }
}

#[test]
fn capacity_native_append_floor_invalid_input_and_cancellation_precede_write_lock() {
    let fixture = Fixture::new();
    let blocker = Connection::open(fixture.directory.path().join("append.sqlite")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut invalid = bounded_entry(1, 4096);
    let EntryPayload::Normal(command) = &mut invalid.payload else {
        unreachable!()
    };
    command.schema_version = 0;
    let rejected = append_logs_sync(
        &fixture.conn,
        identity(),
        &members(),
        std::slice::from_ref(&invalid),
        MODE,
    )
    .unwrap_err()
    .kind();
    let valid = bounded_entry(1, 4096);
    let cancellation = SqliteWorkCancellation::new();
    assert!(cancellation.cancel_before_commit());
    let cancelled = append_logs_cancellable_sync(
        &fixture.conn,
        identity(),
        &members(),
        std::slice::from_ref(&valid),
        &cancellation,
        MODE,
    )
    .unwrap_err()
    .kind();
    let oversized = vec![valid.clone(); CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES + 1];
    let too_many = append_logs_sync(&fixture.conn, identity(), &members(), &oversized, MODE)
        .unwrap_err()
        .kind();
    blocker.execute_batch("ROLLBACK").unwrap();
    blocker.close().unwrap();
    assert_eq!(fixture.count(), 1);
    drop(invalid);
    drop(valid);
    drop(oversized);
    fixture.finish(&[]);
    assert_eq!(rejected, io::ErrorKind::InvalidData);
    assert_eq!(cancelled, io::ErrorKind::TimedOut);
    assert_eq!(too_many, io::ErrorKind::InvalidData);
}
