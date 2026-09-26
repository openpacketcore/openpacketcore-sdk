//! Profile refusal through authenticated transport and original native stores.
//! Captured synthetic requests stay in memory; diagnostics report no values.

use super::*;
use opc_consensus::engine::raft::VoteRequest;
use opc_consensus::engine::{EmptyNode, LogId, SnapshotMeta, StoredMembership, Vote};
use rusqlite::types::ValueRef;
use serde::Serialize;
use std::io::Read;

type Captured = (usize, Vec<u8>);

#[derive(Default)]
pub(super) struct Observation {
    enabled: AtomicBool,
    captured: Mutex<Option<[Option<Captured>; 2]>>,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProfileRequestObservation")
    }
}

impl Observation {
    pub(super) fn capture(&self, request: &ConsensusWireRequest, target: usize) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let slot = match request.family {
            ConsensusRpcFamily::ForwardMutation => 0,
            ConsensusRpcFamily::ReadBarrier => 1,
            _ => return,
        };
        let mut observation = self.captured.lock().expect("bounded profile observation");
        let Some(captured) = observation.as_mut() else {
            return;
        };
        if captured[slot].is_none() {
            assert!(request.payload.len() <= opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
            captured[slot] = Some((target, request.payload.clone()));
        }
    }

    fn enable(&self) {
        *self.captured.lock().expect("enable profile observation") = Some([None, None]);
        self.enabled.store(true, Ordering::SeqCst);
    }

    fn finish(&self) -> [Captured; 2] {
        self.enabled.store(false, Ordering::SeqCst);
        self.captured
            .lock()
            .expect("finish profile observation")
            .take()
            .expect("enabled profile observation")
            .map(|request| request.expect("actual public operation sent this request"))
    }
}

#[derive(Serialize)]
struct Wire<T> {
    revision: u16,
    value: T,
}

// Engine structs are generic over the private configuration type. Their empty
// entry list needs no private command type; field order matches the real DTO.
#[derive(Serialize)]
struct EmptyAppend {
    vote: Vote<ConsensusNodeId>,
    prev_log_id: Option<LogId<ConsensusNodeId>>,
    entries: Vec<()>,
    leader_commit: Option<LogId<ConsensusNodeId>>,
}

#[derive(Serialize)]
struct FirstSnapshotChunk {
    vote: Vote<ConsensusNodeId>,
    meta: SnapshotMeta<ConsensusNodeId, EmptyNode>,
    offset: u64,
    data: Vec<u8>,
    done: bool,
}

fn encode<T: Serialize>(revision: u16, value: T) -> Vec<u8> {
    opc_consensus::encode_bounded(&Wire { revision, value }).expect("bounded fixture DTO")
}

fn engine_payload(
    revision: u16,
    vote: Vote<ConsensusNodeId>,
    family: ConsensusRpcFamily,
) -> Vec<u8> {
    match family {
        ConsensusRpcFamily::Vote => encode(
            revision,
            VoteRequest {
                vote,
                last_log_id: None,
            },
        ),
        ConsensusRpcFamily::AppendEntries => encode(
            revision,
            EmptyAppend {
                vote,
                prev_log_id: None,
                entries: Vec::new(),
                leader_commit: None,
            },
        ),
        ConsensusRpcFamily::InstallSnapshot => encode(
            revision,
            FirstSnapshotChunk {
                vote,
                meta: SnapshotMeta {
                    last_log_id: None,
                    last_membership: StoredMembership::default(),
                    snapshot_id: "synthetic-profile".into(),
                },
                offset: 0,
                data: vec![0xBC; 32],
                done: false,
            },
        ),
        _ => panic!("unsupported engine control"),
    }
}

#[derive(PartialEq, Eq)]
pub(super) struct AuthorityDigest {
    complete: [u8; 32],
    pub(super) tables: BTreeMap<&'static str, ([u8; 32], usize)>,
}

#[derive(Default)]
struct AuthorityHasher {
    complete: Sha256,
    table: Sha256,
}

impl AuthorityHasher {
    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.complete.update(bytes.as_ref());
        self.table.update(bytes.as_ref());
    }
}

pub(super) fn authority_digest(database: &Path) -> AuthorityDigest {
    let mut connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only live authority observation");
    let transaction = connection
        .transaction()
        .expect("consistent authority observation");
    let mut hash = AuthorityHasher::default();
    let mut tables = BTreeMap::new();
    for table in [
        "config_history",
        "audit_trail",
        "config_lifecycle_audit",
        "config_raft_identity",
        "config_raft_vote",
        "config_raft_log",
        "config_raft_purged",
        "config_raft_applied",
        "config_raft_committed",
        "config_raft_machine",
        "config_raft_membership",
        "config_raft_request_outcomes",
        "config_raft_snapshot",
        "config_raft_management_audit",
        "config_raft_history_retention",
        "config_raft_legacy_recovery",
        "config_raft_capacity_records",
        "consensus_retained_binding",
    ] {
        hash.table = Sha256::new();
        let mut row_count = 0;
        hash.update(table.as_bytes());
        let present: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .expect("authority table presence");
        hash.update([u8::from(present)]);
        if !present {
            assert_eq!(table, "config_raft_capacity_records");
            tables.insert(table, (hash.table.clone().finalize().into(), row_count));
            continue;
        }
        let mut statement = transaction
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("authority table observation");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("authority rows");
        while let Some(row) = rows.next().expect("authority row") {
            row_count += 1;
            hash.update([0xFF]);
            for column in 0..columns {
                match row.get_ref(column).expect("authority value") {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(value) => {
                        hash.update([1]);
                        hash.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        hash.update([2]);
                        hash.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) | ValueRef::Blob(value) => {
                        hash.update([
                            if matches!(row.get_ref(column).unwrap(), ValueRef::Text(_)) {
                                3
                            } else {
                                4
                            },
                        ]);
                        hash.update((value.len() as u64).to_be_bytes());
                        hash.update(value);
                    }
                }
            }
        }
        tables.insert(table, (hash.table.clone().finalize().into(), row_count));
    }
    AuthorityDigest {
        complete: hash.complete.finalize().into(),
        tables,
    }
}

type SnapshotFiles = BTreeMap<PathBuf, (bool, u64, [u8; 32])>;

fn snapshot_files(directory: &Path) -> SnapshotFiles {
    let mut pending = vec![directory.to_path_buf()];
    let mut files = BTreeMap::new();
    let mut buffer = [0; 65_536];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).expect("snapshot staging observation") {
            let entry = entry.expect("snapshot entry");
            let kind = entry.file_type().expect("snapshot file type");
            assert!(
                kind.is_file() || kind.is_dir(),
                "native snapshot fixture has no links or special files"
            );
            let relative = entry.path().strip_prefix(directory).unwrap().to_path_buf();
            if kind.is_dir() {
                files.insert(relative, (true, 0, [0; 32]));
                pending.push(entry.path());
            } else {
                let mut file =
                    std::fs::File::open(entry.path()).expect("read snapshot observation");
                let mut hash = Sha256::new();
                let mut length = 0;
                loop {
                    let bytes = file.read(&mut buffer).expect("read snapshot bytes");
                    if bytes == 0 {
                        break;
                    }
                    hash.update(&buffer[..bytes]);
                    length += bytes as u64;
                }
                files.insert(relative, (false, length, hash.finalize().into()));
            }
        }
    }
    files
}

async fn authority_state(
    directory: &Path,
    databases: &[PathBuf; 3],
) -> ([AuthorityDigest; 3], [SnapshotFiles; 3]) {
    let directory = directory.to_path_buf();
    let databases = databases.clone();
    tokio::task::spawn_blocking(move || {
        (
            databases.each_ref().map(|path| authority_digest(path)),
            [0, 1, 2].map(|index| snapshot_files(&directory.join(format!("snapshots-{index}")))),
        )
    })
    .await
    .expect("bounded authority observation task")
}

async fn run(profile: ConfigCapacityProfile) {
    let revision = match profile {
        ConfigCapacityProfile::Legacy => 7,
        ConfigCapacityProfile::BoundedV1 => 8,
        _ => panic!("unsupported fixture profile"),
    };
    let directory = disk_fixture();
    let pki = Pki::new();
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, false, profile,
    )
    .await;
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let leader_id = stores[0].status().leader_id.expect("native profile leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .unwrap();
    let source = (leader + 1) % 3;
    faults[source].profile_rejection.enable();
    let (input, aad, plaintext) = commit(&stores[source], 1, None).await;
    let expected = input.record().clone();
    let operation = stores[source]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xB9; 16]),
            input,
            CALLER,
        )
        .expect("exact forwarded profile control");
    stores[source]
        .append_prepared_commit(operation)
        .await
        .expect("real forwarded control");
    for store in &stores {
        let record = store
            .load_latest()
            .await
            .expect("native control read")
            .expect("native head");
        assert!(record.record == expected);
        assert_decrypted(&record.record, &aad, &plaintext);
    }
    let sender = stores[source].status().node_id;
    let vote = Vote::new_committed(stores[leader].status().term + 1, sender);
    let [(forward_target, forward), (read_target, read)] =
        faults[source].profile_rejection.finish();
    let cases = [
        (leader, ConsensusRpcFamily::Vote, None),
        (leader, ConsensusRpcFamily::AppendEntries, None),
        (leader, ConsensusRpcFamily::InstallSnapshot, None),
        (
            forward_target,
            ConsensusRpcFamily::ForwardMutation,
            Some(forward),
        ),
        (read_target, ConsensusRpcFamily::ReadBarrier, Some(read)),
    ];
    for (target, family, captured) in cases {
        let control = captured
            .clone()
            .unwrap_or_else(|| engine_payload(revision, Vote::new(0, sender), family));
        let payload = captured.unwrap_or_else(|| engine_payload(revision, vote, family));
        assert_eq!(
            payload.first().copied(),
            Some(revision as u8),
            "actual profile discriminator"
        );
        let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
            manifest
                .bind_local(replica_id(source))
                .expect("original sender")
                .bind_remote(replica_id(target))
                .expect("original receiver"),
            resolver(addresses[target].clone()),
            pki.client(source),
        );
        // A matching-profile request must reach the real handler successfully.
        // Engine controls use a stale vote so they exercise parsing without a
        // new election or snapshot stream. Forwarding repeats the exact already
        // committed operation; the captured read remains read-only.
        let accepted = peer
            .call_with_timeout(
                ConsensusWireRequest::try_new(
                    manifest.consensus_identity(),
                    sender,
                    family,
                    control,
                )
                .expect("matching-profile outer request"),
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            )
            .await
            .expect("matching-profile authenticated response");
        let accepted = accepted
            .result
            .expect("matching profile reaches the actual handler");
        assert_eq!(
            accepted.first().copied(),
            Some(revision as u8),
            "matching-profile response"
        );
        if family == ConsensusRpcFamily::ReadBarrier {
            assert!(
                matches!(accepted.get(1), Some(0 | 1)),
                "matching-profile read is compatible or ready"
            );
        } else {
            assert_eq!(
                accepted.get(1),
                Some(&0),
                "matching-profile engine result is Ok or exact forward is Applied"
            );
        }
        if family == ConsensusRpcFamily::ForwardMutation {
            // The matching exact replay is a real Raft proposal even though
            // its configuration effect is deduplicated. Establish each native
            // member's applied frontier before measuring rejected requests;
            // otherwise their baseline can contain legitimate pending apply.
            let records = tokio::time::timeout(
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                futures_util::future::join_all(stores.iter().map(|store| store.load_latest())),
            )
            .await
            .expect("matching replay read barriers keep the original operation budget");
            for (store, record) in stores.iter().zip(records) {
                let record = record
                    .expect("matching replay quorum-current read")
                    .expect("matching replay preserves the native head");
                assert!(
                    record.record == expected,
                    "matching replay preserves the exact record"
                );
                assert_decrypted(&record.record, &aad, &plaintext);
                let status = store.status();
                assert_eq!(
                    status.applied_index, status.committed_index,
                    "matching replay is applied before the rejection baseline"
                );
            }
            eprintln!("CONFIG_CAPACITY_MTLS_PROFILE_CONTROL_APPLIED revision={revision} members=3 exact_record=true");
        }
        eprintln!("CONFIG_CAPACITY_MTLS_PROFILE_CONTROL revision={revision} family={family:?} matching=true");
        // Opposite supported profile plus two unassigned discriminators.
        for other in [if revision == 7 { 8 } else { 7 }, 0, 255] {
            let mut wrong = payload.clone();
            if other == 255 {
                // Postcard's canonical u16 encoding is a two-byte varint.
                drop(wrong.splice(0..1, [0xFF, 0x01]));
            } else {
                wrong[0] = other;
            }
            let status_before = stores
                .iter()
                .map(|store| store.status())
                .collect::<Vec<_>>();
            eprintln!("CONFIG_CAPACITY_MTLS_PROFILE_ATTEMPT revision={revision} family={family:?} other={other}");
            let before = authority_state(&directory, &databases).await;
            let response = peer
                .call_with_timeout(
                    ConsensusWireRequest::try_new(
                        manifest.consensus_identity(),
                        sender,
                        family,
                        wrong,
                    )
                    .expect("valid outer identity and bounded frame"),
                    DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
                .expect("actual authenticated service response");
            assert!(matches!(response.result, Err(ConsensusPeerError::Protocol)),
                "CONFIG_CAPACITY_MTLS_PROFILE_RED: exact profile rejection precedes engine or proposal handoff");
            let after = authority_state(&directory, &databases).await;
            for member in 0..3 {
                if before.0[member] != after.0[member] {
                    let status = stores[member].status();
                    eprintln!(
                        "CONFIG_CAPACITY_MTLS_PROFILE_CHANGE revision={revision} family={family:?} other={other} member={member} target={} term_changed={} applied_changed={} committed_changed={} applied_matches_committed={}",
                        target == member,
                        status.term != status_before[member].term,
                        status.applied_index != status_before[member].applied_index,
                        status.committed_index != status_before[member].committed_index,
                        status.applied_index == status.committed_index,
                    );
                    for (table, (digest, rows)) in &before.0[member].tables {
                        let (next_digest, next_rows) = after.0[member]
                            .tables
                            .get(table)
                            .expect("same authority table set");
                        if digest != next_digest || rows != next_rows {
                            eprintln!("CONFIG_CAPACITY_MTLS_PROFILE_TABLE member={member} table={table} rows_before={rows} rows_after={next_rows}");
                        }
                    }
                }
            }
            assert!(
                after.0 == before.0,
                "complete native authority unchanged by profile rejection"
            );
            assert!(
                after.1 == before.1,
                "rejected profile cannot change snapshot staging or contents"
            );
        }
    }
    for store in &stores {
        let record = store
            .load_latest()
            .await
            .expect("unchanged native control")
            .expect("retained head");
        assert!(record.record == expected);
    }
    snapshot::stop(stores, servers, released, &addresses).await;
    println!("CONFIG_CAPACITY_MTLS_PROFILE revision={revision} families=5 matching_controls=5 rejected=15 native_authority_unchanged=true snapshot_staging_unchanged=true authenticated=true");
}

native_case!(
    config_capacity_957_native_mtls_bounded_receiver_rejects_other_profiles,
    {
        run(ConfigCapacityProfile::BoundedV1).await;
    }
);

native_case!(
    config_capacity_957_native_mtls_legacy_receiver_rejects_other_profiles,
    {
        run(ConfigCapacityProfile::Legacy).await;
    }
);

#[path = "snapshot_boundaries.rs"]
mod snapshot_boundaries;
