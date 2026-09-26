//! Finite native history admission, pruning and original-result preservation.

use super::*;
use opc_persist::{ConfigHistoryLimits, ConfigHistoryRetention};
use std::os::unix::fs::MetadataExt;

const HISTORY_BYTES: u64 = 16 * 1024 * 1024;
// Independently charge fixed record metadata, complete ciphertext and proof,
// plus 21 audit rows with two redacted 12-byte JSON strings each.
const JOINT_RECORD_BYTES: u64 =
    256 + 16_384 + 20 + 1_704_492 + 32 + 32 + 60 + 21 * (128 + 8_192 + 12 + 12);

struct Expected {
    record: CommitRecord,
    aad: EnvelopeAad,
    handle: ConfigCommitRecoveryHandle,
}

fn business_state(database: &Path) -> [u8; 32] {
    let mut connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only business-state observation");
    let transaction = connection.transaction().expect("consistent observation");
    let mut digest = Sha256::new();
    for query in [
        "SELECT * FROM config_history ORDER BY version",
        "SELECT * FROM audit_trail ORDER BY tx_id, sequence",
        "SELECT * FROM config_raft_capacity_records ORDER BY tx_id",
        "SELECT * FROM config_raft_history_retention",
        "SELECT * FROM config_lifecycle_audit ORDER BY rowid",
        "SELECT * FROM rollback_labels ORDER BY label",
    ] {
        digest.update(query.as_bytes());
        let mut statement = transaction.prepare(query).expect("business table");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("business rows");
        while let Some(row) = rows.next().expect("business row") {
            digest.update([0xFF]);
            for index in 0..columns {
                use rusqlite::types::ValueRef;
                match row.get_ref(index).expect("borrowed business column") {
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
                        digest.update([3]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value);
                    }
                }
            }
        }
    }
    digest.finalize().into()
}

fn report_storage(directory: &Path, stage: &str, joint: bool) {
    let mut directories = vec![directory.to_owned()];
    let (mut files, mut logical, mut allocated) = (0_u64, 0_u64, 0_u64);
    while let Some(path) = directories.pop() {
        for entry in std::fs::read_dir(path).expect("owned fixture directory") {
            let entry = entry.expect("owned fixture entry");
            let metadata = entry.path().symlink_metadata().expect("fixture metadata");
            assert!(!metadata.is_symlink(), "fixture storage has no symlink");
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if metadata.is_file() {
                files += 1;
                logical += metadata.len();
                allocated += metadata.blocks() * 512;
            }
        }
    }
    println!("CONFIG_CAPACITY_HISTORY_STORAGE joint={joint} stage={stage} files={files} logical_bytes={logical} allocated_bytes={allocated} sampled_only=true");
}

// Record only after the original readiness future returns or unwinds. The
// guard adds no await, retry, sleep, operation, deadline or assertion change.
pub(super) struct ReopenReadinessObservation<'a> {
    pub(super) started: tokio::time::Instant,
    pub(super) faults: &'a [Arc<Fault>; 3],
    pub(super) stores: &'a [ConsensusConfigStore],
}

impl Drop for ReopenReadinessObservation<'_> {
    fn drop(&mut self) {
        let statuses = self
            .stores
            .iter()
            .map(ConsensusConfigStore::status)
            .collect::<Vec<_>>();
        eprintln!(
            "CONFIG_CAPACITY_HISTORY_READINESS elapsed_ms={} unwinding={}",
            self.started.elapsed().as_millis(),
            std::thread::panicking()
        );
        for (member, status) in statuses.iter().enumerate() {
            eprintln!("CONFIG_CAPACITY_HISTORY_MEMBER member={member} term={} leader_known={} leader_matches_first={} local_leader={} admitted={} applied={:?} committed={:?}", status.term, status.leader_id.is_some(), status.leader_id == statuses[0].leader_id, status.leader_id == Some(status.node_id), status.admitted, status.applied_index, status.committed_index);
        }
        election::report(self.faults);
        for (source, fault) in self.faults.iter().enumerate() {
            for (target, observations) in fault.rpc_observations.iter().enumerate() {
                for (family, observation) in
                    ["vote", "append", "read"].into_iter().zip(observations)
                {
                    eprintln!("CONFIG_CAPACITY_HISTORY_RPC source={source} family={family} target={target} started={} completed={} transport_errors={} service_errors={} cumulative=true", observation.started.load(Ordering::SeqCst), observation.completed.load(Ordering::SeqCst), observation.transport_errors.load(Ordering::SeqCst), observation.service_errors.load(Ordering::SeqCst));
                }
            }
        }
    }
}

async fn applied(stores: &[ConsensusConfigStore]) {
    for store in stores {
        store
            .probe_durable_readiness()
            .await
            .expect("original operation-bound history barrier");
    }
}

fn decision(head: &CommitRecord, from: u64, bytes: u64) -> ConfigHistoryRetention {
    ConfigHistoryRetention::new(
        head.tx_id,
        head.version,
        ConfigVersion::new(from.max(2) - 1),
        ConfigVersion::new(from),
        ConfigHistoryLimits::new(8, bytes).expect("finite eight-record history"),
    )
    .expect("explicit exact-head prefix acknowledgement")
}

fn ordinary_record_charge(record: &CommitRecord) -> u64 {
    // This fixture has no change-audit/lifecycle/label rows. The bound includes
    // its complete independently held record and the 60-byte capacity binding.
    (256 + record.principal.len()
        + record.committed_at.to_string().len()
        + record.encrypted_blob.len()
        + record.plaintext_digest.len()
        + record.schema_digest.as_bytes().len()
        + 60) as u64
}

async fn assert_records(
    stores: &[ConsensusConfigStore],
    expected: &[Expected],
    first: u64,
    joint: bool,
    principal: &str,
) {
    let plaintext = if joint {
        plaintext(0)
    } else {
        serde_json::to_vec(&"x".repeat(BOUNDED_LOGICAL_BYTES - 2))
            .expect("independent complete ordinary plaintext")
    };
    for store in stores {
        let records = store
            .load_since(ConfigVersion::new(first - 1), 64)
            .await
            .expect("exact retained cursor");
        let retained = &expected[first as usize - 1..];
        assert_eq!(records.len(), retained.len(), "no retained record omitted");
        for (value, expected) in records.iter().zip(retained) {
            assert!(value.record == expected.record, "complete retained record");
            if joint {
                assert_readback(value, &expected.record, &expected.aad, &plaintext);
            } else {
                assert_decrypted(&value.record, &expected.aad, &plaintext);
                assert!(value.audit.is_empty());
            }
        }
        for original in expected {
            assert!(matches!(
                store
                    .lookup_commit_operation(&original.handle, principal)
                    .await
                    .expect("original committed result survives retention"),
                ConfigCommitRecoveryOutcome::Committed
            ));
        }
    }
}

async fn assert_rejected(
    stores: &[ConsensusConfigStore],
    handle: &ConfigCommitRecoveryHandle,
    principal: &str,
) {
    for store in stores {
        let outcome = store
            .lookup_commit_operation(handle, principal)
            .await
            .expect("exact original rejected operation lookup");
        assert!(matches!(
            outcome,
            ConfigCommitRecoveryOutcome::Rejected(error)
                if matches!(error.kind(), PersistErrorKind::ConfigHistoryFull)
        ));
    }
}

native_case!(
    config_capacity_957_native_history_record_limit_prune_and_reopen,
    {
        run(false).await;
    }
);

native_case!(
    config_capacity_957_native_history_joint_byte_limit_and_reopen,
    {
        run(true).await;
    }
);

async fn run(joint: bool) {
    let directory = disk_fixture();
    let pki = Pki::new();
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let profile = ConfigCapacityProfile::BoundedV1;
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, false, profile,
    )
    .await;
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let leader_id = stores[0].status().leader_id.expect("history leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .expect("history leader belongs to fixture");
    let follower = (leader + 1) % 3;
    let principal = if joint {
        principal(false)
    } else {
        CALLER.into()
    };
    let count = if joint { 2 } else { 8 };
    let limit_bytes = if joint {
        2 * JOINT_RECORD_BYTES
    } else {
        HISTORY_BYTES
    };
    let mut expected = Vec::<Expected>::new();
    for version in 1..=count {
        let source = if version % 2 == 1 { leader } else { follower };
        let parent = expected.last().map(|value| value.record.tx_id);
        let (input, aad, plaintext) = if joint {
            input(&stores[source], version, parent, &principal, 0).await
        } else {
            commit(&stores[source], version, parent).await
        };
        let record = input.record().clone();
        let operation = stores[source]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0x80 + version as u8; 16]),
                input,
                &principal,
            )
            .expect("at-limit history operation preparation");
        let handle = ConfigCommitRecoveryHandle::from_bytes(operation.recovery_handle().as_bytes())
            .expect("original serialized history operation handle");
        if source == leader {
            stores[source].append_prepared_commit_local(operation).await
        } else {
            stores[source].append_prepared_commit(operation).await
        }
        .expect("at-limit history durable acknowledgement");
        expected.push(Expected {
            record,
            aad,
            handle,
        });
        drop(plaintext);
        applied(&stores).await;
        if version == 2 {
            let head = &expected.last().expect("second exact head").record;
            if joint {
                assert_eq!(JOINT_RECORD_BYTES, 1_896_500);
                let before = databases.each_ref().map(|path| business_state(path));
                let error = stores[leader]
                    .retain_history_idempotent(
                        ConfigConsensusRequestId::from_bytes([0x91; 16]),
                        decision(head, 1, limit_bytes - 1),
                    )
                    .await
                    .expect_err("one canonical byte beyond the proposed budget rejects");
                assert!(matches!(error.kind(), PersistErrorKind::ConfigHistoryFull));
                applied(&stores).await;
                assert_eq!(
                    databases.each_ref().map(|path| business_state(path)),
                    before
                );
            }
            stores[leader]
                .retain_history_idempotent(
                    ConfigConsensusRequestId::from_bytes([0x92; 16]),
                    decision(head, 1, limit_bytes),
                )
                .await
                .expect("exact canonical budget and explicit record limit admit");
            applied(&stores).await;
        }
        report_storage(&directory, "append", joint);
    }
    assert_records(&stores, &expected, 1, joint, &principal).await;

    let next = count + 1;
    let parent = expected.last().map(|value| value.record.tx_id);
    let (input, _, _) = if joint {
        input(&stores[follower], next, parent, &principal, 0).await
    } else {
        commit(&stores[follower], next, parent).await
    };
    if joint {
        assert!(next < 8, "byte rejection is independent of record count");
    } else {
        let proposed_bytes = expected
            .iter()
            .map(|v| ordinary_record_charge(&v.record))
            .sum::<u64>()
            + ordinary_record_charge(input.record());
        assert!(
            proposed_bytes < HISTORY_BYTES,
            "ninth rejection isolates record count"
        );
    }
    let operation = stores[follower]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0x93; 16]),
            input,
            &principal,
        )
        .expect("finite-history rejection occurs in the atomic state-machine transaction");
    let rejected = ConfigCommitRecoveryHandle::from_bytes(operation.recovery_handle().as_bytes())
        .expect("original rejected-operation handle before send");
    let before = databases.each_ref().map(|path| business_state(path));
    let error = stores[follower]
        .append_prepared_commit(operation)
        .await
        .expect_err("one more complete configuration exceeds history capacity");
    assert!(matches!(error.kind(), PersistErrorKind::ConfigHistoryFull));
    applied(&stores).await;
    assert_eq!(
        databases.each_ref().map(|path| business_state(path)),
        before,
        "all six business tables roll back together; Raft outcomes are separate"
    );
    assert_records(&stores, &expected, 1, joint, &principal).await;
    assert_rejected(&stores, &rejected, &principal).await;

    let first = if joint { 1 } else { 7 };
    if !joint {
        stores[leader]
            .retain_history_idempotent(
                ConfigConsensusRequestId::from_bytes([0x94; 16]),
                decision(
                    &expected.last().expect("eighth head").record,
                    first,
                    limit_bytes,
                ),
            )
            .await
            .expect("explicitly acknowledged prefix pruning");
        applied(&stores).await;
    }
    for store in &stores {
        assert_eq!(
            store
                .retained_history_floor()
                .await
                .expect("authenticated history floor"),
            Some(ConfigVersion::new(first - 1))
        );
        if first > 1 {
            let error = store
                .load_since(ConfigVersion::new(first - 2), 64)
                .await
                .expect_err("compacted cursor cannot skip undelivered records");
            assert!(matches!(
                error.kind(),
                PersistErrorKind::ConfigHistoryCompacted
            ));
        }
    }
    assert_records(&stores, &expected, first, joint, &principal).await;
    report_storage(&directory, "bounded", joint);
    let retained = databases.each_ref().map(|path| business_state(path));
    snapshot::stop(stores, servers, released, &addresses).await;
    let trace = reopen_trace::begin();
    election::begin(&faults);
    let reopen_started = tokio::time::Instant::now();
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, true, profile,
    )
    .await;
    assert_eq!(
        databases.each_ref().map(|path| business_state(path)),
        retained,
        "original authenticated history and exact capacity survive before catch-up"
    );
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    eprintln!(
        "CONFIG_CAPACITY_HISTORY_REOPEN_READY_BEGIN elapsed_ms={}",
        reopen_started.elapsed().as_millis()
    );
    let observation = ReopenReadinessObservation {
        started: tokio::time::Instant::now(),
        faults: &faults,
        stores: &stores,
    };
    snapshot::ready(&stores).await;
    drop(observation);
    drop(trace);
    let effects = databases.each_ref().map(|path| effect_counts(path));
    let forwards = faults
        .iter()
        .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
        .sum::<usize>();
    assert_records(&stores, &expected, first, joint, &principal).await;
    assert_rejected(&stores, &rejected, &principal).await;
    assert_eq!(
        databases.each_ref().map(|path| business_state(path)),
        retained
    );
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        effects
    );
    assert_eq!(
        faults
            .iter()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
            .sum::<usize>(),
        forwards
    );
    report_storage(&directory, "reopen", joint);
    snapshot::stop(stores, servers, released, &addresses).await;
    println!("CONFIG_CAPACITY_HISTORY joint={joint} record_limit=8 canonical_limit={limit_bytes} at_limit=true one_over_rejected=true business_atomic=true original_paths=true original_handles=true resubmitted=false");
}
