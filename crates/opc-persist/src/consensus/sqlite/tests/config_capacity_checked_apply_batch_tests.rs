//! Checked native sizing does not authorize identity, effects or late work.
//! The large synthetic principal exercises storage byte boundaries only; it
//! is deliberately not an admitted configuration or a memory-envelope claim.

use super::*;
use crate::consensus::store::config_capacity_cost_observation as observation;

fn blank(index: u64) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Blank,
    }
}

fn bytes_entry(index: u64, encoded_bytes: usize) -> Entry<ConfigRaftTypeConfig> {
    let key = AuditKey::new([0x49; 32]).expect("synthetic key");
    let mut entry = legacy_append_entry(
        index,
        [u8::try_from(index).expect("small synthetic index"); 16],
        TxId::new(),
        None,
        index + 1,
        None,
        &key,
    );
    let original = json_length_bounded_cancellable(
        &entry,
        CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES,
        "synthetic original",
        &SqliteWorkCancellation::new(),
    )
    .expect("original typed JSON length");
    let EntryPayload::Normal(command) = &mut entry.payload else {
        panic!("normal fixture entry")
    };
    let ConfigMutationIntent::AppendCommit(commit) = &mut command.intent else {
        panic!("legacy append fixture")
    };
    assert!(
        encoded_bytes >= original,
        "synthetic target extends the real entry"
    );
    let principal_bytes = commit.record.principal.len() + encoded_bytes - original;
    commit.record.principal = "x".repeat(principal_bytes);
    assert_eq!(
        json_length_bounded_cancellable(
            &entry,
            encoded_bytes,
            "synthetic exact entry",
            &SqliteWorkCancellation::new(),
        )
        .expect("actual typed JSON reaches requested storage boundary"),
        encoded_bytes
    );
    entry
}

fn entry_witness(entry: &Entry<ConfigRaftTypeConfig>) -> (u64, usize, usize, usize, [u8; 32]) {
    struct HashWriter(Sha256);
    impl io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let EntryPayload::Normal(command) = &entry.payload else {
        panic!("normal fixture entry")
    };
    let ConfigMutationIntent::AppendCommit(commit) = &command.intent else {
        panic!("append fixture entry")
    };
    let mut writer = HashWriter(Sha256::new());
    crate::consensus::config_capacity_json::to_writer(&mut writer, entry)
        .expect("hash actual unchanged serialization without an output buffer");
    (
        entry.log_id.index,
        commit.as_ref() as *const PreparedConfigCommit as usize,
        commit.record.principal.as_ptr() as usize,
        commit.record.encrypted_blob.as_ptr() as usize,
        writer.0.finalize().into(),
    )
}

#[test]
fn checked_apply_batch_preserves_exact_transaction_prefix_and_suffix() {
    let limit = CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES;
    assert_eq!(CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES, 4 * limit);
    let lengths = [limit, limit, limit, limit - 4_095, 4_096];
    assert_eq!(lengths.iter().sum::<usize>(), 4 * limit + 1);
    let entries: Vec<_> = lengths
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| bytes_entry(u64::try_from(index).unwrap(), bytes))
        .collect();
    let before: Vec<_> = entries.iter().map(entry_witness).collect();
    let cancellation = SqliteWorkCancellation::new();
    let (batch, remainder) = ApplyBatch::select(entries, &cancellation)
        .expect("split the typed batch one byte over the transaction limit");
    assert!(!batch.needs_sizing());
    assert_eq!(batch.entries().len(), 4);
    assert_eq!(batch.last_log_index(), Some(3));
    assert_eq!(remainder.len(), 1);
    let after: Vec<_> = batch
        .entries()
        .iter()
        .chain(&remainder)
        .map(entry_witness)
        .collect();
    assert_eq!(
        after, before,
        "CHECKED_APPLY_EXACT_PREFIX: all original owners, order and serialized bytes survive partition"
    );
    let (suffix, rest) = ApplyBatch::select(remainder, &cancellation).expect("exact suffix");
    assert!(!suffix.needs_sizing());
    assert_eq!(suffix.last_log_index(), Some(4));
    assert_eq!(suffix.entries().len(), 1);
    assert!(rest.is_empty());
    assert_eq!(entry_witness(&suffix.entries()[0]), before[4]);

    // Consuming the proof and passing its raw vector loses checked authority.
    let unchecked = ApplyBatch::from(batch.into_entries());
    assert!(unchecked.needs_sizing());
    assert_eq!(unchecked.entries().len(), 4);
    drop(unchecked);
    drop(suffix);
    let exact: Vec<_> = (0..4).map(|index| bytes_entry(index, limit)).collect();
    let (exact, rest) = ApplyBatch::select(exact, &cancellation)
        .expect("the original aggregate byte ceiling stays accepted by sizing");
    assert_eq!(exact.entries().len(), 4);
    assert!(rest.is_empty());
}

#[test]
fn checked_apply_batch_retains_entry_collection_and_empty_boundaries() {
    let cancellation = SqliteWorkCancellation::new();
    let Err(error) = ApplyBatch::select(
        vec![bytes_entry(0, CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES + 1)],
        &cancellation,
    ) else {
        panic!("oversized typed entry rejected before proof creation");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "config consensus apply entry exceeds storage limit"
    );
    let entries: Vec<_> = (0..1_024).map(blank).collect();
    let (batch, rest) = ApplyBatch::select(entries, &cancellation).expect("exact count bound");
    assert_eq!(batch.entries().len(), 1_024);
    assert_eq!(batch.last_log_index(), Some(1_023));
    assert!(rest.is_empty());
    assert!(ApplyBatch::select((0..1_025).map(blank).collect(), &cancellation).is_err());
    let (empty, rest) = ApplyBatch::select(Vec::new(), &cancellation).expect("empty prefix");
    assert!(empty.entries().is_empty());
    assert_eq!(empty.last_log_index(), None);
    assert!(rest.is_empty());
}

fn assert_no_apply_effect(conn: &Connection) {
    assert_eq!(
        read_applied_sync(conn, identity()).expect("applied frontier"),
        None
    );
    assert_eq!(
        read_machine_sync(conn, identity())
            .expect("machine state")
            .0,
        0
    );
    for table in ["config_history", "config_raft_request_outcomes"] {
        let count: u64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("unchanged authoritative rows");
        assert_eq!(count, 0, "CHECKED_APPLY_NO_EFFECT: {table}");
    }
}

fn assert_valid_checked_apply(conn: &Connection, key: &AuditKey) {
    let (batch, remainder) = ApplyBatch::select(
        vec![
            membership_entry(),
            mark_confirmed_entry(1, [0x59; 16], TxId::new()),
        ],
        &SqliteWorkCancellation::new(),
    )
    .expect("size genuine valid Legacy control");
    assert!(remainder.is_empty());
    let responses = apply_entries_cancellable_sync(
        conn,
        identity(),
        &expected_members(),
        batch,
        &SqliteWorkCancellation::new(),
        key,
        None,
        ConfigCapacityProfile::Legacy,
    )
    .expect("same native database accepts a valid checked command");
    assert_eq!(responses.len(), 2);
    assert_eq!(
        read_applied_sync(conn, identity()).unwrap(),
        Some(log_id(1))
    );
    assert_eq!(read_machine_sync(conn, identity()).unwrap().0, 1);
}

#[tokio::test]
async fn checked_apply_batch_retains_identity_profile_command_and_membership_checks() {
    let backend = initialized_backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    for case in ["identity", "profile", "command", "membership"] {
        let mut entry = mark_confirmed_entry(1, [0x57; 16], TxId::new());
        match case {
            "identity" => {
                let EntryPayload::Normal(command) = &mut entry.payload else {
                    panic!("normal command")
                };
                command.identity = ConsensusIdentity::new(
                    ConfigConsensusClusterId::new("other-checked-batch-scope").unwrap(),
                    ConfigConsensusConfigurationId::from_bytes([0x72; 32]),
                    ConfigConsensusConfigurationEpoch::new(1).unwrap(),
                );
            }
            "profile" => {
                let EntryPayload::Normal(command) = &mut entry.payload else {
                    panic!("normal command")
                };
                command.schema_version = 8;
                command
                    .validate(identity())
                    .expect("valid revision-eight command");
            }
            "command" => {
                let EntryPayload::Normal(command) = &mut entry.payload else {
                    panic!("normal command")
                };
                command.schema_version = u16::MAX;
            }
            "membership" => {
                let other = BTreeSet::from([ConsensusNodeId::new(8).unwrap()]);
                entry.payload =
                    EntryPayload::Membership(Membership::new(vec![other.clone()], other));
            }
            _ => unreachable!(),
        }
        let (batch, remainder) =
            ApplyBatch::select(vec![blank(0), entry], &SqliteWorkCancellation::new())
                .expect("valid JSON sizing must not grant effect authority");
        assert!(remainder.is_empty());
        let error = apply_entries_cancellable_sync(
            &conn,
            identity(),
            &expected_members(),
            batch,
            &SqliteWorkCancellation::new(),
            backend.audit_key(),
            None,
            ConfigCapacityProfile::Legacy,
        )
        .expect_err("checked size cannot bypass native validation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{case}");
        assert_no_apply_effect(&conn);
    }
    assert_valid_checked_apply(&conn, backend.audit_key());
}

#[tokio::test]
async fn checked_apply_batch_retains_current_cancellation_before_effects() {
    let backend = initialized_backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    for empty in [false, true] {
        for expired in [false, true] {
            let entries = if empty { Vec::new() } else { vec![blank(0)] };
            let (batch, remainder) = ApplyBatch::select(entries, &SqliteWorkCancellation::new())
                .expect("completed sizing before cancellation");
            assert!(remainder.is_empty());
            let cancellation = if expired {
                SqliteWorkCancellation::with_deadline(std::time::Instant::now())
            } else {
                let cancellation = SqliteWorkCancellation::new();
                assert!(cancellation.cancel_before_commit());
                cancellation
            };
            let error = apply_entries_cancellable_sync(
                &conn,
                identity(),
                &expected_members(),
                batch,
                &cancellation,
                backend.audit_key(),
                None,
                ConfigCapacityProfile::Legacy,
            )
            .expect_err("completed sizing cannot refresh an expired or cancelled operation");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_no_apply_effect(&conn);
        }
    }
    assert!(ApplyBatch::select(
        vec![blank(0)],
        &SqliteWorkCancellation::with_deadline(std::time::Instant::now()),
    )
    .is_err());
    assert_valid_checked_apply(&conn, backend.audit_key());
}

#[tokio::test]
async fn unchecked_direct_apply_still_completes_full_size_validation() {
    let backend = initialized_backend().await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let mut entry = mark_confirmed_entry(1, [0x58; 16], TxId::new());
    let request_id = ConfigConsensusRequestId::new();
    let EntryPayload::Normal(command) = &mut entry.payload else {
        panic!("normal command")
    };
    command.request_id = request_id;
    let expected_bytes = json_length_bounded_cancellable(
        &entry,
        CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES,
        "synthetic direct entry",
        &SqliteWorkCancellation::new(),
    )
    .expect("exact direct entry length before observation");
    let observation = observation::Observation::new(request_id);
    let responses = apply_entries_cancellable_sync(
        &conn,
        identity(),
        &expected_members(),
        vec![membership_entry(), entry],
        &SqliteWorkCancellation::new(),
        backend.audit_key(),
        None,
        ConfigCapacityProfile::Legacy,
    )
    .expect("actual direct Legacy apply");
    assert_eq!(responses.len(), 2);
    assert_eq!(
        read_applied_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
    assert_eq!(read_machine_sync(&conn, identity()).unwrap().0, 1);
    let counts = observation.snapshot();
    assert_eq!(counts.batch_sizing_counts, 0);
    assert_eq!(counts.apply_scopes, 1);
    assert_eq!(counts.apply_counts, 1, "UNCHECKED_APPLY_FULL_SIZE_PASS");
    assert_eq!(counts.apply_encoded_bytes, expected_bytes);
    assert_eq!(counts.apply_output_allocations, 0);
}
