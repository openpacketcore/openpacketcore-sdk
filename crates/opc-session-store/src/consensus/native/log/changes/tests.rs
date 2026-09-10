use super::*;
use crate::consensus::{
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};

fn identity() -> SessionConsensusIdentity {
    SessionConsensusIdentity::new(
        SessionConsensusClusterId::new("native-log-changes").unwrap(),
        SessionConsensusConfigurationId::from_bytes([0xAD; 32]),
        SessionConsensusConfigurationEpoch::new(1).unwrap(),
    )
}
fn members() -> BTreeSet<SessionConsensusNodeId> {
    [7, 8, 9]
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .into()
}
fn id(term: u64, index: u64) -> LogId<SessionConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(term, SessionConsensusNodeId::new(7).unwrap()),
        index,
    )
}
fn blank(term: u64, index: u64) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: id(term, index),
        payload: EntryPayload::Blank,
    }
}
fn append(entries: &[Entry<SessionRaftTypeConfig>]) -> Operation {
    Operation::Append(
        entries
            .iter()
            .map(|entry| serde_json::to_vec(entry).unwrap().into())
            .collect(),
    )
}
fn project(storage: &mut NativeStorage, operation: &Operation) {
    storage
        .log
        .project(operation, &storage.business, None)
        .unwrap();
}

fn fixture() -> NativeStorage {
    let mut storage = NativeStorage::empty(identity(), members()).unwrap();
    let formation = Entry {
        log_id: id(1, 0),
        payload: EntryPayload::Membership(Membership::new(vec![members()], members())),
    };
    project(
        &mut storage,
        &append(&[formation.clone(), blank(1, 1), blank(1, 2)]),
    );
    project(&mut storage, &Operation::Committed(Some(id(1, 0))));
    storage.business.apply(&[formation]).unwrap();
    storage.validate_image().unwrap();
    storage
}

fn values(log: &NativeLog) -> Vec<u8> {
    let rows = log
        .entries
        .iter()
        .map(|(index, row)| (*index, row.resident().unwrap().encoded.to_vec()))
        .collect::<Vec<_>>();
    serde_json::to_vec(&(log.vote, log.committed, log.purged, rows)).unwrap()
}

fn cold(storage: &NativeStorage) -> NativeStorage {
    let mut image = Vec::new();
    storage.write_image(&mut image, [0xAD; 32], 19).unwrap();
    let decoded =
        NativeStorage::read_image(&mut image.as_slice(), [0xAD; 32], 19, identity()).unwrap();
    assert_eq!(values(&decoded.log), values(&storage.log));
    for (index, row) in &storage.log.entries {
        assert!(
            decoded.log.entries[index].resident().unwrap().entry == row.resident().unwrap().entry
        );
        assert!(!decoded.log.entries[index].ptr_eq(row));
    }
    decoded
}

fn reconstruct(
    base: &NativeStorage,
    current: &NativeStorage,
    changes: &LogChanges,
) -> NativeStorage {
    let mut decoded = NativeStorage {
        business: current.business.clone(),
        log: base.log.clone(),
    };
    decoded.log.proof = None;
    for (index, change) in &changes.rows {
        match &change.after {
            Some(row) => {
                let encoded: Bytes = row.resident().unwrap().encoded.to_vec().into();
                let entry = sql::decode_consensus_log_entry(&encoded).unwrap();
                decoded
                    .log
                    .entries
                    .insert(*index, SharedRow::new(NativeLogEntry::new(encoded, entry)));
            }
            None => {
                decoded.log.entries.remove(index);
            }
        }
    }
    decoded.log.vote = changes.target.frontiers.vote;
    decoded.log.committed = changes.target.frontiers.committed;
    decoded.log.purged = changes.target.frontiers.purged;
    decoded.log.admit(&decoded.business).unwrap();
    decoded.validate_image().unwrap();
    assert_eq!(values(&decoded.log), values(&current.log));
    assert_eq!(
        decoded.log.proof.as_ref().unwrap().summary.content,
        changes.target.summary.content
    );
    decoded
}

#[test]
fn native_log_changes_retry_truncate_replacement_and_commit_have_complete_cold_parity() {
    let mut storage = fixture();
    let base = storage.clone();
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &append(&[blank(1, 1)]));
    project(&mut storage, &Operation::Truncate(id(1, 2)));
    project(&mut storage, &append(&[blank(2, 2), blank(2, 3)]));
    project(&mut storage, &Operation::Committed(Some(id(2, 3))));
    let entries = storage.log.read(1, Some(4), None).unwrap();
    storage
        .log
        .require_committed_entries(&storage.business, Some(id(2, 3)), &entries)
        .unwrap();
    storage.business.apply(&entries).unwrap();
    let changes = storage.log.capture_changes(&storage.business).unwrap();
    assert_eq!(changes.rows.len(), 3);
    for index in [1, 2] {
        assert!(changes.rows[&index]
            .before
            .as_ref()
            .unwrap()
            .ptr_eq(&base.log.entries[&index]));
    }
    assert!(changes.rows[&3].before.is_none());
    let decoded = reconstruct(&base, &storage, &changes);
    cold(&decoded);
    let empty = storage.log.capture_changes(&storage.business).unwrap();
    assert!(empty.rows.is_empty() && Arc::ptr_eq(&empty.base, &changes.target));
}

#[test]
fn native_log_changes_equal_byte_retry_changes_revision_and_omission_rejects() {
    let mut storage = fixture();
    let base = storage.clone();
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &append(&[blank(1, 1)]));
    let changes = storage.log.changes.as_ref().unwrap();
    assert_eq!(changes.base.summary.content, changes.target.summary.content);
    assert!(changes.base.summary.revisions != changes.target.summary.revisions);
    assert_eq!(values(&base.log), values(&storage.log));
    assert!(!base.log.entries[&1].ptr_eq(&storage.log.entries[&1]));
    reconstruct(&base, &storage, changes);
    cold(&storage);
    storage.log.changes.as_mut().unwrap().rows.remove(&1);
    assert!(storage.log.capture_changes(&storage.business).is_err());
    assert_eq!(values(&base.log), values(&storage.log));
}

#[test]
fn native_log_changes_missing_stale_and_changed_capture_rows_fail_without_publication() {
    for kind in 0..5 {
        let mut storage = fixture();
        let old = storage.log.entries[&2].clone();
        storage.log.begin_changes(&storage.business).unwrap();
        project(&mut storage, &append(&[blank(1, 2), blank(1, 3)]));
        let expected = values(&storage.log);
        let dirty = storage.log.changes.as_mut().unwrap();
        match kind {
            0 => {
                dirty.rows.remove(&3);
            }
            1 => {
                dirty.rows.get_mut(&2).unwrap().after = Some(old);
            }
            2 => {
                dirty
                    .rows
                    .get_mut(&2)
                    .unwrap()
                    .before_stamp
                    .as_mut()
                    .unwrap()
                    .content[0] ^= 1;
            }
            3 => {
                dirty
                    .rows
                    .get_mut(&3)
                    .unwrap()
                    .after_stamp
                    .as_mut()
                    .unwrap()
                    .revision[0] ^= 1;
            }
            _ => {
                dirty.rows.get_mut(&2).unwrap().before = None;
            }
        }
        assert!(
            storage.log.capture_changes(&storage.business).is_err(),
            "capture corruption {kind}"
        );
        assert_eq!(values(&storage.log), expected);
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_log_changes_invalid_operations_leave_values_proof_and_capture_unchanged() {
    // The pinned single-term-leader profile represents a committed leader
    // by term alone. A different constructor node is not a different LogId.
    assert_eq!(
        CommittedLeaderId::new(1, SessionConsensusNodeId::new(7).unwrap()),
        CommittedLeaderId::new(1, SessionConsensusNodeId::new(8).unwrap())
    );
    let cases = vec![
        (Operation::Append(Vec::new()), None),
        (
            Operation::Append(vec![
                serde_json::to_vec(&blank(1, 3)).unwrap().into(),
                Bytes::from_static(b"{"),
            ]),
            None,
        ),
        (append(&[blank(1, 3), blank(1, 5)]), None),
        (append(&[blank(0, 3)]), None),
        (append(&[blank(2, 2)]), None),
        (Operation::Truncate(id(1, 0)), None),
        (Operation::Truncate(id(2, 2)), None),
        (Operation::Truncate(id(1, 4)), None),
        (Operation::Committed(None), None),
        (Operation::Committed(Some(id(2, 2))), None),
        (Operation::Purge(id(1, 1)), None),
        (Operation::Purge(id(1, 2)), Some(id(1, 1))),
        (Operation::Purge(id(2, 1)), Some(id(2, 2))),
        (
            Operation::Vote(Vote::new(2, SessionConsensusNodeId::new(99).unwrap())),
            None,
        ),
    ];
    for (offset, (operation, frozen)) in cases.into_iter().enumerate() {
        let mut storage = fixture();
        storage.log.begin_changes(&storage.business).unwrap();
        let expected = values(&storage.log);
        let proof = Arc::clone(storage.log.require_proof(&storage.business).unwrap());
        assert!(
            storage
                .log
                .project(&operation, &storage.business, frozen)
                .is_err(),
            "invalid operation {offset}"
        );
        assert_eq!(values(&storage.log), expected);
        assert!(Arc::ptr_eq(
            &proof,
            storage.log.require_proof(&storage.business).unwrap()
        ));
        let changes = storage.log.capture_changes(&storage.business).unwrap();
        assert!(changes.rows.is_empty() && Arc::ptr_eq(&changes.base, &changes.target));
    }
}

#[test]
fn native_log_changes_staged_publication_requires_the_exact_owner_revision() {
    let mut storage = fixture();
    storage.log.begin_changes(&storage.business).unwrap();
    let staged = Publication::prepare(
        &storage.log,
        &append(&[blank(1, 3)]),
        &storage.business,
        None,
    )
    .unwrap();
    project(
        &mut storage,
        &Operation::Vote(Vote::new(2, SessionConsensusNodeId::new(7).unwrap())),
    );
    let expected = values(&storage.log);
    assert!(staged.publish(&mut storage.log, &storage.business).is_err());
    assert_eq!(values(&storage.log), expected);
    storage.log.capture_changes(&storage.business).unwrap();
}

#[test]
fn native_log_changes_staged_publication_rejects_a_later_business_revision() {
    let mut storage = fixture();
    project(&mut storage, &Operation::Committed(Some(id(1, 2))));
    let staged =
        Publication::prepare(&storage.log, &Operation::Barrier, &storage.business, None).unwrap();
    let entries = storage.log.read(1, Some(2), None).unwrap();
    storage
        .log
        .require_committed_entries(&storage.business, Some(id(1, 2)), &entries)
        .unwrap();
    storage.business.apply(&entries).unwrap();
    let expected = values(&storage.log);
    assert!(staged.publish(&mut storage.log, &storage.business).is_err());
    assert_eq!(values(&storage.log), expected);
    storage.validate_image().unwrap();
}

#[test]
fn native_log_changes_metadata_revisions_purge_and_durable_authority_remain_distinct() {
    let mut storage = fixture();
    let base = storage.clone();
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &Operation::Barrier);
    let barrier = storage.log.capture_changes(&storage.business).unwrap();
    assert!(barrier.rows.is_empty() && !Arc::ptr_eq(&barrier.base, &barrier.target));
    project(&mut storage, &Operation::Committed(Some(id(1, 2))));
    let entries = storage.log.read(1, Some(3), None).unwrap();
    assert!(
        storage
            .log
            .require_committed_entries(&storage.business, Some(id(1, 0)), &entries)
            .is_err(),
        "admission commit is not durable authority"
    );
    storage
        .log
        .require_committed_entries(&storage.business, Some(id(1, 2)), &entries)
        .unwrap();
    storage.business.apply(&entries).unwrap();
    storage
        .log
        .project(
            &Operation::Purge(id(1, 1)),
            &storage.business,
            Some(id(1, 2)),
        )
        .unwrap();
    let changes = storage.log.capture_changes(&storage.business).unwrap();
    assert!(changes.rows.is_empty());
    assert_eq!(
        storage.log.entries.len(),
        3,
        "logical purge cannot invent physical reclamation"
    );
    assert_eq!(storage.log.read(0, None, None).unwrap().len(), 1);
    reconstruct(&base, &storage, &changes);
    cold(&storage);
    let expected = values(&storage.log);
    assert!(storage
        .log
        .project(&Operation::Purge(id(2, 1)), &storage.business, None)
        .is_err());
    assert!(storage
        .log
        .project(
            &Operation::Committed(Some(id(1, 0))),
            &storage.business,
            None
        )
        .is_err());
    assert_eq!(values(&storage.log), expected);
}

#[test]
fn native_log_changes_full_admission_checks_raw_schema_typed_binding_and_holes() {
    for kind in 0..5 {
        let storage = fixture();
        let mut log = storage.log.clone();
        let mut changed = (*log.entries[&1]).clone();
        match kind {
            0 => {
                changed.resident_mut().unwrap().encoded = Bytes::from_static(b"{");
                log.entries.insert(1, SharedRow::new(changed));
            }
            1 => {
                changed.resident_mut().unwrap().entry.log_id = id(2, 1);
                log.entries.insert(1, SharedRow::new(changed));
            }
            2 => {
                changed.resident_mut().unwrap().encoded =
                    serde_json::to_vec(&blank(1, 2)).unwrap().into();
                log.entries.insert(1, SharedRow::new(changed));
            }
            3 => {
                log.entries.remove(&1);
            }
            _ => {
                log.committed = Some(id(2, 2));
            }
        }
        assert!(
            log.admit(&storage.business).is_err(),
            "cold validation {kind}"
        );
        assert!(
            log.proof.is_none(),
            "a failed full audit cannot leave the old certificate"
        );
        assert!(log
            .project(&Operation::Barrier, &storage.business, None)
            .is_err());
    }
}

#[test]
fn native_log_changes_unproved_copies_require_full_admission_and_clones_drop_journals() {
    let mut storage = fixture();
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &append(&[blank(1, 3)]));
    let fork = storage.log.clone();
    assert!(fork.changes.is_none());
    assert!(Arc::ptr_eq(
        fork.require_proof(&storage.business).unwrap(),
        storage.log.require_proof(&storage.business).unwrap()
    ));
    let mut unproved = NativeLog {
        entries: fork.entries.clone(),
        vote: fork.vote,
        committed: fork.committed,
        purged: fork.purged,
        ..Default::default()
    };
    assert!(unproved
        .project(&Operation::Barrier, &storage.business, None)
        .is_err());
    unproved.admit(&storage.business).unwrap();
    unproved
        .project(&Operation::Barrier, &storage.business, None)
        .unwrap();
    assert_eq!(values(&unproved), values(&fork));
    assert!(
        storage.log.admit(&storage.business).is_err(),
        "full admission cannot discard a live journal"
    );
}

#[test]
fn native_log_changes_capture_rejects_business_lineage_that_old_log_proof_cannot_authorize() {
    let mut storage = fixture();
    storage.log.begin_changes(&storage.business).unwrap();
    storage.business.frontiers.applied = Some(id(1, 99));
    storage.business.admit_business().unwrap();
    assert!(storage.log.capture_changes(&storage.business).is_err());
    assert!(storage
        .log
        .project(&Operation::Barrier, &storage.business, None)
        .is_err());
}

impl CapturedLog {
    pub(in crate::consensus::native) fn reconstruct_for_test(&self, base: &NativeLog) -> NativeLog {
        let mut log = base.clone();
        log.proof = None;
        for (index, change) in &self.changes.rows {
            if let Some(row) = &change.after {
                let encoded: Bytes = row.resident().unwrap().encoded.to_vec().into();
                let entry = sql::decode_consensus_log_entry(&encoded).unwrap();
                log.entries
                    .insert(*index, SharedRow::new(NativeLogEntry::new(encoded, entry)));
            } else {
                log.entries.remove(index);
            }
        }
        log.vote = self.changes.target.frontiers.vote;
        log.committed = self.changes.target.frontiers.committed;
        log.purged = self.changes.target.frontiers.purged;
        log
    }
}

#[test]
fn native_capture_log_worker_rejects_omission_stale_stamp_and_raw_schema_corruption() {
    for kind in 0..7 {
        let mut storage = fixture();
        let old = storage.log.entries[&2].clone();
        storage.begin_changes().unwrap();
        project(&mut storage, &append(&[blank(1, 2), blank(1, 3)]));
        let mut captured = storage.take_changes().unwrap();
        let expected = values(&storage.log);
        let rows = &mut captured.log.changes.rows;
        match kind {
            0 => {
                rows.remove(&3);
            }
            1 => {
                rows.get_mut(&2).unwrap().after = Some(old);
            }
            2 => {
                rows.get_mut(&2)
                    .unwrap()
                    .before_stamp
                    .as_mut()
                    .unwrap()
                    .content[0] ^= 1;
            }
            3 => {
                rows.get_mut(&3)
                    .unwrap()
                    .after_stamp
                    .as_mut()
                    .unwrap()
                    .revision[0] ^= 1;
            }
            4 => {
                rows.get_mut(&2).unwrap().before = None;
            }
            5 | 6 => {
                let change = rows.get_mut(&3).unwrap();
                let mut row = (**change.after.as_ref().unwrap()).clone();
                if kind == 5 {
                    row.resident_mut().unwrap().encoded = Bytes::from_static(b"{");
                } else {
                    row.resident_mut().unwrap().entry.log_id = id(2, 3);
                }
                change.after = Some(SharedRow::new(row));
            }
            _ => unreachable!(),
        }
        assert!(
            captured.validate(&|| Ok(())).is_err(),
            "detached log corruption {kind}"
        );
        assert_eq!(values(&storage.log), expected);
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_capture_log_witnesses_bind_schema_membership_and_exact_revision() {
    for kind in 0..4 {
        let mut storage = fixture();
        storage.begin_changes().unwrap();
        let mut captured = storage.take_changes().unwrap();
        captured.validate(&|| Ok(())).unwrap();
        if kind == 0 {
            for witness in &mut captured.log.witnesses {
                *witness = None;
            }
        } else {
            let witness = captured.log.witnesses.iter_mut().flatten().next().unwrap();
            match kind {
                1 => {
                    witness.index += 1;
                }
                2 => {
                    witness.row = SharedRow::new((*witness.row).clone());
                }
                _ => {
                    let entry = blank(1, 0);
                    witness.row = SharedRow::new(NativeLogEntry::new(
                        serde_json::to_vec(&entry).unwrap().into(),
                        entry,
                    ));
                    // Even a forged process revision cannot make the wrong
                    // membership payload satisfy the captured full context.
                    witness.revision = witness.row.address();
                    for other in captured.log.witnesses.iter_mut().skip(1) {
                        *other = None;
                    }
                }
            }
        }
        assert!(
            captured.validate(&|| Ok(())).is_err(),
            "captured witness corruption {kind}"
        );
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_capture_log_transfer_retains_containers_and_worker_skips_unchanged_rows() {
    use std::cell::Cell;
    let mut visits = Vec::new();
    for extra in [0, 64] {
        let mut storage = fixture();
        for index in 3..3 + extra {
            project(&mut storage, &append(&[blank(1, index)]));
        }
        storage.begin_changes().unwrap();
        let captured = storage.take_changes().unwrap();
        let calls = Cell::new(0);
        captured
            .validate(&|| {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap();
        visits.push(calls.get());
    }
    assert_eq!(
        visits[0], visits[1],
        "unchanged payloads do not enter worker validation"
    );

    let mut storage = fixture();
    storage.begin_changes().unwrap();
    project(&mut storage, &append(&[blank(1, 2), blank(1, 3)]));
    let dirty = storage.log.changes.as_ref().unwrap();
    let row_slot = dirty.rows.get(&3).unwrap() as *const RowChange;
    let memory_slots = dirty.memory.as_ptr();
    let captured = storage.take_changes().unwrap();
    assert_eq!(
        row_slot,
        captured.log.changes.rows.get(&3).unwrap() as *const RowChange
    );
    assert_eq!(memory_slots, captured.log.changes.memory.as_ptr());
    project(&mut storage, &append(&[blank(1, 4)]));
    drop(storage);
    captured.validate(&|| Ok(())).unwrap();
}

#[test]
fn native_capture_log_equal_byte_retry_omission_still_rejects_after_transfer() {
    let mut storage = fixture();
    storage.begin_changes().unwrap();
    project(&mut storage, &append(&[blank(1, 1)]));
    let mut captured = storage.take_changes().unwrap();
    captured.validate(&|| Ok(())).unwrap();
    let changes = &mut captured.log.changes;
    assert_eq!(
        (changes.base.summary.count, changes.base.summary.content),
        (changes.target.summary.count, changes.target.summary.content)
    );
    assert_ne!(
        changes.base.summary.revisions,
        changes.target.summary.revisions
    );
    changes.rows.remove(&1);
    assert!(captured.validate(&|| Ok(())).is_err());
}
