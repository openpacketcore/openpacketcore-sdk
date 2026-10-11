use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use crate::test_process::CommandExt as _;
use generation::{BaseParameters, Catalog, CatalogScope, PreparedBase, PreparedDelta, Version};
use opc_consensus::engine::SnapshotMeta;

const MAXIMUM: u64 = 32 * 1024 * 1024;

fn append_commit(storage: &mut NativeStorage, entry: Entry<SessionRaftTypeConfig>) {
    append(storage, &entry);
    commit(storage, &entry);
}

fn unique_request(table: &VoterSlotTable, slot: u16, sequence: u64) -> VoterReplacementRequest {
    let mut value = request(table, slot);
    let mut id = [0; 16];
    id[..8].copy_from_slice(&sequence.to_le_bytes());
    id[8] = 1;
    value.attestation.request_id = SessionConsensusRequestId::from_bytes(id);
    value.attestation.request_digest = voter_replacement_request_digest(
        value.expected_revision,
        value.expected_configuration,
        &value.candidate,
        &value.attestation,
    )
    .unwrap();
    value
}

fn complete_replacement(storage: &mut NativeStorage, initial: &VoterSlotTable, sequence: u64) {
    let wanted = unique_request(
        storage.voter_slot_state().unwrap().table(),
        2 + (sequence % 2) as u16,
        sequence,
    );
    let advance = |step| VoterSlotControl::Advance {
        request_id: wanted.attestation.request_id,
        request_digest: wanted.attestation.request_digest,
        step,
    };
    let prepare = storage.log.last().unwrap().index + 1;
    append_commit(
        storage,
        command(
            initial,
            prepare,
            VoterSlotControl::Begin(Box::new(wanted.clone())),
        ),
    );
    let operation = storage
        .voter_slot_state()
        .unwrap()
        .table()
        .replacement
        .clone()
        .unwrap();
    let old: BTreeSet<_> = operation
        .predecessor
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect();
    let new: BTreeSet<_> = operation
        .successor
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect();
    let union = old.union(&new).copied().collect::<BTreeSet<_>>();
    append_commit(
        storage,
        command(
            initial,
            prepare + 1,
            advance(VoterReplacementStep::RecordSnapshot(
                VoterSnapshotEvidence {
                    cut: voter_slots::cut(cut(prepare)),
                    snapshot_id: format!("replacement-{sequence}"),
                    digest: [5; 32],
                },
            )),
        ),
    );
    append_commit(
        storage,
        Entry {
            log_id: cut(prepare + 2),
            payload: EntryPayload::Membership(Membership::new(
                vec![old.clone()],
                Some(union.clone()),
            )),
        },
    );
    append_commit(
        storage,
        command(
            initial,
            prepare + 3,
            VoterSlotControl::Marker {
                request_id: wanted.attestation.request_id,
                request_digest: wanted.attestation.request_digest,
            },
        ),
    );
    append_commit(
        storage,
        command(
            initial,
            prepare + 4,
            advance(VoterReplacementStep::RecordCaughtUp(voter_slots::cut(cut(
                prepare + 3,
            )))),
        ),
    );
    append_commit(
        storage,
        command(initial, prepare + 5, advance(VoterReplacementStep::Fence)),
    );
    append_commit(
        storage,
        Entry {
            log_id: cut(prepare + 6),
            payload: EntryPayload::Membership(Membership::new(vec![old, new.clone()], Some(union))),
        },
    );
    append_commit(
        storage,
        Entry {
            log_id: cut(prepare + 7),
            payload: EntryPayload::Membership(Membership::new(vec![new], None)),
        },
    );
    append_commit(
        storage,
        command(
            initial,
            prepare + 8,
            advance(VoterReplacementStep::Finalize),
        ),
    );
    let state = storage.voter_slot_state().unwrap();
    assert!(
        state.table().replacement.is_none(),
        "replacement {sequence} must complete"
    );
    assert_eq!(
        state.table().slots[usize::from(wanted.candidate.identity.slot().get() - 1)].member,
        wanted.candidate
    );
}

fn delta(
    storage: &mut NativeStorage,
    owner: &mut prefix::VerifiedAppendOwner,
    version: &Version,
    epoch: u64,
) -> prefix::PrefixIdentity {
    let prepared = PreparedDelta::prepare(
        owner.current(),
        version,
        epoch,
        epoch,
        [8; 32],
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    let (selected, mut relocations) = prepared.append_with_relocations(owner, &|| Ok(())).unwrap();
    while !relocations.is_empty() {
        drop(relocations.publish_step(storage).unwrap());
    }
    selected.identity()
}

fn projection_bytes(storage: &NativeStorage) -> usize {
    storage
        .log
        .entries
        .values()
        .map(|row| row.slot_projection_bytes_for_test())
        .sum()
}

#[test]
fn native_voter_slot_churn_releases_projection_memory_on_snapshot_purge_and_reopen() {
    const CHILD: &str = "OPC_VOTER_SLOT_CHURN_CHILD";
    const TEST: &str = "consensus::native::voter_slot_tests::memory_tests::native_voter_slot_churn_releases_projection_memory_on_snapshot_purge_and_reopen";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        println!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    let initial = genesis(3);
    let mut storage = NativeStorage::empty_with_voter_slots(initial.clone()).unwrap();
    let identity = storage.business.identity;
    let members = storage.business.members.clone();
    append_commit(
        &mut storage,
        Entry {
            log_id: cut(0),
            payload: EntryPayload::Membership(Membership::new(vec![members.clone()], None)),
        },
    );
    // 3,240 real control/membership rows, 360 completed operations, with the
    // actual process cap unchanged. All old incarnations must remain retired.
    for sequence in 1..=360 {
        complete_replacement(&mut storage, &initial, sequence);
    }
    let completed = storage.voter_slot_state().unwrap();
    assert_eq!(completed.table().slots[1].retired_through, 180);
    assert_eq!(completed.table().slots[2].retired_through, 180);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("slots.native");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let base = PreparedBase::prepare(
        &storage,
        BaseParameters {
            binding: [6; 32],
            file_epoch: 1,
            checkpoint_epoch: 1,
            operation_sequence: 1,
            cut_binding: [8; 32],
            block_bytes: 64 * 1024,
            maximum: MAXIMUM,
        },
        &|| Ok(()),
    )
    .unwrap();
    let selected = base.write_to(&mut file, &|| Ok(())).unwrap();
    file.sync_all().unwrap();
    drop(base);
    drop(file);
    drop(storage);
    let scope = || CatalogScope {
        identity,
        members: &members,
        roster_root: None,
    };
    let (mut owner, catalog) =
        Catalog::open(&path, selected, MAXIMUM, scope(), [8; 32], &|| Ok(())).unwrap();
    let mut storage = catalog
        .into_storage(&|| Ok(()))
        .expect("thousands of completed controls must reopen within the unchanged memory budget");
    assert_eq!(storage.voter_slot_state().unwrap(), completed);
    assert_eq!(
        projection_bytes(&storage),
        0,
        "completed operations retain no decoded slot rows"
    );
    assert!(VerificationMemory::used_bytes() < 8 * 1024 * 1024);
    let mut epoch = 1;
    storage.begin_changes().unwrap();
    let version = Version::capture(&storage).unwrap();
    let marker = command(
        &initial,
        storage.log.last().unwrap().index + 1,
        VoterSlotControl::Marker {
            request_id: SessionConsensusRequestId::from_bytes([1; 16]),
            request_digest: [1; 32],
        },
    );
    append(&mut storage, &marker);
    epoch += 1;
    delta(&mut storage, &mut owner, &version, epoch);
    assert_eq!(
        projection_bytes(&storage),
        0,
        "an unapplied Marker needs no projection"
    );
    for snapshot in [false, true] {
        let version = Version::capture(&storage).unwrap();
        let index = storage.log.last().unwrap().index + 1;
        let wanted = unique_request(storage.voter_slot_state().unwrap().table(), 2, 400 + epoch);
        let prepare = command(&initial, index, VoterSlotControl::Begin(Box::new(wanted)));
        append(&mut storage, &prepare);
        epoch += 1;
        delta(&mut storage, &mut owner, &version, epoch);
        assert!(storage.voter_slot_state().unwrap().intent().is_some());
        assert!(
            projection_bytes(&storage) > 0 && projection_bytes(&storage) < 4096,
            "one unapplied Prepare has a real-sized reservation"
        );
        // A concurrent old capture must keep its exact intent and reservation.
        let captured = storage.clone();
        let version = Version::capture(&storage).unwrap();
        commit(&mut storage, &prepare);
        if snapshot {
            storage
                .business
                .set_current_snapshot((
                    SnapshotMeta {
                        last_log_id: Some(prepare.log_id),
                        last_membership: storage.business.frontiers.membership.clone(),
                        snapshot_id: format!("{}slot-churn", snapshot_prefix([6; 32])),
                    },
                    format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
                    [5; 32],
                    4096,
                ))
                .unwrap();
        }
        epoch += 1;
        delta(&mut storage, &mut owner, &version, epoch);
        if !snapshot {
            // A purge may use only an already selected applied predecessor.
            let version = Version::capture(&storage).unwrap();
            storage
                .log
                .project(
                    &Operation::Purge(prepare.log_id),
                    &storage.business,
                    Some(prepare.log_id),
                )
                .unwrap();
            epoch += 1;
            delta(&mut storage, &mut owner, &version, epoch);
        }
        assert_eq!(
            projection_bytes(&storage),
            0,
            "selected apply/purge/snapshot releases old projections"
        );
        assert!(captured.voter_slot_state().unwrap().intent().is_some());
        assert!(projection_bytes(&captured) > 0);
        drop(captured);
    }
    // A selected but abandoned Prepare is reclaimed by the actual truncate.
    let version = Version::capture(&storage).unwrap();
    let index = storage.log.last().unwrap().index + 1;
    let wanted = unique_request(storage.voter_slot_state().unwrap().table(), 2, 999);
    let prepare = command(&initial, index, VoterSlotControl::Begin(Box::new(wanted)));
    append(&mut storage, &prepare);
    epoch += 1;
    delta(&mut storage, &mut owner, &version, epoch);
    assert!(projection_bytes(&storage) > 0);
    let retained = storage.voter_slot_state().unwrap().table().clone();
    let version = Version::capture(&storage).unwrap();
    storage
        .log
        .project(
            &Operation::Truncate(prepare.log_id),
            &storage.business,
            None,
        )
        .unwrap();
    epoch += 1;
    let selected = delta(&mut storage, &mut owner, &version, epoch);
    assert_eq!(projection_bytes(&storage), 0);
    assert!(storage.voter_slot_state().unwrap().intent().is_none());
    drop(storage);
    drop(owner);
    let (_, catalog) =
        Catalog::open(&path, selected, MAXIMUM, scope(), [8; 32], &|| Ok(())).unwrap();
    let reopened = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(reopened.voter_slot_state().unwrap().table(), &retained);
    assert!(reopened.voter_slot_state().unwrap().intent().is_none());
    assert_eq!(projection_bytes(&reopened), 0);
    assert!(VerificationMemory::used_bytes() < 8 * 1024 * 1024);
    reopened.validate_image().unwrap();
}
