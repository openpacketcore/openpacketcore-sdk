use super::*;

#[test]
fn native_prefix_subtraction_rejects_underflow() {
    let mut summary = Summary {
        count: 2,
        ..Summary::default()
    };
    summary
        .subtract(Summary {
            count: 2,
            ..Summary::default()
        })
        .unwrap();
    assert_eq!(summary.count, 0);
    assert_eq!(
        summary
            .subtract(Summary {
                count: 1,
                ..Summary::default()
            })
            .unwrap_err()
            .to_string(),
        "native log prefix removal count differs"
    );
    assert_eq!(summary.count, 0);
}

fn applied_at(snapshot: u64) -> NativeStorage {
    let mut storage = fixture();
    project(&mut storage, &Operation::Committed(Some(id(1, 2))));
    let entries = storage.log.read(1, None, None).unwrap();
    storage.business.apply(&entries).unwrap();
    select_snapshot(&mut storage, id(1, snapshot));
    storage
}

fn applied() -> NativeStorage {
    applied_at(2)
}

fn metadata(storage: &NativeStorage) -> io::Result<()> {
    validate_context_metadata(
        &LogFrontiers::of(&storage.log),
        &storage.business.members,
        &storage.business.frontiers,
        storage.business.snapshot_origin.as_deref(),
        |index| storage.log.entries.get(&index).map(|row| row.id()),
        |index| index == 0 && storage.log.entries.contains_key(&0),
    )
}

#[test]
fn native_purge_context_requires_a_selected_snapshot_covering_its_frontier() {
    let mut storage = applied();
    storage.log.purged = Some(id(1, 1));
    metadata(&storage).unwrap();
    let selected = storage.business.frontiers.current_snapshot.take();
    assert_eq!(
        metadata(&storage).unwrap_err().to_string(),
        "native purge frontier exceeds selected snapshot"
    );
    storage.business.frontiers.current_snapshot = selected;
    metadata(&storage).unwrap();
    storage
        .business
        .frontiers
        .current_snapshot
        .as_mut()
        .unwrap()
        .0
        .last_log_id = Some(id(1, 0));
    assert_eq!(
        metadata(&storage).unwrap_err().to_string(),
        "native purge frontier exceeds selected snapshot"
    );
    storage
        .business
        .frontiers
        .current_snapshot
        .as_mut()
        .unwrap()
        .0
        .last_log_id = Some(id(1, 1));
    metadata(&storage).unwrap();
}

#[test]
fn native_purge_missing_membership_requires_the_whole_selected_membership() {
    let mut storage = applied();
    storage.log.purged = Some(id(1, 1));
    storage.log.entries.remove(&0);
    storage.log.entries.remove(&1);
    metadata(&storage).unwrap();
    let membership = storage
        .business
        .frontiers
        .current_snapshot
        .as_ref()
        .unwrap()
        .0
        .last_membership
        .clone();
    storage
        .business
        .frontiers
        .current_snapshot
        .as_mut()
        .unwrap()
        .0
        .last_membership = StoredMembership::default();
    assert_eq!(
        metadata(&storage).unwrap_err().to_string(),
        "native membership payload differs from exact log witness"
    );
    storage
        .business
        .frontiers
        .current_snapshot
        .as_mut()
        .unwrap()
        .0
        .last_membership = membership;
    metadata(&storage).unwrap();
}

#[test]
fn native_purge_at_selected_snapshot_allows_its_missing_applied_and_membership_rows() {
    let mut storage = applied();
    storage.log.purged = Some(id(1, 2));
    storage.log.entries.clear();
    storage.log.proof = None;
    storage.log.admit(&storage.business).unwrap();
    metadata(&storage).unwrap();
    storage
        .validate_snapshot(
            storage
                .business
                .frontiers
                .current_snapshot
                .as_ref()
                .unwrap(),
        )
        .unwrap();
    storage.validate_image().unwrap();
    cold(&storage).validate_image().unwrap();
    assert_eq!(storage.log.last(), Some(id(1, 2)));
    assert!(storage.log.read(0, None, None).unwrap().is_empty());
    storage
        .business
        .frontiers
        .current_snapshot
        .as_mut()
        .unwrap()
        .0
        .last_log_id = Some(id(1, 1));
    assert_eq!(
        storage
            .validate_snapshot(
                storage
                    .business
                    .frontiers
                    .current_snapshot
                    .as_ref()
                    .unwrap()
            )
            .unwrap_err()
            .to_string(),
        "native snapshot applied lineage differs from retained log"
    );
}

#[test]
fn native_purge_admission_needs_selected_snapshot_as_well_as_frozen_applied() {
    let mut storage = applied_at(1);
    let before = values(&storage.log);
    let proof = storage
        .log
        .require_proof(&storage.business)
        .unwrap()
        .clone();
    assert_eq!(
        storage
            .log
            .project(
                &Operation::Purge(id(1, 2)),
                &storage.business,
                Some(id(1, 2))
            )
            .unwrap_err()
            .to_string(),
        "native purge frontier exceeds selected snapshot"
    );
    assert_eq!(values(&storage.log), before);
    assert!(proof.same(storage.log.require_proof(&storage.business).unwrap()));
    select_snapshot(&mut storage, id(1, 2));
    storage
        .log
        .project(
            &Operation::Purge(id(1, 2)),
            &storage.business,
            Some(id(1, 2)),
        )
        .unwrap();
    assert!(storage.log.entries.is_empty());
    assert_eq!(storage.log.purged, Some(id(1, 2)));
    storage.validate_image().unwrap();
}

#[test]
fn native_purge_retained_prefix_requires_adjacent_full_lineage_and_no_covered_row() {
    validate_retained_prefix(id(1, 0), None, None).unwrap();
    assert_eq!(
        validate_retained_prefix(id(1, 1), None, None)
            .unwrap_err()
            .to_string(),
        "native retained log lacks its prefix"
    );
    validate_retained_prefix(id(1, 1), Some(id(1, 0)), None).unwrap();
    assert_eq!(
        validate_retained_prefix(id(1, 2), Some(id(1, 0)), None)
            .unwrap_err()
            .to_string(),
        "native retained log lacks its prefix"
    );
    validate_retained_prefix(id(1, 2), Some(id(1, 1)), None).unwrap();
    assert_eq!(
        validate_retained_prefix(id(1, 2), Some(id(2, 1)), None)
            .unwrap_err()
            .to_string(),
        "native retained log prefix lineage differs"
    );
    for first in [id(1, 0), id(1, 1)] {
        assert_eq!(
            validate_retained_prefix(first, Some(id(1, 1)), None)
                .unwrap_err()
                .to_string(),
            "native retained log extends below its purge frontier"
        );
    }
}
