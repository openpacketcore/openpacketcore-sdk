use super::*;
use crate::test_process::CommandExt as _;

#[test]
fn native_purge_rejects_changed_dirty_predecessor() {
    let mut storage = applied_prefix(6);
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &append(&[blank(1, 1)]));
    storage
        .log
        .changes
        .as_mut()
        .unwrap()
        .rows
        .get_mut(&1)
        .unwrap()
        .after_stamp = None;
    assert_eq!(
        storage
            .log
            .project(
                &Operation::Purge(id(1, 2)),
                &storage.business,
                storage.business.applied()
            )
            .unwrap_err()
            .to_string(),
        "native log dirty predecessor changed"
    );
}

fn applied_prefix(count: u64) -> NativeStorage {
    assert!(count >= 3);
    let mut storage = fixture();
    for first in (3..count).step_by(64) {
        let end = (first + 64).min(count);
        let entries = (first..end)
            .map(|index| blank(1, index))
            .collect::<Vec<_>>();
        project(&mut storage, &append(&entries));
    }
    project(&mut storage, &Operation::Committed(Some(id(1, count - 1))));
    for first in (1..count).step_by(64) {
        let entries = storage
            .log
            .read(first, Some((first + 64).min(count)), None)
            .unwrap();
        storage.business.apply(&entries).unwrap();
    }
    select_snapshot(&mut storage, id(1, count - 1));
    storage
}

fn purge(storage: &mut NativeStorage, index: u64) {
    storage
        .log
        .project(
            &Operation::Purge(id(1, index)),
            &storage.business,
            storage.business.applied(),
        )
        .unwrap();
}

#[test]
fn native_purge_coalesces_equal_byte_retries_and_multiple_frontiers_without_row_frames() {
    let mut storage = applied_prefix(6);
    let original = storage.clone();
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &append(&[blank(1, 1)]));
    assert!(!storage.log.entries[&1].ptr_eq(&original.log.entries[&1]));
    purge(&mut storage, 1);
    project(&mut storage, &append(&[blank(1, 2)]));
    assert!(!storage.log.entries[&2].ptr_eq(&original.log.entries[&2]));
    purge(&mut storage, 2);
    // An older, same-lineage callback does not reconstruct covered rows.
    purge(&mut storage, 1);
    let capture = storage.log.capture_changes(&storage.business).unwrap();
    assert_eq!(capture.target.frontiers.purged, Some(id(1, 2)));
    assert_eq!(capture.base.summary.count - capture.target.summary.count, 3);
    assert_eq!(
        storage.log.entries.keys().copied().collect::<Vec<_>>(),
        [3, 4, 5]
    );
    assert!(
        capture.rows.is_empty(),
        "prefix removal is carried by the frontier only"
    );
    reconstruct(&original, &storage, &capture);
    let empty = storage.log.capture_changes(&storage.business).unwrap();
    assert!(empty.rows.is_empty());
    assert_eq!(empty.base.summary.content, empty.target.summary.content);
    assert_eq!(empty.base.summary.revisions, empty.target.summary.revisions);
}

#[test]
fn native_purge_reservation_does_not_grow_with_the_removed_row_count() {
    let mut reservation = None;
    for count in [3, 64, 4096] {
        let mut storage = applied_prefix(count);
        storage.log.begin_changes(&storage.business).unwrap();
        let publication = Publication::prepare(
            &storage.log,
            &Operation::Purge(id(1, count - 2)),
            &storage.business,
            Some(id(1, count - 1)),
        )
        .unwrap();
        assert!(publication.rows.is_empty());
        let bytes = publication
            .memory
            .as_ref()
            .map_or(0, |memory| memory.reserved_bytes());
        assert_eq!(
            bytes, 0,
            "purge requires no additional verifier reservation"
        );
        assert!(Arc::ptr_eq(
            &publication.proof.scope,
            &publication.predecessor.scope,
        ));
        assert_eq!(*reservation.get_or_insert(bytes), bytes);
        publication
            .publish(&mut storage.log, &storage.business)
            .unwrap();
        assert_eq!(storage.log.entries.len(), 1);
        let captured = storage
            .log
            .prepare_transfer(&storage.business)
            .unwrap()
            .take();
        assert_eq!(captured.generation_count(), 0);
        let mut frames = Vec::new();
        captured.write_generation(&mut frames, &|| Ok(())).unwrap();
        assert!(frames.is_empty());
        captured.validate_captured(&|| Ok(())).unwrap();
    }
}

#[test]
fn native_purge_succeeds_with_the_process_verification_budget_fully_reserved() {
    use crate::consensus::verified_snapshot::PROCESS_VERIFICATION_BYTES;

    const CHILD: &str = "OPC_NATIVE_PURGE_PRESSURE_CHILD";
    const TEST: &str = "consensus::native::log::changes::tests::purge_journal_tests::native_purge_succeeds_with_the_process_verification_budget_fully_reserved";
    if std::env::var_os(CHILD).is_none() {
        // Exhaust the real process counter in isolation, without affecting
        // concurrent tests or changing the production reservation limit.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        println!("{stdout}");
        assert!(output.status.success(), "{stderr}");
        assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        return;
    }

    for count in [3, 64, 4096] {
        let mut storage = applied_prefix(count);
        let original = storage.clone();
        storage.log.begin_changes(&storage.business).unwrap();
        let pinned = storage
            .log
            .prepare_transfer(&storage.business)
            .unwrap()
            .take();
        let pressure = VerificationMemory::reserve(
            PROCESS_VERIFICATION_BYTES - VerificationMemory::used_bytes(),
        )
        .unwrap();
        assert_eq!(VerificationMemory::used_bytes(), PROCESS_VERIFICATION_BYTES);
        for through in [count - 2, count - 1] {
            let publication = Publication::prepare(
                &storage.log,
                &Operation::Purge(id(1, through)),
                &storage.business,
                Some(id(1, count - 1)),
            )
            .expect("purge admission must not acquire verification memory");
            publication
                .publish(&mut storage.log, &storage.business)
                .expect("purge publication must not acquire verification memory");
            assert_eq!(storage.log.entries.len() as u64, count - through - 1);
        }
        drop(pressure);

        assert_eq!(original.log.entries.len() as u64, count);
        assert!(original.log.purged.is_none());
        assert_eq!(pinned.changes.target.summary.count as u64, count);
        pinned.validate_captured(&|| Ok(())).unwrap();
        let captured = storage
            .log
            .prepare_transfer(&storage.business)
            .unwrap()
            .take();
        assert_eq!(captured.generation_count(), 0);
        captured.validate_captured(&|| Ok(())).unwrap();
        reconstruct(&original, &storage, &captured.changes);
    }
}

#[test]
fn native_purge_capture_recomputes_all_removed_aggregates_and_requires_the_cut() {
    let mut storage = applied_prefix(6);
    storage.log.begin_changes(&storage.business).unwrap();
    project(&mut storage, &append(&[blank(1, 1)]));
    purge(&mut storage, 2);
    let mut captured = storage
        .log
        .prepare_transfer(&storage.business)
        .unwrap()
        .take();
    captured.validate_captured(&|| Ok(())).unwrap();
    let expected = captured.changes.cut.as_ref().unwrap().removed;
    for field in 0..3 {
        let removed = &mut captured.changes.cut.as_mut().unwrap().removed;
        match field {
            0 => removed.count += 1,
            1 => removed.content[0] ^= 1,
            _ => removed.revisions[0] ^= 1,
        }
        assert_eq!(
            captured
                .validate_captured(&|| Ok(()))
                .unwrap_err()
                .to_string(),
            "native log capture prefix aggregate differs"
        );
        captured.changes.cut.as_mut().unwrap().removed = expected;
        captured.validate_captured(&|| Ok(())).unwrap();
    }
    let cut = captured.changes.cut.take().unwrap();
    assert_eq!(
        captured
            .validate_captured(&|| Ok(()))
            .unwrap_err()
            .to_string(),
        "native log capture prefix cut missing"
    );
    captured.changes.cut = Some(cut);
    captured.validate_captured(&|| Ok(())).unwrap();
    captured.changes.cut.as_mut().unwrap().through = id(1, 1);
    assert_eq!(
        captured
            .validate_captured(&|| Ok(()))
            .unwrap_err()
            .to_string(),
        "native log capture prefix frontier differs"
    );
}

#[test]
fn native_purge_large_prefix_bounds_owner_allocations_at_window_and_cap() {
    const CHILD: &str = "OPC_NATIVE_PURGE_MEASUREMENT_CHILD";
    const TEST: &str = "consensus::native::log::changes::tests::purge_journal_tests::native_purge_large_prefix_bounds_owner_allocations_at_window_and_cap";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        println!("{stdout}");
        for line in stderr
            .lines()
            .filter(|line| line.starts_with("NATIVE_PURGE_WORK "))
        {
            eprintln!("{line}");
        }
        assert!(output.status.success(), "{stderr}");
        assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
        return;
    }
    for count in [262_144, MAX_RETAINED_LOG_ENTRIES as u64] {
        // Setup uses the production entry batch width. The old root remains
        // pinned throughout every purge, just as a detached reader can do.
        let original = applied_prefix(count);
        for keep in [count - 1, count / 2, 1024] {
            let mut storage = original.clone();
            storage.log.begin_changes(&storage.business).unwrap();
            let before = VerificationMemory::used_bytes();
            let mut elapsed = std::time::Duration::ZERO;
            let allocations = allocation_counter::measure(|| {
                let started = std::time::Instant::now();
                let publication = Publication::prepare(
                    &storage.log,
                    &Operation::Purge(id(1, count - keep - 1)),
                    &storage.business,
                    Some(id(1, count - 1)),
                )
                .unwrap();
                assert!(publication.rows.is_empty());
                assert!(publication.memory.is_none());
                publication
                    .publish(&mut storage.log, &storage.business)
                    .unwrap();
                elapsed = started.elapsed();
            });
            assert_eq!(VerificationMemory::used_bytes(), before);
            assert_eq!(storage.log.entries.len() as u64, keep);
            assert_eq!(storage.log.entries.get_min().unwrap().0, count - keep);
            assert_eq!(storage.log.purged, Some(id(1, count - keep - 1)));
            assert_eq!(original.log.entries.len() as u64, count);
            assert!(original.log.purged.is_none());
            // No removed-row vector or payload copy may accompany the cut.
            // Persistent tree edits are bounded by the smaller side; the
            // independent count/content/revision audit still runs afterward.
            let allocation_bound = 128 * 1024 + keep.min(count - keep) * 1024;
            assert!(allocations.bytes_max as u64 <= allocation_bound);
            assert!(allocations.bytes_total <= allocation_bound);
            let capture = storage
                .log
                .prepare_transfer(&storage.business)
                .unwrap()
                .take();
            assert_eq!(capture.generation_count(), 0);
            capture.validate_captured(&|| Ok(())).unwrap();
            eprintln!(
                "NATIVE_PURGE_WORK rows={count} removed={} retained={keep} admission_and_publication_us={} allocated_bytes={} peak_bytes={} allocations={} verifier_extra_bytes=0",
                count - keep,
                elapsed.as_micros(),
                allocations.bytes_total,
                allocations.bytes_max,
                allocations.count_total,
            );
        }
    }
}
