//! Small admitted fixtures isolate allocation ownership from the opt-in fleet.

use super::*;
use crate::consensus::native::lifecycle_tests::{maintenance, seed};
use crate::fenced_transition::FENCED_TRANSITION_V2_RECLAIM_BATCH;
use crate::test_process::CommandExt as _;

fn retiring(batches: usize) -> NativeStorage {
    retiring_with_profile(batches, crate::FencedTransitionV2Profile::V2)
}

fn retiring_with_profile(
    batches: usize,
    profile: crate::FencedTransitionV2Profile,
) -> NativeStorage {
    let (mut storage, _, _) = fixture_with_profile(profile);
    let remaining = batches * FENCED_TRANSITION_V2_RECLAIM_BATCH;
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
    let history = FencedTransitionV2HistoryState::new(
        Some(epoch(2)),
        Some(epoch(1)),
        Some(epoch(1)),
        remaining,
        1,
        0,
        (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - remaining) as u64,
    )
    .unwrap();
    seed(&mut storage, history, time(10), None, false);
    storage.begin_changes().unwrap();
    storage
}

#[test]
fn native_reclaim_memory_publication_releases_only_destroyed_scratch() {
    let mut storage = retiring(2);
    let entry = maintenance(&storage, 2, time(11));
    let publication = Publication::prepare(storage.business.prepare(&[entry]).unwrap()).unwrap();
    let prepared_bytes = publication.memory.reserved_bytes_for_test()
        + publication._scratch.reserved_bytes_for_test()
        + publication.deletions.index_verification_bytes();
    let staged = publication._scratch.reserved_bytes_for_test();
    publication.publish(&mut storage.business).unwrap();
    let retained = storage.business.changes.as_ref().unwrap();
    let owner = Arc::downgrade(&retained.memory[0]);
    let retained_bytes: usize = retained
        .memory
        .iter()
        .map(|owner| owner.reserved_bytes_for_test())
        .sum::<usize>()
        + retained
            .deletions
            .iter()
            .map(DeletedRows::index_verification_bytes)
            .sum::<usize>();
    assert!(owner.upgrade().is_some(), "live journal keeps its owner");
    assert!(
        prepared_bytes < 256 * 1024,
        "deletions share their original row objects and retain exact fingerprints"
    );
    assert!(
        retained_bytes <= prepared_bytes - staged,
        "destroyed staging is still charged: prepared={prepared_bytes}, retained={retained_bytes}, staging={staged}"
    );
    let capture = storage.business.capture_changes().unwrap();
    assert_eq!(
        capture.generation_counts(0)[1],
        FENCED_TRANSITION_V2_RECLAIM_BATCH
    );
    assert!(
        owner.upgrade().is_some(),
        "capture retains deletion evidence"
    );
    assert!(storage.business.changes.as_ref().unwrap().memory.is_empty());
    drop(capture);
    assert!(owner.upgrade().is_none(), "last capture releases its guard");

    let entry = maintenance(&storage, 3, time(12));
    let publication = Publication::prepare(storage.business.prepare(&[entry]).unwrap()).unwrap();
    let owner = Arc::downgrade(&publication.memory);
    let before = Arc::clone(storage.business.require_business_proof().unwrap());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _publication = publication;
        panic!("cancel prepared reclaim");
    }));
    assert!(result.is_err());
    assert!(owner.upgrade().is_none());
    assert!(Arc::ptr_eq(
        &before,
        storage.business.require_business_proof().unwrap()
    ));

    // Ordinary after-images still need staging. Its temporary owner must
    // disappear at publication while the journal retains the row charge.
    let (mut storage, _, outcome) = fixture();
    storage.begin_changes().unwrap();
    let entry = command(2, &request(2, Some(&outcome)), time(2), false);
    let publication = Publication::prepare(storage.business.prepare(&[entry]).unwrap()).unwrap();
    let retained = publication.memory.reserved_bytes_for_test();
    assert!(publication._scratch.reserved_bytes_for_test() > 0);
    publication.publish(&mut storage.business).unwrap();
    assert_eq!(
        storage.business.changes.as_ref().unwrap().memory[0].reserved_bytes_for_test(),
        retained
    );
}

#[test]
fn native_reclaim_memory_compact_capture_rejects_inventory_and_fingerprint_changes() {
    for kind in 0..5 {
        let mut storage = retiring(2);
        let entry = maintenance(&storage, 2, time(11));
        apply(&mut storage, &[entry]);
        let mut captured = storage.business.capture_changes().unwrap();
        captured.validate_captured(&|| Ok(())).unwrap();
        captured.deletions[0].corrupt_for_test(kind);
        assert!(
            captured.validate_captured(&|| Ok(())).is_err(),
            "deletion corruption {kind}"
        );
        storage.validate_image().unwrap();
    }
}

fn isolated(case: &str) -> bool {
    const CHILD: &str = "OPC_RECLAIM_MEMORY_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(case) {
        return false;
    }
    let name = format!("consensus::native::changes::tests::reclaim_memory::{case}");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--test-threads=1", "--nocapture"])
        .env(CHILD, case)
        .test_output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "unchanged per-process budget: {stdout}\n{stderr}"
    );
    assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    true
}

fn entries(storage: &NativeStorage) -> Vec<Entry<SessionRaftTypeConfig>> {
    (0..128)
        .map(|offset| {
            let mut entry = maintenance(storage, 2 + offset, time(11));
            let EntryPayload::Normal(command) = &mut entry.payload else {
                unreachable!()
            };
            let SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation,
                ..
            } = &mut command.intent
            else {
                unreachable!()
            };
            *expected_generation += offset;
            entry
        })
        .collect()
}

fn project(storage: &mut NativeStorage, entries: &[Entry<SessionRaftTypeConfig>]) {
    for entries in entries.chunks(64) {
        storage
            .log
            .project(
                &Operation::Append(
                    entries
                        .iter()
                        .map(|entry| serde_json::to_vec(entry).unwrap().into())
                        .collect(),
                ),
                &storage.business,
                None,
            )
            .unwrap();
    }
    storage
        .log
        .project(
            &Operation::Committed(entries.last().map(|entry| entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
}

fn complete(storage: &NativeStorage) {
    let history = storage.business.history_state().unwrap();
    assert_eq!(history.reclaim_remaining(), 0);
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(
        history.reclaimed_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64
    );
    assert!(storage.business.receipts.is_empty());
    assert_eq!(storage.business.applied().unwrap().index, 129);
    storage.validate_image().unwrap();
}

#[test]
fn native_reclaim_memory_coalesced_delivery_preserves_atomic_publication() {
    if isolated("native_reclaim_memory_coalesced_delivery_preserves_atomic_publication") {
        return;
    }
    let mut storage = retiring(128);
    let entries = entries(&storage);
    project(&mut storage, &entries);
    let before = Arc::clone(storage.business.require_business_proof().unwrap());
    let capture = storage.business.capture_application().unwrap();
    let publication = capture.prepare(&entries, &|| Ok(()), || Ok(())).unwrap();
    assert!(Arc::ptr_eq(
        &before,
        storage.business.require_business_proof().unwrap()
    ));
    assert_eq!(
        storage
            .business
            .history_state()
            .unwrap()
            .reclaim_remaining(),
        131_072
    );
    publication.publish(&mut storage.business).unwrap();
    complete(&storage);
}

#[test]
fn native_reclaim_memory_replay_multiple_full_transport_cohorts() {
    if isolated("native_reclaim_memory_replay_multiple_full_transport_cohorts") {
        return;
    }
    let mut storage = retiring(128);
    let entries = entries(&storage);
    project(&mut storage, &entries);
    storage.replay_committed().unwrap();
    complete(&storage);
}

#[test]
fn native_reclaim_memory_replay_matches_complete_straight_apply() {
    let mut straight = retiring(10);
    let mut replay = straight.clone();
    replay.begin_changes().unwrap();
    let entries = entries(&straight)[..10].to_vec();
    apply(&mut straight, &entries);
    project(&mut replay, &entries);
    replay.replay_committed().unwrap();
    assert_eq!(
        straight.business.business_digest_for_test().unwrap(),
        replay.business.business_digest_for_test().unwrap()
    );
    assert_eq!(straight.business.applied(), replay.business.applied());
    assert_eq!(straight.log.committed, replay.log.committed);
    replay.take_changes().unwrap().validate(&|| Ok(())).unwrap();
}

#[test]
fn native_reclaim_memory_candidate_counts_effects_and_tops_up_shortfall() {
    let storage = retiring(2);
    let entries = entries(&storage);
    assert_eq!(
        storage.business.reclaim_candidate_bytes(&entries).unwrap(),
        2 * 1024 * DeletedRows::row_bytes()
    );
    let mut stale = entries[0].clone();
    let EntryPayload::Normal(command) = &mut stale.payload else {
        unreachable!()
    };
    let SessionMutationIntent::MaintainFencedTransitionV2History {
        expected_generation,
        ..
    } = &mut command.intent
    else {
        unreachable!()
    };
    *expected_generation += 1000;
    assert_eq!(
        storage.business.reclaim_candidate_bytes(&[stale]).unwrap(),
        0
    );
    let captured = storage
        .business
        .capture_application()
        .unwrap()
        .with_reclaim_memory(Some(VerificationMemory::reserve(1).unwrap()));
    let prepared = captured
        .prepare(&entries[..1], &|| Ok(()), || Ok(()))
        .unwrap();
    drop(prepared);
}

#[test]
fn native_reclaim_memory_staged_allocation_dies_before_refund() {
    for publish in [false, true] {
        let (mut storage, _, outcome) = fixture();
        storage.begin_changes().unwrap();
        let entries = [
            command(2, &request(2, Some(&outcome)), time(2), false),
            clock(3, time(3)),
        ];
        let mut publication =
            Publication::prepare(storage.business.prepare(&entries).unwrap()).unwrap();
        assert!(!publication.keys.is_empty());
        assert!(!publication.receipts.is_empty());
        assert!(!publication.generic.is_empty());
        let lifetime = Arc::new(());
        publication.keys.allocation_lifetime = Some(Arc::clone(&lifetime));
        publication.receipts.allocation_lifetime = Some(Arc::clone(&lifetime));
        publication.generic.allocation_lifetime = Some(Arc::clone(&lifetime));
        let weak = Arc::downgrade(&lifetime);
        assert!(Arc::strong_count(&lifetime) > 1);
        drop(lifetime);
        let capacity = publication.keys.capacity()
            * size_of::<StagedRow<SessionKey, NativeKeyState>>()
            + publication.receipts.capacity()
                * size_of::<StagedRow<FencedTransitionV2RequestId, NativeReceipt>>()
            + publication.generic.capacity()
                * size_of::<StagedRow<SessionConsensusRequestId, NativeGenericReceipt>>();
        assert_eq!(publication._scratch.reserved_bytes(), capacity);
        publication._scratch.observe_refund_for_test(move || {
            assert!(
                weak.upgrade().is_none(),
                "scratch refunded before the staging vector buffer was freed"
            );
        });
        if publish {
            publication.publish(&mut storage.business).unwrap();
        } else {
            drop(publication);
        }
    }
    let storage = retiring(1);
    let entry = maintenance(&storage, 2, time(11));
    let publication = Publication::prepare(storage.business.prepare(&[entry]).unwrap()).unwrap();
    assert_eq!(DeletedRows::row_bytes(), 72);
    assert_eq!(
        publication.memory.reserved_bytes(),
        3 * 64 + 4 * size_of::<DeletedRows>()
    );
    eprintln!("native_reclaim_charge_sizes row_bytes={} index_clone_bytes={} publication_bytes={} staging_bytes={}", DeletedRows::row_bytes(), history_order::ReceiptOrder::clone_metadata_bytes(), publication.memory.reserved_bytes(), publication._scratch.reserved_bytes());
    assert_eq!(
        publication.deletions.index_verification_bytes(),
        1024 * 72 + 64 * 1024
    );
}

#[test]
fn native_reclaim_memory_refund_probe_covers_early_shrink() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut memory = VerificationMemory::reserve(2).unwrap();
    memory.observe_refund_for_test({
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    memory.shrink_to(1).unwrap();
    let partial = calls.load(std::sync::atomic::Ordering::SeqCst);
    drop(memory);
    assert_eq!(
        partial, 1,
        "a partial refund must run the allocation lifetime check immediately"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn native_reclaim_memory_refund_probe_follows_split_owner() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut memory = VerificationMemory::reserve(2).unwrap();
    memory.observe_refund_for_test({
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let split = memory.split_off(1).unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(split);
    let partial = calls.load(std::sync::atomic::Ordering::SeqCst);
    drop(memory);
    assert_eq!(partial, 1, "the split owner retains its lifetime check");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn native_reclaim_memory_deletion_charges_outlive_allocations() {
    for publish in [false, true] {
        let mut storage = retiring(1);
        let entry = maintenance(&storage, 2, time(11));
        let mut publication =
            Publication::prepare(storage.business.prepare(&[entry]).unwrap()).unwrap();
        let refunds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        publication
            .deletions
            .observe_allocation_lifetimes_for_test(Arc::clone(&refunds));
        if publish {
            publication.publish(&mut storage.business).unwrap();
            assert_eq!(refunds.load(std::sync::atomic::Ordering::SeqCst), 0);
            let journal = storage.business.changes.as_ref().unwrap();
            assert_eq!(
                storage.business.changed_verification_bytes(),
                journal
                    .memory
                    .iter()
                    .map(|m| m.reserved_bytes())
                    .sum::<usize>()
                    + journal
                        .deletions
                        .iter()
                        .map(DeletedRows::index_verification_bytes)
                        .sum::<usize>()
            );
            let captured = storage.business.capture_changes().unwrap();
            captured.validate_captured(&|| Ok(())).unwrap();
            drop(captured);
        } else {
            drop(publication);
        }
        assert_eq!(refunds.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}

#[test]
fn native_reclaim_memory_mixed_delivery_retains_full_reservation() {
    mixed_delivery_retains_full_reservation(false);
}

#[test]
fn native_reclaim_memory_void_mixed_delivery_retains_full_reservation() {
    mixed_delivery_retains_full_reservation(true);
}

fn mixed_delivery_retains_full_reservation(void: bool) {
    let profile = if void {
        crate::FencedTransitionV2Profile::V2WithVoid
    } else {
        crate::FencedTransitionV2Profile::V2
    };
    let mut storage = retiring_with_profile(2, profile);
    let (_, _, previous) = fixture_with_profile(profile);
    let template = request(7, void.then_some(&previous));
    let successor = |nonce| {
        FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(2).unwrap(),
            crate::FencedTransitionV2CallerNonce::from_bytes([nonce; 16]),
            template.lease().clone(),
            template.mutation().clone(),
        )
        .unwrap()
    };
    let mut reclaim = maintenance(&storage, 4, time(12));
    let EntryPayload::Normal(value) = &mut reclaim.payload else {
        unreachable!()
    };
    let SessionMutationIntent::MaintainFencedTransitionV2History {
        expected_bound_entries,
        ..
    } = &mut value.intent
    else {
        unreachable!()
    };
    *expected_bound_entries = 2;
    let binding = if void { void_command } else { command };
    let entries = [
        binding(2, &successor(0xE1), time(11), false),
        binding(3, &successor(0xE2), time(11), false),
        reclaim,
    ];
    let mut straight = storage.clone();
    for (index, entry) in entries.iter().enumerate() {
        let result = apply(&mut straight, std::slice::from_ref(entry));
        if void && index < 2 {
            assert_eq!(
                result.responses[0].result,
                Err(StoreError::FencedTransitionVoided)
            );
        }
    }
    let hint = storage.business.reclaim_candidate_bytes(&entries).unwrap();
    let mut delta = storage.business.prepare(&entries).unwrap();
    delta.reclaim_memory = Some(VerificationMemory::reserve(hint).unwrap());
    let publication = Publication::prepare(delta).unwrap();
    assert_eq!(publication.deletions.len(), 1024);
    assert_eq!(
        publication.deletions.index_verification_bytes(),
        1024 * 72 + 64 * 1024,
        "mixed bindings cannot bypass the exact fail-closed deletion reservation"
    );
    project(&mut storage, &entries);
    publication.publish(&mut storage.business).unwrap();
    assert_eq!(
        storage.business.business_digest_for_test().unwrap(),
        straight.business.business_digest_for_test().unwrap()
    );
    assert_eq!(storage.business.history_state().unwrap().bound_entries(), 2);
    assert_eq!(
        storage
            .business
            .history_state()
            .unwrap()
            .reclaim_remaining(),
        1024
    );
}

#[test]
fn native_reclaim_memory_void_log_copies_cover_actual_allocations() {
    let body = request(7, None);
    for activate in [false, true] {
        for authorized in [false, true] {
            let mut entry = void_command(2, &body, time(2), activate);
            if authorized {
                let EntryPayload::Normal(value) = &mut entry.payload else {
                    unreachable!()
                };
                value.intent = SessionMutationIntent::Authorized {
                    origin: *members().first().unwrap(),
                    authority_identity: identity(),
                    mutation: Box::new(value.intent.clone()),
                };
            }
            let reservation = scratch::log_owned(&entry).unwrap();
            let mut copied = None;
            let measured = allocation_counter::measure(|| {
                copied = Some(owned::entry(&entry).unwrap());
            });
            assert!(
                measured.bytes_current > 0,
                "the retained request owns real buffers"
            );
            assert!(
                measured.bytes_current as usize <= reservation,
                "void request allocations exceed their charge: actual={}, reserved={reservation}",
                measured.bytes_current,
            );
            assert_eq!(
                serde_json::to_vec(copied.as_ref().unwrap()).unwrap(),
                serde_json::to_vec(&entry).unwrap(),
            );
        }
    }
}

#[test]
fn native_reclaim_memory_void_journal_charges_rows_and_retains_capture_ownership() {
    if isolated("native_reclaim_memory_void_journal_charges_rows_and_retains_capture_ownership") {
        return;
    }
    let (mut storage, original, previous) =
        fixture_with_profile(crate::FencedTransitionV2Profile::V2WithVoid);
    storage.begin_changes().unwrap();
    let watch = storage.business.frontiers.watch_sequence;
    let next_fence = storage.business.frontiers.next_fence;
    let key_before = resident::RowFingerprint::row_fingerprint(
        &**storage.business.keys.get(original.lease().key()).unwrap(),
        0,
        original.lease().key(),
    )
    .unwrap();
    let requests: Vec<_> = (2..66)
        .map(|nonce| request(nonce, Some(&previous)))
        .collect();
    let entries: Vec<_> = requests
        .iter()
        .enumerate()
        .map(|(offset, body)| void_command(2 + offset as u64, body, time(2), false))
        .collect();
    project(&mut storage, &entries);
    let publication = Publication::prepare(storage.business.prepare(&entries).unwrap()).unwrap();
    let retained = publication.memory.reserved_bytes_for_test();
    let minimum_row = size_of::<FencedTransitionV2RequestId>() + 2 * 32 + 2 * size_of::<usize>();
    assert!(retained >= requests.len() * minimum_row);
    let owner = Arc::downgrade(&publication.memory);
    let result = publication.publish(&mut storage.business).unwrap();
    assert!(result
        .responses
        .iter()
        .all(|response| { response.result == Err(StoreError::FencedTransitionVoided) }));
    assert!(result.notifications.is_empty());
    assert_eq!(storage.business.frontiers.watch_sequence, watch);
    assert_eq!(storage.business.frontiers.next_fence, next_fence);
    assert_eq!(
        resident::RowFingerprint::row_fingerprint(
            &**storage.business.keys.get(original.lease().key()).unwrap(),
            0,
            original.lease().key(),
        )
        .unwrap(),
        key_before,
    );
    assert_eq!(storage.business.changed_verification_bytes(), retained);
    assert!(VerificationMemory::used_bytes() >= retained);
    let captured = storage.business.capture_changes().unwrap();
    assert_eq!(captured.generation_counts(0)[1], requests.len());
    assert_eq!(captured.relocation_count().unwrap(), requests.len());
    captured.validate_captured(&|| Ok(())).unwrap();
    assert!(owner.upgrade().is_some());
    assert_eq!(storage.business.changed_verification_bytes(), 0);
    drop(captured);
    assert!(
        owner.upgrade().is_none(),
        "only the last journal owner refunds the rows"
    );
    storage.validate_image().unwrap();
}
