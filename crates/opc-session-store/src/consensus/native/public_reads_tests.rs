//! Journal read admission is independent of committed history validity.

use super::*;
use crate::consensus::native::changes::tests::fixture;

#[test]
fn native_bulk_journal_page_rejects_before_copying_and_smaller_page_still_reads() {
    let (mut storage, _, _) = fixture();
    let state = &mut storage.business;
    let original = state
        .notifications
        .front()
        .unwrap()
        .resident()
        .unwrap()
        .clone();
    state.proof = None;
    state.notifications.clear();
    const ROWS: usize = 16_384;
    for ordinal in 0..ROWS {
        state.notifications.push_back(
            NotificationRow::new(NativeNotification::new(ReplicationEntry {
                sequence: ordinal as u64 + 1,
                ..original.clone()
            }))
            .unwrap(),
        );
    }
    state.frontiers.watch_sequence = ROWS as u64;
    // Use the complete admission validator, never a fabricated certificate.
    state.validate_full_business().unwrap();
    state.admit_business().unwrap();
    let before = state.frontiers.clone();
    let mut result = None;
    let allocations = allocation_counter::measure(|| {
        result = Some(state.replication_log(0, ROWS, &|| Ok(())));
    });
    assert!(
        matches!(result.unwrap(), Err(StoreError::BackendUnavailable(_))),
        "bulk journal page must reject before consuming the verifier progress budget"
    );
    assert!(
        allocations.bytes_total < 64 * 1024,
        "rejected bulk page must not hydrate rows or allocate output containers"
    );
    assert!(state.frontiers == before);
    state.require_business_proof().unwrap();
    let smaller = state.replication_log(0, 8, &|| Ok(())).unwrap();
    assert_eq!(
        smaller.len(),
        8,
        "resource refusal must not return a short success page"
    );
    for (ordinal, entry) in smaller.iter().enumerate() {
        assert_eq!(entry.sequence, ordinal as u64 + 1);
        let expected = ReplicationEntry {
            sequence: entry.sequence,
            ..original.clone()
        };
        assert_eq!(
            postcard::to_allocvec(entry).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
    }
}
