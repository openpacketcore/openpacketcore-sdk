use super::super::changes::tests::{apply, command, fixture, request, time};
use super::*;
use crate::sqlite::consensus::wal::Operation;

fn stage(storage: &mut NativeStorage, entries: &[Entry<SessionRaftTypeConfig>]) {
    let rows = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().into())
        .collect();
    storage
        .log
        .project(&Operation::Append(rows), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(entries.last().map(|entry| entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
}

#[test]
fn native_application_capture_retries_tracking_and_snapshot_predecessors() {
    for snapshot in [false, true] {
        let (mut storage, first, outcome) = fixture();
        if snapshot {
            storage.begin_changes().unwrap();
        }
        let second = request(2, Some(&outcome));
        let entries = [command(2, &second, time(2), false)];
        stage(&mut storage, &entries);
        let captured = storage.business.capture_application().unwrap();
        let prepared = captured
            .prepare(&entries, &|| Ok(()), || {
                panic!("resident apply performs no cold read")
            })
            .unwrap();
        assert!(prepared.is_current(&storage.business).unwrap());
        let expected_snapshot = if snapshot {
            let meta = opc_consensus::engine::SnapshotMeta {
                last_log_id: storage.business.applied(),
                last_membership: storage.business.membership(),
                snapshot_id: format!("{}application", snapshot_prefix([0xA9; 32])),
            };
            let selected = (
                meta,
                format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
                [0xA9; 32],
                100,
            );
            storage.validate_snapshot(&selected).unwrap();
            storage
                .business
                .set_current_snapshot(selected.clone())
                .unwrap();
            Some(selected)
        } else {
            storage.begin_changes().unwrap();
            None
        };
        assert!(!prepared.is_current(&storage.business).unwrap());
        let before = storage.business.clone();
        assert!(prepared.publish(&mut storage.business).is_err());
        assert!(storage.business.frontiers == before.frontiers);
        assert!(
            storage.business.keys[first.lease().key()].ptr_eq(&before.keys[first.lease().key()])
        );
        assert!(storage.business.receipts[&first.request_id()]
            .ptr_eq(&before.receipts[&first.request_id()]));
        assert!(!storage.business.receipts.contains_key(&second.request_id()));
        assert_eq!(
            storage.business.notifications.len(),
            before.notifications.len()
        );
        let retry = storage
            .business
            .capture_application()
            .unwrap()
            .prepare(&entries, &|| Ok(()), || Ok(()))
            .unwrap();
        assert!(retry.is_current(&storage.business).unwrap());
        let applied = retry.publish(&mut storage.business).unwrap();
        assert!(applied.responses[0].result.is_ok());
        assert_eq!(applied.notifications.len(), 1);
        assert_eq!(storage.business.current_snapshot(), expected_snapshot);
        storage.validate_image().unwrap();
        storage
            .take_changes()
            .unwrap()
            .validate(&|| Ok(()))
            .unwrap();
    }
}

#[test]
fn native_application_capture_does_not_copy_or_overwrite_transferred_changes() {
    let (mut storage, _, outcome) = fixture();
    storage.begin_changes().unwrap();
    let second = request(2, Some(&outcome));
    let applied = apply(&mut storage, &[command(2, &second, time(2), false)]);
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &applied.responses[0].result else {
        panic!("second result");
    };
    let third = request(3, Some(outcome));
    let entries = [command(3, &third, time(3), false)];
    stage(&mut storage, &entries);
    let prepared = storage
        .business
        .capture_application()
        .unwrap()
        .prepare(&entries, &|| Ok(()), || Ok(()))
        .unwrap();
    let prior = storage.take_changes().unwrap();
    prior.validate(&|| Ok(())).unwrap();
    // Detaching the journal changes no row or semantic predecessor. The
    // prepared update must join the now-empty live journal without retry.
    assert!(prepared.is_current(&storage.business).unwrap());
    prepared.publish(&mut storage.business).unwrap();
    let next = storage.take_changes().unwrap();
    next.validate(&|| Ok(())).unwrap();
    assert_eq!(storage.business.receipt_count(), 3);
    assert_eq!(storage.business.notifications.len(), 3);
    assert!(matches!(
        storage.business.status(&third).unwrap(),
        FencedTransitionV2Status::Recorded(_)
    ));
    storage.validate_image().unwrap();
}
