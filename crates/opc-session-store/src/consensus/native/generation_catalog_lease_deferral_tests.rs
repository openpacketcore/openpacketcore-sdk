use super::*;
use crate::consensus::native::lease_deferral_tests::pending_fixture;

fn expired() -> Timestamp {
    Timestamp::from_offset_datetime(*time(0).as_offset_datetime() + time::Duration::seconds(80))
}

#[test]
fn native_catalog_lease_deferral_base_and_terminal_delta_preserve_the_same_binding() {
    let (mut hot, pending) = pending_fixture();
    let (mut files, catalog) = Files::new(&hot);
    let mut cold = catalog.into_storage(&|| Ok(())).unwrap();
    let requests = std::slice::from_ref(&pending);
    let reads = cold.business.capture_receipt_reads(requests).unwrap();
    assert!(!reads.is_empty());
    let resolved = reads.resolve(&|| Ok(())).unwrap();
    let copies = resolved.copy_current(&cold.business).unwrap();
    assert_eq!(
        cold.business
            .status_with_receipts(&pending, &copies)
            .unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: pending.request_id()
        }
    );

    // Evaluate the exact same committed entry against admitted file-backed
    // and resident predecessors, with cold decoding outside publication.
    let entries = [command(3, &pending, expired(), false)];
    let encoded = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().into())
        .collect();
    cold.log
        .project(&Operation::Append(encoded), &cold.business, None)
        .unwrap();
    cold.log
        .project(
            &Operation::Committed(Some(entries[0].log_id)),
            &cold.business,
            None,
        )
        .unwrap();
    let publication = cold
        .business
        .capture_application()
        .unwrap()
        .prepare(&entries, &|| Ok(()), || Ok(()))
        .unwrap();
    let cold_applied = publication.publish(&mut cold.business).unwrap();
    hot.begin_changes().unwrap();
    let hot_applied = apply(&mut hot, &entries);
    assert_eq!(cold_applied.responses, hot_applied.responses);
    assert_eq!(cold_applied.notifications.len(), 1);
    assert_eq!(cold.business.history().unwrap().bound_entries(), 2);
    cold.validate_image().unwrap();

    let terminal = files.append(&mut hot, 19).into_storage(&|| Ok(())).unwrap();
    let terminal_reads = terminal
        .business
        .capture_receipt_reads(requests)
        .unwrap()
        .resolve(&|| Ok(()))
        .unwrap();
    let terminal_copies = terminal_reads.copy_current(&terminal.business).unwrap();
    let status = terminal
        .business
        .status_with_receipts(&pending, &terminal_copies)
        .unwrap();
    assert!(matches!(status, FencedTransitionV2Status::Recorded(result) if result.is_ok()));
    assert_eq!(terminal.business.receipts[&pending.request_id()].ordinal, 2);
    assert!(!terminal.business.receipts[&pending.request_id()].lease_deferred());
}

#[test]
fn native_catalog_lease_deferral_read_refreshes_only_the_one_terminal_successor() {
    let (mut hot, pending) = pending_fixture();
    let (mut files, catalog) = Files::new(&hot);
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    let requests = std::slice::from_ref(&pending);
    let mut resolved = cold
        .business
        .capture_receipt_reads(requests)
        .unwrap()
        .resolve(&|| Ok(()))
        .unwrap();
    hot.begin_changes().unwrap();
    apply(&mut hot, &[command(3, &pending, expired(), false)]);
    let terminal = files.append(&mut hot, 19).into_storage(&|| Ok(())).unwrap();
    let missing = resolved
        .capture_missing(&terminal.business, requests)
        .unwrap();
    assert!(!missing.is_empty());
    resolved
        .extend(missing.resolve(&|| Ok(())).unwrap())
        .unwrap();
    assert!(resolved
        .capture_missing(&terminal.business, requests)
        .unwrap()
        .is_empty());
    let copies = resolved.copy_current(&terminal.business).unwrap();
    assert!(
        matches!(terminal.business.status_with_receipts(&pending, &copies).unwrap(),
        FencedTransitionV2Status::Recorded(result) if result.is_ok())
    );
    // Reintroducing the pending revision is still corruption, not another
    // retry window or an indefinitely refreshed receipt.
    assert!(resolved.capture_missing(&cold.business, requests).is_err());
}

#[test]
fn native_catalog_lease_deferral_rejects_forged_resident_response_facts() {
    let (hot, pending) = pending_fixture();
    let (_files, catalog) = Files::new(&hot);
    let indexed = &catalog.rows.receipts[&pending.request_id()];
    for field in 0..4 {
        let mut facts = indexed.row;
        match field {
            0 => facts.facts.lease_deferred = false,
            1 => facts.facts.response.as_mut().unwrap().logical_time = time(1),
            2 => facts.facts.response.as_mut().unwrap().sequence += 1,
            _ => facts.facts.response.as_mut().unwrap().raft_index += 1,
        }
        let row = NativeReceipt::from_admitted_range(
            pending.request_id(),
            facts,
            Arc::clone(&catalog.source),
            indexed.range.offset,
            indexed.range.length,
        );
        assert!(
            row.is_err()
                || !row
                    .unwrap()
                    .matches_decoded(
                        pending.request_id(),
                        &hot.business.receipts[&pending.request_id()]
                    )
                    .unwrap()
        );
    }
}
