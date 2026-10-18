use super::*;
use crate::consensus::native::lease_deferral_tests::{full_epoch_pending_fixture, pending_fixture};

fn expired() -> Timestamp {
    Timestamp::from_offset_datetime(*time(0).as_offset_datetime() + time::Duration::seconds(80))
}

fn review_cohort_catalog_resolution_expiry_case(separate_checkpoint: bool) {
    let (mut hot, pending) = pending_fixture();
    let (mut files, _catalog) = Files::new(&hot);
    hot.begin_changes().unwrap();
    let completed = apply(&mut hot, &[command(3, &pending, expired(), false)]);
    assert!(matches!(
        completed.responses[0].result,
        Ok(SessionMutationOutcome::FencedTransition(_))
    ));
    if separate_checkpoint {
        files.append(&mut hot, 19);
    }
    let expires = crate::consensus::native::retention_deadline(expired()).unwrap();
    let replay = apply(&mut hot, &[command(4, &pending, expires, false)]);
    assert_eq!(
        replay.responses[0].result,
        Err(StoreError::FencedTransitionRequestExpired)
    );
    let cold = files
        .append(&mut hot, if separate_checkpoint { 20 } else { 19 })
        .into_storage(&|| Ok(()))
        .unwrap();
    assert_eq!(
        cold.business.status(&pending).unwrap(),
        FencedTransitionV2Status::Expired
    );
    assert_eq!(cold.business.receipts[&pending.request_id()].ordinal, 2);
    assert_eq!(cold.business.history().unwrap().bound_entries(), 2);
    cold.validate_image().unwrap();
}

#[test]
fn review_cohort_catalog_resolution_expiry_one_checkpoint() {
    review_cohort_catalog_resolution_expiry_case(false);
}

#[test]
fn review_cohort_catalog_resolution_expiry_separate_checkpoints() {
    review_cohort_catalog_resolution_expiry_case(true);
}

fn apply_cold_lifecycle(
    cold: &mut NativeStorage,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> NativeApplied {
    cold.log
        .project(
            &Operation::Append(
                entries
                    .iter()
                    .map(|entry| serde_json::to_vec(entry).unwrap().into())
                    .collect(),
            ),
            &cold.business,
            None,
        )
        .unwrap();
    cold.log
        .project(
            &Operation::Committed(Some(entries.last().unwrap().log_id)),
            &cold.business,
            None,
        )
        .unwrap();
    let publication = cold
        .business
        .capture_application()
        .unwrap()
        .prepare(entries, &|| Ok(()), || Ok(()))
        .unwrap();
    publication.publish(&mut cold.business).unwrap()
}

fn catalog_retirement_schedule(grouped: bool, separate_checkpoint: bool) {
    use crate::consensus::native::lifecycle_tests::maintenance;
    use crate::fenced_transition::FENCED_TRANSITION_V2_RECLAIM_BATCH;
    // This new fixture contains all eight production-sized epochs. Existing
    // small fixtures keep their original 2 MiB file limit.
    const FULL_HISTORY_FILE_LIMIT: u64 = 512 * 1024 * 1024;
    for ordinal in [1, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64] {
        let (mut hot, pending) = full_epoch_pending_fixture(ordinal);
        let sequence = hot.business.frontiers.sequence;
        let (mut files, catalog) = Files::with_maximum(&hot, FULL_HISTORY_FILE_LIMIT);
        let mut cold = catalog.into_storage(&|| Ok(())).unwrap();
        hot.begin_changes().unwrap();
        let resolved_at = Timestamp::from_offset_datetime(
            *time(0).as_offset_datetime() + time::Duration::seconds(80),
        );
        let entries = [
            command(3, &pending, resolved_at, false),
            maintenance(&hot, 4, retention_deadline(resolved_at).unwrap()),
        ];
        let responses = if grouped {
            let actual = apply(&mut hot, &entries);
            let restored = apply_cold_lifecycle(&mut cold, &entries);
            assert_eq!(actual.responses, restored.responses);
            assert_eq!(actual.notifications.len(), 1);
            assert_eq!(restored.notifications.len(), 1);
            actual.responses
        } else {
            let mut responses = Vec::new();
            for (slot, entry) in entries.iter().enumerate() {
                let actual = apply(&mut hot, std::slice::from_ref(entry));
                let restored = apply_cold_lifecycle(&mut cold, std::slice::from_ref(entry));
                assert_eq!(actual.responses, restored.responses);
                responses.extend(actual.responses);
                if separate_checkpoint && slot == 0 {
                    files
                        .append(&mut hot, 19)
                        .into_storage(&|| Ok(()))
                        .unwrap()
                        .validate_image()
                        .unwrap();
                }
            }
            responses
        };
        assert!(matches!(
            responses[0].result,
            Ok(SessionMutationOutcome::FencedTransition(_))
        ));
        assert_eq!(responses[1].result, Ok(SessionMutationOutcome::Unit));
        assert_eq!(hot.business.frontiers.sequence, sequence + 2);
        assert_eq!(cold.business.frontiers.sequence, sequence + 2);
        let reopened = files
            .append(&mut hot, if separate_checkpoint { 20 } else { 19 })
            .into_storage(&|| Ok(()))
            .unwrap();
        for storage in [&hot, &cold, &reopened] {
            assert_eq!(
                storage.business.status(&pending).unwrap(),
                FencedTransitionV2Status::Retired
            );
            let history = storage.business.history().unwrap();
            assert_eq!(history.retired_through().unwrap().get(), 1);
            assert_eq!(
                history.reclaimed_entries(),
                FENCED_TRANSITION_V2_RECLAIM_BATCH as u64
            );
            assert_eq!(
                history.bound_entries(),
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            );
            assert_eq!(
                storage
                    .business
                    .receipts
                    .contains_key(&pending.request_id()),
                ordinal != 1
            );
            if ordinal != 1 {
                let row = &storage.business.receipts[&pending.request_id()];
                assert_eq!(row.ordinal, ordinal);
                assert!(!row.lease_deferred());
                assert_eq!(row.retained_until, retention_deadline(resolved_at).unwrap());
            }
            storage.validate_image().unwrap();
        }
    }
}

#[test]
fn native_catalog_lease_deferral_retirement_grouped_apply_and_checkpoint() {
    catalog_retirement_schedule(true, false);
}

#[test]
fn native_catalog_lease_deferral_retirement_separate_apply_one_checkpoint() {
    catalog_retirement_schedule(false, false);
}

#[test]
fn native_catalog_lease_deferral_retirement_separate_checkpoints() {
    catalog_retirement_schedule(false, true);
}

#[test]
fn native_catalog_lease_deferral_retirement_rejects_false_deletion_witnesses() {
    let (mut hot, pending) = full_epoch_pending_fixture(1);
    let (files, _) = Files::with_maximum(&hot, 512 * 1024 * 1024);
    let prefix = files.bytes();
    hot.begin_changes().unwrap();
    let resolved_at = Timestamp::from_offset_datetime(
        *time(0).as_offset_datetime() + time::Duration::seconds(80),
    );
    let retire = crate::consensus::native::lifecycle_tests::maintenance(
        &hot,
        4,
        retention_deadline(resolved_at).unwrap(),
    );
    apply(
        &mut hot,
        &[command(3, &pending, resolved_at, false), retire],
    );
    assert!(!hot.business.receipts.contains_key(&pending.request_id()));
    let prepared = files.prepare(&mut hot, 19);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    let original = Wire::<Header>::read(&payload);
    let mut cursor = 0;
    for _ in 0..original.header.changed[0] {
        assert_eq!(original.body[cursor], 0);
        cursor += 1;
        let has_before = original.body[cursor];
        assert!(has_before <= 1);
        cursor += 1 + usize::from(has_before) * 32;
        let length =
            u32::from_le_bytes(original.body[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4 + length;
    }
    assert_eq!(original.body[cursor], 1);
    cursor += 1;
    assert_eq!(original.body[cursor], 1);
    cursor += 1 + 32;
    assert_eq!(
        &original.body[cursor..cursor + 56],
        &pending.request_id().to_bytes()
    );
    cursor += 56;
    assert_eq!(original.body[cursor], 0);
    cursor += 1;
    let length = u32::from_le_bytes(original.body[cursor..cursor + 4].try_into().unwrap());
    let range = Range {
        offset: (original.body_offset + cursor + 4) as u64,
        length,
    };
    let witness: (u64, Timestamp) =
        binary::decode(&original.body[cursor + 4..cursor + 4 + length as usize]).unwrap();
    assert_eq!(witness, (1, retention_deadline(resolved_at).unwrap()));
    for kind in 0..4 {
        let mut wire = Wire::<Header>::read(&payload);
        let mut witness = witness;
        match kind {
            0 => witness.1 = crate::fenced_transition::fenced_transition_v2_max_timestamp(),
            1 => {
                witness.1 = Timestamp::from_offset_datetime(
                    *witness.1.as_offset_datetime() + time::Duration::nanoseconds(1),
                )
            }
            2 => {
                witness.1 = retention_deadline(Timestamp::from_offset_datetime(
                    *resolved_at.as_offset_datetime() - time::Duration::seconds(2),
                ))
                .unwrap()
            }
            _ => witness.0 = 2,
        }
        wire.replace(range, &postcard::to_stdvec(&witness).unwrap());
        let bytes = wire.encode(MAGIC, prefix.clone());
        let mut identity = files.owner.current().identity();
        identity.checkpoint_epoch += 1;
        identity.operation_sequence = 19;
        let identity = rebound(&bytes, identity, &wire.header.after);
        let path = files._directory.path().join("false-retirement.opc");
        std::fs::write(&path, &bytes).unwrap();
        let error = match Catalog::open(
            &path,
            identity,
            files.maximum,
            CatalogScope {
                identity: hot.business.identity,
                members: &hot.business.members,
                roster_root: hot.business.roster_root.clone(),
            },
            wire.header.cut_binding,
            &|| Ok(()),
        ) {
            Ok(_) => panic!("false deletion witness admitted: {kind}"),
            Err(error) => error.to_string(),
        };
        let expected = match kind {
            0 | 1 => "removed an unexpired exact receipt",
            2 => "resolution time is outside its interval",
            _ => "deletion changes its exact binding",
        };
        assert!(error.contains(expected), "witness {kind}: {error}");
    }
}

#[test]
fn native_catalog_lease_deferral_refuses_the_profile_without_deletion_witnesses() {
    let (hot, _) = pending_fixture();
    let (files, _) = Files::new(&hot);
    let mut wire = Wire::<BaseHeader>::read(&files.bytes());
    wire.header
        .context
        .business
        .frontiers
        .activation
        .as_mut()
        .unwrap()
        .profile = hex::decode("ff9fb5a129821261d9ddd2cd1482aedd4e528642fc3f3474ce8580c86a6c3d4a")
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = wire.encode(base::MAGIC, Vec::new());
    let error = reject(
        &bytes,
        rebound(
            &bytes,
            files.owner.current().identity(),
            &wire.header.context,
        ),
        &hot,
        wire.header.cut_binding,
    );
    assert!(
        error.contains("activation or receipt count differs"),
        "{error}"
    );
}

#[test]
fn native_catalog_lease_deferral_expired_resolution_rejects_rebound_corruption() {
    let (mut hot, pending) = pending_fixture();
    let before_time = Timestamp::from_offset_datetime(
        *time(0).as_offset_datetime() + time::Duration::seconds(50),
    );
    apply(&mut hot, &[clock(3, before_time)]);
    let (mut files, _) = Files::new(&hot);
    let prefix = files.bytes();
    hot.begin_changes().unwrap();
    apply(
        &mut hot,
        &[
            command(4, &pending, expired(), false),
            command(5, &pending, retention_deadline(expired()).unwrap(), false),
        ],
    );
    let prepared = files.prepare(&mut hot, 19);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();
    prepared.append(&mut files.owner, &|| Ok(())).unwrap();
    let identity = files.owner.current().identity();
    let (_, catalog) = Catalog::open(
        &files.path,
        identity,
        MAXIMUM,
        CatalogScope {
            identity: hot.business.identity,
            members: &hot.business.members,
            roster_root: hot.business.roster_root.clone(),
        },
        prepared.header.cut_binding,
        &|| Ok(()),
    )
    .unwrap();
    let indexed = &catalog.rows.receipts[&pending.request_id()];
    for kind in 0..6 {
        let mut row = (**hot.business.receipts.get(&pending.request_id()).unwrap()).clone();
        match kind {
            0 => row.ordinal = 1,
            1 => row.payload_digest[0] ^= 1,
            2 => row.retained_until = retention_deadline(time(1)).unwrap(),
            3 => {
                row.retained_until = retention_deadline(Timestamp::from_offset_datetime(
                    *before_time.as_offset_datetime() - time::Duration::seconds(1),
                ))
                .unwrap()
            }
            4 => {
                row.retained_until = crate::fenced_transition::fenced_transition_v2_max_timestamp()
            }
            _ => {
                row.retained_until = Timestamp::from_offset_datetime(
                    *row.retained_until.as_offset_datetime() + time::Duration::nanoseconds(1),
                )
            }
        }
        let mut wire = Wire::<Header>::read(&payload);
        let mut encoded = Vec::new();
        cold::write_receipt(&mut encoded, pending.request_id(), &row, &|| Ok(())).unwrap();
        wire.replace(
            Range {
                offset: indexed.range.offset - prefix.len() as u64,
                length: indexed.range.length,
            },
            &encoded,
        );
        replace_hash(
            &mut wire.header.after.business.content[1],
            indexed.row.content,
            changes::fingerprint(1, &pending.request_id(), &row).unwrap(),
        );
        let bytes = wire.encode(MAGIC, prefix.clone());
        let error = reject(
            &bytes,
            rebound(&bytes, identity, &wire.header.after),
            &hot,
            wire.header.cut_binding,
        );
        assert!(
            error.contains("receipt") || error.contains("deferral"),
            "corruption {kind}: {error}"
        );
    }
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

#[test]
fn native_catalog_lease_deferral_expiry_survives_cold_reads_and_compaction() {
    let (mut hot, pending) = pending_fixture();
    let deadline = retention_deadline(time(2)).unwrap();
    let (mut files, catalog) = Files::new(&hot);
    let mut cold = catalog.into_storage(&|| Ok(())).unwrap();
    hot.begin_changes().unwrap();
    let clock = crate::consensus::native::changes::tests::clock(3, deadline);
    assert_eq!(
        apply(&mut hot, std::slice::from_ref(&clock)).responses,
        apply_cold_lifecycle(&mut cold, &[clock]).responses
    );
    // Status alone observes the original expiry before either response has
    // compacted, including a response available only from the cold catalog.
    for storage in [&hot, &cold] {
        assert!(storage.business.receipts[&pending.request_id()].retained());
        assert!(storage.business.receipts[&pending.request_id()].lease_deferred());
        assert_eq!(
            storage.business.status(&pending).unwrap(),
            FencedTransitionV2Status::Expired
        );
    }
    let sequence = hot.business.frontiers.sequence;
    let watch = hot.business.frontiers.watch_sequence;
    let entries = [
        command(4, &pending, deadline, false),
        crate::consensus::native::changes::tests::void_command(5, &pending, deadline, false),
    ];
    let actual = apply(&mut hot, &entries);
    let restored = apply_cold_lifecycle(&mut cold, &entries);
    assert_eq!(actual.responses, restored.responses);
    assert!(actual
        .responses
        .iter()
        .all(|response| response.result == Err(StoreError::FencedTransitionRequestExpired)));
    assert!(actual.notifications.is_empty() && restored.notifications.is_empty());
    let reopened = files.append(&mut hot, 19).into_storage(&|| Ok(())).unwrap();
    for storage in [&hot, &cold, &reopened] {
        assert_eq!(storage.business.frontiers.sequence, sequence);
        assert_eq!(storage.business.frontiers.watch_sequence, watch);
        assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
        assert_eq!(
            storage.business.status(&pending).unwrap(),
            FencedTransitionV2Status::Expired
        );
        let row = &storage.business.receipts[&pending.request_id()];
        assert_eq!(row.ordinal, 2);
        assert_eq!(row.retained_until, deadline);
        assert!(!row.retained());
        storage.validate_image().unwrap();
    }
}
