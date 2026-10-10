use super::super::integrity::{IntegrityFault, ItemDisposition, ItemFailure};
use super::*;
use crate::scope_authority::{ScopeIncarnation, ScopeNamespace};
use crate::scope_batch::tests::{claim, key, value};
use crate::scope_batch::ScopeChildRevision;
use crate::scope_storage::{self, ClaimOwner, ClaimRow, ScopeRow};
use crate::StoredSessionRecord;

fn namespace() -> ScopeNamespace {
    ScopeNamespace::new(
        crate::scope_authority::tests::scope(),
        ScopeIncarnation::new(1).unwrap(),
    )
    .unwrap()
}
const FLOORS: InventoryFloors = InventoryFloors {
    batch_revision: 20,
    birth: 50,
};

#[derive(Clone, Default)]
struct Source {
    rows: Vec<(SessionKey, StoredSessionRecord)>,
    reads: usize,
    stop_at: Option<usize>,
    candidate_reads: usize,
    stop_candidate_at: Option<usize>,
    unavailable: bool,
}
impl Source {
    fn insert(&mut self, row: ScopeRow) {
        let record = row.to_record().unwrap();
        self.rows.push((record.key.clone(), record));
    }
    fn child(&mut self, n: u8, live: bool, claims: &[u8]) {
        self.insert(ScopeRow::Child(ScopeChildRecord {
            namespace: namespace(),
            key: key(n),
            revision: ScopeChildRevision::new(n as u64, 2).unwrap(),
            batch_revision: 7,
            value: live.then(|| value(n)),
            claims: claims.iter().map(|n| claim(*n)).collect(),
        }));
    }
    fn claim(&mut self, n: u8, owner: Option<u8>) {
        self.insert(ScopeRow::Claim(ClaimRow {
            namespace: namespace(),
            key: claim(n),
            revision: 7,
            owner: owner.map(|n| ClaimOwner {
                child: key(n),
                birth: n as u64,
            }),
        }));
    }
    fn record_mut(&mut self, child: bool, n: u8) -> &mut StoredSessionRecord {
        let expected = if child {
            scope_storage::child_key(&namespace(), key(n)).unwrap()
        } else {
            scope_storage::claim_key(&namespace(), claim(n)).unwrap()
        };
        &mut self
            .rows
            .iter_mut()
            .find(|(key, _)| *key == expected)
            .unwrap()
            .1
    }
}
impl InventorySource for Source {
    fn next_candidate(
        &mut self,
        ns: &crate::scope_authority::ScopeNamespace,
        kind: ItemKind,
        after: Option<&crate::scope_scan::engine::InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<crate::scope_scan::engine::InventoryCandidate>, InventoryError> {
        self.candidate_reads += 1;
        if self.stop_candidate_at == Some(self.candidate_reads) {
            return Err(InventoryError::WorkBudget);
        }
        budget.charge(128)?;
        Ok(self
            .rows
            .iter()
            .map(|(key, _)| key)
            .filter(|key| key.key_type.as_str() == crate::scope_scan::engine::kind_name(kind))
            .filter_map(|key| crate::scope_scan::engine::native_candidate(ns, key.clone()).ok())
            .filter(|candidate| after.is_none_or(|after| candidate.position > *after))
            .min_by(|a, b| a.position.cmp(&b.position)))
    }
    fn read(
        &mut self,
        key: &SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError> {
        self.reads += 1;
        if self.stop_at == Some(self.reads) {
            return Err(InventoryError::WorkBudget);
        }
        if self.unavailable {
            return Err(InventoryError::Interrupted);
        }
        let found = self
            .rows
            .iter()
            .find(|(physical, _)| physical == key)
            .map(|(_, row)| row);
        let Some(row) = found else {
            budget.charge(128)?;
            return Ok(RawScopeRecord::Missing);
        };
        if row.payload.len() > scope_storage::MAX_SCOPE_ROW_BYTES {
            budget.charge(512)?;
            return Ok(RawScopeRecord::Corrupt);
        }
        budget.charge(512 + row.payload.len())?;
        Ok(RawScopeRecord::Present(row.clone()))
    }
}
fn collect(
    source: &mut Source,
    rows: usize,
    failures_only: bool,
) -> (Vec<InspectedItem>, InventoryTotals) {
    let mut after = None;
    let mut totals = InventoryTotals::default();
    let mut items = Vec::new();
    for _ in 0..100 {
        let result = page(
            source,
            &namespace(),
            FLOORS,
            PageLimits {
                rows,
                ..PageLimits::default()
            },
            after.clone(),
            totals,
            failures_only,
        )
        .unwrap();
        items.extend(result.items);
        match result.boundary {
            PageBoundary::Continue {
                after: next,
                totals: next_totals,
            } => {
                assert!(after.as_ref().is_none_or(|after| &next > after));
                after = Some(next);
                totals = next_totals;
            }
            PageBoundary::Complete { totals, .. } => return (items, totals),
            PageBoundary::NoProgress => panic!("bounded canonical fixture must make progress"),
        }
    }
    panic!("scan did not finish");
}

#[test]
fn scope_scan_engine_orders_children_then_claims_and_keeps_tombstones_and_releases() {
    let mut source = Source::default();
    source.claim(12, None);
    source.child(2, false, &[]);
    source.claim(11, Some(1));
    source.child(1, true, &[11]);
    let (items, totals) = collect(&mut source, 1, false);
    assert_eq!(items.len(), 4);
    assert_eq!(
        items
            .iter()
            .map(|item| item.position.kind)
            .collect::<Vec<_>>(),
        vec![0, 0, 1, 1]
    );
    assert_eq!(items[0].inspection.disposition, ItemDisposition::LiveChild);
    assert_eq!(
        items[1].inspection.disposition,
        ItemDisposition::ChildTombstone
    );
    assert!(matches!(
        items[2].inspection.disposition,
        ItemDisposition::ClaimHeld(_)
    ));
    assert_eq!(
        items[3].inspection.disposition,
        ItemDisposition::ClaimReleased
    );
    assert_eq!(items[0].child.as_ref().unwrap().value(), Some(&value(1)));
    assert_eq!(items[1].child.as_ref().unwrap().revision().birth(), 2);
    assert_eq!(items[3].claim.as_ref().unwrap().revision, 7);
    assert_eq!(
        totals,
        InventoryTotals {
            items: 4,
            ..InventoryTotals::default()
        }
    );
}

#[test]
fn scope_scan_engine_filters_other_namespaces_with_shared_codec() {
    let mut source = Source::default();
    source.child(1, true, &[]);
    let other = ScopeNamespace::new(
        crate::scope_authority::tests::scope(),
        ScopeIncarnation::new(2).unwrap(),
    )
    .unwrap();
    source.insert(ScopeRow::Claim(ClaimRow {
        namespace: other,
        key: claim(1),
        revision: 1,
        owner: None,
    }));
    let (items, totals) = collect(&mut source, 256, false);
    assert_eq!(items.len(), 1);
    assert_eq!(totals.items, 1);
    assert_eq!(
        items[0].position.bytes,
        scope_storage::child_key(&namespace(), key(1))
            .unwrap()
            .stable_id
            .as_ref()
    );
}

#[test]
fn scope_scan_engine_corrupt_child_keeps_healthy_neighbors_and_its_claim_held_unknown() {
    let mut source = Source::default();
    source.child(1, true, &[]);
    source.child(2, true, &[12]);
    source.child(3, true, &[]);
    source.claim(12, Some(2));
    source.record_mut(true, 2).payload = crate::EncryptedSessionPayload::new(b"broken child body");
    let (items, totals) = collect(&mut source, 2, false);
    assert_eq!(items.len(), 4);
    assert_eq!(items[0].inspection.disposition, ItemDisposition::LiveChild);
    assert_eq!(
        items[1].inspection.disposition,
        ItemDisposition::UnrestorableChild
    );
    assert_eq!(items[2].inspection.disposition, ItemDisposition::LiveChild);
    assert_eq!(
        items[3].inspection.disposition,
        ItemDisposition::ClaimHeldUnknown
    );
    assert_eq!(totals.failed_items, 2);
    assert_eq!(totals.failures, 2);
}

#[test]
fn scope_scan_engine_missing_references_are_final_and_do_not_release_claims() {
    let mut source = Source::default();
    source.child(1, true, &[11]);
    source.claim(12, Some(2));
    source.claim(13, None);
    let (items, totals) = collect(&mut source, 2, false);
    assert_eq!(items.len(), 3);
    assert_eq!(
        items[0].inspection.failures,
        vec![ItemFailure::Missing {
            kind: ItemKind::Claim,
            key: [11; 32]
        }]
    );
    assert_eq!(
        items[1].inspection.failures,
        vec![ItemFailure::Missing {
            kind: ItemKind::Child,
            key: [2; 32]
        }]
    );
    assert_eq!(
        items[1].inspection.disposition,
        ItemDisposition::ClaimHeldUnknown
    );
    assert_eq!(
        items[2].inspection.disposition,
        ItemDisposition::ClaimReleased
    );
    assert_eq!(totals.failed_items, 2);
}

#[test]
fn scope_scan_engine_unreadable_claim_key_marks_inventory_incomplete_and_advances() {
    let mut source = Source::default();
    source.claim(11, None);
    source.claim(12, None);
    let (physical, _) = &mut source.rows[0];
    physical.stable_id = crate::StableId::new(bytes::Bytes::copy_from_slice(
        &physical.stable_id.as_ref()[..48],
    ))
    .unwrap();
    let (items, totals) = collect(&mut source, 1, false);
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[1].inspection.disposition,
        ItemDisposition::ClaimHeldUnknown
    );
    assert!(items[1].inspection.inventory_incomplete);
    assert_eq!(items[1].position.bytes.len(), 48);
    assert_eq!(
        items[0].inspection.disposition,
        ItemDisposition::ClaimReleased
    );
    assert!(totals.claims_incomplete);
}

#[test]
fn scope_scan_engine_rejects_physical_body_key_mismatch_as_final_item() {
    let mut source = Source::default();
    source.child(1, true, &[]);
    source.child(2, true, &[]);
    let valid = source.rows[1].1.clone();
    source.rows[0].1 = valid;
    let (items, totals) = collect(&mut source, 256, false);
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0].inspection.disposition,
        ItemDisposition::UnrestorableChild
    );
    assert_eq!(items[1].inspection.disposition, ItemDisposition::LiveChild);
    assert_eq!(totals.failed_items, 1);
}

#[test]
fn scope_scan_engine_legacy_bodies_are_final_items_and_do_not_hide_neighbors() {
    for magic in [b"OPSC\x02", b"OPSC\x03"] {
        let mut source = Source::default();
        source.child(1, true, &[]);
        source.child(2, true, &[]);
        source.claim(11, None);
        source.claim(12, None);
        for (child, n) in [(true, 1), (false, 11)] {
            let row = source.record_mut(child, n);
            let mut payload = row.payload.as_bytes().to_vec();
            payload[..magic.len()].copy_from_slice(magic);
            row.payload = crate::EncryptedSessionPayload::new(payload);
        }
        let (items, totals) = collect(&mut source, 1, false);
        assert_eq!(items.len(), 4);
        assert_eq!(totals.failed_items, 2);
        for index in [0, 2] {
            assert!(matches!(
                items[index].inspection.failures.as_slice(),
                [ItemFailure::Corrupt {
                    reason: IntegrityFault::Encoding,
                    ..
                }]
            ));
        }
        assert_eq!(items[1].inspection.disposition, ItemDisposition::LiveChild);
        assert_eq!(
            items[3].inspection.disposition,
            ItemDisposition::ClaimReleased
        );
    }
}

#[test]
fn scope_scan_engine_rejects_future_revision_and_birth_against_captured_checkpoint() {
    let mut source = Source::default();
    source.child(51, true, &[]);
    source.insert(ScopeRow::Claim(ClaimRow {
        namespace: namespace(),
        key: claim(12),
        revision: 21,
        owner: None,
    }));
    let (items, totals) = collect(&mut source, 256, false);
    assert_eq!(items.len(), 2);
    assert_eq!(totals.failed_items, 2);
    assert!(items.iter().all(|item| matches!(
        item.inspection.failures.as_slice(),
        [ItemFailure::Corrupt {
            reason: IntegrityFault::Header,
            ..
        }]
    )));
}

#[test]
fn scope_scan_engine_partial_crosscheck_work_never_advances_or_emits_unfinished_item() {
    let mut source = Source::default();
    source.child(1, true, &[]);
    source.child(2, true, &[12]);
    source.claim(12, Some(2));
    source.stop_at = Some(3);
    let result = page(
        &mut source,
        &namespace(),
        FLOORS,
        PageLimits::default(),
        None,
        InventoryTotals::default(),
        false,
    )
    .unwrap();
    assert_eq!(result.items.len(), 1);
    let PageBoundary::Continue { after, totals } = result.boundary else {
        panic!("completed prefix must advance");
    };
    assert_eq!(
        after.bytes,
        scope_storage::child_key(&namespace(), key(1))
            .unwrap()
            .stable_id
            .as_ref()
    );
    assert_eq!(totals.items, 1);
    assert_eq!(totals.failures, 0);
    source.stop_at = None;
    let result = page(
        &mut source,
        &namespace(),
        FLOORS,
        PageLimits::default(),
        Some(after),
        totals,
        false,
    )
    .unwrap();
    assert_eq!(result.items.len(), 2);
    assert!(matches!(
        result.boundary,
        PageBoundary::Complete {
            totals: InventoryTotals {
                items: 3,
                failures: 0,
                ..
            },
            ..
        }
    ));
}

#[test]
fn scope_scan_engine_no_progress_is_retryable_and_unavailability_is_not_empty_completion() {
    let mut source = Source::default();
    source.child(1, true, &[]);
    source.stop_at = Some(1);
    let result = page(
        &mut source,
        &namespace(),
        FLOORS,
        PageLimits::default(),
        None,
        InventoryTotals::default(),
        false,
    )
    .unwrap();
    assert!(result.items.is_empty());
    assert_eq!(result.boundary, PageBoundary::NoProgress);
    source.stop_at = None;
    source.unavailable = true;
    assert!(matches!(
        page(
            &mut source,
            &namespace(),
            FLOORS,
            PageLimits::default(),
            None,
            InventoryTotals::default(),
            false
        ),
        Err(InventoryError::Interrupted)
    ));
}

#[test]
fn scope_scan_engine_candidate_budget_is_not_inventory_completion() {
    for stop_candidate_at in [1, 2] {
        let mut source = Source {
            stop_candidate_at: Some(stop_candidate_at),
            ..Source::default()
        };
        source.child(1, true, &[]);
        source.child(2, true, &[]);
        let result = page(
            &mut source,
            &namespace(),
            FLOORS,
            PageLimits::default(),
            None,
            InventoryTotals::default(),
            false,
        )
        .unwrap();
        assert_eq!(result.items.len(), stop_candidate_at - 1);
        let (after, totals) = match result.boundary {
            PageBoundary::NoProgress if stop_candidate_at == 1 => {
                (None, InventoryTotals::default())
            }
            PageBoundary::Continue { after, totals } if stop_candidate_at == 2 => {
                assert_eq!(totals.items, 1);
                assert_eq!(after, result.items[0].position);
                (Some(after), totals)
            }
            boundary => {
                panic!("candidate work exhaustion must preserve continuation: {boundary:?}")
            }
        };
        let resumed = page(
            &mut source,
            &namespace(),
            FLOORS,
            PageLimits::default(),
            after,
            totals,
            false,
        )
        .unwrap();
        assert_eq!(resumed.items.len(), 3 - stop_candidate_at);
        assert!(matches!(
            resumed.boundary,
            PageBoundary::Complete {
                totals: InventoryTotals { items: 2, .. },
                ..
            }
        ));
    }
}

#[test]
fn scope_scan_engine_failure_manifest_rescans_same_order_without_accumulating_successes() {
    let mut source = Source::default();
    for n in 1..=20 {
        source.child(n, true, if n % 3 == 0 { &[22] } else { &[] });
    }
    let (inventory, totals) = collect(&mut source, 2, false);
    let failed: Vec<_> = inventory
        .iter()
        .filter(|item| !item.inspection.failures.is_empty())
        .map(|item| item.position.clone())
        .collect();
    let (manifest, manifest_totals) = collect(&mut source, 1, true);
    assert_eq!(
        manifest
            .iter()
            .map(|item| item.position.clone())
            .collect::<Vec<_>>(),
        failed
    );
    assert_eq!(manifest.len(), 6);
    assert_eq!(manifest_totals, totals);
}

#[test]
fn scope_scan_engine_lookup_distinguishes_missing_tombstone_and_released_at_cut() {
    let mut source = Source::default();
    source.child(1, false, &[]);
    source.claim(12, None);
    for (key, expected) in [
        (
            scope_storage::child_key(&namespace(), key(1)).unwrap(),
            ItemDisposition::ChildTombstone,
        ),
        (
            scope_storage::claim_key(&namespace(), claim(12)).unwrap(),
            ItemDisposition::ClaimReleased,
        ),
        (
            scope_storage::child_key(&namespace(), key(2)).unwrap(),
            ItemDisposition::MissingAtCut,
        ),
        (
            scope_storage::claim_key(&namespace(), claim(13)).unwrap(),
            ItemDisposition::MissingAtCut,
        ),
    ] {
        let item = lookup(&mut source, &namespace(), FLOORS, &key).unwrap();
        assert_eq!(item.inspection.disposition, expected);
    }
}

#[test]
fn scope_scan_engine_rejects_other_namespace_continuation_before_reading() {
    let mut source = Source::default();
    source.child(1, true, &[]);
    let after = InventoryPosition {
        kind: 0,
        locator: LocatorKind::Canonical,
        bytes: vec![0; 64],
    };
    assert!(matches!(
        page(
            &mut source,
            &namespace(),
            FLOORS,
            PageLimits::default(),
            Some(after),
            InventoryTotals::default(),
            false
        ),
        Err(InventoryError::InvalidPosition)
    ));
    assert_eq!(source.reads, 0);
}

#[test]
fn scope_scan_engine_maximum_legal_child_and_all_claims_fit_and_byte_caps_split_pages() {
    use crate::scope_batch::{ScopeSealedValue, MAX_SCOPE_CHILD_VALUE_BYTES};
    let small = value(1);
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(small.envelope()).unwrap();
    let overhead = small.envelope().len() - envelope.ciphertext_and_tag.len();
    envelope
        .ciphertext_and_tag
        .resize(MAX_SCOPE_CHILD_VALUE_BYTES - overhead, 1);
    let large = ScopeSealedValue::new(envelope.encode().unwrap()).unwrap();
    let mut source = Source::default();
    for n in 1..=5 {
        source.insert(ScopeRow::Child(ScopeChildRecord {
            namespace: namespace(),
            key: key(n),
            revision: ScopeChildRevision::new(n as u64, 1).unwrap(),
            batch_revision: 7,
            value: Some(large.clone()),
            claims: if n == 1 {
                (11..=18).map(claim).collect()
            } else {
                vec![]
            },
        }));
    }
    for n in 11..=18 {
        source.claim(n, Some(1));
    }
    let first = page(
        &mut source,
        &namespace(),
        FLOORS,
        PageLimits::default(),
        None,
        InventoryTotals::default(),
        false,
    )
    .unwrap();
    assert!(
        !first.items.is_empty(),
        "a maximum legal child with eight cross-checks fits"
    );
    assert!(
        first.items.len() < 5,
        "payload and retained-byte caps split the page"
    );
    assert!(first
        .items
        .iter()
        .all(|item| item.inspection.disposition == ItemDisposition::LiveChild));
    assert!(
        first
            .items
            .iter()
            .map(|item| item.stored_bytes)
            .sum::<usize>()
            <= PageLimits::default().payload_bytes
    );
    let (items, totals) = collect(&mut source, 256, false);
    assert_eq!(items.len(), 13);
    assert_eq!(totals.items, 13);
    assert_eq!(totals.failures, 0);
}
