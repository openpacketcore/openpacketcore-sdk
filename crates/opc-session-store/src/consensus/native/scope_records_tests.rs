use super::*;
use allocation_counter::measure;
use changes::tests::{apply, clock, fixture, time};
use opc_types::{NetworkFunctionKind, TenantId};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::sync::atomic::{AtomicBool, Ordering};

fn key(kind: &str, bytes: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static("native-scope-capture"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: crate::SessionKeyType::other(kind).unwrap(),
        stable_id: bytes::Bytes::copy_from_slice(bytes).try_into().unwrap(),
    }
}

fn row(key: &SessionKey, payload: &[u8]) -> NativeKeyState {
    NativeKeyState {
        record: Some(StoredSessionRecord {
            key: key.clone(),
            generation: crate::Generation::new(1),
            owner: crate::OwnerId::new("native-scope-capture").unwrap(),
            fence: crate::FenceToken::new(1),
            state_class: crate::StateClass::AuthoritativeSession,
            state_type: crate::StateType::from_static("native-scope-capture"),
            expires_at: None,
            payload: crate::EncryptedSessionPayload::new(payload),
        }),
        ..NativeKeyState::default()
    }
}

#[test]
fn native_scope_capture_index_preserves_raw_malformed_rows_and_exact_bounds() {
    for kind in ["opc-scope-child", "opc-scope-claim"] {
        let prefix = key(kind, &[0x42; 32]);
        let mut short_bytes = vec![0x42; 32];
        short_bytes.push(1);
        let short = key(kind, &short_bytes);
        let mut full_bytes = vec![0x42; 32];
        full_bytes.extend([2; 32]);
        let full = key(kind, &full_bytes);
        let upper = key(kind, &[0x43; 32]);
        let keys = [
            key(kind, &[0x41; 32]),
            prefix.clone(),
            short,
            full,
            upper.clone(),
        ];
        let mut index = expiry::ExpiryIndex::default();
        for (number, key) in keys.iter().enumerate().rev() {
            let mut row = row(key, &[number as u8]);
            // Do not decode or repair bad bodies in the retained index. The
            // later per-item inspector must see the same key/body mismatch.
            row.record.as_mut().unwrap().key = self::key(kind, &[0x7f]);
            index.replace(key, None, Some(&row));
        }
        let captured = index.scope_records();
        let selected: Vec<_> = captured
            .range(Included(&prefix), Excluded(&upper))
            .map(|(key, _)| key.clone())
            .collect();
        assert_eq!(selected, keys[1..4]);
        for (number, key) in keys.iter().enumerate() {
            let value = captured.get(key).unwrap();
            assert_eq!(value.key, self::key(kind, &[0x7f]));
            assert_eq!(value.payload.as_bytes(), &[number as u8]);
        }
        assert_eq!(
            captured
                .range(Excluded(&keys[2]), Included(&keys[3]))
                .count(),
            1,
        );
        assert!(captured.get(&self::key(kind, &[0x40])).is_none());
    }
}

#[test]
fn native_scope_capture_index_isolates_complete_keys_and_reserved_kinds() {
    let first = key("opc-scope-child", &[1]);
    let mut tenant = first.clone();
    tenant.tenant = TenantId::from_static("other");
    let mut nf = first.clone();
    nf.nf_kind = NetworkFunctionKind::from_static("upf");
    let claim = key("opc-scope-claim", &[1]);
    let mut ordinary = first.clone();
    ordinary.key_type = crate::SessionKeyType::PduSession;
    let mut index = expiry::ExpiryIndex::default();
    for key in [&first, &tenant, &nf, &claim, &ordinary] {
        index.replace(key, None, Some(&row(key, key.tenant.as_str().as_bytes())));
    }
    let captured = index.scope_records();
    assert_eq!(captured.range(Unbounded, Unbounded).count(), 4);
    assert_eq!(captured.get(&first).unwrap().key, first);
    assert_eq!(captured.get(&tenant).unwrap().key, tenant);
    assert_eq!(captured.get(&nf).unwrap().key, nf);
    assert_eq!(captured.get(&claim).unwrap().key, claim);
    assert!(captured.get(&ordinary).is_none());
    assert_eq!(index.ordered_records(None).count(), 5);
    for kind in crate::scope_storage::RESERVED_KEY_TYPES {
        let key = key(kind, &[2]);
        index.replace(&key, None, Some(&row(&key, &[2])));
        assert!(index.scope_records().get(&key).is_some());
    }
}

#[test]
fn native_scope_capture_index_keeps_old_values_after_replacement_and_removal() {
    let a = key("opc-scope-child", &[1]);
    let b = key("opc-scope-claim", &[2]);
    let before = row(&a, &[1]);
    let after = row(&a, &[2]);
    let removed = row(&b, &[3]);
    let mut live = expiry::ExpiryIndex::default();
    live.replace(&a, None, Some(&before));
    live.replace(&b, None, Some(&removed));
    let captured = live.scope_records().clone();
    let original_cost = captured.retained_bytes().unwrap();
    live.replace(&a, Some(&before), Some(&after));
    live.replace(&b, Some(&removed), None);
    assert_eq!(captured.get(&a).unwrap().payload.as_bytes(), &[1]);
    assert_eq!(captured.get(&b).unwrap().payload.as_bytes(), &[3]);
    assert_eq!(captured.retained_bytes().unwrap(), original_cost);
    assert_eq!(
        live.scope_records().get(&a).unwrap().payload.as_bytes(),
        &[2]
    );
    assert!(live.scope_records().get(&b).is_none());
    assert!(live.scope_records().retained_bytes().unwrap() < original_cost);
    live.replace(&a, Some(&after), Some(&NativeKeyState::default()));
    assert_eq!(live.scope_records().range(Unbounded, Unbounded).count(), 0);
    assert_eq!(
        live.scope_records().retained_bytes().unwrap(),
        ScopeRecordIndex::default().retained_bytes().unwrap(),
    );
}

#[test]
fn native_scope_scan_replacement_moves_prefix_corruption_without_aliases() {
    use crate::scope_authority::{ScopeIncarnation, ScopeNamespace};
    use crate::scope_storage::{ClaimRow, ScopeRow};
    let namespace = ScopeNamespace::new(
        crate::scope_authority::tests::scope(),
        ScopeIncarnation::new(1).unwrap(),
    )
    .unwrap();
    let original = ScopeRow::Claim(ClaimRow {
        namespace: namespace.clone(),
        key: crate::scope_batch::tests::claim(1),
        revision: 1,
        owner: None,
    })
    .to_record()
    .unwrap();
    let mut changed = ScopeRow::Claim(ClaimRow {
        namespace: ScopeNamespace::new(
            namespace.scope().clone(),
            ScopeIncarnation::new(2).unwrap(),
        )
        .unwrap(),
        key: crate::scope_batch::tests::claim(1),
        revision: 1,
        owner: None,
    })
    .to_record()
    .unwrap();
    changed.key = original.key.clone();
    let mut index = ScopeRecordIndex::default();
    let counts = |index: &ScopeRecordIndex| {
        std::array::from_fn::<_, 3, _>(|phase| {
            index.scan_range(phase, Unbounded, Unbounded).count()
        })
    };
    index.replace(&original.key, Some(&original));
    let retained = index.clone();
    assert_eq!(counts(&index), [1, 0, 0]);
    index.replace(&original.key, Some(&changed));
    assert_eq!(counts(&index), [0, 0, 1]);
    assert_eq!(counts(&retained), [1, 0, 0]);
    index.replace(&original.key, Some(&original));
    assert_eq!(counts(&index), [1, 0, 0]);
    index.replace(&original.key, Some(&changed));
    index.replace(&original.key, None);
    assert_eq!(counts(&index), [0, 0, 0]);
}

#[test]
fn native_scope_capture_cost_counts_payload_capacity_and_replacement() {
    let key = key("opc-scope-child", &[1]);
    let mut small = row(&key, &[1]);
    let mut small_bytes = Vec::with_capacity(64);
    small_bytes.push(1);
    small.record.as_mut().unwrap().payload =
        crate::EncryptedSessionPayload::new_zeroizing(zeroize::Zeroizing::new(small_bytes));
    let mut large = small.clone();
    let mut large_bytes = Vec::with_capacity(1024 * 1024);
    large_bytes.push(1);
    large.record.as_mut().unwrap().payload =
        crate::EncryptedSessionPayload::new_zeroizing(zeroize::Zeroizing::new(large_bytes));
    let mut index = expiry::ExpiryIndex::default();
    index.replace(&key, None, Some(&small));
    let small_cost = index.scope_records().retained_bytes().unwrap();
    index.replace(&key, Some(&small), Some(&large));
    let large_cost = index.scope_records().retained_bytes().unwrap();
    assert!(large_cost >= small_cost + 1024 * 1024 - 64);
    index.replace(&key, Some(&large), Some(&small));
    assert_eq!(index.scope_records().retained_bytes().unwrap(), small_cost);
}

struct ExternalBytes {
    bytes: Vec<u8>,
    alive: Arc<AtomicBool>,
}

impl AsRef<[u8]> for ExternalBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ExternalBytes {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
    }
}

fn external_id(value: u8) -> (crate::StableId, Arc<AtomicBool>) {
    let alive = Arc::new(AtomicBool::new(true));
    let owner = ExternalBytes {
        bytes: vec![value; 1024 * 1024],
        alive: alive.clone(),
    };
    let bytes = bytes::Bytes::from_owner(owner).slice(64..72);
    (bytes.try_into().unwrap(), alive)
}

#[test]
fn native_scope_capture_normalizes_outer_and_body_identifier_owners() {
    let mut outer = key("opc-scope-child", &[1]);
    let (id, outer_alive) = external_id(1);
    outer.stable_id = id;
    let mut row = row(&outer, &[1]);
    let (id, body_alive) = external_id(2);
    row.record.as_mut().unwrap().key.stable_id = id;
    let mut index = expiry::ExpiryIndex::default();
    index.replace(&outer, None, Some(&row));
    let captured = index.scope_records().clone();
    drop((index, outer, row));
    assert!(
        !outer_alive.load(Ordering::SeqCst),
        "outer key pinned its external owner"
    );
    assert!(
        !body_alive.load(Ordering::SeqCst),
        "record key pinned its external owner"
    );
    let (outer, row) = captured.range(Unbounded, Unbounded).next().unwrap();
    assert_eq!(outer.stable_id.as_bytes(), &[1; 8]);
    assert_eq!(row.key.stable_id.as_bytes(), &[2; 8]);
    assert!(captured.retained_bytes().unwrap() < 128 * 1024);
}

#[test]
fn native_scope_capture_open_and_seek_do_not_materialize_the_inventory() {
    let mut index = expiry::ExpiryIndex::default();
    for number in 0u64..4096 {
        let key = key("opc-scope-child", &number.to_be_bytes());
        index.replace(&key, None, Some(&row(&key, &[1])));
    }
    let mut captured = None;
    let allocation = measure(|| captured = Some(index.scope_records().clone()));
    assert_eq!(
        allocation.count_total, 0,
        "capture must share the admitted root"
    );
    let captured = captured.unwrap();
    for number in [1u64, 4000] {
        let lower = key("opc-scope-child", &number.to_be_bytes());
        let upper = key("opc-scope-child", &4090u64.to_be_bytes());
        let mut found = None;
        let allocation = measure(|| {
            found = captured.range(Included(&lower), Excluded(&upper)).next();
        });
        assert_eq!(found.unwrap().0, &lower);
        assert!(
            allocation.bytes_total <= 16 * 1024,
            "range materialized rows: {allocation:?}"
        );
    }
}

#[test]
fn native_scope_index_reachability_accounts_for_retained_allocations() {
    let mut captured = None;
    let allocation = measure(|| {
        let mut index = expiry::ExpiryIndex::default();
        for number in 0u64..2048 {
            let key = key("opc-scope-child", &number.to_be_bytes());
            let row = row(&key, &[0x55; 257]);
            index.replace(&key, None, Some(&row));
        }
        captured = Some(index.scope_records().clone());
    });
    let captured = captured.unwrap();
    let reserved = captured.retained_bytes().unwrap();
    assert!(allocation.bytes_current > 0);
    assert!(
        reserved as u64 >= allocation.bytes_current as u64,
        "reservation {reserved} below retained allocation {allocation:?}"
    );
    let released = measure(|| drop(captured));
    assert_eq!(released.bytes_current, -allocation.bytes_current);
    assert!(reserved as u64 >= released.bytes_current.unsigned_abs());
}

#[test]
fn native_scope_capture_rejects_overflowed_reservation() {
    let key = key("opc-scope-child", &[1]);
    let row = row(&key, &[1]);
    let mut index = ScopeRecordIndex {
        record_bytes: Some(usize::MAX),
        ..ScopeRecordIndex::default()
    };
    index.replace(&key, row.record.as_ref());
    assert!(
        index.retained_bytes().is_err(),
        "overflow cannot wrap or saturate into an admitted cost"
    );
}

#[test]
fn native_scope_capture_does_not_pin_the_business_proof_or_ordinary_payload() {
    let (storage, request, outcome) = fixture();
    drop((request, outcome));
    let proof = Arc::downgrade(storage.business.proof.as_ref().unwrap());
    let receipt = Arc::downgrade(
        storage
            .business
            .receipts
            .values()
            .find_map(|row| row.response.as_ref())
            .unwrap(),
    );
    let payload = storage
        .business
        .keys
        .values()
        .next()
        .unwrap()
        .record
        .as_ref()
        .unwrap()
        .payload
        .log_row_reuse_test_weak_bytes();
    let capture = storage.capture_scope_records().unwrap();
    assert_eq!(capture.records().range(Unbounded, Unbounded).count(), 0);
    drop(storage);
    assert!(
        proof.upgrade().is_none(),
        "capture pinned unrelated admitted business history"
    );
    assert!(
        payload.upgrade().is_none(),
        "capture pinned an ordinary session payload"
    );
    assert!(
        receipt.upgrade().is_none(),
        "capture pinned receipt history"
    );
    assert!(capture.retained_bytes().unwrap() < 128 * 1024);
}

#[test]
fn native_scope_open_reservation_is_independent_of_retained_store_rows() {
    use crate::scope_scan::admission::{AdmissionQueue, CaptureCost, RetentionLimits};
    let (mut storage, _, _) = fixture();
    let empty = storage.scope_record_bytes().unwrap();
    for n in 0..131_072u64 {
        for (kind, payload) in [("opc-scope-child", 160usize), ("opc-scope-claim", 120)] {
            let mut stable = [0x5a; 64];
            stable[32..40].copy_from_slice(&n.to_be_bytes());
            let key = key(kind, &stable);
            Arc::get_mut(storage.business.proof.as_mut().unwrap())
                .unwrap()
                .expiry
                .replace(&key, None, Some(&row(&key, &vec![0x11; payload])));
        }
    }
    let populated = storage.scope_record_bytes().unwrap();
    assert_eq!(
        populated, empty,
        "unrelated retained rows became an open ceiling"
    );
    assert!(populated <= 2 * crate::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES + 64 * 1024);
    let mut queue: AdmissionQueue<u8, ()> = AdmissionQueue::new(RetentionLimits::default());
    assert!(queue
        .enqueue(1, CaptureCost::Native(populated as u64), ())
        .is_ok());
    let capture = storage.capture_scope_records().unwrap();
    assert_eq!(
        capture.records().range(Unbounded, Unbounded).count(),
        262_144
    );
}

#[test]
fn native_scope_capture_requires_an_admitted_matching_log_and_business_context() {
    let (storage, _, _) = fixture();
    let capture = storage.capture_scope_records().unwrap();
    let mut missing = storage.clone();
    missing.business.proof = None;
    assert!(missing.capture_scope_records().is_err());
    let mut identity = storage.clone();
    identity.business.identity = different_identity();
    assert!(identity.capture_scope_records().is_err());
    let mut membership = storage.clone();
    membership
        .business
        .members
        .insert(SessionConsensusNodeId::new(99).unwrap());
    assert!(membership.capture_scope_records().is_err());
    let mut advanced = storage.clone();
    apply(&mut advanced, &[clock(2, time(2))]);
    let mut mismatched = advanced;
    mismatched.log = storage.log.clone();
    assert!(mismatched.capture_scope_records().is_err());
    assert!(capture.require_current_authority(&mismatched).is_err());
    let mut missing_log = storage.clone();
    missing_log.log = log::NativeLog::default();
    assert!(missing_log.capture_scope_records().is_err());
}

#[test]
fn native_scope_capture_keeps_its_cut_but_checks_current_configuration() {
    let (mut storage, _, _) = fixture();
    let capture = storage.capture_scope_records().unwrap();
    let applied = capture.applied();
    apply(&mut storage, &[clock(2, time(2))]);
    capture.require_current_authority(&storage).unwrap();
    assert_eq!(capture.applied(), applied);
    assert_ne!(storage.capture_scope_records().unwrap().applied(), applied);
    let different = NativeStorage::empty_with_roster_root(
        different_identity(),
        storage.business.members.clone(),
        None,
    )
    .unwrap();
    assert!(capture.require_current_authority(&different).is_err());
    let different_members = NativeStorage::empty_with_roster_root(
        storage.business.identity,
        [10, 11, 12]
            .map(|id| SessionConsensusNodeId::new(id).unwrap())
            .into_iter()
            .collect(),
        None,
    )
    .unwrap();
    assert!(capture
        .require_current_authority(&different_members)
        .is_err());
}

fn different_identity() -> SessionConsensusIdentity {
    SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::new("different-native-capture").unwrap(),
        crate::consensus::SessionConsensusConfigurationId::from_bytes([9; 32]),
        crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn entry(
    storage: &NativeStorage,
    index: u64,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = clock(index, time(2));
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(match &intent {
        SessionMutationIntent::ScopeAuthority(operation) => *operation.request.request_id(),
        SessionMutationIntent::ScopeBatch(operation) => *operation.request.request_id(),
        _ => (0x2000 + u128::from(index)).to_be_bytes(),
    });
    command.intent = SessionMutationIntent::Authorized {
        origin: *storage.business.members.first().unwrap(),
        authority_identity: storage.business.identity,
        mutation: Box::new(intent),
    };
    entry
}

#[test]
fn native_scope_capture_tracks_atomic_publication_and_full_readmission() {
    use crate::scope_authority::{
        ScopeAuthorityCommand, ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeId,
        ScopeProfileActivation,
    };
    use crate::scope_batch::{ScopeBatchCommand, ScopeBatchRequest, ScopeChildMutation};
    use crate::scope_storage::ScopeRow;

    let (mut storage, _, _) = fixture();
    let empty_capture = measure(|| drop(storage.capture_scope_records().unwrap()));
    let identity = storage.business.identity;
    let scope = ScopeId::new(
        identity,
        TenantId::from_static("captured-scope"),
        NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let activation = entry(
        &storage,
        2,
        SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
            identity,
            fenced_transition_voter_set_digest(identity, &storage.business.members),
        ))),
    );
    apply(&mut storage, &[activation]);
    let initial = entry(
        &storage,
        3,
        SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
            request: ScopeAuthorityRequest::new(
                scope.clone(),
                [3; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: crate::scope_authority::tests::execution(1),
                },
            )
            .unwrap(),
        })),
    );
    let applied = apply(&mut storage, &[initial]);
    let Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))) = &applied.responses[0].result
    else {
        panic!("admitted scope")
    };
    let stamp = checkpoint.state().unwrap().view.stamp().cloned().unwrap();
    let create = entry(
        &storage,
        4,
        SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                &stamp,
                [1; 16],
                0,
                vec![crate::scope_batch::tests::create(1, &[1])],
                vec![],
            )
            .unwrap(),
        })),
    );
    let applied = apply(&mut storage, &[create]);
    let Ok(SessionMutationOutcome::ScopeBatch(Ok(outcome))) = &applied.responses[0].result else {
        panic!("created child")
    };
    let child_key =
        crate::scope_storage::child_key(stamp.namespace(), crate::scope_batch::tests::key(1))
            .unwrap();
    let claim_key =
        crate::scope_storage::claim_key(stamp.namespace(), crate::scope_batch::tests::claim(1))
            .unwrap();
    let mut captured = None;
    let populated_capture = measure(|| {
        captured = Some(storage.capture_scope_records().unwrap());
    });
    assert!(
        populated_capture.count_total <= empty_capture.count_total,
        "opening the same configuration must not allocate its inventory: empty={empty_capture:?}, populated={populated_capture:?}",
    );
    let captured = captured.unwrap();
    let old_child = captured
        .records()
        .get(&child_key)
        .unwrap()
        .payload
        .as_bytes()
        .to_vec();
    let old_claim = captured
        .records()
        .get(&claim_key)
        .unwrap()
        .payload
        .as_bytes()
        .to_vec();
    let old_batch = captured
        .records()
        .get(&crate::scope_storage::batch_key(&scope).unwrap())
        .unwrap()
        .payload
        .as_bytes()
        .to_vec();
    assert!(captured.records().get(&scope.key().unwrap()).is_some());
    let delete = entry(
        &storage,
        5,
        SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                &stamp,
                [2; 16],
                1,
                vec![ScopeChildMutation::Delete {
                    key: crate::scope_batch::tests::key(1),
                    expected: outcome.rows()[0],
                }],
                vec![],
            )
            .unwrap(),
        })),
    );
    let applied = apply(&mut storage, &[delete]);
    assert!(matches!(
        applied.responses[0].result,
        Ok(SessionMutationOutcome::ScopeBatch(Ok(_)))
    ));
    captured.require_current_authority(&storage).unwrap();
    assert_native_scope_source_inventory(&captured, stamp.namespace(), true);
    assert_eq!(
        captured
            .records()
            .get(&child_key)
            .unwrap()
            .payload
            .as_bytes(),
        old_child
    );
    assert_eq!(
        captured
            .records()
            .get(&claim_key)
            .unwrap()
            .payload
            .as_bytes(),
        old_claim
    );
    assert_eq!(
        captured
            .records()
            .get(&crate::scope_storage::batch_key(&scope).unwrap())
            .unwrap()
            .payload
            .as_bytes(),
        old_batch
    );
    for cold in [false, true] {
        if cold {
            storage.business.admit_business().unwrap();
            storage.log.admit(&storage.business).unwrap();
        }
        let current = storage.capture_scope_records().unwrap();
        assert_native_scope_source_inventory(&current, stamp.namespace(), false);
        let ScopeRow::Child(child) =
            ScopeRow::from_record(current.records().get(&child_key).unwrap()).unwrap()
        else {
            panic!("child row")
        };
        assert!(child.value.is_none(), "tombstones remain in the inventory");
        let ScopeRow::Claim(claim) =
            ScopeRow::from_record(current.records().get(&claim_key).unwrap()).unwrap()
        else {
            panic!("claim row")
        };
        assert!(
            claim.owner.is_none(),
            "released claims remain in the inventory"
        );
        assert_ne!(
            current
                .records()
                .get(&child_key)
                .unwrap()
                .payload
                .as_bytes(),
            old_child
        );
        assert_ne!(
            current
                .records()
                .get(&claim_key)
                .unwrap()
                .payload
                .as_bytes(),
            old_claim
        );
        assert_ne!(
            current
                .records()
                .get(&crate::scope_storage::batch_key(&scope).unwrap())
                .unwrap()
                .payload
                .as_bytes(),
            old_batch
        );
    }
}

fn assert_native_scope_source_inventory(
    capture: &ScopeRecordCapture,
    namespace: &crate::scope_authority::ScopeNamespace,
    live: bool,
) {
    use crate::scope_scan::{engine, integrity, progress, sources};
    let mut source = sources::NativeSource {
        capture,
        check: &|| Ok(()),
        work_exhausted: &|| false,
    };
    let floors = integrity::InventoryFloors {
        batch_revision: if live { 1 } else { 2 },
        birth: 1,
    };
    let first = engine::page(
        &mut source,
        namespace,
        floors,
        progress::PageLimits {
            rows: 1,
            ..progress::PageLimits::default()
        },
        None,
        progress::InventoryTotals::default(),
        false,
    )
    .unwrap();
    assert_eq!(
        first.items.len(),
        1,
        "native retained range emits the child"
    );
    assert_eq!(
        first.items[0].inspection.disposition,
        if live {
            integrity::ItemDisposition::LiveChild
        } else {
            integrity::ItemDisposition::ChildTombstone
        }
    );
    let progress::PageBoundary::Continue { after, totals } = first.boundary else {
        panic!("first bounded page advances");
    };
    let second = engine::page(
        &mut source,
        namespace,
        floors,
        progress::PageLimits::default(),
        Some(after),
        totals,
        false,
    )
    .unwrap();
    assert_eq!(second.items.len(), 1, "native keyset continues into claims");
    if live {
        assert!(matches!(
            second.items[0].inspection.disposition,
            integrity::ItemDisposition::ClaimHeld(_)
        ));
    } else {
        assert_eq!(
            second.items[0].inspection.disposition,
            integrity::ItemDisposition::ClaimReleased
        );
    }
    assert!(matches!(
        second.boundary,
        progress::PageBoundary::Complete {
            totals: progress::InventoryTotals {
                items: 2,
                failures: 0,
                ..
            },
            ..
        }
    ));
    let missing =
        crate::scope_storage::child_key(namespace, crate::scope_batch::tests::key(9)).unwrap();
    assert_eq!(
        engine::lookup(&mut source, namespace, floors, &missing)
            .unwrap()
            .inspection
            .disposition,
        integrity::ItemDisposition::MissingAtCut
    );
}

fn native_scope_scan_bad_physical_keys(damaged: impl Fn(&SessionKey) -> Vec<Vec<u8>>) {
    use crate::scope_authority::{ScopeIncarnation, ScopeNamespace};
    use crate::scope_batch::{
        tests::{claim, key as child_key, value},
        ScopeChildRecord, ScopeChildRevision,
    };
    use crate::scope_scan::{engine, integrity, progress, sources};
    use crate::scope_storage::{ClaimRow, ScopeRow};
    let namespace = ScopeNamespace::new(
        crate::scope_authority::tests::scope(),
        ScopeIncarnation::new(1).unwrap(),
    )
    .unwrap();
    let healthy = [
        ScopeRow::Child(ScopeChildRecord {
            namespace: namespace.clone(),
            key: child_key(1),
            revision: ScopeChildRevision::new(1, 1).unwrap(),
            batch_revision: 1,
            value: Some(value(1)),
            claims: vec![],
        })
        .to_record()
        .unwrap(),
        ScopeRow::Claim(ClaimRow {
            namespace: namespace.clone(),
            key: claim(1),
            revision: 1,
            owner: None,
        })
        .to_record()
        .unwrap(),
    ];
    // Inject physical damage in the actual native reserved-record index. Such
    // keys are legal StableIds; the scan cannot attribute them to a namespace.
    let mut index = ScopeRecordIndex::default();
    for record in &healthy {
        index.replace(&record.key, Some(record));
        for bytes in damaged(&record.key) {
            let mut malformed = record.clone();
            malformed.key.stable_id = bytes::Bytes::from(bytes).try_into().unwrap();
            index.replace(&malformed.key, Some(&malformed));
        }
        let mut other_tenant = record.clone();
        other_tenant.key.tenant = TenantId::from_static("outside-scan-tenant");
        other_tenant.key.stable_id = bytes::Bytes::from_static(&[2]).try_into().unwrap();
        index.replace(&other_tenant.key, Some(&other_tenant));
    }
    let (storage, _, _) = fixture();
    let mut capture = storage.capture_scope_records().unwrap();
    capture.records = index.clone();
    // Atomic replacement must not mutate the retained malformed-key inventory.
    for record in &healthy {
        let mut short = record.key.clone();
        short.stable_id = bytes::Bytes::from(damaged(&record.key).remove(0))
            .try_into()
            .unwrap();
        index.replace(&short, None);
    }
    let mut source = sources::NativeSource {
        capture: &capture,
        check: &|| Ok(()),
        work_exhausted: &|| false,
    };
    let mut after = None;
    let mut totals = progress::InventoryTotals::default();
    let mut items = Vec::new();
    let mut complete = false;
    for _ in 0..12 {
        let result = engine::page(
            &mut source,
            &namespace,
            integrity::InventoryFloors {
                batch_revision: 1,
                birth: 1,
            },
            progress::PageLimits {
                rows: 1,
                ..progress::PageLimits::default()
            },
            after,
            totals,
            false,
        )
        .unwrap();
        items.extend(result.items);
        match result.boundary {
            progress::PageBoundary::Continue {
                after: next,
                totals: next_totals,
            } => {
                after = Some(next);
                totals = next_totals;
            }
            progress::PageBoundary::Complete {
                totals: final_totals,
                ..
            } => {
                totals = final_totals;
                complete = true;
                break;
            }
            progress::PageBoundary::NoProgress => {
                panic!("malformed native keys cannot prevent progress")
            }
        }
    }
    assert!(complete);
    assert_eq!(
        totals.items, 6,
        "malformed physical keys must be included alongside healthy records"
    );
    assert_eq!(totals.failed_items, 4);
    assert_eq!(totals.failures, 4);
    assert!(totals.claims_incomplete);
    assert!(items
        .windows(2)
        .all(|pair| pair[0].position < pair[1].position));
    assert_eq!(
        items
            .iter()
            .filter(|item| item.inspection.disposition == integrity::ItemDisposition::LiveChild)
            .count(),
        1
    );
    assert_eq!(
        items
            .iter()
            .filter(|item| item.inspection.disposition == integrity::ItemDisposition::ClaimReleased)
            .count(),
        1
    );
    assert_eq!(
        items
            .iter()
            .filter(|item| item.inspection.disposition
                == integrity::ItemDisposition::ClaimHeldUnknown
                && item.inspection.inventory_incomplete)
            .count(),
        2
    );
}

#[test]
fn native_scope_scan_short_physical_keys_are_final_and_do_not_hide_healthy_rows() {
    native_scope_scan_bad_physical_keys(|_| vec![vec![2; 1], vec![2; 31]]);
}

#[test]
fn native_scope_scan_corrupt_key_prefix_is_explicit_and_does_not_hide_neighbors() {
    native_scope_scan_bad_physical_keys(|key| {
        [48, 64]
            .into_iter()
            .map(|length| {
                let mut bytes = key.stable_id.as_ref()[..length].to_vec();
                bytes[0] ^= 1;
                bytes
            })
            .collect()
    });
}
