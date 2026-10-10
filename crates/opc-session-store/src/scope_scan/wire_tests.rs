use super::*;
use crate::scope_authority::tests::{admitted, successor};
use crate::scope_batch::tests::{claim, key, value};
use crate::scope_batch::{
    ScopeBatchCheckpoint, ScopeChildRecord, ScopeChildRevision, ScopeSealedValue,
    MAX_SCOPE_CHILD_VALUE_BYTES,
};
use crate::scope_scan::engine::{InventoryBudget, InventoryError, InventorySource};
use crate::scope_scan::headers::RawScopeRecord;
use crate::scope_scan::integrity::{ItemDisposition, ItemFailure, ItemKind};
use crate::scope_scan::progress::{InventoryTotals, PageLimits};
use crate::scope_scan::protocol::{PageProtocol, ReplyBody};
use crate::scope_storage::{self, ClaimOwner, ClaimRow, ScopeRow};
use crate::{SessionKey, StoredSessionRecord};
use opc_consensus::engine::{CommittedLeaderId, LogId};

struct Fixture {
    open: ScopeScanOpenRequest,
    reply: ScopeScanOpenReply,
    protocol: PageProtocol,
}
fn fixture(limits: PageLimits) -> Fixture {
    let before = admitted();
    let succession = successor(&before, 2);
    let state = before.transition(&succession).unwrap();
    let stamp = state.view.stamp().unwrap().clone();
    let node = SessionConsensusNodeId::new(3).unwrap();
    let cut = ScopeCut {
        namespace: stamp.namespace().clone(),
        authority_revision: stamp.revision(),
        batch_revision: 10,
        applied: LogId::new(
            CommittedLeaderId::new(7, SessionConsensusNodeId::new(2).unwrap()),
            91,
        ),
        epoch: 17,
        capture_id: [19; 16],
        serving_node: node,
    };
    let (protocol, initial_cursor) = PageProtocol::new(cut.clone(), &stamp, 100, limits).unwrap();
    let mut checkpoint = ScopeBatchCheckpoint::empty(stamp.scope().clone());
    checkpoint.revision = 10;
    checkpoint.birth_floor = 100;
    checkpoint.counters = std::array::from_fn(|n| n as u64 + 1);
    Fixture {
        open: ScopeScanOpenRequest::from_claims(stamp, succession, ScopeScanPageLimits(limits))
            .unwrap(),
        reply: ScopeScanOpenReply {
            cut,
            authority: state.view,
            checkpoint: checkpoint.into(),
            initial_cursor,
        },
        protocol,
    }
}
#[derive(Default)]
struct Source(Vec<StoredSessionRecord>);
impl Source {
    fn child(&mut self, fixture: &Fixture, n: u8, claims: &[u8], value: Option<ScopeSealedValue>) {
        self.0.push(
            ScopeRow::Child(ScopeChildRecord {
                namespace: fixture.reply.cut.namespace.clone(),
                key: key(n),
                revision: ScopeChildRevision::new(n as u64, 1).unwrap(),
                batch_revision: 2,
                value,
                claims: claims.iter().map(|n| claim(*n)).collect(),
            })
            .to_record()
            .unwrap(),
        );
    }
    fn claim(&mut self, fixture: &Fixture, n: u8, child: Option<u8>) {
        self.0.push(
            ScopeRow::Claim(ClaimRow {
                namespace: fixture.reply.cut.namespace.clone(),
                key: claim(n),
                revision: 2,
                owner: child.map(|n| ClaimOwner {
                    child: key(n),
                    birth: n as u64,
                }),
            })
            .to_record()
            .unwrap(),
        );
    }
}
impl InventorySource for Source {
    fn next_candidate(
        &mut self,
        namespace: &crate::scope_authority::ScopeNamespace,
        kind: ItemKind,
        after: Option<&crate::scope_scan::engine::InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<crate::scope_scan::engine::InventoryCandidate>, InventoryError> {
        budget.charge(128)?;
        Ok(self
            .0
            .iter()
            .map(|row| &row.key)
            .filter(|key| key.key_type.as_str() == crate::scope_scan::engine::kind_name(kind))
            .filter_map(|key| {
                crate::scope_scan::engine::native_candidate(namespace, key.clone()).ok()
            })
            .filter(|candidate| after.is_none_or(|after| candidate.position > *after))
            .min_by(|a, b| a.position.cmp(&b.position)))
    }
    fn read(
        &mut self,
        key: &SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError> {
        budget.charge(128)?;
        match self.0.iter().find(|r| &r.key == key) {
            Some(row) => {
                budget.charge(row.payload.len())?;
                Ok(RawScopeRecord::Present(row.clone()))
            }
            None => Ok(RawScopeRecord::Missing),
        }
    }
}
fn page_roundtrip(reply: Arc<ScopeScanReply>) -> Arc<ScopeScanReply> {
    let bytes = ScopeScanResponse::Page(Arc::clone(&reply))
        .encode_canonical()
        .unwrap();
    assert!(bytes.len() <= MAX_SCOPE_SCAN_REPLY_BYTES);
    let decoded = ScopeScanResponse::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded.encode_canonical().unwrap(), bytes);
    let ScopeScanResponse::Page(decoded) = decoded else {
        panic!("page tag changed")
    };
    assert_eq!(decoded.cut(), reply.cut());
    assert_eq!(decoded.status(), reply.status());
    assert_eq!(decoded.continuation(), reply.continuation());
    assert_eq!(decoded.items().len(), reply.items().len());
    for (actual, expected) in decoded.items().zip(reply.items()) {
        assert_eq!(actual.position(), expected.position());
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(actual.child(), expected.child());
        assert_eq!(actual.disposition(), expected.disposition());
        assert_eq!(actual.failures(), expected.failures());
        assert_eq!(
            actual.inventory_incomplete(),
            expected.inventory_incomplete()
        );
        assert_eq!(
            actual.claim().map(|c| (c.key(), c.revision(), c.owner())),
            expected.claim().map(|c| (c.key(), c.revision(), c.owner()))
        );
    }
    decoded
}
#[test]
fn scope_scan_wire_open_preserves_full_cut_headers_and_all_counter_floors() {
    let fixture = fixture(PageLimits::default());
    let expected = fixture.reply.clone();
    let bytes = ScopeScanResponse::Open(fixture.reply)
        .encode_canonical()
        .unwrap();
    let decoded = ScopeScanResponse::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded.encode_canonical().unwrap(), bytes);
    let ScopeScanResponse::Open(actual) = decoded else {
        panic!("open tag changed")
    };
    assert_eq!(actual.cut, expected.cut);
    assert_eq!(actual.authority, expected.authority);
    assert_eq!(actual.checkpoint.revision(), expected.checkpoint.revision());
    assert_eq!(
        actual.checkpoint.birth_floor(),
        expected.checkpoint.birth_floor()
    );
    assert_eq!(actual.checkpoint.counters(), expected.checkpoint.counters());
    assert_eq!(actual.initial_cursor, expected.initial_cursor);
}
#[test]
fn scope_scan_wire_requests_bind_method_boot_node_handle_cursor_and_lookup_kind() {
    let f = fixture(PageLimits::default());
    let view = ScopeScanViewToken::new(f.open.stamp(), &f.reply.cut).unwrap();
    let requests = [
        ScopeScanRequest::Open(Box::new(f.open.clone())),
        ScopeScanRequest::Page {
            view: view.clone(),
            cursor: f.reply.initial_cursor.clone(),
        },
        ScopeScanRequest::Lookup {
            view: view.clone(),
            key: ScopeScanLookupKey::Child(key(1)),
        },
        ScopeScanRequest::Classify {
            view: view.clone(),
            key: ScopeScanLookupKey::Claim(claim(7)),
        },
        ScopeScanRequest::Close(view),
    ];
    let mut encodings = std::collections::BTreeSet::new();
    for request in requests {
        let bytes = request.encode_canonical().unwrap();
        assert!(bytes.len() <= MAX_SCOPE_SCAN_REQUEST_BYTES);
        let decoded = ScopeScanRequest::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded.stamp(), request.stamp());
        assert_eq!(decoded.encode_canonical().unwrap(), bytes);
        assert!(encodings.insert(bytes));
    }
}
#[test]
fn scope_scan_wire_keeps_every_retry_and_final_error_typed() {
    use ScopeScanError::*;
    use ScopeScanRetryCause::*;
    let finals = [
        Unauthorized,
        HandoverRequired,
        StaleAuthority,
        Retired,
        ScopeScanError::Unavailable,
        RestartRequired,
        InvalidPageLimits,
        InvalidCursor,
        ScopeFault(ScopeScanHeaderFault::Authority),
        ScopeFault(ScopeScanHeaderFault::Checkpoint),
        ScopeFault(ScopeScanHeaderFault::Namespace),
        FreshInstallationRequired,
        DurableConsensusRequired,
        CapacityRefused,
    ];
    let retries = [
        ScopeScanRetryCause::Unavailable,
        IdleExpired,
        BackendRestarted,
        SnapshotInstalled,
        ConfigurationChanged,
        WorkBudgetExceeded,
        AdmissionPressure,
        ViewEnded,
    ];
    let mut encodings = std::collections::BTreeSet::new();
    for failure in finals
        .into_iter()
        .map(ScopeScanRequestFailure::Final)
        .chain(retries.into_iter().map(ScopeScanRequestFailure::Retryable))
    {
        let bytes = ScopeScanResponse::Failure(failure)
            .encode_canonical()
            .unwrap();
        let ScopeScanResponse::Failure(actual) =
            ScopeScanResponse::decode_canonical(&bytes).unwrap()
        else {
            panic!("error tag changed")
        };
        assert_eq!(actual, failure);
        assert!(encodings.insert(bytes));
    }
    assert_eq!(
        ScopeScanResponse::Closed.encode_canonical().unwrap(),
        vec![1, 4]
    );
}
#[test]
fn scope_scan_wire_actual_page_preserves_final_failures_tombstones_and_held_claims() {
    let mut f = fixture(PageLimits::default());
    let mut source = Source::default();
    source.child(&f, 1, &[7], Some(value(1)));
    source.child(&f, 2, &[], None);
    source.child(&f, 3, &[8], Some(value(3)));
    source.claim(&f, 7, Some(1));
    source.claim(&f, 9, None);
    source.claim(&f, 10, Some(4));
    let reply = f
        .protocol
        .page(&f.reply.initial_cursor, &mut source)
        .unwrap();
    let decoded = page_roundtrip(reply);
    assert_eq!(decoded.items().len(), 6);
    assert!(decoded
        .items()
        .any(|item| item.disposition() == ItemDisposition::ChildTombstone));
    assert!(decoded
        .items()
        .any(|item| item.disposition() == ItemDisposition::ClaimHeldUnknown));
    assert!(decoded.items().any(|item| !item.failures().is_empty()));
}
#[test]
fn scope_scan_wire_maximum_legal_child_fits_a_frame_chosen_before_page_cache() {
    let limits = ScopeScanPageLimits::new(1024, crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES)
        .unwrap()
        .for_transport(MAX_SCOPE_SCAN_REPLY_BYTES)
        .unwrap();
    let mut f = fixture(limits.0);
    let mut source = Source::default();
    let small = value(1);
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(small.envelope()).unwrap();
    let overhead = small.envelope().len() - envelope.ciphertext_and_tag.len();
    envelope
        .ciphertext_and_tag
        .resize(MAX_SCOPE_CHILD_VALUE_BYTES - overhead, 1);
    let large = ScopeSealedValue::new(envelope.encode().unwrap()).unwrap();
    source.child(
        &f,
        1,
        &[11, 12, 13, 14, 15, 16, 17, 18],
        Some(large.clone()),
    );
    source.child(&f, 2, &[], Some(large));
    for n in 11..=18 {
        source.claim(&f, n, Some(1));
    }
    let reply = f
        .protocol
        .page(&f.reply.initial_cursor, &mut source)
        .unwrap();
    assert_eq!(
        reply.items().len(),
        1,
        "one maximum child fits and the next advances to a later page"
    );
    let decoded = page_roundtrip(Arc::clone(&reply));
    assert_eq!(
        decoded
            .items()
            .next()
            .unwrap()
            .child()
            .unwrap()
            .value()
            .unwrap()
            .envelope()
            .len(),
        MAX_SCOPE_CHILD_VALUE_BYTES
    );
    assert!(
        Arc::ptr_eq(
            &reply,
            &f.protocol
                .page(&f.reply.initial_cursor, &mut source)
                .unwrap()
        ),
        "encoding never rebuilds the cached page"
    );
}
#[test]
fn scope_scan_wire_terminal_manifest_and_work_budget_remain_distinct() {
    let f = fixture(PageLimits::default());
    for body in [
        ReplyBody::Complete {
            totals: InventoryTotals {
                items: 1000,
                failed_items: 3,
                failures: 8,
                claims_incomplete: true,
            },
            manifest: Some(f.reply.initial_cursor.clone()),
        },
        ReplyBody::WorkBudget {
            next: f.reply.initial_cursor.clone(),
        },
    ] {
        let reply = Arc::new(ScopeScanReply {
            cut: f.reply.cut.clone(),
            body,
        });
        let decoded = page_roundtrip(Arc::clone(&reply));
        if let Some(summary) = decoded.summary() {
            assert_eq!(summary.examined_items(), 1000);
            assert_eq!(summary.failed_items(), 3);
            assert_eq!(summary.failures(), 8);
            assert_eq!(summary.incomplete_kinds(), &[ItemKind::Claim]);
            assert_eq!(summary.failure_manifest(), Some(&f.reply.initial_cursor));
        }
    }
}
#[test]
fn scope_scan_wire_point_result_keeps_missing_explicit_at_the_same_cut() {
    let f = fixture(PageLimits::default());
    let mut source = Source::default();
    let lookup = f
        .protocol
        .lookup(ScopeScanLookupKey::Claim(claim(8)), &mut source)
        .unwrap();
    let bytes = ScopeScanResponse::Lookup(lookup)
        .encode_canonical()
        .unwrap();
    let ScopeScanResponse::Lookup(actual) = ScopeScanResponse::decode_canonical(&bytes).unwrap()
    else {
        panic!("lookup tag changed")
    };
    assert_eq!(actual.cut(), &f.reply.cut);
    assert_eq!(actual.item().disposition(), ItemDisposition::MissingAtCut);
    assert_eq!(
        actual.item().failures(),
        &[ItemFailure::Missing {
            kind: ItemKind::Claim,
            key: [8; 32]
        }]
    );
}
#[test]
fn scope_scan_wire_rejects_truncated_trailing_and_oversized_envelopes() {
    let f = fixture(PageLimits::default());
    let request = ScopeScanRequest::Open(Box::new(f.open))
        .encode_canonical()
        .unwrap();
    for end in 0..request.len() {
        assert!(ScopeScanRequest::decode_canonical(&request[..end]).is_err());
    }
    let mut trailing = request;
    trailing.push(0);
    assert!(ScopeScanRequest::decode_canonical(&trailing).is_err());
    let response = ScopeScanResponse::Open(f.reply).encode_canonical().unwrap();
    for end in 0..response.len() {
        assert!(ScopeScanResponse::decode_canonical(&response[..end]).is_err());
    }
    let mut trailing = response;
    trailing.push(0);
    assert!(ScopeScanResponse::decode_canonical(&trailing).is_err());
    assert!(
        ScopeScanRequest::decode_canonical(&vec![0; MAX_SCOPE_SCAN_REQUEST_BYTES + 1]).is_err()
    );
    assert!(ScopeScanResponse::decode_canonical(&vec![0; MAX_SCOPE_SCAN_REPLY_BYTES + 1]).is_err());
}
#[test]
fn scope_scan_wire_transport_budget_rejects_too_small_frames_and_clamps_only_pages() {
    for rows in [1, 256, 1024] {
        let original =
            ScopeScanPageLimits::new(rows, crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES)
                .unwrap();
        let bounded = original.for_transport(MAX_SCOPE_SCAN_REPLY_BYTES).unwrap();
        assert_eq!(bounded.rows(), rows);
        assert!(bounded.payload_bytes() >= scope_storage::MAX_SCOPE_ROW_BYTES);
        assert!(bounded.payload_bytes() < original.payload_bytes());
        assert!(original
            .for_transport(scope_storage::MAX_SCOPE_ROW_BYTES)
            .is_err());
        assert!(original.for_transport(usize::MAX).is_err());
    }
}

#[test]
fn scope_scan_wire_shared_inventory_bodies_are_exact_stored_profile_bytes() {
    let f = fixture(PageLimits::default());
    let mut source = Source::default();
    source.child(&f, 1, &[7], Some(value(1)));
    source.claim(&f, 7, Some(1));
    for record in &source.0 {
        let row = ScopeRow::from_record(record).unwrap();
        assert_eq!(row.inventory_body().unwrap(), record.payload.as_bytes());
        assert_eq!(
            ScopeRow::from_inventory_body(record.payload.as_bytes()).unwrap(),
            row
        );
        let mut noncanonical = record.payload.as_bytes().to_vec();
        noncanonical.push(0);
        assert!(ScopeRow::from_inventory_body(&noncanonical).is_err());
    }
    let batch = ScopeRow::Batch(Box::new(ScopeBatchCheckpoint::empty(
        f.open.stamp().scope().clone(),
    )))
    .to_record()
    .unwrap();
    assert!(ScopeRow::from_inventory_body(batch.payload.as_bytes()).is_err());
}

#[test]
fn scope_scan_wire_rejects_counts_keys_flags_and_body_lengths_before_decoding_rows() {
    let mut f = fixture(PageLimits::default());
    let mut source = Source::default();
    source.child(&f, 1, &[], Some(value(1)));
    let page = f
        .protocol
        .page(&f.reply.initial_cursor, &mut source)
        .unwrap();
    let bytes = ScopeScanResponse::Page(page).encode_canonical().unwrap();
    let mut reader = Reader::new(&bytes, MAX_SCOPE_SCAN_REPLY_BYTES).unwrap();
    assert_eq!(reader.u8().unwrap(), 1);
    assert_eq!(reader.u8().unwrap(), 2);
    values::read_cut(&mut reader).unwrap();
    let phase = bytes.len() - reader.remaining();
    assert_eq!(bytes[phase], 0);
    let item = phase + 3;
    let key_len = usize::from(bytes[item + 2]);
    let failure_count = item + key_len + 5;
    assert_eq!(bytes[failure_count], 0);
    assert_eq!(bytes[failure_count + 1], 1);
    let mut mutations = Vec::new();
    let mut count = bytes.clone();
    count[phase + 1..phase + 3].copy_from_slice(&u16::MAX.to_be_bytes());
    mutations.push(count);
    for (at, value) in [
        (item, 2),
        (item + 1, 255),
        (item + 2, 255),
        (failure_count - 1, 2),
        (failure_count, 9),
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        mutations.push(bad);
    }
    let mut wrong_prefix = bytes.clone();
    wrong_prefix[item + 3] ^= 1;
    mutations.push(wrong_prefix);
    let mut body = bytes.clone();
    body[failure_count + 2..failure_count + 6].copy_from_slice(&u32::MAX.to_be_bytes());
    mutations.push(body);
    for bad in mutations {
        assert!(ScopeScanResponse::decode_canonical(&bad).is_err());
    }
}

#[test]
fn scope_scan_wire_unreadable_claim_key_keeps_inventory_incomplete() {
    let mut f = fixture(PageLimits::default());
    let mut source = Source::default();
    source.child(&f, 1, &[], Some(value(1)));
    source.claim(&f, 7, Some(1));
    let mut bad_key = scope_storage::namespace_prefix(&f.reply.cut.namespace)
        .unwrap()
        .to_vec();
    bad_key.push(7);
    source.0[1].key.stable_id = crate::StableId::new(bytes::Bytes::from(bad_key)).unwrap();
    let page = f
        .protocol
        .page(&f.reply.initial_cursor, &mut source)
        .unwrap();
    let decoded = page_roundtrip(page);
    let incomplete = decoded
        .items()
        .find(|item| item.inventory_incomplete())
        .unwrap();
    assert_eq!(incomplete.disposition(), ItemDisposition::ClaimHeldUnknown);
    let next = decoded.continuation().unwrap();
    let terminal = f.protocol.page(next, &mut source).unwrap();
    let terminal = page_roundtrip(terminal);
    assert_eq!(
        terminal.summary().unwrap().incomplete_kinds(),
        &[ItemKind::Claim]
    );
}

#[test]
fn scope_scan_wire_refuses_inconsistent_cut_checkpoint_and_terminal_claims() {
    let f = fixture(PageLimits::default());
    let mut bad = f.reply.clone();
    bad.checkpoint.revision += 1;
    assert!(ScopeScanResponse::Open(bad).encode_canonical().is_err());
    let mut bad = f.reply.clone();
    bad.checkpoint.counters[7] = u64::MAX;
    assert!(ScopeScanResponse::Open(bad).encode_canonical().is_err());
    let mut bad = f.reply.clone();
    bad.cut.capture_id = [0; 16];
    assert!(ScopeScanResponse::Open(bad).encode_canonical().is_err());
    let reply = ScopeScanReply {
        cut: f.reply.cut,
        body: ReplyBody::Complete {
            totals: InventoryTotals {
                items: 1,
                failed_items: 2,
                failures: 2,
                claims_incomplete: false,
            },
            manifest: None,
        },
    };
    assert!(ScopeScanResponse::Page(Arc::new(reply))
        .encode_canonical()
        .is_err());
}

#[test]
fn scope_scan_lookup_binds_kind_namespace_and_exact_key_even_for_absence() {
    let f = fixture(PageLimits::default());
    let mut source = Source::default();
    source.child(&f, 1, &[7], Some(value(1)));
    source.claim(&f, 7, Some(1));
    for (requested, wrong_kind, other) in [
        (
            ScopeScanLookupKey::Child(key(1)),
            ScopeScanLookupKey::Claim(claim(1)),
            ScopeScanLookupKey::Child(key(2)),
        ),
        (
            ScopeScanLookupKey::Child(key(2)),
            ScopeScanLookupKey::Claim(claim(2)),
            ScopeScanLookupKey::Child(key(1)),
        ),
        (
            ScopeScanLookupKey::Claim(claim(7)),
            ScopeScanLookupKey::Child(key(7)),
            ScopeScanLookupKey::Claim(claim(8)),
        ),
        (
            ScopeScanLookupKey::Claim(claim(8)),
            ScopeScanLookupKey::Child(key(8)),
            ScopeScanLookupKey::Claim(claim(7)),
        ),
    ] {
        let lookup = f.protocol.lookup(requested, &mut source).unwrap();
        let encoded = ScopeScanResponse::Lookup(lookup)
            .encode_canonical()
            .unwrap();
        let ScopeScanResponse::Lookup(mut observed) =
            ScopeScanResponse::decode_canonical(&encoded).unwrap()
        else {
            panic!("lookup response")
        };
        assert!(
            observed.matches_key(requested),
            "present and absent point observations retain the original request identity"
        );
        assert!(!observed.matches_key(wrong_kind));
        assert!(!observed.matches_key(other));
        observed.item.position.bytes[0] ^= 1;
        assert!(
            !observed.matches_key(requested),
            "a foreign namespace cannot borrow a same-suffix item"
        );
        observed.item.position.bytes[0] ^= 1;
        observed.item.position.bytes.push(1);
        assert!(
            !observed.matches_key(requested),
            "extra physical key bytes are not the requested point"
        );
    }
}

#[test]
fn scope_scan_wire_malformed_locators_round_trip_only_with_final_unknown_key_verdicts() {
    use crate::scope_scan::engine::InspectedItem;
    use crate::scope_scan::position::{InventoryPosition, LocatorKind};
    let f = fixture(PageLimits::default());
    let prefix = scope_storage::namespace_prefix(f.reply.cut.namespace()).unwrap();
    for kind in 0..=1 {
        let mut positions = vec![
            InventoryPosition {
                kind,
                locator: LocatorKind::NativeKnown,
                bytes: prefix.to_vec(),
            },
            InventoryPosition {
                kind,
                locator: LocatorKind::NativeUnknown,
                bytes: vec![0],
            },
            InventoryPosition {
                kind,
                locator: LocatorKind::NativeUnknown,
                bytes: vec![255; 64],
            },
        ];
        for known in [false, true] {
            for rowid in [i64::MIN, 0, i64::MAX] {
                positions.push(InventoryPosition::sqlite(kind, known, rowid));
            }
        }
        for position in positions {
            let item_kind = if kind == 0 {
                ItemKind::Child
            } else {
                ItemKind::Claim
            };
            let build = |incomplete: bool| {
                let mut inspection = crate::scope_scan::integrity::unreadable_key(item_kind);
                inspection.inventory_incomplete = incomplete;
                Arc::new(ScopeScanReply {
                    cut: f.reply.cut.clone(),
                    body: ReplyBody::Data {
                        items: vec![InspectedItem {
                            position: position.clone(),
                            child: None,
                            claim: None,
                            inspection,
                            stored_bytes: 0,
                        }],
                        next: f.reply.initial_cursor.clone(),
                    },
                })
            };
            let page = page_roundtrip(build(kind == 1));
            let item = page.items().next().unwrap();
            assert_eq!(item.position(), position.bytes);
            assert_eq!(item.inventory_incomplete(), kind == 1);
            assert_eq!(
                item.disposition(),
                if kind == 0 {
                    ItemDisposition::UnrestorableChild
                } else {
                    ItemDisposition::ClaimHeldUnknown
                }
            );
            assert!(
                ScopeScanResponse::Page(build(kind == 0))
                    .encode_canonical()
                    .is_err(),
                "a malformed claim key can never lose its incomplete-inventory restriction"
            );
        }
    }
}

#[test]
fn scope_scan_wire_accepts_a_full_page_of_small_unreadable_keys() {
    use crate::scope_scan::engine::InspectedItem;
    use crate::scope_scan::position::{InventoryPosition, LocatorKind};
    let f = fixture(PageLimits::default());
    let items = (0..=255)
        .map(|byte| InspectedItem {
            position: InventoryPosition {
                kind: 1,
                locator: LocatorKind::NativeUnknown,
                bytes: vec![byte],
            },
            child: None,
            claim: None,
            stored_bytes: 0,
            inspection: crate::scope_scan::integrity::unreadable_key(ItemKind::Claim),
        })
        .collect();
    let page = Arc::new(ScopeScanReply {
        cut: f.reply.cut.clone(),
        body: ReplyBody::Data {
            items,
            next: f.reply.initial_cursor.clone(),
        },
    });
    let decoded = page_roundtrip(page);
    assert_eq!(decoded.items().len(), 256);
    assert!(decoded.items().all(|item| item.inventory_incomplete()
        && item.disposition() == ItemDisposition::ClaimHeldUnknown));
}
