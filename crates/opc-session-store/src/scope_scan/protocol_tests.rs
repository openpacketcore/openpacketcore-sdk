use super::*;
use crate::scope_authority::tests::{admitted, successor};
use crate::scope_batch::tests::{claim, key, value};
use crate::scope_batch::{ScopeChildRecord, ScopeChildRevision};
use crate::scope_scan::{
    engine::{InventoryBudget, InventoryError},
    headers::RawScopeRecord,
    integrity::{ItemDisposition, ItemKind},
};
use crate::scope_storage::{self, ClaimOwner, ClaimRow, ScopeRow};
use crate::{SessionKey, StoredSessionRecord};
use opc_consensus::engine::{CommittedLeaderId, LogId};

#[derive(Default)]
struct Source {
    rows: Vec<StoredSessionRecord>,
    calls: usize,
    stop: bool,
    unavailable: bool,
}
impl Source {
    fn child(&mut self, ns: &crate::scope_authority::ScopeNamespace, n: u8, claims: &[u8]) {
        self.rows.push(
            ScopeRow::Child(ScopeChildRecord {
                namespace: ns.clone(),
                key: key(n),
                revision: ScopeChildRevision::new(n as u64, 1).unwrap(),
                batch_revision: 1,
                value: Some(value(n)),
                claims: claims.iter().map(|n| claim(*n)).collect(),
            })
            .to_record()
            .unwrap(),
        );
    }
    fn claim(&mut self, ns: &crate::scope_authority::ScopeNamespace, n: u8, child: u8) {
        self.rows.push(
            ScopeRow::Claim(ClaimRow {
                namespace: ns.clone(),
                key: claim(n),
                revision: 1,
                owner: Some(ClaimOwner {
                    child: key(child),
                    birth: child as u64,
                }),
            })
            .to_record()
            .unwrap(),
        );
    }
    fn check(&mut self, budget: &mut InventoryBudget) -> Result<(), InventoryError> {
        self.calls += 1;
        if self.unavailable {
            return Err(InventoryError::Interrupted);
        }
        if self.stop {
            return Err(InventoryError::WorkBudget);
        }
        budget.charge(512)
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
        self.check(budget)?;
        Ok(self
            .rows
            .iter()
            .map(|row| &row.key)
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
        self.check(budget)?;
        let row = self.rows.iter().find(|row| row.key == *key);
        if let Some(row) = row {
            budget.charge(row.payload.len())?;
        }
        Ok(match row {
            Some(row) if row.payload.len() <= super::super::engine::maximum_record_bytes(key) => {
                RawScopeRecord::Present(row.clone())
            }
            Some(_) => RawScopeRecord::Corrupt,
            None => RawScopeRecord::Missing,
        })
    }
}
fn fixture(rows: usize) -> (PageProtocol, ScopeScanCursor, Source) {
    let first = admitted();
    let after = first.transition(&successor(&first, 2)).unwrap();
    let stamp = after.view.stamp().unwrap().clone();
    let node = crate::SessionConsensusNodeId::new(1).unwrap();
    let cut = ScopeCut {
        namespace: stamp.namespace().clone(),
        authority_revision: stamp.revision(),
        batch_revision: 10,
        applied: LogId::new(CommittedLeaderId::new(2, node), 8),
        epoch: 1,
        capture_id: [9; 16],
        serving_node: node,
    };
    let (protocol, cursor) = PageProtocol::new(
        cut,
        &stamp,
        100,
        PageLimits {
            rows,
            ..PageLimits::default()
        },
    )
    .unwrap();
    (protocol, cursor, Source::default())
}
fn next(reply: &ScopeScanReply) -> ScopeScanCursor {
    match &reply.body {
        ReplyBody::Data { next, .. } | ReplyBody::WorkBudget { next } => next.clone(),
        ReplyBody::Complete {
            manifest: Some(next),
            ..
        } => next.clone(),
        _ => panic!("reply needs a successor"),
    }
}
fn complete(reply: &ScopeScanReply) -> InventoryTotals {
    match &reply.body {
        ReplyBody::Complete { totals, .. } => *totals,
        _ => panic!("terminal summary required"),
    }
}
#[test]
fn scope_scan_protocol_empty_inventory_is_explicit_small_replayable_completion() {
    let (mut protocol, cursor, mut source) = fixture(256);
    let reply = protocol.page(&cursor, &mut source).unwrap();
    assert_eq!(complete(&reply), InventoryTotals::default());
    let calls = source.calls;
    assert!(Arc::ptr_eq(
        &reply,
        &protocol.page(&cursor, &mut source).unwrap()
    ));
    assert_eq!(source.calls, calls);
}
#[test]
fn scope_scan_protocol_data_reply_replays_without_reading_and_acknowledges_only_successor() {
    let (mut protocol, cursor, mut source) = fixture(1);
    source.child(&protocol.cut.namespace, 1, &[]);
    source.child(&protocol.cut.namespace, 2, &[]);
    let first = protocol.page(&cursor, &mut source).unwrap();
    let calls = source.calls;
    assert!(Arc::ptr_eq(
        &first,
        &protocol.page(&cursor, &mut source).unwrap()
    ));
    assert_eq!(source.calls, calls);
    let weak = Arc::downgrade(&first);
    let second_cursor = next(&first);
    drop(first);
    let second = protocol.page(&second_cursor, &mut source).unwrap();
    assert!(weak.upgrade().is_none());
    assert!(matches!(
        protocol.page(&cursor, &mut source),
        Err(ScopeScanError::InvalidCursor)
    ));
    let ReplyBody::Data { items, .. } = &second.body else {
        panic!("second data page")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].child.as_ref().unwrap().key(), key(2));
    let terminal_cursor = next(&second);
    let terminal = protocol.page(&terminal_cursor, &mut source).unwrap();
    assert_eq!(complete(&terminal).items, 2);
    assert!(Arc::ptr_eq(
        &terminal,
        &protocol.page(&terminal_cursor, &mut source).unwrap()
    ));
}
#[test]
fn scope_scan_protocol_last_payload_never_becomes_retained_terminal_history() {
    let (mut protocol, cursor, mut source) = fixture(256);
    source.child(&protocol.cut.namespace, 1, &[]);
    let data = protocol.page(&cursor, &mut source).unwrap();
    let weak = Arc::downgrade(&data);
    let finalize = next(&data);
    assert!(matches!(&data.body,ReplyBody::Data{items,..} if items.len()==1));
    drop(data);
    let terminal = protocol.page(&finalize, &mut source).unwrap();
    assert_eq!(complete(&terminal).items, 1);
    assert!(weak.upgrade().is_none());
    assert!(matches!(
        protocol.page(&cursor, &mut source),
        Err(ScopeScanError::InvalidCursor)
    ));
}
#[test]
fn scope_scan_protocol_no_progress_halves_rows_preserves_position_and_replays_exact_cursor() {
    let (mut protocol, mut cursor, mut source) = fixture(256);
    source.stop = true;
    for rows in [128, 64, 32, 16, 8, 4, 2, 1, 1] {
        let reply = protocol.page(&cursor, &mut source).unwrap();
        assert!(matches!(reply.body, ReplyBody::WorkBudget { .. }));
        let calls = source.calls;
        assert!(Arc::ptr_eq(
            &reply,
            &protocol.page(&cursor, &mut source).unwrap()
        ));
        assert_eq!(calls, source.calls);
        cursor = next(&reply);
        let state = protocol.codec.open(&cursor).unwrap();
        assert_eq!(state.rows, rows);
        assert_eq!(state.after, None);
        assert_eq!(state.totals, InventoryTotals::default());
    }
    source.stop = false;
    assert_eq!(
        complete(&protocol.page(&cursor, &mut source).unwrap()),
        InventoryTotals::default()
    );
}
#[test]
fn scope_scan_protocol_operational_failure_retries_same_attempt_without_empty_completion() {
    let (mut protocol, cursor, mut source) = fixture(256);
    source.unavailable = true;
    assert!(matches!(
        protocol.page(&cursor, &mut source),
        Err(ScopeScanError::Unavailable)
    ));
    source.unavailable = false;
    source.child(&protocol.cut.namespace, 1, &[]);
    let reply = protocol.page(&cursor, &mut source).unwrap();
    assert!(matches!(&reply.body,ReplyBody::Data{items,..} if items.len()==1));
}
#[test]
fn scope_scan_protocol_failure_manifest_rescans_cut_with_only_one_payload_reply() {
    let (mut protocol, mut cursor, mut source) = fixture(1);
    source.child(&protocol.cut.namespace, 1, &[]);
    source.child(&protocol.cut.namespace, 2, &[7]);
    source.claim(&protocol.cut.namespace, 7, 2);
    let damaged = source
        .rows
        .iter_mut()
        .find(|r| r.key == scope_storage::child_key(&protocol.cut.namespace, key(2)).unwrap())
        .unwrap();
    damaged.payload = crate::EncryptedSessionPayload::new(b"corrupt");
    let terminal_cursor;
    let summary;
    loop {
        let reply = protocol.page(&cursor, &mut source).unwrap();
        if matches!(reply.body, ReplyBody::Complete { .. }) {
            terminal_cursor = cursor;
            summary = reply;
            break;
        }
        cursor = next(&reply);
    }
    let totals = complete(&summary);
    assert_eq!(totals.items, 3);
    assert_eq!(totals.failed_items, 2);
    cursor = next(&summary);
    let mut failures = 0;
    let mut unknown = 0;
    loop {
        let reply = protocol.page(&cursor, &mut source).unwrap();
        match &reply.body {
            ReplyBody::Data { items, .. } => {
                for item in items {
                    assert!(item.child.is_none() && item.claim.is_none());
                    assert!(!item.inspection.failures.is_empty());
                    failures += 1;
                    unknown += usize::from(
                        item.inspection.disposition == ItemDisposition::ClaimHeldUnknown,
                    );
                }
            }
            ReplyBody::Complete {
                totals: rescanned,
                manifest,
            } => {
                assert_eq!(*rescanned, totals);
                assert!(manifest.is_none());
                break;
            }
            _ => panic!("fixture must make progress"),
        }
        assert!(Arc::ptr_eq(
            &summary,
            &protocol.page(&terminal_cursor, &mut source).unwrap()
        ));
        cursor = next(&reply);
    }
    assert_eq!(failures, 2);
    assert_eq!(unknown, 1);
    assert!(Arc::ptr_eq(
        &summary,
        &protocol.page(&terminal_cursor, &mut source).unwrap()
    ));
}
#[test]
fn scope_scan_protocol_bad_cursor_cannot_acknowledge_or_read_the_cut() {
    let (mut protocol, cursor, mut source) = fixture(1);
    source.child(&protocol.cut.namespace, 1, &[]);
    let reply = protocol.page(&cursor, &mut source).unwrap();
    let calls = source.calls;
    let mut bad = next(&reply).as_bytes().to_vec();
    bad[20] ^= 1;
    let bad = ScopeScanCursor::from_bytes(&bad).unwrap();
    assert!(matches!(
        protocol.page(&bad, &mut source),
        Err(ScopeScanError::InvalidCursor)
    ));
    assert_eq!(source.calls, calls);
    assert!(Arc::ptr_eq(
        &reply,
        &protocol.page(&cursor, &mut source).unwrap()
    ));
}
#[test]
fn scope_scan_protocol_drop_releases_its_cached_reply() {
    let (mut protocol, cursor, mut source) = fixture(1);
    source.child(&protocol.cut.namespace, 1, &[]);
    let reply = protocol.page(&cursor, &mut source).unwrap();
    let weak = Arc::downgrade(&reply);
    drop(reply);
    assert!(weak.upgrade().is_some());
    drop(protocol);
    assert!(weak.upgrade().is_none());
}
