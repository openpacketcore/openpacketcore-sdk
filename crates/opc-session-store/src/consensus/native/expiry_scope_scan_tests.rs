use super::*;
use allocation_counter::measure;
use changes::tests::fixture;
use opc_types::{NetworkFunctionKind, TenantId};
use std::ops::Bound::{Excluded, Included, Unbounded};

fn key(kind: &str, bytes: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::from_static("native-scope-range"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: crate::SessionKeyType::other(kind).unwrap(),
        stable_id: bytes::Bytes::copy_from_slice(bytes).try_into().unwrap(),
    }
}

fn index(keys: &[SessionKey]) -> ExpiryIndex {
    let (storage, _, _) = fixture();
    let row = &**storage.business.keys.values().next().unwrap();
    let mut index = ExpiryIndex::default();
    for key in keys.iter().rev() {
        // Only record presence is indexed. Stored row decoding, namespace
        // authentication and claim classification belong to the scan adapter.
        index.replace(key, None, Some(row));
    }
    index
}

#[test]
fn native_scope_range_includes_malformed_prefix_and_short_suffix_rows() {
    for kind in ["opc-scope-child", "opc-scope-claim"] {
        // These synthetic prefixes do not prescribe the durable key encoding.
        let prefix = vec![0x42; 32];
        let mut short = prefix.clone();
        short.push(1);
        let mut complete = prefix.clone();
        complete.extend([2; 32]);
        let lower = key(kind, &prefix);
        let upper = key(kind, &[0x43; 32]);
        let keys = [
            key(kind, &[0x41; 32]),
            lower.clone(),
            key(kind, &short),
            key(kind, &complete),
            upper.clone(),
        ];
        let index = index(&keys);
        assert_eq!(
            index
                .ordered_record_range(Included(&lower), Excluded(&upper))
                .cloned()
                .collect::<Vec<_>>(),
            keys[1..4],
            "malformed rows at the prefix must reach per-item inspection",
        );
    }
}

#[test]
fn native_scope_range_obeys_included_excluded_and_unbounded_endpoints() {
    let keys: Vec<_> = (1..=5).map(|n| key("opc-scope-child", &[n])).collect();
    let index = index(&keys);
    let cases = [
        (Included(&keys[1]), Included(&keys[3]), 1..4),
        (Excluded(&keys[1]), Excluded(&keys[3]), 2..3),
        (Unbounded, Excluded(&keys[1]), 0..1),
        (Excluded(&keys[3]), Unbounded, 4..5),
        (Unbounded, Unbounded, 0..5),
        (Included(&keys[2]), Included(&keys[2]), 2..3),
        (Included(&keys[2]), Excluded(&keys[2]), 2..2),
    ];
    for (lower, upper, expected) in cases {
        assert_eq!(
            index
                .ordered_record_range(lower, upper)
                .cloned()
                .collect::<Vec<_>>(),
            keys[expected],
        );
    }
    let absent = key("opc-scope-child", &[8]);
    assert_eq!(
        index
            .ordered_record_range(Included(&absent), Unbounded)
            .next(),
        None,
    );
    assert_eq!(
        ExpiryIndex::default()
            .ordered_record_range(Unbounded, Unbounded)
            .next(),
        None,
    );
}

#[test]
fn native_scope_range_continuation_is_exclusive_without_repeating_rows() {
    let keys: Vec<_> = (0..8).map(|n| key("opc-scope-claim", &[n])).collect();
    let index = index(&keys);
    let first: Vec<_> = index
        .ordered_record_range(Included(&keys[1]), Excluded(&keys[7]))
        .take(2)
        .cloned()
        .collect();
    assert_eq!(first, keys[1..3]);
    let second: Vec<_> = index
        .ordered_record_range(Excluded(first.last().unwrap()), Excluded(&keys[7]))
        .cloned()
        .collect();
    assert_eq!(second, keys[3..7]);
    assert_eq!(
        index
            .ordered_records(Some(&keys[2]))
            .cloned()
            .collect::<Vec<_>>(),
        keys[3..],
        "ordinary restore retains its existing exclusive continuation",
    );
}

#[test]
fn native_scope_range_isolates_tenant_nf_kind_and_complete_key_bytes() {
    let base = key("opc-scope-child", &[0x42; 32]);
    let mut last = base.clone();
    last.stable_id = bytes::Bytes::from(vec![0x42; 64]).try_into().unwrap();
    let upper = key("opc-scope-child", &[0x43; 32]);
    let mut tenant = base.clone();
    tenant.tenant = TenantId::from_static("native-scope-range-other");
    let mut nf = base.clone();
    nf.nf_kind = NetworkFunctionKind::from_static("upf");
    let mut claim = base.clone();
    claim.key_type = crate::SessionKeyType::other("opc-scope-claim").unwrap();
    let mut ordinary = base.clone();
    ordinary.key_type = crate::SessionKeyType::PduSession;
    let index = index(&[
        tenant,
        last.clone(),
        claim,
        ordinary,
        nf,
        base.clone(),
        upper.clone(),
    ]);
    assert_eq!(
        index
            .ordered_record_range(Included(&base), Excluded(&upper))
            .cloned()
            .collect::<Vec<_>>(),
        [base, last],
    );
}

#[test]
fn native_scope_range_captured_roots_keep_the_original_inventory() {
    let keys: Vec<_> = (0..6).map(|n| key("opc-scope-claim", &[n])).collect();
    let mut live = index(&keys);
    let captured = live.clone();
    let (storage, _, _) = fixture();
    let row = &**storage.business.keys.values().next().unwrap();
    live.replace(&keys[2], Some(row), None);
    let inserted = key("opc-scope-claim", &[3, 1]);
    live.replace(&inserted, None, Some(row));
    assert_eq!(
        captured
            .ordered_record_range(Included(&keys[1]), Excluded(&keys[5]))
            .cloned()
            .collect::<Vec<_>>(),
        keys[1..5],
    );
    assert_eq!(
        live.ordered_record_range(Included(&keys[1]), Excluded(&keys[5]))
            .cloned()
            .collect::<Vec<_>>(),
        [keys[1].clone(), keys[3].clone(), inserted, keys[4].clone()],
    );
}

#[test]
fn native_scope_range_seeks_without_materializing_the_namespace() {
    let keys: Vec<_> = (0u64..4096)
        .map(|n| key("opc-scope-child", &n.to_be_bytes()))
        .collect();
    let index = index(&keys);
    // Check both a large remaining namespace and a seek near its end. Even
    // copying only references for the large range exceeds this allocation cap.
    for start in [1, 4000] {
        let mut first = None;
        let allocation = measure(|| {
            first = index
                .ordered_record_range(Included(&keys[start]), Excluded(&keys[4090]))
                .next();
        });
        assert_eq!(first, Some(&keys[start]));
        assert!(
            allocation.bytes_total <= 16 * 1024,
            "a bounded seek allocated {} bytes",
            allocation.bytes_total,
        );
    }
}
