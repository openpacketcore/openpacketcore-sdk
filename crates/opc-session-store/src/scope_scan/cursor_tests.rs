use super::*;
use crate::scope_authority::tests::{admitted, successor};
use crate::scope_authority::{ScopeIncarnation, ScopeNamespace};
use opc_consensus::engine::{CommittedLeaderId, LogId};

fn fixture() -> (ScopeCut, ScopeAuthorityStamp, CursorState) {
    let before = admitted();
    let after = before.transition(&successor(&before, 2)).unwrap();
    let stamp = after.view.stamp().unwrap().clone();
    let node = crate::SessionConsensusNodeId::new(1).unwrap();
    let cut = ScopeCut {
        namespace: stamp.namespace().clone(),
        authority_revision: stamp.revision(),
        batch_revision: 40,
        applied: LogId::new(CommittedLeaderId::new(5, node), 10),
        epoch: 3,
        capture_id: [19; 16],
        serving_node: node,
    };
    let mut physical = crate::scope_storage::namespace_prefix(&cut.namespace)
        .unwrap()
        .to_vec();
    physical.extend_from_slice(&[49; 32]);
    let state = CursorState {
        phase: CursorPhase::Inventory,
        attempt: 7,
        rows: 128,
        after: Some(InventoryPosition {
            kind: 0,
            locator: super::super::position::LocatorKind::Canonical,
            bytes: physical,
        }),
        totals: InventoryTotals {
            items: 30,
            failed_items: 2,
            failures: 3,
            claims_incomplete: true,
        },
    };
    (cut, stamp, state)
}
fn codec(cut: &ScopeCut, stamp: &ScopeAuthorityStamp, limits: PageLimits) -> CursorCodec {
    CursorCodec {
        key: Zeroizing::new([7; 32]),
        binding: binding(cut, stamp, limits).unwrap(),
        limits,
    }
}
#[test]
fn scope_scan_cursor_round_trips_all_phases_positions_and_totals() {
    let (cut, stamp, state) = fixture();
    let codec = codec(&cut, &stamp, PageLimits::default());
    for phase in [
        CursorPhase::Inventory,
        CursorPhase::InventoryFinalize,
        CursorPhase::Manifest,
        CursorPhase::ManifestFinalize,
    ] {
        for position in [None, state.after.clone()] {
            let mut candidate = state.clone();
            candidate.phase = phase;
            candidate.after = position;
            let token = codec.seal(&candidate).unwrap();
            assert_eq!(codec.open(&token).unwrap(), candidate);
        }
    }
}
#[test]
fn scope_scan_cursor_hides_key_and_binds_every_envelope_byte() {
    let (cut, stamp, state) = fixture();
    let codec = codec(&cut, &stamp, PageLimits::default());
    let token = codec.seal(&state).unwrap();
    assert_eq!(codec.open(&token).unwrap(), state);
    assert!(!token.as_bytes().windows(32).any(|bytes| bytes == [49; 32]));
    assert!(!token
        .as_bytes()
        .windows(32)
        .any(|bytes| bytes == crate::scope_storage::namespace_prefix(&cut.namespace).unwrap()));
    for index in 0..token.as_bytes().len() {
        let mut changed = token.as_bytes().to_vec();
        changed[index] ^= 1;
        if let Ok(forged) = ScopeScanCursor::from_bytes(&changed) {
            assert_eq!(codec.open(&forged), Err(ScopeScanError::InvalidCursor));
        }
    }
    assert_eq!(format!("{token:?}"), "ScopeScanCursor(<redacted>)");
}
#[test]
fn scope_scan_cursor_binds_full_cut_even_with_same_secret() {
    let (cut, stamp, state) = fixture();
    let original = codec(&cut, &stamp, PageLimits::default());
    let token = original.seal(&state).unwrap();
    assert_eq!(original.open(&token).unwrap(), state);
    for field in 0..8 {
        let mut other = cut.clone();
        match field {
            0 => {
                other.namespace = ScopeNamespace::new(
                    cut.namespace.scope().clone(),
                    ScopeIncarnation::new(2).unwrap(),
                )
                .unwrap()
            }
            1 => other.authority_revision += 1,
            2 => other.batch_revision += 1,
            3 => {
                other.applied = LogId::new(
                    CommittedLeaderId::new(6, cut.serving_node),
                    cut.applied.index,
                )
            }
            4 => other.applied.index += 1,
            5 => other.epoch += 1,
            6 => other.capture_id[0] ^= 1,
            _ => other.serving_node = crate::SessionConsensusNodeId::new(2).unwrap(),
        }
        assert_eq!(
            codec(&other, &stamp, PageLimits::default()).open(&token),
            Err(ScopeScanError::InvalidCursor),
            "cut field {field}"
        );
    }
}
#[test]
fn scope_scan_cursor_binds_exact_boot_and_every_limit() {
    let (cut, stamp, state) = fixture();
    let original = codec(&cut, &stamp, PageLimits::default());
    let token = original.seal(&state).unwrap();
    assert_eq!(original.open(&token).unwrap(), state);
    let before = admitted();
    let changed = before.transition(&successor(&before, 3)).unwrap();
    assert_eq!(
        codec(&cut, changed.view.stamp().unwrap(), PageLimits::default()).open(&token),
        Err(ScopeScanError::InvalidCursor)
    );
    for field in 0..5 {
        let mut limits = PageLimits::default();
        match field {
            0 => limits.rows -= 1,
            1 => limits.payload_bytes -= 1,
            2 => limits.retained_bytes -= 1,
            3 => limits.visits -= 1,
            _ => limits.metadata_bytes -= 1,
        }
        assert_eq!(
            codec(&cut, &stamp, limits).open(&token),
            Err(ScopeScanError::InvalidCursor),
            "limit field {field}"
        );
    }
}
#[test]
fn scope_scan_cursor_keys_are_independent_for_equal_claims() {
    let (cut, stamp, state) = fixture();
    let a = CursorCodec::new(&cut, &stamp, PageLimits::default()).unwrap();
    let b = CursorCodec::new(&cut, &stamp, PageLimits::default()).unwrap();
    let token = a.seal(&state).unwrap();
    assert_eq!(a.open(&token).unwrap(), state);
    assert_eq!(b.open(&token), Err(ScopeScanError::InvalidCursor));
}
#[test]
fn scope_scan_cursor_rejects_invalid_effective_rows_and_positions_before_sealing() {
    let (cut, stamp, state) = fixture();
    let codec = codec(&cut, &stamp, PageLimits::default());
    for rows in [0, 257, 1025, usize::MAX] {
        let mut bad = state.clone();
        bad.rows = rows;
        assert_eq!(codec.seal(&bad), Err(ScopeScanError::InvalidCursor));
    }
    for len in [0, 31, 65, 4096] {
        let mut bad = state.clone();
        bad.after.as_mut().unwrap().bytes = vec![0; len];
        assert_eq!(codec.seal(&bad), Err(ScopeScanError::InvalidCursor));
    }
    let mut bad = state;
    bad.after.as_mut().unwrap().kind = 2;
    assert_eq!(codec.seal(&bad), Err(ScopeScanError::InvalidCursor));
}
#[test]
fn scope_scan_cursor_rejects_impossible_totals() {
    let (cut, stamp, state) = fixture();
    let codec = codec(&cut, &stamp, PageLimits::default());
    for totals in [
        InventoryTotals {
            items: 0,
            failed_items: 1,
            failures: 1,
            claims_incomplete: false,
        },
        InventoryTotals {
            items: 1,
            failed_items: 1,
            failures: 9,
            claims_incomplete: false,
        },
        InventoryTotals {
            items: 1,
            failed_items: 0,
            failures: 0,
            claims_incomplete: true,
        },
    ] {
        let mut bad = state.clone();
        bad.totals = totals;
        assert_eq!(codec.seal(&bad), Err(ScopeScanError::InvalidCursor));
    }
}
#[test]
fn scope_scan_cursor_import_bounds_before_copy_and_rejects_truncation() {
    let (cut, stamp, state) = fixture();
    let codec = codec(&cut, &stamp, PageLimits::default());
    let token = codec.seal(&state).unwrap();
    assert_eq!(codec.open(&token).unwrap(), state);
    for len in 0..token.as_bytes().len() {
        if let Ok(short) = ScopeScanCursor::from_bytes(&token.as_bytes()[..len]) {
            assert_eq!(codec.open(&short), Err(ScopeScanError::InvalidCursor));
        }
    }
    assert_eq!(
        ScopeScanCursor::from_bytes(&vec![VERSION; MAX_BYTES + 1]),
        Err(ScopeScanError::InvalidCursor)
    );
    let mut trailing = token.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        codec.open(&ScopeScanCursor::from_bytes(&trailing).unwrap()),
        Err(ScopeScanError::InvalidCursor)
    );
}

#[test]
fn scope_scan_cursor_round_trips_bounded_malformed_locators_without_aliasing() {
    use super::super::position::LocatorKind;
    let (cut, stamp, state) = fixture();
    let codec = codec(&cut, &stamp, PageLimits::default());
    let prefix = crate::scope_storage::namespace_prefix(&cut.namespace).unwrap();
    let mut positions = Vec::new();
    for kind in 0..=1 {
        positions.push(InventoryPosition {
            kind,
            locator: LocatorKind::NativeKnown,
            bytes: prefix.to_vec(),
        });
        positions.push(InventoryPosition {
            kind,
            locator: LocatorKind::NativeUnknown,
            bytes: vec![0; 1],
        });
        positions.push(InventoryPosition {
            kind,
            locator: LocatorKind::NativeUnknown,
            bytes: vec![255; 64],
        });
        for known in [false, true] {
            for rowid in [i64::MIN, -1, 0, i64::MAX] {
                let position = InventoryPosition::sqlite(kind, known, rowid);
                assert_eq!(position.rowid(), Some(rowid));
                positions.push(position);
            }
        }
    }
    for position in positions {
        let mut candidate = state.clone();
        candidate.after = Some(position);
        let token = codec.seal(&candidate).unwrap();
        assert_eq!(codec.open(&token).unwrap(), candidate);
        assert!(token.as_bytes().len() <= MAX_BYTES);
        let mut bad = candidate;
        bad.after.as_mut().unwrap().bytes.clear();
        assert_eq!(codec.seal(&bad), Err(ScopeScanError::InvalidCursor));
    }
}
