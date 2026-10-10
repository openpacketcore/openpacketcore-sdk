use super::*;
use crate::scope_authority::tests::{admitted, execution, request, successor};
use crate::scope_authority::{ScopeAuthorityCheckpoint, ScopeAuthorityCommand};
use crate::scope_batch::ScopeBatchCheckpoint;
use crate::scope_scan::headers::{decode_headers_with_handover, RawScopeRecord};
use crate::scope_storage::ScopeRow;
use std::collections::HashMap;

fn fixture() -> (
    ScopeScanOpenRequest,
    HashMap<crate::SessionKey, crate::StoredSessionRecord>,
) {
    let first = admitted();
    let succession = successor(&first, 2);
    let state = first.transition(&succession).unwrap();
    let stamp = state.view.stamp().unwrap().clone();
    let authority = ScopeAuthorityCommand {
        request: request(
            0,
            1,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
        ),
    }
    .apply(None)
    .unwrap();
    let authority = ScopeAuthorityCommand {
        request: succession.clone(),
    }
    .apply(Some(authority.stored().unwrap()))
    .unwrap()
    .to_record()
    .unwrap();
    let checkpoint = ScopeRow::Batch(Box::new(ScopeBatchCheckpoint::empty(stamp.scope().clone())))
        .to_record()
        .unwrap();
    (
        ScopeScanOpenRequest {
            stamp,
            succession,
            limits: ScopeScanPageLimits::default(),
        },
        HashMap::from([
            (authority.key.clone(), authority),
            (checkpoint.key.clone(), checkpoint),
        ]),
    )
}
fn read(
    open: &ScopeScanOpenRequest,
    rows: &HashMap<crate::SessionKey, crate::StoredSessionRecord>,
) -> Result<crate::scope_scan::headers::CapturedHeaders, ScopeScanError> {
    decode_headers_with_handover(
        open.stamp.namespace(),
        &open.stamp,
        Some(&open.succession),
        |key, _| {
            Ok(rows
                .get(key)
                .cloned()
                .map_or(RawScopeRecord::Missing, RawScopeRecord::Present))
        },
    )
}
#[test]
fn scope_scan_remote_open_shared_codecs_roundtrip_without_capability() {
    let (open, _) = fixture();
    let bytes = open.encode_canonical().unwrap();
    let stamp = open.stamp.encode_canonical().unwrap();
    let succession = open.succession.encode_canonical().unwrap();
    let mut expected = vec![1];
    expected.extend_from_slice(&(stamp.len() as u16).to_be_bytes());
    expected.extend_from_slice(&stamp);
    expected.extend_from_slice(&(succession.len() as u16).to_be_bytes());
    expected.extend_from_slice(&succession);
    expected.extend_from_slice(&(open.limits.rows() as u32).to_be_bytes());
    expected.extend_from_slice(&(open.limits.payload_bytes() as u32).to_be_bytes());
    assert_eq!(bytes, expected, "authority bytes have exactly one owner");
    let decoded = ScopeScanOpenRequest::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded.stamp, open.stamp);
    assert_eq!(decoded.succession, open.succession);
    assert_eq!(decoded.limits.rows(), open.limits.rows());
    assert_eq!(decoded.limits.payload_bytes(), open.limits.payload_bytes());
    assert!(!format!("{decoded:?}").contains("worker-2"));
}
#[test]
fn scope_scan_remote_open_codec_rejects_truncation_trailing_and_oversize() {
    let (open, _) = fixture();
    let bytes = open.encode_canonical().unwrap();
    for end in 0..bytes.len() {
        assert!(ScopeScanOpenRequest::decode_canonical(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ScopeScanOpenRequest::decode_canonical(&trailing).is_err());
    let mut oversized = bytes;
    oversized[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(ScopeScanOpenRequest::decode_canonical(&oversized).is_err());
    assert!(
        ScopeScanOpenRequest::decode_canonical(&vec![0; MAX_SCOPE_SCAN_OPEN_BYTES + 1]).is_err()
    );
}
#[test]
fn scope_scan_remote_open_codec_rejects_malformed_limits_and_nested_noncanonical() {
    let (open, _) = fixture();
    let bytes = open.encode_canonical().unwrap();
    for (offset, invalid) in [(8, 0), (8, u32::MAX), (4, 1), (4, u32::MAX)] {
        let mut bad = bytes.clone();
        let start = bad.len() - offset;
        bad[start..start + 4].copy_from_slice(&invalid.to_be_bytes());
        assert!(ScopeScanOpenRequest::decode_canonical(&bad).is_err());
    }
    let stamp = open.stamp.encode_canonical().unwrap();
    let mut bad = bytes;
    let len = u16::from_be_bytes([bad[1], bad[2]]) as usize;
    bad.insert(3 + len, 0);
    bad[1..3].copy_from_slice(&((stamp.len() + 1) as u16).to_be_bytes());
    assert!(ScopeScanOpenRequest::decode_canonical(&bad).is_err());
}
#[test]
fn scope_scan_remote_open_accepts_only_the_exact_captured_committed_succession() {
    let (open, rows) = fixture();
    assert_eq!(
        read(&open, &rows).unwrap().authority.stamp(),
        Some(&open.stamp)
    );
}
#[test]
fn scope_scan_remote_open_rejects_changed_request_id_even_for_same_current_stamp() {
    let (mut open, rows) = fixture();
    open.succession = crate::scope_authority::ScopeAuthorityRequest::new(
        open.succession.scope().clone(),
        [8; 16],
        open.succession.expected_revision(),
        open.succession.operation().clone(),
    )
    .unwrap();
    assert!(matches!(
        read(&open, &rows),
        Err(ScopeScanError::HandoverRequired)
    ));
}
#[test]
fn scope_scan_remote_open_rejects_changed_evidence_even_with_exact_request_id() {
    let (mut open, rows) = fixture();
    let ScopeAuthorityOperation::SucceedClosed {
        predecessor,
        execution,
        ..
    } = open.succession.operation()
    else {
        unreachable!()
    };
    let operation = ScopeAuthorityOperation::SucceedClosed {
        predecessor: predecessor.clone(),
        execution: execution.clone(),
        evidence: crate::scope_authority::ScopeClosureEvidence::new(
            crate::scope_authority::ScopeClosureKind::FinalTermination,
            [9; 32],
        )
        .unwrap(),
    };
    open.succession = crate::scope_authority::ScopeAuthorityRequest::new(
        open.succession.scope().clone(),
        *open.succession.request_id(),
        open.succession.expected_revision(),
        operation,
    )
    .unwrap();
    assert!(matches!(
        read(&open, &rows),
        Err(ScopeScanError::HandoverRequired)
    ));
}
#[test]
fn scope_scan_remote_open_refuses_initial_admission_even_when_it_exactly_replays() {
    let first = ScopeAuthorityCommand {
        request: request(
            0,
            1,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
        ),
    };
    let authority = first.apply(None).unwrap().to_record().unwrap();
    let state = ScopeAuthorityCheckpoint::from_record(&authority)
        .unwrap()
        .state()
        .unwrap();
    let stamp = state.view.stamp().unwrap().clone();
    let checkpoint = ScopeRow::Batch(Box::new(ScopeBatchCheckpoint::empty(stamp.scope().clone())))
        .to_record()
        .unwrap();
    let rows = HashMap::from([
        (authority.key.clone(), authority),
        (checkpoint.key.clone(), checkpoint),
    ]);
    let open = ScopeScanOpenRequest {
        stamp,
        succession: first.request,
        limits: ScopeScanPageLimits::default(),
    };
    assert!(matches!(
        read(&open, &rows),
        Err(ScopeScanError::HandoverRequired)
    ));
}
