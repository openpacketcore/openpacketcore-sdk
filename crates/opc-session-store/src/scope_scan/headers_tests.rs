use super::*;
use crate::scope_authority::tests::{execution, request, scope, successor};
use crate::scope_authority::{ScopeAuthorityCommand, ScopeAuthorityOperation};
use std::collections::HashMap;

fn fixture() -> (
    ScopeAuthorityStamp,
    HashMap<SessionKey, StoredSessionRecord>,
) {
    let first = ScopeAuthorityCommand {
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
    let after = ScopeAuthorityCommand {
        request: successor(&first.state().unwrap(), 2),
    }
    .apply(Some(first.stored().unwrap()))
    .unwrap();
    let stamp = after.state().unwrap().view.stamp().unwrap().clone();
    let authority = after.to_record().unwrap();
    let checkpoint = ScopeRow::Batch(Box::new(ScopeBatchCheckpoint::empty(scope())))
        .to_record()
        .unwrap();
    (
        stamp,
        HashMap::from([
            (authority.key.clone(), authority),
            (checkpoint.key.clone(), checkpoint),
        ]),
    )
}
fn read(
    stamp: &ScopeAuthorityStamp,
    rows: &HashMap<SessionKey, StoredSessionRecord>,
) -> Result<CapturedHeaders, ScopeScanError> {
    decode_headers(stamp.namespace(), stamp, |key, _| {
        Ok(rows
            .get(key)
            .cloned()
            .map_or(RawScopeRecord::Missing, RawScopeRecord::Present))
    })
}
#[test]
fn scope_scan_headers_accept_explicit_zero_checkpoint_at_exact_successor() {
    let (stamp, rows) = fixture();
    let result = read(&stamp, &rows).expect("explicit initialized-zero header is a real cut");
    assert_eq!(result.authority.stamp(), Some(&stamp));
    assert_eq!(result.checkpoint.revision, 0);
    assert_eq!(result.checkpoint.birth_floor, 0);
    assert_eq!(result.checkpoint.counters, [0; 16]);
}
#[test]
fn scope_scan_headers_never_infer_an_absent_checkpoint_or_authority() {
    let (stamp, rows) = fixture();
    for (key, expected) in [
        (scope().key().unwrap(), ScopeScanHeaderFault::Authority),
        (
            scope_storage::batch_key(&scope()).unwrap(),
            ScopeScanHeaderFault::Checkpoint,
        ),
    ] {
        let mut damaged = rows.clone();
        damaged.remove(&key);
        assert!(
            matches!(read(&stamp, &damaged), Err(ScopeScanError::ScopeFault(found)) if found == expected)
        );
    }
}
#[test]
fn scope_scan_headers_reject_corrupt_body_and_noncanonical_envelope() {
    let (stamp, rows) = fixture();
    for (key, expected) in [
        (scope().key().unwrap(), ScopeScanHeaderFault::Authority),
        (
            scope_storage::batch_key(&scope()).unwrap(),
            ScopeScanHeaderFault::Checkpoint,
        ),
    ] {
        for body in [true, false] {
            let mut damaged = rows.clone();
            let row = damaged.get_mut(&key).unwrap();
            if body {
                row.payload = crate::EncryptedSessionPayload::new(b"corrupt");
            } else {
                row.generation = crate::Generation::new(999);
            }
            assert!(
                matches!(read(&stamp, &damaged), Err(ScopeScanError::ScopeFault(found)) if found == expected)
            );
        }
    }
}
#[test]
fn scope_scan_headers_check_physical_key_agreement_before_using_body() {
    let (stamp, mut rows) = fixture();
    let key = scope().key().unwrap();
    rows.get_mut(&key).unwrap().key.tenant = opc_types::TenantId::from_static("other");
    assert!(matches!(
        read(&stamp, &rows),
        Err(ScopeScanError::ScopeFault(ScopeScanHeaderFault::Authority))
    ));
}
#[test]
fn scope_scan_headers_keep_backend_failures_retryable() {
    let (stamp, _) = fixture();
    assert!(matches!(
        decode_headers(stamp.namespace(), &stamp, |_, _| Err(
            ScopeScanError::Unavailable
        )),
        Err(ScopeScanError::Unavailable)
    ));
}
#[test]
fn scope_scan_headers_recheck_the_exact_current_successor_stamp() {
    let (stamp, mut rows) = fixture();
    let key = scope().key().unwrap();
    let checkpoint = ScopeAuthorityCheckpoint::from_record(&rows[&key]).unwrap();
    let newer = ScopeAuthorityCommand {
        request: successor(&checkpoint.state().unwrap(), 3),
    }
    .apply(Some(checkpoint.stored().unwrap()))
    .unwrap();
    rows.insert(key, newer.to_record().unwrap());
    assert!(matches!(
        read(&stamp, &rows),
        Err(ScopeScanError::StaleAuthority)
    ));
}
#[test]
fn scope_scan_capture_must_be_at_or_beyond_the_exact_barrier_position() {
    use opc_consensus::engine::{CommittedLeaderId, LogId};
    let at = |term, index| {
        LogId::new(
            CommittedLeaderId::new(term, SessionConsensusNodeId::new(1).unwrap()),
            index,
        )
    };
    let barrier = Some(at(2, 10));
    assert_eq!(validate_applied(barrier, Some(at(2, 10))), Ok(at(2, 10)));
    assert_eq!(validate_applied(barrier, Some(at(3, 11))), Ok(at(3, 11)));
    for applied in [
        None,
        Some(at(2, 9)),
        Some(at(3, 9)),
        Some(at(3, 10)),
        Some(at(1, 11)),
    ] {
        assert_eq!(
            validate_applied(barrier, applied),
            Err(ScopeScanError::Unavailable)
        );
    }
    assert_eq!(
        validate_applied(None, None),
        Err(ScopeScanError::Unavailable)
    );
}
