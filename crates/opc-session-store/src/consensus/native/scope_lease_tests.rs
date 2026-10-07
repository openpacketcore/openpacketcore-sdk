use super::*;
use crate::scope_lease::tests::{at, bounds, execution, request};
use crate::scope_lease::ScopeLeaseOperation;

#[test]
fn scope_checkpoint_replacement_does_not_weaken_ordinary_receipt_immutability() {
    let checkpoint = ScopeLeaseCommand {
        request: request(
            0,
            1,
            ScopeLeaseOperation::Select {
                execution: execution(1),
            },
        ),
        bounds: bounds(0),
    }
    .apply(None)
    .unwrap();
    let scoped = NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
        payload_digest: checkpoint.digest().unwrap(),
        response: Box::new(SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))),
            sequence: 1,
            digest: None,
            logical_time: Some(at(0)),
            raft_log_index: 1,
        }),
    });
    let mut ordinary = scoped.clone();
    let NativeGenericReceipt::Ordinary(row) = &mut ordinary else {
        unreachable!()
    };
    row.response.result = Ok(SessionMutationOutcome::Unit);
    assert!(ordinary
        .validate_replacement(&ordinary, Some(at(0)))
        .is_ok());
    assert!(scoped.validate_replacement(&ordinary, Some(at(0))).is_err());
    assert!(ordinary.validate_replacement(&scoped, Some(at(0))).is_err());
    let mut changed = ordinary.clone();
    let NativeGenericReceipt::Ordinary(row) = &mut changed else {
        unreachable!()
    };
    row.response.sequence += 1;
    assert!(changed
        .validate_replacement(&ordinary, Some(at(1)))
        .is_err());
}
