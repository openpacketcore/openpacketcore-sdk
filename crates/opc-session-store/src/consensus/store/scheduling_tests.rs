//! Scheduling metadata protocol regressions.
use super::*;

#[test]
fn scope_scheduler_reserved_credits_are_additional_to_eight_ordinary_slots() {
    let budgets = crate::scope_scheduler::ScopeSchedulerBudgets::default();
    assert!(crate::scope_scheduler::ScopeSchedulerOwner::new(budgets).is_ok());
    assert_eq!(
        budgets.normal.running,
        opc_consensus::DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS
    );
    assert_eq!(SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS, 13);
    assert_eq!(
        StoreWorkAdmission::new().available_permits(),
        SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS
    );
}

#[test]
fn scope_scheduler_mutation_forward_requires_class_metadata() {
    // This independent old shape must never gain the new field through a
    // shared alias to the current struct (the original v711 mirror did).
    #[derive(Serialize)]
    struct OldMutation {
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_consumer_scope: ForwardConsumerScope,
    }
    #[derive(Serialize)]
    enum OldForward {
        Mutation(OldMutation),
    }
    let old = encode_bounded(&OldForward::Mutation(OldMutation {
        request_id: SessionConsensusRequestId::from_bytes([1; 16]),
        intent: SessionMutationIntent::AdvanceLogicalTime,
        required_consumer_scope: ForwardConsumerScope::Internal,
    }))
    .unwrap();
    assert!(
        decode_bounded::<ForwardRequest>(&old).is_err(),
        "missing class metadata must fail closed"
    );
}

#[test]
fn scope_scheduler_forward_class_is_required_bounded_metadata_outside_intent() {
    let request = ForwardMutationRequest {
        request_id: SessionConsensusRequestId::from_bytes([1; 16]),
        intent: SessionMutationIntent::AdvanceLogicalTime,
        required_consumer_scope: ForwardConsumerScope::Internal,
        work_class: ForwardWorkClass::Inferred,
    };
    let encoded = encode_bounded(&ForwardRequest::Mutation(request.clone())).unwrap();
    assert!(decode_bounded::<FrozenV711ForwardRequest>(&encoded).is_err());
    assert!(decode_bounded::<ForwardRequest>(&encoded[..encoded.len() - 1]).is_err());
    let mut invalid = encoded.clone();
    *invalid.last_mut().unwrap() = 0x7F;
    assert!(decode_bounded::<ForwardRequest>(&invalid).is_err());
    let mut forged = request.clone();
    forged.work_class = ForwardWorkClass::Declared(ScopeWorkClass::SafetyControl);
    assert_eq!(
        forged.scheduling(),
        Err(StoreError::TopologyAuthorityRevoked)
    );
    forged.work_class = ForwardWorkClass::Declared(ScopeWorkClass::Emergency);
    assert_eq!(
        forged.scheduling(),
        Err(StoreError::TopologyAuthorityRevoked),
        "only own-scope batch ingress declares a data class"
    );
    assert_eq!(
        encode_bounded(&request.intent).unwrap(),
        encode_bounded(&forged.intent).unwrap()
    );
    assert_eq!(request.request_id, forged.request_id);
    assert_eq!(request.scheduling().unwrap().1, ScopeWorkClass::Normal);
}

#[test]
fn scope_scheduler_leader_refuses_declared_control_on_forwarded_child_batch() {
    use crate::scope_batch::{ScopeBatchCommand, ScopeBatchRequest};
    let admitted = crate::scope_authority::tests::admitted();
    let request = ForwardMutationRequest {
        request_id: SessionConsensusRequestId::from_bytes([3; 16]),
        intent: SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                admitted.view.stamp().unwrap(),
                [3; 16],
                0,
                vec![crate::scope_batch::tests::create(1, &[1])],
                vec![],
            )
            .unwrap(),
        })),
        required_consumer_scope: ForwardConsumerScope::Internal,
        work_class: ForwardWorkClass::Declared(ScopeWorkClass::SafetyControl),
    };
    let encoded = encode_bounded(&ForwardRequest::Mutation(request)).unwrap();
    let ForwardRequest::Mutation(mut forwarded) = decode_bounded(&encoded).unwrap() else {
        panic!("forwarded mutation");
    };
    assert_eq!(
        forwarded.scheduling(),
        Err(StoreError::TopologyAuthorityRevoked)
    );
    // This shape reaches the batch-specific arm. A generic non-batch rejection
    // would not prove that forged control is rejected at leader admission.
    forwarded.work_class = ForwardWorkClass::Declared(ScopeWorkClass::Emergency);
    assert_eq!(forwarded.scheduling().unwrap().1, ScopeWorkClass::Emergency);
}
