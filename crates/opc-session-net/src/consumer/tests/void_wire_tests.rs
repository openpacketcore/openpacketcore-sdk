use super::super::{v2_outcome_unknown, v2_response_matches_request};
use super::*;

#[tokio::test]
async fn void_wire_requires_the_full_original_identity_for_every_result() {
    let original = v2_effectful_request(0x43).await;
    let other = v2_effectful_request(0x44).await;
    let SessionConsumerV2Operation::FencedTransitionV2 { request } = original.operation() else {
        panic!("singleton")
    };
    let SessionConsumerV2Operation::FencedTransitionV2 { request: foreign } = other.operation()
    else {
        panic!("singleton")
    };
    let void = SessionConsumerV2Request::new(
        original.scope(),
        SessionConsumerV2Operation::FencedTransitionV2Void {
            request: request.clone(),
        },
    );
    assert!(void.operation().is_effectful());
    let terminal = opc_session_store::SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(
        Err(opc_session_store::SessionConsumerV2FencedTransitionError::Voided),
    ));
    for result in [
        Ok(terminal),
        Err(SessionConsumerStoreError::Unavailable),
        Err(SessionConsumerStoreError::CapabilityNotSupported),
    ] {
        let exact = SessionConsumerV2Response::FencedTransitionV2Void {
            request_id: request.request_id(),
            result: result.clone(),
        };
        let wrong = SessionConsumerV2Response::FencedTransitionV2Void {
            request_id: foreign.request_id(),
            result,
        };
        assert!(v2_response_matches_request(&void, &exact));
        assert!(!v2_response_matches_request(&void, &wrong));
        assert!(!v2_response_matches_request(&original, &exact));
        let encoded = serde_json::to_vec(&exact).unwrap();
        let decoded = serde_json::from_slice(&encoded).unwrap();
        assert!(v2_response_matches_request(&void, &decoded));
    }
    assert!(!v2_response_matches_request(
        &void,
        &SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
    ));
    assert!(
        matches!(v2_outcome_unknown(&void), Some(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }) if request_id == request.request_id())
    );
}

#[test]
fn void_wire_terminal_error_is_lossless_without_changing_original_error_classification() {
    let error =
        opc_session_store::SessionConsumerV2FencedTransitionError::from_recorded_store_error(
            StoreError::FencedTransitionVoided,
        )
        .unwrap();
    assert!(error.is_recorded_deterministic());
    assert!(!error.is_pre_dispatch_deterministic());
    assert!(matches!(
        error.into_store_error(),
        StoreError::FencedTransitionVoided
    ));
    assert_eq!(
        serde_json::to_string(&opc_session_store::FencedTransitionV2Capability::V2).unwrap(),
        "\"V2\""
    );
}
