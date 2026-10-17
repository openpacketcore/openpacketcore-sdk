use super::super::v2_response_matches_request;
use super::*;

async fn acquire_request(nonce: u8) -> SessionConsumerV2Request {
    let original = v2_effectful_request(nonce).await;
    let SessionConsumerV2Operation::FencedTransitionV2 { request } = original.operation() else {
        panic!("singleton")
    };
    let request = FencedTransitionV2Request::new(
        request.request_id().epoch(),
        request.request_id().nonce(),
        FencedTransitionLease::acquire(
            request.lease().key().clone(),
            OwnerId::new(format!("deferral-wire-owner-{nonce}")).unwrap(),
            FenceToken::new(1),
            Duration::from_secs(30),
        )
        .unwrap(),
        request.mutation().clone(),
    )
    .unwrap();
    SessionConsumerV2Request::new(
        original.scope(),
        SessionConsumerV2Operation::FencedTransitionV2 {
            request: Box::new(request),
        },
    )
}

#[tokio::test]
async fn lease_deferral_wire_requires_full_identity_and_is_never_a_terminal_error() {
    let original = acquire_request(0xA1).await;
    let foreign = acquire_request(0xA2).await;
    let SessionConsumerV2Operation::FencedTransitionV2 { request } = original.operation() else {
        panic!("singleton")
    };
    let SessionConsumerV2Operation::FencedTransitionV2 { request: other } = foreign.operation()
    else {
        panic!("singleton")
    };
    for id in [
        request.request_id(),
        other.request_id(),
        FencedTransitionV2RequestId::from_parts(
            request.request_id().epoch(),
            request.request_id().nonce(),
            *other.request_id().body_commitment(),
        ),
    ] {
        let exact = id == request.request_id();
        let response = SessionConsumerV2Response::FencedTransitionV2Deferred { request_id: id };
        assert_eq!(v2_response_matches_request(&original, &response), exact);
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(v2_response_matches_request(&original, &decoded), exact);
        let status_request = SessionConsumerV2Request::new(
            original.scope(),
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: request.clone(),
            },
        );
        let response = SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            opc_session_store::SessionConsumerV2FencedTransitionStatus::LeaseDeferred {
                request_id: id,
            },
        ));
        assert_eq!(
            v2_response_matches_request(&status_request, &response),
            exact
        );
        assert!(!v2_response_matches_request(&original, &response));
    }
    let error = opc_session_store::SessionConsumerV2FencedTransitionError::LeaseDeferred;
    assert!(error.is_lease_deferred());
    assert!(!error.is_pre_dispatch_deterministic());
    assert!(!error.is_recorded_deterministic());
    assert!(
        opc_session_store::SessionConsumerV2FencedTransitionError::from_recorded_store_error(
            StoreError::FencedTransitionLeaseDeferred
        )
        .is_none()
    );
    assert!(!v2_response_matches_request(
        &original,
        &SessionConsumerV2Response::FencedTransitionV2(Err(error.clone()))
    ));
    assert_eq!(
        error.into_store_error(),
        StoreError::FencedTransitionLeaseDeferred
    );
}

#[tokio::test]
async fn lease_deferral_wire_rejects_a_correlated_deferral_for_a_renewal() {
    let renewal = v2_effectful_request(0xA3).await;
    let SessionConsumerV2Operation::FencedTransitionV2 { request } = renewal.operation() else {
        panic!("singleton")
    };
    assert!(matches!(
        request.lease(),
        FencedTransitionLease::Renew { .. }
    ));
    assert!(!v2_response_matches_request(
        &renewal,
        &SessionConsumerV2Response::FencedTransitionV2Deferred {
            request_id: request.request_id()
        }
    ));
    let status = SessionConsumerV2Request::new(
        renewal.scope(),
        SessionConsumerV2Operation::FencedTransitionV2Status {
            request: request.clone(),
        },
    );
    assert!(!v2_response_matches_request(
        &status,
        &SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            opc_session_store::SessionConsumerV2FencedTransitionStatus::LeaseDeferred {
                request_id: request.request_id()
            }
        ))
    ));
}
