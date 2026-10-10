use super::*;
use opc_session_store::scope_batch::{ScopeBatchError, ScopeBatchRequest, ScopeCounterMutation};

fn stamp() -> ScopeAuthorityStamp {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
    ))
    .unwrap();
    let encoded = vectors["authority_requests"][1]["canonical_postcard_hex"]
        .as_str()
        .unwrap();
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
        .collect::<Vec<_>>();
    match ScopeAuthorityRequest::decode_canonical(&bytes)
        .unwrap()
        .operation()
    {
        ScopeAuthorityOperation::SucceedClosed { predecessor, .. } => predecessor.clone(),
        _ => panic!("the frozen succession fixture names its actual predecessor"),
    }
}

fn request() -> ScopeBatchRequest {
    ScopeBatchRequest::in_lane(
        &stamp(),
        [31; 16],
        0,
        1,
        Vec::new(),
        vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
    )
    .unwrap()
}

fn header(method: Method, id: [u8; 16], digest: [u8; 32], length: usize) -> Header {
    let binding = ScopeBinding::from_scope(stamp().scope()).unwrap();
    Header {
        kind: FrameKind::Call,
        class: Class::Normal,
        method,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: id,
        digest,
        payload_len: length + 36,
    }
}

#[test]
fn batch_apply_uses_the_complete_native_identity_and_execution() {
    let request = request();
    let bytes = request.encode_canonical().unwrap();
    let call = header(
        Method::ApplyBatch,
        *request.request_id(),
        request.digest().unwrap(),
        bytes.len(),
    );
    let decoded = NativeCall::decode(&call, &bytes, request.stamp().scope())
        .expect("a canonical native batch is a supported typed worker call");
    assert_eq!(decoded.execution(), Some(request.stamp().execution()));
    for field in 0..2 {
        let mut changed = call.clone();
        if field == 0 {
            changed.request_id[0] ^= 1;
        } else {
            changed.digest[0] ^= 1;
        }
        assert!(NativeCall::decode(&changed, &bytes, request.stamp().scope()).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(NativeCall::decode(&call, &trailing, request.stamp().scope()).is_err());
}

#[test]
fn batch_cancel_binds_the_original_attempt_with_the_native_cancel_digest() {
    let request = request();
    let attempt = request.attempt().unwrap();
    let bytes = attempt.encode_canonical().unwrap();
    let method = Method::try_from(10).expect("batch cancellation has its own method");
    let mut call = header(
        method,
        *attempt.request_id(),
        attempt.cancellation_digest().unwrap(),
        bytes.len(),
    );
    let decoded = NativeCall::decode(&call, &bytes, attempt.stamp().scope()).unwrap();
    assert_eq!(decoded.execution(), Some(attempt.stamp().execution()));
    call.digest = *attempt.request_digest();
    assert!(NativeCall::decode(&call, &bytes, attempt.stamp().scope()).is_err());
}

#[test]
fn batch_observations_do_not_ask_a_successor_to_prove_the_predecessor_key() {
    let request = request();
    let attempt = request.attempt().unwrap();
    for (tag, bytes) in [
        (9, request.stamp().encode_canonical().unwrap()),
        (11, attempt.encode_canonical().unwrap()),
    ] {
        let method =
            Method::try_from(tag).expect("batch read methods are distinct from authority outcome");
        let id = [32; 16];
        let digest = transport_request_digest(method, &id, &bytes).unwrap();
        let mut call = header(method, id, digest, bytes.len());
        let decoded = NativeCall::decode(&call, &bytes, request.stamp().scope()).unwrap();
        assert!(
            decoded.execution().is_none(),
            "the query target is not the caller's proven boot"
        );
        call.digest[0] ^= 1;
        assert!(NativeCall::decode(&call, &bytes, request.stamp().scope()).is_err());
    }
}

#[test]
fn native_batch_errors_never_claim_committed_worker_authority() {
    let status = ResultStatus::try_from(5).expect("native batch errors have a separate result tag");
    let body = ScopeBatchError::RevisionConflict
        .encode_canonical()
        .unwrap();
    let payload = ResultPayload::new([1; 32], status, [0; 32], body.clone()).unwrap();
    assert_eq!(
        ResultPayload::decode(&payload.encode().unwrap())
            .unwrap()
            .body,
        body
    );
    assert!(ResultPayload::new([1; 32], status, [2; 32], body).is_err());
    assert!(ResultPayload::new([1; 32], status, [0; 32], Vec::new()).is_err());
}

#[test]
fn batch_methods_pin_native_codecs_and_complete_frozen_frames() {
    use opc_session_store::scope_batch::{
        ScopeBatchLookup, ScopeBatchOutcome, ScopeBatchReceipt, ScopeBatchReopen,
    };
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/rfc/026-scope-authenticated-transport-batch-vectors.json"
    ))
    .unwrap();
    let decode = |value: &serde_json::Value| {
        let value = value.as_str().unwrap();
        (0..value.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let request = request();
    let attempt = request.attempt().unwrap();
    assert_eq!(
        stamp().encode_canonical().unwrap(),
        decode(&vectors["inputs"]["stamp_hex"])
    );
    assert_eq!(
        attempt.encode_canonical().unwrap(),
        decode(&vectors["attempt_hex"])
    );
    assert_eq!(
        request.digest().unwrap().as_slice(),
        decode(&vectors["request_digest_hex"])
    );
    assert_eq!(
        attempt.cancellation_digest().unwrap().as_slice(),
        decode(&vectors["cancellation_digest_hex"])
    );
    for fixture in vectors["methods"].as_array().unwrap() {
        let method = Method::try_from(fixture["method"].as_u64().unwrap() as u8).unwrap();
        let canonical = decode(&fixture["canonical_hex"]);
        let id: [u8; 16] = decode(&fixture["request_id_hex"]).try_into().unwrap();
        let digest = match method {
            Method::ApplyBatch => request.digest().unwrap(),
            Method::BatchCancel => attempt.cancellation_digest().unwrap(),
            _ => transport_request_digest(method, &id, &canonical).unwrap(),
        };
        assert_eq!(digest.as_slice(), decode(&fixture["digest_hex"]));
        let call = header(method, id, digest, canonical.len());
        assert_eq!(
            call.encode().unwrap().as_slice(),
            decode(&fixture["call_header_hex"])
        );
        assert_eq!(
            CallPayload {
                nonce: [33; 32],
                canonical: canonical.clone()
            }
            .encode(method)
            .unwrap(),
            decode(&fixture["call_payload_hex"])
        );
        let native = NativeCall::decode(&call, &canonical, stamp().scope()).unwrap();
        assert_eq!(
            native.execution().is_some(),
            matches!(method, Method::ApplyBatch | Method::BatchCancel)
        );
        let result = ResultPayload::decode(&decode(&fixture["result_payload_hex"])).unwrap();
        assert_eq!(
            result.status as u8,
            fixture["result_status"].as_u64().unwrap() as u8
        );
        assert_eq!(result.body, decode(&fixture["result_body_hex"]));
        let body = match method {
            Method::ApplyBatch => {
                let outcome = ScopeBatchOutcome::decode_canonical(&result.body).unwrap();
                assert!(outcome.matches_request(&request));
                outcome.encode_canonical().unwrap()
            }
            Method::BatchCancel => {
                let receipt = ScopeBatchReceipt::decode_canonical(&result.body).unwrap();
                assert_eq!(receipt.attempt(), &attempt);
                receipt.encode_canonical().unwrap()
            }
            Method::BatchReopen => {
                let cut = ScopeBatchReopen::decode_canonical(&result.body).unwrap();
                assert!(matches!(
                    cut.lookup(&attempt).unwrap(),
                    ScopeBatchLookup::Applied(_)
                ));
                cut.encode_canonical().unwrap()
            }
            Method::BatchLookup => ScopeBatchLookup::decode_canonical(&result.body)
                .unwrap()
                .encode_canonical()
                .unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(body, result.body);
        let reply = call
            .response(FrameKind::Result, result.encode().unwrap().len())
            .unwrap();
        assert_eq!(
            reply.encode().unwrap().as_slice(),
            decode(&fixture["result_header_hex"])
        );
    }
    let result =
        ResultPayload::decode(&decode(&vectors["revision_conflict"]["result_payload_hex"]))
            .unwrap();
    assert_eq!(result.status, ResultStatus::BatchError);
    assert_eq!(
        ScopeBatchError::decode_canonical(&result.body).unwrap(),
        ScopeBatchError::RevisionConflict
    );
}

#[test]
fn batch_role_routing_reserves_control_for_authority_calls() {
    let stamp = stamp();
    let binding = ScopeBinding::from_scope(stamp.scope()).unwrap();
    let principal = opc_types::SpiffeId::new(stamp.execution().identity().as_str()).unwrap();
    for role in [
        ScopeRole::Worker,
        ScopeRole::Controller,
        ScopeRole::Observer,
    ] {
        let policy = super::super::ScopePolicy::new(vec![super::super::PrincipalGrant::new(
            principal.clone(),
            role,
            vec![binding.clone()],
        )
        .unwrap()])
        .unwrap();
        for tag in [4, 9, 10, 11] {
            let method = Method::try_from(tag).expect("the typed batch method exists");
            assert!(policy
                .authorize(&principal, &binding, method, Class::SafetyControl)
                .is_err());
            let allowed = role == ScopeRole::Worker || matches!(tag, 9 | 11);
            assert_eq!(
                policy
                    .authorize(&principal, &binding, method, Class::Normal)
                    .is_ok(),
                allowed
            );
            assert_eq!(
                policy
                    .authorize(&principal, &binding, method, Class::Emergency)
                    .is_ok(),
                role == ScopeRole::Worker
            );
        }
    }
}
