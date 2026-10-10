//! Scan frames must remain current-worker observations with fixed work classes.
use super::*;
use opc_session_store::scope_batch::{ScopeChildKey, ScopeClaimKey};
use opc_session_store::scope_scan::*;

fn succession() -> ScopeAuthorityRequest {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
    ))
    .unwrap();
    let hex = vectors["authority_requests"][1]["canonical_postcard_hex"]
        .as_str()
        .unwrap();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    ScopeAuthorityRequest::decode_canonical(&bytes).unwrap()
}
fn stamp() -> ScopeAuthorityStamp {
    let request = succession();
    let ScopeAuthorityOperation::SucceedClosed {
        predecessor,
        execution,
        ..
    } = request.operation()
    else {
        panic!("frozen succession")
    };
    let mut claims = serde_json::to_value(predecessor).unwrap();
    claims["revision"] = serde_json::json!(request.expected_revision() + 1);
    claims["execution"] = serde_json::to_value(execution).unwrap();
    let stamp: ScopeAuthorityStamp = serde_json::from_value(claims).unwrap();
    ScopeAuthorityStamp::decode_canonical(&stamp.encode_canonical().unwrap()).unwrap()
}
fn put(bytes: &mut Vec<u8>, body: &[u8]) {
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(body);
}
fn open_claim() -> ScopeScanOpenRequest {
    // Test-only untrusted observation bytes; this deliberately creates no grant.
    let mut bytes = vec![1];
    put(&mut bytes, &stamp().encode_canonical().unwrap());
    put(&mut bytes, &succession().encode_canonical().unwrap());
    bytes.extend_from_slice(&256_u32.to_be_bytes());
    bytes.extend_from_slice(&(ScopeScanPageLimits::default().payload_bytes() as u32).to_be_bytes());
    ScopeScanOpenRequest::decode_canonical(&bytes).unwrap()
}
fn token() -> ScopeScanViewToken {
    let mut bytes = vec![1, 5];
    put(&mut bytes, &stamp().encode_canonical().unwrap());
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&[7; 16]);
    match ScopeScanRequest::decode_canonical(&bytes).unwrap() {
        ScopeScanRequest::Close(token) => token,
        _ => unreachable!(),
    }
}
fn requests() -> Vec<(u8, ScopeScanRequest)> {
    vec![
        (12, ScopeScanRequest::Open(Box::new(open_claim()))),
        (
            13,
            ScopeScanRequest::Page {
                view: token(),
                cursor: ScopeScanCursor::from_bytes(&[1; 98]).unwrap(),
            },
        ),
        (
            14,
            ScopeScanRequest::Lookup {
                view: token(),
                key: ScopeScanLookupKey::Child(ScopeChildKey::new([3; 32]).unwrap()),
            },
        ),
        (
            15,
            ScopeScanRequest::Classify {
                view: token(),
                key: ScopeScanLookupKey::Claim(ScopeClaimKey::new([4; 32]).unwrap()),
            },
        ),
        (16, ScopeScanRequest::Close(token())),
    ]
}
fn call(method: Method, body: &[u8]) -> Header {
    let binding = ScopeBinding::from_scope(stamp().scope()).unwrap();
    let id = [9; 16];
    Header {
        kind: FrameKind::Call,
        class: if method as u8 == 15 {
            Class::EmergencyClassification
        } else {
            Class::Normal
        },
        method,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: id,
        digest: transport_request_digest(method, &id, body).unwrap(),
        payload_len: body.len() + 36,
    }
}

#[test]
fn scan_methods_bind_the_exact_current_boot_and_complete_canonical_request() {
    for (tag, request) in requests() {
        let method = Method::try_from(tag).expect("scan requests have distinct native method tags");
        let bytes = request.encode_canonical().unwrap();
        let header = call(method, &bytes);
        let decoded = NativeCall::decode(&header, &bytes, request.stamp().scope()).unwrap();
        assert_eq!(
            decoded.execution(),
            Some(request.stamp().execution()),
            "every scan operation proves its exact worker boot"
        );
        for changed in 0..2 {
            let mut invalid = header.clone();
            if changed == 0 {
                invalid.request_id[0] ^= 1;
            } else {
                invalid.digest[0] ^= 1;
            }
            assert!(NativeCall::decode(&invalid, &bytes, request.stamp().scope()).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        let updated = call(method, &trailing);
        assert!(NativeCall::decode(&updated, &trailing, request.stamp().scope()).is_err());
        let mut other = serde_json::to_value(request.stamp().scope()).unwrap();
        other["slot"] = serde_json::to_value([99_u8; 32]).unwrap();
        let other: ScopeId = serde_json::from_value(other).unwrap();
        let other = ScopeId::decode_canonical(&other.encode_canonical().unwrap()).unwrap();
        assert!(NativeCall::decode(&header, &bytes, &other).is_err());
        for other in 12..=16 {
            if tag == other {
                continue;
            }
            let wrong = call(Method::try_from(other).unwrap(), &bytes);
            assert!(
                NativeCall::decode(&wrong, &bytes, request.stamp().scope()).is_err(),
                "a valid digest cannot relabel a scan operation"
            );
        }
    }
}

#[test]
fn scan_digests_keep_distinct_methods_request_ids_and_canonical_payloads() {
    let bytes = ScopeScanRequest::Close(token()).encode_canonical().unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for tag in 12..=16 {
        let method = Method::try_from(tag).expect("scan digest method is supported");
        let digest = transport_request_digest(method, &[1; 16], &bytes).unwrap();
        assert!(seen.insert(digest));
        assert_ne!(
            digest,
            transport_request_digest(method, &[2; 16], &bytes).unwrap()
        );
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_ne!(
            digest,
            transport_request_digest(method, &[1; 16], &changed).unwrap()
        );
        assert!(transport_request_digest(method, &[0; 16], &bytes).is_err());
    }
}

#[test]
fn scan_routes_require_workers_and_exact_normal_or_classification_channels() {
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
        for tag in 12..=16 {
            let method = Method::try_from(tag).expect("scan method routes before body allocation");
            for class in CLASSES {
                let allowed = role == ScopeRole::Worker
                    && class
                        == if tag == 15 {
                            Class::EmergencyClassification
                        } else {
                            Class::Normal
                        };
                let routed = policy.authorize(&principal, &binding, method, class);
                assert_eq!(routed.is_ok(), allowed);
                if let Ok(routed) = routed {
                    assert!(routed.requires_worker_proof());
                }
            }
        }
    }
}

#[test]
fn scan_frame_bounds_cover_the_native_envelope_without_widening_authority_frames() {
    for tag in 12..=16 {
        let method = Method::try_from(tag).expect("bounded scan method exists");
        assert_eq!(method.command_limit(), MAX_SCOPE_SCAN_REQUEST_BYTES);
        let body = vec![1; MAX_SCOPE_SCAN_REQUEST_BYTES];
        let mut header = call(method, &body);
        let encoded = header.encode().unwrap();
        assert_eq!(
            Header::decode(&encoded).unwrap().payload_len,
            MAX_SCOPE_SCAN_REQUEST_BYTES + 36
        );
        header.payload_len += 1;
        assert!(header.encode().is_err());
        let mut result = call(method, &[1])
            .response(FrameKind::Result, MAX_SCOPE_SCAN_REPLY_BYTES + 69)
            .unwrap();
        assert!(result.payload_len + HEADER_BYTES <= MAX_SCOPE_FRAME_BYTES);
        result.payload_len = MAX_SCOPE_FRAME_BYTES - HEADER_BYTES + 1;
        assert!(result.encode().is_err());
    }
    assert_eq!(Method::Current.command_limit(), MAX_AUTHORITY_BYTES);
    assert_eq!(Method::ApplyBatch.command_limit(), MAX_SCOPE_COMMAND_BYTES);
}

#[test]
fn scan_results_use_observation_status_without_minting_worker_authority() {
    let status = ResultStatus::try_from(6).expect("scan responses have a distinct observation tag");
    for response in [
        ScopeScanResponse::Closed,
        ScopeScanResponse::Failure(ScopeScanRequestFailure::Final(
            ScopeScanError::StaleAuthority,
        )),
        ScopeScanResponse::Failure(ScopeScanRequestFailure::Retryable(
            ScopeScanRetryCause::Unavailable,
        )),
    ] {
        let bytes = response.encode_canonical().unwrap();
        let payload = ResultPayload::new([1; 32], status, [0; 32], bytes.clone()).unwrap();
        let decoded = ResultPayload::decode(&payload.encode().unwrap()).unwrap();
        assert_eq!(decoded.status as u8, 6);
        assert_eq!(decoded.own_execution, [0; 32]);
        assert_eq!(decoded.body, bytes);
        assert!(ResultPayload::new([1; 32], status, [2; 32], bytes).is_err());
    }
    assert!(ResultPayload::new([1; 32], status, [0; 32], Vec::new()).is_err());
}
