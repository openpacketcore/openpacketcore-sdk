//! Runtime codecs are checked against the independently generated revision-2 vectors.

use super::{child_read_wire, proof::*, wire::*};
use opc_session_store::scope_batch::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../docs/rfc/026-scope-transport-revision2-vectors.json"
    ))
    .unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    let (pairs, remainder) = value.as_str().unwrap().as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn child_read_native_call_binds_execution_namespace_digest_and_raw_key_sets() {
    use super::rpc_server::NativeCall;
    let v = vectors();
    let child = &v["child_read"];
    let request = ScopeChildReadRequest::decode_canonical(&bytes(&child["request_hex"])).unwrap();
    let frame = Frame::decode(&bytes(&child["frames"][0]["frame_hex"])).unwrap();
    let canonical = request.encode_canonical().unwrap();
    let decoded = NativeCall::decode(&frame.header, &canonical, request.stamp().scope()).unwrap();
    assert_eq!(decoded.execution(), Some(request.stamp().execution()));
    for field in 0..2 {
        let mut header = frame.header.clone();
        if field == 0 {
            header.digest[0] ^= 1;
        } else {
            header.request_id[0] ^= 1;
        }
        assert!(NativeCall::decode(&header, &canonical, request.stamp().scope()).is_err());
    }
    let mut foreign = serde_json::to_value(request.stamp().scope()).unwrap();
    foreign["slot"] = serde_json::to_value([99_u8; 32]).unwrap();
    let foreign = serde_json::from_value(foreign).unwrap();
    assert!(NativeCall::decode(&frame.header, &canonical, &foreign).is_err());
    for fixture in child["negative_requests"].as_array().unwrap() {
        let encoded = bytes(&fixture["request_hex"]);
        let mut header = frame.header.clone();
        header.digest =
            transport_request_digest(Method::ChildRead, &header.request_id, &encoded).unwrap();
        assert!(
            NativeCall::decode(&header, &encoded, request.stamp().scope()).is_err(),
            "{}",
            fixture["name"]
        );
    }
}

#[test]
fn child_read_routing_requires_worker_and_a_data_class() {
    use super::{policy::*, PrincipalGrant};
    let v = vectors();
    let request =
        ScopeChildReadRequest::decode_canonical(&bytes(&v["child_read"]["request_hex"])).unwrap();
    let scope = ScopeBinding::from_scope(request.stamp().scope()).unwrap();
    let principal =
        opc_types::SpiffeId::new(request.stamp().execution().identity().as_str()).unwrap();
    for role in [
        ScopeRole::Worker,
        ScopeRole::Controller,
        ScopeRole::Observer,
    ] {
        let policy = ScopePolicy::new(vec![PrincipalGrant::new(
            principal.clone(),
            role,
            vec![scope.clone()],
        )
        .unwrap()])
        .unwrap();
        for class in [
            Class::SafetyControl,
            Class::Emergency,
            Class::EmergencyClassification,
            Class::Normal,
            Class::Maintenance,
        ] {
            let allowed = policy.authorize(&principal, &scope, Method::ChildRead, class);
            assert_eq!(
                allowed.is_ok(),
                role == ScopeRole::Worker && class != Class::SafetyControl
            );
            if let Ok(route) = allowed {
                assert!(route.requires_worker_proof());
            }
        }
    }
}

#[test]
fn child_read_revision_two_keeps_every_frame_kind_and_all_seventeen_methods() {
    let v = vectors();
    for method in 1..=17 {
        assert_eq!(Method::try_from(method).unwrap() as u8, method);
    }
    for status in 0..=7 {
        assert_eq!(ResultStatus::try_from(status).unwrap() as u8, status);
    }
    assert!(Method::try_from(18).is_err());
    assert!(ResultStatus::try_from(8).is_err());
    for group in [
        &v["authority_startup"]["frames"],
        &v["authority_startup"]["startup_frames"],
        &v["authority_startup"]["notice_frames"],
        &v["authority_startup"]["refusal_frames"],
        &v["child_read"]["frames"],
        &v["child_read"]["results"],
    ] {
        for fixture in group.as_array().unwrap() {
            let encoded = bytes(&fixture["frame_hex"]);
            assert_eq!(&encoded[4..6], &2_u16.to_be_bytes());
            let frame = Frame::decode(&encoded).unwrap();
            assert_eq!(
                frame.header.encode().unwrap().as_slice(),
                bytes(&fixture["header_hex"])
            );
            assert_eq!(frame.payload, bytes(&fixture["payload_hex"]));
            assert_eq!(frame.encode().unwrap(), encoded);
            let mut revision_one = encoded;
            revision_one[4..6].copy_from_slice(&1_u16.to_be_bytes());
            assert!(Frame::decode(&revision_one).is_err(), "{}", fixture["name"]);
        }
    }
}

#[test]
fn child_read_request_proof_and_complete_observations_match_reference_bytes() {
    let v = vectors();
    let child = &v["child_read"];
    let request = ScopeChildReadRequest::decode_canonical(&bytes(&child["request_hex"])).unwrap();
    assert_eq!(
        request.encode_canonical().unwrap(),
        bytes(&child["request_hex"])
    );
    let id = bytes(&child["request_id_hex"]).try_into().unwrap();
    assert_eq!(
        transport_request_digest(Method::ChildRead, &id, &request.encode_canonical().unwrap())
            .unwrap()
            .as_slice(),
        bytes(&child["digest_hex"])
    );
    let proof = PossessionProof::decode(&bytes(&child["frames"][2]["payload_hex"])).unwrap();
    assert_eq!(
        proof.claims.encode().unwrap(),
        bytes(&child["possession_input_hex"])
    );
    assert_eq!(
        proof.signature.as_slice(),
        bytes(&child["possession_signature_hex"])
    );
    proof.verify_against(&proof.claims).unwrap();
    let records = child["record_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| ScopeChildRecord::decode_canonical(&bytes(raw)).unwrap())
        .collect::<Vec<_>>();
    let binding = bytes(&v["authority_startup"]["exporters"][1]["binding_hex"])
        .try_into()
        .unwrap();
    for fixture in child["results"].as_array().unwrap() {
        let frame = Frame::decode(&bytes(&fixture["frame_hex"])).unwrap();
        let result = ResultPayload::decode(&frame.payload).unwrap();
        assert_eq!(result.status, ResultStatus::ChildObservation);
        assert_eq!(result.own_execution, [0; 32]);
        assert_eq!(result.body, bytes(&fixture["body_hex"]));
        let input = response_binding_input(&frame.header, &result, &binding).unwrap();
        assert_eq!(input, bytes(&fixture["response_binding"]["input_hex"]));
        assert_eq!(
            hash(&input).as_slice(),
            bytes(&fixture["response_binding"]["digest_hex"])
        );
        if fixture["name"] == "too_large" {
            assert_eq!(
                child_read_wire::decode_observation(&request, &result.body),
                Err(ScopeChildReadError::ObservationTooLarge)
            );
            assert_eq!(result.body, [1]);
        } else {
            let expected = match fixture["name"].as_str().unwrap() {
                "all_present" => vec![Some(records[0].clone()), Some(records[1].clone())],
                "all_missing" => vec![None, None],
                "mixed" => vec![Some(records[0].clone()), None],
                other => panic!("unknown observation fixture {other}"),
            };
            assert_eq!(
                child_read_wire::decode_observation(&request, &result.body).unwrap(),
                expected
            );
            assert_eq!(
                child_read_wire::encode_observation(&request, &expected).unwrap(),
                result.body
            );
        }
    }
}

#[test]
fn child_read_rejects_every_reference_mismatch_and_malformed_peer_observation() {
    let v = vectors();
    let child = &v["child_read"];
    let request = ScopeChildReadRequest::decode_canonical(&bytes(&child["request_hex"])).unwrap();
    for fixture in child["negative_responses"].as_array().unwrap() {
        if fixture.get("frame_hex").is_none() {
            assert!(
                Header::decode(&bytes(&fixture["header_hex"])).is_err(),
                "{}",
                fixture["name"]
            );
            continue;
        }
        let frame = Frame::decode(&bytes(&fixture["frame_hex"])).unwrap();
        let payload = ResultPayload::decode(&frame.payload).unwrap();
        assert_eq!(
            child_read_wire::decode_observation(&request, &payload.body),
            Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)),
            "{}",
            fixture["name"]
        );
    }
    for fixture in child["negative_requests"].as_array().unwrap() {
        assert_eq!(
            ScopeChildReadRequest::decode_canonical(&bytes(&fixture["request_hex"])),
            Err(ScopeBatchError::InvalidRequest),
            "{}",
            fixture["name"]
        );
    }
    let valid = bytes(&child["results"][0]["body_hex"]);
    for end in 0..valid.len() {
        assert_eq!(
            child_read_wire::decode_observation(&request, &valid[..end]),
            Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)),
            "prefix {end}"
        );
    }
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        child_read_wire::decode_observation(&request, &trailing),
        Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable))
    );
    assert_eq!(
        child_read_wire::decode_observation(
            &request,
            &vec![0; MAX_SCOPE_CHILD_OBSERVATION_BYTES + 1]
        ),
        Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable))
    );
}

#[test]
fn child_read_aggregate_overflow_never_encodes_a_partial_set() {
    use base64::Engine as _;
    let v = vectors();
    let child = &v["child_read"];
    let original = ScopeChildReadRequest::decode_canonical(&bytes(&child["request_hex"])).unwrap();
    let request = ScopeChildReadRequest::new(
        original.stamp(),
        (1..=3)
            .map(|n| ScopeChildKey::new([n; 32]).unwrap())
            .collect(),
    )
    .unwrap();
    let envelope = opc_crypto::CryptoEnvelopeV1 {
        algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
        key_id: opc_key::KeyId::new("child-read-fixture").unwrap(),
        nonce: vec![1; 12],
        aad: vec![2; 32],
        ciphertext_and_tag: vec![3; MAX_SCOPE_CHILD_VALUE_BYTES - 256],
    }
    .encode()
    .unwrap();
    let template = ScopeChildRecord::decode_canonical(&bytes(&child["record_hex"][0])).unwrap();
    let rows = request
        .keys()
        .iter()
        .map(|key| {
            let mut row = serde_json::to_value(&template).unwrap();
            row["key"] = serde_json::to_value(key).unwrap();
            row["value"] =
                Value::String(base64::engine::general_purpose::STANDARD.encode(&envelope));
            Some(serde_json::from_value::<ScopeChildRecord>(row).unwrap())
        })
        .collect::<Vec<_>>();
    assert!(
        rows[0].as_ref().unwrap().encode_canonical().unwrap().len() < MAX_SCOPE_CHILD_RECORD_BYTES
    );
    let encoded = child_read_wire::encode_observation(&request, &rows).unwrap();
    assert_eq!(encoded, [1]);
    assert_eq!(
        child_read_wire::decode_observation(&request, &encoded),
        Err(ScopeChildReadError::ObservationTooLarge)
    );
}
