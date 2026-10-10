use super::wire::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../docs/rfc/026-scope-authenticated-transport-vectors.json"
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
fn fixed_headers_and_payloads_round_trip_the_normative_vectors() {
    let v = vectors();
    for fixture in v["frames"].as_array().unwrap() {
        let encoded = bytes(&fixture["frame_hex"]);
        let frame = Frame::decode(&encoded).unwrap();
        assert_eq!(
            frame.header.encode().unwrap().as_slice(),
            bytes(&fixture["header_hex"])
        );
        assert_eq!(frame.payload, bytes(&fixture["payload_hex"]));
        assert_eq!(frame.encode().unwrap(), encoded);
        assert_eq!(frame.header.method, Method::SucceedClosed);
        assert_eq!(frame.header.class, Class::SafetyControl);
        assert_eq!(format!("{:?}", frame.header), "Header([redacted])");
    }
}

#[test]
fn malformed_or_oversized_headers_are_rejected_before_payload_read() {
    let v = vectors();
    let good = bytes(&v["frames"][0]["frame_hex"]);
    for length in 0..128 {
        assert!(Header::decode(&good[..length]).is_err());
    }
    for (offset, value) in [
        (5, 2),
        (6, 0),
        (6, 6),
        (7, 4),
        (8, 1),
        (9, 0),
        (9, 17),
        (10, 1),
        (11, 1),
    ] {
        let mut bad = good[..128].to_vec();
        bad[offset] = value;
        assert!(
            Header::decode(&bad).is_err(),
            "offset {offset} value {value}"
        );
    }
    let mut overflow = good[..128].to_vec();
    overflow[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    overflow[124..128].copy_from_slice(&(u32::MAX - 124).to_be_bytes());
    assert!(Header::decode(&overflow).is_err());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(Frame::decode(&trailing).is_err());
    assert!(Frame::decode(&good[..good.len() - 1]).is_err());
}

#[test]
fn header_correlation_pins_class_and_all_call_fields() {
    let v = vectors();
    let call = Header::decode(&bytes(&v["frames"][0]["header_hex"])).unwrap();
    let proof = Header::decode(&bytes(&v["frames"][1]["header_hex"])).unwrap();
    assert!(call.matches_attempt(&proof));
    for offset in [12, 44, 76, 92] {
        let mut encoded = proof.encode().unwrap();
        encoded[offset] ^= 1;
        assert!(!call.matches_attempt(&Header::decode(&encoded).unwrap()));
    }
    let mut encoded = proof.encode().unwrap();
    encoded[7] = 2;
    assert!(!call.matches_attempt(&Header::decode(&encoded).unwrap()));
}

#[test]
fn scope_binding_and_transport_digests_match_vectors() {
    let v = vectors();
    let encoded = bytes(&v["scope"]["transport_bytes_hex"]);
    let scope = ScopeBinding::decode(&encoded).unwrap();
    assert_eq!(scope.encode(), encoded);
    assert_eq!(
        scope.commitment().as_slice(),
        bytes(&v["scope"]["scope_commitment_hex"])
    );
    for fixture in v["read_requests"]
        .as_array()
        .unwrap()
        .iter()
        .chain(v["startup_requests"].as_array().unwrap())
    {
        let method = Method::try_from(fixture["method"].as_u64().unwrap() as u8).unwrap();
        let request_id = bytes(&fixture["request_id_hex"]).try_into().unwrap();
        let canonical = bytes(&fixture["canonical_request_hex"]);
        assert_eq!(
            transport_request_digest(method, &request_id, &canonical)
                .unwrap()
                .as_slice(),
            bytes(&fixture["digest_hex"])
        );
    }
    assert!(
        transport_request_digest(Method::SucceedClosed, &[1; 16], b"not a native digest").is_err()
    );
    for length in 0..encoded.len() {
        assert!(ScopeBinding::decode(&encoded[..length]).is_err());
    }
}

#[test]
fn proof_and_result_limits_and_closed_status_tags_are_enforced() {
    let v = vectors();
    let frame = Frame::decode(&bytes(&v["frames"][2]["frame_hex"])).unwrap();
    let result = ResultPayload::decode(&frame.payload).unwrap();
    assert_eq!(result.encode().unwrap(), frame.payload);
    assert_eq!(result.status, ResultStatus::Committed);
    for tag in [6, 127, 255] {
        let mut invalid = frame.payload.clone();
        invalid[32] = tag;
        assert!(ResultPayload::decode(&invalid).is_err());
    }
    for body in [vec![], vec![0, 0], vec![0, 6]] {
        assert!(ResultPayload::new([1; 32], ResultStatus::ProvenNoEffect, [0; 32], body).is_err());
    }
    assert!(ResultPayload::new([1; 32], ResultStatus::OutcomeUnknown, [0; 32], vec![1]).is_err());
    assert!(ResultPayload::new([1; 32], ResultStatus::CurrentView, [1; 32], vec![1]).is_err());
    let mut header = frame.header;
    header.kind = FrameKind::Proof;
    header.payload_len = MAX_PROOF_FRAME_BYTES - HEADER_BYTES + 1;
    assert!(Frame::new(header, vec![0; MAX_PROOF_FRAME_BYTES - HEADER_BYTES + 1]).is_err());
}

#[test]
fn prechallenge_refusal_is_a_correlated_fixed_size_no_effect_result() {
    let v = vectors();
    let fixture = v["frames"]
        .as_array()
        .unwrap()
        .iter()
        .find(|frame| frame["name"] == "succession_prechallenge_refusal")
        .unwrap();
    let frame = Frame::decode(&bytes(&fixture["frame_hex"])).unwrap();
    let call = Header::decode(&bytes(&v["frames"][0]["header_hex"])).unwrap();
    assert!(frame.header.matches_attempt(&call));
    assert_eq!(frame.header.kind, FrameKind::Result);
    assert_eq!(frame.header.payload_len, 71);
    let payload = ResultPayload::decode(&frame.payload).unwrap();
    assert_eq!(payload.nonce.as_slice(), bytes(&v["caller_nonce_hex"]));
    assert_eq!(payload.status, ResultStatus::ProvenNoEffect);
    assert_eq!(payload.own_execution, [0; 32]);
    assert_eq!(payload.body, [0, 2]);
    for reason in 1..=5 {
        let result = ResultPayload::new(
            payload.nonce,
            ResultStatus::ProvenNoEffect,
            [0; 32],
            vec![0, reason],
        )
        .unwrap()
        .encode()
        .unwrap();
        assert_eq!(result.len(), 71);
    }
}
