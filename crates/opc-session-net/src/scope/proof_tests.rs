use super::{proof::*, wire::*};
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
fn field(value: &Value, name: &str) -> String {
    value[name].as_str().unwrap().to_owned()
}
fn observation(v: &Value) -> BootObservation {
    let f = &v["startup_observation"]["fields"];
    BootObservation {
        namespace: field(f, "namespace"),
        pod_name: field(f, "pod_name"),
        pod_uid: bytes(&f["pod_uid_hex"]).try_into().unwrap(),
        service_account: field(f, "service_account_name"),
        service_account_uid: bytes(&f["service_account_uid_hex"]).try_into().unwrap(),
        container_name: field(f, "container_name"),
        container_id: field(f, "container_id"),
        started_at: field(f, "started_at"),
    }
}

#[test]
fn observed_boot_and_startup_signing_inputs_match_language_independent_vectors() {
    let v = vectors();
    let observation = observation(&v);
    assert_eq!(
        observation.input().unwrap(),
        bytes(&v["startup_observation"]["input_hex"])
    );
    assert_eq!(
        observation.digest().unwrap().as_slice(),
        bytes(&v["startup_observation"]["digest_hex"])
    );
    let scope = ScopeBinding::decode(&bytes(&v["scope"]["transport_bytes_hex"])).unwrap();
    let boot = &v["executions"][0];
    for (index, mode) in [StartupMode::Liveness, StartupMode::Candidate]
        .into_iter()
        .enumerate()
    {
        let exporter = v["exporters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| {
                e["purpose"]
                    == if index == 0 {
                        "boot-liveness"
                    } else {
                        "boot-candidate"
                    }
            })
            .unwrap();
        let claims = StartupClaims {
            mode,
            scope: scope.clone(),
            workload: observation.pod_uid,
            process: bytes(&boot["process_hex"]).try_into().unwrap(),
            public_key: bytes(&boot["public_key_hex"]).try_into().unwrap(),
            credential_digest: bytes(&v["startup_credential"]["sha256"])
                .try_into()
                .unwrap(),
            observation: observation.digest().unwrap(),
            challenge: bytes(&v["challenge_hex"]).try_into().unwrap(),
            binding: bytes(&exporter["binding_hex"]).try_into().unwrap(),
        };
        let input = claims.encode().unwrap();
        assert_eq!(input, bytes(&v["startup_proofs"][index]["input_hex"]));
        assert_eq!(
            StartupClaims::decode(&input).unwrap().encode().unwrap(),
            input
        );
        let signature = bytes(&v["startup_proofs"][index]["signature_hex"])
            .try_into()
            .unwrap();
        verify_signature(&claims.public_key, &input, &signature).unwrap();
        let proof = StartupProof::new(
            field(&v["startup_credential"], "raw_ascii").into_bytes(),
            claims,
            signature,
        )
        .unwrap();
        assert_eq!(
            proof.encode().unwrap(),
            bytes(&v["startup_proofs"][index]["proof_body_hex"])
        );
    }
}

#[test]
fn startup_claims_reject_invalid_contexts_trailing_bytes_and_points() {
    let v = vectors();
    let valid = bytes(&v["startup_proofs"][1]["input_hex"]);
    let parsed = StartupClaims::decode(&valid).unwrap();
    let mut changed = parsed.clone();
    changed.public_key = [0; 33];
    assert!(changed.encode().is_err());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(StartupClaims::decode(&trailing).is_err());
    for length in 0..valid.len() {
        assert!(StartupClaims::decode(&valid[..length]).is_err());
    }
    let position = valid.len() - 64 - 3;
    let mut malformed = valid.clone();
    malformed[position + 2] = 0;
    assert!(StartupClaims::decode(&malformed).is_err());
    let key = parsed.public_key;
    let signature = bytes(&v["startup_proofs"][1]["signature_hex"])
        .try_into()
        .unwrap();
    for offset in [0, position, valid.len() - 1] {
        let mut tampered = valid.clone();
        tampered[offset] ^= 1;
        assert!(verify_signature(&key, &tampered, &signature).is_err());
    }
    let high = v["negative_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "high_s_candidate_signature")
        .unwrap();
    let input = valid;
    let key = parsed.public_key;
    assert!(verify_signature(
        &key,
        &input,
        &bytes(&high["signature_hex"]).try_into().unwrap()
    )
    .is_err());
}

#[test]
fn final_termination_and_local_quiescence_bytes_match_vectors() {
    let v = vectors();
    let fixture = &v["closure_evidence"]["final_termination"];
    let f = &fixture["fields"];
    let observation = TerminationObservation {
        namespace: field(f, "namespace"),
        pod_name: field(f, "pod_name"),
        pod_uid: bytes(&f["pod_uid_hex"]).try_into().unwrap(),
        container_name: field(f, "container_name"),
        container_id: field(f, "container_id"),
        exit_code: field(f, "exit_code").parse().unwrap(),
        signal: field(f, "signal").parse().unwrap(),
        reason: field(f, "reason"),
        message: field(f, "message"),
        started_at: field(f, "started_at"),
        finished_at: field(f, "finished_at"),
        record: AuthorityReference::new(
            field(f, "record_uid").into_bytes(),
            field(f, "record_revision").into_bytes(),
        )
        .unwrap(),
    };
    let input = observation
        .input(&bytes(&fixture["predecessor_stamp_hex"]))
        .unwrap();
    assert_eq!(input, bytes(&fixture["input_hex"]));
    assert_eq!(hash(&input).as_slice(), bytes(&fixture["digest_hex"]));
    let mut opaque = observation.clone();
    opaque.message = "line1\nline2\0".into();
    assert!(opaque
        .input(&bytes(&fixture["predecessor_stamp_hex"]))
        .is_ok());
    let mut missing_finish = observation;
    missing_finish.finished_at.clear();
    assert!(missing_finish
        .input(&bytes(&fixture["predecessor_stamp_hex"]))
        .is_err());
    let fixture = &v["closure_evidence"]["local_quiescence"];
    let input = local_quiescence_input(
        &bytes(&fixture["current_stamp_hex"]),
        &bytes(&fixture["fence_nonce_hex"]).try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(input, bytes(&fixture["input_hex"]));
    assert_eq!(hash(&input).as_slice(), bytes(&fixture["digest_hex"]));
    assert!(local_quiescence_input(&bytes(&fixture["current_stamp_hex"]), &[0; 32]).is_err());
}

#[test]
fn possession_and_response_bind_every_correlated_call_field() {
    let v = vectors();
    let call = Header::decode(&bytes(&v["frames"][0]["header_hex"])).unwrap();
    let reference = &v["fixture_parameters"]["authority_reference"];
    let claims = PossessionClaims {
        call,
        caller_nonce: bytes(&v["caller_nonce_hex"]).try_into().unwrap(),
        execution: bytes(&v["executions"][1]["execution_digest_hex"])
            .try_into()
            .unwrap(),
        public_key: bytes(&v["scope_possession"]["public_key_hex"])
            .try_into()
            .unwrap(),
        authority: Some(
            AuthorityReference::new(
                field(reference, "record_uid").into_bytes(),
                field(reference, "revision").into_bytes(),
            )
            .unwrap(),
        ),
        challenge: bytes(&v["challenge_hex"]).try_into().unwrap(),
        binding: bytes(&v["exporters"][0]["binding_hex"]).try_into().unwrap(),
    };
    let input = claims.encode().unwrap();
    assert_eq!(input, bytes(&v["scope_possession"]["input_hex"]));
    assert_eq!(
        PossessionClaims::decode(&input).unwrap().encode().unwrap(),
        input
    );
    let proof = PossessionProof {
        claims: claims.clone(),
        signature: bytes(&v["scope_possession"]["signature_hex"])
            .try_into()
            .unwrap(),
    };
    assert_eq!(
        proof.encode().unwrap(),
        bytes(&v["frames"][1]["payload_hex"])
    );
    proof.verify_against(&claims).unwrap();
    let mut wrong = claims.clone();
    wrong.call.class = Class::Normal;
    assert!(proof.verify_against(&wrong).is_err());
    let mut wrong = claims.clone();
    wrong.binding[0] ^= 1;
    assert!(proof.verify_against(&wrong).is_err());
    let mut wrong = claims;
    wrong.caller_nonce[0] ^= 1;
    assert!(proof.verify_against(&wrong).is_err());
    let direction_offset = b"openpacketcore/scope/process-possession/v1\0".len() + 2;
    let mut controller = input;
    controller[direction_offset] = 1;
    assert!(PossessionClaims::decode(&controller).is_err());

    let frame = Frame::decode(&bytes(&v["frames"][2]["frame_hex"])).unwrap();
    let result = ResultPayload::decode(&frame.payload).unwrap();
    let binding = bytes(&v["exporters"][1]["binding_hex"]).try_into().unwrap();
    let input = response_binding_input(&frame.header, &result, &binding).unwrap();
    assert_eq!(input, bytes(&v["response_binding"]["input_hex"]));
    assert_eq!(
        hash(&input).as_slice(),
        bytes(&v["response_binding"]["digest_hex"])
    );
}

#[test]
fn startup_request_and_call_payload_codecs_use_the_exact_golden_bodies() {
    let v = vectors();
    for fixture in v["startup_requests"].as_array().unwrap() {
        let encoded = bytes(&fixture["canonical_request_hex"]);
        let request = StartupRequest::decode(&encoded).unwrap();
        assert_eq!(request.encode().unwrap(), encoded);
        assert_eq!(
            request.observation.as_slice(),
            bytes(&v["startup_observation"]["digest_hex"])
        );
    }
    let encoded = bytes(&v["frames"][0]["payload_hex"]);
    let payload = CallPayload::decode(Method::SucceedClosed, &encoded).unwrap();
    assert_eq!(payload.encode(Method::SucceedClosed).unwrap(), encoded);
    let mut wrong = encoded.clone();
    wrong[..32].fill(0);
    assert!(CallPayload::decode(Method::SucceedClosed, &wrong).is_err());
    let mut length = encoded;
    length[32..36].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CallPayload::decode(Method::SucceedClosed, &length).is_err());
}
