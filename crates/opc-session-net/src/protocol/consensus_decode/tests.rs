use super::*;
use crate::protocol::legacy_capture;

fn wire(frame: &impl Serialize) -> Vec<u8> {
    let json = serde_json::to_vec(frame).unwrap();
    let mut bytes = (json.len() as u32).to_be_bytes().to_vec();
    bytes.extend(json);
    bytes
}

#[test]
fn every_captured_legacy_frame_preserves_its_decoded_result() {
    for (name, bytes, is_request) in legacy_capture::fixtures() {
        if is_request {
            let original =
                serde_json::from_slice::<SessionConsensusTransportRequest>(&bytes).unwrap();
            assert_eq!(request(&bytes).unwrap(), original, "{name}");
            let mut encoded = Vec::new();
            super::super::consensus_json::to_writer(
                &mut encoded,
                &super::super::consensus_json::BorrowedRequest(&original),
            )
            .unwrap();
            assert_eq!(encoded, bytes, "{name}");
        } else {
            assert_eq!(
                response(&bytes).unwrap(),
                serde_json::from_slice::<SessionConsensusTransportResponse>(&bytes).unwrap(),
                "{name}"
            );
        }
    }
}

#[test]
fn numeric_bytes_keep_all_adjacent_values_and_noncanonical_valid_json() {
    let payload: Vec<u8> = (0..=255)
        .flat_map(|a| (0..=255).flat_map(move |b| [a, b]))
        .collect();
    let frame = legacy_capture::request(ConsensusRpcFamily::AppendEntries, payload);
    let canonical = serde_json::to_vec(&frame).unwrap();
    assert_eq!(request(&canonical).unwrap(), frame);
    let mut encoded = Vec::new();
    super::super::consensus_json::to_writer(
        &mut encoded,
        &super::super::consensus_json::BorrowedRequest(&frame),
    )
    .unwrap();
    assert_eq!(encoded, canonical);
    let value = serde_json::to_value(&frame).unwrap();
    // Value sorts keys in a package build: payload can precede sender, and
    // whitespace, ignored inner fields and escaped enum names remain legal.
    let pretty = serde_json::to_string_pretty(&value)
        .unwrap()
        .replace("AppendEntries", "Append\\u0045ntries");
    assert_eq!(request(pretty.as_bytes()).unwrap(), frame);
    let mut value = value;
    value["Call"]["request"]["ignored"] = serde_json::json!([1, {"nested": true}]);
    assert_eq!(
        request(&serde_json::to_vec(&value).unwrap()).unwrap(),
        frame
    );
}

#[test]
fn payload_bounds_are_inclusive_for_request_and_response() {
    let frame = legacy_capture::request(
        ConsensusRpcFamily::ForwardMutation,
        vec![255; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES],
    );
    let json = serde_json::to_vec(&frame).unwrap();
    let decoded = request(&json).unwrap();
    let SessionConsensusTransportRequest::Call { request: inner, .. } = decoded else {
        unreachable!()
    };
    assert_eq!(inner.payload.len(), SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
    assert!(inner.payload.capacity() <= SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
    let mut over = frame;
    let SessionConsensusTransportRequest::Call { request: inner, .. } = &mut over else {
        unreachable!()
    };
    inner.payload.push(255);
    let json = serde_json::to_vec(&over).unwrap();
    assert!(request(&json).is_err());
    let old: SessionConsensusTransportRequest = serde_json::from_slice(&json).unwrap();
    assert!(old.into_wire_call().is_err());

    let mut frame = SessionConsensusTransportResponse::Call {
        call_id: uuid::Uuid::from_bytes([1; 16]),
        response: SessionConsensusWireResponse {
            result: Ok(vec![0; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES]),
        },
    };
    assert_eq!(
        response(&serde_json::to_vec(&frame).unwrap()).unwrap(),
        frame
    );
    let SessionConsensusTransportResponse::Call {
        response: inner, ..
    } = &mut frame;
    inner.result.as_mut().unwrap().push(0);
    assert!(response(&serde_json::to_vec(&frame).unwrap()).is_err());
}

#[test]
fn malformed_byte_elements_and_unknown_frame_kinds_keep_rejecting() {
    let frame = legacy_capture::request(ConsensusRpcFamily::Vote, vec![0]);
    let json = String::from_utf8(serde_json::to_vec(&frame).unwrap()).unwrap();
    for invalid in [
        "-1", "256", "1.0", "1e0", "null", "true", "[]", "{}", "\"0\"",
    ] {
        let input = json.replace("\"payload\":[0]", &format!("\"payload\":[{invalid}]"));
        assert!(serde_json::from_str::<SessionConsensusTransportRequest>(&input).is_err());
        assert!(request(input.as_bytes()).is_err(), "{invalid}");
    }
    for kind in ["BoundedAppend", "BoundedCall", "FutureCall"] {
        let input = format!("{{\"{kind}\":{{}}}}");
        let old = serde_json::from_str::<SessionConsensusTransportRequest>(&input).unwrap_err();
        assert_eq!(
            request(input.as_bytes()).unwrap_err().to_string(),
            old.to_string()
        );
        let old = serde_json::from_str::<SessionConsensusTransportResponse>(&input).unwrap_err();
        assert_eq!(
            response(input.as_bytes()).unwrap_err().to_string(),
            old.to_string()
        );
    }
}

#[test]
fn family_limit_precedes_payload_ownership_even_when_payload_is_first() {
    let frame = legacy_capture::request(ConsensusRpcFamily::LeadershipTransfer, vec![0; 1024]);
    assert_eq!(
        request(&serde_json::to_vec(&frame).unwrap()).unwrap(),
        frame
    );
    let mut value = serde_json::to_value(&frame).unwrap();
    value["Call"]["request"]["payload"]
        .as_array_mut()
        .unwrap()
        .push(0.into());
    let fields = &value["Call"]["request"];
    let input = format!("{{\"Call\":{{\"call_id\":{},\"request\":{{\"payload\":{},\"family\":{},\"sender\":{},\"identity\":{},\"schema_version\":{}}}}}}}", value["Call"]["call_id"], fields["payload"], fields["family"], fields["sender"], fields["identity"], fields["schema_version"]);
    assert!(request(input.as_bytes()).is_err());
    let old: SessionConsensusTransportRequest = serde_json::from_str(&input).unwrap();
    assert!(old.into_wire_call().is_err());
}

#[test]
fn counting_pass_stops_at_the_payload_bound_without_an_owner() {
    let at = serde_json::to_vec(&vec![0u8; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Count>(&at).unwrap().0,
        SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
    );
    let mut over = at;
    over.pop();
    over.extend_from_slice(b",0]");
    assert!(serde_json::from_slice::<Count>(&over).is_err());
}

#[tokio::test]
async fn exact_frame_bound_and_truncated_declarations_are_checked_before_payload() {
    let frame = legacy_capture::request(ConsensusRpcFamily::Vote, vec![0, 1, 255]);
    let encoded = wire(&frame);
    let length = encoded.len() - 4;
    assert_eq!(
        read_authenticated_frame_within(&mut encoded.as_slice(), length, Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap(),
        frame
    );
    let mut reader = encoded.as_slice();
    assert!(
        matches!(read_authenticated_frame_within(&mut reader, length - 1, Duration::from_secs(1)).await, Err(ProtocolError::FrameTooLarge(size)) if size == length)
    );
    assert_eq!(reader.len(), length, "refuse before reading the payload");
    let declared = u32::MAX.to_be_bytes();
    assert!(matches!(
        read_authenticated_frame_within(
            &mut declared.as_slice(),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1)
        )
        .await,
        Err(ProtocolError::FrameTooLarge(_))
    ));
    let declared = (MAX_NEGOTIATED_FRAME_SIZE as u32).to_be_bytes();
    assert!(
        matches!(read_authenticated_frame_within(&mut declared.as_slice(), MAX_NEGOTIATED_FRAME_SIZE, Duration::from_secs(1)).await, Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
}

#[tokio::test]
async fn response_frame_bound_precedes_payload_decoding() {
    let frame = SessionConsensusTransportResponse::Call {
        call_id: uuid::Uuid::from_bytes([1; 16]),
        response: SessionConsensusWireResponse {
            result: Ok(vec![0, 1, 255]),
        },
    };
    let encoded = wire(&frame);
    let length = encoded.len() - 4;
    assert_eq!(
        read_consensus_response_frame(&mut encoded.as_slice(), length)
            .await
            .unwrap(),
        frame
    );
    let mut reader = encoded.as_slice();
    assert!(matches!(
        read_consensus_response_frame(&mut reader, length - 1).await,
        Err(ProtocolError::FrameTooLarge(size)) if size == length
    ));
    assert_eq!(reader.len(), length);
    let declared = u32::MAX.to_be_bytes();
    assert!(matches!(
        read_consensus_response_frame(&mut declared.as_slice(), MAX_NEGOTIATED_FRAME_SIZE).await,
        Err(ProtocolError::FrameTooLarge(_))
    ));
}

#[tokio::test]
async fn borrowed_writer_preserves_budget_and_does_not_publish_oversize_frames() {
    let frame = legacy_capture::request(ConsensusRpcFamily::AppendEntries, vec![255; 4097]);
    let expected = wire(&frame);
    let length = expected.len() - 4;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut actual = Vec::new();
    write_consensus_frame_bounded_until(&mut actual, &frame, length, deadline)
        .await
        .unwrap();
    assert_eq!(actual, expected);
    let mut refused = Vec::new();
    assert!(matches!(
        write_consensus_frame_bounded_until(&mut refused, &frame, length - 1, deadline).await,
        Err(ProtocolError::FrameTooLarge(_))
    ));
    assert!(refused.is_empty());
    let deadline = tokio::time::Instant::now() - Duration::from_secs(1);
    assert!(
        matches!(write_consensus_frame_bounded_until(&mut refused, &frame, length, deadline).await, Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
    );
    assert!(refused.is_empty());
}
