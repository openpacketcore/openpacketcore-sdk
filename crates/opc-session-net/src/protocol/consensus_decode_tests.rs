//! Real framed receive regressions with independent owned DTO/Serde oracles.

use super::*;

mod dispatch;
#[cfg(feature = "insecure-test")]
pub(crate) use dispatch::Count as ConsensusDecodeDispatchCount;
pub(crate) use dispatch::{deserialize_request, deserialize_response};

fn request(payload: Vec<u8>) -> SessionConsensusTransportRequest {
    SessionConsensusTransportRequest::Call {
        call_id: uuid::Uuid::from_u128(0x7f50_f66f_9f44_4bc4_a71e_6830_8d62_dc93),
        request: SessionConsensusWireRequest::try_new(
            opc_consensus::ConsensusIdentity::new(
                opc_consensus::ConsensusClusterId::from_bytes([17; 32]),
                opc_consensus::ConsensusConfigurationId::from_bytes([251; 32]),
                opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
            ),
            opc_consensus::ConsensusNodeId::new(1).unwrap(),
            ConsensusRpcFamily::AppendEntries,
            payload,
        )
        .unwrap(),
    }
}

fn response(payload: Vec<u8>) -> SessionConsensusTransportResponse {
    SessionConsensusTransportResponse::Call {
        call_id: uuid::Uuid::from_u128(3),
        response: SessionConsensusWireResponse {
            result: Ok(payload),
        },
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

async fn receive_request(body: &[u8]) -> Result<SessionConsensusTransportRequest, ProtocolError> {
    let bytes = framed(body);
    let mut reader = bytes.as_slice();
    read_authenticated_frame_within(&mut reader, body.len(), Duration::from_secs(1))
        .await
        .map(|frame| frame.expect("complete in-memory frame"))
}

async fn receive_response(body: &[u8]) -> Result<SessionConsensusTransportResponse, ProtocolError> {
    let bytes = framed(body);
    let mut reader = bytes.as_slice();
    read_consensus_response_frame(&mut reader, body.len()).await
}

async fn request_oracle(body: &[u8]) -> bool {
    // This independent decoder remains the unchanged derived DTO, including
    // both the shared inner deserializer and outer unknown-field rejection.
    let reference = serde_json::from_slice::<SessionConsensusTransportRequest>(body);
    match (receive_request(body).await, reference) {
        (Ok(actual), Ok(expected)) => {
            assert!(actual == expected);
            assert_eq!(
                serde_json::to_vec(&actual).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
            assert!(actual.into_wire_call() == expected.into_wire_call());
            true
        }
        (Err(ProtocolError::Serialization(error)), Err(_)) => {
            assert_eq!(error.to_string(), "serialization error");
            false
        }
        (actual, expected) => {
            panic!("request/reference admission mismatch: {actual:?} {expected:?}")
        }
    }
}

async fn response_oracle(body: &[u8]) -> bool {
    let reference = serde_json::from_slice::<SessionConsensusTransportResponse>(body);
    match (receive_response(body).await, reference) {
        (Ok(actual), Ok(expected)) => {
            assert!(actual == expected);
            assert_eq!(
                serde_json::to_vec(&actual).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
            let SessionConsensusTransportResponse::Call {
                response: actual, ..
            } = actual;
            let SessionConsensusTransportResponse::Call {
                response: expected, ..
            } = expected;
            assert_eq!(actual.validate(), expected.validate());
            true
        }
        (Err(ProtocolError::Serialization(error)), Err(_)) => {
            assert_eq!(error.to_string(), "serialization error");
            false
        }
        (actual, expected) => {
            panic!("response/reference admission mismatch: {actual:?} {expected:?}")
        }
    }
}

fn replace_once(body: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let at = body
        .windows(needle.len())
        .position(|bytes| bytes == needle)
        .unwrap();
    let mut changed = body[..at].to_vec();
    changed.extend_from_slice(replacement);
    changed.extend_from_slice(&body[at + needle.len()..]);
    changed
}

#[test]
fn serde_dispatch_probe_counts_the_real_shared_vec_only() {
    for len in [0, 1, 4096] {
        let body = serde_json::to_vec(&request(vec![73; len])).unwrap();
        let count = dispatch::Count::start();
        let decoded: SessionConsensusTransportRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            count.finish(),
            len,
            "fixed identity tuples are not payload Vec work"
        );
        assert!(decoded == request(vec![73; len]));
        let body = serde_json::to_vec(&response(vec![73; len])).unwrap();
        let count = dispatch::Count::start();
        let decoded: SessionConsensusTransportResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(count.finish(), len);
        assert!(decoded == response(vec![73; len]));
    }
}

#[tokio::test]
async fn ordinary_request_decodes_without_per_byte_serde_dispatch() {
    for len in [1_573_769, 1_880_759] {
        let frame = request((0_u8..=255).cycle().take(len).collect());
        let mut body = serde_json::to_vec(&frame).unwrap();
        let reference: SessionConsensusTransportRequest = serde_json::from_slice(&body).unwrap();
        assert!(reference == frame);
        let count = dispatch::Count::start();
        let actual = receive_request(&body).await.unwrap();
        let elements = count.finish();
        body.fill(0);
        assert!(
            actual == reference,
            "returned payload owns its complete byte sequence"
        );
        assert!(actual.into_wire_call() == reference.into_wire_call());
        assert_eq!(
            elements, 0,
            "CONSENSUS_OUTER_DECODE_WORK_RED: the real request payload still dispatched {elements} Serde sequence elements for {len} bytes",
        );
    }
}

#[tokio::test]
async fn ordinary_response_decodes_without_per_byte_serde_dispatch() {
    let len = SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES;
    let frame = response((0_u8..=255).cycle().take(len).collect());
    let mut body = serde_json::to_vec(&frame).unwrap();
    let reference: SessionConsensusTransportResponse = serde_json::from_slice(&body).unwrap();
    let count = dispatch::Count::start();
    let actual = receive_response(&body).await.unwrap();
    let elements = count.finish();
    body.fill(0);
    assert!(actual == reference);
    let SessionConsensusTransportResponse::Call { response, .. } = actual;
    assert_eq!(response.validate(), Ok(()));
    assert_eq!(
        elements, 0,
        "CONSENSUS_OUTER_DECODE_WORK_RED: the real success payload still dispatched {elements} Serde sequence elements for {len} bytes",
    );
}

#[tokio::test]
async fn outer_decoder_matches_every_adjacent_byte_pair_and_small_boundaries() {
    let mut pairs = Vec::new();
    for left in 0_u8..=255 {
        for right in 0_u8..=255 {
            pairs.extend_from_slice(&[left, right]);
        }
    }
    // The oracle emits each digit from Display, separately from both the
    // production formatter and decoder; every adjacent pair occurs in order.
    let mut array = String::from("[");
    for (index, byte) in pairs.iter().enumerate() {
        if index != 0 {
            array.push(',');
        }
        array.push_str(&byte.to_string());
    }
    array.push(']');
    let body = replace_once(
        &serde_json::to_vec(&request(Vec::new())).unwrap(),
        b"\"payload\":[]",
        format!("\"payload\":{array}").as_bytes(),
    );
    let actual = receive_request(&body).await.unwrap();
    assert!(actual == request(pairs.clone()));
    assert_eq!(serde_json::to_vec(&actual).unwrap(), body);
    let body = replace_once(
        &serde_json::to_vec(&response(Vec::new())).unwrap(),
        b"\"Ok\":[]",
        format!("\"Ok\":{array}").as_bytes(),
    );
    let actual = receive_response(&body).await.unwrap();
    assert!(actual == response(pairs));
    assert_eq!(serde_json::to_vec(&actual).unwrap(), body);

    for len in [
        0, 1, 255, 256, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193,
    ] {
        let payload: Vec<_> = (0_u8..=255).cycle().take(len).collect();
        assert!(request_oracle(&serde_json::to_vec(&request(payload.clone())).unwrap()).await);
        assert!(response_oracle(&serde_json::to_vec(&response(payload)).unwrap()).await);
    }
}

#[tokio::test]
async fn outer_decoder_preserves_malformed_and_noncanonical_fallbacks() {
    let original = serde_json::to_vec(&request(vec![0; 4096])).unwrap();
    for token in [
        "-1", "256", "999", "+1", "1.0", "1e0", "01", "true", "null", "\"0\"", "{}", "[0]", "",
    ] {
        let body = replace_once(
            &original,
            b"\"payload\":[0,",
            format!("\"payload\":[{token},").as_bytes(),
        );
        assert!(
            !request_oracle(&body).await,
            "reject malformed u8 token {token:?}"
        );
    }
    for (needle, replacement) in [
        (b"]}}}".as_slice(), b",]}}}".as_slice()),
        (b"]}}}", b"],\"payload\":[]}}}"),
        (b"]}}}", b"]},\"unexpected\":0}}"),
        (
            b"{\"Call\":{",
            b"{\"Call\":{\"call_id\":\"00000000-0000-0000-0000-000000000000\",",
        ),
        (b"\"sender\":1", b"\"sender\":0"),
        (b"\"sender\":1", b"\"sender\":9223372036854775808"),
        (b"\"configuration_epoch\":1", b"\"configuration_epoch\":0"),
        (
            b"\"configuration_epoch\":1",
            b"\"configuration_epoch\":1,\"configuration_epoch\":1",
        ),
        (b"\"AppendEntries\"", b"\"UnknownFamily\""),
    ] {
        assert!(!request_oracle(&replace_once(&original, needle, replacement)).await);
    }
    for tail in [b"x".as_slice(), b"{}", b"\0"] {
        let mut body = original.clone();
        body.extend_from_slice(tail);
        assert!(!request_oracle(&body).await);
    }
    for remove in [1, 2, 3, 4, 17] {
        assert!(!request_oracle(&original[..original.len() - remove]).await);
    }

    // All are accepted by the existing wire decoder but are outside this
    // canonical subset. In each case the real Vec visitor must still run.
    let mut noncanonical = vec![
        replace_once(&original, b"\"payload\":[0", b"\"payload\":[ 0"),
        replace_once(&original, b"\"payload\":", b"\"pay\\u006coad\":"),
        replace_once(&original, b"]}}}", b"],\"ignored\":0}}}"),
        replace_once(
            &original,
            b"\"sender\":1",
            b"\"sender\":1,\"ignored\":{\"payload\":[0]}",
        ),
        replace_once(
            &original,
            b"\"configuration_epoch\":1",
            b"\"configuration_epoch\":1,\"ignored\":0",
        ),
        replace_once(&original, b"7f50f66f", b"7F50F66F"),
        replace_once(&original, b"\"schema_version\":1", b"\"schema_version\":0"),
    ];
    let mut spaced = b" \n".to_vec();
    spaced.extend_from_slice(&original);
    noncanonical.push(spaced);
    let mut trailing = original.clone();
    trailing.extend_from_slice(b"\n ");
    noncanonical.push(trailing);
    noncanonical.push(replace_once(
        &original,
        b"\"schema_version\":1,",
        format!("\"ignored\":\"{}\",\"schema_version\":1,", "x".repeat(2048)).as_bytes(),
    ));
    noncanonical.push(replace_once(
        &original,
        b"\"schema_version\":1,",
        b"\"ignored\":0,\"ignored\":1,\"schema_version\":1,",
    ));
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    noncanonical.push(serde_json::to_vec_pretty(&value).unwrap());
    for body in noncanonical {
        assert!(request_oracle(&body).await);
        let count = dispatch::Count::start();
        let decoded = receive_request(&body).await.unwrap();
        let elements = count.finish();
        let SessionConsensusTransportRequest::Call { request, .. } = decoded else {
            panic!("ordinary request");
        };
        assert_eq!(request.payload, vec![0; 4096]);
        assert_eq!(
            elements, 4096,
            "noncanonical request retains original Vec dispatch"
        );
    }

    let original = serde_json::to_vec(&response(vec![255; 4096])).unwrap();
    for token in ["-1", "256", "255.0", "2.55e2", "0255", "true", "null", "{}"] {
        let body = replace_once(
            &original,
            b"\"Ok\":[255",
            format!("\"Ok\":[{token}").as_bytes(),
        );
        assert!(!response_oracle(&body).await);
    }
    for (needle, replacement) in [
        (b"]}}}}".as_slice(), b",]}}}}".as_slice()),
        (b"]}}}}", b"],\"Err\":\"Protocol\"}}}}"),
        (b"]}}}}", b"]},\"result\":{\"Ok\":[]}}}}"),
        (b"]}}}}", b"]}},\"unexpected\":0}}"),
    ] {
        assert!(!response_oracle(&replace_once(&original, needle, replacement)).await);
    }
    for body in [
        replace_once(&original, b"\"Ok\":[255", b"\"Ok\":[ 255"),
        replace_once(&original, b"]}}}}", b"]},\"ignored\":0}}}"),
        replace_once(&original, b"\"Ok\":", b"\"O\\u006b\":"),
    ] {
        assert!(response_oracle(&body).await);
        let count = dispatch::Count::start();
        receive_response(&body).await.unwrap();
        assert_eq!(count.finish(), 4096);
    }
}

#[tokio::test]
async fn outer_decoder_preserves_family_schema_and_response_limits() {
    for family in [
        ConsensusRpcFamily::Vote,
        ConsensusRpcFamily::AppendEntries,
        ConsensusRpcFamily::InstallSnapshot,
        ConsensusRpcFamily::ForwardMutation,
        ConsensusRpcFamily::ReadBarrier,
        ConsensusRpcFamily::TopologyAdmissionBarrier,
        ConsensusRpcFamily::LeadershipTransfer,
        ConsensusRpcFamily::AppendEntriesRoster,
        ConsensusRpcFamily::ForwardRosterMutation,
    ] {
        let SessionConsensusTransportRequest::Call {
            call_id,
            mut request,
        } = request(vec![255; 8193])
        else {
            panic!("ordinary fixture");
        };
        request.family = family;
        // Raw ordinary envelopes preserve their later rejection for compact
        // roster families and the smaller leadership-transfer payload bound.
        let raw = SessionConsensusTransportRequest::Call {
            call_id,
            request: request.clone(),
        };
        assert!(request_oracle(&serde_json::to_vec(&raw).unwrap()).await);
        if compact_roster_family(family) {
            let compact =
                SessionConsensusTransportRequest::from_wire_call(call_id, request).unwrap();
            assert!(request_oracle(&serde_json::to_vec(&compact).unwrap()).await);
        }
    }
    for len in [
        SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
        SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1,
    ] {
        let SessionConsensusTransportRequest::Call {
            call_id,
            mut request,
        } = request(Vec::new())
        else {
            panic!("ordinary fixture");
        };
        request.payload = vec![255; len];
        let raw = SessionConsensusTransportRequest::Call { call_id, request };
        let body = serde_json::to_vec(&raw).unwrap();
        assert!(request_oracle(&body).await);
        let actual = receive_request(&body).await.unwrap();
        assert_eq!(
            actual.into_wire_call().is_ok(),
            len == SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
        );
        let body = serde_json::to_vec(&response(vec![255; len])).unwrap();
        assert!(response_oracle(&body).await);
        let SessionConsensusTransportResponse::Call { response, .. } =
            receive_response(&body).await.unwrap();
        assert_eq!(
            response.validate().is_ok(),
            len == SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
        );
    }
    for error in [
        SessionConsensusPeerError::Unavailable,
        SessionConsensusPeerError::Timeout,
        SessionConsensusPeerError::Authentication,
        SessionConsensusPeerError::ScopeMismatch,
        SessionConsensusPeerError::Protocol,
        SessionConsensusPeerError::Rejected,
    ] {
        let frame = SessionConsensusTransportResponse::Call {
            call_id: uuid::Uuid::nil(),
            response: SessionConsensusWireResponse { result: Err(error) },
        };
        assert!(response_oracle(&serde_json::to_vec(&frame).unwrap()).await);
    }
}

#[tokio::test]
async fn outer_decoder_keeps_the_actual_payload_owner_and_frame_ceiling() {
    use super::inbound_decode_observation::{self, Observation, Phase};

    let expected = request(vec![197; 8193]);
    let body = serde_json::to_vec(&expected).unwrap();
    let observation = Observation::new();
    let scope = inbound_decode_observation::install(&observation);
    let actual = receive_request(&body).await.unwrap();
    let report = observation.report();
    drop(scope);
    assert!(actual == expected);
    let SessionConsensusTransportRequest::Call { request, .. } = actual else {
        panic!("ordinary request");
    };
    assert_eq!(report.request_samples, 1);
    assert_eq!(report.decode_samples, 1);
    let sample = report.request.unwrap();
    assert_eq!(sample.address, request.payload.as_ptr() as usize);
    assert_eq!(sample.length, request.payload.len());
    assert_eq!(sample.capacity, request.payload.capacity());
    assert_eq!(sample.current.distinct_allocations, 2);
    assert!(sample.current.aliases_agree);
    let raw = sample
        .current
        .owners
        .iter()
        .find(|owner| owner.phase == Phase::DecodeRaw)
        .unwrap();
    assert_eq!(raw.length, body.len());
    assert_ne!(raw.address, sample.address);
    assert_eq!(sample.current.capacity, raw.capacity + sample.capacity);
    assert!(report.current.owners.is_empty());
    assert_eq!(report.registered, report.released);
    assert!(report.release_identity_valid);
    assert!(!report.decode.unwrap().rejected);

    for limit in [0, body.len() - 1] {
        let bytes = framed(&body);
        let mut reader = bytes.as_slice();
        let result: Result<Option<SessionConsensusTransportRequest>, _> =
            read_authenticated_frame_within(&mut reader, limit, Duration::from_secs(1)).await;
        assert!(matches!(result, Err(ProtocolError::FrameTooLarge(len)) if len == body.len()));
        assert_eq!(reader, body, "oversized prefix must not read any body byte");
    }
    let body = serde_json::to_vec(&response(vec![197; 8193])).unwrap();
    let bytes = framed(&body);
    let mut reader = bytes.as_slice();
    let result = read_consensus_response_frame(&mut reader, body.len() - 1).await;
    assert!(matches!(result, Err(ProtocolError::FrameTooLarge(len)) if len == body.len()));
    assert_eq!(reader, body);
}

#[tokio::test(start_paused = true)]
async fn outer_decoder_keeps_idle_partial_frame_and_cancel_release() {
    use super::inbound_decode_observation::{self, Observation};

    let (_peer, mut reader) = tokio::io::duplex(16);
    let idle: Option<SessionConsensusTransportRequest> =
        read_authenticated_frame_within(&mut reader, 8192, Duration::from_secs(1))
            .await
            .unwrap();
    assert!(idle.is_none());
    let (mut peer, mut reader) = tokio::io::duplex(16);
    peer.write_all(&[0]).await.unwrap();
    let partial: Result<Option<SessionConsensusTransportRequest>, _> =
        read_authenticated_frame_within(&mut reader, 8192, Duration::from_secs(1)).await;
    assert!(
        matches!(partial, Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
    );

    let observation = Observation::new();
    let scope = inbound_decode_observation::install(&observation);
    let (mut peer, mut reader) = tokio::io::duplex(16 * 1024);
    peer.write_all(&8193_u32.to_be_bytes()).await.unwrap();
    peer.write_all(&[b' '; 8192]).await.unwrap();
    let read = tokio::spawn(async move {
        let result: Result<Option<SessionConsensusTransportRequest>, _> =
            read_authenticated_frame_within(&mut reader, 8193, Duration::from_secs(1)).await;
        result
    });
    observation.wait_for_raw_read(8193, 8192).await;
    read.abort();
    assert!(read.await.unwrap_err().is_cancelled());
    let report = observation.report();
    drop(scope);
    assert!(report.current.owners.is_empty());
    assert_eq!(report.registered, report.released);
    assert!(report.release_identity_valid);
    assert_eq!(report.decode_samples, 0);
    assert_eq!(report.request_samples, 0);
}
