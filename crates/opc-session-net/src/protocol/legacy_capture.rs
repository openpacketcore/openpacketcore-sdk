//! Synthetic legacy transport capture. Run the ignored capture on the baseline
//! by overlaying this file, `legacy.json`, and its test module declaration only.
//! Production baseline: eb1a60bfdd838ebced25983e187f44ea024d0613.
//!
//! `OPC_SESSION_LEGACY_CAPTURE=tmp/session-legacy.json cargo test --locked
//! -p opc-session-net --lib protocol::legacy_capture::capture_legacy_frames
//! -- --exact --ignored --test-threads=1`
//!
//! From a clean checkout containing this harness, save `git rev-parse HEAD`,
//! then switch to the baseline above, create `crates/opc-session-net/src/protocol/`
//! (absent there), copy both files from that saved commit with
//! `git show COMMIT:crates/opc-session-net/src/protocol/FILE`, and append
//! `#[cfg(test)] mod legacy_capture;` to `protocol.rs`. Run the command above,
//! then restore `protocol.rs`, remove the overlaid directory and switch back.
//! Use `mkdir -p crates/opc-session-net/src/protocol/` for the directory creation.

use super::*;

fn identity() -> SessionConsensusIdentity {
    SessionConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::new("encoding-fixture").unwrap(),
        opc_consensus::ConsensusConfigurationId::from_bytes([3; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

pub(super) fn request(
    family: ConsensusRpcFamily,
    payload: Vec<u8>,
) -> SessionConsensusTransportRequest {
    SessionConsensusTransportRequest::from_wire_call(
        uuid::Uuid::from_bytes([1; 16]),
        SessionConsensusWireRequest::try_new(
            identity(),
            SessionConsensusNodeId::new(1).unwrap(),
            family,
            payload,
        )
        .unwrap(),
    )
    .unwrap()
}

pub(super) fn fixtures() -> Vec<(String, Vec<u8>, bool)> {
    let mut rows = Vec::new();
    for family in [
        ConsensusRpcFamily::Vote,
        ConsensusRpcFamily::AppendEntries,
        ConsensusRpcFamily::AppendEntriesRoster,
        ConsensusRpcFamily::InstallSnapshot,
        ConsensusRpcFamily::ForwardMutation,
        ConsensusRpcFamily::ForwardRosterMutation,
        ConsensusRpcFamily::ReadBarrier,
        ConsensusRpcFamily::TopologyAdmissionBarrier,
        ConsensusRpcFamily::LeadershipTransfer,
    ] {
        rows.push((
            family.as_str().to_owned(),
            serde_json::to_vec(&request(family, vec![0, 1, 9, 10, 99, 100, 255])).unwrap(),
            true,
        ));
    }
    let commands: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../opc-persist/src/consensus/capacity_tests/legacy.json"
    ))
    .unwrap();
    for row in commands {
        if row.get("payload_digest").is_none() {
            continue;
        }
        let binary = row["postcard"].as_str().unwrap();
        let payload = binary
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        rows.push((
            format!("command-{}", row["name"].as_str().unwrap()),
            serde_json::to_vec(&request(ConsensusRpcFamily::ForwardMutation, payload)).unwrap(),
            true,
        ));
    }
    for result in [
        Ok(vec![0, 9, 10, 99, 100, 255]),
        Err(SessionConsensusPeerError::Unavailable),
        Err(SessionConsensusPeerError::Timeout),
        Err(SessionConsensusPeerError::Authentication),
        Err(SessionConsensusPeerError::ScopeMismatch),
        Err(SessionConsensusPeerError::Protocol),
        Err(SessionConsensusPeerError::Rejected),
    ] {
        let name = format!("response-{}", rows.len());
        let response = SessionConsensusTransportResponse::Call {
            call_id: uuid::Uuid::from_bytes([1; 16]),
            response: SessionConsensusWireResponse { result },
        };
        rows.push((name, serde_json::to_vec(&response).unwrap(), false));
    }
    rows
}

fn capture() -> Vec<serde_json::Value> {
    fixtures().into_iter().map(|(name, bytes, request)| {
        let canonical = if request {
            let frame: SessionConsensusTransportRequest = serde_json::from_slice(&bytes).unwrap();
            frame.clone().into_wire_call().unwrap();
            serde_json::to_vec(&frame).unwrap()
        } else {
            let frame: SessionConsensusTransportResponse = serde_json::from_slice(&bytes).unwrap();
            serde_json::to_vec(&frame).unwrap()
        };
        assert_eq!(canonical, bytes);
        serde_json::json!({"name":name,"request":request,"json":String::from_utf8(bytes).unwrap()})
    }).collect()
}

#[test]
#[ignore = "writes a fixture only to an explicit capture destination"]
fn capture_legacy_frames() {
    let destination = std::env::var("OPC_SESSION_LEGACY_CAPTURE").unwrap();
    std::fs::write(
        destination,
        serde_json::to_string_pretty(&capture()).unwrap() + "\n",
    )
    .unwrap();
}

#[test]
fn legacy_frames() {
    let expected: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("legacy.json")).unwrap();
    assert_eq!(capture(), expected);
}

#[tokio::test]
async fn oversized_inner_payload_is_refused_by_frame_decoder() {
    let mut frame = request(
        ConsensusRpcFamily::ForwardMutation,
        vec![0; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES],
    );
    let SessionConsensusTransportRequest::Call { request, .. } = &mut frame else {
        unreachable!()
    };
    request.payload.push(0);
    let body = serde_json::to_vec(&frame).unwrap();
    let mut encoded = (body.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(&body);
    let decoded: Result<Option<SessionConsensusTransportRequest>, _> =
        read_authenticated_frame_within(
            &mut encoded.as_slice(),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(5),
        )
        .await;
    assert!(
        decoded.is_err(),
        "the payload ceiling must precede construction of an oversized owned request"
    );
}
