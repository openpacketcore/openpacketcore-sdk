//! Decode numeric payloads through a bounded owner on every JSON shape.
//! The outer framing has already checked the negotiated raw byte length.

use super::*;

struct Payload(Vec<u8>);
impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct PayloadVisitor;
        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = Payload;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded consensus numeric payload")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Payload, A::Error> {
                if input
                    .size_hint()
                    .is_some_and(|len| len > SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES)
                {
                    return Err(serde::de::Error::custom("consensus payload exceeds limit"));
                }
                let mut bytes = Vec::new();
                while let Some(byte) = input.next_element::<u8>()? {
                    if bytes.len() == SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
                        return Err(serde::de::Error::custom("consensus payload exceeds limit"));
                    }
                    if bytes.len() == bytes.capacity() {
                        let additional =
                            (SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES - bytes.len()).min(4096);
                        bytes
                            .try_reserve_exact(additional)
                            .map_err(serde::de::Error::custom)?;
                    }
                    bytes.push(byte);
                }
                Ok(Payload(bytes))
            }
        }
        input.deserialize_seq(PayloadVisitor)
    }
}

// Match the original inner struct's unknown-field and positional semantics.
// In particular, field order is not an admission rule: payload may come first.
#[derive(Deserialize)]
#[serde(rename = "ConsensusWireRequest")]
struct WireRequest<P = Payload> {
    schema_version: u16,
    identity: SessionConsensusIdentity,
    sender: SessionConsensusNodeId,
    family: ConsensusRpcFamily,
    payload: P,
}
impl From<WireRequest> for SessionConsensusWireRequest {
    fn from(value: WireRequest) -> Self {
        Self {
            schema_version: value.schema_version,
            identity: value.identity,
            sender: value.sender,
            family: value.family,
            payload: value.payload.0,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "SessionConsensusTransportRequest", deny_unknown_fields)]
enum Request<P = Payload> {
    Call {
        call_id: uuid::Uuid,
        request: WireRequest<P>,
    },
    RosterCall {
        call_id: uuid::Uuid,
        request: CompactRosterWireRequest,
    },
}

#[derive(Deserialize)]
#[serde(rename = "ConsensusWireResponse")]
struct WireResponse {
    result: Result<Payload, SessionConsensusPeerError>,
}

#[derive(Deserialize)]
#[serde(rename = "SessionConsensusTransportResponse", deny_unknown_fields)]
enum Response {
    Call {
        call_id: uuid::Uuid,
        response: WireResponse,
    },
}

pub(super) fn request(bytes: &[u8]) -> serde_json::Result<SessionConsensusTransportRequest> {
    // JSON permits payload before family. A non-owning first pass proves its
    // exact count against that family's bound before the owning visitor runs.
    // Compact roster requests already preflight their base64 extent and can
    // transfer the single decoded owner straight from this pass.
    match serde_json::from_slice::<Request<Count>>(bytes)? {
        Request::RosterCall { call_id, request } => {
            return Ok(SessionConsensusTransportRequest::RosterCall { call_id, request });
        }
        Request::Call { request, .. } => {
            if request.payload.0 > request.family.max_request_payload_bytes() {
                return Err(serde::de::Error::custom(
                    "consensus payload exceeds family limit",
                ));
            }
        }
    }
    Ok(match serde_json::from_slice::<Request>(bytes)? {
        Request::Call { call_id, request } => SessionConsensusTransportRequest::Call {
            call_id,
            request: request.into(),
        },
        Request::RosterCall { call_id, request } => {
            SessionConsensusTransportRequest::RosterCall { call_id, request }
        }
    })
}

struct Count(usize);
impl<'de> Deserialize<'de> for Count {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct CountVisitor;
        impl<'de> Visitor<'de> for CountVisitor {
            type Value = Count;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded consensus numeric payload")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Count, A::Error> {
                let mut count = 0;
                while input.next_element::<u8>()?.is_some() {
                    if count == SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
                        return Err(serde::de::Error::custom("consensus payload exceeds limit"));
                    }
                    count += 1;
                }
                Ok(Count(count))
            }
        }
        input.deserialize_seq(CountVisitor)
    }
}

pub(super) fn response(bytes: &[u8]) -> serde_json::Result<SessionConsensusTransportResponse> {
    let Response::Call { call_id, response } = serde_json::from_slice(bytes)?;
    Ok(SessionConsensusTransportResponse::Call {
        call_id,
        response: SessionConsensusWireResponse {
            result: response.result.map(|payload| payload.0),
        },
    })
}

#[cfg(test)]
mod tests;
