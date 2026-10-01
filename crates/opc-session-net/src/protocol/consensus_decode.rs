//! Closed-type fast path for canonical consensus numeric payload arrays.
//! Other representations retain the original Serde decoder and its errors.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use super::{
    compact_roster_family, SessionConsensusTransportRequest, SessionConsensusTransportResponse,
    SessionConsensusWireRequest, SessionConsensusWireResponse,
    SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};

const MIN_FAST_BYTES: usize = 4096;
const MAX_METADATA_BYTES: usize = 1024;

// This recognizes only the shortest decimal representation of one u8. In
// particular, signs, whitespace, exponents, floats and leading zeros miss.
fn byte_token(token: &[u8]) -> Option<u8> {
    match token {
        [ones @ b'0'..=b'9'] => Some(*ones - b'0'),
        [tens @ b'1'..=b'9', ones @ b'0'..=b'9'] => Some((*tens - b'0') * 10 + (*ones - b'0')),
        [hundreds @ b'1'..=b'2', tens @ b'0'..=b'9', ones @ b'0'..=b'9'] => {
            let value = u16::from(*hundreds - b'0') * 100
                + u16::from(*tens - b'0') * 10
                + u16::from(*ones - b'0');
            u8::try_from(value).ok()
        }
        _ => None,
    }
}

struct ValidatedArray<'a> {
    tokens: &'a [u8],
    count: usize,
}

impl<'a> ValidatedArray<'a> {
    fn new(encoded: &'a [u8]) -> Option<Self> {
        let tokens = encoded.strip_prefix(b"[")?.strip_suffix(b"]")?;
        let mut count = 0;
        for token in tokens.split(|byte| *byte == b',') {
            byte_token(token)?;
            count += 1;
            if count > SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
                return None;
            }
        }
        (count >= MIN_FAST_BYTES).then_some(Self { tokens, count })
    }

    fn decode(self) -> Option<Vec<u8>> {
        // The complete grammar and exact count were proved before allocation.
        // The caller has also proved the original canonical metadata and bound.
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(self.count).ok()?;
        for token in self.tokens.split(|byte| *byte == b',') {
            decoded.push(byte_token(token)?);
        }
        Some(decoded)
    }
}

struct Metadata<'a> {
    bytes: [u8; MAX_METADATA_BYTES],
    len: usize,
    array: ValidatedArray<'a>,
}

impl<'a> Metadata<'a> {
    fn new(bytes: &'a [u8], marker: &[u8], suffix: &[u8]) -> Option<Self> {
        // The large array must be the final field of this exact outer shape.
        // A bounded field search only proposes a span; it confers no authority.
        if !bytes.starts_with(b"{\"Call\":{") {
            return None;
        }
        let body = bytes.strip_suffix(suffix)?;
        let header = &body[..body.len().min(MAX_METADATA_BYTES)];
        let start = header
            .windows(marker.len())
            .position(|part| part == marker)?
            + marker.len();
        let len = start.checked_add(2)?.checked_add(suffix.len())?;
        if len > MAX_METADATA_BYTES {
            return None;
        }
        let array = ValidatedArray::new(body.get(start..)?)?;
        let mut metadata = [0; MAX_METADATA_BYTES];
        metadata[..start].copy_from_slice(&bytes[..start]);
        metadata[start..start + 2].copy_from_slice(b"[]");
        metadata[start + 2..len].copy_from_slice(suffix);
        Some(Self {
            bytes: metadata,
            len,
            array,
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn matches(&self, frame: &impl Serialize) -> bool {
        // Serialize the original owned DTO, whose payload is still empty.
        // Equality proves every other token, field, order and enum wrapper.
        // Ignored inner fields therefore miss, preserving their Serde fallback.
        let mut writer = Matches(self.as_slice());
        serde_json::to_writer(&mut writer, frame).is_ok() && writer.0.is_empty()
    }
}

struct Matches<'a>(&'a [u8]);

impl Write for Matches<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.0.starts_with(bytes) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.0 = &self.0[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Reuse the real inner types, including identity and ordinal validation. These
// small outer views avoid firing the decoded-request observation on a temporary
// empty payload. Only the actual completed request is observed below.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum RequestMetadata {
    Call {
        call_id: uuid::Uuid,
        request: SessionConsensusWireRequest,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum ResponseMetadata {
    Call {
        call_id: uuid::Uuid,
        response: SessionConsensusWireResponse,
    },
}

fn canonical_request(bytes: &[u8]) -> Option<SessionConsensusTransportRequest> {
    let metadata = Metadata::new(bytes, b"\"payload\":", b"}}}")?;
    let RequestMetadata::Call { call_id, request } =
        serde_json::from_slice(metadata.as_slice()).ok()?;
    if compact_roster_family(request.family)
        || request.validate().is_err()
        || !request.payload.is_empty()
        || metadata.array.count > request.family.max_request_payload_bytes()
    {
        return None;
    }
    let mut frame = SessionConsensusTransportRequest::Call { call_id, request };
    if !metadata.matches(&frame) {
        return None;
    }
    let SessionConsensusTransportRequest::Call { request, .. } = &mut frame else {
        return None;
    };
    request.payload = metadata.array.decode()?;
    #[cfg(all(test, feature = "test-control"))]
    super::inbound_decode_observation::capture_request(request);
    Some(frame)
}

fn canonical_response(bytes: &[u8]) -> Option<SessionConsensusTransportResponse> {
    let metadata = Metadata::new(bytes, b"\"Ok\":", b"}}}}")?;
    let ResponseMetadata::Call { call_id, response } =
        serde_json::from_slice(metadata.as_slice()).ok()?;
    if !matches!(&response.result, Ok(payload) if payload.is_empty()) {
        return None;
    }
    let mut frame = SessionConsensusTransportResponse::Call { call_id, response };
    if !metadata.matches(&frame) {
        return None;
    }
    let SessionConsensusTransportResponse::Call { response, .. } = &mut frame;
    response.result = Ok(metadata.array.decode()?);
    Some(frame)
}

/// Decode the closed ordinary request shape, retaining the original fallback.
pub(super) fn request(bytes: &[u8]) -> serde_json::Result<SessionConsensusTransportRequest> {
    match canonical_request(bytes) {
        Some(frame) => Ok(frame),
        None => serde_json::from_slice(bytes),
    }
}

/// Decode the closed successful response shape, retaining the original fallback.
pub(super) fn response(bytes: &[u8]) -> serde_json::Result<SessionConsensusTransportResponse> {
    match canonical_response(bytes) {
        Some(frame) => Ok(frame),
        None => serde_json::from_slice(bytes),
    }
}
