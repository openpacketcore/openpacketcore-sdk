//! NETCONF base 1.0 end-marker framing.

use opc_mgmt_limits::MgmtLimits;

use super::FramingError;

/// NETCONF 1.0 end-of-message marker.
pub const END_MARKER: &[u8] = b"]]>]]>";

/// Encodes one XML message using base 1.0 framing.
pub fn encode_message(message: &[u8], limits: &MgmtLimits) -> Result<Vec<u8>, FramingError> {
    limits.validate()?;
    limits.check_request_bytes(message.len())?;

    let mut out = Vec::with_capacity(message.len() + END_MARKER.len());
    out.extend_from_slice(message);
    out.extend_from_slice(END_MARKER);
    Ok(out)
}

/// Decodes one complete base 1.0 frame.
pub fn decode_message(frame: &[u8], limits: &MgmtLimits) -> Result<Vec<u8>, FramingError> {
    limits.validate()?;
    let Some(marker_at) = find_subslice(frame, END_MARKER) else {
        return Err(FramingError::MissingEndMarker);
    };
    let trailing = &frame[marker_at + END_MARKER.len()..];
    if !trailing.iter().all(u8::is_ascii_whitespace) {
        return Err(FramingError::TrailingBytes);
    }

    let message = &frame[..marker_at];
    limits.check_request_bytes(message.len())?;
    Ok(message.to_vec())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use opc_mgmt_limits::MgmtLimits;

    use super::*;

    #[test]
    fn round_trips_base10_message() {
        let limits = MgmtLimits::default();
        let encoded = encode_message(b"<rpc/>", &limits).expect("encode");
        assert_eq!(
            decode_message(&encoded, &limits).expect("decode"),
            b"<rpc/>"
        );
    }

    #[test]
    fn rejects_missing_marker() {
        let err = decode_message(b"<rpc/>", &MgmtLimits::default()).expect_err("missing");
        assert_eq!(err, FramingError::MissingEndMarker);
    }

    #[test]
    fn enforces_decoded_size_limit() {
        let limits = MgmtLimits {
            max_request_bytes: 3,
            ..MgmtLimits::default()
        };
        let err = decode_message(b"abcd]]>]]>", &limits).expect_err("too large");
        assert!(matches!(err, FramingError::Limit(_)));
    }
}
