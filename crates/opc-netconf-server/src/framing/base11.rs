//! NETCONF base 1.1 chunked framing.

use opc_mgmt_limits::MgmtLimits;

use super::FramingError;

pub(crate) const MAX_CHUNK_LENGTH_DIGITS: usize = 20;

/// Encodes one XML message as a single base 1.1 chunk.
pub fn encode_message(message: &[u8], limits: &MgmtLimits) -> Result<Vec<u8>, FramingError> {
    limits.validate()?;
    limits.check_request_bytes(message.len())?;

    let mut out = format!("\n#{}\n", message.len()).into_bytes();
    out.extend_from_slice(message);
    out.extend_from_slice(b"\n##\n");
    Ok(out)
}

/// Decodes one complete base 1.1 chunked frame.
pub fn decode_message(frame: &[u8], limits: &MgmtLimits) -> Result<Vec<u8>, FramingError> {
    limits.validate()?;
    let mut cursor = 0;
    let mut chunks = 0usize;
    let mut out = Vec::new();

    loop {
        if cursor + 2 > frame.len() || frame[cursor] != b'\n' || frame[cursor + 1] != b'#' {
            return Err(FramingError::InvalidChunkHeader);
        }
        cursor += 2;

        if cursor < frame.len() && frame[cursor] == b'#' {
            cursor += 1;
            if cursor >= frame.len() || frame[cursor] != b'\n' {
                return Err(FramingError::InvalidEndMarker);
            }
            cursor += 1;
            if chunks == 0 {
                return Err(FramingError::InvalidChunkHeader);
            }
            if !frame[cursor..].iter().all(u8::is_ascii_whitespace) {
                return Err(FramingError::TrailingBytes);
            }
            limits.check_request_bytes(out.len())?;
            return Ok(out);
        }

        let len_start = cursor;
        while cursor < frame.len() && frame[cursor].is_ascii_digit() {
            cursor += 1;
            if cursor - len_start > MAX_CHUNK_LENGTH_DIGITS {
                return Err(FramingError::InvalidChunkLength);
            }
        }
        if len_start == cursor || cursor >= frame.len() || frame[cursor] != b'\n' {
            return Err(FramingError::InvalidChunkHeader);
        }
        if frame[len_start] == b'0' {
            return Err(FramingError::InvalidChunkLength);
        }

        let len_str = std::str::from_utf8(&frame[len_start..cursor])
            .map_err(|_| FramingError::InvalidChunkLength)?;
        let chunk_len = len_str
            .parse::<usize>()
            .map_err(|_| FramingError::InvalidChunkLength)?;
        if chunk_len == 0 {
            return Err(FramingError::InvalidChunkLength);
        }
        cursor += 1;

        let next_chunks = chunks
            .checked_add(1)
            .ok_or(FramingError::InvalidChunkLength)?;
        limits.check_frame_chunks(next_chunks)?;

        let next_len = out
            .len()
            .checked_add(chunk_len)
            .ok_or(FramingError::InvalidChunkLength)?;
        limits.check_request_bytes(next_len)?;
        if frame.len().saturating_sub(cursor) < chunk_len {
            return Err(FramingError::MissingChunkData);
        }

        out.extend_from_slice(&frame[cursor..cursor + chunk_len]);
        cursor += chunk_len;
        chunks = next_chunks;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use opc_mgmt_limits::MgmtLimits;

    use super::*;

    #[test]
    fn round_trips_base11_message() {
        let limits = MgmtLimits::default();
        let encoded = encode_message(b"<rpc/>", &limits).expect("encode");
        assert_eq!(
            decode_message(&encoded, &limits).expect("decode"),
            b"<rpc/>"
        );
    }

    #[test]
    fn decodes_multiple_chunks() {
        let frame = b"\n#3\n<rp\n#3\nc/>\n##\n";
        assert_eq!(
            decode_message(frame, &MgmtLimits::default()).expect("decode"),
            b"<rpc/>"
        );
    }

    #[test]
    fn rejects_missing_chunk_data() {
        let err = decode_message(b"\n#10\nshort\n##\n", &MgmtLimits::default())
            .expect_err("missing data");
        assert_eq!(err, FramingError::MissingChunkData);
    }

    #[test]
    fn rejects_leading_zero_chunk_length() {
        let err =
            decode_message(b"\n#03\nabc\n##\n", &MgmtLimits::default()).expect_err("leading zero");
        assert_eq!(err, FramingError::InvalidChunkLength);
    }

    #[test]
    fn rejects_overlong_chunk_length_digit_run() {
        let mut frame = b"\n#".to_vec();
        frame.extend(std::iter::repeat_n(b'9', 20_000));
        frame.extend_from_slice(b"\n<rpc/>\n##\n");

        let err =
            decode_message(&frame, &MgmtLimits::default()).expect_err("overlong chunk length");

        assert_eq!(err, FramingError::InvalidChunkLength);
    }

    #[test]
    fn enforces_accumulated_size_limit() {
        let limits = MgmtLimits {
            max_request_bytes: 5,
            ..MgmtLimits::default()
        };
        let err = decode_message(b"\n#3\nabc\n#3\ndef\n##\n", &limits).expect_err("too large");
        assert!(matches!(err, FramingError::Limit(_)));
    }

    #[test]
    fn enforces_chunk_count_limit() {
        let limits = MgmtLimits {
            max_frame_chunks_per_message: 1,
            ..MgmtLimits::default()
        };
        let err = decode_message(b"\n#1\na\n#1\nb\n##\n", &limits).expect_err("too many chunks");
        assert_eq!(
            err,
            FramingError::Limit(opc_mgmt_limits::LimitsError::Exceeded {
                limit: "frame_chunks_per_message",
                max: 1,
                actual: 2,
            })
        );
    }
}
