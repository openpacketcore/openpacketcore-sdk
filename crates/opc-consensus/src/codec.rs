//! Exact, bounded binary codec for private consensus engine messages.
//!
//! The outer authenticated transport owns framing and peer identity. This
//! codec keeps encrypted session values byte-compact inside that envelope and
//! rejects oversized or trailing input before it reaches Openraft.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::CONSENSUS_MAX_RPC_PAYLOAD_BYTES;

/// Redaction-safe binary codec failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConsensusCodecError {
    /// Encoded or received payload exceeded the shared admission ceiling.
    #[error("consensus payload exceeds the bounded codec limit")]
    TooLarge,
    /// The private engine value could not be encoded.
    #[error("consensus payload encoding failed")]
    Encode,
    /// The bounded input was malformed, non-canonical, or had trailing bytes.
    #[error("consensus payload decoding failed")]
    Decode,
}

/// Encode one private consensus value with the exact SDK binary codec.
pub fn encode_bounded<T>(value: &T) -> Result<Vec<u8>, ConsensusCodecError>
where
    T: Serialize + ?Sized,
{
    let encoded = postcard::to_allocvec(value).map_err(|_| ConsensusCodecError::Encode)?;
    if encoded.len() > CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
        return Err(ConsensusCodecError::TooLarge);
    }
    Ok(encoded)
}

/// Decode one complete private consensus value after enforcing the shared
/// byte ceiling.
pub fn decode_bounded<T>(encoded: &[u8]) -> Result<T, ConsensusCodecError>
where
    T: DeserializeOwned,
{
    if encoded.len() > CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
        return Err(ConsensusCodecError::TooLarge);
    }
    let (decoded, remainder) =
        postcard::take_from_bytes(encoded).map_err(|_| ConsensusCodecError::Decode)?;
    if !remainder.is_empty() {
        return Err(ConsensusCodecError::Decode);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct BytePayload {
        bytes: Vec<u8>,
    }

    #[test]
    fn encrypted_sized_bytes_remain_compact() {
        let input = BytePayload {
            bytes: vec![0xff; 1_048_576],
        };
        let encoded = encode_bounded(&input).expect("bounded payload");

        assert!(encoded.len() < input.bytes.len() + 16);
        assert_eq!(
            decode_bounded::<BytePayload>(&encoded).expect("round trip"),
            input
        );
    }

    #[test]
    fn oversized_and_trailing_input_fail_closed() {
        assert_eq!(
            decode_bounded::<BytePayload>(&vec![0; CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1]),
            Err(ConsensusCodecError::TooLarge)
        );

        let mut encoded = encode_bounded(&BytePayload {
            bytes: vec![1, 2, 3],
        })
        .expect("payload");
        encoded.push(0);
        assert_eq!(
            decode_bounded::<BytePayload>(&encoded),
            Err(ConsensusCodecError::Decode)
        );
    }
}
