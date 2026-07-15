//! Exact, bounded binary codec for private consensus engine messages.
//!
//! The outer authenticated transport owns framing and peer identity. This
//! codec keeps encrypted session values byte-compact inside that envelope and
//! rejects oversized or trailing input before it reaches Openraft.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{CONSENSUS_MAX_RPC_PAYLOAD_BYTES, DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES};

/// Soft target for the encoded entry section of one AppendEntries request.
///
/// A singleton above this target is still admitted so Openraft can make
/// progress. The outer codec's hard RPC ceiling remains authoritative.
pub const DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES: usize = 1024 * 1024;

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

/// Admission result for the next ordered durable log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendEntriesBatchDecision {
    /// Retain this entry and continue considering the ordered suffix.
    Include,
    /// Retain this entry, then close the batch.
    IncludeAndStop,
    /// Close the batch before this entry without retaining it.
    StopBefore,
}

/// Stateful count-and-byte budget for one ordered AppendEntries entry section.
#[derive(Debug, Default)]
pub struct AppendEntriesBatchAccumulator {
    included_entries: usize,
    serialized_entry_bytes: usize,
    closed: bool,
}

impl AppendEntriesBatchAccumulator {
    /// Create an empty AppendEntries entry-section budget.
    pub const fn new() -> Self {
        Self {
            included_entries: 0,
            serialized_entry_bytes: 0,
            closed: false,
        }
    }

    /// Consider the next entry in log order without allocating its encoding.
    ///
    /// The first entry is retained even when it exceeds the soft byte target.
    /// Every later entry is admitted only when the complete ordered prefix
    /// remains within both the count and byte targets.
    pub fn consider<T>(
        &mut self,
        entry: &T,
    ) -> Result<AppendEntriesBatchDecision, ConsensusCodecError>
    where
        T: Serialize + ?Sized,
    {
        if self.closed || self.included_entries >= DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES {
            self.closed = true;
            return Ok(AppendEntriesBatchDecision::StopBefore);
        }

        let entry_bytes = postcard::experimental::serialized_size(entry)
            .map_err(|_| ConsensusCodecError::Encode)?;
        if self.included_entries != 0
            && entry_bytes
                > DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES
                    .saturating_sub(self.serialized_entry_bytes)
        {
            self.closed = true;
            return Ok(AppendEntriesBatchDecision::StopBefore);
        }

        self.included_entries += 1;
        self.serialized_entry_bytes = self
            .serialized_entry_bytes
            .checked_add(entry_bytes)
            .ok_or(ConsensusCodecError::Encode)?;
        let reached_count = self.included_entries == DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES;
        let reached_bytes =
            self.serialized_entry_bytes >= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES;
        if reached_count || reached_bytes {
            self.closed = true;
            Ok(AppendEntriesBatchDecision::IncludeAndStop)
        } else {
            Ok(AppendEntriesBatchDecision::Include)
        }
    }

    /// Return the number of entries already admitted to this batch.
    pub const fn included_entries(&self) -> usize {
        self.included_entries
    }

    /// Return the aggregate postcard size of entries already admitted.
    pub const fn serialized_entry_bytes(&self) -> usize {
        self.serialized_entry_bytes
    }
}

/// Encode one private consensus value with the exact SDK binary codec.
pub fn encode_bounded<T>(value: &T) -> Result<Vec<u8>, ConsensusCodecError>
where
    T: Serialize + ?Sized,
{
    let serialized_size =
        postcard::experimental::serialized_size(value).map_err(|_| ConsensusCodecError::Encode)?;
    if serialized_size > CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
        return Err(ConsensusCodecError::TooLarge);
    }
    let mut encoded = vec![0_u8; serialized_size];
    let actual_len = postcard::to_slice(value, encoded.as_mut_slice())
        .map_err(|_| ConsensusCodecError::Encode)?
        .len();
    if actual_len > serialized_size || actual_len > CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
        return Err(ConsensusCodecError::TooLarge);
    }
    encoded.truncate(actual_len);
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
    use std::cell::Cell;

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct BytePayload {
        bytes: Vec<u8>,
    }

    struct ExpandingSerialize {
        passes: Cell<u8>,
    }

    impl Serialize for ExpandingSerialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let pass = self.passes.get();
            self.passes.set(pass.saturating_add(1));
            if pass == 0 {
                serializer.serialize_u8(0)
            } else {
                serializer.serialize_bytes(&[0x5a; 32])
            }
        }
    }

    #[test]
    fn encrypted_sized_bytes_remain_compact() {
        let input = BytePayload {
            bytes: vec![0xff; 1_048_576],
        };
        let encoded = encode_bounded(&input).expect("bounded payload");

        assert_eq!(
            encoded,
            postcard::to_allocvec(&input).expect("existing postcard encoding")
        );
        assert!(encoded.len() < input.bytes.len() + 16);
        assert_eq!(
            decode_bounded::<BytePayload>(&encoded).expect("round trip"),
            input
        );
    }

    #[test]
    fn oversized_and_trailing_input_fail_closed() {
        assert_eq!(
            encode_bounded(&BytePayload {
                bytes: vec![0; CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1],
            }),
            Err(ConsensusCodecError::TooLarge)
        );
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

    #[test]
    fn second_pass_cannot_grow_beyond_the_preflight_allocation() {
        let input = ExpandingSerialize {
            passes: Cell::new(0),
        };

        assert_eq!(encode_bounded(&input), Err(ConsensusCodecError::Encode));
        assert_eq!(input.passes.get(), 2);
    }

    #[test]
    fn append_entries_budget_keeps_the_longest_ordered_prefix() {
        let entry = BytePayload {
            bytes: vec![0x5a; 400 * 1024],
        };
        let mut budget = AppendEntriesBatchAccumulator::new();

        assert_eq!(
            budget.consider(&entry),
            Ok(AppendEntriesBatchDecision::Include)
        );
        assert_eq!(
            budget.consider(&entry),
            Ok(AppendEntriesBatchDecision::Include)
        );
        assert_eq!(
            budget.consider(&entry),
            Ok(AppendEntriesBatchDecision::StopBefore)
        );
        assert_eq!(budget.included_entries(), 2);
        assert!(budget.serialized_entry_bytes() <= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
    }

    #[test]
    fn append_entries_budget_retains_an_oversized_first_entry_alone() {
        let entry = BytePayload {
            bytes: vec![0x5a; DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + 1],
        };
        let mut budget = AppendEntriesBatchAccumulator::new();

        assert_eq!(
            budget.consider(&entry),
            Ok(AppendEntriesBatchDecision::IncludeAndStop)
        );
        assert_eq!(
            budget.consider(&0_u8),
            Ok(AppendEntriesBatchDecision::StopBefore)
        );
        assert_eq!(budget.included_entries(), 1);
        assert!(budget.serialized_entry_bytes() > DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
    }

    #[test]
    fn append_entries_budget_closes_at_the_shared_entry_limit() {
        let mut budget = AppendEntriesBatchAccumulator::new();
        for index in 0..DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES {
            let expected = if index + 1 == DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES {
                AppendEntriesBatchDecision::IncludeAndStop
            } else {
                AppendEntriesBatchDecision::Include
            };
            assert_eq!(budget.consider(&0_u8), Ok(expected));
        }
        assert_eq!(
            budget.consider(&0_u8),
            Ok(AppendEntriesBatchDecision::StopBefore)
        );
        assert_eq!(
            budget.included_entries(),
            DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES
        );
    }
}
