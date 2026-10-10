//! Canonical bounded codecs shared by transport and durable replay helpers.

use super::*;

fn bounded_vec<'de, D, T, const LIMIT: usize>(decoder: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const LIMIT: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const LIMIT: usize> serde::de::Visitor<'de> for Bounded<T, LIMIT> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {LIMIT} scope entries")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if seq.size_hint().is_some_and(|count| count > LIMIT) {
                return Err(serde::de::Error::custom("scope count exceeds profile"));
            }
            let mut entries = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(LIMIT));
            while entries.len() < LIMIT {
                let Some(entry) = seq.next_element()? else {
                    return Ok(entries);
                };
                entries.push(entry);
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("scope count exceeds profile"));
            }
            Ok(entries)
        }
    }
    decoder.deserialize_seq(Bounded::<T, LIMIT>(std::marker::PhantomData))
}

macro_rules! sequence_decoder {
    ($name:ident, $limit:expr) => {
        pub(super) fn $name<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
            decoder: D,
        ) -> Result<Vec<T>, D::Error> {
            bounded_vec::<D, T, { $limit }>(decoder)
        }
    };
}
sequence_decoder!(children, MAX_SCOPE_BATCH_CHILDREN);
sequence_decoder!(claims, MAX_SCOPE_CHILD_CLAIMS);
sequence_decoder!(counters, SCOPE_COUNTERS);
sequence_decoder!(
    claim_conditions,
    MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS
);

macro_rules! canonical_codec {
    ($ty:ty, $limit:expr) => {
        impl $ty {
            /// Encode the validated value using the shared canonical Postcard codec.
            /// These bytes carry no independent authority or commitment proof.
            pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeBatchError> {
                self.validate()?;
                let bytes =
                    postcard::to_allocvec(self).map_err(|_| ScopeBatchError::InvalidRequest)?;
                if bytes.len() > $limit {
                    return Err(ScopeBatchError::InvalidRequest);
                }
                Ok(bytes)
            }
            /// Decode bounded canonical bytes, rejecting trailing bytes and
            /// alternate encodings. Counts are checked before vector allocation.
            pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeBatchError> {
                if bytes.len() > $limit {
                    return Err(ScopeBatchError::InvalidRequest);
                }
                let (value, trailing): (Self, _) = postcard::take_from_bytes(bytes)
                    .map_err(|_| ScopeBatchError::InvalidRequest)?;
                if !trailing.is_empty() || value.encode_canonical()? != bytes {
                    return Err(ScopeBatchError::InvalidRequest);
                }
                Ok(value)
            }
        }
    };
}
canonical_codec!(
    ScopeBatchRequest,
    MAX_SCOPE_BATCH_COMMAND_BYTES - COMMAND_HEADROOM
);
canonical_codec!(ScopeBatchOutcome, COMMAND_HEADROOM);
canonical_codec!(
    ScopeBatchAttempt,
    crate::scope_authority::MAX_SCOPE_AUTHORITY_RECORD_BYTES
);
canonical_codec!(ScopeBatchReceipt, COMMAND_HEADROOM);
canonical_codec!(ScopeBatchLookup, COMMAND_HEADROOM);
canonical_codec!(ScopeBatchReopen, MAX_SCOPE_BATCH_REOPEN_BYTES);
canonical_codec!(ScopeBatchError, MAX_SCOPE_BATCH_ERROR_BYTES);

impl ScopeBatchError {
    fn validate(&self) -> Result<(), Self> {
        let Self::Conflict(conflicts) = self else {
            return Ok(());
        };
        if conflicts.children.len() > MAX_SCOPE_BATCH_CHILDREN
            || conflicts.claims.len() > MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS
            || conflicts.counters.len() > SCOPE_COUNTERS
            || conflicts.children.iter().any(|key| key.0 == [0; 32])
            || conflicts.claims.iter().any(|key| key.0 == [0; 32])
            || conflicts
                .counters
                .iter()
                .any(|counter| usize::from(*counter) >= SCOPE_COUNTERS)
            || conflicts.children.iter().collect::<HashSet<_>>().len() != conflicts.children.len()
            || conflicts.claims.iter().collect::<HashSet<_>>().len() != conflicts.claims.len()
            || conflicts.counters.iter().collect::<HashSet<_>>().len() != conflicts.counters.len()
        {
            return Err(Self::InvalidRequest);
        }
        Ok(())
    }
}

impl ScopeBatchLookup {
    pub(super) fn validate(&self) -> Result<(), ScopeBatchError> {
        match self {
            Self::Applied(outcome) => outcome.validate(),
            _ => Ok(()),
        }
    }
}

impl ScopeBatchOutcome {
    pub(super) fn validate(&self) -> Result<(), ScopeBatchError> {
        if usize::from(self.lane) >= SCOPE_BATCH_LANES
            || !(1..=COUNTER_MAX).contains(&self.sequence)
            || !(self.sequence..=COUNTER_MAX).contains(&self.revision)
            || self.rows.len() > MAX_SCOPE_BATCH_CHILDREN
            || self.counters.iter().any(|value| *value > COUNTER_MAX)
        {
            return Err(ScopeBatchError::InvalidRequest);
        }
        for row in &self.rows {
            ScopeChildRevision::new(row.birth, row.generation)?;
        }
        Ok(())
    }

    /// Compare canonical identity and effect shape against the complete request.
    /// Matching decoded bytes alone grants no authority or effect capability.
    pub fn matches_request(&self, request: &ScopeBatchRequest) -> bool {
        self.validate().is_ok()
            && request.digest() == Ok(self.request_digest)
            && self.lane == request.lane
            && self.sequence == request.sequence
            && (1..=COUNTER_MAX).contains(&self.revision)
            && request
                .expected_revision
                .is_none_or(|revision| self.revision == revision + 1)
            && self.rows.len() == request.operations.len()
            && self.rows.iter().zip(&request.operations).all(|(row, op)| {
                ScopeChildRevision::new(row.birth, row.generation).is_ok()
                    && match op.expected() {
                        Some(old) => row.birth == old.birth && row.generation == old.generation + 1,
                        None => row.generation == 1,
                    }
            })
            && self.counters.iter().all(|value| *value <= COUNTER_MAX)
            && request
                .counters
                .iter()
                .all(|counter| self.counters[usize::from(counter.counter)] == counter.next)
    }
}
