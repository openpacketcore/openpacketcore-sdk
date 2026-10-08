//! One replaceable authority checkpoint, independently of operation receipts.

use sha2::{Digest, Sha256};

use super::*;
use crate::consensus::{
    SessionConsensusRequestId, SessionConsensusResponse, SessionMutationOutcome,
};

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;

/// Internal versioned consensus operation. Admission is performed by the
/// quorum service; apply independently checks the exact predecessor and time.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeLeaseCommand {
    pub(crate) request: ScopeLeaseRequest,
    pub(crate) bounds: ScopeClockBounds,
}

/// Fixed-size scope authority checkpoint, not a per-operation receipt.
///
/// The metadata is visible to replicated apply. It contains no credentials or
/// child session payloads. Its durable key is derived from the stable scope;
/// every successful mutation replaces that same row.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeLeaseCheckpoint(Vec<u8>);

/// Fixed-size comparison facts for the validated native catalog. Complete
/// checkpoint decoding and slot validation still precede these commitments.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScopeCheckpointFacts {
    scope: [u8; 32],
    body: [u8; 32],
    revision: u64,
    selection: u64,
    grant_floor: u64,
    granted_selection: u64,
    last_time: Timestamp,
}

impl ScopeCheckpointFacts {
    pub(crate) fn can_replace(self, before: Self) -> bool {
        if self.scope != before.scope {
            return false;
        }
        if self.revision == before.revision {
            return self.body == before.body;
        }
        self.revision > before.revision
            && self.selection >= before.selection
            && self.grant_floor >= before.grant_floor
            && self.granted_selection >= before.granted_selection
            && self.last_time >= before.last_time
    }
}

impl Serialize for ScopeLeaseCheckpoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // A fixed-width encoding keeps the persisted checkpoint size constant
        // even as counters cross varint boundaries. Hex is an encoding, not
        // encryption: this is non-secret authority metadata.
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for ScopeLeaseCheckpoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ScopeLeaseCheckpoint;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one fixed-width scope authority checkpoint")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() != MAX_SCOPE_LEASE_RECORD_BYTES * 2 {
                    return Err(E::custom("scope checkpoint size differs"));
                }
                let bytes =
                    hex::decode(value).map_err(|_| E::custom("scope checkpoint invalid"))?;
                let checkpoint = ScopeLeaseCheckpoint(bytes);
                checkpoint
                    .state()
                    .map_err(|_| E::custom("scope checkpoint invalid"))?;
                Ok(checkpoint)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

impl ScopeLeaseId {
    pub(crate) fn checkpoint_id(&self) -> Result<SessionConsensusRequestId, ScopeLeaseError> {
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-lease/checkpoint/v2\0");
        hash.update(postcard::to_allocvec(self).map_err(|_| ScopeLeaseError::InvalidRequest)?);
        let digest = hash.finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Ok(SessionConsensusRequestId::from_bytes(id))
    }
}

impl ScopeLeaseCheckpoint {
    pub(crate) fn to_record(&self) -> Result<crate::StoredSessionRecord, ScopeLeaseError> {
        let state = self.state()?;
        Ok(crate::StoredSessionRecord {
            key: state.view.scope.key()?,
            generation: crate::Generation::new(state.view.revision),
            owner: crate::OwnerId::new("scope-authority")
                .map_err(|_| ScopeLeaseError::FormatMismatch)?,
            fence: crate::FenceToken::new(0),
            state_class: crate::StateClass::AuthoritativeSession,
            state_type: crate::StateType::from_static("opc-scope-authority-v2"),
            expires_at: None,
            // This reserved row contains only non-secret authority metadata.
            // It is never accepted as an ordinary consumer session value.
            payload: crate::EncryptedSessionPayload::new(&self.0),
        })
    }

    pub(crate) fn from_record(
        record: &crate::StoredSessionRecord,
    ) -> Result<Self, ScopeLeaseError> {
        if record.payload.encoding() != crate::SessionPayloadEncoding::Plaintext
            || record.payload.len() != MAX_SCOPE_LEASE_RECORD_BYTES
        {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        let checkpoint = Self(record.payload.as_bytes().to_vec());
        if checkpoint.to_record()? != *record {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        Ok(checkpoint)
    }

    pub(crate) fn stored(&self) -> Result<([u8; 32], SessionConsensusResponse), ScopeLeaseError> {
        Ok((
            self.digest()?,
            SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::ScopeLease(Ok(self.clone()))),
                sequence: 0,
                digest: None,
                logical_time: None,
                raft_log_index: 0,
            },
        ))
    }

    fn new(state: &ScopeState) -> Result<Self, ScopeLeaseError> {
        let body = state.encode()?;
        if body.len() > MAX_SCOPE_LEASE_RECORD_BYTES - 2 {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        let mut bytes = Vec::with_capacity(MAX_SCOPE_LEASE_RECORD_BYTES);
        bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.resize(MAX_SCOPE_LEASE_RECORD_BYTES, 0);
        Ok(Self(bytes))
    }

    pub(crate) fn state(&self) -> Result<ScopeState, ScopeLeaseError> {
        if self.0.len() != MAX_SCOPE_LEASE_RECORD_BYTES {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        let length = usize::from(u16::from_le_bytes([self.0[0], self.0[1]]));
        if length > MAX_SCOPE_LEASE_RECORD_BYTES - 2
            || self.0[2 + length..].iter().any(|byte| *byte != 0)
        {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        ScopeState::decode_any(&self.0[2..2 + length])
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], ScopeLeaseError> {
        Ok(self.state()?.last_digest)
    }

    pub(crate) fn can_replace(&self, before: &Self) -> bool {
        let (Ok(old), Ok(new)) = (before.facts(), self.facts()) else {
            return false;
        };
        // A persisted change journal may coalesce many already-validated
        // commands. Check monotonic floors across that whole captured span;
        // each individual command still runs the complete transition above.
        new.can_replace(old)
    }

    pub(crate) fn facts(&self) -> Result<ScopeCheckpointFacts, ScopeLeaseError> {
        let state = self.state()?;
        let scope = postcard::to_allocvec(&state.view.scope)
            .map_err(|_| ScopeLeaseError::FormatMismatch)?;
        Ok(ScopeCheckpointFacts {
            scope: Sha256::digest(scope).into(),
            body: Sha256::digest(&self.0).into(),
            revision: state.view.revision,
            selection: state.view.selection,
            grant_floor: state.view.grant_floor,
            granted_selection: state.view.granted_selection,
            last_time: state.last_time,
        })
    }

    pub(crate) fn validate_slot(
        &self,
        slot: SessionConsensusRequestId,
        digest: [u8; 32],
    ) -> Result<(), ScopeLeaseError> {
        let state = self.state()?;
        if state.view.scope.checkpoint_id()? != slot || state.last_digest != digest {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        Ok(())
    }
}

impl ScopeLeaseCommand {
    pub(crate) fn validate(&self) -> Result<(), ScopeLeaseError> {
        self.request.validate()?;
        ScopeClockBounds::new(self.bounds.earliest, self.bounds.latest)?;
        Ok(())
    }

    pub(crate) fn apply(
        &self,
        current: Option<([u8; 32], SessionConsensusResponse)>,
    ) -> Result<ScopeLeaseCheckpoint, ScopeLeaseError> {
        self.validate()?;
        let state = checkpoint_state(&self.request.scope, current)?;
        ScopeLeaseCheckpoint::new(&state.transition(&self.request, self.bounds)?)
    }

    pub(crate) fn matches(&self, checkpoint: &ScopeLeaseCheckpoint) -> bool {
        checkpoint
            .state()
            .and_then(|state| state.replay(&self.request))
            == Ok(true)
    }
}

pub(crate) fn checkpoint_state(
    scope: &ScopeLeaseId,
    current: Option<([u8; 32], SessionConsensusResponse)>,
) -> Result<ScopeState, ScopeLeaseError> {
    let Some((digest, response)) = current else {
        return Ok(ScopeState::empty(scope.clone()));
    };
    let Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))) = response.result else {
        return Err(ScopeLeaseError::FormatMismatch);
    };
    checkpoint.validate_slot(scope.checkpoint_id()?, digest)?;
    let state = checkpoint.state()?;
    if state.view.scope != *scope {
        return Err(ScopeLeaseError::FormatMismatch);
    }
    Ok(state)
}

redacted_debug!(ScopeLeaseCheckpoint, ScopeLeaseCommand);
