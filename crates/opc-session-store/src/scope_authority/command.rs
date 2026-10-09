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
/// quorum service; apply independently checks the exact predecessor and retained floors.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAuthorityCommand {
    pub(crate) request: ScopeAuthorityRequest,
}

/// Fixed-size scope authority checkpoint, not a per-operation receipt.
///
/// The metadata is visible to replicated apply. It contains no credentials or
/// child session payloads. Its durable key is derived from the stable scope;
/// every successful mutation replaces that same row.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeAuthorityCheckpoint(Vec<u8>);

/// Fixed-size comparison facts for the validated native catalog. Complete
/// checkpoint decoding and slot validation still precede these commitments.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScopeCheckpointFacts {
    scope: [u8; 32],
    body: [u8; 32],
    revision: u64,
    incarnation: u64,
    retired_through: u64,
    generation: u64,
    execution: [u8; 32],
    active: bool,
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
            && self.incarnation >= before.incarnation
            && self.retired_through >= before.retired_through
            && (self.incarnation == before.incarnation
                || self.retired_through >= before.incarnation)
            && self.generation >= before.generation
            && (self.generation > before.generation
                || (self.incarnation == before.incarnation
                    && self.execution == before.execution
                    && (before.active || !self.active)))
    }
}

impl Serialize for ScopeAuthorityCheckpoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // A fixed-width encoding keeps the persisted checkpoint size constant
        // even as counters cross varint boundaries. Hex is an encoding, not
        // encryption: this is non-secret authority metadata.
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for ScopeAuthorityCheckpoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ScopeAuthorityCheckpoint;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one fixed-width scope authority checkpoint")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() != MAX_SCOPE_AUTHORITY_RECORD_BYTES * 2 {
                    return Err(E::custom("scope checkpoint size differs"));
                }
                let bytes =
                    hex::decode(value).map_err(|_| E::custom("scope checkpoint invalid"))?;
                let checkpoint = ScopeAuthorityCheckpoint(bytes);
                checkpoint
                    .state()
                    .map_err(|_| E::custom("scope checkpoint invalid"))?;
                Ok(checkpoint)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

impl ScopeId {
    pub(crate) fn checkpoint_id(&self) -> Result<SessionConsensusRequestId, ScopeAuthorityError> {
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-authority/checkpoint/v4\0");
        hash.update(postcard::to_allocvec(self).map_err(|_| ScopeAuthorityError::InvalidRequest)?);
        let digest = hash.finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Ok(SessionConsensusRequestId::from_bytes(id))
    }
}

impl ScopeAuthorityCheckpoint {
    pub(crate) fn to_record(&self) -> Result<crate::StoredSessionRecord, ScopeAuthorityError> {
        let state = self.state()?;
        Ok(crate::StoredSessionRecord {
            key: state.view.scope.key()?,
            generation: crate::Generation::new(state.view.revision),
            owner: crate::OwnerId::new("scope-authority")
                .map_err(|_| ScopeAuthorityError::FormatMismatch)?,
            fence: crate::FenceToken::new(0),
            state_class: crate::StateClass::AuthoritativeSession,
            state_type: crate::StateType::from_static("opc-scope-authority-v4"),
            expires_at: None,
            // This reserved row contains only non-secret authority metadata.
            // It is never accepted as an ordinary consumer session value.
            payload: crate::EncryptedSessionPayload::new(&self.0),
        })
    }

    pub(crate) fn from_record(
        record: &crate::StoredSessionRecord,
    ) -> Result<Self, ScopeAuthorityError> {
        if record.payload.encoding() != crate::SessionPayloadEncoding::Plaintext
            || record.payload.len() != MAX_SCOPE_AUTHORITY_RECORD_BYTES
        {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        let checkpoint = Self(record.payload.as_bytes().to_vec());
        if checkpoint.to_record()? != *record {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(checkpoint)
    }

    pub(crate) fn stored(
        &self,
    ) -> Result<([u8; 32], SessionConsensusResponse), ScopeAuthorityError> {
        Ok((
            self.digest()?,
            SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::ScopeAuthority(Ok(self.clone()))),
                sequence: 0,
                digest: None,
                logical_time: None,
                raft_log_index: 0,
            },
        ))
    }

    fn new(state: &ScopeState) -> Result<Self, ScopeAuthorityError> {
        let body = state.encode()?;
        if body.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES - 2 {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        let mut bytes = Vec::with_capacity(MAX_SCOPE_AUTHORITY_RECORD_BYTES);
        bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.resize(MAX_SCOPE_AUTHORITY_RECORD_BYTES, 0);
        Ok(Self(bytes))
    }

    pub(crate) fn state(&self) -> Result<ScopeState, ScopeAuthorityError> {
        if self.0.len() != MAX_SCOPE_AUTHORITY_RECORD_BYTES {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        let length = usize::from(u16::from_le_bytes([self.0[0], self.0[1]]));
        if length > MAX_SCOPE_AUTHORITY_RECORD_BYTES - 2
            || self.0[2 + length..].iter().any(|byte| *byte != 0)
        {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        ScopeState::decode_any(&self.0[2..2 + length])
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], ScopeAuthorityError> {
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

    pub(crate) fn facts(&self) -> Result<ScopeCheckpointFacts, ScopeAuthorityError> {
        let state = self.state()?;
        let scope = postcard::to_allocvec(&state.view.scope)
            .map_err(|_| ScopeAuthorityError::FormatMismatch)?;
        Ok(ScopeCheckpointFacts {
            scope: Sha256::digest(scope).into(),
            body: Sha256::digest(&self.0).into(),
            revision: state.view.revision,
            incarnation: state
                .view
                .current_incarnation()
                .ok_or(ScopeAuthorityError::FormatMismatch)?
                .get(),
            retired_through: state.view.retired_through,
            generation: state.view.admission_generation_floor,
            execution: Sha256::digest(
                postcard::to_allocvec(
                    state
                        .view
                        .stamp()
                        .ok_or(ScopeAuthorityError::FormatMismatch)?
                        .execution(),
                )
                .map_err(|_| ScopeAuthorityError::FormatMismatch)?,
            )
            .into(),
            active: state.view.active,
        })
    }

    pub(crate) fn validate_slot(
        &self,
        slot: SessionConsensusRequestId,
        digest: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        let state = self.state()?;
        if state.view.scope.checkpoint_id()? != slot || state.last_digest != digest {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(())
    }
}

impl ScopeAuthorityCommand {
    pub(super) fn verified(
        request: ScopeAuthorityRequest,
        closure: Option<VerifiedScopeClosure>,
    ) -> Result<Self, ScopeAuthorityError> {
        match (request.operation.closure(), closure) {
            (None, None) => {}
            (Some((predecessor, evidence)), Some(verified))
                if predecessor == &verified.predecessor && evidence == &verified.evidence => {}
            _ => return Err(ScopeAuthorityError::ClosureRequired),
        }
        request.validate()?;
        Ok(Self { request })
    }

    pub(crate) fn validate(&self) -> Result<(), ScopeAuthorityError> {
        self.request.validate()?;
        Ok(())
    }

    pub(crate) fn apply(
        &self,
        current: Option<([u8; 32], SessionConsensusResponse)>,
    ) -> Result<ScopeAuthorityCheckpoint, ScopeAuthorityError> {
        self.validate()?;
        let state = checkpoint_state(&self.request.scope, current)?;
        ScopeAuthorityCheckpoint::new(&state.transition(&self.request)?)
    }

    pub(crate) fn matches(&self, checkpoint: &ScopeAuthorityCheckpoint) -> bool {
        let Ok(state) = checkpoint.state() else {
            return false;
        };
        if state.replay(&self.request) != Ok(true)
            || self.request.expected_revision.checked_add(1) != Some(state.view.revision)
        {
            return false;
        }
        let Some(stamp) = state.view.stamp() else {
            return false;
        };
        if stamp.execution() != self.request.operation.execution() {
            return false;
        }
        match &self.request.operation {
            ScopeAuthorityOperation::AdmitInitial { .. } => {
                state.view.active
                    && stamp.incarnation().get() == 1
                    && state.view.retired_through == 0
            }
            ScopeAuthorityOperation::SucceedClosed { predecessor, .. } => {
                state.view.active && stamp.namespace() == predecessor.namespace()
            }
            ScopeAuthorityOperation::Close { current, .. } => {
                !state.view.active && stamp.namespace() == current.namespace()
            }
        }
    }
}

pub(crate) fn checkpoint_state(
    scope: &ScopeId,
    current: Option<([u8; 32], SessionConsensusResponse)>,
) -> Result<ScopeState, ScopeAuthorityError> {
    let Some((digest, response)) = current else {
        return Ok(ScopeState::empty(scope.clone()));
    };
    let Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))) = response.result else {
        return Err(ScopeAuthorityError::FormatMismatch);
    };
    checkpoint.validate_slot(scope.checkpoint_id()?, digest)?;
    let state = checkpoint.state()?;
    if state.view.scope != *scope {
        return Err(ScopeAuthorityError::FormatMismatch);
    }
    Ok(state)
}

redacted_debug!(ScopeAuthorityCheckpoint, ScopeAuthorityCommand);
