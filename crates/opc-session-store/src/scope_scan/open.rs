//! Read-only handover claims for an authenticated remote restore open.

use super::{ScopeScanError, ScopeScanPageLimits};
use crate::scope_authority::{
    CommittedScopeAuthority, ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeAuthorityStamp,
};
use std::fmt;

/// Largest canonical restore-open request, including two shared authority codecs.
pub const MAX_SCOPE_SCAN_OPEN_BYTES: usize =
    2 * crate::scope_authority::MAX_SCOPE_AUTHORITY_RECORD_BYTES + 32;

/// A malformed, noncanonical or out-of-bounds scan observation or request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid scope scan wire claim")]
pub struct ScopeScanWireError;

/// An exact committed succession claim, never a mutation or effect capability.
/// The serving node verifies this against the authority row in the captured cut.
#[derive(Clone)]
pub struct ScopeScanOpenRequest {
    pub(crate) stamp: ScopeAuthorityStamp,
    pub(crate) succession: ScopeAuthorityRequest,
    pub(crate) limits: ScopeScanPageLimits,
}
impl fmt::Debug for ScopeScanOpenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanOpenRequest(<redacted>)")
    }
}
impl ScopeScanOpenRequest {
    /// Retain the original immutable request that issued the committed successor.
    pub fn new(
        authority: &CommittedScopeAuthority,
        succession: &ScopeAuthorityRequest,
        limits: ScopeScanPageLimits,
    ) -> Result<Self, ScopeScanError> {
        let predecessor = authority
            .closed_predecessor()
            .ok_or(ScopeScanError::HandoverRequired)?;
        match succession.operation() {
            ScopeAuthorityOperation::SucceedClosed {
                predecessor: claimed,
                ..
            } if claimed == predecessor => {}
            _ => return Err(ScopeScanError::HandoverRequired),
        }
        Self::from_claims(authority.stamp().clone(), succession.clone(), limits)
    }

    pub(crate) fn from_claims(
        stamp: ScopeAuthorityStamp,
        succession: ScopeAuthorityRequest,
        limits: ScopeScanPageLimits,
    ) -> Result<Self, ScopeScanError> {
        let value = Self {
            stamp,
            succession,
            limits,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub(crate) fn validate_shape(&self) -> Result<(), ScopeScanError> {
        ScopeScanPageLimits::new(self.limits.rows(), self.limits.payload_bytes())?;
        self.stamp
            .encode_canonical()
            .map_err(|_| ScopeScanError::Unauthorized)?;
        self.succession
            .encode_canonical()
            .map_err(|_| ScopeScanError::HandoverRequired)?;
        match self.succession.operation() {
            ScopeAuthorityOperation::SucceedClosed {
                predecessor,
                execution,
                ..
            } if predecessor.namespace() == self.stamp.namespace()
                && self.succession.scope() == self.stamp.scope()
                && execution == self.stamp.execution()
                && self.succession.expected_revision().checked_add(1)
                    == Some(self.stamp.revision()) =>
            {
                Ok(())
            }
            _ => Err(ScopeScanError::HandoverRequired),
        }
    }

    /// Exact current successor claims; decoded values convey no capability.
    pub fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }
    /// Original immutable authority request, including closure evidence digest.
    pub fn succession(&self) -> &ScopeAuthorityRequest {
        &self.succession
    }
    /// Per-view row and stored-payload bounds.
    pub const fn limits(&self) -> ScopeScanPageLimits {
        self.limits
    }

    /// Canonical bounded envelope around the existing shared authority codecs.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeScanWireError> {
        self.validate_shape().map_err(|_| ScopeScanWireError)?;
        let stamp = self
            .stamp
            .encode_canonical()
            .map_err(|_| ScopeScanWireError)?;
        let request = self
            .succession
            .encode_canonical()
            .map_err(|_| ScopeScanWireError)?;
        let mut bytes = Vec::with_capacity(13 + stamp.len() + request.len());
        bytes.push(1);
        bytes.extend_from_slice(&(stamp.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&stamp);
        bytes.extend_from_slice(&(request.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&request);
        bytes.extend_from_slice(&(self.limits.rows() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.limits.payload_bytes() as u32).to_be_bytes());
        if bytes.len() > MAX_SCOPE_SCAN_OPEN_BYTES {
            return Err(ScopeScanWireError);
        }
        Ok(bytes)
    }
    /// Decode only claims; opening still requires current boot and committed replay.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeScanWireError> {
        use crate::scope_authority::MAX_SCOPE_AUTHORITY_RECORD_BYTES;
        let mut reader = super::codec::Reader::new(bytes, MAX_SCOPE_SCAN_OPEN_BYTES)?;
        if reader.u8()? != 1 {
            return Err(ScopeScanWireError);
        }
        let stamp = ScopeAuthorityStamp::decode_canonical(
            reader.bytes_u16(MAX_SCOPE_AUTHORITY_RECORD_BYTES)?,
        )
        .map_err(|_| ScopeScanWireError)?;
        let succession = ScopeAuthorityRequest::decode_canonical(
            reader.bytes_u16(MAX_SCOPE_AUTHORITY_RECORD_BYTES)?,
        )
        .map_err(|_| ScopeScanWireError)?;
        let limits = ScopeScanPageLimits::new(reader.u32()? as usize, reader.u32()? as usize)
            .map_err(|_| ScopeScanWireError)?;
        reader.finish()?;
        let value = Self::from_claims(stamp, succession, limits).map_err(|_| ScopeScanWireError)?;
        if value.encode_canonical()? != bytes {
            return Err(ScopeScanWireError);
        }
        Ok(value)
    }
}

#[cfg(test)]
#[path = "open_tests.rs"]
mod tests;
