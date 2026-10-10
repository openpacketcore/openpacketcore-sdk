//! Exact read-only predicates included in the enclosing request's namespace.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{ScopeBatchError, ScopeChildKey, ScopeChildRevision, ScopeClaimKey};

/// Compare one live child without rewriting its sealed value.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeChildCondition {
    key: ScopeChildKey,
    expected: ScopeChildRevision,
}

impl ScopeChildCondition {
    /// Bind a live key to its exact birth and generation in the request namespace.
    pub fn new(key: ScopeChildKey, expected: ScopeChildRevision) -> Result<Self, ScopeBatchError> {
        let condition = Self { key, expected };
        condition.validate()?;
        Ok(condition)
    }

    /// Exact child key, never a range or absence predicate.
    pub const fn key(&self) -> ScopeChildKey {
        self.key
    }

    /// Exact live child birth and generation.
    pub const fn expected(&self) -> ScopeChildRevision {
        self.expected
    }

    pub(super) fn validate(&self) -> Result<(), ScopeBatchError> {
        if self.key.as_bytes() == &[0; 32] {
            return Err(ScopeBatchError::InvalidRequest);
        }
        ScopeChildRevision::new(self.expected.birth(), self.expected.generation())?;
        Ok(())
    }

    pub(super) fn matches(
        &self,
        key: ScopeChildKey,
        live_revision: Option<ScopeChildRevision>,
    ) -> bool {
        self.validate().is_ok() && key == self.key && live_revision == Some(self.expected)
    }
}

/// The exact child birth which owns a claim in one request namespace.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeClaimOwner {
    child: ScopeChildKey,
    birth: u64,
}

impl ScopeClaimOwner {
    /// Bind claim ownership to one nonzero child key and non-recycled birth.
    pub fn new(child: ScopeChildKey, birth: u64) -> Result<Self, ScopeBatchError> {
        let owner = Self { child, birth };
        owner.validate()?;
        Ok(owner)
    }

    /// Exact owner child key.
    pub const fn child(&self) -> ScopeChildKey {
        self.child
    }

    /// Exact owner birth, which survives subsequent child generation changes.
    pub const fn birth(&self) -> u64 {
        self.birth
    }

    fn validate(&self) -> Result<(), ScopeBatchError> {
        if self.child.as_bytes() == &[0; 32] || !(1..=i64::MAX as u64).contains(&self.birth) {
            return Err(ScopeBatchError::InvalidRequest);
        }
        Ok(())
    }
}

/// Compare a retained claim's revision and exact owner, including Released.
/// A missing row is not a versioned Released row and never satisfies this type.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeClaimCondition {
    key: ScopeClaimKey,
    revision: u64,
    owner: Option<ScopeClaimOwner>,
}

impl ScopeClaimCondition {
    /// Compare a retained claim row. `None` names Released at this revision.
    pub fn new(
        key: ScopeClaimKey,
        revision: u64,
        owner: Option<ScopeClaimOwner>,
    ) -> Result<Self, ScopeBatchError> {
        let condition = Self {
            key,
            revision,
            owner,
        };
        condition.validate()?;
        Ok(condition)
    }

    /// Exact claim key in the request namespace.
    pub const fn key(&self) -> ScopeClaimKey {
        self.key
    }

    /// Stable-scope batch revision at the last claim change.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact owner birth, or Released for a retained row at this revision.
    pub const fn owner(&self) -> Option<ScopeClaimOwner> {
        self.owner
    }

    pub(super) fn validate(&self) -> Result<(), ScopeBatchError> {
        if self.key.as_bytes() == &[0; 32] || !(1..=i64::MAX as u64).contains(&self.revision) {
            return Err(ScopeBatchError::InvalidRequest);
        }
        if let Some(owner) = self.owner {
            owner.validate()?;
        }
        Ok(())
    }

    pub(super) fn matches(
        &self,
        key: ScopeClaimKey,
        revision: Option<u64>,
        owner: Option<ScopeClaimOwner>,
    ) -> bool {
        self.validate().is_ok()
            && key == self.key
            && revision == Some(self.revision)
            && owner == self.owner
    }
}

impl fmt::Debug for ScopeChildCondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeChildCondition(<redacted>)")
    }
}

impl fmt::Debug for ScopeClaimOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeClaimOwner(<redacted>)")
    }
}

impl fmt::Debug for ScopeClaimCondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopeClaimCondition(<redacted>)")
    }
}

#[cfg(test)]
#[path = "read_set_tests.rs"]
mod tests;
