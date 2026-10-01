//! Process-local binding and freshness for authenticated MOBIKE effects.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use super::{Error, Path};

pub(crate) struct MigrationScope {
    generation: AtomicU64,
}

impl MigrationScope {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            generation: AtomicU64::new(1),
        })
    }

    pub(crate) fn advance(&self) -> Result<u64, Error> {
        let previous = self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value != 0).then(|| value.checked_add(1).unwrap_or(0))
            })
            .map_err(|_| Error::Closed)?;
        previous.checked_add(1).ok_or(Error::Closed)
    }

    pub(crate) fn current(&self) -> Result<u64, Error> {
        match self.generation.load(Ordering::Acquire) {
            0 => Err(Error::Closed),
            value => Ok(value),
        }
    }

    pub(crate) fn close(&self) {
        self.generation.store(0, Ordering::Release);
    }
}

/// Opaque identity of one live authenticated MOBIKE responder.
///
/// Obtain this from [`super::Responder::migration_association`] and bind it to
/// the exact Child-SA roster owned by that established IKE SA before applying
/// updates. The caller owns that IKE-to-Child-SA association; this type neither
/// establishes IKE_AUTH trust nor imports an association from caller labels.
/// Cloning the identity does not mint migration authority. Dropping the
/// responder permanently closes its scope, including all retained clones.
#[derive(Clone)]
pub struct MigrationAssociation {
    pub(crate) scope: Arc<MigrationScope>,
}

/// Once-produced, live-scoped authority for one authenticated COOKIE2 update.
///
/// Only [`super::Migration::authorize`] can construct this non-cloneable type.
/// A backend must validate it against its previously bound association before
/// admission and again before publishing its completed roster. An accepted
/// later MOBIKE request, explicit IKE-event invalidation, responder closure or
/// generation exhaustion makes it stale. Failed authentication does not.
///
/// This is a process-local authorization, not a durable recovery receipt. It
/// does not grant counter restoration, key reuse, ownership of a resource not
/// in the associated roster or authority from an observed ESP source address.
///
/// ```compile_fail
/// let forged = opc_proto_ikev2::nwu::mobike::MigrationPermit {};
/// ```
pub struct MigrationPermit {
    scope: Arc<MigrationScope>,
    generation: u64,
    path: Path,
    esp_udp: bool,
}

impl MigrationPermit {
    pub(crate) fn issue(
        scope: Arc<MigrationScope>,
        generation: u64,
        path: Path,
        esp_udp: bool,
        association: &MigrationAssociation,
    ) -> Result<Self, Error> {
        let permit = Self {
            scope,
            generation,
            path,
            esp_udp,
        };
        permit.validate(association)?;
        Ok(permit)
    }

    /// Recheck exact association identity and the current live event generation.
    ///
    /// Equal public IKE SPIs, peer tuples or caller generation labels do not
    /// substitute for the private association. Validation is point-in-time;
    /// the caller serializes later IKE events with effect publication.
    pub fn validate(&self, association: &MigrationAssociation) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.scope, &association.scope) {
            return Err(Error::Correlation);
        }
        if self.scope.current()? != self.generation {
            return Err(Error::Replay);
        }
        Ok(())
    }

    /// Authenticated observed path in peer-to-local packet direction.
    #[must_use]
    pub const fn path(&self) -> Path {
        self.path
    }

    /// Authenticated desired ESP UDP encapsulation mode.
    #[must_use]
    pub const fn esp_udp_encapsulation(&self) -> bool {
        self.esp_udp
    }
}

impl fmt::Debug for MigrationAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationAssociation(<redacted>)")
    }
}
impl fmt::Debug for MigrationPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationPermit(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_exhaustion_closes_every_retained_scope_without_wrap() {
        let scope = MigrationScope {
            generation: AtomicU64::new(u64::MAX),
        };
        assert_eq!(scope.advance(), Err(Error::Closed));
        assert_eq!(scope.current(), Err(Error::Closed));
        assert_eq!(scope.advance(), Err(Error::Closed));
        let scope = MigrationScope::new();
        let retained = scope.clone();
        scope.close();
        assert_eq!(retained.current(), Err(Error::Closed));
    }
}
