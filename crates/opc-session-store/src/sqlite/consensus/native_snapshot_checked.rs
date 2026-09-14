//! A complete SQL audit retained with its read transaction. The
//! result is consumable only for the same full authority tuple; it grants no
//! native origin, file admission, selector or resident publication authority.

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct Scope<'members, 'root> {
    pub(crate) identity: SessionConsensusIdentity,
    pub(crate) members: &'members BTreeSet<SessionConsensusNodeId>,
    pub(crate) bindings: &'members BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    pub(crate) placement: PlacementResiliencePolicy,
    pub(crate) root: Option<&'root RosterAttestationTrustRootV1>,
}

struct OwnedScope {
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    placement: PlacementResiliencePolicy,
    root: Option<RosterAttestationTrustRootV1>,
}

pub(crate) struct ValidatedSource<'a> {
    tx: Transaction<'a>,
    metadata: Metadata,
    scope: OwnedScope,
    // The original reservation includes 512 KiB of metadata scratch. Retain
    // it before cloning this bounded fixed-authority tuple and through every
    // allocating header read. All owned scope fields drop before its refund.
    memory: VerificationMemory,
}

impl<'a> ValidatedSource<'a> {
    pub(crate) fn new(
        conn: &'a mut Connection,
        scope: Scope<'_, '_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        conn.pragma_update(None, "query_only", true)
            .map_err(db_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        let (metadata, memory) = validate(
            &tx,
            scope.identity,
            scope.members,
            scope.bindings,
            scope.placement,
            scope.root,
            check,
        )?;
        let scope = OwnedScope {
            identity: scope.identity,
            members: scope.members.clone(),
            bindings: scope.bindings.clone(),
            placement: scope.placement,
            root: scope.root.cloned(),
        };
        Ok(Self {
            tx,
            metadata,
            scope,
            memory,
        })
    }

    /// Used only for the original install admission and authority reads before
    /// conversion. Callers must leave the query-only transaction intact.
    pub(in crate::sqlite::consensus) fn connection(&self) -> &Connection {
        &self.tx
    }

    pub(crate) fn into_parts(
        self,
        expected: Scope<'_, '_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<(Transaction<'a>, Metadata, VerificationMemory)> {
        check()?;
        if self.scope.identity != expected.identity
            || &self.scope.members != expected.members
            || &self.scope.bindings != expected.bindings
            || self.scope.placement != expected.placement
            || self.scope.root.as_ref() != expected.root
            || self.tx.is_autocommit()
            || !self
                .tx
                .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
                .map_err(db_error)?
        {
            return Err(invalid_data(
                "native SQL validated source scope or read transaction differs",
            ));
        }
        Ok((self.tx, self.metadata, self.memory))
    }
}
