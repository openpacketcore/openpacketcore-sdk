//! Native protected-roster storage. Persistent indexes contain scalar facts
//! derived from the original authenticated carriers. They are process-local
//! access paths; neither an index nor a serialized projection admits a row.

pub(super) mod catalog;
pub(super) mod changes;
mod commands;
pub(super) mod frame;
pub(super) mod generation;
mod index;
mod publication;
mod row;
pub(in crate::consensus::native) mod store;
#[cfg(test)]
#[path = "roster/v1_fixture.rs"]
pub(crate) mod v1_fixture;
pub(in crate::consensus::native) use commands::validate_activation;
pub(crate) use index::Index;
pub(in crate::consensus::native) use publication::validate_candidate;
pub(crate) use row::Row;

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use crate::fenced_mutation_roster::{
    IrreversibleHistoryFloor, RequestBindingKey, RosterAttestationTrustRootV1,
};
use crate::fenced_mutation_roster_storage::{
    GlobalChargeBudget, GlobalChargeWitness, ProductionFloorKey, ProductionRetirementCursor,
    ProductionSnapshotAccounting, ProductionSnapshotStreamValidator,
};
pub(crate) use crate::sqlite::consensus::roster_rows::{
    self as carrier, Facts, Profile, Projection, State,
};
use crate::sqlite::consensus::MembershipValidationScope;
use changes::{Certificate, Edit, Journal};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The floor and its optional exclusive retirement cursor form one row. A
/// cursor can never be published without the exact floor it constrains.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Partition {
    pub(crate) floor: IrreversibleHistoryFloor,
    pub(crate) cursor: Option<ProductionRetirementCursor>,
}

impl Partition {
    pub(crate) fn validate(&self, key: ProductionFloorKey) -> io::Result<()> {
        if ProductionFloorKey::from_floor(self.floor)
            .map_err(|_| invalid("native roster floor invalid"))?
            != key
            || self.cursor.as_ref().is_some_and(|cursor| {
                cursor.key() != key || cursor.validate_for_floor(self.floor).is_err()
            })
        {
            return Err(invalid("native roster partition projection differs"));
        }
        Ok(())
    }

    pub(in crate::consensus::native) fn accounting(
        &self,
    ) -> io::Result<ProductionSnapshotAccounting> {
        let _memory = VerificationMemory::reserve(frame::MAX_PARTITION + 4096)?;
        let mut validator = ProductionSnapshotStreamValidator::new(0, None);
        validator
            .add_floor(self.floor)
            .map_err(|_| invalid("native roster floor accounting failed"))?;
        if let Some(cursor) = &self.cursor {
            validator
                .add_cursor(cursor)
                .map_err(|_| invalid("native roster cursor accounting failed"))?;
        }
        Ok(validator.into_accounting())
    }
}

/// The original complete row/horizon/charge validator visits one authenticated
/// carrier under a fixed reservation. The persistent Index independently
/// enforces both cross-profile uniqueness keys across all such fragments.
pub(in crate::consensus::native) fn accounting(
    hydrated: &carrier::Hydration,
    application_sequence: u64,
    applied: Option<u64>,
    witness: Option<GlobalChargeWitness>,
) -> io::Result<ProductionSnapshotAccounting> {
    let _memory = VerificationMemory::reserve(4096)?;
    let mut validator = ProductionSnapshotStreamValidator::new(application_sequence, applied);
    hydrated
        .account(
            &mut validator,
            witness.unwrap_or_else(GlobalChargeWitness::empty),
        )
        .map_err(|_| invalid("native roster row accounting failed"))?;
    Ok(validator.into_accounting())
}

/// Fixed-quorum membership interpretation for the unchanged attestation
/// verifier. The caller supplies the independently admitted owner identity.
pub(crate) fn fixed_scope(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> MembershipValidationScope {
    MembershipValidationScope {
        current_identity: identity,
        current_members: members.clone(),
        current_bindings: BTreeMap::new(),
        application_authority_epoch: identity.configuration_epoch(),
        application_authority_members: members.clone(),
        predecessor: None,
        history: Vec::new(),
        terminal_history: Vec::new(),
        pending: None,
        terminal: None,
    }
}

/// One admitted ledger. A prepared command works on shared immutable roots;
/// publishing the resulting root is left to the enclosing native transaction.
#[derive(Clone)]
pub(crate) struct Ledger {
    pub(crate) rows: ResidentMap<RequestBindingKey, SharedRow<Row>>,
    pub(crate) partitions: imbl::OrdMap<ProductionFloorKey, SharedRow<Partition>>,
    pub(crate) index: Index,
    pub(crate) witness: Option<GlobalChargeWitness>,
    certificate: Arc<Certificate>,
}

impl Ledger {
    pub(crate) fn empty() -> Self {
        Self {
            rows: ResidentMap::new(),
            partitions: imbl::OrdMap::new(),
            index: Index::default(),
            witness: None,
            certificate: Certificate::empty(),
        }
    }

    /// Full admission is a streaming semantic pass, including exact live
    /// business predicates, shared floors/cursors, all uniqueness constraints,
    /// applied horizons and the original aggregate charge calculation.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn admit(
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        application_sequence: u64,
        applied_raft_log_index: Option<u64>,
        rows: impl IntoIterator<Item = SharedRow<Row>>,
        partitions: impl IntoIterator<Item = (ProductionFloorKey, Partition)>,
        witness: Option<GlobalChargeWitness>,
        business: impl Fn(&SessionKey) -> io::Result<Option<StoredSessionRecord>>,
    ) -> io::Result<Self> {
        Self::admit_using(
            application_sequence,
            applied_raft_log_index,
            rows.into_iter().map(Ok),
            partitions,
            witness,
            business,
            |row| row.hydrate(root, scope),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn admit_detached(
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        application_sequence: u64,
        applied_raft_log_index: Option<u64>,
        rows: impl IntoIterator<Item = SharedRow<Row>>,
        partitions: impl IntoIterator<Item = (ProductionFloorKey, Partition)>,
        witness: Option<GlobalChargeWitness>,
        business: impl Fn(&SessionKey) -> io::Result<Option<StoredSessionRecord>>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::admit_detached_fallible(
            root,
            scope,
            application_sequence,
            applied_raft_log_index,
            rows.into_iter().map(Ok),
            partitions,
            witness,
            business,
            check,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::consensus::native) fn admit_detached_fallible(
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        application_sequence: u64,
        applied_raft_log_index: Option<u64>,
        rows: impl IntoIterator<Item = io::Result<SharedRow<Row>>>,
        partitions: impl IntoIterator<Item = (ProductionFloorKey, Partition)>,
        witness: Option<GlobalChargeWitness>,
        business: impl Fn(&SessionKey) -> io::Result<Option<StoredSessionRecord>>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        let ledger = Self::admit_using(
            application_sequence,
            applied_raft_log_index,
            rows,
            partitions,
            witness,
            business,
            |row| row.hydrate_detached(root, scope, check),
        )?;
        check()?;
        Ok(ledger)
    }

    fn admit_using(
        application_sequence: u64,
        applied_raft_log_index: Option<u64>,
        rows: impl IntoIterator<Item = io::Result<SharedRow<Row>>>,
        partitions: impl IntoIterator<Item = (ProductionFloorKey, Partition)>,
        witness: Option<GlobalChargeWitness>,
        business: impl Fn(&SessionKey) -> io::Result<Option<StoredSessionRecord>>,
        hydrate: impl Fn(&Row) -> io::Result<carrier::Hydration>,
    ) -> io::Result<Self> {
        let mut next = Self::empty();
        let mut charges = ProductionSnapshotAccounting::empty();
        for (key, partition) in partitions {
            partition.validate(key)?;
            if next.partitions.len() >= crate::fenced_mutation_roster::MAX_RESERVED_AND_RETAINED {
                return Err(invalid("native roster floor count exceeds original bound"));
            }
            charges
                .replace(None, Some(partition.accounting()?))
                .map_err(|_| invalid("native roster partition charge overflow"))?;
            if next
                .partitions
                .insert(key, SharedRow::new(partition)?)
                .is_some()
            {
                return Err(invalid("native roster repeats a partition"));
            }
        }
        for row in rows {
            let row = row?;
            if next.rows.len() >= crate::fenced_mutation_roster::MAX_RESERVED_AND_RETAINED {
                return Err(invalid("native roster count exceeds original bound"));
            }
            let hydrated = hydrate(&row)?;
            let partition = next.partition(row.binding)?;
            hydrated
                .validate_partition(partition.floor, partition.cursor.as_ref())
                .map_err(|_| invalid("native roster row lies outside its partition"))?;
            if let Some(key) = row.reserved_key() {
                let current = business(key)?;
                hydrated
                    .validate_business(current.as_ref())
                    .map_err(|_| invalid("native roster business reservation differs"))?;
            }
            charges
                .replace(
                    None,
                    Some(accounting(
                        &hydrated,
                        application_sequence,
                        applied_raft_log_index,
                        witness,
                    )?),
                )
                .map_err(|_| invalid("native roster aggregate charge overflow"))?;
            next.index = next.index.replaced(row.binding, None, Some(&row))?;
            if next.rows.insert(row.binding, row).is_some() {
                return Err(invalid("native roster repeats a binding"));
            }
        }
        for key in next.partitions.keys() {
            if next.index.partition_count(*key) == 0 {
                return Err(invalid("native roster contains an orphan partition"));
            }
        }
        charges
            .finish(
                application_sequence,
                witness,
                GlobalChargeBudget::production(),
            )
            .map_err(|_| invalid("native roster global witness differs"))?;
        next.witness = witness;
        next.certificate = Certificate::admit(&next)?;
        Ok(next)
    }

    pub(crate) fn partition(&self, binding: RequestBindingKey) -> io::Result<&Partition> {
        let key = ProductionFloorKey::from_binding(binding)
            .map_err(|_| invalid("native roster partition key invalid"))?;
        self.partitions
            .get(&key)
            .map(|row| &**row)
            .ok_or_else(|| invalid("native roster floor missing"))
    }

    pub(crate) fn hydrate(
        &self,
        binding: RequestBindingKey,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
    ) -> io::Result<Option<carrier::Hydration>> {
        let Some(row) = self.rows.get(&binding) else {
            return Ok(None);
        };
        let hydrated = row.hydrate(root, scope)?;
        self.validate_selected(binding, hydrated).map(Some)
    }

    pub(crate) fn hydrate_detached(
        &self,
        binding: RequestBindingKey,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Option<carrier::Hydration>> {
        check()?;
        let Some(row) = self.rows.get(&binding) else {
            return Ok(None);
        };
        let hydrated = row.hydrate_detached(root, scope, check)?;
        self.validate_selected(binding, hydrated).map(Some)
    }

    fn validate_selected(
        &self,
        binding: RequestBindingKey,
        hydrated: carrier::Hydration,
    ) -> io::Result<carrier::Hydration> {
        let partition = self.partition(binding)?;
        hydrated
            .validate_partition(partition.floor, partition.cursor.as_ref())
            .map_err(|_| invalid("native roster selected partition differs"))?;
        Ok(hydrated)
    }
}
