//! Roster and business rows share one private publication certificate. Full
//! admission rebuilds the ledger; live preparation visits only touched rows.
//! No hydration, hashing or historical scan occurs in the owner commit step.

use super::*;

fn empty_without_root(ledger: &Ledger) -> io::Result<()> {
    if !ledger.rows.is_empty() || !ledger.partitions.is_empty() || ledger.witness.is_some() {
        return Err(invalid(
            "native roster state lacks its configured trust root",
        ));
    }
    ledger.certificate()?;
    Ok(())
}

fn reserved_matches(key: &SessionKey, value: &NativeKeyState, ledger: &Ledger) -> io::Result<()> {
    if value.reserved != ledger.index.reservation(key).is_some() {
        return Err(invalid(
            "native business reservation differs from the roster ledger",
        ));
    }
    Ok(())
}

fn selected_business(
    ledger: &Ledger,
    hydrated: &carrier::Hydration,
    business: impl Fn(&SessionKey) -> NativeKeyState,
) -> io::Result<()> {
    if let Some(key) = hydrated.reserved_key() {
        let row = business(key);
        if !row.reserved || ledger.index.reservation(key) != Some(hydrated.binding()) {
            return Err(invalid(
                "native roster reservation has no exact business row",
            ));
        }
        hydrated
            .validate_business(row.record.as_ref())
            .map_err(|_| invalid("native roster reserved business predicate differs"))?;
    }
    Ok(())
}

pub(in crate::consensus::native) fn validate_candidate(
    delta: &NativeDelta<'_>,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    delta.base.require_business_proof()?;
    delta.roster_changes.require_base(&delta.base.roster)?;
    delta.roster_changes.require_current(&delta.roster)?;
    delta.roster_changes.validate(check)?;
    for (key, row) in &delta.keys {
        check()?;
        reserved_matches(key, row, &delta.roster)?;
    }
    let Some(root) = delta.base.roster_root.as_deref() else {
        empty_without_root(&delta.base.roster)?;
        empty_without_root(&delta.roster)?;
        return check();
    };
    let scope = fixed_scope(delta.base.identity, &delta.base.members);
    for (binding, change) in &delta.roster_changes.rows {
        check()?;
        if change.before.is_some() {
            let hydrated = delta
                .base
                .roster
                .hydrate_detached(*binding, root, &scope, check)?
                .ok_or_else(|| invalid("native roster publication predecessor disappeared"))?;
            selected_business(&delta.base.roster, &hydrated, |key| {
                delta
                    .base
                    .keys
                    .get(key)
                    .map(|row| (**row).clone())
                    .unwrap_or_default()
            })?;
            if let Some(key) = hydrated.reserved_key() {
                // A released reservation must update the business flag even
                // when an omitted key would otherwise skip delta.keys. Use
                // the final index so release/re-reserve in one apply works.
                reserved_matches(key, &delta.key(key), &delta.roster)?;
            }
        }
        if change.after.is_some() {
            commands::validate_row_profile(
                delta
                    .roster
                    .rows
                    .get(binding)
                    .ok_or_else(|| invalid("native roster changed row absent"))?,
                &delta.frontiers,
            )?;
            let hydrated = delta
                .roster
                .hydrate_detached(*binding, root, &scope, check)?
                .ok_or_else(|| invalid("native roster publication after-image disappeared"))?;
            selected_business(&delta.roster, &hydrated, |key| delta.key(key))?;
            // Reuse the original row horizon and retirement predicates. The
            // aggregate witness itself comes from the accepted savepoint.
            let _memory = VerificationMemory::reserve(4096)?;
            let mut validator = ProductionSnapshotStreamValidator::new(
                delta.frontiers.sequence,
                delta.frontiers.applied.map(|id| id.index),
            );
            hydrated
                .account(
                    &mut validator,
                    delta
                        .roster
                        .witness
                        .ok_or_else(|| invalid("native roster publication witness absent"))?,
                )
                .map_err(|_| invalid("native roster publication exceeds its applied horizon"))?;
        }
    }
    for (key, row) in &delta.keys {
        check()?;
        let Some(binding) = delta.roster.index.reservation(key) else {
            continue;
        };
        if delta.roster_changes.rows.contains_key(&binding) {
            continue;
        }
        // A lease update can touch a reserved business key while retaining
        // the same roster row. Its original reservation still constrains it.
        let hydrated = delta
            .roster
            .hydrate_detached(binding, root, &scope, check)?
            .ok_or_else(|| invalid("native reserved business roster row absent"))?;
        hydrated
            .validate_business(row.record.as_ref())
            .map_err(|_| invalid("native unchanged roster business predicate differs"))?;
    }
    for (key, change) in &delta.roster_changes.partitions {
        check()?;
        if let Some(after) = &change.after {
            after.validate(*key)?;
            if delta.roster.index.partition_count(*key) == 0 {
                return Err(invalid(
                    "native roster publication contains an orphan partition",
                ));
            }
        } else if delta.roster.index.partition_count(*key) != 0 {
            return Err(invalid(
                "native roster publication removes a referenced partition",
            ));
        }
    }
    check()
}

impl NativeState {
    pub(in crate::consensus::native) fn require_legacy_roster_absent(&self) -> io::Result<()> {
        if self.snapshot_origin.is_some() {
            return Err(invalid(
                "native installed origin requires its complete generation vocabulary",
            ));
        }
        if self.roster_root.is_some()
            || self.frontiers.roster_v1_namespace
            || self.frontiers.roster_v2_activation.is_some()
        {
            return Err(invalid(
                "native roster requires its complete generation vocabulary",
            ));
        }
        empty_without_root(&self.roster)
    }

    pub(in crate::consensus::native) fn admit_full_roster(
        &self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Ledger> {
        self.admit_roster_rows(
            self.roster.rows.values().cloned().map(Ok),
            self.roster
                .partitions
                .iter()
                .map(|(key, row)| (*key, (**row).clone())),
            self.roster.witness,
            check,
        )
    }

    pub(in crate::consensus::native) fn admit_roster_rows(
        &self,
        rows: impl IntoIterator<Item = io::Result<SharedRow<Row>>>,
        partitions: impl IntoIterator<Item = (ProductionFloorKey, Partition)>,
        witness: Option<GlobalChargeWitness>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Ledger> {
        check()?;
        let mut rows = rows.into_iter();
        let mut partitions = partitions.into_iter();
        let ledger = if let Some(root) = self.roster_root.as_deref() {
            let rows = rows.map(|row| {
                check()?;
                let row = row?;
                commands::validate_row_profile(&row, &self.frontiers)?;
                Ok(row)
            });
            Ledger::admit_detached_fallible(
                root,
                &fixed_scope(self.identity, &self.members),
                self.frontiers.sequence,
                self.frontiers.applied.map(|id| id.index),
                rows,
                partitions,
                witness,
                |key| Ok(self.keys.get(key).and_then(|row| row.record.clone())),
                check,
            )?
        } else {
            if rows.next().transpose()?.is_some()
                || partitions.next().is_some()
                || witness.is_some()
            {
                return Err(invalid(
                    "native roster state lacks its configured trust root",
                ));
            }
            Ledger::empty()
        };
        // Check both directions against the newly rebuilt index. An orphan
        // business flag cannot be admitted by merely supplying no roster row.
        for (key, row) in &self.keys {
            check()?;
            reserved_matches(key, row, &ledger)?;
        }
        check()?;
        Ok(ledger)
    }
}

impl NativeDelta<'_> {
    pub(in crate::consensus::native) fn accept_roster_savepoint(
        &mut self,
        ledger: Ledger,
        changes: Journal,
        keys: HashMap<SessionKey, NativeKeyState>,
        restore_revision: u64,
    ) -> io::Result<()> {
        changes.require_base(&self.roster)?;
        changes.require_current(&ledger)?;
        self.roster_changes.append(changes)?;
        for (key, row) in keys {
            self.set_key(key, row);
        }
        self.frontiers.restore_revision = restore_revision;
        self.roster = ledger;
        Ok(())
    }
}
