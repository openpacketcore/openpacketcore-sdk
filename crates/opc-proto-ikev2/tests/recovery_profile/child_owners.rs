//! Idempotent consumer Child-SA ownership transfer from exact committed rekey
//! results. The packet-driven peer has a separate epoch/Child-SA oracle.

use super::{
    codec::ProfileCodec,
    driver::{Error, Runtime},
    envelope::{self, Provider},
    handoff, ke,
    row::{KeKind, Outcome, Row},
    store::{CasStore, Command, RowKey},
};
use std::collections::BTreeMap;

pub struct ChildOwners {
    owners: BTreeMap<u64, (RowKey, u64)>,
    pub changes: usize,
}

fn current(
    provider: &Provider,
    store: &CasStore,
    prior: &Command,
    runtime: &Runtime,
) -> Result<Row, Error> {
    runtime.permit().check()?;
    if runtime.pending.is_some() || runtime.row.closed {
        return Err(Error::Unresolved);
    }
    let cut = store.fenced_read(prior, runtime.row.key)?;
    let stored = cut.row().ok_or(Error::Closed)?;
    let plain = envelope::unseal(provider, cut.key(), stored)?;
    let row = ProfileCodec::decode(&plain, cut.key(), stored.version, stored.sealed_stamp)?;
    ke::validate_row(&row)?;
    if row.closed
        || row.version != runtime.row.version
        || runtime.permit().binding() != (row.key, row.version.birth, cut.stamp())
    {
        return Err(Error::Unresolved);
    }
    Ok(row)
}

impl ChildOwners {
    pub fn new(children: &[u64], row: &Row) -> Self {
        Self {
            owners: children
                .iter()
                .map(|id| (*id, (row.key, row.version.birth)))
                .collect(),
            changes: 0,
        }
    }

    pub fn owner(&self, child: u64) -> RowKey {
        self.owners[&child].0
    }

    pub fn transfer(
        &mut self,
        provider: &Provider,
        store: &CasStore,
        prior: &Command,
        old_runtime: &Runtime,
        new_runtime: &Runtime,
    ) -> Result<bool, Error> {
        let old = current(provider, store, prior, old_runtime)?;
        let new = current(provider, store, prior, new_runtime)?;
        if old
            .operations
            .values()
            .any(|op| op.kind == KeKind::IkeRekey && op.outcome == Outcome::Pending)
        {
            return Err(Error::Unresolved);
        }
        let mut winners = old
            .operations
            .values()
            .filter(|op| op.kind == KeKind::IkeRekey && op.outcome == Outcome::Success);
        let operation = winners.next().ok_or(Error::Unresolved)?;
        if winners.next().is_some()
            || operation.checkpoint.is_some()
            || operation.spis != new.spis
            || old.profile != new.profile
            || (old.identity, old.namespace) != (new.identity, new.namespace)
        {
            return Err(Error::Unresolved);
        }
        let expected = handoff::keys_from_bytes(
            old.profile,
            operation.derived.as_ref().ok_or(Error::Unresolved)?,
        )?;
        if expected.sk_d() != new.keys.sk_d()
            || expected.sk_ai() != new.keys.sk_ai()
            || expected.sk_ar() != new.keys.sk_ar()
            || expected.sk_ei() != new.keys.sk_ei()
            || expected.sk_er() != new.keys.sk_er()
            || expected.sk_pi() != new.keys.sk_pi()
            || expected.sk_pr() != new.keys.sk_pr()
        {
            return Err(Error::Unresolved);
        }
        let old_identity = (old.key, old.version.birth);
        let new_identity = (new.key, new.version.birth);
        if self
            .owners
            .values()
            .any(|owner| *owner != old_identity && *owner != new_identity)
        {
            return Err(Error::Unresolved);
        }
        old_runtime
            .permit()
            .while_both_current(&new_runtime.permit(), || {
                let mut changed = false;
                for owner in self.owners.values_mut() {
                    if *owner == old_identity {
                        *owner = new_identity;
                        self.changes += 1;
                        changed = true;
                    }
                }
                changed
            })
            .map_err(Error::from)
    }
}
