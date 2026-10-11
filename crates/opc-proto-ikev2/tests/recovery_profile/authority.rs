//! Consumer ownership and local submission fencing, separate from SDK windows.

use bytes::Bytes;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use super::store::{CurrentCut, RowKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    DuplicateOwner,
    NotCommitted,
    Revoked,
}

struct Slot {
    generation: u64,
    active: Arc<AtomicBool>,
}
struct Registry {
    stamp: AtomicU64,
    next_generation: AtomicU64,
    slots: Mutex<BTreeMap<RowKey, Slot>>,
}

pub struct EpochOwners(Arc<Registry>);

impl EpochOwners {
    pub fn new(committed_stamp: u64) -> Self {
        Self(Arc::new(Registry {
            stamp: AtomicU64::new(committed_stamp),
            next_generation: AtomicU64::new(1),
            slots: Mutex::new(BTreeMap::new()),
        }))
    }

    /// Acquire before constructing either the window or its ordinary allocator.
    /// Revocation alone is insufficient: the previous executor must stop/drop.
    pub fn acquire(&self, cut: &CurrentCut) -> Result<Owner, Error> {
        let row = cut.row().ok_or(Error::NotCommitted)?;
        let mut slots = self.0.slots.lock().unwrap();
        if cut.stamp() != self.0.stamp.load(Ordering::SeqCst) {
            return Err(Error::Revoked);
        }
        if slots.contains_key(&cut.key()) {
            return Err(Error::DuplicateOwner);
        }
        let generation = self.0.next_generation.fetch_add(1, Ordering::SeqCst);
        let active = Arc::new(AtomicBool::new(true));
        slots.insert(
            cut.key(),
            Slot {
                generation,
                active: active.clone(),
            },
        );
        Ok(Owner {
            registry: self.0.clone(),
            permit: SendPermit {
                key: cut.key(),
                birth: row.version.birth,
                stamp: cut.stamp(),
                generation,
                active,
                registry: self.0.clone(),
            },
        })
    }

    /// Called on learned committed succession; no per-packet store read or timer.
    pub fn learn_succession(&self, stamp: u64) {
        let slots = self.0.slots.lock().unwrap();
        let prior = self.0.stamp.load(Ordering::SeqCst);
        assert!(stamp > prior);
        self.0.stamp.store(stamp, Ordering::SeqCst);
        for slot in slots.values() {
            slot.active.store(false, Ordering::SeqCst);
        }
    }
}

/// Affine owner for the entire key epoch, including canonical-disabled windows.
pub struct Owner {
    registry: Arc<Registry>,
    permit: SendPermit,
}

impl Owner {
    pub fn permit(&self) -> SendPermit {
        self.permit.clone()
    }
    pub fn revoke(&self) {
        let _slots = self.registry.slots.lock().unwrap();
        self.permit.active.store(false, Ordering::SeqCst);
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.revoke();
        let mut slots = self.registry.slots.lock().unwrap();
        if slots
            .get(&self.permit.key)
            .is_some_and(|slot| slot.generation == self.permit.generation)
        {
            slots.remove(&self.permit.key);
        }
    }
}

#[derive(Clone)]
pub struct SendPermit {
    key: RowKey,
    birth: u64,
    stamp: u64,
    generation: u64,
    active: Arc<AtomicBool>,
    registry: Arc<Registry>,
}

impl SendPermit {
    pub fn check(&self) -> Result<(), Error> {
        if !self.active.load(Ordering::SeqCst)
            || self.stamp != self.registry.stamp.load(Ordering::SeqCst)
        {
            return Err(Error::Revoked);
        }
        Ok(())
    }
    pub fn binding(&self) -> (RowKey, u64, u64) {
        (self.key, self.birth, self.stamp)
    }

    pub fn while_current<T>(&self, action: impl FnOnce() -> T) -> Result<T, Error> {
        let _slots = self.registry.slots.lock().unwrap();
        self.check()?;
        Ok(action())
    }

    pub fn while_both_current<T>(
        &self,
        other: &Self,
        action: impl FnOnce() -> T,
    ) -> Result<T, Error> {
        if !Arc::ptr_eq(&self.registry, &other.registry) {
            return Err(Error::NotCommitted);
        }
        let _slots = self.registry.slots.lock().unwrap();
        self.check()?;
        other.check()?;
        Ok(action())
    }
}

#[derive(Default)]
pub struct Transport {
    pub submitted: Vec<Bytes>,
    pub destinations: Vec<Option<(u32, u16)>>,
}

impl Transport {
    pub fn submit_to(
        &mut self,
        permit: &SendPermit,
        bytes: &[u8],
        destination: (u32, u16),
    ) -> Result<(), Error> {
        permit.while_current(|| {
            self.submitted.push(Bytes::copy_from_slice(bytes));
            self.destinations.push(Some(destination));
        })
    }
    pub fn submit(&mut self, permit: &SendPermit, bytes: &[u8]) -> Result<(), Error> {
        permit.while_current(|| {
            self.submitted.push(Bytes::copy_from_slice(bytes));
            self.destinations.push(None);
        })
    }
}
