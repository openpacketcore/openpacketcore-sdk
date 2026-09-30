//! Borrow the actual simultaneous target-preflight ledger owners. Registrations
//! and samples contain allocation metadata, never a ledger or retained payload.
//! This lower bound excludes allocator headers, parser scratch and SQLite memory.

use super::{AuditOperationHandle, EntryPayload, LedgerState};
use crate::audit_authority::AuditToken;
use crate::ConfigConsensusIdentity;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};

type Allocations = BTreeMap<usize, usize>;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn vector<T>(owners: &mut Allocations, value: &Vec<T>) {
    let bytes = value.capacity() * size_of::<T>();
    if bytes != 0 {
        owners.insert(value.as_ptr() as usize, bytes);
    }
}

fn boxed<T>(owners: &mut Allocations, value: &T) {
    owners.insert(std::ptr::from_ref(value) as usize, size_of::<T>());
}

#[derive(Default)]
struct Owners {
    allocations: Allocations,
    recovery_owners: Allocations,
    recovery: Allocations,
    maximum_plaintext_recovery: Allocations,
}

impl Owners {
    fn payload(&mut self, payload: &EntryPayload) {
        match payload {
            EntryPayload::Intent(value) => boxed(&mut self.allocations, &**value),
            EntryPayload::Event(value) => boxed(&mut self.allocations, &**value),
            EntryPayload::KeyTransition(value) => boxed(&mut self.allocations, &**value),
            EntryPayload::TargetIntent(value) => {
                boxed(&mut self.allocations, &**value);
                let (address, bytes) = value.recovery_owner_allocation();
                self.allocations.insert(address, bytes);
                self.recovery_owners.insert(address, bytes);
                if value.recovery.capacity() != 0 {
                    let address = value.recovery.as_ptr() as usize;
                    let capacity = value.recovery.capacity();
                    self.allocations.insert(address, capacity);
                    self.recovery.insert(address, capacity);
                    // Metadata to distinguish the two large authenticated
                    // originals from the small device/lock setup descriptions.
                    if value.recovery.len() >= opc_crypto::CONFIG_CAPACITY_V1_PLAINTEXT_BYTES {
                        self.maximum_plaintext_recovery.insert(address, capacity);
                    }
                }
            }
            EntryPayload::EmptyCommit(value) => boxed(&mut self.allocations, &**value),
            EntryPayload::Outcome { .. } | EntryPayload::Terminal { .. } => {}
        }
    }

    fn ledger(value: &LedgerState) -> Self {
        let mut owners = Self::default();
        vector(&mut owners.allocations, &value.entries);
        vector(&mut owners.allocations, &value.operations);
        if let Some(chain) = &value.continuity {
            vector(&mut owners.allocations, &chain.rows);
        }
        for entry in &value.entries {
            owners.payload(&entry.payload);
        }
        owners
    }
}

/// One synchronous instant after the real inner clone, before its mutation.
/// The three array positions are original, outer receiver and inner candidate.
#[derive(Clone, Debug)]
pub(crate) struct Sample {
    pub(crate) ledger_owned_bytes: [usize; 3],
    pub(crate) recovery_owner_bytes: [usize; 3],
    pub(crate) recovery_owned_bytes: [usize; 3],
    pub(crate) recovery_allocations: [usize; 3],
    pub(crate) large_recovery_bytes: [usize; 3],
    pub(crate) large_recovery_allocations: [usize; 3],
    pub(crate) incoming_owned_bytes: usize,
    pub(crate) distinct_ledger_roots: bool,
    pub(crate) distinct_ledger_allocations: bool,
    pub(crate) consistent_extents: bool,
    pub(crate) unique_recovery_owner_bytes: usize,
    pub(crate) unique_recovery_allocations: usize,
    pub(crate) unique_large_recovery_allocations: usize,
    pub(crate) unique_large_recovery_bytes: usize,
    pub(crate) shared_owned_bytes: usize,
    pub(crate) live_owned_bytes: usize,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Snapshot {
    pub(crate) preflight_scopes: usize,
    pub(crate) active_scopes: usize,
    pub(crate) samples: Vec<Sample>,
}

struct Watch {
    identity: ConfigConsensusIdentity,
    request: AuditToken,
    snapshot: Mutex<Snapshot>,
}

static WATCHES: LazyLock<Mutex<Vec<Weak<Watch>>>> = LazyLock::new(Mutex::default);

/// Process registration reaches the actual blocking SQLite worker. The exact
/// authority and privacy-projected request prevent unrelated test observations.
pub(crate) struct Observation(Arc<Watch>);

impl Observation {
    pub(crate) fn start(identity: ConfigConsensusIdentity, request: AuditToken) -> Self {
        let watch = Arc::new(Watch {
            identity,
            request,
            snapshot: Mutex::new(Snapshot::default()),
        });
        let mut watches = lock(&WATCHES);
        watches.retain(|previous| previous.strong_count() != 0);
        assert!(!watches
            .iter()
            .filter_map(Weak::upgrade)
            .any(|previous| { previous.identity == identity && previous.request == request }));
        watches.push(Arc::downgrade(&watch));
        Self(watch)
    }

    pub(crate) fn finish(self) -> Snapshot {
        lock(&self.0.snapshot).clone()
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        lock(&WATCHES).retain(|watch| !watch.ptr_eq(&Arc::downgrade(&self.0)));
    }
}

struct Original {
    watch: Arc<Watch>,
    root: usize,
    owners: Owners,
}

thread_local! {
    static ORIGINALS: RefCell<Vec<Original>> = const { RefCell::new(Vec::new()) };
}

/// The metadata remains valid because the original is immutably borrowed until
/// this guard drops. No pointer is dereferenced or retained after that scope.
pub(crate) struct Preflight<'a> {
    depth: Option<usize>,
    _borrowed: PhantomData<&'a LedgerState>,
}

impl<'a> Preflight<'a> {
    pub(crate) fn enter(ledger: &'a LedgerState, handle: &AuditOperationHandle) -> Self {
        let watch = lock(&WATCHES)
            .iter()
            .filter_map(Weak::upgrade)
            .find(|watch| {
                watch.identity == ledger.identity && watch.request == handle.body.binding.request
            });
        let depth = watch.map(|watch| {
            {
                let mut snapshot = lock(&watch.snapshot);
                snapshot.preflight_scopes += 1;
                snapshot.active_scopes += 1;
            }
            ORIGINALS.with(|originals| {
                let mut originals = originals.borrow_mut();
                let depth = originals.len();
                originals.push(Original {
                    watch,
                    root: std::ptr::from_ref(ledger) as usize,
                    owners: Owners::ledger(ledger),
                });
                depth
            })
        });
        Self {
            depth,
            _borrowed: PhantomData,
        }
    }
}

impl Drop for Preflight<'_> {
    fn drop(&mut self) {
        if let Some(depth) = self.depth {
            ORIGINALS.with(|originals| {
                let mut originals = originals.borrow_mut();
                assert_eq!(originals.len(), depth + 1);
                let original = originals.pop().expect("borrowed original scope");
                lock(&original.watch.snapshot).active_scopes -= 1;
            });
        }
    }
}

pub(super) fn admission_clone(
    receiver: &LedgerState,
    candidate: &LedgerState,
    payload: &EntryPayload,
) {
    ORIGINALS.with(|originals| {
        let originals = originals.borrow();
        let Some(original) = originals.last() else {
            return;
        };
        let receiver_owners = Owners::ledger(receiver);
        let candidate_owners = Owners::ledger(candidate);
        let ledgers = [&original.owners, &receiver_owners, &candidate_owners];
        let mut incoming = Owners::default();
        incoming.payload(payload);
        let mut union = Allocations::new();
        let mut exclusive = Allocations::new();
        let mut recovery_owners = Allocations::new();
        let mut recovery = Allocations::new();
        let mut large_recovery = Allocations::new();
        let mut distinct_ledger_allocations = true;
        let mut consistent_extents = true;
        let mut shared_owned_bytes = 0;
        for owners in ledgers.into_iter().chain([&incoming]) {
            for (&address, &capacity) in &owners.allocations {
                if let Some(previous) = union.insert(address, capacity) {
                    consistent_extents &= previous == capacity;
                    shared_owned_bytes += capacity;
                }
                if !owners.recovery_owners.contains_key(&address)
                    && !owners.recovery.contains_key(&address)
                {
                    distinct_ledger_allocations &= exclusive.insert(address, capacity).is_none();
                }
            }
            recovery_owners.extend(&owners.recovery_owners);
            recovery.extend(&owners.recovery);
            large_recovery.extend(&owners.maximum_plaintext_recovery);
        }
        let roots = [
            original.root,
            std::ptr::from_ref(receiver) as usize,
            std::ptr::from_ref(candidate) as usize,
        ];
        let sample = Sample {
            ledger_owned_bytes: ledgers.map(|owners| owners.allocations.values().sum()),
            recovery_owner_bytes: ledgers.map(|owners| owners.recovery_owners.values().sum()),
            recovery_owned_bytes: ledgers.map(|owners| owners.recovery.values().sum()),
            recovery_allocations: ledgers.map(|owners| owners.recovery.len()),
            large_recovery_bytes: ledgers
                .map(|owners| owners.maximum_plaintext_recovery.values().sum()),
            large_recovery_allocations: ledgers
                .map(|owners| owners.maximum_plaintext_recovery.len()),
            incoming_owned_bytes: incoming.allocations.values().sum(),
            distinct_ledger_roots: roots[0] != roots[1]
                && roots[0] != roots[2]
                && roots[1] != roots[2],
            distinct_ledger_allocations,
            consistent_extents,
            unique_recovery_owner_bytes: recovery_owners.values().sum(),
            unique_recovery_allocations: recovery.len(),
            unique_large_recovery_allocations: large_recovery.len(),
            unique_large_recovery_bytes: large_recovery.values().sum(),
            shared_owned_bytes,
            live_owned_bytes: union.values().sum(),
        };
        lock(&original.watch.snapshot).samples.push(sample);
    });
}
