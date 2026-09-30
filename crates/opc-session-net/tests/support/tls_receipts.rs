// Shared only by qualification test executables. No production global allocator.
// OWNER_LIMIT, RECEIPT_LIMIT and RECEIPT_BUCKETS are bounded fixture capacities.
// Original source/thread/address/Layout/serial provenance survives foreign frees,
// owner closure, bucket collisions and free-list slot reuse. An indistinguishable
// same-tuple reuse invalidates the receipt rather than overwriting its generation.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Condvar, Mutex as ReceiptMutex, Once, TryLockError};
use tracking_allocator::{
    AllocationGroupId, AllocationGroupToken, AllocationRegistry, AllocationTracker, Allocator,
};

#[global_allocator]
static TEST_ALLOCATOR: Allocator<std::alloc::System> = Allocator::system();

const PHASES: usize = 12;
const GROUP_LIMIT: usize = OWNER_LIMIT * 2 + 2;
const EMPTY_SLOT: usize = usize::MAX;
const SATURATED: u32 = 1;
const ARITHMETIC: u32 = 2;
const UNMATCHED_FREE: u32 = 4;
const AMBIGUOUS_REUSE: u32 = 8;
const INVALID_SCOPE: u32 = 16;
const LATE_ALLOCATION: u32 = 32;

static INITIALIZE: Once = Once::new();
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);
static NEXT_THREAD: AtomicUsize = AtomicUsize::new(1);
static RECEIPT_CHANGED: Condvar = Condvar::new();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Extent {
    allocations: usize,
    object: usize,
    wrapped: usize,
}

impl Extent {
    const ZERO: Self = Self {
        allocations: 0,
        object: 0,
        wrapped: 0,
    };

    fn add(&mut self, object: usize, wrapped: usize) -> bool {
        match (
            self.allocations.checked_add(1),
            self.object.checked_add(object),
            self.wrapped.checked_add(wrapped),
        ) {
            (Some(allocations), Some(object), Some(wrapped)) => {
                *self = Self {
                    allocations,
                    object,
                    wrapped,
                };
                true
            }
            _ => false,
        }
    }

    fn subtract(&mut self, object: usize, wrapped: usize) -> bool {
        match (
            self.allocations.checked_sub(1),
            self.object.checked_sub(object),
            self.wrapped.checked_sub(wrapped),
        ) {
            (Some(allocations), Some(object), Some(wrapped)) => {
                *self = Self {
                    allocations,
                    object,
                    wrapped,
                };
                true
            }
            _ => false,
        }
    }
}

fn sum_extents<'a>(values: impl IntoIterator<Item = &'a Extent>) -> Extent {
    values.into_iter().fold(Extent::ZERO, |sum, value| Extent {
        allocations: sum
            .allocations
            .checked_add(value.allocations)
            .expect("receipt count"),
        object: sum
            .object
            .checked_add(value.object)
            .expect("receipt object bytes"),
        wrapped: sum
            .wrapped
            .checked_add(value.wrapped)
            .expect("receipt wrapped bytes"),
    })
}

#[derive(Clone, Copy)]
struct Active {
    owner: u64,
    phase: TlsAllocationPhase,
}

impl Active {
    const NONE: Self = Self {
        owner: 0,
        phase: TlsAllocationPhase::Construct,
    };
}

thread_local! {
    static ACTIVE: Cell<Active> = const { Cell::new(Active::NONE) };
    static THREAD: usize = NEXT_THREAD.fetch_update(
        Ordering::Relaxed, Ordering::Relaxed, |thread| thread.checked_add(1),
    ).unwrap_or_else(|_| { ledger().flags |= ARITHMETIC; 0 });
}

struct ActiveGuard(Active);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(self.0));
    }
}

fn socket_phase(phase: TlsAllocationPhase) -> bool {
    matches!(
        phase,
        TlsAllocationPhase::SocketPoll
            | TlsAllocationPhase::SocketDrop
            | TlsAllocationPhase::OwnerStorage
    )
}

// Observation controls change this decision only. Original source receipts,
// allocation groups, real I/O, TLS work, deadlines and cleanup stay intact.
fn enroll_allocation(_phase: TlsAllocationPhase) -> bool {
    true
}

#[derive(Clone, Copy)]
struct OwnerRow {
    run: u64,
    id: u64,
    source: Option<TlsAllocationSource>,
    material: Option<u64>,
    tls_group: usize,
    socket_group: usize,
    visible: bool,
    established: bool,
    closed: bool,
    origins: [Extent; PHASES],
    retired: [Extent; PHASES],
    enrolled_origins: [Extent; PHASES],
    reported_tls: Extent,
    reported_socket: Extent,
    reported_owner_storage: Extent,
    scopes: [usize; PHASES],
    frees: [usize; PHASES],
    cross_thread_frees: usize,
    foreign_source_frees: usize,
    unscoped_frees: usize,
}

impl OwnerRow {
    const EMPTY: Self = Self {
        run: 0,
        id: 0,
        source: None,
        material: None,
        tls_group: 0,
        socket_group: 0,
        visible: false,
        established: false,
        closed: false,
        origins: [Extent::ZERO; PHASES],
        retired: [Extent::ZERO; PHASES],
        enrolled_origins: [Extent::ZERO; PHASES],
        reported_tls: Extent::ZERO,
        reported_socket: Extent::ZERO,
        reported_owner_storage: Extent::ZERO,
        scopes: [0; PHASES],
        frees: [0; PHASES],
        cross_thread_frees: 0,
        foreign_source_frees: 0,
        unscoped_frees: 0,
    };
}

#[derive(Clone, Copy)]
struct Receipt {
    next: usize,
    serial: u64,
    address: usize,
    group: usize,
    owner_index: usize,
    object: usize,
    wrapped: usize,
    thread: usize,
    socket: bool,
    enrolled: bool,
    phase: TlsAllocationPhase,
}

impl Receipt {
    const EMPTY: Self = Self {
        next: EMPTY_SLOT,
        serial: 0,
        address: 0,
        group: 0,
        owner_index: 0,
        object: 0,
        wrapped: 0,
        thread: 0,
        socket: false,
        enrolled: false,
        phase: TlsAllocationPhase::Construct,
    };
}

struct Ledger {
    owners: [OwnerRow; OWNER_LIMIT],
    receipts: [Receipt; RECEIPT_LIMIT],
    groups: [usize; GROUP_LIMIT],
    buckets: [usize; RECEIPT_BUCKETS],
    free: usize,
    high_water: usize,
    serial: u64,
    flags: u32,
    pointer_reuse_tails: usize,
}

// Allocator callbacks neither allocate nor retain application/TLS objects.
// Poison recovery performs no formatting, logging, or recursive callback.
static LEDGER: ReceiptMutex<Ledger> = ReceiptMutex::new(Ledger {
    owners: [OwnerRow::EMPTY; OWNER_LIMIT],
    receipts: [Receipt::EMPTY; RECEIPT_LIMIT],
    groups: [0; GROUP_LIMIT],
    buckets: [EMPTY_SLOT; RECEIPT_BUCKETS],
    free: EMPTY_SLOT,
    high_water: 0,
    serial: 0,
    flags: 0,
    pointer_reuse_tails: 0,
});

fn ledger() -> std::sync::MutexGuard<'static, Ledger> {
    LEDGER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn checked_increment(value: &mut usize) -> bool {
    match value.checked_add(1) {
        Some(next) => {
            *value = next;
            true
        }
        None => false,
    }
}

// Only explicitly registered source groups map to rows. Source identities and
// group mappings are never reused, even after every original allocation frees.
impl Ledger {
    fn owner_index(&self, group: usize) -> Option<usize> {
        self.groups.get(group).copied()?.checked_sub(1)
    }

    fn bucket(address: usize) -> usize {
        (address >> 4)
            .checked_rem(RECEIPT_BUCKETS)
            .expect("receipt table has at least one bucket")
    }

    fn drained(&self, run: u64) -> bool {
        self.owners
            .iter()
            .all(|owner| owner.run != run || owner.closed)
            && self.receipts[..self.high_water].iter().all(|receipt| {
                receipt.serial == 0
                    || self.owners[receipt.owner_index].run != run
                    || (receipt.socket && receipt.phase != TlsAllocationPhase::OwnerStorage)
            })
    }
}

struct Tracker;

impl AllocationTracker for Tracker {
    fn allocated(&self, address: usize, object: usize, wrapped: usize, group: AllocationGroupId) {
        if group == AllocationGroupId::ROOT {
            return;
        }
        let group = group.as_usize().get();
        let active = ACTIVE.with(Cell::get);
        let thread = THREAD.with(|thread| *thread);
        let mut ledger = ledger();
        let Some(index) = ledger.owner_index(group) else {
            // Preexisting material, application, observer and unscoped runtime
            // storage are not connection TLS bytes.
            return;
        };
        let socket = ledger.owners[index].socket_group == group;
        if active.owner != ledger.owners[index].id || socket != socket_phase(active.phase) {
            ledger.flags |= INVALID_SCOPE;
        }
        if ledger.owners[index].closed && !socket {
            ledger.flags |= LATE_ALLOCATION;
        }
        let Some(serial) = ledger.serial.checked_add(1) else {
            ledger.flags |= ARITHMETIC;
            return;
        };
        ledger.serial = serial;
        let mut reuse = false;
        let mut ambiguous = false;
        let bucket = Ledger::bucket(address);
        let mut slot = ledger.buckets[bucket];
        while slot != EMPTY_SLOT {
            let receipt = &ledger.receipts[slot];
            if receipt.address == address {
                reuse = true;
                ambiguous |= receipt.group == group
                    && receipt.object == object
                    && receipt.wrapped == wrapped;
            }
            slot = receipt.next;
        }
        if reuse && !checked_increment(&mut ledger.pointer_reuse_tails) {
            ledger.flags |= ARITHMETIC;
        }
        if ambiguous {
            // System free precedes its callback. Keep both generations rather
            // than overwrite a still-unretired receipt. Identical tuples cannot
            // be disambiguated by this API; qualification fails explicitly.
            ledger.flags |= AMBIGUOUS_REUSE;
        }
        let slot = if ledger.free != EMPTY_SLOT {
            let slot = ledger.free;
            ledger.free = ledger.receipts[slot].next;
            slot
        } else if ledger.high_water < RECEIPT_LIMIT {
            let slot = ledger.high_water;
            ledger.high_water += 1;
            slot
        } else {
            ledger.flags |= SATURATED;
            return;
        };
        let enrolled = enroll_allocation(active.phase);
        ledger.receipts[slot] = Receipt {
            next: ledger.buckets[bucket],
            serial,
            address,
            group,
            owner_index: index,
            object,
            wrapped,
            thread,
            socket,
            enrolled,
            phase: active.phase,
        };
        ledger.buckets[bucket] = slot;
        let owner = &mut ledger.owners[index];
        let mut valid = owner.origins[active.phase as usize].add(object, wrapped);
        if enrolled {
            valid &= owner.enrolled_origins[active.phase as usize].add(object, wrapped);
            valid &= if active.phase == TlsAllocationPhase::OwnerStorage {
                owner.reported_owner_storage.add(object, wrapped)
            } else if socket {
                owner.reported_socket.add(object, wrapped)
            } else {
                owner.reported_tls.add(object, wrapped)
            };
        }
        if !valid {
            ledger.flags |= ARITHMETIC;
        }
    }

    fn deallocated(
        &self,
        address: usize,
        object: usize,
        wrapped: usize,
        source_group: AllocationGroupId,
        current_group: AllocationGroupId,
    ) {
        // Preserve root frees inside a TLS scope: they witness foreign-source
        // destruction. Only the entirely unobserved root/root pair bypasses us.
        if source_group == AllocationGroupId::ROOT && current_group == AllocationGroupId::ROOT {
            return;
        }
        let source_group = source_group.as_usize().get();
        let current_group = current_group.as_usize().get();
        let thread = THREAD.with(|thread| *thread);
        let active = ACTIVE.with(Cell::get);
        let mut ledger = ledger();
        if let Some(index) = ledger.owner_index(current_group) {
            let owner = &mut ledger.owners[index];
            if owner.tls_group == current_group
                && source_group != current_group
                && !checked_increment(&mut owner.foreign_source_frees)
            {
                ledger.flags |= ARITHMETIC;
            }
        }
        if ledger.owner_index(source_group).is_none() {
            return;
        }
        let bucket = Ledger::bucket(address);
        let mut previous = EMPTY_SLOT;
        let mut slot = ledger.buckets[bucket];
        let mut found: Option<(usize, usize, Receipt)> = None;
        while slot != EMPTY_SLOT {
            let receipt = ledger.receipts[slot];
            if receipt.address == address
                && receipt.group == source_group
                && receipt.object == object
                && receipt.wrapped == wrapped
                && found.is_none_or(|(_, _, old)| receipt.serial < old.serial)
            {
                found = Some((slot, previous, receipt));
            }
            previous = slot;
            slot = receipt.next;
        }
        let Some((slot, previous, receipt)) = found else {
            ledger.flags |= UNMATCHED_FREE;
            return;
        };
        if previous == EMPTY_SLOT {
            ledger.buckets[bucket] = receipt.next;
        } else {
            ledger.receipts[previous].next = receipt.next;
        }
        ledger.receipts[slot] = Receipt {
            next: ledger.free,
            ..Receipt::EMPTY
        };
        ledger.free = slot;
        let owner = &mut ledger.owners[receipt.owner_index];
        let mut valid = owner.retired[receipt.phase as usize].add(object, wrapped);
        if receipt.enrolled {
            valid &= if receipt.phase == TlsAllocationPhase::OwnerStorage {
                owner.reported_owner_storage.subtract(object, wrapped)
            } else if receipt.socket {
                owner.reported_socket.subtract(object, wrapped)
            } else {
                owner.reported_tls.subtract(object, wrapped)
            };
        }
        if !receipt.socket {
            if active.owner == owner.id {
                valid &= checked_increment(&mut owner.frees[active.phase as usize]);
            } else {
                valid &= checked_increment(&mut owner.unscoped_frees);
            }
            if receipt.thread != thread {
                valid &= checked_increment(&mut owner.cross_thread_frees);
            }
        }
        if !valid {
            ledger.flags |= ARITHMETIC;
        }
        drop(ledger);
        // Condvar notification does not execute an arbitrary async waker inside
        // the allocator's reentrancy guard. The owned waiter thread below sends
        // the async completion outside allocator callbacks and the ledger lock.
        RECEIPT_CHANGED.notify_all();
    }
}

// A finite wait owned by one test future. Timeout/cancellation wakes and joins
// this thread; it can never outlive the qualification future that created it.
struct DrainWait {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DrainWait {
    fn drop(&mut self) {
        {
            // Pair cancellation with the same mutex as Condvar::wait so a
            // cancellation between the predicate and wait cannot lose its wake.
            let _ledger = ledger();
            self.cancelled.store(true, Ordering::Relaxed);
        }
        RECEIPT_CHANGED.notify_all();
        if let Some(thread) = self.thread.take() {
            // The oneshot receiver reports worker failure. Drop still joins it
            // during unwinding without introducing a second panic.
            let _ = thread.join();
        }
    }
}

struct Tokens {
    tls: ReceiptMutex<Option<AllocationGroupToken>>,
    socket: ReceiptMutex<Option<AllocationGroupToken>>,
}

struct Observation {
    run: u64,
    tokens: [Tokens; OWNER_LIMIT],
}

impl Observation {
    fn new() -> Arc<Self> {
        INITIALIZE.call_once(|| {
            AllocationRegistry::set_global_tracker(Tracker).expect("one test allocator registry");
            AllocationRegistry::enable_tracking();
        });
        AllocationRegistry::untracked(|| {
            Arc::new(Self {
                run: NEXT_RUN
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |run| {
                        run.checked_add(1)
                    })
                    .expect("test run identity must not wrap"),
                tokens: std::array::from_fn(|_| Tokens {
                    tls: ReceiptMutex::new(None),
                    socket: ReceiptMutex::new(None),
                }),
            })
        })
    }

    fn attach(self: &Arc<Self>, observation: &ConsensusBufferObservation) {
        observation.set_tls_allocation_observer(self.clone());
    }

    fn snapshot(&self) -> Snapshot {
        AllocationRegistry::untracked(|| {
            let ledger = ledger();
            let mut owners = Vec::new();
            let mut positions = [EMPTY_SLOT; OWNER_LIMIT];
            for (index, owner) in ledger.owners.iter().enumerate() {
                if owner.run != self.run {
                    continue;
                }
                positions[index] = owners.len();
                owners.push(OwnerSnapshot {
                    row: *owner,
                    tls: Extent::ZERO,
                    socket: Extent::ZERO,
                    owner_storage: Extent::ZERO,
                });
            }
            // One pass over original live receipts; reported counters are a
            // separate enrollment oracle, never the source of these extents.
            for receipt in &ledger.receipts[..ledger.high_water] {
                if receipt.serial == 0 || positions[receipt.owner_index] == EMPTY_SLOT {
                    continue;
                }
                let owner = &mut owners[positions[receipt.owner_index]];
                let valid = if receipt.phase == TlsAllocationPhase::OwnerStorage {
                    owner.owner_storage.add(receipt.object, receipt.wrapped)
                } else if receipt.socket {
                    owner.socket.add(receipt.object, receipt.wrapped)
                } else {
                    owner.tls.add(receipt.object, receipt.wrapped)
                };
                assert!(valid, "snapshot receipt arithmetic");
            }
            Snapshot {
                owners,
                flags: ledger.flags,
                pointer_reuse_tails: ledger.pointer_reuse_tails,
            }
        })
    }

    /// After producers stop, wait for original TLS/material and split receipts.
    /// Socket/runtime receipts remain a separate category. Callers retain their
    /// existing finite deadline; cancellation terminates and joins this waiter.
    async fn wait_for_drain(&self) {
        let run = self.run;
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = cancelled.clone();
        let (completed, completion) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let mut ledger = ledger();
            while !ledger.drained(run) && !stop.load(Ordering::Relaxed) {
                ledger = RECEIPT_CHANGED
                    .wait(ledger)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            let drained = ledger.drained(run);
            drop(ledger);
            if drained {
                let _ = completed.send(());
            }
        });
        let _wait = DrainWait {
            cancelled,
            thread: Some(thread),
        };
        completion
            .await
            .expect("original TLS receipt waiter completed");
    }
}

impl TlsAllocationObserver for Observation {
    fn open(&self, source: TlsAllocationSource) -> Option<u64> {
        AllocationRegistry::untracked(|| {
            // Released tracking-allocator 0.4.0 issues group IDs with two atomic
            // operations. Serialize its allocation-free registration so a lower
            // issued ID cannot arrive after a higher ID at fetch_max and produce
            // a false exhaustion result. I/O and allocation scopes stay ungated.
            let mut ledger = ledger();
            let (Some(tls), Some(socket)) = (
                AllocationGroupToken::register(),
                AllocationGroupToken::register(),
            ) else {
                ledger.flags |= SATURATED;
                return None;
            };
            let tls_group = tls.id().as_usize().get();
            let socket_group = socket.id().as_usize().get();
            if tls_group >= GROUP_LIMIT || socket_group >= GROUP_LIMIT {
                ledger.flags |= SATURATED;
                return None;
            }
            let Some(index) = ledger.owners.iter().position(|owner| owner.id == 0) else {
                ledger.flags |= SATURATED;
                return None;
            };
            let id = (index + 1) as u64;
            ledger.groups[tls_group] = index + 1;
            ledger.groups[socket_group] = index + 1;
            ledger.owners[index] = OwnerRow {
                run: self.run,
                id,
                source: Some(source),
                tls_group,
                socket_group,
                visible: true,
                ..OwnerRow::EMPTY
            };
            drop(ledger);
            *self.tokens[index]
                .tls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tls);
            *self.tokens[index]
                .socket
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(socket);
            Some(id)
        })
    }

    fn link_material(&self, connection: u64, material: u64) {
        let mut ledger = ledger();
        let material_is_valid = ledger.owners.iter().any(|row| {
            row.run == self.run
                && row.id == material
                && matches!(
                    row.source,
                    Some(
                        TlsAllocationSource::InboundMaterial(_)
                            | TlsAllocationSource::OutboundMaterial(_)
                    )
                )
        });
        if material_is_valid {
            if let Some(row) = ledger.owners.iter_mut().find(|row| row.id == connection) {
                row.material = Some(material);
                return;
            }
        }
        ledger.flags |= INVALID_SCOPE;
    }

    fn scope(&self, owner: u64, phase: TlsAllocationPhase, operation: &mut dyn FnMut()) {
        let index = usize::try_from(owner)
            .ok()
            .and_then(|owner| owner.checked_sub(1));
        let token = index.and_then(|index| self.tokens.get(index));
        let Some(token) = token else {
            ledger().flags |= INVALID_SCOPE;
            operation();
            return;
        };
        {
            let mut ledger = ledger();
            let row = ledger.owners.iter_mut().find(|row| row.id == owner);
            if !row.is_some_and(|row| checked_increment(&mut row.scopes[phase as usize])) {
                ledger.flags |= ARITHMETIC;
            }
        }
        let previous = ACTIVE.with(|active| active.replace(Active { owner, phase }));
        let _active = ActiveGuard(previous);
        if previous.owner == owner && socket_phase(previous.phase) == socket_phase(phase) {
            operation();
            return;
        }
        let lock = if socket_phase(phase) {
            &token.socket
        } else {
            &token.tls
        };
        let mut token = match lock.try_lock() {
            Ok(token) => token,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                // Do not manufacture cross-connection serialization. This
                // marks the observation incomplete and still executes real I/O.
                ledger().flags |= INVALID_SCOPE;
                operation();
                return;
            }
        };
        let Some(token) = token.as_mut() else {
            ledger().flags |= INVALID_SCOPE;
            operation();
            return;
        };
        let guard = token.enter();
        operation();
        // Explicit exit() in released 0.4.0 also pops again in Drop. Use Drop.
        drop(guard);
    }

    fn established(&self, owner: u64) {
        let mut ledger = ledger();
        if let Some(row) = ledger.owners.iter_mut().find(|row| row.id == owner) {
            row.established = true;
        }
    }

    fn close(&self, owner: u64) {
        let mut ledger = ledger();
        if let Some(row) = ledger.owners.iter_mut().find(|row| row.id == owner) {
            row.closed = true;
            row.visible = false;
        }
        // Never erase source groups or outstanding receipts at owner closure.
        drop(ledger);
        RECEIPT_CHANGED.notify_all();
    }
}

struct OwnerSnapshot {
    row: OwnerRow,
    tls: Extent,
    socket: Extent,
    owner_storage: Extent,
}

struct Snapshot {
    owners: Vec<OwnerSnapshot>,
    flags: u32,
    pointer_reuse_tails: usize,
}

fn connection_rows(snapshot: &Snapshot) -> impl Iterator<Item = &OwnerSnapshot> {
    snapshot
        .owners
        .iter()
        .filter(|owner| matches!(owner.row.source, Some(TlsAllocationSource::Connection(_))))
}

fn material_rows(snapshot: &Snapshot) -> impl Iterator<Item = &OwnerSnapshot> {
    snapshot.owners.iter().filter(|owner| {
        matches!(
            owner.row.source,
            Some(
                TlsAllocationSource::InboundMaterial(_) | TlsAllocationSource::OutboundMaterial(_)
            )
        )
    })
}

fn assert_conserved(snapshot: &Snapshot) {
    assert_eq!(
        snapshot.flags, 0,
        "CONFIG_CAPACITY_TLS_RECEIPT_VALIDITY_RED"
    );
    for owner in &snapshot.owners {
        assert_eq!(
            owner.tls, owner.row.reported_tls,
            "CONFIG_CAPACITY_TLS_ENROLLMENT_RED: original live receipts differ"
        );
        assert_eq!(
            owner.socket, owner.row.reported_socket,
            "CONFIG_CAPACITY_TLS_SOCKET_CLASSIFICATION_RED"
        );
        assert_eq!(
            owner.owner_storage, owner.row.reported_owner_storage,
            "CONFIG_CAPACITY_TLS_SPLIT_ENROLLMENT_RED"
        );
        assert_eq!(
            owner.row.origins, owner.row.enrolled_origins,
            "CONFIG_CAPACITY_TLS_PHASE_ENROLLMENT_RED: original allocation receipts differ"
        );
        assert_eq!(
            sum_extents(&owner.row.origins),
            sum_extents(owner.row.retired.iter().chain([
                &owner.tls,
                &owner.socket,
                &owner.owner_storage,
            ])),
            "CONFIG_CAPACITY_TLS_RETIREMENT_RED: every original allocation is live or physically freed"
        );
        assert!(owner.tls.wrapped >= owner.tls.object);
    }
}

fn assert_drained(snapshot: &Snapshot) {
    assert_conserved(snapshot);
    assert!(snapshot
        .owners
        .iter()
        .all(|owner| owner.row.closed && !owner.row.visible));
    assert!(
        snapshot
            .owners
            .iter()
            .all(|owner| owner.tls == Extent::ZERO),
        "CONFIG_CAPACITY_TLS_FINAL_FREE_RED: owner closure is not allocation release"
    );
    assert!(
        snapshot
            .owners
            .iter()
            .all(|owner| owner.owner_storage == Extent::ZERO),
        "CONFIG_CAPACITY_TLS_SPLIT_CONTAINER_FREE_RED"
    );
    // Socket/runtime receipts are reported separately. Wakers can be retained
    // by the runtime after this task/stream closes; they cannot cancel TLS bytes.
    let runtime_object: usize = snapshot
        .owners
        .iter()
        .map(|owner| owner.socket.object)
        .sum();
    println!(
        "CONFIG_CAPACITY_TLS_RECEIPTS_DRAINED connections={} material_sources={} tls_object=0 material_object=0 split_object=0 runtime_object={} pointer_reuse_tails={} fixed_ledger_bytes={} token_storage_bytes={} snapshot_vector_bytes={} observer_arc_header=unmeasured tracker_thread_stack=unmeasured",
        connection_rows(snapshot).count(), material_rows(snapshot).count(), runtime_object,
        snapshot.pointer_reuse_tails, std::mem::size_of_val(&LEDGER),
        std::mem::size_of::<Observation>(),
        snapshot.owners.capacity() * std::mem::size_of::<OwnerSnapshot>(),
    );
}
