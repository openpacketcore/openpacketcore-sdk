//! Real TLS provenance qualification, with an independent source-receipt ledger.
//!
//! The allocator exists only in this feature-gated unit-test executable. Its
//! callback records original Layout extents, never TLS/application stand-in
//! allocations. Tables are fixed and contain no observed resource owners.

use std::cell::Cell;
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Mutex as ReceiptMutex, Once, TryLockError};

use tracking_allocator::{
    AllocationGroupId, AllocationGroupToken, AllocationRegistry, AllocationTracker, Allocator,
};

use super::inbound_sockets::material_fixture_bindings;
use super::outbound_sockets::ready_cached_lanes_observed;
use super::*;
use capacity_observation::{
    ConsensusBufferObservation, TlsAllocationObserver, TlsAllocationSource,
};

#[global_allocator]
static TEST_ALLOCATOR: Allocator<std::alloc::System> = Allocator::system();

const OWNER_LIMIT: usize = 64;
const RECEIPT_LIMIT: usize = 16_384;
const PHASES: usize = 12;
const SATURATED: u32 = 1;
const ARITHMETIC: u32 = 2;
const UNMATCHED_FREE: u32 = 4;
const AMBIGUOUS_REUSE: u32 = 8;
const INVALID_SCOPE: u32 = 16;
const LATE_ALLOCATION: u32 = 32;

static SERIAL_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static INITIALIZE: Once = Once::new();
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);
static NEXT_THREAD: AtomicUsize = AtomicUsize::new(1);

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

struct Tracker;

impl AllocationTracker for Tracker {
    fn allocated(&self, address: usize, object: usize, wrapped: usize, group: AllocationGroupId) {
        let group = group.as_usize().get();
        let active = ACTIVE.with(Cell::get);
        let thread = THREAD.with(|thread| *thread);
        let mut ledger = ledger();
        let Some(index) = ledger.owners.iter().position(|owner| {
            owner.id != 0 && (owner.tls_group == group || owner.socket_group == group)
        }) else {
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
        for receipt in &ledger.receipts[..ledger.high_water] {
            if receipt.serial != 0 && receipt.address == address {
                reuse = true;
                ambiguous |= receipt.group == group
                    && receipt.object == object
                    && receipt.wrapped == wrapped;
            }
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
        let slot = ledger.receipts[..ledger.high_water]
            .iter()
            .position(|receipt| receipt.serial == 0)
            .unwrap_or(ledger.high_water);
        if slot == RECEIPT_LIMIT {
            ledger.flags |= SATURATED;
            return;
        }
        ledger.high_water = ledger.high_water.max(slot + 1);
        let enrolled = enroll_allocation(active.phase);
        ledger.receipts[slot] = Receipt {
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
        let source_group = source_group.as_usize().get();
        let current_group = current_group.as_usize().get();
        let thread = THREAD.with(|thread| *thread);
        let active = ACTIVE.with(Cell::get);
        let mut ledger = ledger();
        if let Some(owner) = ledger.owners.iter_mut().find(|owner| {
            owner.id != 0 && owner.tls_group == current_group && source_group != current_group
        }) {
            if !checked_increment(&mut owner.foreign_source_frees) {
                ledger.flags |= ARITHMETIC;
            }
        }
        if !ledger.owners.iter().any(|owner| {
            owner.id != 0 && (owner.tls_group == source_group || owner.socket_group == source_group)
        }) {
            return;
        }
        let receipt = ledger.receipts[..ledger.high_water]
            .iter()
            .enumerate()
            .filter(|(_, receipt)| {
                receipt.serial != 0
                    && receipt.address == address
                    && receipt.group == source_group
                    && receipt.object == object
                    && receipt.wrapped == wrapped
            })
            .min_by_key(|(_, receipt)| receipt.serial)
            .map(|(index, receipt)| (index, *receipt));
        let Some((slot, receipt)) = receipt else {
            ledger.flags |= UNMATCHED_FREE;
            return;
        };
        ledger.receipts[slot] = Receipt::EMPTY;
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
            for (index, owner) in ledger.owners.iter().enumerate() {
                if owner.run != self.run {
                    continue;
                }
                let mut tls = Extent::ZERO;
                let mut socket = Extent::ZERO;
                let mut owner_storage = Extent::ZERO;
                for receipt in &ledger.receipts[..ledger.high_water] {
                    if receipt.serial == 0 || receipt.owner_index != index {
                        continue;
                    }
                    let valid = if receipt.phase == TlsAllocationPhase::OwnerStorage {
                        owner_storage.add(receipt.object, receipt.wrapped)
                    } else if receipt.socket {
                        socket.add(receipt.object, receipt.wrapped)
                    } else {
                        tls.add(receipt.object, receipt.wrapped)
                    };
                    assert!(valid, "snapshot receipt arithmetic");
                }
                owners.push(OwnerSnapshot {
                    row: *owner,
                    tls,
                    socket,
                    owner_storage,
                });
            }
            Snapshot {
                owners,
                flags: ledger.flags,
                pointer_reuse_tails: ledger.pointer_reuse_tails,
            }
        })
    }
}

impl TlsAllocationObserver for Observation {
    fn open(&self, source: TlsAllocationSource) -> Option<u64> {
        AllocationRegistry::untracked(|| {
            let (Some(tls), Some(socket)) = (
                AllocationGroupToken::register(),
                AllocationGroupToken::register(),
            ) else {
                ledger().flags |= SATURATED;
                return None;
            };
            let tls_group = tls.id().as_usize().get();
            let socket_group = socket.id().as_usize().get();
            let mut ledger = ledger();
            let Some(index) = ledger.owners.iter().position(|owner| owner.id == 0) else {
                ledger.flags |= SATURATED;
                return None;
            };
            let id = (index + 1) as u64;
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

fn print_snapshot(checkpoint: &str, snapshot: &Snapshot) {
    for owner in &snapshot.owners {
        println!(
            "CONFIG_CAPACITY_TLS_SAMPLE checkpoint={} owner={} source={:?} material={:?} source_group={} object={} wrapped={} allocations={} runtime_object={} runtime_wrapped={} split_object={} split_wrapped={} visible={} closed={} cross_thread_frees={} foreign_source_frees={} unscoped_frees={} origins={:?} retired={:?}",
            checkpoint, owner.row.id, owner.row.source, owner.row.material, owner.row.tls_group,
            owner.tls.object, owner.tls.wrapped, owner.tls.allocations,
            owner.socket.object, owner.socket.wrapped, owner.owner_storage.object,
            owner.owner_storage.wrapped, owner.row.visible, owner.row.closed,
            owner.row.cross_thread_frees, owner.row.foreign_source_frees, owner.row.unscoped_frees,
            owner.row.origins,
            owner.row.retired,
        );
    }
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

fn assert_live(snapshot: &Snapshot, expected: usize) {
    assert_eq!(
        connection_rows(snapshot).count(),
        expected,
        "CONFIG_CAPACITY_TLS_OWNER_OMISSION_RED"
    );
    assert!(
        connection_rows(snapshot).all(|owner| owner.row.visible && !owner.row.closed),
        "CONFIG_CAPACITY_TLS_OWNER_EARLY_RETIREMENT_RED"
    );
    assert_conserved(snapshot);
    assert!(
        connection_rows(snapshot).all(|owner| owner.tls.object > 0),
        "CONFIG_CAPACITY_TLS_ORIGINAL_STORAGE_RED"
    );
    assert_eq!(
        material_rows(snapshot).count(),
        expected,
        "CONFIG_CAPACITY_TLS_MATERIAL_OMISSION_RED"
    );
    for connection in connection_rows(snapshot) {
        let material = material_rows(snapshot)
            .find(|material| Some(material.row.id) == connection.row.material)
            .expect("CONFIG_CAPACITY_TLS_MATERIAL_LINK_RED");
        assert!(
            material.row.closed && !material.row.visible,
            "material construction has ended independently of allocation lifetime"
        );
        assert!(
            material.row.origins[TlsAllocationPhase::MaterialConstruct as usize].object > 0,
            "CONFIG_CAPACITY_TLS_MATERIAL_SCOPE_RED"
        );
    }
}

fn assert_material_retained(snapshot: &Snapshot) {
    assert!(
        material_rows(snapshot).all(|owner| owner.tls.object > 0),
        "CONFIG_CAPACITY_TLS_MATERIAL_STORAGE_RED"
    );
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

#[tokio::test]
async fn mtls_allocations_follow_ready_cache_and_application_io() {
    let _serial = SERIAL_TEST.lock().await;
    let receipts = Observation::new();
    let observation = Arc::new(ConsensusBufferObservation::default());
    receipts.attach(&observation);
    let mut checkpoints = Vec::new();
    ready_cached_lanes_observed(true, observation, |name| {
        checkpoints.push((name, receipts.snapshot()));
    })
    .await;
    // The unchanged fixture completed authenticated Hello/Ack, three exact
    // application replies, both setup joins and server cleanup before assertions.
    println!("CONFIG_CAPACITY_TLS_MTLS_LIFECYCLE original_fixture=true replies=3 setup_joins=2 real_cleanup=true");
    for (name, sample) in &checkpoints {
        print_snapshot(name, sample);
        if *name == "drained" {
            assert_drained(sample);
        } else {
            assert_live(
                sample,
                if matches!(*name, "ready" | "first_active") {
                    2
                } else {
                    4
                },
            );
            for material in material_rows(sample) {
                // The pinned TLS 1.3 server traffic state no longer owns its
                // frozen config, and final bootstrap admission drops the SDK
                // handshake. The client traffic state retains its config.
                // Both lifetimes conserve the original allocation/free receipts.
                match material.row.source {
                    Some(TlsAllocationSource::InboundMaterial(_)) => assert_eq!(
                        material.tls,
                        Extent::ZERO,
                        "CONFIG_CAPACITY_TLS_SERVER_MATERIAL_RETIREMENT_RED"
                    ),
                    Some(TlsAllocationSource::OutboundMaterial(_)) => assert!(
                        material.tls.object > 0,
                        "CONFIG_CAPACITY_TLS_MATERIAL_STORAGE_RED"
                    ),
                    _ => unreachable!("material_rows selects only material sources"),
                }
            }
            assert!(connection_rows(sample).all(|owner| owner.row.established));
        }
    }
    let (_, final_sample) = checkpoints.last().expect("unchanged fixture checkpoints");
    assert_eq!(checkpoints.len(), 6);
    for owner in connection_rows(final_sample) {
        for phase in [
            TlsAllocationPhase::Construct,
            TlsAllocationPhase::HandshakePoll,
            TlsAllocationPhase::Write,
        ] {
            assert!(
                owner.row.origins[phase as usize].object > 0,
                "CONFIG_CAPACITY_TLS_PHASE_SCOPE_RED: actual TLS path produced no source receipts"
            );
        }
        assert!(
            owner.row.origins[TlsAllocationPhase::OwnerStorage as usize].object > 0,
            "CONFIG_CAPACITY_TLS_SPLIT_SCOPE_RED"
        );
        assert!(owner.row.scopes[TlsAllocationPhase::Read as usize] > 0);
        assert!(
            owner.row.frees[TlsAllocationPhase::StreamDrop as usize] > 0,
            "CONFIG_CAPACITY_TLS_STREAM_DROP_SCOPE_RED"
        );
    }
}

async fn cancelled_accept(poll_handshake: bool) {
    let _serial = SERIAL_TEST.lock().await;
    let receipts = Observation::new();
    let observation = Arc::new(ConsensusBufferObservation::default());
    receipts.attach(&observation);
    let (_, binding) = material_fixture_bindings();
    let material =
        crate::test_support::RotatableServerMaterial::new(binding.remote_spiffe_id().as_str());
    let config = material.config();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let address = listener.local_addr().expect("address");
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let (raw, accepted) = tokio::time::timeout_at(guard, async {
        tokio::join!(TcpStream::connect(address), listener.accept())
    })
    .await
    .expect("real TCP pair guard");
    let mut raw = raw.expect("raw client");
    let (stream, _) = accepted.expect("accepted socket");
    let stream = capacity_observation::InboundSocket::new(stream, Some(&observation));
    let numeric_socket_context = stream.context();
    let material_owner = stream.tls_material_owner();
    let handshake = config
        .begin_handshake_observed(|construct| {
            TlsOwner::run(
                material_owner.as_ref(),
                TlsAllocationPhase::MaterialConstruct,
                construct,
            );
        })
        .expect("existing material snapshot");
    let material_context = material_owner.as_ref().map(TlsOwner::context);
    drop(material_owner);
    let owner = stream.tls_owner();
    TlsOwner::link_material(owner.as_ref(), material_context.as_ref());
    let mut stream = Some(TlsIo::new(stream, owner.as_ref()));
    let future = TlsOwner::run(owner.as_ref(), TlsAllocationPhase::Construct, || {
        tokio_rustls::TlsAcceptor::from(consensus_server_tls_config(handshake.rustls_config()))
            .accept(stream.take().expect("constructor executes once"))
    });
    drop(handshake);
    let constructed = receipts.snapshot();
    let mut future = TlsHandshake::new(future, owner);
    let pending = if poll_handshake {
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut future).poll(cx).is_pending())).await
    } else {
        true
    };
    let stalled = receipts.snapshot();
    drop(future);
    let mut byte = [0_u8];
    let eof = tokio::time::timeout_at(guard, raw.read(&mut byte))
        .await
        .expect("cancelled TLS socket EOF guard")
        .expect("cancelled socket read");
    drop(raw);
    drop(listener);
    let drained = receipts.snapshot();
    assert!(pending);
    assert_eq!(eof, 0);
    assert!(observation.inbound_socket_snapshot().owners.is_empty());
    // Holding the numeric TCP context and both observers did not keep TLS alive.
    drop(numeric_socket_context);
    println!("CONFIG_CAPACITY_TLS_CANCEL_LIFECYCLE actual_accept=true polled={poll_handshake} future_dropped=true peer_eof=true");
    print_snapshot("constructed", &constructed);
    print_snapshot("stalled", &stalled);
    assert_live(&constructed, 1);
    assert_live(&stalled, 1);
    assert_material_retained(&constructed);
    assert_material_retained(&stalled);
    assert_drained(&drained);
    let owner = &connection_rows(&drained)
        .next()
        .expect("one TLS connection")
        .row;
    assert!(!owner.established);
    assert!(owner.origins[TlsAllocationPhase::Construct as usize].object > 0);
    if poll_handshake {
        assert!(
            owner.origins[TlsAllocationPhase::HandshakePoll as usize].object > 0,
            "CONFIG_CAPACITY_TLS_PHASE_SCOPE_RED"
        );
    } else {
        assert_eq!(owner.scopes[TlsAllocationPhase::HandshakePoll as usize], 0);
    }
    assert!(
        owner.frees[TlsAllocationPhase::HandshakeDrop as usize] > 0,
        "CONFIG_CAPACITY_TLS_HANDSHAKE_DROP_SCOPE_RED"
    );
}

#[tokio::test]
async fn stalled_tls_accept_keeps_receipts_until_future_cancellation() {
    cancelled_accept(true).await;
}

#[tokio::test]
async fn unpolled_tls_accept_drops_constructed_state_inside_owner_scope() {
    cancelled_accept(false).await;
}

#[tokio::test]
async fn mtls_last_split_half_drops_original_allocations_on_another_thread() {
    let _serial = SERIAL_TEST.lock().await;
    let receipts = Observation::new();
    let observation = Arc::new(ConsensusBufferObservation::default());
    receipts.attach(&observation);
    let (server_binding, binding) = material_fixture_bindings();
    let material =
        crate::test_support::RotatableServerMaterial::new(binding.remote_spiffe_id().as_str());
    let client_identity = server_binding
        .bind_remote(binding.local_replica_id().clone())
        .expect("reverse binding")
        .remote_spiffe_id()
        .clone();
    let client_config = material.trusted_client_config(client_identity.as_str());
    let server_config = material.config();
    let server_handshake = server_config.begin_handshake().expect("server material");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let address = listener.local_addr().expect("address");
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let client_tcp = capacity_observation::observe_outbound_attempt(
        Some(&observation),
        binding.local_consensus_node_id(),
        binding.remote_consensus_node_id(),
        async {
            let material_owner = capacity_observation::outbound_tls_material();
            let handshake = client_config
                .begin_handshake_observed(|construct| {
                    TlsOwner::run(
                        material_owner.as_ref(),
                        TlsAllocationPhase::MaterialConstruct,
                        construct,
                    );
                })
                .expect("client material");
            let context = material_owner.as_ref().map(TlsOwner::context);
            drop(material_owner);
            let socket = capacity_observation::OutboundSocket::new(
                TcpStream::connect(address).await.expect("connect"),
            );
            (socket, context, handshake)
        },
    );
    let (client, accepted) =
        tokio::time::timeout_at(guard, async { tokio::join!(client_tcp, listener.accept()) })
            .await
            .expect("real TCP pair guard");
    let (server, _) = accepted.expect("server socket");
    let (client, material_context, client_handshake) = client;
    let retained_material = client_handshake.rustls_config();
    let numeric_context = client.context();
    let owner = client.tls_owner();
    TlsOwner::link_material(owner.as_ref(), material_context.as_ref());
    let mut client = Some(TlsIo::new(client, owner.as_ref()));
    let connect = TlsOwner::run(owner.as_ref(), TlsAllocationPhase::Construct, || {
        let connector = tokio_rustls::TlsConnector::from(consensus_client_tls_config(
            client_handshake.rustls_config(),
        ));
        let name = ConsensusTarget::pinned(address)
            .tls_server_name(address)
            .expect("server name");
        connector.connect(name, client.take().expect("constructor executes once"))
    });
    drop(client_handshake);
    let acceptor = tokio_rustls::TlsAcceptor::from(consensus_server_tls_config(
        server_handshake.rustls_config(),
    ));
    let (client, server) = tokio::time::timeout_at(guard, async {
        tokio::join!(TlsHandshake::new(connect, owner), acceptor.accept(server))
    })
    .await
    .expect("original TLS handshake guard");
    let client = client.expect("mutual TLS client");
    let mut server = server.expect("mutual TLS server");
    assert_eq!(
        client
            .inner()
            .expect("live stream")
            .get_ref()
            .1
            .alpn_protocol(),
        Some(SESSION_CONSENSUS_ALPN)
    );
    assert_eq!(
        server.get_ref().1.alpn_protocol(),
        Some(SESSION_CONSENSUS_ALPN)
    );
    let (mut reader, mut writer) = client.split().expect("original TLS split");
    let mut byte = [0_u8];
    tokio::time::timeout_at(guard, async {
        server.write_all(&[7]).await.expect("server TLS write");
        server.flush().await.expect("server TLS flush");
        reader.read_exact(&mut byte).await.expect("client TLS read");
    })
    .await
    .expect("real TLS read guard");
    assert_eq!(byte, [7]);
    let split = receipts.snapshot();
    drop(reader);
    let one_half = receipts.snapshot();
    tokio::time::timeout_at(guard, async {
        writer
            .write_all(&[9])
            .await
            .expect("remaining half TLS write");
        writer.flush().await.expect("remaining half TLS flush");
        server.read_exact(&mut byte).await.expect("server TLS read");
    })
    .await
    .expect("real final-half IO guard");
    assert_eq!(byte, [9]);
    tokio::time::timeout_at(guard, writer.shutdown())
        .await
        .expect("original TLS shutdown guard")
        .expect("TLS close_notify");
    let shutdown = receipts.snapshot();
    std::thread::spawn(move || drop(writer))
        .join()
        .expect("actual final-half destructor joined");
    let eof = tokio::time::timeout_at(guard, server.read(&mut byte))
        .await
        .expect("TLS peer EOF guard")
        .expect("TLS peer close_notify read");
    drop(server);
    drop(listener);
    let material_tail = receipts.snapshot();
    drop(retained_material);
    let drained = receipts.snapshot();
    assert_eq!(eof, 0);
    let sockets = observation.outbound_socket_snapshot();
    assert!(sockets.attempts.is_empty() && sockets.sockets.is_empty());
    drop(numeric_context);
    println!("CONFIG_CAPACITY_TLS_SPLIT_LIFECYCLE mutual_tls=true actual_io_both_directions=true remaining_half_wrote=true close_notify=true destructor_thread_joined=true");
    for (name, sample) in [
        ("split", &split),
        ("one_half", &one_half),
        ("shutdown", &shutdown),
    ] {
        print_snapshot(name, sample);
        assert_live(sample, 1);
        assert_material_retained(sample);
        assert!(
            connection_rows(sample).all(|owner| owner.owner_storage.object > 0),
            "CONFIG_CAPACITY_TLS_SPLIT_SCOPE_RED"
        );
    }
    let split_owner = &connection_rows(&split)
        .next()
        .expect("split connection")
        .row;
    let one_half_owner = &connection_rows(&one_half)
        .next()
        .expect("remaining connection")
        .row;
    assert_eq!(split_owner.id, one_half_owner.id);
    assert_eq!(split_owner.source, one_half_owner.source);
    print_snapshot("material_tail", &material_tail);
    assert_conserved(&material_tail);
    assert!(
        connection_rows(&material_tail).all(|owner| owner.row.closed && owner.tls == Extent::ZERO)
    );
    assert!(
        material_rows(&material_tail).all(|owner| owner.row.closed && owner.tls.object > 0),
        "CONFIG_CAPACITY_TLS_MATERIAL_SHARED_TAIL_RED"
    );
    assert_drained(&drained);
    let owner = &connection_rows(&drained)
        .next()
        .expect("one TLS connection")
        .row;
    assert!(
        owner.cross_thread_frees > 0,
        "CONFIG_CAPACITY_TLS_CROSS_THREAD_SOURCE_RED"
    );
    assert!(
        owner.frees[TlsAllocationPhase::StreamDrop as usize] > 0,
        "CONFIG_CAPACITY_TLS_STREAM_DROP_SCOPE_RED"
    );
    assert!(owner.scopes[TlsAllocationPhase::Flush as usize] > 0);
    assert!(owner.scopes[TlsAllocationPhase::Shutdown as usize] > 0);
}
