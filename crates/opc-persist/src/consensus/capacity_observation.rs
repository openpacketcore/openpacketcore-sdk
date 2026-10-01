//! Opt-in qualification bridge for actual prepared/native allocation owners.
//!
//! Enabled only by `dangerous-test-hooks`. Registrations contain allocation
//! identities, capacities and counter observers; never a backend or command.
//! Samples are partial lower bounds, with no allocator/header/parser estimate.
//! Addresses stay private. Immutable preparation borrows and synchronous native
//! borrows keep the measured owners alive while the callback joins transport.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::time::Instant;

use opc_consensus::engine::raft::AppendEntriesRequest;
use opc_consensus::engine::EntryPayload;
use opc_consensus::{
    ConsensusIdentity, ConsensusNodeId, ConsensusRequestId, ConsensusRpcFamily,
    ConsensusWireRequest,
};
use rusqlite::Connection;

use super::audit_mutation::{AuditedConfigCommand, AuditedConfigEffect, AuditedMutationFields};
use super::{
    ConfigMutationIntent, ConfigRaftTypeConfig, PreparedAuditedMutation, PreparedConfigCommit,
    PreparedConfigCommitOperation,
};
use crate::audit_authority::ledger::{EntryPayload as LedgerPayload, LedgerOperation, LedgerState};

pub(crate) mod append_buffers;
pub use append_buffers::{AppendOwnerSample, AppendStage};
pub mod raft_buffers;
pub mod working_buffers;

type Allocations = BTreeMap<usize, usize>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn vector<T>(allocations: &mut Allocations, values: &Vec<T>) {
    let bytes = values.capacity() * size_of::<T>();
    if bytes != 0 {
        allocations.insert(values.as_ptr() as usize, bytes);
    }
}

fn string(allocations: &mut Allocations, value: &String) {
    if value.capacity() != 0 {
        allocations.insert(value.as_ptr() as usize, value.capacity());
    }
}

fn boxed<T>(allocations: &mut Allocations, value: &T) {
    allocations.insert(std::ptr::from_ref(value) as usize, size_of::<T>());
}

fn commit_allocations(commit: &PreparedConfigCommit) -> Allocations {
    let mut allocations = Allocations::new();
    // All supported prepared append representations own this actual Box.
    boxed(&mut allocations, commit);
    vector(&mut allocations, &commit.record.encrypted_blob);
    string(&mut allocations, &commit.record.principal);
    vector(&mut allocations, &commit.record.plaintext_digest);
    vector(&mut allocations, &commit.audit);
    for audit in &commit.audit {
        string(&mut allocations, &audit.yang_path);
        if let Some(value) = &audit.previous_value {
            string(&mut allocations, value);
        }
        if let Some(value) = &audit.new_value {
            string(&mut allocations, value);
        }
    }
    allocations
}

fn audited_allocations(command: &AuditedConfigCommand) -> Option<Allocations> {
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &command.effect else {
        return None;
    };
    let mut allocations = commit_allocations(commit);
    // Arc aliases share this payload. Arc headers and reservation bookkeeping
    // are deliberately unmeasured, as in the existing command_heap oracle.
    boxed::<AuditedMutationFields>(&mut allocations, command);
    Some(allocations)
}

/// Borrow one genuine audited preparation's allocation map for a synchronous
/// join outside native apply. The authority comes from the immutable original
/// command, not a caller-supplied identity. The view cannot retain payloads or
/// escape the callback; unsupported effects return no measurement.
pub fn with_audited_allocations<R>(
    source: ConsensusNodeId,
    prepared: &PreparedAuditedMutation,
    capture: impl FnOnce(raft_buffers::AllocationView<'_>) -> R,
) -> Option<R> {
    let command = prepared.command();
    let allocations = audited_allocations(command)?;
    Some(capture(raft_buffers::AllocationView::new(
        command.handle.body.identity,
        source,
        &allocations,
    )))
}

fn ledger_allocations(ledger: &LedgerState) -> Allocations {
    let mut allocations = Allocations::new();
    vector(&mut allocations, &ledger.entries);
    vector(&mut allocations, &ledger.operations);
    if let Some(chain) = &ledger.continuity {
        vector(&mut allocations, &chain.rows);
    }
    for entry in &ledger.entries {
        match &entry.payload {
            LedgerPayload::Intent(value) => boxed(&mut allocations, &**value),
            LedgerPayload::Event(value) => boxed(&mut allocations, &**value),
            LedgerPayload::KeyTransition(value) => boxed(&mut allocations, &**value),
            LedgerPayload::Outcome { .. } | LedgerPayload::Terminal { .. } => {}
        }
    }
    allocations
}

struct PreparedRecord {
    node: ConsensusNodeId,
    root: usize,
    allocations: Allocations,
}

#[derive(Default)]
struct Preparations {
    next: u64,
    owners: BTreeMap<u64, PreparedRecord>,
}

/// Redaction-safe current preparation census. Bytes are not a resource bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreparationTotals {
    /// Borrow registrations; two aliases can register one physical command.
    pub registrations: usize,
    /// Unique immutable command identities across the registered nodes.
    pub commands: usize,
}

/// Metadata-only census of immutable genuinely prepared command allocations.
#[derive(Default)]
pub struct PreparationCensus {
    state: Mutex<Preparations>,
    // Lock order is state -> totals. Counter readers take only totals; no
    // observer is called while totals is locked. The owner barrier stays held
    // across native/transport joins, while callback counter reads stay safe.
    totals: Mutex<PreparationTotals>,
}

impl PreparationCensus {
    fn register<'a>(
        self: &Arc<Self>,
        node: ConsensusNodeId,
        root: usize,
        allocations: Allocations,
    ) -> Option<PreparationOwner<'a>> {
        let mut state = lock(&self.state);
        let id = state.next.checked_add(1)?;
        state.next = id;
        state.owners.insert(
            id,
            PreparedRecord {
                node,
                root,
                allocations,
            },
        );
        *lock(&self.totals) = preparation_totals(&state);
        Some(PreparationOwner {
            census: self.clone(),
            id,
            borrowed: PhantomData,
        })
    }

    /// Borrow a real bounded ordinary preparation without cloning its command.
    pub fn observe_commit<'a>(
        self: &Arc<Self>,
        node: ConsensusNodeId,
        prepared: &'a PreparedConfigCommitOperation,
    ) -> Option<PreparationOwner<'a>> {
        let ConfigMutationIntent::BoundedAppend { commit, .. } = prepared.capacity_intent() else {
            return None;
        };
        self.register(
            node,
            std::ptr::from_ref(&**commit) as usize,
            commit_allocations(commit),
        )
    }

    /// Borrow an audited preparation. Arc aliases deduplicate by actual identity.
    pub fn observe_audited<'a>(
        self: &Arc<Self>,
        node: ConsensusNodeId,
        prepared: &'a PreparedAuditedMutation,
    ) -> Option<PreparationOwner<'a>> {
        let command = prepared.command();
        self.register(
            node,
            std::ptr::from_ref(&**command) as usize,
            audited_allocations(command)?,
        )
    }

    /// Current registrations and distinct commands; contains no historical peak.
    /// Safe inside a native observer: this read does not take the owner barrier.
    pub fn snapshot(&self) -> PreparationTotals {
        *lock(&self.totals)
    }
}

fn preparation_totals(state: &Preparations) -> PreparationTotals {
    PreparationTotals {
        registrations: state.owners.len(),
        commands: state
            .owners
            .values()
            .map(|owner| (owner.node, owner.root))
            .collect::<BTreeSet<_>>()
            .len(),
    }
}

/// Borrow-only registration. Drop it before moving or freeing its real owner.
pub struct PreparationOwner<'a> {
    census: Arc<PreparationCensus>,
    id: u64,
    borrowed: PhantomData<&'a ()>,
}

impl Drop for PreparationOwner<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.census.state);
        state.owners.remove(&self.id);
        *lock(&self.census.totals) = preparation_totals(&state);
    }
}

/// Concrete native ledger checkpoint, inside the selected effect's SQL apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStage {
    /// Actual owned ledger after decoding; SQL's borrowed blob is excluded.
    DecodedLedger,
    /// Validated ledger while its original derived-operation Vec is still live.
    ValidatedLedger,
    /// Authenticated ledger and decoded effect before the actual mutation.
    AuthenticatedMutation,
    /// Actual mutated ledger and its one owned encoded write buffer.
    LedgerWrite,
}

/// One instant of real prepared/native capacities, before joining transport.
/// Timing fields diagnose the capture path; they are not capacity sample instants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeOwnerSample {
    /// Native source node selected by exact connection and operation request.
    pub source: ConsensusNodeId,
    /// Concrete checkpoint; no sum of independently measured phases.
    pub stage: NativeStage,
    /// Entry to the selected native scope, before registry lookup and command census.
    /// Monotonic diagnostic only; neither an API start nor an RPC deadline.
    pub native_scope_entered_at: Instant,
    /// Entry to this active census, before the preparation-owner lock and walks.
    /// The observer's callback entry follows this work; neither is a time limit.
    pub census_entered_at: Instant,
    /// Currently borrowed preparations across all observed nodes.
    pub preparations: PreparationTotals,
    /// Unique prepared commands on this one source node.
    pub node_prepared_commands: usize,
    /// Source node's union of real prepared allocations.
    pub node_prepared_bytes: usize,
    /// Selected immutable preparation's actual allocated extent.
    pub selected_prepared_bytes: usize,
    /// Actual independently decoded native command payload/Box/Vec/String extent.
    pub native_command_bytes: usize,
    /// Actual ledger vectors and boxed payload extents at this checkpoint.
    pub native_ledger_bytes: usize,
    /// Actual retained event count at this checkpoint.
    pub native_ledger_entries: usize,
    /// Actual retained operation count at this checkpoint.
    pub native_ledger_operations: usize,
    /// Actual continuity row count, or zero without continuity.
    pub native_continuity_rows: usize,
    /// Allocated element capacities for entries, operations and continuity rows.
    pub native_ledger_capacities: [usize; 3],
    /// Actual derived-operation Vec capacity, or zero outside validation.
    pub native_derived_bytes: usize,
    /// Actual native row-write Vec capacity, or zero outside that checkpoint.
    pub native_write_bytes: usize,
    /// Whether native allocations are distinct from the selected prepared ones.
    pub native_is_distinct: bool,
    /// Allocation-identity union for selected preparation plus native owners.
    pub selected_mutation_bytes: usize,
    /// Allocation-identity union for source preparations plus native owners.
    pub node_mutation_bytes: usize,
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) independent_oracles_match: bool,
}

/// Implementations may retain only counter/ID metadata and observation controls.
/// Called synchronously with native and immutable preparation owners still live.
/// Counter reads through `PreparationCensus::snapshot` are supported. Registering
/// or dropping preparation guards inside this callback is not supported: those
/// operations change owners protected by the active sample's drop barrier.
pub trait NativeOwnerObserver: Send + Sync {
    /// Join a current transport census here, before the borrowed owners can drop.
    fn observe(&self, sample: NativeOwnerSample);

    /// Join transport here while the original native append buffers are borrowed.
    /// This is a separate instant from an apply callback, never an added peak.
    fn observe_append(&self, _sample: AppendOwnerSample) {}

    /// Join original Raft owners while the exact current native union is borrowed.
    fn observe_with_allocations(
        &self,
        sample: NativeOwnerSample,
        _owners: raft_buffers::AllocationView<'_>,
    ) {
        self.observe(sample);
    }

    /// Join original Raft owners while the exact current append union is borrowed.
    fn observe_append_with_allocations(
        &self,
        sample: AppendOwnerSample,
        _owners: raft_buffers::AllocationView<'_>,
    ) {
        self.observe_append(sample);
    }
}

struct Shared {
    identity: ConsensusIdentity,
    source: ConsensusNodeId,
    request: ConsensusRequestId,
    selected_root: usize,
    preparations: Arc<PreparationCensus>,
    observer: Arc<dyn NativeOwnerObserver>,
    native_scopes: AtomicUsize,
    transport_scopes: AtomicUsize,
    callbacks: AtomicUsize,
    next_transport: AtomicU64,
    append_scopes: AtomicUsize,
    append_callbacks: AtomicUsize,
    next_append: AtomicU64,
}

static REGISTRY: LazyLock<Mutex<BTreeMap<usize, Weak<Shared>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Redaction-safe drainage for this exact registration only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeDrain {
    /// Whether the exact backend/request registration is still attached.
    pub registered: bool,
    /// Synchronous selected native scopes still running.
    pub native_scopes: usize,
    /// Typed selected append/snapshot scopes still running.
    pub transport_scopes: usize,
    /// Total concrete native checkpoint callbacks, not a capacity total.
    pub callbacks: usize,
    /// Selected synchronous append calls still running, including error unwind.
    pub append_scopes: usize,
    /// Concrete append checkpoints; contains no historical capacity maximum.
    pub append_callbacks: usize,
}

/// Metadata-only exact-connection/request attachment; detach after joined work.
pub struct NativeRegistration {
    connection: usize,
    shared: Arc<Shared>,
}

impl NativeRegistration {
    pub(super) fn new(
        conn: &Connection,
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
        request: ConsensusRequestId,
        prepared: &PreparedAuditedMutation,
        preparations: Arc<PreparationCensus>,
        observer: Arc<dyn NativeOwnerObserver>,
    ) -> Option<Self> {
        let connection = std::ptr::from_ref(conn) as usize;
        let mut registry = lock(&REGISTRY);
        if registry.get(&connection).and_then(Weak::upgrade).is_some() {
            return None;
        }
        let shared = Arc::new(Shared {
            identity,
            source,
            request,
            selected_root: std::ptr::from_ref(&**prepared.command()) as usize,
            preparations,
            observer,
            native_scopes: AtomicUsize::new(0),
            transport_scopes: AtomicUsize::new(0),
            callbacks: AtomicUsize::new(0),
            next_transport: AtomicU64::new(0),
            append_scopes: AtomicUsize::new(0),
            append_callbacks: AtomicUsize::new(0),
            next_append: AtomicU64::new(0),
        });
        registry.insert(connection, Arc::downgrade(&shared));
        Some(Self { connection, shared })
    }

    /// Detach this registration without touching any other observer or backend.
    pub fn detach(&self) {
        let mut registry = lock(&REGISTRY);
        if registry
            .get(&self.connection)
            .and_then(Weak::upgrade)
            .is_some_and(|value| Arc::ptr_eq(&value, &self.shared))
        {
            registry.remove(&self.connection);
        }
    }

    /// Current counters. Registration owns no native, RPC or preparation storage.
    pub fn snapshot(&self) -> NativeDrain {
        NativeDrain {
            registered: lock(&REGISTRY)
                .get(&self.connection)
                .and_then(Weak::upgrade)
                .is_some_and(|value| Arc::ptr_eq(&value, &self.shared)),
            native_scopes: self.shared.native_scopes.load(Ordering::SeqCst),
            transport_scopes: self.shared.transport_scopes.load(Ordering::SeqCst),
            callbacks: self.shared.callbacks.load(Ordering::SeqCst),
            append_scopes: self.shared.append_scopes.load(Ordering::SeqCst),
            append_callbacks: self.shared.append_callbacks.load(Ordering::SeqCst),
        }
    }
}

impl Drop for NativeRegistration {
    fn drop(&mut self) {
        self.detach();
    }
}

struct ActiveNative {
    shared: Arc<Shared>,
    entered_at: Instant,
    command: Allocations,
    #[cfg(all(test, target_os = "linux"))]
    command_oracle_bytes: usize,
}

thread_local! { static NATIVE: RefCell<Option<ActiveNative>> = const { RefCell::new(None) }; }

pub(crate) struct NativeScope<'a> {
    shared: Arc<Shared>,
    borrowed: PhantomData<&'a AuditedConfigCommand>,
}

impl<'a> NativeScope<'a> {
    pub(crate) fn start(
        conn: &Connection,
        request: ConsensusRequestId,
        command: &'a AuditedConfigCommand,
    ) -> Option<Self> {
        let entered_at = Instant::now();
        let shared = lock(&REGISTRY)
            .get(&(std::ptr::from_ref(conn) as usize))
            .and_then(Weak::upgrade)?;
        if shared.request != request {
            return None;
        }
        #[cfg(all(test, target_os = "linux"))]
        let command_oracle_bytes = super::store::observed_command_heap(command);
        let command = audited_allocations(command)?;
        NATIVE.with(|slot| {
            let mut current = slot.borrow_mut();
            if current.is_some() {
                return None;
            }
            *current = Some(ActiveNative {
                shared: shared.clone(),
                entered_at,
                command,
                #[cfg(all(test, target_os = "linux"))]
                command_oracle_bytes,
            });
            shared.native_scopes.fetch_add(1, Ordering::SeqCst);
            Some(Self {
                shared,
                borrowed: PhantomData,
            })
        })
    }
}

impl Drop for NativeScope<'_> {
    fn drop(&mut self) {
        NATIVE.with(|slot| {
            slot.borrow_mut().take();
        });
        self.shared.native_scopes.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) fn sample(stage: NativeStage, ledger: &LedgerState, write: Option<&Vec<u8>>) {
    sample_owners(stage, ledger, write, None);
}

pub(crate) fn validated_ledger(ledger: &LedgerState, derived: &Vec<LedgerOperation>) {
    // This borrows the original validation local, before its scope can end.
    // An inactive native registration returns before constructing any census.
    sample_owners(NativeStage::ValidatedLedger, ledger, None, Some(derived));
}

fn sample_owners(
    stage: NativeStage,
    ledger: &LedgerState,
    write: Option<&Vec<u8>>,
    derived: Option<&Vec<LedgerOperation>>,
) {
    NATIVE.with(|slot| {
        let active = slot.borrow();
        let Some(active) = active.as_ref() else {
            return;
        };
        let shared = &active.shared;
        let census_entered_at = Instant::now();
        // Keep this lock through the callback: a preparation registration cannot
        // disappear and permit its owner to drop between native and transport reads.
        let preparations = lock(&shared.preparations.state);
        let (mut node, mut selected, node_prepared_commands) =
            preparation_allocations(&preparations, shared);
        let native_is_distinct = active
            .command
            .keys()
            .all(|address| !selected.contains_key(address));
        let node_prepared_bytes = node.values().sum();
        let selected_prepared_bytes = selected.values().sum();
        #[cfg(all(test, target_os = "linux"))]
        let ledger_oracle_bytes =
            super::config_capacity_simultaneous_working_tests::ledger::ledger_heap(ledger);
        let native_ledger_entries = ledger.entries.len();
        let native_ledger_operations = ledger.operations.len();
        let (native_continuity_rows, continuity_capacity) = ledger
            .continuity
            .as_ref()
            .map_or((0, 0), |chain| (chain.rows.len(), chain.rows.capacity()));
        let native_ledger_capacities = [
            ledger.entries.capacity(),
            ledger.operations.capacity(),
            continuity_capacity,
        ];
        let ledger = ledger_allocations(ledger);
        let mut native = active.command.clone();
        native.extend(ledger.iter().map(|(&address, &bytes)| (address, bytes)));
        if let Some(write) = write {
            vector(&mut native, write);
        }
        if let Some(derived) = derived {
            vector(&mut native, derived);
        }
        node.extend(native.iter().map(|(&address, &bytes)| (address, bytes)));
        selected.extend(native);
        shared.callbacks.fetch_add(1, Ordering::SeqCst);
        shared.observer.observe_with_allocations(
            NativeOwnerSample {
                source: shared.source,
                stage,
                native_scope_entered_at: active.entered_at,
                census_entered_at,
                preparations: preparation_totals(&preparations),
                node_prepared_commands,
                node_prepared_bytes,
                selected_prepared_bytes,
                native_command_bytes: active.command.values().sum(),
                native_ledger_bytes: ledger.values().sum(),
                native_ledger_entries,
                native_ledger_operations,
                native_continuity_rows,
                native_ledger_capacities,
                native_derived_bytes: derived
                    .map_or(0, |values| values.capacity() * size_of::<LedgerOperation>()),
                native_write_bytes: write.map_or(0, Vec::capacity),
                native_is_distinct,
                selected_mutation_bytes: selected.values().sum(),
                node_mutation_bytes: node.values().sum(),
                #[cfg(all(test, target_os = "linux"))]
                independent_oracles_match: active.command.values().sum::<usize>()
                    == active.command_oracle_bytes
                    && ledger.values().sum::<usize>() == ledger_oracle_bytes,
            },
            raft_buffers::AllocationView::new(shared.identity, shared.source, &node),
        );
    });
}

fn preparation_allocations(
    preparations: &Preparations,
    shared: &Shared,
) -> (Allocations, Allocations, usize) {
    let mut node = Allocations::new();
    let mut selected = Allocations::new();
    let mut roots = BTreeSet::new();
    for owner in preparations
        .owners
        .values()
        .filter(|owner| owner.node == shared.source)
    {
        roots.insert(owner.root);
        node.extend(
            owner
                .allocations
                .iter()
                .map(|(&address, &bytes)| (address, bytes)),
        );
        if owner.root == shared.selected_root {
            selected.extend(
                owner
                    .allocations
                    .iter()
                    .map(|(&address, &bytes)| (address, bytes)),
            );
        }
    }
    (node, selected, roots.len())
}

pub(crate) struct TypedTransport {
    shared: Arc<Shared>,
    target: ConsensusNodeId,
    family: ConsensusRpcFamily,
    payload: usize,
    capacity: usize,
    snapshot_data_bytes: usize,
    generation: u64,
}

fn find_source(identity: ConsensusIdentity, source: ConsensusNodeId) -> Option<Arc<Shared>> {
    let registry = lock(&REGISTRY);
    let mut matches = registry
        .values()
        .filter_map(Weak::upgrade)
        .filter(|shared| shared.identity == identity && shared.source == source);
    let selected = matches.next()?;
    // Concurrent independent fixtures can use identical synthetic identities.
    // Without a unique source binding, refuse a transport witness.
    matches.next().is_none().then_some(selected)
}

pub(crate) fn append_context(
    identity: ConsensusIdentity,
    source: ConsensusNodeId,
    target: ConsensusNodeId,
    request: &AppendEntriesRequest<ConfigRaftTypeConfig>,
    payload: &Vec<u8>,
) -> Option<TypedTransport> {
    let shared = find_source(identity, source)?;
    // A single selected mutation prevents charging a shared batch twice.
    let [entry] = request.entries.as_slice() else {
        return None;
    };
    let EntryPayload::Normal(command) = &entry.payload else {
        return None;
    };
    if command.request_id != shared.request {
        return None;
    }
    transport_context(
        shared,
        target,
        ConsensusRpcFamily::AppendEntries,
        payload,
        0,
    )
}

pub(crate) fn snapshot_context(
    identity: ConsensusIdentity,
    source: ConsensusNodeId,
    target: ConsensusNodeId,
    data: &Vec<u8>,
    payload: &Vec<u8>,
) -> Option<TypedTransport> {
    let shared = find_source(identity, source)?;
    if data.capacity() != 0 && data.as_ptr() == payload.as_ptr() {
        return None;
    }
    transport_context(
        shared,
        target,
        ConsensusRpcFamily::InstallSnapshot,
        payload,
        data.capacity(),
    )
}

fn transport_context(
    shared: Arc<Shared>,
    target: ConsensusNodeId,
    family: ConsensusRpcFamily,
    payload: &Vec<u8>,
    snapshot_data_bytes: usize,
) -> Option<TypedTransport> {
    let generation = shared
        .next_transport
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        })
        .ok()?
        .checked_add(1)?;
    Some(TypedTransport {
        shared,
        target,
        family,
        payload: payload.as_ptr() as usize,
        capacity: payload.capacity(),
        snapshot_data_bytes,
        generation,
    })
}

tokio::task_local! { static TRANSPORT: TypedTransport; }

struct TransportScope(Arc<Shared>);
impl Drop for TransportScope {
    fn drop(&mut self) {
        self.0.transport_scopes.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) async fn scope_transport<F: Future>(
    context: Option<TypedTransport>,
    future: F,
) -> F::Output {
    match context {
        Some(context) => {
            context
                .shared
                .transport_scopes
                .fetch_add(1, Ordering::SeqCst);
            let _scope = TransportScope(context.shared.clone());
            TRANSPORT.scope(context, future).await
        }
        None => future.await,
    }
}

/// Opaque typed provenance carried across the move into the genuine peer call.
#[derive(Clone, Copy, Debug)]
pub struct TransportWitness {
    /// True only for one typed entry with the selected exact mutation request.
    pub selected_append: bool,
    /// Actual original snapshot data Vec capacity; separate from encoded RPC.
    pub snapshot_data_bytes: usize,
    /// Fresh per-registration call generation, independent of allocation reuse.
    pub generation: u64,
}

/// Check that the peer owns the exact same encoded allocation after its move.
/// No decoding, hashing, payload copy or public pointer identity is involved.
pub fn transport_witness(
    request: &ConsensusWireRequest,
    target: ConsensusNodeId,
) -> Option<TransportWitness> {
    TRANSPORT
        .try_with(|context| {
            (request.identity == context.shared.identity
                && request.sender == context.shared.source
                && target == context.target
                && request.family == context.family
                && request.payload.as_ptr() as usize == context.payload
                && request.payload.capacity() == context.capacity)
                .then_some(TransportWitness {
                    selected_append: context.family == ConsensusRpcFamily::AppendEntries,
                    snapshot_data_bytes: context.snapshot_data_bytes,
                    generation: context.generation,
                })
        })
        .ok()
        .flatten()
}
