//! Opt-in inventory of actual SDK routing owners and enrolled recovery encoders.
//!
//! Records contain numeric allocation identities only. An owner wrapper moves
//! the existing value, never clones it, and drops it inside the capture barrier.
//! Transfer into Openraft ends this inventory's scope; engine-internal owners,
//! allocator/Arc headers and caller-owned returned recovery bytes are excluded.
//! A source registration must precede the work and remain until it drains.

use super::raft_buffers::AllocationView;
use super::{lock, Allocations};
use crate::consensus::audit_mutation::{AuditedConfigEffect, AuditedMutationFields};
use crate::consensus::{ConfigMutationIntent, PreparedAuditedMutation, PreparedConfigCommit};
use opc_consensus::{ConsensusIdentity, ConsensusNodeId, ConsensusRequestId};
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Deref;
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Observation metadata limits, unrelated to admission or the remote node count.
#[derive(Clone, Copy, Debug)]
pub struct WorkingBufferLimits {
    /// Maximum simultaneous source attachments, recovery enrollments and owners,
    /// and retained historical source counters, separately. Exhaustion refuses
    /// observation completeness; it never changes production admission.
    pub owners: usize,
    /// Maximum distinct nested allocations recorded for one actual owner.
    pub allocations_per_owner: usize,
}

impl Default for WorkingBufferLimits {
    fn default() -> Self {
        Self {
            owners: 256,
            allocations_per_owner: 4096,
        }
    }
}

/// Explicit reasons this inventory cannot account for its declared owners.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkingBufferIssues {
    /// Duplicate source or recovery enrollment, or source dropped before drain.
    pub ambiguous_source: bool,
    /// A metadata limit or generation counter was exhausted. Sticky until drop.
    pub metadata_saturated: bool,
    /// The same live allocation address had incompatible extents.
    pub inconsistent_extents: bool,
    /// An allocation extent or total could not be represented as `usize`.
    pub arithmetic_overflow: bool,
    /// A live intent has an unmeasured nested representation.
    pub unsupported_owners: usize,
    /// A recovery enrollment's authority differs from its immutable handle.
    pub mismatched_identity: bool,
    /// Recovery enrollment was removed while an enrolled output was still live.
    pub early_recovery_unregister: bool,
}

impl WorkingBufferIssues {
    /// Complete only within the documented SDK-staging and enrollment scope.
    /// This never certifies engine-internal or caller-owned memory coverage.
    pub fn complete(self) -> bool {
        self == Self::default()
    }

    fn merge(&mut self, other: Self) {
        self.ambiguous_source |= other.ambiguous_source;
        self.metadata_saturated |= other.metadata_saturated;
        self.inconsistent_extents |= other.inconsistent_extents;
        self.arithmetic_overflow |= other.arithmetic_overflow;
        self.unsupported_owners = self
            .unsupported_owners
            .saturating_add(other.unsupported_owners);
        self.mismatched_identity |= other.mismatched_identity;
        self.early_recovery_unregister |= other.early_recovery_unregister;
    }
}

/// The actual SDK owner currently holding an observed allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkingBufferKind {
    /// The original LocalIntent retained by the automatic routing loop.
    RoutingOriginal,
    /// A local attempt, including its read/admission barrier wait.
    LocalAttempt,
    /// The sender's original typed forwarding request, including supervision.
    ForwardAttempt,
    /// A finalized command before ownership is transferred into Openraft.
    FinalizedCommand,
    /// The actual reserved recovery output, before returning it to the caller.
    RecoveryOutput,
}

/// A synchronous checkpoint of an actual owner, outside the census mutex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkingBufferStage {
    /// Original immutable input or reserved output entered its observed scope.
    Retained,
    /// Serialization finished; the actual output and encoding guard remain live.
    RecoveryReady,
}

/// Redaction-safe metadata for one real owner; contains no allocation addresses.
#[derive(Clone, Copy, Debug)]
pub struct WorkingBufferOwner {
    /// The actual store authority, or the enrolled recovery handle's authority.
    pub identity: ConsensusIdentity,
    /// Store source for intents; explicit observer enrollment source for encode.
    pub source: ConsensusNodeId,
    /// Unique observation generation, never reused for retry or pointer reuse.
    pub generation: u64,
    /// Actual durable request for intents; recovery outputs are handle-enrolled.
    pub request: Option<ConsensusRequestId>,
    /// Actual SDK owner stage, independent of other phase measurements.
    pub kind: WorkingBufferKind,
    /// Allocation-identity union for this owner, including nested spare capacity.
    pub bytes: usize,
}

/// Synchronous hook useful for bounded test barriers. No payload is exposed.
/// Callbacks may capture this census but must not drop or mutate their own owner.
pub trait WorkingBufferObserver: Send + Sync {
    /// Observe a real retained owner. No census/registry lock is held here.
    fn observe(&self, stage: WorkingBufferStage, owner: WorkingBufferOwner);

    /// Test-only witness that an actual retirement attempt met a held capture.
    #[cfg(test)]
    fn retirement_blocked(&self) {}

    /// Test-only witness after a birth/resize encountered the capture barrier.
    #[cfg(test)]
    fn allocation_blocked(&self, _current_bytes: usize) {}
}

/// Current staged owners plus explicit transfer exclusions; never a peak sum.
#[derive(Clone, Debug)]
pub struct WorkingBufferSample {
    /// Live source attachments, which must begin before the measured work.
    pub registrations: usize,
    /// Borrow-only recovery enrollments; aliases must not enroll twice.
    pub recovery_enrollments: usize,
    /// Actual currently retained SDK owners.
    pub owners: Vec<WorkingBufferOwner>,
    /// Allocation union, deduplicated within each authority across all sources.
    pub bytes: usize,
    /// Completed transfers into Openraft. Their subsequent live bytes are outside
    /// this inventory, even when `owners` is empty; this is not a live-owner count.
    pub engine_transfers: usize,
    /// Recovery Vecs returned to callers, whose subsequent lifetime is excluded.
    pub caller_transfers: usize,
    /// Consistency and completeness for the declared staging scope only.
    pub issues: WorkingBufferIssues,
}

/// A simultaneous native/preparation plus working-buffer allocation union.
#[derive(Clone, Copy, Debug)]
pub struct WorkingBufferUnion {
    /// Exact borrowed authority; equal node IDs in other authorities never match.
    pub identity: ConsensusIdentity,
    /// Exact source selected by the borrowed allocation view.
    pub source: ConsensusNodeId,
    /// Current SDK staging owners on this authority/source pair.
    pub owners: usize,
    /// Original working-buffer union on this source.
    pub working_bytes: usize,
    /// Borrowed native/preparation union before this join.
    pub native_bytes: usize,
    /// Actual aliases present in both inventories.
    pub shared_bytes: usize,
    /// Native/preparation/working allocation union, with aliases counted once.
    pub union_bytes: usize,
    /// Completed engine transfers on this source; subsequent bytes are excluded.
    pub engine_transfers: usize,
    /// Consistency and coverage diagnostics for this inventory's declared scope.
    pub issues: WorkingBufferIssues,
}

struct Record {
    sample: WorkingBufferOwner,
    registration: u64,
    recovery: Option<u64>,
    allocations: Allocations,
    issues: WorkingBufferIssues,
}

struct Enrollment {
    registration: u64,
    root: usize,
}

#[derive(Default)]
struct State {
    next: u64,
    registrations: BTreeMap<u64, (ConsensusIdentity, ConsensusNodeId)>,
    enrollments: BTreeMap<u64, Enrollment>,
    owners: BTreeMap<u64, Record>,
    engine_transfers: HashMap<(ConsensusIdentity, ConsensusNodeId), usize>,
    caller_transfers: usize,
    issues: WorkingBufferIssues,
}

impl State {
    fn generation(&mut self) -> Option<u64> {
        let Some(next) = self.next.checked_add(1) else {
            self.issues.metadata_saturated = true;
            return None;
        };
        self.next = next;
        Some(next)
    }
}

/// Opt-in metadata census. The mutex is also the actual drop/transfer barrier.
pub struct WorkingBufferCensus {
    limits: WorkingBufferLimits,
    state: Mutex<State>,
}

impl Default for WorkingBufferCensus {
    fn default() -> Self {
        Self::new(WorkingBufferLimits::default())
    }
}

impl WorkingBufferCensus {
    /// Create bounded observation metadata. Zero limits refuse completeness.
    pub fn new(limits: WorkingBufferLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    /// Attach before submitting work on an exact authority/source pair.
    /// Retain until all observed SDK owners and enrolled encoders have drained.
    pub fn observe_source(
        self: &Arc<Self>,
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
        observer: Option<Arc<dyn WorkingBufferObserver>>,
    ) -> Option<WorkingBufferRegistration> {
        let mut registry = lock(&SOURCES);
        registry.retain(|value| value.strong_count() != 0);
        let mut state = lock(&self.state);
        if state.registrations.len() >= self.limits.owners {
            state.issues.metadata_saturated = true;
            return None;
        }
        if state
            .registrations
            .values()
            .any(|pair| *pair == (identity, source))
        {
            state.issues.ambiguous_source = true;
        }
        let id = state.generation()?;
        state.registrations.insert(id, (identity, source));
        let shared = Arc::new(Source {
            census: self.clone(),
            identity,
            source,
            id,
            observer,
        });
        registry.push(Arc::downgrade(&shared));
        Some(WorkingBufferRegistration { shared })
    }

    /// Borrow current metadata while actual owner drops/transfers are barred.
    /// Lock order: native/preparation, working census, then transport/Raft census.
    /// The callback must not await, drop/cancel owners, or reenter this census.
    pub fn with_current_capture<R>(&self, f: impl FnOnce(WorkingBufferCapture<'_>) -> R) -> R {
        let state = lock(&self.state);
        f(WorkingBufferCapture { state: &state })
    }
}

struct Source {
    census: Arc<WorkingBufferCensus>,
    identity: ConsensusIdentity,
    source: ConsensusNodeId,
    id: u64,
    observer: Option<Arc<dyn WorkingBufferObserver>>,
}

static SOURCES: LazyLock<Mutex<Vec<Weak<Source>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Scoped metadata-only source attachment; owns no request or preparation.
pub struct WorkingBufferRegistration {
    shared: Arc<Source>,
}

impl WorkingBufferRegistration {
    /// Enroll one genuine immutable audited command for public `encode` calls.
    /// Source is this explicit enrollment, not an inherent property of encode.
    /// The borrow prevents command identity reuse. Duplicate alias enrollment or
    /// unregistering during an encode is a sticky completeness failure.
    pub fn observe_recovery<'a>(
        &self,
        prepared: &'a PreparedAuditedMutation,
    ) -> Option<RecoveryEnrollment<'a>> {
        let _registry = lock(&SOURCES);
        let mut state = lock(&self.shared.census.state);
        if prepared.handle().body.identity != self.shared.identity {
            state.issues.mismatched_identity = true;
            return None;
        }
        if state.enrollments.len() >= self.shared.census.limits.owners {
            state.issues.metadata_saturated = true;
            return None;
        }
        let root = std::ptr::from_ref(&**prepared.command()) as usize;
        if state.enrollments.values().any(|value| value.root == root) {
            state.issues.ambiguous_source = true;
        }
        let id = state.generation()?;
        state.enrollments.insert(
            id,
            Enrollment {
                registration: self.shared.id,
                root,
            },
        );
        Some(RecoveryEnrollment {
            shared: self.shared.clone(),
            id,
            borrowed: PhantomData,
        })
    }
}

impl Drop for WorkingBufferRegistration {
    fn drop(&mut self) {
        let mut registry = lock(&SOURCES);
        registry.retain(|value| {
            value
                .upgrade()
                .is_some_and(|source| !Arc::ptr_eq(&source, &self.shared))
        });
        let mut state = lock(&self.shared.census.state);
        if state
            .owners
            .values()
            .any(|owner| owner.registration == self.shared.id)
            || state
                .enrollments
                .values()
                .any(|value| value.registration == self.shared.id)
        {
            state.issues.ambiguous_source = true;
        }
        state.registrations.remove(&self.shared.id);
    }
}

/// Borrow-only exact command enrollment. Cloning a preparation is unnecessary.
pub struct RecoveryEnrollment<'a> {
    shared: Arc<Source>,
    id: u64,
    borrowed: PhantomData<&'a PreparedAuditedMutation>,
}

impl Drop for RecoveryEnrollment<'_> {
    fn drop(&mut self) {
        let _registry = lock(&SOURCES);
        let mut state = lock(&self.shared.census.state);
        if state
            .owners
            .values()
            .any(|owner| owner.recovery == Some(self.id))
        {
            state.issues.early_recovery_unregister = true;
        }
        state.enrollments.remove(&self.id);
    }
}

/// Borrowed access held only during `with_current_capture`.
pub struct WorkingBufferCapture<'a> {
    state: &'a State,
}

impl WorkingBufferCapture<'_> {
    /// Copy redaction-safe numbers while the actual owners remain alive.
    pub fn sample(&self) -> WorkingBufferSample {
        let mut issues = self.state.issues;
        let mut authorities = HashMap::<ConsensusIdentity, Allocations>::new();
        for record in self.state.owners.values() {
            issues.merge(record.issues);
            extend(
                authorities.entry(record.sample.identity).or_default(),
                &record.allocations,
                &mut issues,
            );
        }
        let bytes = authorities.values().fold(0usize, |total, allocations| {
            checked_add(total, sum(allocations, &mut issues), &mut issues)
        });
        WorkingBufferSample {
            registrations: self.state.registrations.len(),
            recovery_enrollments: self.state.enrollments.len(),
            owners: self
                .state
                .owners
                .values()
                .map(|record| record.sample)
                .collect(),
            bytes,
            engine_transfers: self
                .state
                .engine_transfers
                .values()
                .fold(0, |total, value| checked_add(total, *value, &mut issues)),
            caller_transfers: self.state.caller_transfers,
            issues,
        }
    }

    /// Join actual allocation identities for exactly one authority/source pair.
    pub fn join(&self, native: &AllocationView<'_>) -> WorkingBufferUnion {
        self.with_joined(native, |sample, _| sample)
    }

    /// Extend the opaque borrowed union so later observers can deduplicate the
    /// same immutable allocations across native, working and transport owners.
    /// Neither this view nor its private allocation identities can be retained.
    pub fn with_joined<R>(
        &self,
        native: &AllocationView<'_>,
        f: impl FnOnce(WorkingBufferUnion, AllocationView<'_>) -> R,
    ) -> R {
        let mut issues = self.state.issues;
        if self
            .state
            .registrations
            .values()
            .filter(|pair| **pair == (native.identity, native.source))
            .count()
            != 1
        {
            issues.ambiguous_source = true;
        }
        let mut allocations = Allocations::new();
        let mut owners = 0;
        for record in self.state.owners.values().filter(|record| {
            record.sample.identity == native.identity && record.sample.source == native.source
        }) {
            owners += 1;
            issues.merge(record.issues);
            extend(&mut allocations, &record.allocations, &mut issues);
        }
        let working_bytes = sum(&allocations, &mut issues);
        let native_bytes = sum(native.allocations, &mut issues);
        let shared_bytes = allocations
            .iter()
            .filter(|(address, _)| native.allocations.contains_key(address))
            .fold(0, |total, (_, bytes)| {
                checked_add(total, *bytes, &mut issues)
            });
        extend(&mut allocations, native.allocations, &mut issues);
        let union_bytes = sum(&allocations, &mut issues);
        let sample = WorkingBufferUnion {
            identity: native.identity,
            source: native.source,
            owners,
            working_bytes,
            native_bytes,
            shared_bytes,
            union_bytes,
            engine_transfers: self
                .state
                .engine_transfers
                .get(&(native.identity, native.source))
                .copied()
                .unwrap_or(0),
            issues,
        };
        f(
            sample,
            AllocationView::new(native.identity, native.source, &allocations),
        )
    }
}

fn checked_add(a: usize, b: usize, issues: &mut WorkingBufferIssues) -> usize {
    a.checked_add(b).unwrap_or_else(|| {
        issues.arithmetic_overflow = true;
        usize::MAX
    })
}
fn sum(values: &Allocations, issues: &mut WorkingBufferIssues) -> usize {
    values
        .values()
        .fold(0, |total, bytes| checked_add(total, *bytes, issues))
}
fn insert(
    values: &mut Allocations,
    address: usize,
    bytes: usize,
    issues: &mut WorkingBufferIssues,
) {
    if bytes != 0 {
        if let Some(previous) = values.insert(address, bytes) {
            issues.inconsistent_extents |= previous != bytes;
        }
    }
}
fn extend(values: &mut Allocations, other: &Allocations, issues: &mut WorkingBufferIssues) {
    for (&address, &bytes) in other {
        insert(values, address, bytes, issues);
    }
}

struct Inventory {
    values: Allocations,
    limit: usize,
    issues: WorkingBufferIssues,
}
impl Inventory {
    fn add(&mut self, address: usize, bytes: usize) {
        if bytes != 0 && !self.values.contains_key(&address) && self.values.len() >= self.limit {
            self.issues.metadata_saturated = true;
        } else {
            insert(&mut self.values, address, bytes, &mut self.issues);
        }
    }
    fn vector<T>(&mut self, value: &Vec<T>) {
        match value.capacity().checked_mul(size_of::<T>()) {
            Some(bytes) => self.add(value.as_ptr() as usize, bytes),
            None => self.issues.arithmetic_overflow = true,
        }
    }
    fn string(&mut self, value: &String) {
        self.add(value.as_ptr() as usize, value.capacity());
    }
    fn boxed<T>(&mut self, value: &T) {
        self.add(std::ptr::from_ref(value) as usize, size_of::<T>());
    }
    fn commit(&mut self, value: &PreparedConfigCommit) {
        self.boxed(value);
        self.vector(&value.record.encrypted_blob);
        self.string(&value.record.principal);
        self.vector(&value.record.plaintext_digest);
        self.vector(&value.audit);
        for audit in &value.audit {
            self.string(&audit.yang_path);
            if let Some(value) = &audit.previous_value {
                self.string(value);
            }
            if let Some(value) = &audit.new_value {
                self.string(value);
            }
        }
    }
    fn intent(&mut self, intent: &ConfigMutationIntent) {
        match intent {
            ConfigMutationIntent::AppendCommit(commit)
            | ConfigMutationIntent::ResolveConfirmedAndAppend { commit, .. }
            | ConfigMutationIntent::BoundedAppend { commit, .. } => self.commit(commit),
            ConfigMutationIntent::AuditedMutation(command) => {
                self.boxed::<AuditedMutationFields>(command);
                match &command.effect {
                    AuditedConfigEffect::Append { commit, .. }
                    | AuditedConfigEffect::BoundedAppend { commit, .. } => self.commit(commit),
                    AuditedConfigEffect::RollbackPoint { label, .. } => {
                        if let Some(label) = label {
                            self.string(&label.0);
                        }
                    }
                    AuditedConfigEffect::Confirm { .. } => {}
                }
            }
            ConfigMutationIntent::CreateRollbackPoint { label, .. } => {
                if let Some(label) = label {
                    self.string(&label.0);
                }
            }
            ConfigMutationIntent::MarkConfirmed { .. }
            | ConfigMutationIntent::ClearRecoveryRequired { .. }
            | ConfigMutationIntent::RetainHistory(_) => {}
            ConfigMutationIntent::ManagementAudit(_) => self.issues.unsupported_owners += 1,
        }
    }
}

pub(crate) struct Observation {
    shared: Arc<Source>,
    generation: u64,
}
impl Observation {
    pub(crate) fn intent(
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
        request: ConsensusRequestId,
        kind: WorkingBufferKind,
        intent: &ConfigMutationIntent,
    ) -> Option<Self> {
        let registry = lock(&SOURCES);
        let matches: Vec<_> = registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|value| value.identity == identity && value.source == source)
            .collect();
        if matches.len() != 1 {
            for shared in matches {
                lock(&shared.census.state).issues.ambiguous_source = true;
            }
            return None;
        }
        let shared = matches.into_iter().next()?;
        let mut inventory = Inventory {
            values: Allocations::new(),
            limit: shared.census.limits.allocations_per_owner,
            issues: WorkingBufferIssues::default(),
        };
        inventory.intent(intent);
        Self::start(shared, Some(request), kind, None, inventory)
    }
    fn start(
        shared: Arc<Source>,
        request: Option<ConsensusRequestId>,
        kind: WorkingBufferKind,
        recovery: Option<u64>,
        inventory: Inventory,
    ) -> Option<Self> {
        let mut state = lock(&shared.census.state);
        Self::start_locked(&shared, &mut state, request, kind, recovery, inventory)
    }
    fn start_locked(
        shared: &Arc<Source>,
        state: &mut State,
        request: Option<ConsensusRequestId>,
        kind: WorkingBufferKind,
        recovery: Option<u64>,
        mut inventory: Inventory,
    ) -> Option<Self> {
        if state.owners.len() >= shared.census.limits.owners {
            state.issues.metadata_saturated = true;
            return None;
        }
        let generation = state.generation()?;
        let bytes = sum(&inventory.values, &mut inventory.issues);
        state.issues.metadata_saturated |= inventory.issues.metadata_saturated;
        state.owners.insert(
            generation,
            Record {
                sample: WorkingBufferOwner {
                    identity: shared.identity,
                    source: shared.source,
                    generation,
                    request,
                    kind,
                    bytes,
                },
                registration: shared.id,
                recovery,
                allocations: inventory.values,
                issues: inventory.issues,
            },
        );
        Some(Self {
            shared: shared.clone(),
            generation,
        })
    }
    fn checkpoint(&self, stage: WorkingBufferStage) {
        let sample = lock(&self.shared.census.state)
            .owners
            .get(&self.generation)
            .map(|value| value.sample);
        if let (Some(observer), Some(sample)) = (&self.shared.observer, sample) {
            observer.observe(stage, sample);
        }
    }
    fn kind(&self, kind: WorkingBufferKind) {
        if let Some(record) = lock(&self.shared.census.state)
            .owners
            .get_mut(&self.generation)
        {
            record.sample.kind = kind;
        }
    }
}

/// Vacate an actual owner without cloning or allocating a replacement payload.
/// Vacant values are private teardown placeholders and are never submitted.
pub(crate) trait Vacate {
    fn vacate(&mut self) -> Self;
}
impl Vacate for ConfigMutationIntent {
    fn vacate(&mut self) -> Self {
        std::mem::replace(
            self,
            Self::MarkConfirmed {
                tx_id: opc_types::TxId::from_uuid(uuid::Uuid::nil()),
            },
        )
    }
}
impl Vacate for Vec<u8> {
    fn vacate(&mut self) -> Self {
        std::mem::take(self)
    }
}

/// Owns the existing value in exactly its original lifecycle, not an extra copy.
pub(crate) struct Observed<T: Vacate> {
    value: T,
    observation: Option<Observation>,
}
impl<T: Vacate> Observed<T> {
    /// Construct an actual clone only after acquiring its birth/drop barrier.
    /// The closure may move/clone the closed SDK value, never call observers.
    pub(crate) fn create_intent(
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
        request: ConsensusRequestId,
        kind: WorkingBufferKind,
        create: impl FnOnce() -> T,
        intent: impl FnOnce(&T) -> &ConfigMutationIntent,
    ) -> Self {
        let registry = lock(&SOURCES);
        let matches: Vec<_> = registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|value| value.identity == identity && value.source == source)
            .collect();
        if matches.len() != 1 {
            for shared in matches {
                lock(&shared.census.state).issues.ambiguous_source = true;
            }
            drop(registry);
            return Self::new(create(), None);
        }
        let shared = &matches[0];
        #[cfg(test)]
        if shared.census.state.try_lock().is_err() {
            if let Some(observer) = &shared.observer {
                observer.allocation_blocked(0);
            }
        }
        let mut state = lock(&shared.census.state);
        let value = create();
        let mut inventory = Inventory {
            values: Allocations::new(),
            limit: shared.census.limits.allocations_per_owner,
            issues: WorkingBufferIssues::default(),
        };
        inventory.intent(intent(&value));
        let observation =
            Observation::start_locked(shared, &mut state, Some(request), kind, None, inventory);
        drop(state);
        drop(registry);
        Self::new(value, observation)
    }
    pub(crate) fn new(value: T, observation: Option<Observation>) -> Self {
        let owner = Self { value, observation };
        if let Some(observation) = &owner.observation {
            observation.checkpoint(WorkingBufferStage::Retained);
        }
        owner
    }
    pub(crate) fn attach(mut self, observation: Option<Observation>) -> Self {
        self.observation = observation;
        if let Some(observation) = &self.observation {
            observation.checkpoint(WorkingBufferStage::Retained);
        }
        self
    }
    /// Representation-preserving move; all inventoried nested owners move too.
    pub(crate) fn map<U: Vacate>(
        mut self,
        kind: WorkingBufferKind,
        f: impl FnOnce(T) -> U,
    ) -> Observed<U> {
        let value = f(self.value.vacate());
        let observation = self.observation.take();
        if let Some(observation) = &observation {
            observation.kind(kind);
        }
        Observed { value, observation }
    }
    pub(crate) fn into_engine(mut self) -> T {
        if let Some(observation) = self.observation.take() {
            let mut state = lock(&observation.shared.census.state);
            let pair = (observation.shared.identity, observation.shared.source);
            let previous = state.engine_transfers.get(&pair).copied().unwrap_or(0);
            let next = checked_add(previous, 1, &mut state.issues);
            if !state.engine_transfers.contains_key(&pair)
                && state.engine_transfers.len() >= observation.shared.census.limits.owners
            {
                state.issues.metadata_saturated = true;
            } else {
                state.engine_transfers.insert(pair, next);
            }
            let value = self.value.vacate();
            state.owners.remove(&observation.generation);
            value
        } else {
            self.value.vacate()
        }
    }
}
impl<T: Vacate> Deref for Observed<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T: Vacate + serde::Serialize> serde::Serialize for Observed<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}
impl<T: Vacate> Drop for Observed<T> {
    fn drop(&mut self) {
        if let Some(observation) = self.observation.take() {
            #[cfg(test)]
            if observation.shared.census.state.try_lock().is_err() {
                if let Some(observer) = &observation.shared.observer {
                    observer.retirement_blocked();
                }
            }
            let mut state = lock(&observation.shared.census.state);
            // The actual owner is destroyed before another capture can observe
            // retirement. No weak/strong payload clone survives this barrier.
            drop(self.value.vacate());
            state.owners.remove(&observation.generation);
        }
    }
}

/// Writer around the actual Vec, including its allocated-before-write interval.
pub(crate) struct RecoveryOutput(Observed<Vec<u8>>);
impl RecoveryOutput {
    pub(crate) fn start(prepared: &PreparedAuditedMutation) -> Self {
        let encoded = Vec::new();
        let root = std::ptr::from_ref(&**prepared.command()) as usize;
        let identity = prepared.handle().body.identity;
        let registry = lock(&SOURCES);
        let mut matches = Vec::new();
        for shared in registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|value| value.identity == identity)
        {
            let state = lock(&shared.census.state);
            for (&id, value) in &state.enrollments {
                if value.registration == shared.id && value.root == root {
                    matches.push((shared.clone(), id));
                }
            }
        }
        let observation = if matches.len() == 1 {
            let (shared, id) = matches.remove(0);
            let mut inventory = Inventory {
                values: Allocations::new(),
                limit: shared.census.limits.allocations_per_owner,
                issues: WorkingBufferIssues::default(),
            };
            inventory.vector(&encoded);
            Observation::start(
                shared,
                None,
                WorkingBufferKind::RecoveryOutput,
                Some(id),
                inventory,
            )
        } else {
            for (shared, _) in matches {
                lock(&shared.census.state).issues.ambiguous_source = true;
            }
            None
        };
        drop(registry);
        Self(Observed::new(encoded, observation))
    }
    pub(crate) fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> Result<(), std::collections::TryReserveError> {
        if let Some(observation) = &self.0.observation {
            #[cfg(test)]
            if observation.shared.census.state.try_lock().is_err() {
                if let Some(observer) = &observation.shared.observer {
                    observer.allocation_blocked(self.0.value.capacity());
                }
            }
            let mut state = lock(&observation.shared.census.state);
            self.0.value.try_reserve_exact(additional)?;
            self.update(&mut state);
        } else {
            self.0.value.try_reserve_exact(additional)?;
        }
        Ok(())
    }
    fn update(&self, state: &mut State) {
        if let Some(observation) = &self.0.observation {
            if let Some(record) = state.owners.get_mut(&observation.generation) {
                let mut inventory = Inventory {
                    values: Allocations::new(),
                    limit: observation.shared.census.limits.allocations_per_owner,
                    issues: WorkingBufferIssues::default(),
                };
                inventory.vector(&self.0.value);
                record.sample.bytes = sum(&inventory.values, &mut inventory.issues);
                record.allocations = inventory.values;
                record.issues.merge(inventory.issues);
                state.issues.metadata_saturated |= inventory.issues.metadata_saturated;
            }
        }
    }
    // Construct the public encoder result under the handoff barrier. This is
    // logical result ownership transfer, not evidence of caller scheduling.
    pub(crate) fn finish(mut self) -> Result<Vec<u8>, crate::audit_authority::AuditAuthorityError> {
        if let Some(observation) = &self.0.observation {
            observation.checkpoint(WorkingBufferStage::RecoveryReady);
        }
        if let Some(observation) = self.0.observation.take() {
            let mut state = lock(&observation.shared.census.state);
            state.caller_transfers = checked_add(state.caller_transfers, 1, &mut state.issues);
            let value = self.0.value.vacate();
            state.owners.remove(&observation.generation);
            Ok(value)
        } else {
            Ok(self.0.value.vacate())
        }
    }
}
impl std::io::Write for RecoveryOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() <= self.0.value.capacity() - self.0.value.len() {
            // The counted output fits its reservation; pointer and capacity
            // remain immutable, so numeric captures need no per-token lock.
            self.0.value.extend_from_slice(bytes);
        } else if let Some(observation) = &self.0.observation {
            // If a future serializer changes that assumption, any reallocation
            // and metadata replacement still occur under the retirement barrier.
            let mut state = lock(&observation.shared.census.state);
            self.0.value.extend_from_slice(bytes);
            self.update(&mut state);
        } else {
            self.0.value.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
