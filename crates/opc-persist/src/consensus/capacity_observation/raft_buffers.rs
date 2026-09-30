//! Original typed requests owned by the real Raft append encoder.
//!
//! This opt-in census retains numeric metadata only. It measures the entries
//! Vec backing and recognized nested allocation extents, including spare
//! capacity. Arc headers, allocator overhead, stack frames and observation
//! metadata are excluded. Encoded transport buffers are separate owners.
//! A complete sample means this declared inventory is covered, not that a
//! whole-node, 32 MiB operation or 256 MiB fleet bound has been established.

use super::{lock, Allocations};
use crate::consensus::audit_mutation::{AuditedConfigEffect, AuditedMutationFields};
use crate::consensus::{ConfigMutationIntent, ConfigRaftTypeConfig, PreparedConfigCommit};
use opc_consensus::engine::raft::AppendEntriesRequest;
use opc_consensus::engine::EntryPayload;
use opc_consensus::{
    ConsensusIdentity, ConsensusNodeId, ConsensusRequestId, ConsensusRpcFamily,
    ConsensusWireRequest,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::mem::size_of;
use std::sync::{Arc, LazyLock, Mutex, Weak};

/// Observation metadata limits, independent of any admitted payload budget.
#[derive(Clone, Copy, Debug)]
pub struct RaftAppendLimits {
    /// Maximum simultaneous source attachments and original calls, separately.
    pub calls: usize,
    /// Maximum recorded entry identities per original call.
    pub entries_per_call: usize,
    /// Maximum recorded distinct nested allocations per original call.
    pub allocations_per_call: usize,
}

impl Default for RaftAppendLimits {
    fn default() -> Self {
        Self {
            calls: 256,
            entries_per_call: 256,
            allocations_per_call: 4096,
        }
    }
}

/// Explicit reasons why the declared inventory cannot certify completeness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RaftAppendIssues {
    /// More than one attachment could claim a source, or no source was attached.
    pub ambiguous_source: bool,
    /// A metadata limit or generation counter was exhausted. Sticky until drop.
    pub metadata_saturated: bool,
    /// A simultaneously live address had contradictory allocation extents.
    pub inconsistent_extents: bool,
    /// An extent or total could not be represented as `usize`.
    pub arithmetic_overflow: bool,
    /// Live entries with an unmeasured nested representation.
    pub unsupported_entries: usize,
    /// Live normal commands whose scope differs from the actual source binding.
    pub mismatched_identity_entries: usize,
}

impl RaftAppendIssues {
    /// Whether every declared owner was inventoried without a consistency fault.
    pub fn complete(self) -> bool {
        self == Self::default()
    }

    fn merge(&mut self, other: Self) {
        self.ambiguous_source |= other.ambiguous_source;
        self.metadata_saturated |= other.metadata_saturated;
        self.inconsistent_extents |= other.inconsistent_extents;
        self.arithmetic_overflow |= other.arithmetic_overflow;
        self.unsupported_entries = self
            .unsupported_entries
            .saturating_add(other.unsupported_entries);
        self.mismatched_identity_entries = self
            .mismatched_identity_entries
            .saturating_add(other.mismatched_identity_entries);
    }
}

/// Identity and measured extent of one original batch entry, without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaftAppendEntry {
    /// Actual log index; multiple entries may bear the same mutation request.
    pub log_index: u64,
    /// Exact normal-command request ID, absent for blank or membership entries.
    pub request: Option<ConsensusRequestId>,
    /// Declared nested extent for this entry. Aliases can repeat this number.
    /// Use the union on the call or capture when accounting bytes.
    pub payload_bytes: usize,
    /// Whether this entry's nested representation was inventoried completely.
    pub supported: bool,
}

/// One currently borrowed original typed call, attributed to its actual route.
#[derive(Clone, Debug)]
pub struct RaftAppendCall {
    /// Exact source identity, independent of selected native mutation requests.
    pub identity: ConsensusIdentity,
    /// Actual source node.
    pub source: ConsensusNodeId,
    /// Actual follower target.
    pub target: ConsensusNodeId,
    /// Unique original-call identity within this census, never reused on retry.
    pub generation: u64,
    /// Actual original batch length, even if attribution metadata saturated.
    pub entries: usize,
    /// Actual entries Vec capacity in bytes, including unused descriptor slots.
    pub descriptor_bytes: usize,
    /// Allocation-identity union of recognized nested payloads in this call.
    pub payload_bytes: usize,
    /// All original entry identities, subject to the explicit metadata limit.
    pub attribution: Vec<RaftAppendEntry>,
}

/// Encoded call provenance; this metadata owns no typed or encoded payload.
/// Use an actual wire borrow and `raft_append_witness` to establish wire liveness.
#[derive(Clone, Debug)]
pub struct RaftAppendOrigin {
    /// Exact authority of the originating typed call.
    pub identity: ConsensusIdentity,
    /// Actual source node.
    pub source: ConsensusNodeId,
    /// Actual follower target.
    pub target: ConsensusNodeId,
    /// Original-call identity, preserved after its typed allocations retire.
    pub generation: u64,
    /// Original batch length.
    pub entries: usize,
    /// Historical entry attribution; these extents are not current ownership.
    pub attribution: Vec<RaftAppendEntry>,
}

/// Current redaction-safe snapshot; never a sum of separate phase maxima.
#[derive(Clone, Debug)]
pub struct RaftAppendSample {
    /// Currently attached source registrations, separate from active calls.
    pub registrations: usize,
    /// Current original calls; empty heartbeat batches remain visible.
    pub calls: Vec<RaftAppendCall>,
    /// Metadata for encoded call contexts, separate from current typed owners.
    pub origins: Vec<RaftAppendOrigin>,
    /// Unique original entries Vec backing extents across all live calls.
    pub descriptor_bytes: usize,
    /// Unique nested payload extents across all live calls and true aliases.
    pub payload_bytes: usize,
    /// Union of descriptor and nested allocations across all live calls.
    pub original_bytes: usize,
    /// Completeness and identity diagnostics for this simultaneous inventory.
    pub issues: RaftAppendIssues,
}

/// Borrowed numeric native/preparation allocation set for a synchronous join.
/// Private identities cannot be inspected, cloned, or saved as owned evidence.
pub struct AllocationView<'a> {
    identity: ConsensusIdentity,
    source: ConsensusNodeId,
    allocations: &'a Allocations,
}

impl<'a> AllocationView<'a> {
    // The native bridge constructs this only while its real owners are borrowed.
    // Keeping it here lets the bridge expose no allocation addresses publicly.
    pub(crate) fn new(
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
        allocations: &'a Allocations,
    ) -> Self {
        Self {
            identity,
            source,
            allocations,
        }
    }
}

/// Simultaneous union of a source's native/preparation and typed Raft owners.
#[derive(Clone, Copy, Debug)]
pub struct RaftAppendUnion {
    /// Exact consensus authority carried by the borrowed native allocation view.
    pub identity: ConsensusIdentity,
    /// Source carried by the opaque borrowed native allocation view.
    pub source: ConsensusNodeId,
    /// Original calls on this source, including every follower and batch entry.
    pub calls: usize,
    /// Recognized typed allocation union on this source.
    pub original_bytes: usize,
    /// Borrowed native/preparation union before joining original requests.
    pub native_bytes: usize,
    /// Bytes whose actual allocation identity occurs in both sets.
    pub shared_bytes: usize,
    /// Allocation-identity union, with shared allocations counted once.
    pub union_bytes: usize,
    /// Contradictory extents, unsupported kinds and saturation refuse coverage.
    pub issues: RaftAppendIssues,
}

struct Call {
    sample: RaftAppendCall,
    registration: u64,
    descriptors: Allocations,
    payloads: Allocations,
    issues: RaftAppendIssues,
}

struct Origin {
    sample: RaftAppendOrigin,
    registration: u64,
    payload: usize,
    capacity: usize,
    issues: RaftAppendIssues,
}

#[derive(Default)]
struct State {
    next: u64,
    registrations: BTreeMap<u64, (ConsensusIdentity, ConsensusNodeId)>,
    calls: BTreeMap<u64, Call>,
    origins: BTreeMap<u64, Origin>,
    issues: RaftAppendIssues,
}

impl State {
    fn active_generations(&self) -> usize {
        self.calls.len()
            + self
                .origins
                .keys()
                .filter(|generation| !self.calls.contains_key(generation))
                .count()
    }

    fn generation(&mut self) -> Option<u64> {
        match self.next.checked_add(1) {
            Some(next) => {
                self.next = next;
                Some(next)
            }
            None => {
                self.issues.metadata_saturated = true;
                None
            }
        }
    }
}

/// Numeric census with a drop barrier for actual borrowed typed request owners.
pub struct RaftAppendCensus {
    limits: RaftAppendLimits,
    state: Mutex<State>,
    #[cfg(test)]
    encoded_gate: Mutex<Option<Arc<tests::EncodedGate>>>,
}

impl Default for RaftAppendCensus {
    fn default() -> Self {
        Self::new(RaftAppendLimits::default())
    }
}

impl RaftAppendCensus {
    /// Create bounded observation metadata. Zero limits explicitly saturate.
    pub fn new(limits: RaftAppendLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
            #[cfg(test)]
            encoded_gate: Mutex::new(None),
        }
    }

    /// Attach to an exact identity/source. Duplicate live matches fail closed
    /// when an append starts; callers must retain the registration until drain.
    pub fn observe_source(
        self: &Arc<Self>,
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
    ) -> Option<RaftAppendRegistration> {
        let mut registry = lock(&SOURCES);
        registry.retain(|value| value.strong_count() != 0);
        let mut state = lock(&self.state);
        if state.registrations.len() >= self.limits.calls {
            state.issues.metadata_saturated = true;
            return None;
        }
        let id = state.generation()?;
        if state
            .registrations
            .values()
            .any(|(bound_identity, node)| *bound_identity == identity && *node == source)
        {
            state.issues.ambiguous_source = true;
        }
        state.registrations.insert(id, (identity, source));
        let shared = Arc::new(Source {
            census: self.clone(),
            identity,
            source,
            id,
        });
        registry.push(Arc::downgrade(&shared));
        Some(RaftAppendRegistration { shared })
    }

    /// Capture synchronously while original request borrows and their drop
    /// barrier remain held. Supported lock order is native/preparation, then
    /// transport, then this census, then any lower transport ledger. The callback
    /// must not register, drop, cancel or await owners protected by this census.
    pub fn with_current_capture<R>(&self, f: impl FnOnce(RaftAppendCapture<'_>) -> R) -> R {
        let state = lock(&self.state);
        f(RaftAppendCapture { state: &state })
    }
}

struct Source {
    census: Arc<RaftAppendCensus>,
    identity: ConsensusIdentity,
    source: ConsensusNodeId,
    id: u64,
}

static SOURCES: LazyLock<Mutex<Vec<Weak<Source>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Scoped source attachment. This owns no payload, request or backend.
pub struct RaftAppendRegistration {
    shared: Arc<Source>,
}

impl Drop for RaftAppendRegistration {
    fn drop(&mut self) {
        let mut registry = lock(&SOURCES);
        registry.retain(|value| {
            value
                .upgrade()
                .is_some_and(|source| !Arc::ptr_eq(&source, &self.shared))
        });
        let mut state = lock(&self.shared.census.state);
        if state
            .calls
            .values()
            .any(|call| call.registration == self.shared.id)
            || state
                .origins
                .values()
                .any(|origin| origin.registration == self.shared.id)
        {
            state.issues.ambiguous_source = true;
        }
        state.registrations.remove(&self.shared.id);
    }
}

/// Borrowed snapshot access valid only inside `with_current_capture`.
pub struct RaftAppendCapture<'a> {
    state: &'a State,
}

impl RaftAppendCapture<'_> {
    /// Copy numeric diagnostics while the original owners remain borrowed.
    pub fn sample(&self) -> RaftAppendSample {
        let mut issues = self.state.issues;
        let mut descriptors = Allocations::new();
        let mut payloads = Allocations::new();
        for call in self.state.calls.values() {
            issues.merge(call.issues);
            extend(&mut descriptors, &call.descriptors, &mut issues);
            extend(&mut payloads, &call.payloads, &mut issues);
        }
        for (&generation, origin) in &self.state.origins {
            if !self.state.calls.contains_key(&generation) {
                issues.merge(origin.issues);
            }
        }
        let descriptor_bytes = sum(&descriptors, &mut issues);
        let payload_bytes = sum(&payloads, &mut issues);
        extend(&mut descriptors, &payloads, &mut issues);
        let original_bytes = sum(&descriptors, &mut issues);
        RaftAppendSample {
            registrations: self.state.registrations.len(),
            calls: self
                .state
                .calls
                .values()
                .map(|call| call.sample.clone())
                .collect(),
            origins: self
                .state
                .origins
                .values()
                .map(|origin| origin.sample.clone())
                .collect(),
            descriptor_bytes,
            payload_bytes,
            original_bytes,
            issues,
        }
    }

    /// Join the exact currently borrowed native/preparation map for its authority
    /// and source. Equal node numbers in different authorities never match.
    /// Addresses stay private; aliases are matched by live allocation identity.
    pub fn join(&self, native: &AllocationView<'_>) -> RaftAppendUnion {
        let mut issues = self.state.issues;
        if self
            .state
            .registrations
            .values()
            .filter(|(identity, node)| *identity == native.identity && *node == native.source)
            .count()
            != 1
        {
            issues.ambiguous_source = true;
        }
        let mut original = Allocations::new();
        let mut calls = 0;
        for call in self.state.calls.values().filter(|call| {
            call.sample.identity == native.identity && call.sample.source == native.source
        }) {
            calls += 1;
            issues.merge(call.issues);
            extend(&mut original, &call.descriptors, &mut issues);
            extend(&mut original, &call.payloads, &mut issues);
        }
        for origin in self.state.origins.values().filter(|origin| {
            origin.sample.identity == native.identity
                && origin.sample.source == native.source
                && !self.state.calls.contains_key(&origin.sample.generation)
        }) {
            issues.merge(origin.issues);
        }
        let original_bytes = sum(&original, &mut issues);
        let native_bytes = sum(native.allocations, &mut issues);
        let shared: Allocations = original
            .iter()
            .filter(|(address, _)| native.allocations.contains_key(address))
            .map(|(&address, &bytes)| (address, bytes))
            .collect();
        let shared_bytes = sum(&shared, &mut issues);
        extend(&mut original, native.allocations, &mut issues);
        let union_bytes = sum(&original, &mut issues);
        RaftAppendUnion {
            identity: native.identity,
            source: native.source,
            calls,
            original_bytes,
            native_bytes,
            shared_bytes,
            union_bytes,
            issues,
        }
    }
}

fn sum(values: &Allocations, issues: &mut RaftAppendIssues) -> usize {
    values.values().fold(0usize, |total, bytes| {
        total.checked_add(*bytes).unwrap_or_else(|| {
            issues.arithmetic_overflow = true;
            usize::MAX
        })
    })
}

fn insert(values: &mut Allocations, address: usize, bytes: usize, issues: &mut RaftAppendIssues) {
    if bytes != 0 {
        if let Some(previous) = values.insert(address, bytes) {
            issues.inconsistent_extents |= previous != bytes;
        }
    }
}

fn extend(values: &mut Allocations, other: &Allocations, issues: &mut RaftAppendIssues) {
    for (&address, &bytes) in other {
        insert(values, address, bytes, issues);
    }
}

struct Inventory {
    allocations: Allocations,
    limit: usize,
    issues: RaftAppendIssues,
}

impl Inventory {
    fn add(&mut self, address: usize, bytes: usize) {
        if bytes != 0
            && !self.allocations.contains_key(&address)
            && self.allocations.len() >= self.limit
        {
            self.issues.metadata_saturated = true;
        } else {
            insert(&mut self.allocations, address, bytes, &mut self.issues);
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

    fn commit(&mut self, commit: &PreparedConfigCommit) {
        self.boxed(commit);
        self.vector(&commit.record.encrypted_blob);
        self.string(&commit.record.principal);
        self.vector(&commit.record.plaintext_digest);
        self.vector(&commit.audit);
        for audit in &commit.audit {
            self.string(&audit.yang_path);
            if let Some(value) = &audit.previous_value {
                self.string(value);
            }
            if let Some(value) = &audit.new_value {
                self.string(value);
            }
        }
    }

    fn intent(&mut self, intent: &ConfigMutationIntent) -> bool {
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
            ConfigMutationIntent::ManagementAudit(_) => return false,
        }
        true
    }
}

pub(crate) struct OriginalAppend {
    request: Option<AppendEntriesRequest<ConfigRaftTypeConfig>>,
    observation: Option<ObservedAppend>,
    #[cfg(test)]
    sources: Vec<Arc<Source>>,
}

struct ObservedAppend {
    shared: Arc<Source>,
    generation: u64,
}

impl OriginalAppend {
    pub(crate) fn start(
        identity: ConsensusIdentity,
        source: ConsensusNodeId,
        target: ConsensusNodeId,
        request: AppendEntriesRequest<ConfigRaftTypeConfig>,
    ) -> Self {
        let registry = lock(&SOURCES);
        let matches: Vec<_> = registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|value| value.identity == identity && value.source == source)
            .collect();
        let observation = if matches.len() == 1 {
            ObservedAppend::start(matches[0].clone(), target, &request)
        } else {
            for value in &matches {
                lock(&value.census.state).issues.ambiguous_source = true;
            }
            None
        };
        Self {
            request: Some(request),
            observation,
            #[cfg(test)]
            sources: matches,
        }
    }

    pub(crate) fn borrow(&self) -> &AppendEntriesRequest<ConfigRaftTypeConfig> {
        self.request
            .as_ref()
            .expect("original owner has not dropped")
    }

    pub(crate) fn wire(&self, payload: &Vec<u8>) -> Option<OriginalWire> {
        self.observation.as_ref().map(|owner| owner.wire(payload))
    }

    #[cfg(test)]
    pub(crate) async fn before_drop(&self) {
        // Component tests pause the actual encoded call before physical release.
        // No gate exists in the production or integration-test build.
        let mut seen = Vec::new();
        for source in &self.sources {
            if seen.iter().any(|prior| Arc::ptr_eq(prior, &source.census)) {
                continue;
            }
            seen.push(source.census.clone());
            let gate = lock(&source.census.encoded_gate).clone();
            if let Some(gate) = gate {
                gate.arrived.add_permits(1);
                gate.release.acquire().await.unwrap().forget();
            }
        }
    }
}

impl ObservedAppend {
    fn start(
        shared: Arc<Source>,
        target: ConsensusNodeId,
        request: &AppendEntriesRequest<ConfigRaftTypeConfig>,
    ) -> Option<Self> {
        let identity = shared.identity;
        let source = shared.source;
        let mut state = lock(&shared.census.state);
        let limits = shared.census.limits;
        if state.active_generations() >= limits.calls {
            state.issues.metadata_saturated = true;
            return None;
        }
        let generation = state.generation()?;
        let mut descriptor = Inventory {
            allocations: Allocations::new(),
            limit: 1,
            issues: RaftAppendIssues::default(),
        };
        descriptor.vector(&request.entries);
        let mut payload = Inventory {
            allocations: Allocations::new(),
            limit: limits.allocations_per_call,
            issues: descriptor.issues,
        };
        let mut attribution =
            Vec::with_capacity(request.entries.len().min(limits.entries_per_call));
        for entry in &request.entries {
            let mut individual = Inventory {
                allocations: Allocations::new(),
                limit: limits.allocations_per_call,
                issues: RaftAppendIssues::default(),
            };
            let (request_id, supported) = match &entry.payload {
                EntryPayload::Normal(command) => {
                    payload.issues.mismatched_identity_entries +=
                        usize::from(command.identity != identity);
                    (Some(command.request_id), individual.intent(&command.intent))
                }
                EntryPayload::Blank => (None, true),
                EntryPayload::Membership(_) => (None, false),
            };
            let payload_bytes = sum(&individual.allocations, &mut individual.issues);
            let entry_complete = supported && individual.issues.complete();
            payload.issues.merge(individual.issues);
            payload.issues.unsupported_entries += usize::from(!supported);
            for (address, bytes) in individual.allocations {
                payload.add(address, bytes);
            }
            if attribution.len() < limits.entries_per_call {
                attribution.push(RaftAppendEntry {
                    log_index: entry.log_id.index,
                    request: request_id,
                    payload_bytes,
                    supported: entry_complete,
                });
            } else {
                payload.issues.metadata_saturated = true;
            }
        }
        let descriptor_bytes = sum(&descriptor.allocations, &mut payload.issues);
        let payload_bytes = sum(&payload.allocations, &mut payload.issues);
        state.issues.metadata_saturated |= payload.issues.metadata_saturated;
        state.calls.insert(
            generation,
            Call {
                sample: RaftAppendCall {
                    identity,
                    source,
                    target,
                    generation,
                    entries: request.entries.len(),
                    descriptor_bytes,
                    payload_bytes,
                    attribution,
                },
                registration: shared.id,
                descriptors: descriptor.allocations,
                payloads: payload.allocations,
                issues: payload.issues,
            },
        );
        drop(state);
        Some(Self { shared, generation })
    }

    fn wire(&self, payload: &Vec<u8>) -> OriginalWire {
        let mut state = lock(&self.shared.census.state);
        let call = &state.calls[&self.generation];
        let origin = Origin {
            sample: RaftAppendOrigin {
                identity: call.sample.identity,
                source: call.sample.source,
                target: call.sample.target,
                generation: call.sample.generation,
                entries: call.sample.entries,
                attribution: call.sample.attribution.clone(),
            },
            registration: call.registration,
            payload: payload.as_ptr() as usize,
            capacity: payload.capacity(),
            issues: call.issues,
        };
        assert!(state.origins.insert(self.generation, origin).is_none());
        OriginalWire {
            shared: self.shared.clone(),
            generation: self.generation,
        }
    }
}

impl Drop for OriginalAppend {
    fn drop(&mut self) {
        if let Some(observation) = &self.observation {
            let mut state = lock(&observation.shared.census.state);
            // Physically destroy the only typed request owner before retiring
            // its metadata. A capture cannot race this allocation release.
            drop(self.request.take());
            state.calls.remove(&observation.generation);
        } else {
            drop(self.request.take());
        }
    }
}

pub(crate) struct OriginalWire {
    shared: Arc<Source>,
    generation: u64,
}

impl Drop for OriginalWire {
    fn drop(&mut self) {
        lock(&self.shared.census.state)
            .origins
            .remove(&self.generation);
    }
}

tokio::task_local! { static WIRE: OriginalWire; }

pub(crate) async fn scope_wire<F: Future>(context: Option<OriginalWire>, future: F) -> F::Output {
    match context {
        Some(context) => WIRE.scope(context, future).await,
        None => future.await,
    }
}

/// Typed original-call attribution verified against the genuine moved payload.
#[derive(Clone, Copy, Debug)]
pub struct RaftAppendWitness {
    /// Original generation, matching an encoded provenance context.
    pub generation: u64,
    /// Actual entries length, including multi-entry and empty heartbeat batches.
    pub entries: usize,
}

/// Verify encoded allocation provenance without decoding or retaining payloads.
pub fn raft_append_witness(
    request: &ConsensusWireRequest,
    target: ConsensusNodeId,
) -> Option<RaftAppendWitness> {
    WIRE.try_with(|wire| {
        let state = lock(&wire.shared.census.state);
        let original = state.origins.get(&wire.generation)?;
        (request.identity == wire.shared.identity
            && request.sender == wire.shared.source
            && request.family == ConsensusRpcFamily::AppendEntries
            && target == original.sample.target
            && request.payload.as_ptr() as usize == original.payload
            && request.payload.capacity() == original.capacity)
            .then_some(RaftAppendWitness {
                generation: wire.generation,
                entries: original.sample.entries,
            })
    })
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests;
