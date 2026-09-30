//! Qualification-only census of pending/negotiated RPCs and owned outer frames.
//!
//! This observes real allocation extents and a same-instant frame intersection.
//! Pool and cold-connection acquisition requests are separate from negotiated
//! calls. Accepted inbound TCP endpoints have a separate count-only census.
//! Detached outbound attempts and connected outbound TCP have separate counts.
//! DNS/material/connect internals, other queues, engine/prepared owners,
//! inbound decoding, TLS allocation bytes and allocator overhead remain
//! outside this incomplete census.
//! Snapshot RPC backing and outer framing remain separate categories. No buffer
//! contents or allocation addresses leave this module. Enabling the feature alone
//! does not arm an observer or a write gate.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use opc_consensus::{ConsensusNodeId, ConsensusRpcFamily};
use tokio::sync::watch;

pub(crate) mod tls_allocations;
pub use tls_allocations::{
    TlsAllocationObserver, TlsAllocationPhase, TlsAllocationSource, TlsEndpoint,
};

mod inbound_sockets;
pub(crate) use inbound_sockets::{
    current_inbound_listener, inbound_socket_phase, scope_inbound_socket, InboundSocket,
};
pub use inbound_sockets::{InboundSocketCensus, InboundSocketOwner, InboundSocketPhase};

mod outbound_sockets;
pub(crate) use outbound_sockets::{
    observe_outbound_attempt, outbound_attempt_phase, outbound_tls_material, OutboundSocket,
    OutboundSocketContext,
};
pub use outbound_sockets::{
    OutboundAttemptOwner, OutboundAttemptPhase, OutboundSocketCensus, OutboundSocketOwner,
    OutboundSocketPhase,
};

/// Simultaneous capacities in the observed negotiated calls only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferTotals {
    /// Number of borrowed negotiated request owners.
    pub calls: usize,
    /// Unique backing capacity of the observed RPC payloads.
    pub rpc_bytes: usize,
    /// Encoded frames which have reached the write boundary.
    pub ready_frames: usize,
    /// Unique boxed chunks and descriptor-vector backing allocations.
    pub frame_allocations: usize,
    /// Outer frame allocation extents, including descriptor-vector capacity.
    pub frame_bytes: usize,
}

/// One coherent intersection of distinct-target append and snapshot frames.
///
/// These capacities belong to just the two indicated calls, not a sum of peaks.
/// Their frame bytes are outer transport storage, not the snapshot/RPC category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferOverlap {
    /// Source shared by both observed calls.
    pub source: ConsensusNodeId,
    /// Recipient of a real snapshot-family call.
    pub snapshot_target: ConsensusNodeId,
    /// Different recipient of a large append-family call.
    pub append_target: ConsensusNodeId,
    /// Snapshot RPC backing, kept separate from the append and outer frame categories.
    pub snapshot_rpc_bytes: usize,
    /// Append RPC backing, kept separate from snapshot and outer frame storage.
    pub append_rpc_bytes: usize,
    /// Unique RPC payload capacities of this pair; not a contract budget.
    pub rpc_bytes: usize,
    /// Unique frame backing allocations of this pair.
    pub frame_allocations: usize,
    /// Actual outer frame extents of this pair.
    pub frame_bytes: usize,
}

/// A current census, independent field maxima, and one coherent overlap witness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferSnapshot {
    /// Currently registered live owners only.
    pub live: BufferTotals,
    /// Independent field maxima; these must never be summed as one instant.
    pub peak: BufferTotals,
    /// Same-instant witness since the most recent snapshot gate was armed.
    pub overlap: Option<BufferOverlap>,
}

/// One actually registered call at a single native checkpoint.
/// Call IDs distinguish registrations; typed generation zero remains untyped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCensusCall {
    /// Observer-local registration identity, independent of pointer reuse.
    pub call_id: u64,
    /// Actual recipient of this live call.
    pub target: ConsensusNodeId,
    /// Original typed provenance, or zero for an untyped observed call.
    pub generation: u64,
    /// Whether native provenance selected this exact append operation.
    pub selected_append: bool,
    /// This call's capacities; shared RPC allocations can occur in other rows.
    pub buffers: BufferTotals,
}

/// Current owners for one source and RPC family, deduplicated within this group.
/// Groups can share RPC backing; never add their byte totals as a global union.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportCensusGroup {
    /// Actual source of every included call.
    pub source: ConsensusNodeId,
    /// Observed family: large AppendEntries or InstallSnapshot only.
    pub family: ConsensusRpcFamily,
    /// Exact allocation union within this source/family group.
    pub totals: BufferTotals,
    /// All current call registrations, including RPC-only and untyped owners.
    pub owners: Vec<TransportCensusCall>,
}

/// Coherent census of all currently registered negotiated RPC/frame owners.
/// Excludes small appends, other RPC families, queues, inbound buffers and TLS.
/// Native and snapshot-input storage remain separate from this census.
/// Owns numeric metadata only and never extends the observed payload lifetime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CurrentTransportCensus {
    /// Global allocation union, deduplicated across every source and family.
    pub total: BufferTotals,
    /// Calls outside the selected pair and allocated bytes not already in it.
    /// Pair plus additional equals total even when additional calls alias it.
    pub additional: BufferTotals,
    /// Independent source/family unions and exact target/generation evidence.
    pub groups: Vec<TransportCensusGroup>,
}

/// Exact request interval covered by the pending RPC observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRpcPhase {
    /// The real pool-acquisition future has begun and has not returned a lane.
    /// This includes its first poll, even when acquisition can finish promptly.
    PoolAcquire,
    /// The real cold-connection acquisition future has begun and has not returned.
    /// Includes coordinator/admission waits and joining a shared setup attempt;
    /// this observes the caller's RPC payload, not the physical setup's buffers.
    ColdConnectionAcquire,
}

/// One borrowed RPC owner during an actual pool or cold-connection acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRpcOwner {
    /// Registration identity, shared with the negotiated-call ID sequence.
    pub call_id: u64,
    /// The exact observed acquisition interval; physical setup buffers are separate.
    pub phase: PendingRpcPhase,
    /// Declared request sender, not yet checked against the peer binding.
    pub source: ConsensusNodeId,
    /// Recipient from the actual peer binding.
    pub target: ConsensusNodeId,
    /// Declared request family, including small control and forwarded calls.
    pub family: ConsensusRpcFamily,
    /// Original typed provenance when present; zero otherwise.
    pub generation: u64,
    /// Whether existing typed provenance selected this append operation.
    pub selected_append: bool,
    /// Actual capacity of this borrowed Vec; other rows may alias it.
    pub rpc_bytes: usize,
}

/// One locked census of pending RPCs and their union with negotiated RPCs.
/// Contains numeric metadata only. No frame, snapshot-input or native bytes are
/// included; negotiated coverage remains the existing large append/snapshot slice.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingRpcCensus {
    /// All registered acquisition waits at this instant, including aliases.
    pub owners: Vec<PendingRpcOwner>,
    /// Distinct nonempty backing allocations among pending owners.
    pub rpc_allocations: usize,
    /// Allocation-identity union of actual pending Vec capacities.
    pub rpc_bytes: usize,
    /// Pending backing not already charged by the negotiated RPC census.
    pub additional_rpc_bytes: usize,
    /// One allocation union across pending and currently observed negotiated RPCs.
    pub observed_rpc_bytes: usize,
}

/// Current typed pair and all observed calls inside one native checkpoint.
/// Snapshot input, snapshot RPC and outer transport are separate categories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTransportOverlap {
    /// Actual pair of live encoded RPC/frame owners at this instant.
    pub pair: BufferOverlap,
    /// Original snapshot chunk Vec capacity, independent of its encoded RPC.
    pub snapshot_data_bytes: usize,
    /// Exact typed-call generation for the selected append's moved allocation.
    pub append_generation: u64,
    /// Different typed-call generation for the actual snapshot's moved allocation.
    pub snapshot_generation: u64,
    /// Current registration identity of the selected append.
    pub append_call_id: u64,
    /// Current registration identity of the selected snapshot.
    pub snapshot_call_id: u64,
    /// All registered call owners from this exact locked checkpoint.
    pub current: CurrentTransportCensus,
    /// Actual acquisition waits, captured under the same lock as `current`.
    pub pending: PendingRpcCensus,
    /// Accepted inbound TCP owners captured under the same observer lock.
    /// These are endpoint counts, with the documented destructor tail, not bytes.
    pub inbound: InboundSocketCensus,
    /// Detached outbound attempts and TCP owners from this exact checkpoint.
    /// Attempts overlap endpoints; inbound/outbound endpoints are not summed
    /// as unique network connections, and no TLS storage is inferred.
    pub outbound: OutboundSocketCensus,
}

#[derive(Clone, Copy, Default)]
struct TypedTransportTag {
    selected_append: bool,
    snapshot_data_bytes: usize,
    generation: u64,
}

tokio::task_local! { static TYPED_TRANSPORT: TypedTransportTag; }

/// Carry already-verified typed owner metadata through one genuine peer call.
/// The caller must derive this from the live typed request, not encoded length.
/// Owns no request, engine entry, snapshot chunk or storage backend.
pub async fn scope_typed_transport<F: Future>(
    selected_append: bool,
    snapshot_data_bytes: usize,
    generation: u64,
    future: F,
) -> F::Output {
    TYPED_TRANSPORT
        .scope(
            TypedTransportTag {
                selected_append,
                snapshot_data_bytes,
                generation,
            },
            future,
        )
        .await
}

#[derive(Clone, Copy)]
struct Allocation {
    address: usize,
    bytes: usize,
}

#[derive(Default)]
struct FrameRecord {
    descriptor: Option<Allocation>,
    chunks: BTreeMap<usize, usize>,
    ready: bool,
}

impl FrameRecord {
    fn allocations(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.chunks
            .iter()
            .map(|(&address, &bytes)| (address, bytes))
            .chain(
                self.descriptor
                    .iter()
                    .map(|allocation| (allocation.address, allocation.bytes)),
            )
    }
}

struct CallRecord {
    source: ConsensusNodeId,
    target: ConsensusNodeId,
    family: ConsensusRpcFamily,
    payload: Allocation,
    typed: TypedTransportTag,
    frame: Option<FrameRecord>,
}

struct PendingCallRecord {
    phase: PendingRpcPhase,
    source: ConsensusNodeId,
    target: ConsensusNodeId,
    family: ConsensusRpcFamily,
    payload: Allocation,
    typed: TypedTransportTag,
}

#[derive(Default)]
struct State {
    next_id: u64,
    calls: BTreeMap<u64, CallRecord>,
    pending_calls: BTreeMap<u64, PendingCallRecord>,
    inbound_sockets: BTreeMap<u64, InboundSocketOwner>,
    inbound_socket_registration_exhausted: bool,
    outbound_attempts: BTreeMap<u64, OutboundAttemptOwner>,
    outbound_sockets: BTreeMap<u64, OutboundSocketOwner>,
    outbound_registration_exhausted: bool,
    tls_allocations: Option<Arc<dyn TlsAllocationObserver>>,
    held_snapshot_target: Option<ConsensusNodeId>,
    native_source: Option<ConsensusNodeId>,
    held_append_target: Option<ConsensusNodeId>,
    append_quorum_released: bool,
    snapshot: BufferSnapshot,
}

fn totals<'a>(calls: impl Iterator<Item = &'a CallRecord>) -> BufferTotals {
    let mut result = BufferTotals::default();
    let mut payloads = BTreeMap::new();
    for call in calls {
        result.calls += 1;
        if call.payload.bytes != 0 {
            payloads.insert(call.payload.address, call.payload.bytes);
        }
        if let Some(frame) = &call.frame {
            result.ready_frames += usize::from(frame.ready);
            // Each frame owns distinct Box/Vec backing; frames cannot alias
            // each other. Deduplication inside the chunk map uses real identity.
            result.frame_allocations +=
                frame.chunks.len() + usize::from(frame.descriptor.is_some());
            result.frame_bytes += frame.allocations().map(|(_, bytes)| bytes).sum::<usize>();
        }
    }
    result.rpc_bytes = payloads.values().sum();
    result
}

#[derive(Default)]
struct CensusAllocations {
    calls: usize,
    ready_frames: usize,
    payloads: BTreeMap<usize, usize>,
    frames: BTreeMap<usize, usize>,
}

impl CensusAllocations {
    fn include(&mut self, call: &CallRecord) {
        self.calls += 1;
        if call.payload.bytes != 0 {
            self.payloads
                .insert(call.payload.address, call.payload.bytes);
        }
        if let Some(frame) = &call.frame {
            self.ready_frames += usize::from(frame.ready);
            for (address, bytes) in frame.allocations() {
                if bytes != 0 {
                    self.frames.insert(address, bytes);
                }
            }
        }
    }

    fn totals(&self) -> BufferTotals {
        BufferTotals {
            calls: self.calls,
            rpc_bytes: self.payloads.values().sum(),
            ready_frames: self.ready_frames,
            frame_allocations: self.frames.len(),
            frame_bytes: self.frames.values().sum(),
        }
    }
}

// Run only for the synchronous native capture, never on each frame allocation
// or gate refresh. The caller keeps the registration mutex held throughout.
fn current_census<'a>(
    calls: impl Iterator<Item = (u64, &'a CallRecord)>,
    pair_ids: [u64; 2],
) -> CurrentTransportCensus {
    let mut all = CensusAllocations::default();
    let mut pair = CensusAllocations::default();
    let mut groups: BTreeMap<_, (TransportCensusGroup, CensusAllocations)> = BTreeMap::new();
    for (id, call) in calls {
        all.include(call);
        if pair_ids.contains(&id) {
            pair.include(call);
        }
        // observe_call admits only these two families. Use the family key
        // without adding an ordering requirement to the shared RPC enum.
        let key = (
            call.source,
            call.family == ConsensusRpcFamily::InstallSnapshot,
        );
        let (group, allocations) = groups.entry(key).or_insert_with(|| {
            (
                TransportCensusGroup {
                    source: call.source,
                    family: call.family,
                    totals: BufferTotals::default(),
                    owners: Vec::new(),
                },
                CensusAllocations::default(),
            )
        });
        allocations.include(call);
        group.owners.push(TransportCensusCall {
            call_id: id,
            target: call.target,
            generation: call.typed.generation,
            selected_append: call.typed.selected_append,
            buffers: totals(std::iter::once(call)),
        });
    }
    let total = all.totals();
    let pair = pair.totals();
    // The pair is a subset of this same current allocation union. Subtraction
    // charges only genuinely additional backing, including aliases across groups.
    let additional = BufferTotals {
        calls: total.calls - pair.calls,
        rpc_bytes: total.rpc_bytes - pair.rpc_bytes,
        ready_frames: total.ready_frames - pair.ready_frames,
        frame_allocations: total.frame_allocations - pair.frame_allocations,
        frame_bytes: total.frame_bytes - pair.frame_bytes,
    };
    CurrentTransportCensus {
        total,
        additional,
        groups: groups
            .into_values()
            .map(|(mut group, allocations)| {
                group.totals = allocations.totals();
                group
            })
            .collect(),
    }
}

impl State {
    fn pending_census(&self) -> PendingRpcCensus {
        let mut combined: BTreeMap<_, _> = self
            .calls
            .values()
            .filter(|call| call.payload.bytes != 0)
            .map(|call| (call.payload.address, call.payload.bytes))
            .collect();
        let negotiated_bytes: usize = combined.values().sum();
        let mut pending = BTreeMap::new();
        let mut owners = Vec::with_capacity(self.pending_calls.len());
        for (&id, call) in &self.pending_calls {
            if call.payload.bytes != 0 {
                pending.insert(call.payload.address, call.payload.bytes);
                combined.insert(call.payload.address, call.payload.bytes);
            }
            owners.push(PendingRpcOwner {
                call_id: id,
                phase: call.phase,
                source: call.source,
                target: call.target,
                family: call.family,
                generation: call.typed.generation,
                selected_append: call.typed.selected_append,
                rpc_bytes: call.payload.bytes,
            });
        }
        let observed_rpc_bytes = combined.values().sum::<usize>();
        PendingRpcCensus {
            owners,
            rpc_allocations: pending.len(),
            rpc_bytes: pending.values().sum(),
            additional_rpc_bytes: observed_rpc_bytes - negotiated_bytes,
            observed_rpc_bytes,
        }
    }

    fn snapshot_provenance_matches(&self, call: &CallRecord) -> bool {
        self.native_source.is_none_or(|source| {
            call.source == source
                && call.typed.generation != 0
                && call.typed.snapshot_data_bytes > 0
        })
    }

    fn native_pair(&self) -> Option<[(u64, &CallRecord); 2]> {
        let source = self.native_source?;
        let append_target = self.held_append_target?;
        let snapshot_target = self.held_snapshot_target?;
        let (snapshot_id, snapshot) = self.calls.iter().find(|(_, call)| {
            call.source == source
                && call.target == snapshot_target
                && call.family == ConsensusRpcFamily::InstallSnapshot
                && call.typed.generation != 0
                && call.typed.snapshot_data_bytes > 0
                && call.frame.as_ref().is_some_and(|frame| frame.ready)
        })?;
        let (append_id, append) = self.calls.iter().find(|(_, call)| {
            call.source == source
                && call.target == append_target
                && call.family == ConsensusRpcFamily::AppendEntries
                && call.typed.selected_append
                && call.typed.generation != 0
                && call.frame.as_ref().is_some_and(|frame| frame.ready)
        })?;
        Some([(*append_id, append), (*snapshot_id, snapshot)])
    }

    fn native_overlap(&self) -> Option<NativeTransportOverlap> {
        let [(append_id, append), (snapshot_id, snapshot)] = self.native_pair()?;
        let pair = totals([snapshot, append].into_iter());
        let pair_ids = [append_id, snapshot_id];
        let current = current_census(self.calls.iter().map(|(&id, call)| (id, call)), pair_ids);
        Some(NativeTransportOverlap {
            pair: BufferOverlap {
                source: append.source,
                snapshot_target: snapshot.target,
                append_target: append.target,
                snapshot_rpc_bytes: snapshot.payload.bytes,
                append_rpc_bytes: append.payload.bytes,
                rpc_bytes: pair.rpc_bytes,
                frame_allocations: pair.frame_allocations,
                frame_bytes: pair.frame_bytes,
            },
            snapshot_data_bytes: snapshot.typed.snapshot_data_bytes,
            append_generation: append.typed.generation,
            snapshot_generation: snapshot.typed.generation,
            append_call_id: append_id,
            snapshot_call_id: snapshot_id,
            current,
            pending: self.pending_census(),
            inbound: InboundSocketCensus {
                owners: self.inbound_sockets.values().copied().collect(),
                registration_exhausted: self.inbound_socket_registration_exhausted,
            },
            outbound: OutboundSocketCensus {
                attempts: self.outbound_attempts.values().copied().collect(),
                sockets: self.outbound_sockets.values().copied().collect(),
                registration_exhausted: self.outbound_registration_exhausted,
            },
        })
    }

    fn refresh(&mut self) {
        let live = totals(self.calls.values());
        self.snapshot.live = live;
        let peak = &mut self.snapshot.peak;
        peak.calls = peak.calls.max(live.calls);
        peak.rpc_bytes = peak.rpc_bytes.max(live.rpc_bytes);
        peak.ready_frames = peak.ready_frames.max(live.ready_frames);
        peak.frame_allocations = peak.frame_allocations.max(live.frame_allocations);
        peak.frame_bytes = peak.frame_bytes.max(live.frame_bytes);
        // Admit quorum progress as soon as the selected minority frame is
        // really ready beside the snapshot. Only those two frames remain held.
        if !self.append_quorum_released && self.native_pair().is_some() {
            self.append_quorum_released = true;
        }
        if self.snapshot.overlap.is_some() {
            return;
        }
        let held_snapshot_target = self.held_snapshot_target;
        for snapshot in self.calls.values().filter(|call| {
            call.family == ConsensusRpcFamily::InstallSnapshot
                && Some(call.target) == held_snapshot_target
                && call.frame.as_ref().is_some_and(|frame| frame.ready)
        }) {
            if let Some(append) = self.calls.values().find(|call| {
                call.family == ConsensusRpcFamily::AppendEntries
                    && call.source == snapshot.source
                    && call.target != snapshot.target
                    && call.frame.as_ref().is_some_and(|frame| frame.ready)
            }) {
                let pair = totals([snapshot, append].into_iter());
                self.snapshot.overlap = Some(BufferOverlap {
                    source: snapshot.source,
                    snapshot_target: snapshot.target,
                    append_target: append.target,
                    snapshot_rpc_bytes: snapshot.payload.bytes,
                    append_rpc_bytes: append.payload.bytes,
                    rpc_bytes: pair.rpc_bytes,
                    frame_allocations: pair.frame_allocations,
                    frame_bytes: pair.frame_bytes,
                });
                break;
            }
        }
    }
}

/// Opt-in observation/control for a finite transport qualification scenario.
///
/// Registrations contain only addresses, extents, IDs and notifications. They do
/// not clone payloads or retain a store, prepared operation, frame or TLS stream.
/// Pointer identities stay private; buffer registrations end before owners free.
/// Inbound TCP registrations instead end after their socket field is destroyed.
/// Metadata follows observed calls, frames, inbound sockets and numeric rows.
/// The census copies no buffers and contains no public allocation addresses.
pub struct ConsensusBufferObservation {
    state: Mutex<State>,
    changed: watch::Sender<()>,
}

impl Default for ConsensusBufferObservation {
    fn default() -> Self {
        let (changed, _) = watch::channel(());
        Self {
            state: Mutex::new(State::default()),
            changed,
        }
    }
}

impl fmt::Debug for ConsensusBufferObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsensusBufferObservation")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl ConsensusBufferObservation {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn update(&self, change: impl FnOnce(&mut State)) {
        {
            let mut state = self.state();
            change(&mut state);
            state.refresh();
        }
        self.changed.send_replace(());
    }

    /// Hold this recipient's encoded snapshot frames before their first write.
    /// With a native source armed, only its typed snapshots are held. An older
    /// untyped call can complete and cannot satisfy native snapshot readiness.
    /// The original absolute call/write deadlines still apply while held.
    pub fn hold_snapshot_writes(&self, target: ConsensusNodeId) {
        self.update(|state| {
            state.held_snapshot_target = Some(target);
            state.snapshot.overlap = None;
        });
    }

    /// Release all frames held by this observer without changing any deadline.
    pub fn release_snapshot_writes(&self) {
        self.update(|state| {
            state.held_snapshot_target = None;
            state.held_append_target = None;
            state.native_source = None;
        });
    }

    /// Hold one selected minority append beside the existing snapshot gate.
    /// Other selected append frames wait only until that pair is ready, then
    /// proceed to the original quorum with the original absolute deadlines.
    pub fn hold_native_append_writes(&self, source: ConsensusNodeId, target: ConsensusNodeId) {
        self.update(|state| {
            state.native_source = Some(source);
            state.held_append_target = Some(target);
            state.append_quorum_released = false;
        });
    }

    /// Join a synchronous native checkpoint to currently live transport owners.
    /// Copies this instant under the same lock that unregisters real RPC/frame
    /// owners, then releases the minority and snapshot. Never uses saved peaks.
    pub fn capture_native_overlap_and_release(
        &self,
        source: ConsensusNodeId,
    ) -> Option<NativeTransportOverlap> {
        let captured = {
            let mut state = self.state();
            if state.native_source != Some(source) {
                return None;
            }
            let captured = state.native_overlap();
            state.held_snapshot_target = None;
            state.held_append_target = None;
            state.native_source = None;
            state.refresh();
            captured
        };
        self.changed.send_replace(());
        captured
    }

    /// Wait for a real encoded snapshot frame eligible for the current gate.
    /// Native arming requires the same typed provenance as the hold predicate.
    /// The caller must keep its existing finite qualification deadline.
    pub async fn wait_for_snapshot_write(&self, target: ConsensusNodeId) {
        let mut changed = self.changed.subscribe();
        loop {
            let ready = {
                let state = self.state();
                state.calls.values().any(|call| {
                    call.family == ConsensusRpcFamily::InstallSnapshot
                        && call.target == target
                        && state.snapshot_provenance_matches(call)
                        && call.frame.as_ref().is_some_and(|frame| frame.ready)
                })
            };
            if ready {
                return;
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }

    /// Copy numeric observations without copying or extending any buffer owner.
    pub fn snapshot(&self) -> BufferSnapshot {
        self.state().snapshot
    }

    /// Observe pending and negotiated RPC backing under their shared lock.
    /// This is a current sample, not a peak or an aggregate transport bound.
    pub fn pending_snapshot(&self) -> PendingRpcCensus {
        self.state().pending_census()
    }

    pub(crate) fn observe_pending_call<'a>(
        self: &Arc<Self>,
        phase: PendingRpcPhase,
        source: ConsensusNodeId,
        target: ConsensusNodeId,
        family: ConsensusRpcFamily,
        payload: &'a Vec<u8>,
    ) -> Option<PendingCallOwner<'a>> {
        let id = {
            let mut state = self.state();
            let id = state.next_id.checked_add(1)?;
            state.next_id = id;
            state.pending_calls.insert(
                id,
                PendingCallRecord {
                    phase,
                    source,
                    target,
                    family,
                    payload: Allocation {
                        address: payload.as_ptr() as usize,
                        bytes: payload.capacity(),
                    },
                    typed: TYPED_TRANSPORT.try_with(|tag| *tag).unwrap_or_default(),
                },
            );
            id
        };
        // Pending owners do not participate in frame gates or peak refresh.
        Some(PendingCallOwner {
            context: CallContext {
                observation: self.clone(),
                id,
            },
            _payload: payload,
        })
    }

    pub(crate) fn observe_call<'a>(
        self: &Arc<Self>,
        source: ConsensusNodeId,
        target: ConsensusNodeId,
        family: ConsensusRpcFamily,
        payload: &'a Vec<u8>,
    ) -> Option<CallOwner<'a>> {
        // Heartbeats/read probes stay outside the selected large mutation slice.
        if family != ConsensusRpcFamily::InstallSnapshot
            && !(family == ConsensusRpcFamily::AppendEntries && payload.len() > 1_048_576)
        {
            return None;
        }
        let id = {
            let mut state = self.state();
            let id = state.next_id.checked_add(1)?;
            state.next_id = id;
            state.calls.insert(
                id,
                CallRecord {
                    source,
                    target,
                    family,
                    payload: Allocation {
                        address: payload.as_ptr() as usize,
                        bytes: payload.capacity(),
                    },
                    typed: TYPED_TRANSPORT.try_with(|tag| *tag).unwrap_or_default(),
                    frame: None,
                },
            );
            state.refresh();
            id
        };
        self.changed.send_replace(());
        Some(CallOwner {
            context: CallContext {
                observation: self.clone(),
                id,
            },
            _payload: payload,
        })
    }
}

#[derive(Clone)]
struct CallContext {
    observation: Arc<ConsensusBufferObservation>,
    id: u64,
}

/// The request stays borrowed until the acquisition guard deregisters.
pub(crate) struct PendingCallOwner<'a> {
    context: CallContext,
    _payload: &'a Vec<u8>,
}

impl Drop for PendingCallOwner<'_> {
    fn drop(&mut self) {
        self.context
            .observation
            .state()
            .pending_calls
            .remove(&self.context.id);
    }
}

/// The borrow prevents freeing/moving the observed request before deregistration.
pub(crate) struct CallOwner<'a> {
    context: CallContext,
    _payload: &'a Vec<u8>,
}

impl Drop for CallOwner<'_> {
    fn drop(&mut self) {
        self.context.observation.update(|state| {
            state.calls.remove(&self.context.id);
        });
    }
}

tokio::task_local! {
    static CALL_CONTEXT: CallContext;
}

pub(crate) async fn scope<F: Future>(owner: Option<&CallOwner<'_>>, future: F) -> F::Output {
    match owner {
        Some(owner) => CALL_CONTEXT.scope(owner.context.clone(), future).await,
        None => future.await,
    }
}

/// Numeric guard which must precede the frame's owned buffers in field order.
pub(crate) struct FrameObservation {
    context: CallContext,
}

impl FrameObservation {
    pub(crate) fn current() -> Option<Self> {
        CALL_CONTEXT
            .try_with(|context| {
                let mut state = context.observation.state();
                let call = state.calls.get_mut(&context.id)?;
                if call.frame.is_some() {
                    return None;
                }
                call.frame = Some(FrameRecord::default());
                Some(Self {
                    context: context.clone(),
                })
            })
            .ok()
            .flatten()
    }

    /// Remove only the descriptor identity before Vec growth can reallocate it.
    pub(crate) fn before_chunk_allocation(&self) {
        self.context.observation.update(|state| {
            if let Some(frame) = state
                .calls
                .get_mut(&self.context.id)
                .and_then(|call| call.frame.as_mut())
            {
                frame.descriptor = None;
            }
        });
    }

    /// Register the actual new Box and the resulting Vec backing, not a limit.
    pub(crate) fn chunk_allocated(&self, descriptor: (usize, usize), chunk: (usize, usize)) {
        self.context.observation.update(|state| {
            if let Some(frame) = state
                .calls
                .get_mut(&self.context.id)
                .and_then(|call| call.frame.as_mut())
            {
                frame.descriptor = Some(Allocation {
                    address: descriptor.0,
                    bytes: descriptor.1,
                });
                frame.chunks.insert(chunk.0, chunk.1);
            }
        });
    }

    pub(crate) async fn ready_and_wait(&self) {
        let mut changed = self.context.observation.changed.subscribe();
        self.context.observation.update(|state| {
            if let Some(frame) = state
                .calls
                .get_mut(&self.context.id)
                .and_then(|call| call.frame.as_mut())
            {
                frame.ready = true;
            }
        });
        loop {
            let held = {
                let state = self.context.observation.state();
                state.calls.get(&self.context.id).is_some_and(|call| {
                    (call.family == ConsensusRpcFamily::InstallSnapshot
                        && Some(call.target) == state.held_snapshot_target
                        && state.snapshot_provenance_matches(call))
                        || (call.typed.selected_append
                            && Some(call.source) == state.native_source
                            && state.held_append_target.is_some()
                            && (!state.append_quorum_released
                                || Some(call.target) == state.held_append_target))
                })
            };
            if !held || changed.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for FrameObservation {
    fn drop(&mut self) {
        self.context.observation.update(|state| {
            if let Some(call) = state.calls.get_mut(&self.context.id) {
                call.frame = None;
            }
        });
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod native_arming_tests {
    use super::*;
    use crate::error::ProtocolError;
    use crate::protocol::write_frame_bounded_until;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWrite};

    // This focused regression uses the real frame writer and actual borrowed
    // Vec/Box/descriptor owners. Tags isolate the transport scheduling rule;
    // actual native-derived provenance is checked by the nine-member fixture.
    async fn frame<W: AsyncWrite + Unpin>(
        observation: &Arc<ConsensusBufferObservation>,
        endpoints: (ConsensusNodeId, ConsensusNodeId),
        family: ConsensusRpcFamily,
        tag: TypedTransportTag,
        payload: &Vec<u8>,
        output: &mut W,
    ) -> Result<(), ProtocolError> {
        scope_typed_transport(
            tag.selected_append,
            tag.snapshot_data_bytes,
            tag.generation,
            async {
                let owner = observation
                    .observe_call(endpoints.0, endpoints.1, family, payload)
                    .unwrap();
                scope(
                    Some(&owner),
                    write_frame_bounded_until(
                        output,
                        payload,
                        4 * 1_048_576,
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    ),
                )
                .await
            },
        )
        .await
    }

    fn assert_wire(output: &[u8], payload: &[u8]) {
        let expected = serde_json::to_vec(payload).unwrap();
        assert_eq!(&output[..4], &(expected.len() as u32).to_be_bytes());
        assert_eq!(&output[4..], expected);
    }

    #[tokio::test]
    async fn pre_registration_snapshot_does_not_hold_native_quorum() {
        let observation = Arc::new(ConsensusBufferObservation::default());
        let source = ConsensusNodeId::new(1).unwrap();
        let snapshot_target = ConsensusNodeId::new(2).unwrap();
        let minority_target = ConsensusNodeId::new(3).unwrap();
        let quorum_target = ConsensusNodeId::new(4).unwrap();
        let snapshot_payload = vec![1_u8; 128];
        let mut old_wire = Vec::new();
        let mut context = Context::from_waker(Waker::noop());
        let (old_wrote_without_gate_release, old_satisfied_readiness) = {
            // The old call carries its pre-registration (zero-generation) tag
            // across arming. A real one-byte duplex keeps its encoded frame
            // alive after the hold decision, so readiness is checked while
            // that untyped frame still exists, not after it has disappeared.
            let (mut writer, mut reader) = tokio::io::duplex(1);
            let old_observation = observation.clone();
            let old_payload = &snapshot_payload;
            let old = async move {
                let result = frame(
                    &old_observation,
                    (source, snapshot_target),
                    ConsensusRpcFamily::InstallSnapshot,
                    TypedTransportTag::default(),
                    old_payload,
                    &mut writer,
                )
                .await;
                drop(writer);
                result
            };
            tokio::pin!(old);
            observation.hold_snapshot_writes(snapshot_target);
            observation.hold_native_append_writes(source, minority_target);
            assert!(old.as_mut().poll(&mut context).is_pending());
            let wrote_before_release = {
                let mut byte = [0_u8];
                let read = {
                    let first = reader.read_exact(&mut byte);
                    tokio::pin!(first);
                    match first.as_mut().poll(&mut context) {
                        Poll::Ready(result) => {
                            result.unwrap();
                            true
                        }
                        Poll::Pending => false,
                    }
                };
                if read {
                    old_wire.push(byte[0]);
                }
                read
            };
            let ready = observation.wait_for_snapshot_write(snapshot_target);
            tokio::pin!(ready);
            let accepted = ready.as_mut().poll(&mut context).is_ready();
            // Cleanup also runs on the causal-removal source. Its late failure
            // needs neither expiration nor an abandoned writer/task.
            observation.release_snapshot_writes();
            let (written, drained) = tokio::join!(old, reader.read_to_end(&mut old_wire));
            written.unwrap();
            drained.unwrap();
            (wrote_before_release, accepted)
        };
        assert_wire(&old_wire, &snapshot_payload);
        assert_eq!(observation.snapshot().live, BufferTotals::default());

        observation.hold_snapshot_writes(snapshot_target);
        observation.hold_native_append_writes(source, minority_target);
        let minority_payload = vec![0_u8; 1_048_577];
        let quorum_payload = vec![0_u8; 1_048_577];
        let mut snapshot_wire = Vec::new();
        let mut minority_wire = Vec::new();
        let mut quorum_wire = Vec::new();
        let (typed_ready, quorum_progress, pair) = {
            let snapshot = frame(
                &observation,
                (source, snapshot_target),
                ConsensusRpcFamily::InstallSnapshot,
                TypedTransportTag {
                    selected_append: false,
                    snapshot_data_bytes: snapshot_payload.capacity(),
                    generation: 11,
                },
                &snapshot_payload,
                &mut snapshot_wire,
            );
            let quorum = frame(
                &observation,
                (source, quorum_target),
                ConsensusRpcFamily::AppendEntries,
                TypedTransportTag {
                    selected_append: true,
                    snapshot_data_bytes: 0,
                    generation: 12,
                },
                &quorum_payload,
                &mut quorum_wire,
            );
            let minority = frame(
                &observation,
                (source, minority_target),
                ConsensusRpcFamily::AppendEntries,
                TypedTransportTag {
                    selected_append: true,
                    snapshot_data_bytes: 0,
                    generation: 13,
                },
                &minority_payload,
                &mut minority_wire,
            );
            tokio::pin!(snapshot, quorum, minority);
            assert!(snapshot.as_mut().poll(&mut context).is_pending());
            let ready = observation.wait_for_snapshot_write(snapshot_target);
            tokio::pin!(ready);
            let typed_ready = ready.as_mut().poll(&mut context).is_ready();
            assert!(quorum.as_mut().poll(&mut context).is_pending());
            assert!(minority.as_mut().poll(&mut context).is_pending());
            let quorum_progress = match quorum.as_mut().poll(&mut context) {
                Poll::Ready(result) => {
                    result.unwrap();
                    true
                }
                Poll::Pending => false,
            };
            let pair = observation.capture_native_overlap_and_release(source);
            if !quorum_progress {
                quorum.await.unwrap();
            }
            snapshot.await.unwrap();
            minority.await.unwrap();
            (typed_ready, quorum_progress, pair)
        };
        assert_wire(&snapshot_wire, &snapshot_payload);
        assert_wire(&minority_wire, &minority_payload);
        assert_wire(&quorum_wire, &quorum_payload);
        assert_eq!(observation.snapshot().live, BufferTotals::default());
        println!(
            "CONFIG_CAPACITY_NATIVE_ARMING_LIFECYCLE original_wire=true drained=true no_timeout=true no_retry=true"
        );
        assert!(
            old_wrote_without_gate_release,
            "CONFIG_CAPACITY_UNTYPED_SNAPSHOT_GATE_RED: an old untyped frame must reach actual IO without waiting for native quorum"
        );
        assert!(
            !old_satisfied_readiness,
            "CONFIG_CAPACITY_UNTYPED_SNAPSHOT_READY_RED: an old untyped frame cannot satisfy the typed snapshot wait"
        );
        assert!(
            typed_ready && quorum_progress,
            "CONFIG_CAPACITY_NATIVE_QUORUM_GATE_RED: the current typed pair releases only quorum traffic"
        );
        let pair = pair.expect("current typed append and snapshot are still owned together");
        assert_eq!(pair.pair.append_target, minority_target);
        assert_eq!(pair.pair.snapshot_target, snapshot_target);
        assert_eq!(pair.snapshot_generation, 11);
        assert_eq!(pair.append_generation, 13);
        assert_eq!(pair.snapshot_data_bytes, snapshot_payload.capacity());
        println!("CONFIG_CAPACITY_NATIVE_ARMING_PASS full_memory_bound=false");
    }
}
