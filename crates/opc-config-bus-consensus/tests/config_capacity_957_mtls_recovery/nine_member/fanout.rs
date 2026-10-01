//! One operation's actual original owners at the eight-follower boundary.
//!
//! The barrier pauses genuine already-encoded RPCs inside their unchanged
//! native deadlines. It releases those same calls before any allocation
//! assertion; successful IO, readback, recovery and shutdown are prerequisites.

#[path = "fanout/native_tail.rs"]
mod native_tail;

#[path = "fanout/public_history.rs"]
mod public_history;

#[path = "fanout/working.rs"]
mod working;

use super::super::joint_metadata as joint;
use super::*;
use opc_crypto::capacity_observation::{
    self as encryption, AllocationIdentity, BufferKind, BufferObservation, BufferSnapshot,
};
use opc_persist::audit_authority::{AuditAdmission, AuditLedgerLimits, AuditOperationState};
use opc_persist::config_capacity_observation::raft_buffers::{
    raft_append_witness, RaftAppendCensus, RaftAppendSample, RaftAppendUnion,
};
use opc_persist::config_capacity_observation::with_audited_allocations;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::atomic::AtomicU64;

const WORKING_BYTES: usize = 32 * 1024 * 1024;
const MAX_CALL_DIAGNOSTICS: usize = 128;

// A fixed diagnostic slot avoids reacquiring a census lock after notification.
// Saturation is diagnostic only; no gate or deadline reads these observations.
struct ObservedDuration(AtomicU64);

impl Default for ObservedDuration {
    fn default() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }
}

impl ObservedDuration {
    fn record(&self, elapsed: Duration) {
        self.0.store(
            elapsed.as_nanos().min(u128::from(u64::MAX - 1)) as u64,
            Ordering::Relaxed,
        );
    }

    fn get(&self) -> Option<Duration> {
        let nanos = self.0.load(Ordering::Relaxed);
        (nanos != u64::MAX).then(|| Duration::from_nanos(nanos))
    }
}

#[derive(Clone, Copy, Debug)]
struct Wire {
    call: u64,
    target: ConsensusNodeId,
    generation: Option<u64>,
    bytes: usize,
}

struct CallTiming {
    target: ConsensusNodeId,
    generation: Option<u64>,
    invocation_entered_us: u128,
    registered_us: u128,
    // This is the invocation resuming from the gate, not the notification time.
    released_us: Option<u128>,
    transport_entered_us: Option<u128>,
    peer_response_us: Option<u128>,
    result_us: Option<u128>,
    result_at: Option<tokio::time::Instant>,
    dropped_us: Option<u128>,
    // Drop observes cancellation; it does not identify the inner/outer timeout.
    cancelled: bool,
    success: Option<bool>,
    hard_ttl_us: Option<u128>,
    deadline_earliest_us: Option<u128>,
    deadline_latest_us: Option<u128>,
    deadline_earliest: Option<tokio::time::Instant>,
    deadline_latest: Option<tokio::time::Instant>,
}

#[derive(Default)]
struct State {
    source: Option<ConsensusNodeId>,
    retained_targets: Option<BTreeSet<ConsensusNodeId>>,
    epoch: Option<tokio::time::Instant>,
    next: u64,
    rows: BTreeMap<u64, (Wire, usize)>,
    completed: BTreeMap<u64, bool>,
    timings: BTreeMap<u64, CallTiming>,
    timings_saturated: bool,
    hold_one_response: bool,
    held_response: Option<u64>,
    response_released: bool,
    settle_entered_us: Option<u128>,
    response_released_us: Option<u128>,
    mutation_completed_us: Option<u128>,
    gate_release_entered_us: Option<u128>,
    gate_opened_us: Option<u128>,
}

impl State {
    fn micros(&self, instant: tokio::time::Instant) -> u128 {
        instant
            .saturating_duration_since(self.epoch.expect("armed timing origin"))
            .as_micros()
    }

    fn completed_in_time(&self, wires: &[Wire]) -> bool {
        !self.timings_saturated
            && wires.iter().all(|wire| {
                self.completed.get(&wire.call) == Some(&true)
                    && self.timings.get(&wire.call).is_some_and(|timing| {
                        !timing.cancelled
                            && matches!(
                                (timing.result_at, timing.deadline_earliest),
                                (Some(result), Some(deadline)) if result <= deadline
                            )
                    })
            })
    }
}

pub(super) struct Gate {
    state: std::sync::Mutex<State>,
    changed: tokio::sync::watch::Sender<()>,
    gate_notification_completed: ObservedDuration,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(State::default()),
            changed: tokio::sync::watch::channel(()).0,
            gate_notification_completed: ObservedDuration::default(),
        }
    }
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanoutGate")
            .field("live_calls", &self.state.lock().unwrap().rows.len())
            .finish_non_exhaustive()
    }
}

struct Paused<'a> {
    gate: &'a Gate,
    token: u64,
    request: PhantomData<&'a ConsensusWireRequest>,
}

impl Drop for Paused<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        let now = state.micros(tokio::time::Instant::now());
        state.rows.remove(&self.token);
        if let Some(timing) = state.timings.get_mut(&self.token) {
            if timing.released_us.is_none() {
                timing.dropped_us = Some(now);
                timing.cancelled = true;
            }
        }
        drop(state);
        self.gate.changed.send_replace(());
    }
}

pub(super) struct InFlight<'a> {
    gate: &'a Gate,
    call: u64,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        let now = state.micros(tokio::time::Instant::now());
        if let Some(timing) = state.timings.get_mut(&self.call) {
            timing.dropped_us = Some(now);
            timing.cancelled = timing.result_us.is_none();
        }
        drop(state);
        self.gate.changed.send_replace(());
    }
}

impl Gate {
    fn arm(&self, source: ConsensusNodeId) {
        let mut state = self.state.lock().unwrap();
        assert!(state.source.is_none() && state.rows.is_empty());
        state.source = Some(source);
        state.retained_targets = None;
        state.epoch = Some(tokio::time::Instant::now());
    }

    pub(super) async fn pause(
        &self,
        request: &ConsensusWireRequest,
        target: ConsensusNodeId,
        invocation_entered: tokio::time::Instant,
    ) -> Option<u64> {
        if request.family != ConsensusRpcFamily::AppendEntries
            || request.payload.len() <= BOUNDED_LOGICAL_BYTES
        {
            return None;
        }
        let original = raft_append_witness(request, target);
        let mut changed = self.changed.subscribe();
        let guard = {
            let mut state = self.state.lock().unwrap();
            if state.source != Some(request.sender)
                || state
                    .retained_targets
                    .as_ref()
                    .is_some_and(|targets| !targets.contains(&target))
            {
                return None;
            }
            state.next = state.next.checked_add(1).expect("finite original calls");
            let token = state.next;
            if state.timings.len() < MAX_CALL_DIAGNOSTICS {
                let deadline = original.and_then(|original| original.deadline);
                let timing = CallTiming {
                    target,
                    generation: original.map(|original| original.generation),
                    invocation_entered_us: state.micros(invocation_entered),
                    registered_us: state.micros(tokio::time::Instant::now()),
                    released_us: None,
                    transport_entered_us: None,
                    peer_response_us: None,
                    result_us: None,
                    result_at: None,
                    dropped_us: None,
                    cancelled: false,
                    success: None,
                    hard_ttl_us: deadline.map(|deadline| deadline.hard_ttl.as_micros()),
                    deadline_earliest_us: deadline
                        .and_then(|deadline| deadline.earliest)
                        .map(|instant| state.micros(instant)),
                    deadline_latest_us: deadline
                        .and_then(|deadline| deadline.latest)
                        .map(|instant| state.micros(instant)),
                    deadline_earliest: deadline.and_then(|deadline| deadline.earliest),
                    deadline_latest: deadline.and_then(|deadline| deadline.latest),
                };
                state.timings.insert(token, timing);
            } else {
                state.timings_saturated = true;
            }
            state.rows.insert(
                token,
                (
                    Wire {
                        call: token,
                        target,
                        generation: original.map(|original| original.generation),
                        bytes: request.payload.capacity(),
                    },
                    request.payload.as_ptr() as usize,
                ),
            );
            Paused {
                gate: self,
                token,
                request: PhantomData,
            }
        };
        self.changed.send_replace(());
        loop {
            {
                let state = self.state.lock().unwrap();
                if state.source.is_none()
                    || state
                        .retained_targets
                        .as_ref()
                        .is_some_and(|targets| !targets.contains(&target))
                {
                    break;
                }
            }
            changed
                .changed()
                .await
                .expect("original gate remains owned");
        }
        let call = guard.token;
        {
            let mut state = self.state.lock().unwrap();
            let now = state.micros(tokio::time::Instant::now());
            if let Some(timing) = state.timings.get_mut(&call) {
                timing.released_us = Some(now);
            }
        }
        drop(guard);
        Some(call)
    }

    pub(super) fn in_flight(&self, call: u64) -> InFlight<'_> {
        let mut state = self.state.lock().unwrap();
        let now = state.micros(tokio::time::Instant::now());
        if let Some(timing) = state.timings.get_mut(&call) {
            timing.transport_entered_us = Some(now);
        }
        InFlight { gate: self, call }
    }

    fn native_success(response: &Result<ConsensusWireResponse, ConsensusPeerError>) -> bool {
        use opc_consensus::engine::{error::RaftError, raft::AppendEntriesResponse};
        #[derive(serde::Deserialize)]
        struct Reply<T> {
            revision: u16,
            value: T,
        }
        type AppendReply =
            Result<AppendEntriesResponse<ConsensusNodeId>, RaftError<ConsensusNodeId>>;
        response
            .as_ref()
            .ok()
            .and_then(|response| response.result.as_ref().ok())
            .and_then(|bytes| opc_consensus::decode_bounded::<Reply<AppendReply>>(bytes).ok())
            .is_some_and(|reply| {
                reply.revision == 8 && matches!(reply.value, Ok(AppendEntriesResponse::Success))
            })
    }

    fn hold_one_response(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(state.source.is_some() && state.held_response.is_none());
        state.hold_one_response = true;
    }

    pub(super) async fn response_ready(
        &self,
        call: u64,
        response: &Result<ConsensusWireResponse, ConsensusPeerError>,
    ) {
        let mut changed = self.changed.subscribe();
        let held = {
            let mut state = self.state.lock().unwrap();
            let now = state.micros(tokio::time::Instant::now());
            if let Some(timing) = state.timings.get_mut(&call) {
                timing.peer_response_us = Some(now);
            }
            if state.hold_one_response
                && state.held_response.is_none()
                && Self::native_success(response)
            {
                state.held_response = Some(call);
                true
            } else {
                false
            }
        };
        if !held {
            return;
        }
        // The real authenticated peer has returned this original call's own
        // native success. Hold its response delivery, still inside the same
        // adapter timeout. No new request, retry, or response is constructed.
        self.changed.send_replace(());
        loop {
            if self.state.lock().unwrap().response_released {
                return;
            }
            changed
                .changed()
                .await
                .expect("response gate remains owned");
        }
    }

    pub(super) fn complete(
        &self,
        call: u64,
        response: &Result<ConsensusWireResponse, ConsensusPeerError>,
    ) {
        let success = Self::native_success(response);
        let mut state = self.state.lock().unwrap();
        assert!(state.completed.insert(call, success).is_none());
        let instant = tokio::time::Instant::now();
        let now = state.micros(instant);
        if let Some(timing) = state.timings.get_mut(&call) {
            timing.result_us = Some(now);
            timing.result_at = Some(instant);
            timing.success = Some(success);
        }
        drop(state);
        self.changed.send_replace(());
    }

    async fn settle(&self, wires: &[Wire]) -> bool {
        let mut changed = self.changed.subscribe();
        let deadline = {
            let mut state = self.state.lock().unwrap();
            state.settle_entered_us = Some(state.micros(tokio::time::Instant::now()));
            wires
                .iter()
                .map(|wire| {
                    // The lower constructor bound is no later than the actual
                    // deadline. This wait grants no new duration; every
                    // original adapter also enforces its own timeout.
                    state.timings.get(&wire.call)?.deadline_earliest
                })
                .collect::<Option<Vec<_>>>()
                .and_then(|deadlines| deadlines.into_iter().max())
        };
        let Some(deadline) = deadline else {
            return false;
        };
        tokio::time::timeout_at(deadline, async {
            loop {
                let (released, completed) = {
                    let mut state = self.state.lock().unwrap();
                    // The join starts immediately after ownership capture.
                    // When a real response hold is armed, observe its genuine
                    // native Success before releasing that same invocation.
                    // No mutation-completion dependency delays this release.
                    let released = !state.response_released
                        && (!state.hold_one_response || state.held_response.is_some());
                    if released {
                        state.response_released = true;
                        state.response_released_us =
                            Some(state.micros(tokio::time::Instant::now()));
                    }
                    let completed = wires.iter().all(|wire| {
                        state.completed.contains_key(&wire.call)
                            || state
                                .timings
                                .get(&wire.call)
                                .is_some_and(|timing| timing.cancelled)
                    });
                    (released, completed.then(|| state.completed_in_time(wires)))
                };
                if released {
                    self.changed.send_replace(());
                }
                if let Some(completed) = completed {
                    return completed;
                }
                changed
                    .changed()
                    .await
                    .expect("original calls remain observed");
            }
        })
        .await
        .unwrap_or(false)
    }

    fn completed_in_time(&self, wires: &[Wire]) -> bool {
        self.state.lock().unwrap().completed_in_time(wires)
    }

    async fn wait_for_all(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            if self.state.lock().unwrap().rows.len() == MEMBERS - 1 {
                return;
            }
            changed
                .changed()
                .await
                .expect("original gate remains owned");
        }
    }

    fn capture<R>(&self, capture: impl FnOnce(Vec<Wire>, usize) -> R) -> R {
        let state = self.state.lock().unwrap();
        let identities: BTreeSet<_> = state.rows.values().map(|(_, identity)| identity).collect();
        capture(
            state.rows.values().map(|(wire, _)| *wire).collect(),
            identities.len(),
        )
    }

    fn retain_targets(&self, targets: BTreeSet<ConsensusNodeId>) {
        {
            let mut state = self.state.lock().unwrap();
            assert!(state.source.is_some() && state.retained_targets.is_none());
            state.retained_targets = Some(targets);
        }
        self.changed.send_replace(());
    }

    fn release(&self) {
        let entered_at = tokio::time::Instant::now();
        let epoch = {
            let mut state = self.state.lock().unwrap();
            let first_release = state.source.is_some();
            state.source = None;
            if first_release {
                // Preserve the first opening; cleanup repeats this method.
                state.gate_release_entered_us = Some(state.micros(entered_at));
                state.gate_opened_us = Some(state.micros(tokio::time::Instant::now()));
                state.epoch
            } else {
                None
            }
        };
        self.changed.send_replace(());
        if let Some(epoch) = epoch {
            self.gate_notification_completed
                .record(tokio::time::Instant::now().saturating_duration_since(epoch));
        }
    }

    fn drained(&self) -> bool {
        self.state.lock().unwrap().rows.is_empty()
    }

    fn elapsed_micros(&self) -> u128 {
        self.state
            .lock()
            .unwrap()
            .micros(tokio::time::Instant::now())
    }

    fn print_diagnostics(&self, shutdown_entered_us: u128) {
        let state = self.state.lock().unwrap();
        println!("CONFIG_CAPACITY_NINE_FANOUT_RPC_LIFECYCLE shutdown_entered_us={shutdown_entered_us} shutdown_completed_us={} diagnostics_saturated={} held_response={:?} response_released={} settle_entered_us={:?} response_released_us={:?} mutation_completed_us={:?}", state.micros(tokio::time::Instant::now()), state.timings_saturated, state.held_response, state.response_released, state.settle_entered_us, state.response_released_us, state.mutation_completed_us);
        println!("CONFIG_CAPACITY_NINE_FANOUT_GATE_TIMING gate_release_entered_us={:?} gate_opened_us={:?} gate_notification_completed_us={:?} origin=gate_arm first_release=true released_us_is_rpc_resumption=true dropped_us_is_scope_drop_observation=true timeout_cause_known=false diagnostic_only=true", state.gate_release_entered_us, state.gate_opened_us, self.gate_notification_completed.get().map(|elapsed| elapsed.as_micros()));
        for (call, timing) in &state.timings {
            let epoch = state.epoch.expect("armed timing origin");
            let result_ns = timing
                .result_at
                .map(|instant| instant.duration_since(epoch).as_nanos());
            let deadline_earliest_ns = timing
                .deadline_earliest
                .map(|instant| instant.duration_since(epoch).as_nanos());
            let deadline_latest_ns = timing
                .deadline_latest
                .map(|instant| instant.duration_since(epoch).as_nanos());
            println!("CONFIG_CAPACITY_NINE_FANOUT_RPC call={call} target={} generation={:?} invocation_entered_us={} registered_us={} released_us={:?} transport_entered_us={:?} peer_response_us={:?} result_us={:?} dropped_us={:?} cancelled={} success={:?} hard_ttl_us={:?} deadline_earliest_us={:?} deadline_latest_us={:?} result_ns={result_ns:?} deadline_earliest_ns={deadline_earliest_ns:?} deadline_latest_ns={deadline_latest_ns:?}", timing.target, timing.generation, timing.invocation_entered_us, timing.registered_us, timing.released_us, timing.transport_entered_us, timing.peer_response_us, timing.result_us, timing.dropped_us, timing.cancelled, timing.success, timing.hard_ttl_us, timing.deadline_earliest_us, timing.deadline_latest_us);
        }
    }
}

#[test]
fn gate_release_timing_survives_cleanup_without_completing_calls() {
    let gate = Gate::default();
    let mut changed = gate.changed.subscribe();
    assert!(gate.gate_notification_completed.get().is_none());
    gate.arm(ConsensusNodeId::new(1).unwrap());
    gate.release();
    assert!(changed.has_changed().unwrap());
    drop(changed.borrow_and_update());
    let first = {
        let state = gate.state.lock().unwrap();
        assert!(state.source.is_none());
        assert!(state.completed.is_empty() && state.timings.is_empty());
        (
            state.gate_release_entered_us.unwrap(),
            state.gate_opened_us.unwrap(),
            gate.gate_notification_completed.get().unwrap(),
        )
    };
    gate.release();
    assert!(changed.has_changed().unwrap());
    let state = gate.state.lock().unwrap();
    assert_eq!(
        first,
        (
            state.gate_release_entered_us.unwrap(),
            state.gate_opened_us.unwrap(),
            gate.gate_notification_completed.get().unwrap(),
        )
    );
    assert!(state.completed.is_empty() && state.timings.is_empty());
}

struct Checkpoint {
    wires: Vec<Wire>,
    wire_allocations: usize,
    original: RaftAppendSample,
    selected: RaftAppendUnion,
    encryption: BufferSnapshot,
    envelope_identity: AllocationIdentity,
    envelope_length: usize,
}

fn arc_slice_requested_bytes(length: usize) -> usize {
    // Pinned Rust's ArcInner is repr(C), two AtomicUsize counts followed by
    // the slice. This is a requested-layout allowance, not an allocator receipt.
    std::alloc::Layout::array::<AtomicUsize>(2)
        .unwrap()
        .extend(std::alloc::Layout::array::<u8>(length).unwrap())
        .unwrap()
        .0
        .pad_to_align()
        .size()
}

native_case!(config_capacity_957_nine_live_fanout_working_bound, {
    let directory = disk_fixture();
    let databases: [_; MEMBERS] =
        std::array::from_fn(|member| directory.join(format!("config-{member}.sqlite")));
    let pki = Pki::new();
    let manifest = nine_manifest();
    let addresses = std::array::from_fn(|_| Arc::new(RwLock::new(None)));
    let transfers: [_; MEMBERS] = std::array::from_fn(|_| Arc::new(Transfers::default()));
    let observation = Arc::new(ConsensusBufferObservation::default());
    let stores = open_nine(
        &directory,
        &manifest,
        &pki,
        &addresses,
        &transfers,
        false,
        Some(&observation),
    )
    .await;
    let raft = Arc::new(RaftAppendCensus::default());
    let registrations: Vec<_> = stores
        .iter()
        .map(|store| {
            raft.observe_source(manifest.consensus_identity(), store.status().node_id)
                .expect("original node's scoped typed-request census")
        })
        .collect();
    let mut servers = Vec::new();
    let mut released = Vec::new();
    for member in 0..MEMBERS {
        let (server, receipt) =
            overlap::listen_one(&stores, member, &pki, &manifest, &addresses, &observation).await;
        servers.push(Some(server));
        released.push(receipt);
    }
    overlap::ready(&stores, None, "fanout").await;
    let leader = stores
        .iter()
        .position(|store| Some(store.status().node_id) == stores[0].status().leader_id)
        .unwrap();
    let leader_id = stores[leader].status().node_id;
    let (control, control_aad, control_plaintext) = commit(&stores[leader], 1, None).await;
    let control_record = control.record().clone();
    let control = stores[leader]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xA1; 16]),
            control,
            CALLER,
        )
        .unwrap();
    stores[leader]
        .append_prepared_commit_local(control)
        .await
        .unwrap();
    read_all(&stores, &control_record, &control_aad, &control_plaintext).await;
    stores[leader]
        .initialize_audit_authority(&joint::privacy(), AuditLedgerLimits::new(12, 4).unwrap())
        .await
        .unwrap();

    let principal = joint::principal(true);
    let encryption = Arc::new(BufferObservation::new(|_, _| {}));
    let (input, aad, plaintext, envelope) = encryption::scope(
        Arc::clone(&encryption),
        1,
        joint::input_with_envelope(
            &stores[leader],
            2,
            Some(control_record.tx_id),
            &principal,
            0,
        ),
    )
    .await;
    let expected = input.record().clone();
    let prepared = stores[leader]
        .prepare_audited_commit(
            &joint::privacy(),
            &joint::event(2, &principal),
            input,
            Duration::from_secs(60),
        )
        .unwrap();
    let alias = prepared.clone();
    let handle = prepared.handle().clone();
    let AuditAdmission::Applied(admission) = stores[leader]
        .admit_audit_operation_local(&handle, joint::caller(&principal))
        .await
    else {
        panic!("original native Intent receipt");
    };
    let recovery = prepared.encode().unwrap();
    let caller_recovery_bytes = recovery.capacity();
    let mut held: Vec<Vec<PreparedConfigCommitOperation>> =
        (0..MEMBERS).map(|_| Vec::new()).collect();
    for (member, store) in stores.iter().enumerate() {
        for slot in 0..PREPARATIONS - usize::from(member == leader) {
            let (input, _, _) = commit(store, 2, Some(control_record.tx_id)).await;
            let mut request = [0xA2; 16];
            request[0] = member as u8;
            request[1] = slot as u8;
            held[member].push(
                store
                    .prepare_recoverable_commit(
                        ConfigConsensusRequestId::from_bytes(request),
                        input,
                        CALLER,
                    )
                    .unwrap(),
            );
        }
        assert_exhausted(store);
    }
    let before: [_; MEMBERS] = std::array::from_fn(|target| {
        transfers[leader].large_append_success[target].load(Ordering::SeqCst)
    });
    let gate = &transfers[leader].fanout;
    gate.arm(leader_id);
    gate.hold_one_response();
    let (result, (checkpoint, settled)) = tokio::join!(
        async {
            let result = stores[leader]
                .submit_audited_mutation_local(&alias, &admission, joint::caller(&principal))
                .await;
            let mut state = gate.state.lock().unwrap();
            state.mutation_completed_us = Some(state.micros(tokio::time::Instant::now()));
            result
        },
        async {
            let ready =
                tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, gate.wait_for_all())
                    .await;
            let checkpoint = ready.map(|()| {
                with_audited_allocations(leader_id, &prepared, |owners| {
                    gate.capture(|wires, wire_allocations| {
                        raft.with_current_capture(|capture| {
                            encryption.capture(|encrypted| Checkpoint {
                                wires,
                                wire_allocations,
                                original: capture.sample(),
                                selected: capture.join(&owners),
                                encryption: *encrypted,
                                envelope_identity: AllocationIdentity::of(envelope.encoded()),
                                envelope_length: envelope.encoded().len(),
                            })
                        })
                    })
                })
                .expect("original bounded audited preparation")
            });
            gate.release();
            // The actual original responses have their own shorter deadlines.
            // Join them as soon as capture releases their requests, while the
            // same audited mutation can continue through native application.
            let settled = match &checkpoint {
                Ok(checkpoint) => gate.settle(&checkpoint.wires).await,
                Err(_) => false,
            };
            (checkpoint, settled)
        },
    );
    let AuditAdmission::Applied(receipt) = result else {
        panic!("original audited mutation completes after releasing original calls");
    };
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 2 }
    );
    let records = tokio::time::timeout(
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        join_all(stores.iter().map(|store| store.load_latest())),
    )
    .await
    .expect("all nine original joint read deadlines");
    for record in records {
        joint::assert_readback(&record.unwrap().unwrap(), &expected, &aad, &plaintext);
    }
    for store in &stores {
        let outcome = store
            .lookup_audit_operation(&handle, joint::caller(&principal))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome.state(),
            AuditOperationState::Committed { version: 2 }
        );
    }
    let after: [_; MEMBERS] = std::array::from_fn(|target| {
        transfers[leader].large_append_success[target].load(Ordering::SeqCst)
    });
    let committed = databases.each_ref().map(|path| effect_counts(path));
    assert!(!recovery.is_empty());
    drop(prepared);
    drop(alias);
    drop(held);
    // The original envelope shares the consumed preparation's lease. Dropping
    // every prepared alias must still leave exactly one leader slot occupied.
    let slots: Vec<_> = (0..PREPARATIONS - 1)
        .map(|_| {
            stores[leader]
                .try_reserve_config_preparation()
                .unwrap()
                .unwrap()
        })
        .collect();
    assert_exhausted(&stores[leader]);
    drop(slots);
    drop(envelope);
    let encryption_drained = encryption.capture(|snapshot| *snapshot);
    for store in &stores {
        let slots: Vec<_> = (0..PREPARATIONS)
            .map(|_| store.try_reserve_config_preparation().unwrap().unwrap())
            .collect();
        assert_exhausted(store);
        drop(slots);
    }
    let shutdown_entered_us = gate.elapsed_micros();
    for (store, server) in stores.iter().zip(servers) {
        server.unwrap().abort_and_wait().await;
        store.shutdown().await.unwrap();
    }
    all_handlers_released(released).await;
    drop(stores);
    for address in &addresses {
        *address.write().unwrap() = None;
    }
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        observation.wait_for_no_inbound_sockets().await;
        observation.wait_for_no_outbound_owners().await;
    })
    .await
    .unwrap();
    let drained = raft.with_current_capture(|capture| capture.sample());
    drop(registrations);
    let detached = raft.with_current_capture(|capture| capture.sample());
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        committed
    );
    println!("CONFIG_CAPACITY_NINE_FANOUT_LIFECYCLE members=9 prepared=72 remote_targets=8 audited_commits=1 exact_readback=true original_handle=true original_paths=true joined_shutdown=true caller_recovery_bytes={caller_recovery_bytes} full_memory_bound=false");
    gate.print_diagnostics(shutdown_entered_us);
    assert!(gate.drained());
    assert!(drained.calls.is_empty() && drained.origins.is_empty() && drained.issues.complete());
    assert!(detached.calls.is_empty() && detached.origins.is_empty() && detached.issues.complete());
    assert_eq!(detached.registrations, 0);
    assert!(!encryption_drained.overflowed);
    assert_eq!(encryption_drained.allocations(), 0);
    let checkpoint = checkpoint.expect("CONFIG_CAPACITY_NINE_FANOUT_BARRIER_RED: all original calls coexist inside their original deadline");
    assert_eq!(checkpoint.wires.len(), MEMBERS - 1);
    let completed = gate.state.lock().unwrap().completed.clone();
    assert_eq!(
        completed.len(),
        MEMBERS - 1,
        "CONFIG_CAPACITY_NINE_FANOUT_GENERATION_COMPLETION_RED"
    );
    assert!(checkpoint.wires.iter().all(|wire| completed.get(&wire.call) == Some(&true)),
        "CONFIG_CAPACITY_NINE_FANOUT_GENERATION_COMPLETION_RED: every captured original call receives its own native success");
    // Tokio polls its inner future before its timer. A successful timeout
    // wrapper therefore cannot prove that a ready response met its deadline.
    // Compare the actual unrounded instants for every captured original call.
    assert!(gate.completed_in_time(&checkpoint.wires), "CONFIG_CAPACITY_NINE_FANOUT_DEADLINE_RED: each original response arrives within its own unchanged deadline");
    assert!(settled, "CONFIG_CAPACITY_NINE_FANOUT_DEADLINE_RED: original-call join stays inside original deadlines");
    {
        let state = gate.state.lock().unwrap();
        let call = state.held_response.expect("genuine original response tail");
        let timing = &state.timings[&call];
        assert!(timing.peer_response_us.is_some_and(|received| {
            state
                .response_released_us
                .is_some_and(|released| received <= released)
        }));
        assert!(state.settle_entered_us.is_some_and(|joined| {
            state
                .response_released_us
                .is_some_and(|released| joined <= released)
        }));
        println!("CONFIG_CAPACITY_NINE_FANOUT_RESPONSE_JOIN held_original_call={call} native_success_before_release=true captured_calls=8 settled=true original_deadlines=true");
    }
    for (target, before) in before.iter().enumerate() {
        if target != leader {
            assert!(after[target] > *before);
        }
    }
    assert_eq!(checkpoint.wire_allocations, MEMBERS - 1);
    let targets: BTreeSet<_> = checkpoint.wires.iter().map(|wire| wire.target).collect();
    assert_eq!(targets.len(), MEMBERS - 1);
    assert!(!targets.contains(&leader_id));
    assert!(checkpoint
        .wires
        .iter()
        .all(|wire| wire.bytes > BOUNDED_LOGICAL_BYTES));
    assert!(checkpoint.original.issues.complete() && checkpoint.selected.issues.complete());
    let origins: Vec<_> = checkpoint
        .original
        .origins
        .iter()
        .filter(|call| call.source == leader_id)
        .collect();
    assert_eq!(
        origins.len(),
        MEMBERS - 1,
        "CONFIG_CAPACITY_NINE_FANOUT_ORIGIN_RED"
    );
    for wire in &checkpoint.wires {
        assert!(origins
            .iter()
            .any(|call| Some(call.generation) == wire.generation
                && call.target == wire.target
                && call.entries == 1
                && call.attribution.len() == 1
                && call.attribution[0].supported));
    }
    assert_eq!(checkpoint.selected.source, leader_id);
    assert_eq!(checkpoint.selected.shared_bytes, 0);
    assert!(checkpoint.selected.native_bytes > BOUNDED_LOGICAL_BYTES);
    let postcard_bytes: usize = checkpoint.wires.iter().map(|wire| wire.bytes).sum();
    assert!(!checkpoint.encryption.overflowed);
    assert_eq!(
        checkpoint.encryption.allocations(),
        1,
        "CONFIG_CAPACITY_NINE_FANOUT_ENVELOPE_RED"
    );
    let encrypted: Vec<_> = checkpoint.encryption.buffers.iter().flatten().collect();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].kind, BufferKind::EnvelopeArc);
    assert_eq!(encrypted[0].identity, checkpoint.envelope_identity);
    assert_eq!(encrypted[0].capacity, checkpoint.envelope_length);
    assert_eq!(encrypted[0].aliases, 1);
    let envelope_data = checkpoint.encryption.data_capacity();
    let envelope_layout = arc_slice_requested_bytes(checkpoint.envelope_length);
    let working = checkpoint
        .selected
        .union_bytes
        .checked_add(postcard_bytes)
        .unwrap()
        .checked_add(envelope_layout)
        .unwrap();
    println!("CONFIG_CAPACITY_NINE_FANOUT_CHECKPOINT selected={:?} postcard_bytes={postcard_bytes} envelope_data={envelope_data} envelope_requested_layout={envelope_layout} working_bytes={working} operation_bound={WORKING_BYTES} caller_recovery_bytes={caller_recovery_bytes} caller_recovery_in_working=false envelope_reservation_retained=true snapshot=false outer_frames_separate=true full_memory_bound=false", checkpoint.selected);
    assert!(working <= WORKING_BYTES, "CONFIG_CAPACITY_NINE_FANOUT_WORKING_RED: admitted original mutation owners exceed reservation");
    assert_eq!(
        checkpoint.selected.calls, 0,
        "CONFIG_CAPACITY_NINE_FANOUT_TYPED_RETIREMENT_RED"
    );
    assert_eq!(checkpoint.selected.original_bytes, 0);
    assert!(checkpoint.original.calls.is_empty());
});
