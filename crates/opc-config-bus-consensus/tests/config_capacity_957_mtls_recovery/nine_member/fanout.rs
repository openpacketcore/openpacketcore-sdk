//! One operation's actual original owners at the eight-follower boundary.
//!
//! The barrier pauses genuine already-encoded RPCs inside their unchanged
//! native deadlines. It releases those same calls before any allocation
//! assertion; successful IO, readback, recovery and shutdown are prerequisites.

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

const WORKING_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct Wire {
    call: u64,
    target: ConsensusNodeId,
    generation: Option<u64>,
    bytes: usize,
}

#[derive(Default)]
struct State {
    source: Option<ConsensusNodeId>,
    next: u64,
    rows: BTreeMap<u64, (Wire, usize)>,
    completed: BTreeMap<u64, bool>,
}

pub(super) struct Gate {
    state: std::sync::Mutex<State>,
    changed: tokio::sync::watch::Sender<()>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(State::default()),
            changed: tokio::sync::watch::channel(()).0,
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
        self.gate.state.lock().unwrap().rows.remove(&self.token);
        self.gate.changed.send_replace(());
    }
}

impl Gate {
    fn arm(&self, source: ConsensusNodeId) {
        let mut state = self.state.lock().unwrap();
        assert!(state.source.is_none() && state.rows.is_empty());
        state.source = Some(source);
    }

    pub(super) async fn pause(
        &self,
        request: &ConsensusWireRequest,
        target: ConsensusNodeId,
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
            if state.source != Some(request.sender) {
                return None;
            }
            state.next = state.next.checked_add(1).expect("finite original calls");
            let token = state.next;
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
            if self.state.lock().unwrap().source.is_none() {
                break;
            }
            changed
                .changed()
                .await
                .expect("original gate remains owned");
        }
        let call = guard.token;
        drop(guard);
        Some(call)
    }

    pub(super) fn complete(
        &self,
        call: u64,
        response: &Result<ConsensusWireResponse, ConsensusPeerError>,
    ) {
        use opc_consensus::engine::{error::RaftError, raft::AppendEntriesResponse};
        #[derive(serde::Deserialize)]
        struct Reply<T> {
            revision: u16,
            value: T,
        }
        type AppendReply =
            Result<AppendEntriesResponse<ConsensusNodeId>, RaftError<ConsensusNodeId>>;
        let success = response
            .as_ref()
            .ok()
            .and_then(|response| response.result.as_ref().ok())
            .and_then(|bytes| opc_consensus::decode_bounded::<Reply<AppendReply>>(bytes).ok())
            .is_some_and(|reply| {
                reply.revision == 8 && matches!(reply.value, Ok(AppendEntriesResponse::Success))
            });
        assert!(self
            .state
            .lock()
            .unwrap()
            .completed
            .insert(call, success)
            .is_none());
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

    fn release(&self) {
        self.state.lock().unwrap().source = None;
        self.changed.send_replace(());
    }

    fn drained(&self) -> bool {
        self.state.lock().unwrap().rows.is_empty()
    }
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
    let (result, checkpoint) = tokio::join!(
        stores[leader].submit_audited_mutation_local(&alias, &admission, joint::caller(&principal)),
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
            checkpoint
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
    for (target, before) in before.iter().enumerate() {
        if target != leader {
            assert!(
                transfers[leader].large_append_success[target].load(Ordering::SeqCst) > *before
            );
        }
    }
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
