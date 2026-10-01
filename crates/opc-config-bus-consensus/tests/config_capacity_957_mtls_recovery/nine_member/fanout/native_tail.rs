//! Actual native apply and SDK recovery output beside four original RPC tails.
//!
//! Four genuine remote successes form the original nine-voter quorum while
//! four captured original calls remain held inside their own RPC deadlines.
//! Each native callback joins actual preparations, ledger/output, recovery Vec,
//! typed Raft allocations, outgoing wires and the lease-bearing envelope at
//! one instant. Separate stages are never added. This remains a partial bound.
//!
//! Diagnostic microseconds share the gate-arm origin, before recovery readiness
//! and API submission. Stage indices are decoded (0), validated (1), authenticated
//! (2), and ledger write (3). These observations never decide a deadline or pass.

use super::*;
use opc_persist::config_capacity_observation::raft_buffers::AllocationView;
use opc_persist::config_capacity_observation::{
    AppendOwnerSample, NativeOwnerObserver, NativeOwnerSample, NativePhase, NativePhaseSample,
    NativeStage, PreparationCensus,
};

const HELD_TAILS: usize = 4;
use opc_persist::config_capacity_observation::working_buffers::{
    WorkingBufferCensus, WorkingBufferKind, WorkingBufferObserver, WorkingBufferOwner,
    WorkingBufferSample, WorkingBufferStage, WorkingBufferUnion,
};

struct EncoderGate {
    arrived: Mutex<Option<tokio::sync::oneshot::Sender<WorkingBufferOwner>>>,
    release: Mutex<bool>,
    condition: std::sync::Condvar,
    deadline: std::time::Instant,
    expired: AtomicBool,
}

impl EncoderGate {
    fn open(&self) {
        *self.release.lock().unwrap() = true;
        self.condition.notify_all();
    }
}

impl WorkingBufferObserver for EncoderGate {
    fn observe(&self, stage: WorkingBufferStage, owner: WorkingBufferOwner) {
        if stage != WorkingBufferStage::RecoveryReady {
            return;
        }
        if let Some(sender) = self.arrived.lock().unwrap().take() {
            let _ = sender.send(owner);
        }
        // The hook runs outside the working census. It borrows the actual Vec
        // at the end of the writer, before ownership can pass to the caller.
        // Only this finite condition variable is held while the encoder waits.
        let released = self
            .condition
            .wait_timeout_while(
                self.release.lock().unwrap(),
                self.deadline
                    .saturating_duration_since(std::time::Instant::now()),
                |released| !*released,
            )
            .unwrap();
        self.expired.store(!*released.0, Ordering::SeqCst);
    }
}

struct InitialCalls {
    wires: Vec<Wire>,
    held: BTreeSet<ConsensusNodeId>,
    allocations: usize,
}

struct TailCheckpoint {
    native: NativeOwnerSample,
    working: WorkingBufferSample,
    working_union: WorkingBufferUnion,
    raft: RaftAppendSample,
    joined: RaftAppendUnion,
    wires: Vec<Wire>,
    wire_allocations: usize,
    successful_quorum_calls: Vec<u64>,
    encryption: BufferSnapshot,
}

struct NativeTiming {
    native_scope_entered_at: std::time::Instant,
    census_entered_at: std::time::Instant,
    callback_entered_at: std::time::Instant,
    owned_capture_completed_at: Option<std::time::Instant>,
}

#[derive(Default)]
struct NativeResults {
    samples: [Option<TailCheckpoint>; 4],
    timings: [Option<NativeTiming>; 4],
    counts: [usize; 4],
    missing_views: usize,
    request: Option<opc_consensus::ConsensusRequestId>,
    request_changed: bool,
    phases: [Option<NativePhaseSample>; NativePhase::COUNT],
    phase_counts: [usize; NativePhase::COUNT],
    phase_incomplete: [usize; NativePhase::COUNT],
    phase_counts_saturated: bool,
}

// The bridge owns only numeric ledgers and scheduling controls. Native and
// preparation allocations are borrowed by the real callback; encoded payloads
// remain in their original paused RPC futures.
struct NativeTail {
    gate: Arc<Gate>,
    encoder: Arc<EncoderGate>,
    working: Arc<WorkingBufferCensus>,
    raft: Arc<RaftAppendCensus>,
    encryption: Arc<BufferObservation>,
    results: Mutex<NativeResults>,
    tail_release_entered_after_callback: ObservedDuration,
    tail_release_returned_after_callback: ObservedDuration,
}

impl NativeTail {
    fn record(&self, native: NativeOwnerSample, owners: Option<AllocationView<'_>>) {
        let callback_entered_at = std::time::Instant::now();
        let index = match native.stage {
            NativeStage::DecodedLedger => 0,
            NativeStage::ValidatedLedger => 1,
            NativeStage::AuthenticatedMutation => 2,
            NativeStage::LedgerWrite => 3,
        };
        let checkpoint = owners.map(|owners| {
            // Native/preparation -> working -> live wire gate -> Raft ->
            // encryption. No callback awaits or changes a protected owner.
            self.working.with_current_capture(|working| {
                working.with_joined(&owners, |working_union, joined| {
                    let gate = self.gate.state.lock().unwrap();
                    let wires = gate.rows.values().map(|(wire, _)| *wire).collect();
                    let wire_allocations = gate
                        .rows
                        .values()
                        .map(|(_, identity)| identity)
                        .collect::<BTreeSet<_>>()
                        .len();
                    let successful_quorum_calls = gate
                        .completed
                        .iter()
                        .filter_map(|(call, success)| success.then_some(*call))
                        .collect();
                    self.raft.with_current_capture(|raft| {
                        self.encryption.capture(|encryption| TailCheckpoint {
                            native,
                            working: working.sample(),
                            working_union,
                            raft: raft.sample(),
                            joined: raft.join(&joined),
                            wires,
                            wire_allocations,
                            successful_quorum_calls,
                            encryption: *encryption,
                        })
                    })
                })
            })
        });
        let owned_capture_completed_at = checkpoint.as_ref().map(|_| std::time::Instant::now());
        let first_callback = {
            let mut results = self.results.lock().unwrap();
            let first_callback = results.timings[index].is_none();
            if first_callback {
                results.timings[index] = Some(NativeTiming {
                    native_scope_entered_at: native.native_scope_entered_at,
                    census_entered_at: native.census_entered_at,
                    callback_entered_at,
                    owned_capture_completed_at,
                });
            }
            results.counts[index] += 1;
            if checkpoint.is_none() {
                results.missing_views += 1;
            }
            if results.samples[index].is_none() {
                results.samples[index] = checkpoint;
            }
            first_callback
        };
        if native.stage == NativeStage::LedgerWrite {
            // Release the very same four calls and public encoder only after
            // the actual native output has been captured. Neither deadline nor
            // operation authority changes at this scheduling checkpoint.
            let release_entered_at = std::time::Instant::now();
            self.gate.release();
            let release_returned_at = std::time::Instant::now();
            self.encoder.open();
            if first_callback {
                self.tail_release_entered_after_callback
                    .record(release_entered_at.duration_since(callback_entered_at));
                self.tail_release_returned_after_callback
                    .record(release_returned_at.duration_since(callback_entered_at));
            }
        }
    }

    fn print_diagnostics(&self) {
        let epoch = self.gate.state.lock().unwrap().epoch.unwrap();
        let micros = |instant| {
            tokio::time::Instant::from_std(instant)
                .saturating_duration_since(epoch)
                .as_micros()
        };
        let results = self.results.lock().unwrap();
        // Preserve small receipts even if the original completion assertion
        // fails. The original rich shape assertions remain below, unchanged.
        for (stage_index, checkpoint) in results.samples.iter().enumerate() {
            if let Some(checkpoint) = checkpoint {
                let sample = checkpoint.native;
                println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_SCALAR stage_index={stage_index} present=true callbacks={} entries={} operations={} continuity_rows={} entries_capacity={} operations_capacity={} rows_capacity={} command_bytes={} ledger_bytes={} derived_bytes={} write_bytes={} wires_observed={} wire_allocations={} successful_quorum_calls={} native_is_distinct={} diagnostic_only=true", results.counts[stage_index], sample.native_ledger_entries, sample.native_ledger_operations, sample.native_continuity_rows, sample.native_ledger_capacities[0], sample.native_ledger_capacities[1], sample.native_ledger_capacities[2], sample.native_command_bytes, sample.native_ledger_bytes, sample.native_derived_bytes, sample.native_write_bytes, checkpoint.wires.len(), checkpoint.wire_allocations, checkpoint.successful_quorum_calls.len(), sample.native_is_distinct);
            } else {
                println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_SCALAR stage_index={stage_index} present=false callbacks={} diagnostic_only=true", results.counts[stage_index]);
            }
        }
        for (phase_index, phase) in results.phases.iter().enumerate() {
            if let Some(phase) = phase {
                println!("CONFIG_CAPACITY_NINE_NATIVE_PHASE phase_index={phase_index} phase={:?} occurrences={} incomplete={} native_scope_entered_us={} started_us={} finished_us={} rows={} bytes={} saturated={} completed={} first_occurrence=true nested_durations=true origin=gate_arm diagnostic_only=true", phase.phase, results.phase_counts[phase_index], results.phase_incomplete[phase_index], micros(phase.native_scope_entered_at), micros(phase.started_at), micros(phase.finished_at), phase.rows, phase.bytes, phase.saturated || results.phase_counts_saturated, phase.completed);
            }
        }
        // Four fixed stages, including a callback without a valid owner view.
        // Print before completion assertions so failed original calls retain it.
        for (stage_index, timing) in results.timings.iter().enumerate() {
            if let Some(timing) = timing {
                println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_TIMING stage_index={stage_index} callbacks={} native_scope_entered_us={} census_entered_us={} callback_entered_us={} owned_capture_completed_us={:?} origin=gate_arm first_callback=true diagnostic_only=true", results.counts[stage_index], micros(timing.native_scope_entered_at), micros(timing.census_entered_at), micros(timing.callback_entered_at), timing.owned_capture_completed_at.map(micros));
                if stage_index == 3 {
                    let release_entered_us = self
                        .tail_release_entered_after_callback
                        .get()
                        .map(|elapsed| micros(timing.callback_entered_at + elapsed));
                    let release_returned_us = self
                        .tail_release_returned_after_callback
                        .get()
                        .map(|elapsed| micros(timing.callback_entered_at + elapsed));
                    println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_RELEASE release_entered_us={release_entered_us:?} release_returned_us={release_returned_us:?} origin=gate_arm first_ledger_write_callback=true diagnostic_only=true");
                }
            }
        }
    }
}

impl NativeOwnerObserver for NativeTail {
    fn observe_phase(&self, sample: NativePhaseSample) {
        // Fixed slots and one existing metadata mutex. No gate/owner lock,
        // payload capture, allocation, printing, or per-outcome callback.
        let mut results = self.results.lock().unwrap();
        let index = sample.phase as usize;
        results.phase_counts_saturated |= results.phase_counts[index] == usize::MAX;
        results.phase_counts[index] = results.phase_counts[index].saturating_add(1);
        if !sample.completed {
            results.phase_incomplete[index] = results.phase_incomplete[index].saturating_add(1);
        }
        if results.phases[index].is_none() {
            results.phases[index] = Some(sample);
        }
    }

    fn observe_append(&self, sample: AppendOwnerSample) {
        let mut results = self.results.lock().unwrap();
        if results
            .request
            .is_some_and(|request| request != sample.request)
        {
            results.request_changed = true;
        }
        results.request = Some(sample.request);
    }

    fn observe(&self, sample: NativeOwnerSample) {
        self.record(sample, None);
    }

    fn observe_with_allocations(&self, sample: NativeOwnerSample, owners: AllocationView<'_>) {
        self.record(sample, Some(owners));
    }
}

/// The original small ledger and the separate public history case.
#[derive(Clone, Copy)]
pub(super) enum AuditHistory {
    Small,
    PublicOperationLimit,
}

pub(super) async fn run(history: AuditHistory) {
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
    overlap::ready(&stores, None, "native_four_tail").await;
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
        .initialize_audit_authority(
            &joint::privacy(),
            match history {
                AuditHistory::Small => AuditLedgerLimits::new(12, 4).unwrap(),
                AuditHistory::PublicOperationLimit => AuditLedgerLimits::new(4_096, 1_024).unwrap(),
            },
        )
        .await
        .unwrap();

    let principal = joint::principal(true);
    if let AuditHistory::PublicOperationLimit = history {
        super::public_history::fill(&stores, leader, &principal).await;
    }
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
    let preparations = Arc::new(PreparationCensus::default());
    let mut preparation_owners = Vec::new();
    for (member, operations) in held.iter().enumerate() {
        for operation in operations {
            preparation_owners
                .extend(preparations.observe_commit(stores[member].status().node_id, operation));
        }
    }
    preparation_owners.extend(preparations.observe_audited(leader_id, &prepared));
    preparation_owners.extend(preparations.observe_audited(leader_id, &alias));
    let envelope_identity = AllocationIdentity::of(envelope.encoded());
    let envelope_length = envelope.encoded().len();
    let deadline = std::time::Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
    let (arrived_tx, mut arrived_rx) = tokio::sync::oneshot::channel();
    let encoder_gate = Arc::new(EncoderGate {
        arrived: Mutex::new(Some(arrived_tx)),
        release: Mutex::new(false),
        condition: std::sync::Condvar::new(),
        deadline,
        expired: AtomicBool::new(false),
    });
    let working = Arc::new(WorkingBufferCensus::default());
    let registration = working
        .observe_source(
            manifest.consensus_identity(),
            leader_id,
            Some(encoder_gate.clone()),
        )
        .unwrap();
    let enrollment = registration.observe_recovery(&prepared).unwrap();
    let (finished_tx, mut finished_rx) = tokio::sync::oneshot::channel();
    let gate = &transfers[leader].fanout;
    let native = Arc::new(NativeTail {
        gate: gate.clone(),
        encoder: encoder_gate.clone(),
        working: working.clone(),
        raft: raft.clone(),
        encryption: encryption.clone(),
        results: Mutex::new(NativeResults::default()),
        tail_release_entered_after_callback: ObservedDuration::default(),
        tail_release_returned_after_callback: ObservedDuration::default(),
    });
    let native_registration = stores[leader]
        .observe_capacity_native_owners_for_test(&prepared, preparations.clone(), native.clone())
        .await
        .unwrap();
    gate.arm(leader_id);
    let completion_origin = gate.state.lock().unwrap().epoch.unwrap().into_std();
    let completion_registration = stores[leader]
        .observe_capacity_completion_for_test(&prepared, completion_origin)
        .expect("bounded selected-request completion observer");
    let (result, checkpoint, ready, recovery, after_return, released_in_time, settled) =
        tokio::task::block_in_place(|| {
            std::thread::scope(|scope| {
                // This thread borrows the original preparation and calls its
                // public encoder once. The observer owns no payload or alias.
                let encoder = scope.spawn(|| {
                    let _ = finished_tx.send(prepared.encode());
                });
                let result = tokio::runtime::Handle::current().block_on(async {
                    // A removed recovery hook completes early. Keep running the
                    // real operation and cleanup before the named detector.
                    let mut early = None;
                    let deadline = tokio::time::Instant::from_std(deadline);
                    let ready = tokio::time::timeout_at(deadline, async {
                        tokio::select! {
                            value = &mut arrived_rx => value.ok(),
                            value = &mut finished_rx => {
                                early = Some(value.unwrap());
                                None
                            },
                        }
                    })
                    .await
                    .ok()
                    .flatten();
                    let (result, (checkpoint, released_in_time, settled)) = tokio::join!(
                        async {
                            let result = stores[leader]
                                .submit_audited_mutation_local(
                                    &alias,
                                    &admission,
                                    joint::caller(&principal),
                                )
                                .await;
                            let mut state = gate.state.lock().unwrap();
                            state.mutation_completed_us =
                                Some(state.micros(tokio::time::Instant::now()));
                            result
                        },
                        async {
                            let ready =
                                tokio::time::timeout_at(deadline, gate.wait_for_all()).await;
                            let checkpoint = ready.map(|()| {
                                gate.capture(|wires, allocations| InitialCalls {
                                    // All eight genuine calls exist first. Let
                                    // four form quorum while retaining four of
                                    // those exact original invocations.
                                    held: wires
                                        .iter()
                                        .rev()
                                        .take(HELD_TAILS)
                                        .map(|wire| wire.target)
                                        .collect(),
                                    wires,
                                    allocations,
                                })
                            });
                            if let Ok(checkpoint) = &checkpoint {
                                gate.retain_targets(checkpoint.held.clone());
                            } else {
                                gate.release();
                                encoder_gate.open();
                            }
                            let released_in_time = tokio::time::Instant::now() < deadline
                                && !encoder_gate.expired.load(Ordering::SeqCst);
                            // Join captured responses while the mutation runs.
                            // The native LedgerWrite callback still releases the
                            // retained original tails; no fresh timeout is added.
                            let settled = match &checkpoint {
                                Ok(checkpoint) => gate.settle(&checkpoint.wires).await,
                                Err(_) => false,
                            };
                            (checkpoint, released_in_time, settled)
                        },
                    );
                    // Failure still releases controls and joins original
                    // work before any measurement assertion.
                    gate.release();
                    encoder_gate.open();
                    let recovery = match early {
                        Some(value) => value,
                        None => finished_rx.await.unwrap(),
                    }
                    .unwrap();
                    let after_return = working.with_current_capture(|capture| capture.sample());
                    (
                        result,
                        checkpoint,
                        ready,
                        recovery,
                        after_return,
                        released_in_time,
                        settled,
                    )
                });
                gate.release();
                encoder_gate.open();
                encoder.join().unwrap();
                result
            })
        });
    let caller_recovery_bytes = recovery.capacity();
    let decoded = opc_persist::audit_authority::PreparedAuditedMutation::decode(&recovery).unwrap();
    assert!(decoded == prepared, "the exact original recovery encoding");
    assert!(decoded.handle() == &handle);
    drop(decoded);
    drop(enrollment);
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
    let committed = databases.each_ref().map(|path| effect_counts(path));
    for store in &stores {
        assert_exhausted(store);
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
    assert!(stores.iter().all(|store| {
        let status = store.status();
        status.admitted && status.leader_id == Some(leader_id)
    }));
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        committed
    );
    assert!(!recovery.is_empty());
    drop(preparation_owners);
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
    let completion_diagnostics = completion_registration.finish();
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
    let native_drained = native_registration.snapshot();
    native_registration.detach();
    let native_detached = native_registration.snapshot();
    drop(native_registration);
    let working_drained = working.with_current_capture(|capture| capture.sample());
    drop(registration);
    let working_detached = working.with_current_capture(|capture| capture.sample());
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        committed
    );
    println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_LIFECYCLE members=9 prepared=72 original_calls=8 remote_quorum_successes=4 held_rpc_tails=4 audited_commits=1 exact_readback=true original_handle=true original_paths=true joined_shutdown=true actual_encoder_joined=true caller_recovery_bytes={caller_recovery_bytes} full_memory_bound=false");
    gate.print_diagnostics(shutdown_entered_us);
    native.print_diagnostics();
    if let Some(snapshot) = &completion_diagnostics {
        println!("CONFIG_CAPACITY_NINE_NATIVE_COMPLETION_METADATA present=true events={} omitted={} cutoff_us={} origin=gate_arm diagnostic_only=true", snapshot.events.len(), snapshot.omitted, snapshot.cutoff_us);
        for event in &snapshot.events {
            println!("CONFIG_CAPACITY_NINE_NATIVE_COMPLETION_PHASE phase={:?} at_us={} index={:?} deadline_us={:?} origin=gate_arm diagnostic_only=true", event.phase, event.at_us, event.index, event.deadline_us);
        }
    } else {
        println!(
            "CONFIG_CAPACITY_NINE_NATIVE_COMPLETION_METADATA present=false diagnostic_only=true"
        );
    }
    assert!(gate.drained());
    assert!(drained.calls.is_empty() && drained.origins.is_empty() && drained.issues.complete());
    assert!(detached.calls.is_empty() && detached.origins.is_empty() && detached.issues.complete());
    assert_eq!(detached.registrations, 0);
    assert!(!encryption_drained.overflowed);
    assert_eq!(encryption_drained.allocations(), 0);
    assert!(working_drained.owners.is_empty() && working_drained.bytes == 0);
    assert!(working_drained.issues.complete());
    assert_eq!(working_drained.recovery_enrollments, 0);
    assert!(working_detached.owners.is_empty() && working_detached.bytes == 0);
    assert!(working_detached.issues.complete());
    assert_eq!(working_detached.registrations, 0);
    assert!(native_drained.registered && !native_detached.registered);
    assert_eq!(native_drained.native_scopes, 0);
    assert_eq!(native_drained.transport_scopes, 0);
    assert_eq!(native_drained.append_scopes, 0);
    assert_eq!(preparations.snapshot().registrations, 0);
    let initial = checkpoint.expect("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_BARRIER_RED");
    assert_eq!(initial.wires.len(), MEMBERS - 1);
    assert_eq!(initial.allocations, MEMBERS - 1);
    assert_eq!(initial.held.len(), HELD_TAILS);
    let completed = gate.state.lock().unwrap().completed.clone();
    assert_eq!(
        completed.len(),
        MEMBERS - 1,
        "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_COMPLETION_RED"
    );
    assert!(initial.wires.iter().all(|wire| completed.get(&wire.call) == Some(&true)),
    "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_COMPLETION_RED: every captured original receives its own native success");
    assert!(gate.completed_in_time(&initial.wires),
        "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_DEADLINE_RED: every original response obeys its own deadline");
    assert!(
        settled,
        "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_DEADLINE_RED: original deadlines"
    );
    println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_ORIGINAL_CALLS original_calls=8 native_successes=8 joined_shutdown=true retries_substituted=false");
    assert!(released_in_time && !encoder_gate.expired.load(Ordering::SeqCst));
    let ready = ready.expect("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_RECOVERY_RED: actual post-writer, pre-handoff recovery output");
    assert_eq!(after_return.caller_transfers, 1);
    assert!(after_return.owners.is_empty() && after_return.bytes == 0);
    assert!(after_return.issues.complete());
    let results = native.results.lock().unwrap();
    assert_eq!(
        results.missing_views, 0,
        "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_VIEW_RED"
    );
    assert!(!results.request_changed);
    let request = results.request.expect("selected native append request");
    for (index, checkpoint) in results.samples.iter().enumerate() {
        let checkpoint = checkpoint
            .as_ref()
            .expect("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_STAGE_RED");
        let sample = checkpoint.native;
        assert!(results.counts[index] > 0);
        if let AuditHistory::PublicOperationLimit = history {
            super::public_history::assert_native_shape(sample, results.counts[index]);
        }
        assert_eq!(sample.source, leader_id);
        assert_eq!(
            sample.preparations.registrations,
            MEMBERS * PREPARATIONS + 1
        );
        assert_eq!(sample.preparations.commands, MEMBERS * PREPARATIONS);
        assert_eq!(sample.node_prepared_commands, PREPARATIONS);
        assert!(sample.native_command_bytes > BOUNDED_LOGICAL_BYTES);
        assert!(sample.native_ledger_bytes > 0);
        assert!(sample.native_is_distinct);
        assert_eq!(
            checkpoint.wires.len(),
            HELD_TAILS,
            "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_WIRES_RED"
        );
        assert_eq!(checkpoint.wire_allocations, HELD_TAILS);
        let targets: BTreeSet<_> = checkpoint.wires.iter().map(|wire| wire.target).collect();
        assert_eq!(targets, initial.held);
        assert_eq!(
            checkpoint.successful_quorum_calls.len(),
            HELD_TAILS,
            "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_QUORUM_RED"
        );
        assert!(checkpoint.successful_quorum_calls.iter().all(|call| {
            initial.wires.iter().any(|wire| wire.call == *call && !initial.held.contains(&wire.target))
        }), "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_QUORUM_RED: the other four captured originals supplied native success");
        for wire in &checkpoint.wires {
            assert!(initial
                .wires
                .iter()
                .any(|original| original.call == wire.call
                    && original.target == wire.target
                    && original.generation == wire.generation
                    && original.bytes == wire.bytes));
            assert!(
                checkpoint.raft.origins.iter().any(|origin| {
                    origin.identity == manifest.consensus_identity()
                        && origin.source == leader_id
                        && origin.target == wire.target
                        && Some(origin.generation) == wire.generation
                        && origin.entries == 1
                        && origin.attribution.len() == 1
                        && origin.attribution[0].request == Some(request)
                        && origin.attribution[0].supported
                }),
                "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_ORIGIN_RED"
            );
        }
        assert!(checkpoint.working.issues.complete());
        assert!(checkpoint.working_union.issues.complete());
        assert!(checkpoint.raft.issues.complete() && checkpoint.joined.issues.complete());
        assert_eq!(checkpoint.working_union.source, leader_id);
        assert_eq!(
            checkpoint.working_union.identity,
            manifest.consensus_identity()
        );
        assert_eq!(
            checkpoint.working_union.native_bytes,
            sample.node_mutation_bytes
        );
        assert_eq!(
            checkpoint.joined.native_bytes,
            checkpoint.working_union.union_bytes
        );
        assert_eq!(checkpoint.joined.source, leader_id);
        assert_eq!(checkpoint.joined.identity, manifest.consensus_identity());
        let outputs: Vec<_> = checkpoint
            .working
            .owners
            .iter()
            .filter(|owner| owner.kind == WorkingBufferKind::RecoveryOutput)
            .collect();
        assert_eq!(
            outputs.len(),
            1,
            "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_RECOVERY_RED"
        );
        let output = outputs[0];
        assert_eq!(output.generation, ready.generation);
        assert_eq!(output.identity, manifest.consensus_identity());
        assert_eq!(output.source, leader_id);
        assert_eq!(output.request, None);
        assert_eq!(output.bytes, caller_recovery_bytes);
        assert_eq!(checkpoint.working.recovery_enrollments, 1);
        assert_eq!(checkpoint.working.caller_transfers, 0);
        assert!(checkpoint.working.owners.iter().all(|owner| {
            owner.identity == manifest.consensus_identity()
                && owner.source == leader_id
                && (owner.kind == WorkingBufferKind::RecoveryOutput
                    || owner.request == Some(request))
        }));
        assert!(!checkpoint.encryption.overflowed);
        assert_eq!(checkpoint.encryption.allocations(), 1);
        let encrypted = checkpoint
            .encryption
            .buffers
            .iter()
            .flatten()
            .next()
            .unwrap();
        assert_eq!(encrypted.kind, BufferKind::EnvelopeArc);
        assert_eq!(encrypted.identity, envelope_identity);
        assert_eq!(encrypted.capacity, envelope_length);
        assert_eq!(encrypted.aliases, 1);
        let wire_bytes: usize = checkpoint.wires.iter().map(|wire| wire.bytes).sum();
        let working_added = checkpoint
            .working_union
            .union_bytes
            .checked_sub(sample.node_mutation_bytes)
            .unwrap();
        let raft_added = checkpoint
            .joined
            .union_bytes
            .checked_sub(checkpoint.working_union.union_bytes)
            .unwrap();
        let envelope_layout = arc_slice_requested_bytes(envelope_length);
        let selected = sample
            .selected_mutation_bytes
            .checked_add(working_added)
            .unwrap()
            .checked_add(raft_added)
            .unwrap()
            .checked_add(wire_bytes)
            .unwrap()
            .checked_add(envelope_layout)
            .unwrap();
        let node = checkpoint
            .joined
            .union_bytes
            .checked_add(wire_bytes)
            .unwrap()
            .checked_add(envelope_layout)
            .unwrap();
        println!("CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_CHECKPOINT stage={:?} native={sample:?} working={:?} joined={:?} held_rpc_tails=4 sdk_recovery_bytes={} wire_bytes={wire_bytes} envelope_requested_layout={envelope_layout} selected_partial_bytes={selected} node_partial_bytes={node} same_instant=true same_original_calls=true snapshot=false outer_frames_separate=true full_memory_bound=false", sample.stage, checkpoint.working_union, checkpoint.joined, output.bytes);
        assert!(
            selected <= WORKING_BYTES,
            "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_WORKING_RED"
        );
        assert!(
            node <= PREPARATIONS * WORKING_BYTES,
            "CONFIG_CAPACITY_NINE_NATIVE_FOUR_TAIL_NODE_RED"
        );
    }
}

native_case!(
    config_capacity_957_nine_native_four_rpc_recovery_checkpoint,
    { run(AuditHistory::Small).await }
);
