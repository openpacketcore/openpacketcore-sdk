//! Actual SDK recovery output overlapping the original eight authenticated calls.
//!
//! This checkpoint joins real preparation and encoder allocations with live
//! outgoing postcard buffers and the original envelope. Retired typed Raft
//! requests contribute provenance, never current ownership.
//! Outer transport/TLS buffers, native SQL rows and engine-internal owners are
//! separate obligations; this does not establish a complete 32/256 MiB bound.

use super::*;
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

struct RecoveryCheckpoint {
    fanout: Checkpoint,
    staging: WorkingBufferSample,
    selected: WorkingBufferUnion,
}

native_case!(config_capacity_957_nine_live_recovery_fanout_checkpoint, {
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
    overlap::ready(&stores, None, "recovery_fanout").await;
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
    gate.arm(leader_id);
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
                                // Lock order: borrowed native preparation,
                                // working census, live wire gate, Raft census,
                                // encryption census. Callbacks only read numbers;
                                // none reenters an already-held census. TLS and
                                // outer transport frames are outside this slice.
                                with_audited_allocations(leader_id, &prepared, |owners| {
                                    working.with_current_capture(|capture| {
                                        let staging = capture.sample();
                                        capture.with_joined(&owners, |selected, joined| {
                                            gate.capture(|wires, wire_allocations| {
                                                raft.with_current_capture(|raft| {
                                                    encryption.capture(|encrypted| {
                                                        RecoveryCheckpoint {
                                                            fanout: Checkpoint {
                                                                wires,
                                                                wire_allocations,
                                                                original: raft.sample(),
                                                                selected: raft.join(&joined),
                                                                encryption: *encrypted,
                                                                envelope_identity:
                                                                    AllocationIdentity::of(
                                                                        envelope.encoded(),
                                                                    ),
                                                                envelope_length: envelope
                                                                    .encoded()
                                                                    .len(),
                                                            },
                                                            staging,
                                                            selected,
                                                        }
                                                    })
                                                })
                                            })
                                        })
                                    })
                                })
                                .expect("original bounded audited preparation")
                            });
                            let released_in_time = tokio::time::Instant::now() < deadline
                                && !encoder_gate.expired.load(Ordering::SeqCst);
                            gate.release();
                            encoder_gate.open();
                            // Settle the captured originals concurrently with the
                            // mutation, inside each original response deadline.
                            let settled = match &checkpoint {
                                Ok(checkpoint) => gate.settle(&checkpoint.fanout.wires).await,
                                Err(_) => false,
                            };
                            (checkpoint, released_in_time, settled)
                        },
                    );
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
    let working_drained = working.with_current_capture(|capture| capture.sample());
    drop(registration);
    let working_detached = working.with_current_capture(|capture| capture.sample());
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        committed
    );
    println!("CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_LIFECYCLE members=9 prepared=72 remote_targets=8 audited_commits=1 exact_readback=true original_handle=true original_paths=true joined_shutdown=true actual_encoder_joined=true caller_recovery_bytes={caller_recovery_bytes} full_memory_bound=false");
    gate.print_diagnostics(shutdown_entered_us);
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
    let recovery_checkpoint = checkpoint.expect("CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_BARRIER_RED: all original calls coexist inside their original deadline");
    let checkpoint = &recovery_checkpoint.fanout;
    assert_eq!(checkpoint.wires.len(), MEMBERS - 1);
    let completed = gate.state.lock().unwrap().completed.clone();
    assert_eq!(
        completed.len(),
        MEMBERS - 1,
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_GENERATION_COMPLETION_RED"
    );
    assert!(checkpoint.wires.iter().all(|wire| completed.get(&wire.call) == Some(&true)),
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_GENERATION_COMPLETION_RED: every captured original call receives its own native success");
    assert!(gate.completed_in_time(&checkpoint.wires),
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_DEADLINE_RED: every original response obeys its own deadline");
    assert!(settled,
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_DEADLINE_RED: captured calls joined inside original deadlines");
    println!("CONFIG_CAPACITY_NINE_RECOVERY_ORIGINAL_CALLS original_calls=8 native_successes=8 joined_shutdown=true retries_substituted=false");
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
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_ORIGIN_RED"
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
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_ENVELOPE_RED"
    );
    let encrypted: Vec<_> = checkpoint.encryption.buffers.iter().flatten().collect();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].kind, BufferKind::EnvelopeArc);
    assert_eq!(encrypted[0].identity, checkpoint.envelope_identity);
    assert_eq!(encrypted[0].capacity, checkpoint.envelope_length);
    assert_eq!(encrypted[0].aliases, 1);
    let outputs: Vec<_> = recovery_checkpoint
        .staging
        .owners
        .iter()
        .filter(|owner| owner.kind == WorkingBufferKind::RecoveryOutput)
        .collect();
    assert_eq!(outputs.len(), 1,
        "CONFIG_CAPACITY_NINE_RECOVERY_OWNER_RED: the actual SDK recovery Vec must coexist with all eight original wires");
    let output = outputs[0];
    let ready = ready.expect("actual post-writer, pre-handoff encoder checkpoint");
    assert_eq!(ready.generation, output.generation);
    assert_eq!(output.identity, manifest.consensus_identity());
    assert_eq!(output.source, leader_id);
    assert_eq!(output.request, None);
    assert_eq!(output.bytes, caller_recovery_bytes);
    assert!(output.bytes > BOUNDED_LOGICAL_BYTES);
    assert!(released_in_time && !encoder_gate.expired.load(Ordering::SeqCst));
    assert!(recovery_checkpoint.staging.issues.complete());
    assert_eq!(recovery_checkpoint.staging.recovery_enrollments, 1);
    assert_eq!(recovery_checkpoint.staging.caller_transfers, 0);
    assert_eq!(recovery_checkpoint.selected.source, leader_id);
    assert_eq!(
        recovery_checkpoint.selected.identity,
        manifest.consensus_identity()
    );
    assert!(recovery_checkpoint.selected.issues.complete());
    assert!(recovery_checkpoint.selected.working_bytes >= output.bytes);
    assert!(recovery_checkpoint.selected.native_bytes > BOUNDED_LOGICAL_BYTES);
    assert_eq!(after_return.caller_transfers, 1);
    assert!(after_return.owners.is_empty() && after_return.bytes == 0);
    assert!(after_return.issues.complete());
    assert_eq!(
        checkpoint.selected.native_bytes,
        recovery_checkpoint.selected.union_bytes
    );
    let envelope_data = checkpoint.encryption.data_capacity();
    let envelope_layout = arc_slice_requested_bytes(checkpoint.envelope_length);
    let working = checkpoint
        .selected
        .union_bytes
        .checked_add(postcard_bytes)
        .unwrap()
        .checked_add(envelope_layout)
        .unwrap();
    println!("CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_CHECKPOINT staging={:?} selected={:?} sdk_recovery_bytes={} postcard_bytes={postcard_bytes} envelope_data={envelope_data} envelope_requested_layout={envelope_layout} working_bytes={working} operation_bound={WORKING_BYTES} caller_recovery_bytes={caller_recovery_bytes} caller_recovery_in_working=false envelope_reservation_retained=true snapshot=false outer_frames_separate=true sdk_recovery_in_working=true native_sql_row=false full_memory_bound=false", recovery_checkpoint.selected, checkpoint.selected, output.bytes);
    assert!(working <= WORKING_BYTES, "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_WORKING_RED: admitted original mutation owners exceed reservation");
    assert_eq!(
        checkpoint.selected.calls, 0,
        "CONFIG_CAPACITY_NINE_RECOVERY_FANOUT_TYPED_RETIREMENT_RED"
    );
    assert_eq!(checkpoint.selected.original_bytes, 0);
    assert!(checkpoint.original.calls.is_empty());
});
