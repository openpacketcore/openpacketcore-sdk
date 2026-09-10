//! Async and USER129 volatile measurements of the original SDK-702 workload.
//!
//! Both entries retain the original workload, deadlines, tails and resources.
//! Public Async uses ordinary construction and mode-aware readiness. The
//! earlier volatile experiment retains its explicit test-control activation.
//! Neither entry supplies the durable release test's all-cold attestation.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScalePersistence {
    VolatileExperiment,
    Async,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScaleWorkload {
    Original,
    PreloadDiagnostic,
}

impl ScalePersistence {
    fn label(self) -> &'static str {
        match self {
            Self::VolatileExperiment => "volatile",
            Self::Async => "async",
        }
    }

    fn evidence_mode(self) -> &'static str {
        match self {
            Self::VolatileExperiment => {
                "explicit_volatile_original_scale_not_durable_qualification"
            }
            Self::Async => "public_async_original_scale_not_durable_qualification",
        }
    }

    async fn ready_leader(self, stores: &[ConsensusSessionStore]) -> usize {
        if self == Self::VolatileExperiment {
            return ready_leader(stores).await;
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let readiness = futures_util::future::join_all(
                    stores
                        .iter()
                        .map(ConsensusSessionStore::probe_fixed_quorum_readiness),
                )
                .await;
                let statuses = stores
                    .iter()
                    .map(ConsensusSessionStore::status)
                    .collect::<Vec<_>>();
                if readiness
                    .iter()
                    .all(|report| report.traffic_authority().is_granted())
                    && statuses.iter().all(|status| status.admitted)
                    && statuses
                        .first()
                        .and_then(|status| status.leader_id)
                        .is_some_and(|leader| {
                            statuses
                                .iter()
                                .all(|status| status.leader_id == Some(leader))
                        })
                {
                    let leader = statuses[0].leader_id.expect("known fixed-quorum leader");
                    return statuses
                        .iter()
                        .position(|status| status.node_id == leader)
                        .expect("leader is an exact fixed voter");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixed quorum reaches public Async readiness and elects a leader")
    }
}

fn voter_persistence_observations(stores: &[ConsensusSessionStore]) -> Vec<serde_json::Value> {
    stores
        .iter()
        .map(|store| {
            let engine = consensus_local_durable_progress_for_test(store);
            serde_json::json!({
                "health": store.persistence_health(),
                "engine_state": format!("{:?}", engine.engine_state),
                "storage_error_subject": engine.storage_error_subject.map(|value| format!("{value:?}")),
                "storage_error_verb": engine.storage_error_verb.map(|value| format!("{value:?}")),
                "last_log_index": engine.last_log_index,
                "applied_index": engine.applied_index,
                "snapshot_index": engine.snapshot_index,
                "purged_index": engine.purged_index,
            })
        })
        .collect()
}

fn volatile_voter_costs(stores: &[ConsensusSessionStore]) -> Vec<serde_json::Value> {
    stores
        .iter()
        .map(|store| {
            opc_session_store::test_support::consensus_local_wal_costs_for_test(store)
                .expect("volatile native voter observations")
                .expect("volatile native voter has a WAL owner")
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "USER129 original 1,010,000-operation volatile performance measurement"]
async fn original_workload_preserves_rates_tails_and_limits() {
    assert_eq!(
        std::env::var_os("OPC_SESSION_VOLATILE_PERFORMANCE_EXPERIMENT").as_deref(),
        Some(std::ffi::OsStr::new("1")),
        "original volatile scale requires explicit experimental activation",
    );
    run_original_scale(
        ScalePersistence::VolatileExperiment,
        ScaleWorkload::Original,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "public Async original 1,010,000-operation performance qualification"]
async fn public_async_original_workload_preserves_rates_tails_and_limits() {
    assert_eq!(
        std::env::var_os("OPC_SESSION_ASYNC_PERFORMANCE_QUALIFICATION").as_deref(),
        Some(std::ffi::OsStr::new("required")),
        "public Async scale requires its explicit qualification controller",
    );
    assert!(std::env::var_os("OPC_SESSION_VOLATILE_PERFORMANCE_EXPERIMENT").is_none());
    run_original_scale(ScalePersistence::Async, ScaleWorkload::Original).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "public Async bounded reproduction of the original 50,000-operation preload"]
async fn public_async_original_preload_diagnostic() {
    assert_eq!(
        std::env::var_os("OPC_SESSION_ASYNC_PRELOAD_DIAGNOSTIC").as_deref(),
        Some(std::ffi::OsStr::new("required")),
        "preload diagnosis requires its explicit controller",
    );
    assert!(std::env::var_os("OPC_SESSION_VOLATILE_PERFORMANCE_EXPERIMENT").is_none());
    run_original_scale(ScalePersistence::Async, ScaleWorkload::PreloadDiagnostic).await;
}

#[allow(clippy::assertions_on_constants)]
async fn run_original_scale(persistence: ScalePersistence, workload: ScaleWorkload) {
    let mode_label = persistence.label();
    let build_profile = require_release_qualification_profile();
    let quiet_host_monitor =
        QualificationQuietHostMonitor::start().expect("quiet host before original volatile scale");
    let started = Instant::now();
    let directory = tempfile::tempdir().expect("original volatile scale directory");
    let snapshot_root = std::fs::canonicalize(
        std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV)
            .expect("original volatile scale requires its explicit fs-verity snapshot root"),
    )
    .expect("canonical original volatile scale fs-verity root");
    assert_ne!(
        std::fs::metadata(directory.path())
            .expect("mutable scale filesystem")
            .dev(),
        std::fs::metadata(&snapshot_root)
            .expect("snapshot scale filesystem")
            .dev(),
        "mutable storage must remain separate from the fs-verity filesystem",
    );
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("SDK-702 release qualification start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, database_paths, snapshot_paths, peer_slots) = match persistence {
        ScalePersistence::VolatileExperiment => {
            fixed_cluster_with_snapshot_root(directory.path(), &snapshot_root, clock.clone()).await
        }
        ScalePersistence::Async => {
            fixed_cluster_with_snapshot_integrity_and_persistence(
                directory.path(),
                &snapshot_root,
                clock.clone(),
                opc_session_store::SnapshotIntegrityPolicy::FsVerity,
                opc_session_store::SessionPersistenceMode::Async,
            )
            .await
        }
    };
    if persistence == ScalePersistence::VolatileExperiment {
        for store in &stores {
            opc_session_store::test_support::enable_volatile_memory_performance_experiment_for_test(
                store,
            )
            .expect("enable original volatile scale voter");
        }
    } else {
        assert!(stores.iter().all(|store| {
            store.persistence_mode() == opc_session_store::SessionPersistenceMode::Async
        }));
    }
    eprintln!("sdk-741 {mode_label} original scale activation: durability=waived real_quorum=true real_apply=true background_coalesced_native_generations=true original_snapshot_policy=true cold_restart_qualification=false");
    let provider = sealing_provider();
    let transient_retries = Arc::new(AtomicU64::new(0));
    // Keep every permitted retry in a causally distinct ledger: immutable
    // application observations, maintenance readback reconciliation, and
    // backend-proved non-transmitted effects. The serialized aggregate is
    // checked against these three exact components before publication.
    let maintenance_reconciliation_retries = AtomicU64::new(0);
    let effect_counters = Arc::new(ReleaseEffectCounters::default());
    let lifecycle_counters = Arc::new(ReleaseLifecycleMutationCounters::default());
    let production_maintenance_counters = ProductionMaintenanceCounters::default();
    let matched_workload_outcomes = Arc::new(AtomicU64::new(0));
    let first_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");
    // Observe only after an original operation has failed. These scalar
    // diagnostics neither dispatch another mutation nor extend its deadline.
    let report_preload_failure = |stage: &str, chunk_start: usize, chunk_end: usize| {
        eprintln!(
            "sdk-741 {mode_label} original scale preload failure: {}",
            serde_json::json!({
                "mode": persistence.evidence_mode(),
                "workload": format!("{workload:?}"),
                "phase": "preload", "stage": stage,
                "chunk_start": chunk_start, "chunk_end_exclusive": chunk_end,
                "total_exact_outcomes": matched_workload_outcomes.load(Ordering::Relaxed),
                "elapsed_ms": started.elapsed().as_millis(),
                "effect_counters": effect_counters.snapshot(),
                "read_backend_unavailable_retries": transient_retries.load(Ordering::Relaxed),
                "voter_status": stores.iter().map(|store| format!("{:?}", store.status())).collect::<Vec<_>>(),
                "voter_diagnostics": stores.iter().map(|store| format!("{:?}", store.diagnostic_snapshot())).collect::<Vec<_>>(),
                "voter_wal_costs": stores.iter().map(|store| {
                    match opc_session_store::test_support::consensus_local_wal_costs_for_test(store) {
                        Ok(costs) => serde_json::json!(costs),
                        Err(_) => serde_json::json!({"observation_unavailable": true}),
                    }
                }).collect::<Vec<_>>(),
                "voter_persistence": voter_persistence_observations(&stores),
                "peak_rss_kib": process_peak_rss_kib(),
            })
        );
    };

    assert_eq!(
        QUALIFICATION_RELEASE_TRANSITIONS, 1_010_000,
        "the release envelope is 50k + (500/s * 30m) + (1k/s * 60s)"
    );
    assert_eq!(FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS, 1);
    assert_eq!(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, 7);
    assert_eq!(
        FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            * (FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS + FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS),
        "the public fixed resource contract must remain exactly eight epochs"
    );

    // The first V2 effect is deliberately singleton activation.  Every later
    // preload create is submitted through the public bounded coalescing API;
    // no receipt, database, or private-apply shortcut exists in this path.
    // Keep the original request/outcome as an attestation exemplar for each
    // epoch; later updates exercise independent lease renewal paths.
    // Readiness and leader discovery are phase setup, not application traffic.
    // Keep one public ingress: its normal forwarding path follows any later
    // leader change without adding three fresh read barriers to every batch.
    let leader = persistence.ready_leader(&stores).await;
    let ingress_store = &stores[leader];
    let first_key = key(0);
    let first_observation = retry_exact_consensus_operation(&transient_retries, || {
        ingress_store.observe_fenced_transition(&first_key)
    })
    .await
    .inspect_err(|_| report_preload_failure("singleton_fence_observation", 0, 1))
    .expect("singleton activation fence observation");
    let first_request = create_request(
        0,
        first_epoch,
        first_key,
        first_observation.current_fence(),
        &provider,
    )
    .await;
    let first_outcome = execute_release_store_batch(
        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
        ingress_store,
        vec![first_request.clone()],
        &effect_counters,
    )
    .await
    .inspect_err(|failure| report_preload_failure(failure.stage.as_str(), 0, 1))
    .expect("singleton V2 activation effect must converge")
    .into_iter()
    .next()
    .expect("singleton V2 activation has one result")
    .expect("singleton V2 activation");
    assert_exact_qualified_v2_success(&first_request, &first_outcome);
    matched_workload_outcomes.fetch_add(1, Ordering::Relaxed);
    let mut sessions = vec![(first_request, first_outcome)];
    for chunk_start in (1..QUALIFICATION_SESSIONS).step_by(QUALIFICATION_PRELOAD_BATCH_OPERATIONS) {
        let chunk_end =
            (chunk_start + QUALIFICATION_PRELOAD_BATCH_OPERATIONS).min(QUALIFICATION_SESSIONS);
        let mut requests = Vec::with_capacity(chunk_end - chunk_start);
        for session_index in chunk_start..chunk_end {
            let session_key = key(session_index);
            let observation = retry_exact_consensus_operation(&transient_retries, || {
                ingress_store.observe_fenced_transition(&session_key)
            })
            .await
            .inspect_err(|_| {
                report_preload_failure("preload_fence_observation", chunk_start, chunk_end)
            })
            .expect("preload batch fence observation");
            requests.push(
                create_request(
                    session_index,
                    first_epoch,
                    session_key,
                    observation.current_fence(),
                    &provider,
                )
                .await,
            );
        }
        let outcomes = execute_release_store_batch(
            Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
            ingress_store,
            requests.clone(),
            &effect_counters,
        )
        .await
        .inspect_err(|failure| {
            report_preload_failure(failure.stage.as_str(), chunk_start, chunk_end)
        })
        .expect("preload bounded V2 batch effect must converge");
        assert_eq!(outcomes.len(), requests.len());
        for (request, outcome) in requests.into_iter().zip(outcomes) {
            let outcome = outcome.expect("preload item result");
            assert_exact_qualified_v2_success(&request, &outcome);
            matched_workload_outcomes.fetch_add(1, Ordering::Relaxed);
            sessions.push((request, outcome));
        }
        if workload == ScaleWorkload::PreloadDiagnostic && chunk_start / 4096 != chunk_end / 4096 {
            eprintln!(
                "sdk-741 public async preload diagnostic progress: {}",
                serde_json::json!({
                    "total_exact_outcomes": matched_workload_outcomes.load(Ordering::Relaxed),
                    "elapsed_ms": started.elapsed().as_millis(),
                    "voter_persistence": voter_persistence_observations(&stores),
                })
            );
        }
    }
    assert_eq!(sessions.len(), QUALIFICATION_SESSIONS);
    if workload == ScaleWorkload::PreloadDiagnostic {
        assert_eq!(
            matched_workload_outcomes.load(Ordering::Relaxed),
            QUALIFICATION_SESSIONS as u64,
        );
        eprintln!("sdk-741 public async preload diagnostic: all {QUALIFICATION_SESSIONS} exact preload results matched; beginning owned shutdown");
        let persistence_observations = voter_persistence_observations(&stores);
        let costs = volatile_voter_costs(&stores);
        let effect_snapshot = effect_counters.snapshot();
        let elapsed_ms = started.elapsed().as_millis();
        shutdown_fixed_cluster(&stores, &peer_slots).await;
        drop(stores);
        drop(peer_slots);
        let quiet_host = quiet_host_monitor
            .finish()
            .expect("original preload diagnostic quiet-host interval");
        eprintln!(
            "sdk-741 public async preload diagnostic summary: {}",
            serde_json::json!({
                "mode": "public_async_original_preload_diagnostic_not_performance_qualification",
                "total_exact_outcomes": matched_workload_outcomes.load(Ordering::Relaxed),
                "preload_operations": QUALIFICATION_SESSIONS,
                "batch_deadline_ms": QUALIFICATION_RELEASE_BATCH_DEADLINE.as_millis(),
                "preload_elapsed_ms": elapsed_ms,
                "effect_counters": effect_snapshot,
                "read_backend_unavailable_retries": transient_retries.load(Ordering::Relaxed),
                "voter_persistence_before_shutdown": persistence_observations,
                "voter_wal_costs_before_shutdown": costs,
                "peak_rss_kib": process_peak_rss_kib(), "quiet_host": quiet_host,
                "performance_qualified": false, "cold_restart_qualification": false,
            })
        );
        assert_eq!(transient_retries.load(Ordering::Relaxed), 0);
        assert_eq!(effect_snapshot.not_transmitted_retries, 0);
        assert_eq!(effect_snapshot.outcome_unknown_batches, 0);
        assert_eq!(effect_snapshot.resolved_after_deadline, 0);
        return;
    }
    let mut representatives = vec![sessions[0].clone()];
    let mut active_epoch = first_epoch;
    let mut active_entries = QUALIFICATION_SESSIONS;
    let mut nonce = QUALIFICATION_SESSIONS;
    let mut rotations = 0usize;
    let mut phase_evidence = Vec::with_capacity(2);

    // Keep exactly 50,000 representative sessions in memory. The retained
    // receipt resource itself is bounded by the public eight-epoch contract
    // asserted above, not by this test-side cache.
    for (phase_name, target_rate, operations) in [
        (
            "sustained-500-per-second",
            QUALIFICATION_SUSTAINED_RATE,
            QUALIFICATION_SUSTAINED_TRANSITIONS,
        ),
        (
            "burst-1000-per-second",
            QUALIFICATION_BURST_RATE,
            QUALIFICATION_BURST_TRANSITIONS,
        ),
    ] {
        let phase_started = Instant::now();
        let mut latency = ReleaseLatencySamples::default();
        let mut submitted = 0usize;
        let mut completed = 0usize;
        let mut in_flight: JoinSet<Result<ReleaseBatchCompletion, ReleaseBatchFailure>> =
            JoinSet::new();
        let mut in_flight_session_slots = BTreeSet::new();
        // `JoinSet::len()` counts submitted batch tasks until they are
        // joined, including a task that has already completed. It bounds
        // outstanding/unjoined client task slots; it is not a measurement of
        // simultaneously executing consensus calls.
        let mut peak_unjoined_batch_task_slots = 0usize;
        while completed < operations {
            if active_entries == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
                assert!(
                    in_flight.is_empty() && in_flight_session_slots.is_empty(),
                    "successor rotation must wait for every exact submitted batch"
                );
                let leader = current_local_maintenance_leader(&stores).await;
                let before = retry_exact_consensus_operation(&transient_retries, || {
                    stores[leader].fenced_transition_v2_history_state()
                })
                .await
                .expect("linearized full active epoch before successor rotation");
                assert_eq!(before.active_epoch(), Some(active_epoch));
                assert_eq!(
                    before.bound_entries(),
                    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                );
                assert!(
                    rotations < FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS,
                    "the 1.01m envelope must require exactly seven successors, never a ninth epoch"
                );
                let after = measure_eventual_lifecycle_mutation(
                    &lifecycle_counters,
                    maintain_exact_history_batch(
                        &stores,
                        before,
                        &maintenance_reconciliation_retries,
                        &production_maintenance_counters,
                        None,
                    ),
                    Result::is_ok,
                )
                .await
                .expect("open bounded successor through local-leader maintenance");
                rotations += 1;
                active_epoch = FencedTransitionV2HistoryEpoch::new(active_epoch.get() + 1)
                    .expect("representable successor epoch");
                assert_eq!(after.active_epoch(), Some(active_epoch));
                assert_eq!(after.retired_through(), None);
                assert_eq!(after.reclaim_epoch(), None);
                assert_eq!(after.bound_entries(), 0);
                active_entries = 0;

                // Every earlier epoch remains publicly attestable and exactly
                // replayable before the 24-hour floor/reclaim boundary.
                for (request, outcome) in &representatives {
                    assert!(matches!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2_status(request)
                        })
                        .await
                        .expect("pre-floor representative status"),
                        FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
                    ));
                    let replay = execute_release_store_batch(
                        Instant::now() + QUALIFICATION_RELEASE_BATCH_DEADLINE,
                        &stores[leader],
                        vec![request.clone()],
                        &effect_counters,
                    )
                    .await
                    .expect("pre-floor exact replay effect must converge")
                    .into_iter()
                    .next()
                    .expect("pre-floor exact replay has one result")
                    .expect("pre-floor exact replay");
                    assert_exact_qualified_v2_success(request, &replay);
                    assert_eq!(replay, *outcome);
                    let changed = request_with_changed_body(request);
                    assert_eq!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2_status(&changed)
                        })
                        .await
                        .expect("pre-floor changed-body status"),
                        FencedTransitionV2Status::RequestConflict
                    );
                }
            }

            let outstanding_entries = in_flight_session_slots.len();
            let remaining_epoch_capacity = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                .checked_sub(active_entries + outstanding_entries)
                .expect("in-flight release batches remain within the active epoch");
            if submitted < operations
                && in_flight.len() < QUALIFICATION_IN_FLIGHT_CLIENTS
                && remaining_epoch_capacity > 0
            {
                let batch_len = QUALIFICATION_PACED_BATCH_OPERATIONS
                    .min(operations - submitted)
                    .min(remaining_epoch_capacity);
                let mut requests = Vec::with_capacity(batch_len);
                let mut session_slots = Vec::with_capacity(batch_len);
                let mut scheduled_at = Vec::with_capacity(batch_len);
                let successor_first_item = active_entries == 0 && outstanding_entries == 0;
                for batch_offset in 0..batch_len {
                    pace_release_phase(phase_started, submitted + batch_offset, target_rate).await;
                    scheduled_at.push(
                        phase_started
                            + qualification_schedule_offset(submitted + batch_offset, target_rate),
                    );
                    // Every outstanding batch updates disjoint independently
                    // fenced sessions. Its first item after a rotation is
                    // retained as that epoch's exact replay representative.
                    // Physical coalescing never creates an all-or-nothing
                    // multi-key contract or permits two concurrent effects
                    // for one session.
                    let slot = nonce % sessions.len();
                    assert!(
                        in_flight_session_slots.insert(slot),
                        "one session cannot have two release mutations in flight"
                    );
                    let update =
                        renew_update_request(nonce, active_epoch, &sessions[slot].1, &provider)
                            .await;
                    assert_exact_qualified_update_request(&sessions[slot].1, &update);
                    requests.push(update);
                    session_slots.push(slot);
                    nonce += 1;
                }
                let task_ingress_store = (*ingress_store).clone();
                let task_effect_counters = Arc::clone(&effect_counters);
                let batch_started = Instant::now();
                let batch_deadline = batch_started
                    .checked_add(QUALIFICATION_RELEASE_BATCH_DEADLINE)
                    .expect("release batch deadline is representable");
                in_flight.spawn(async move {
                    let outcomes = execute_release_store_batch(
                        batch_deadline,
                        &task_ingress_store,
                        requests.clone(),
                        &task_effect_counters,
                    )
                    .await?;
                    let completed_at = Instant::now();
                    Ok(ReleaseBatchCompletion {
                        requests,
                        outcomes,
                        session_slots,
                        scheduled_at,
                        batch_elapsed: completed_at.duration_since(batch_started),
                        completed_at,
                        successor_first_item,
                    })
                });
                submitted += batch_len;
                peak_unjoined_batch_task_slots =
                    peak_unjoined_batch_task_slots.max(in_flight.len());
                continue;
            }
            let batch_len = match collect_next_release_batch(
                &mut in_flight,
                &mut in_flight_session_slots,
                &mut latency,
                &mut sessions,
                &mut representatives,
                &matched_workload_outcomes,
            )
            .await
            {
                Ok(batch_len) => batch_len,
                Err(failure) => {
                    let voter_status = stores
                        .iter()
                        .map(ConsensusSessionStore::status)
                        .collect::<Vec<_>>();
                    let voter_diagnostics = stores
                        .iter()
                        .map(ConsensusSessionStore::diagnostic_snapshot)
                        .collect::<Vec<_>>();
                    let effect_snapshot = effect_counters.snapshot();
                    eprintln!(
                        "sdk-702 successor failure: phase={phase_name} stage={} submitted={submitted} completed={completed} active_entries={active_entries} in_flight_batches={} in_flight_sessions={} effect_counters={effect_snapshot:?} voter_status={voter_status:?} voter_diagnostics={voter_diagnostics:?}",
                        failure.stage.as_str(),
                        in_flight.len(),
                        in_flight_session_slots.len(),
                    );
                    let tails = (!latency.batch.is_empty()
                        && !latency.item_scheduled_to_completion.is_empty())
                    .then(|| latency.p99_and_p999());
                    eprintln!(
                        "sdk-741 {mode_label} original scale failure: {}",
                        serde_json::json!({
                            "mode": persistence.evidence_mode(),
                            "phase": phase_name, "stage": failure.stage.as_str(),
                            "offered_ops_per_second": target_rate, "submitted_operations": submitted,
                            "completed_operations": completed, "elapsed_ms": phase_started.elapsed().as_millis(),
                            "batch_p99_us": tails.map(|value| value.0.as_micros()), "batch_p999_us": tails.map(|value| value.1.as_micros()),
                            "item_p99_us": tails.map(|value| value.2.as_micros()), "item_p999_us": tails.map(|value| value.3.as_micros()),
                            "effect_counters": effect_snapshot,
                            "voter_wal_costs": volatile_voter_costs(&stores),
                            "voter_persistence": voter_persistence_observations(&stores),
                        })
                    );
                    panic!(
                        "paced bounded V2 batch failed closed at stage {}",
                        failure.stage.as_str()
                    );
                }
            };
            active_entries += batch_len;
            completed += batch_len;
        }
        assert_eq!(submitted, operations);
        assert!(in_flight.is_empty());
        assert!(in_flight_session_slots.is_empty());
        assert!(peak_unjoined_batch_task_slots <= QUALIFICATION_IN_FLIGHT_CLIENTS);
        let elapsed = phase_started.elapsed();
        let batch_samples = latency.batch.len();
        let item_samples = latency.item_scheduled_to_completion.len();
        let (batch_p99, batch_p999, item_p99, item_p999) = latency.p99_and_p999();
        let batch_max = *latency
            .batch
            .last()
            .expect("qualified phase has a batch maximum after percentile sort");
        let item_max = *latency
            .item_scheduled_to_completion
            .last()
            .expect("qualified phase has an item maximum after percentile sort");
        eprintln!(
            "sdk-741 {mode_label} original scale phase: {}",
            serde_json::json!({
                "mode": persistence.evidence_mode(),
                "phase": phase_name, "stage": "completed", "offered_ops_per_second": target_rate,
                "submitted_operations": submitted, "completed_operations": completed,
                "elapsed_ms": elapsed.as_millis(), "batch_samples": batch_samples,
                "item_samples": item_samples, "peak_unjoined_batch_task_slots": peak_unjoined_batch_task_slots,
                "batch_p99_us": batch_p99.as_micros(), "batch_p999_us": batch_p999.as_micros(),
                "item_p99_us": item_p99.as_micros(), "item_p999_us": item_p999.as_micros(),
                "batch_max_us": batch_max.as_micros(), "item_max_us": item_max.as_micros(),
                "read_backend_unavailable_retries": transient_retries.load(Ordering::Relaxed),
                "effect_counters": effect_counters.snapshot(),
                "voter_wal_costs": volatile_voter_costs(&stores),
                "voter_persistence": voter_persistence_observations(&stores),
            })
        );
        assert_qualification_phase_pacing(elapsed, operations as u64, target_rate as u64);
        assert!(item_p99 <= Duration::from_millis(25));
        assert!(item_p999 <= Duration::from_millis(100));
        assert!(
            batch_max <= QUALIFICATION_RELEASE_BATCH_DEADLINE,
            "a qualified batch must not hide a multi-second tail behind percentiles"
        );
        assert!(
            item_max <= QUALIFICATION_RELEASE_BATCH_DEADLINE,
            "a qualified item must not hide a multi-second tail behind percentiles"
        );
        phase_evidence.push(ReleaseEvidencePhase {
            name: phase_name.to_owned(),
            offered_ops_per_second: target_rate as u64,
            operations: operations as u64,
            // Every relevant `Duration` above was compared against its exact
            // bound before this intentionally coarser evidence conversion.
            elapsed_ms: duration_evidence_milliseconds(elapsed, "qualified phase elapsed"),
            batch_samples: batch_samples as u64,
            item_samples: item_samples as u64,
            peak_unjoined_batch_task_slots: peak_unjoined_batch_task_slots as u64,
            batch_p99_us: duration_evidence_microseconds(batch_p99, "qualified batch p99"),
            batch_p999_us: duration_evidence_microseconds(batch_p999, "qualified batch p999"),
            batch_max_us: duration_evidence_microseconds(batch_max, "qualified batch maximum"),
            item_p99_us: duration_evidence_microseconds(item_p99, "qualified item p99"),
            item_p999_us: duration_evidence_microseconds(item_p999, "qualified item p999"),
            item_max_us: duration_evidence_microseconds(item_max, "qualified item maximum"),
        });
    }

    assert_eq!(
        nonce, QUALIFICATION_RELEASE_TRANSITIONS,
        "the paced workload must use exactly its declared 1,010,000 unique V2 IDs"
    );
    assert_eq!(sessions.len(), QUALIFICATION_SESSIONS);
    assert_eq!(
        matched_workload_outcomes.load(Ordering::Relaxed),
        QUALIFICATION_RELEASE_TRANSITIONS as u64,
        "every declared workload result must match its exact request and expected mutation"
    );
    assert_eq!(rotations, 7, "the 1.01m envelope crosses seven successors");
    let leader = persistence.ready_leader(&stores).await;
    let history = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("history after 1.01m real operations");
    assert_eq!(
        history.active_epoch(),
        Some(FencedTransitionV2HistoryEpoch::new(8).expect("epoch 8"))
    );
    assert_eq!(history.retired_through(), None);
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(
        history.bound_entries(),
        QUALIFICATION_RELEASE_TRANSITIONS % FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
    );
    assert_eq!(representatives.len(), 8);

    let statuses = stores
        .iter()
        .map(ConsensusSessionStore::status)
        .collect::<Vec<_>>();
    let before_shutdown_costs = volatile_voter_costs(&stores);
    let before_shutdown_persistence = voter_persistence_observations(&stores);
    if persistence == ScalePersistence::Async {
        for store in &stores {
            let health = store.persistence_health();
            assert!(health.engine_running);
            assert_eq!(
                health.storage_state,
                opc_session_store::SessionStorageState::Running
            );
            assert!(health.storage_failure.is_none());
            assert_eq!(
                health.recovery,
                Some(opc_session_store::SessionAsyncRecoveryState::Active)
            );
            let progress = health
                .asynchronous
                .expect("public Async persistence observation");
            assert!(progress.background_failure.is_none() && !progress.saturated);
            assert!(progress.completed_generation > 0);
        }
    }
    let effect_snapshot = effect_counters.snapshot();
    let read_only_retries = transient_retries.load(Ordering::Relaxed);
    let maintenance_retries = maintenance_reconciliation_retries.load(Ordering::Relaxed);
    shutdown_fixed_cluster(&stores, &peer_slots).await;
    drop(stores);
    drop(peer_slots);
    let database_bytes_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    let peak_rss_kib = process_peak_rss_kib();
    let quiet_host = quiet_host_monitor
        .finish()
        .expect("original volatile scale quiet-host interval");
    let observation = serde_json::json!({
        "mode": persistence.evidence_mode(),
        "cargo_profile_family": build_profile.cargo_profile_family, "cargo_opt_level": build_profile.cargo_opt_level,
        "debug_assertions": build_profile.debug_assertions, "topology_voters": statuses.len(),
        "preload_operations": QUALIFICATION_SESSIONS, "total_exact_outcomes": matched_workload_outcomes.load(Ordering::Relaxed),
        "sustained_operations": QUALIFICATION_SUSTAINED_TRANSITIONS, "sustained_rate_per_second": QUALIFICATION_SUSTAINED_RATE,
        "sustained_seconds": QUALIFICATION_SUSTAINED_SECONDS, "burst_operations": QUALIFICATION_BURST_TRANSITIONS,
        "burst_rate_per_second": QUALIFICATION_BURST_RATE, "burst_seconds": QUALIFICATION_BURST_SECONDS,
        "paced_batch_operations": QUALIFICATION_PACED_BATCH_OPERATIONS, "in_flight_clients": QUALIFICATION_IN_FLIGHT_CLIENTS,
        "batch_deadline_ms": QUALIFICATION_RELEASE_BATCH_DEADLINE.as_millis(),
        "phases": phase_evidence, "successor_rotations": rotations, "elapsed_ms": started.elapsed().as_millis(),
        "completed_snapshot_count_by_voter": statuses.iter().map(|status| status.completed_snapshot_count).collect::<Vec<_>>(),
        "read_backend_unavailable_retries": read_only_retries, "maintenance_reconciliation_retries": maintenance_retries,
        "effect_counters": effect_snapshot, "voter_wal_costs_before_shutdown": before_shutdown_costs,
        "voter_persistence_before_shutdown": before_shutdown_persistence,
        "database_bytes_by_voter": database_bytes_by_voter, "snapshot_bytes_by_voter": snapshot_bytes_by_voter,
        "database_ceiling_bytes_per_voter": QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
        "snapshot_ceiling_bytes_per_voter": QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
        "peak_rss_kib": peak_rss_kib, "process_peak_rss_ceiling_kib": QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "quiet_host": quiet_host, "cold_restart_qualification": false,
    });
    eprintln!("sdk-741 {mode_label} original scale summary: {observation}");
    assert_voter_resource_ceiling(
        "original volatile database family",
        &database_bytes_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "original volatile snapshot directory",
        &snapshot_bytes_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    assert!(
        peak_rss_kib <= QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "three-voter peak RSS {peak_rss_kib} KiB exceeds the original {} KiB ceiling",
        QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB
    );
    assert_eq!(read_only_retries, 0);
    assert_eq!(maintenance_retries, 0);
    assert_eq!(effect_snapshot.not_transmitted_retries, 0);
    assert_eq!(effect_snapshot.outcome_unknown_batches, 0);
    assert_eq!(effect_snapshot.resolved_after_deadline, 0);
    assert!(statuses
        .iter()
        .all(|status| status.completed_snapshot_count >= 2));
    assert!(before_shutdown_costs
        .iter()
        .all(|costs| costs["volatile_experiment"]["background_error"].is_null()));
}
