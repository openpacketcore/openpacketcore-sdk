//! Unpaced capacity diagnostic of native WAL in DURABLE mode.
//!
//! A workload capped at 1,000 offered operations/s cannot establish capacity
//! above that rate. This fixture measures actual formation-to-completion time
//! for the original bounded workload, retaining its deadlines and validators.
//! Full-scale, sustained-duration and quiet-host qualification remain separate.

use super::*;
use std::panic::AssertUnwindSafe;

fn assert_native_durable(stores: &[ConsensusSessionStore]) {
    for store in stores {
        assert_eq!(
            store.persistence_mode(),
            opc_session_store::SessionPersistenceMode::Durable
        );
        assert!(
            opc_session_store::test_support::consensus_local_wal_costs_for_test(store)
                .expect("observe native WAL owner")
                .is_some(),
            "native WAL must be attached"
        );
    }
    eprintln!(
        "native_capacity_mode={}",
        serde_json::json!({"voters":stores.len(),"persistence":"DURABLE","native_wal_attached":true})
    );
}

struct Completion {
    at: Instant,
    effect: Option<ReleaseBatchEffect>,
}

struct Attempt {
    requests: Vec<FencedTransitionV2Request>,
    slots: Vec<usize>,
    started: Instant,
    completion: Option<Completion>,
}

async fn invoke(
    store: ConsensusSessionStore,
    requests: Vec<FencedTransitionV2Request>,
) -> Completion {
    // The original public invocation always finishes. An overdue or ambiguous
    // mutation is retained and never cancelled, retried, or counted as success.
    let effect = AssertUnwindSafe(store.fenced_transition_v2_batch_effect(requests))
        .catch_unwind()
        .await
        .ok();
    Completion {
        at: Instant::now(),
        effect,
    }
}

fn exact_count(attempt: &Attempt) -> usize {
    match attempt.completion.as_ref().and_then(|c| c.effect.as_ref()) {
        Some(FencedTransitionV2Effect::Resolved(Ok(outcomes)))
            if outcomes.len() == attempt.requests.len() =>
        {
            attempt
                .requests
                .iter()
                .zip(outcomes)
                .filter(|(request, outcome)| {
                    outcome
                        .as_ref()
                        .is_ok_and(|outcome| is_exact_qualified_v2_success(request, outcome))
                })
                .count()
        }
        _ => 0,
    }
}

fn accept(
    index: usize,
    completion: Completion,
    attempts: &mut [Attempt],
    sessions: &mut [(FencedTransitionV2Request, FencedTransitionOutcome)],
    busy: &mut BTreeSet<usize>,
) -> bool {
    let attempt = &mut attempts[index];
    if let Some(FencedTransitionV2Effect::Resolved(Ok(outcomes))) = &completion.effect {
        if outcomes.len() == attempt.requests.len() {
            for ((request, slot), outcome) in
                attempt.requests.iter().zip(&attempt.slots).zip(outcomes)
            {
                if let Ok(outcome) = outcome {
                    if is_exact_qualified_v2_success(request, outcome) {
                        sessions[*slot] = (request.clone(), outcome.clone());
                    }
                }
            }
        }
    }
    let on_time =
        completion.at.duration_since(attempt.started) <= QUALIFICATION_RELEASE_BATCH_DEADLINE;
    for slot in &attempt.slots {
        busy.remove(slot);
    }
    attempt.completion = Some(completion);
    exact_count(attempt) == attempt.requests.len() && on_time
}

fn rate(exact: usize, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        0.0
    } else {
        exact as f64 / elapsed.as_secs_f64()
    }
}

#[test]
fn capacity_reporting_has_no_offered_rate_or_sixty_second_denominator_cap() {
    assert_eq!(rate(60_000, Duration::from_secs(30)), 2_000.0);
    assert_eq!(rate(60_000, Duration::from_secs(60)), 1_000.0);
    assert_eq!(rate(30_000, Duration::from_secs(60)), 500.0);
    assert!(rate(60_000, Duration::from_secs(60) + Duration::from_nanos(1)) < 1_000.0);
}

async fn measure_phase(
    phase: usize,
    ingress: &ConsensusSessionStore,
    provider: &MemoryKeyProvider,
    sessions: &mut [(FencedTransitionV2Request, FencedTransitionOutcome)],
    attempts: &mut Vec<Attempt>,
) -> serde_json::Value {
    let begin = attempts.len();
    let start = Instant::now();
    let admission_end = start + Duration::from_secs(60);
    let mut pending = JoinSet::new();
    let mut busy = BTreeSet::new();
    let mut peak_clients = 0;
    let mut stopped = false;
    let mut join_failed = false;
    let mut progress = start;
    let admission = AssertUnwindSafe(async {
        while attempts.len() - begin < BOUNDED_SCALE_STALL_BATCHES_PER_PHASE || !pending.is_empty() {
            if !stopped && Instant::now() < admission_end
                && attempts.len() - begin < BOUNDED_SCALE_STALL_BATCHES_PER_PHASE
                && pending.len() < QUALIFICATION_IN_FLIGHT_CLIENTS
            {
                // Start before request formation and real AEAD encryption.
                let started = Instant::now();
                let mut requests = Vec::with_capacity(QUALIFICATION_PACED_BATCH_OPERATIONS);
                let mut slots = Vec::with_capacity(QUALIFICATION_PACED_BATCH_OPERATIONS);
                for offset in 0..QUALIFICATION_PACED_BATCH_OPERATIONS {
                    let slot = (0..sessions.len()).find(|slot| !busy.contains(slot)).expect("free session");
                    assert!(busy.insert(slot));
                    let nonce = BOUNDED_SCALE_STALL_SESSION_SLOTS
                        + attempts.len() * QUALIFICATION_PACED_BATCH_OPERATIONS + offset;
                    let request = renew_update_request(nonce, FencedTransitionV2HistoryEpoch::new(1).expect("epoch"), &sessions[slot].1, provider).await;
                    assert_exact_qualified_update_request(&sessions[slot].1, &request);
                    requests.push(request);
                    slots.push(slot);
                }
                if Instant::now() >= admission_end {
                    for slot in slots { busy.remove(&slot); }
                    stopped = true;
                    continue;
                }
                let index = attempts.len();
                let store = ingress.clone();
                let dispatch = requests.clone();
                attempts.push(Attempt { requests, slots, started, completion: None });
                pending.spawn(async move { (index, invoke(store, dispatch).await) });
                peak_clients = peak_clients.max(pending.len());
                continue;
            }
            let Some(joined) = pending.join_next().await else { break; };
            match joined {
                Ok((index, completion)) => stopped |= !accept(index, completion, attempts, sessions, &mut busy),
                Err(_) => { join_failed = true; stopped = true; }
            }
            if progress.elapsed() >= Duration::from_secs(5) {
                let exact: usize = attempts[begin..].iter().map(exact_count).sum();
                eprintln!("native_capacity_progress={}", serde_json::json!({"phase":phase,"elapsed_ns":start.elapsed().as_nanos(),"admitted_operations":(attempts.len()-begin)*QUALIFICATION_PACED_BATCH_OPERATIONS,"exact_operations":exact,"pending_clients":pending.len(),"peak_rss_kib":process_peak_rss_kib()}));
                progress = Instant::now();
            }
        }
    }).catch_unwind().await;
    // Even a fixture panic reaches every already-dispatched invocation.
    while let Some(joined) = pending.join_next().await {
        match joined {
            Ok((index, completion)) => {
                accept(index, completion, attempts, sessions, &mut busy);
            }
            Err(_) => join_failed = true,
        }
    }
    let phase_attempts = &attempts[begin..];
    let exact: usize = phase_attempts.iter().map(exact_count).sum();
    let finish = phase_attempts
        .iter()
        .filter_map(|a| a.completion.as_ref().map(|c| c.at))
        .max()
        .unwrap_or(start);
    let elapsed = finish.duration_since(start);
    let late = phase_attempts
        .iter()
        .filter(|a| {
            a.completion.as_ref().is_some_and(|c| {
                c.at.duration_since(a.started) > QUALIFICATION_RELEASE_BATCH_DEADLINE
            })
        })
        .count();
    let not_transmitted = phase_attempts
        .iter()
        .filter(|a| {
            matches!(
                a.completion.as_ref().and_then(|c| c.effect.as_ref()),
                Some(FencedTransitionV2Effect::NotTransmitted(_))
            )
        })
        .count();
    let ambiguous = phase_attempts
        .iter()
        .filter(|a| {
            matches!(
                a.completion.as_ref().and_then(|c| c.effect.as_ref()),
                Some(FencedTransitionV2Effect::OutcomeUnknown { .. })
            )
        })
        .count();
    let missing = phase_attempts
        .iter()
        .filter(|a| {
            a.completion
                .as_ref()
                .and_then(|c| c.effect.as_ref())
                .is_none()
        })
        .count();
    let mut seconds = vec![0_usize; elapsed.as_secs() as usize + 1];
    let mut durations = Vec::new();
    for attempt in phase_attempts {
        if let Some(completion) = &attempt.completion {
            seconds[completion.at.duration_since(start).as_secs() as usize] += exact_count(attempt);
            durations.push(completion.at.duration_since(attempt.started));
        }
    }
    durations.sort_unstable();
    let percentile = |n: usize| {
        durations
            .get((durations.len() * n).div_ceil(1000).saturating_sub(1))
            .map(|d| d.as_nanos())
    };
    let complete = phase_attempts.len() == BOUNDED_SCALE_STALL_BATCHES_PER_PHASE
        && exact == BOUNDED_SCALE_STALL_BATCHES_PER_PHASE * QUALIFICATION_PACED_BATCH_OPERATIONS
        && late == 0
        && !join_failed
        && admission.is_ok()
        && busy.is_empty();
    let report = serde_json::json!({"phase":phase,"backend":"native_wal","load_mode":"unpaced_bounded_clients","offered_rate_cap":null,"operation_budget":BOUNDED_SCALE_STALL_BATCHES_PER_PHASE*QUALIFICATION_PACED_BATCH_OPERATIONS,"admission_budget_seconds":60,"batch_deadline_ms":800,"admitted_operations":phase_attempts.len()*QUALIFICATION_PACED_BATCH_OPERATIONS,"exact_successful_operations":exact,"actual_workload_elapsed_ns":elapsed.as_nanos(),"exact_successful_ops_per_second":rate(exact,elapsed),"minimum_1000_ops_per_second_met":!elapsed.is_zero() && exact as u128*1_000_000_000 >= elapsed.as_nanos()*1000,"late_batches":late,"not_transmitted_batches":not_transmitted,"ambiguous_batches":ambiguous,"missing_effect_batches":missing,"join_failed":join_failed,"fixture_panicked":admission.is_err(),"peak_clients":peak_clients,"batch_formation_to_completion_p99_ns":percentile(990),"batch_formation_to_completion_p999_ns":percentile(999),"exact_completions_per_second":seconds,"functional_complete":complete,"peak_rss_kib":process_peak_rss_kib(),"performance_qualification":false});
    eprintln!("native_capacity_phase={report}");
    report
}

async fn latest_witness(
    stores: &[ConsensusSessionStore],
    sessions: &[(FencedTransitionV2Request, FencedTransitionOutcome)],
    provider: &MemoryKeyProvider,
    entries: usize,
) {
    let _ = ready_leader(stores).await;
    for store in stores {
        let history = store
            .fenced_transition_v2_history_state()
            .await
            .expect("public history");
        assert_eq!(history.bound_entries(), entries);
        for (request, expected) in sessions {
            let status = store
                .fenced_transition_v2_status(request)
                .await
                .expect("exact public status");
            assert!(
                matches!(status, FencedTransitionV2Status::Recorded(result) if result.as_ref().as_ref().is_ok_and(|found| found == expected))
            );
            let record = store
                .get(request.lease().key())
                .await
                .expect("public record")
                .expect("record retained");
            let (expected_record, expected_plaintext): (_, &[u8]) = match request.mutation() {
                FencedTransitionMutation::Update { record, .. } => {
                    (record, b"qualification-update")
                }
                FencedTransitionMutation::Create { record } => (record, b"qualification"),
                _ => panic!("fixture create or update"),
            };
            assert_eq!(record, **expected_record);
            let plaintext = record
                .payload
                .decrypt(
                    provider,
                    &record.key,
                    &record.state_type,
                    record.generation,
                    record.fence,
                    "sdk-702-v2-qualification",
                )
                .await
                .expect("authenticated payload");
            assert_eq!(plaintext.as_slice(), expected_plaintext);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "SDK-741 uncapped current native WAL in DURABLE mode capacity diagnostic"]
async fn unpaced_native_two_snapshot_thresholds_public_durable_capacity() {
    let _profile = require_release_qualification_profile();
    assert_eq!(QUALIFICATION_IN_FLIGHT_CLIENTS, 8);
    assert_eq!(QUALIFICATION_PACED_BATCH_OPERATIONS, 8);
    let directory = tempfile::tempdir()
        .expect("isolated capacity directory")
        .keep();
    let snapshot_root = std::fs::canonicalize(
        std::env::var_os(FS_VERITY_SNAPSHOT_ROOT_ENV).expect("designated snapshot root"),
    )
    .expect("snapshot root");
    eprintln!(
        "native_capacity_artifacts={}",
        serde_json::json!({"mutable_directory":directory,"snapshot_root":snapshot_root,"backend":"native WAL","persistence":"DURABLE","contended_diagnostic":true,"performance_qualification":false})
    );
    let clock = Arc::new(MutableClock::new(Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("clock"),
    )));
    let (stores, database_paths, snapshot_paths, peers) =
        fixed_cluster_with_snapshot_root(&directory, &snapshot_root, clock.clone()).await;
    let mut attempts = Vec::new();
    let mut sessions = Vec::new();
    let mut phase_reports = Vec::new();
    let provider = sealing_provider();
    let experiment = AssertUnwindSafe(async {
        assert_native_durable(&stores);
        let ingress = &stores[ready_leader(&stores).await];
        let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("epoch");
        let mut creates = Vec::new();
        for index in 0..BOUNDED_SCALE_STALL_SESSION_SLOTS {
            let key = key(index);
            let observed = ingress.observe_fenced_transition(&key).await.expect("setup fence");
            creates.push(create_request(index, epoch, key, observed.current_fence(), &provider).await);
        }
        for batch in std::iter::once(&creates[..1]).chain(creates[1..].chunks(QUALIFICATION_PACED_BATCH_OPERATIONS)) {
            let started = Instant::now();
            let completion = invoke(ingress.clone(), batch.to_vec()).await;
            let Some(FencedTransitionV2Effect::Resolved(Ok(outcomes))) = completion.effect else { panic!("exact setup effect"); };
            assert_eq!(outcomes.len(), batch.len());
            for (request, outcome) in batch.iter().zip(outcomes) {
                let outcome = outcome.expect("setup result");
                assert_exact_qualified_v2_success(request, &outcome);
                sessions.push((request.clone(), outcome));
            }
            assert!(completion.at.duration_since(started) <= QUALIFICATION_RELEASE_BATCH_DEADLINE);
        }
        for phase in 0..BOUNDED_SCALE_STALL_PHASES.len() {
            let report = measure_phase(phase, ingress, &provider, &mut sessions, &mut attempts).await;
            let complete = report["functional_complete"] == true;
            phase_reports.push(report);
            if !complete { break; }
        }
        let exact: usize = attempts.iter().map(exact_count).sum();
        assert_eq!(exact, BOUNDED_SCALE_STALL_BATCHES_PER_PHASE * BOUNDED_SCALE_STALL_PHASES.len() * QUALIFICATION_PACED_BATCH_OPERATIONS, "all original bounded workload operations");
        assert!(phase_reports.iter().all(|r|r["functional_complete"] == true));
        latest_witness(&stores, &sessions, &provider, sessions.len()+exact).await;
        let snapshots: Vec<_> = stores.iter().map(|store|store.status().completed_snapshot_count).collect();
        eprintln!("native_capacity_live_witness={}", serde_json::json!({"exact_operations":exact,"history_entries_per_voter":sessions.len()+exact,"snapshots_per_voter":snapshots,"peak_rss_kib":process_peak_rss_kib()}));
        assert!(snapshots.iter().all(|count| *count >= 2), "original two snapshots per voter");
    }).catch_unwind().await;
    let stopped = AssertUnwindSafe(shutdown_fixed_cluster(&stores, &peers))
        .catch_unwind()
        .await;
    drop(stores);
    drop(peers);
    let journal_path = directory.join("capacity-exact-attempts.jsonl");
    let mut journal = File::create(&journal_path).expect("retain exact original invocations");
    for attempt in &attempts {
        let effect = match attempt.completion.as_ref().and_then(|c| c.effect.as_ref()) {
            Some(FencedTransitionV2Effect::Resolved(result)) => {
                serde_json::json!({"Resolved":result})
            }
            Some(FencedTransitionV2Effect::NotTransmitted(error)) => {
                serde_json::json!({"NotTransmitted":error})
            }
            Some(FencedTransitionV2Effect::OutcomeUnknown { request_ids }) => {
                serde_json::json!({"OutcomeUnknown":request_ids})
            }
            None => serde_json::json!({"NoEffectReturned":true}),
            Some(_) => serde_json::json!({"UnrecognizedEffect":true}),
        };
        writeln!(journal, "{}", serde_json::json!({"requests":attempt.requests,"original_effect":effect,"elapsed_ns":attempt.completion.as_ref().map(|c|c.at.duration_since(attempt.started).as_nanos())})).expect("write exact retained invocation");
    }
    journal
        .sync_all()
        .expect("persist exact invocation journal");
    eprintln!(
        "native_capacity_clean_stop={}",
        serde_json::json!({"success":stopped.is_ok(),"experiment_success":experiment.is_ok(),"peak_rss_kib":process_peak_rss_kib()})
    );
    assert!(stopped.is_ok(), "original clean shutdown must succeed");
    assert!(
        experiment.is_ok(),
        "capacity experiment failed; raw results and voter files retained"
    );
    // Cold construction is timed separately; it cannot inflate or reduce the
    // reported workload throughput. All old owners were dropped above.
    let (reopened, reopened_databases, reopened_snapshots, reopened_peers) =
        fixed_cluster_with_snapshot_root(&directory, &snapshot_root, clock).await;
    assert_eq!(reopened_databases, database_paths);
    assert_eq!(reopened_snapshots, snapshot_paths);
    let cold = AssertUnwindSafe(async {
        assert_native_durable(&reopened);
        latest_witness(
            &reopened,
            &sessions,
            &provider,
            sessions.len() + attempts.iter().map(exact_count).sum::<usize>(),
        )
        .await;
    })
    .catch_unwind()
    .await;
    let cold_stop = AssertUnwindSafe(shutdown_fixed_cluster(&reopened, &reopened_peers))
        .catch_unwind()
        .await;
    drop(reopened);
    drop(reopened_peers);
    let database_bytes: Vec<_> = database_paths
        .iter()
        .map(|p| sqlite_database_family_bytes(p))
        .collect();
    let snapshot_bytes: Vec<_> = snapshot_paths.iter().map(|p| directory_bytes(p)).collect();
    let peak_rss_kib = process_peak_rss_kib();
    eprintln!(
        "native_capacity_result={}",
        serde_json::json!({"phases":phase_reports,"cold_latest_witness":cold.is_ok(),"cold_clean_stop":cold_stop.is_ok(),"peak_rss_kib":peak_rss_kib,"rss_ceiling_kib":QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,"database_bytes_per_voter":database_bytes,"snapshot_bytes_per_voter":snapshot_bytes,"performance_qualification":false,"scope":"98496 operations, 65 keys, three durable native WAL voters over in-process peers; independent of original full-cardinality acceptance"})
    );
    assert!(cold.is_ok() && cold_stop.is_ok());
    assert!(
        peak_rss_kib <= QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "unchanged 2 GiB ceiling"
    );
    assert_voter_resource_ceiling(
        "native WAL capacity database family",
        &database_bytes,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "native WAL capacity snapshots",
        &snapshot_bytes,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    assert!(
        phase_reports
            .iter()
            .all(|r| r["minimum_1000_ops_per_second_met"] == true),
        "strict 1000 successful durable operations/s floor"
    );
}
