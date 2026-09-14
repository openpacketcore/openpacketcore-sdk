//! Original cardinality and schedule, with separate voter and driver processes.

use super::*;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

// The original in-process workload and this driver use the same request,
// encryption, exact-result and descriptor-pinned disk-accounting helpers.
#[path = "../../../../opc-session-store/tests/fenced_transition_v2_qualification/requests.rs"]
mod requests;
#[path = "../../../../opc-session-store/tests/fenced_transition_v2_qualification/resources.rs"]
mod resources;
use opc_consensus::DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS;
use opc_session_net::consumer::PersistentSessionConsumerExecuteError;
use opc_session_store::consumer::{
    SessionConsumerV2FencedTransitionBatchError, SessionConsumerV2FencedTransitionBatchResult,
};
use opc_session_store::{
    FencedTransitionMutationResult, FencedTransitionOutcome,
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES,
};
use opc_types::{NetworkFunctionKind, TenantId};
use requests::*;
use resources::*;
use std::collections::BTreeSet;
use tokio::task::JoinSet;

const VOTERS: usize = 3;
const SESSIONS: usize = 50_000;
const DATABASE_CEILING: u64 = FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES * 3;
const SNAPSHOT_CEILING: u64 = FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES * 2;
const BATCH_BOUND: Duration = Duration::from_millis(800);
const RETRY_BACKOFF: Duration = Duration::from_millis(25);
const RETRIES: usize = 16;

#[derive(Default)]
struct Effects {
    evidence_root: PathBuf,
    failure_records: AtomicU64,
    read_unavailable_retries: AtomicU64,
    maintenance_retries: AtomicU64,
    dispatched_batches: AtomicU64,
    not_transmitted_retries: AtomicU64,
    ambiguous_batches: AtomicU64,
    status_reads: AtomicU64,
    resolved_after_deadline: AtomicU64,
}

impl Effects {
    fn preserve_effect(
        &self,
        kind: &str,
        requests: &[FencedTransitionV2Request],
        resolved: &[Option<FencedTransitionOutcome>],
        returned: &[SessionConsumerV2FencedTransitionBatchResult],
    ) {
        let index = self.failure_records.fetch_add(1, Ordering::Relaxed);
        let path = self.evidence_root.join(format!("effect-{index}.json"));
        let evidence = serde_json::json!({
            "kind": kind, "requests": requests, "resolved": resolved, "returned": returned,
            "counters": self.json(), "performance_acceptance": false,
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&evidence).expect("exact failure evidence"),
        )
        .expect("preserve bounded submitted-effect ledger");
        eprintln!("sdk_isolated_effect_evidence={}", path.display());
    }

    fn assert_clean(&self) {
        assert_eq!(self.read_unavailable_retries.load(Ordering::Relaxed), 0);
        assert_eq!(self.maintenance_retries.load(Ordering::Relaxed), 0);
        assert_eq!(self.not_transmitted_retries.load(Ordering::Relaxed), 0);
        assert_eq!(self.ambiguous_batches.load(Ordering::Relaxed), 0);
        assert_eq!(self.resolved_after_deadline.load(Ordering::Relaxed), 0);
        assert_eq!(self.failure_records.load(Ordering::Relaxed), 0);
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "read_backend_unavailable_retries": self.read_unavailable_retries.load(Ordering::Relaxed),
            "maintenance_reconciliation_retries": self.maintenance_retries.load(Ordering::Relaxed),
            "failure_records": self.failure_records.load(Ordering::Relaxed),
            "dispatched_batches": self.dispatched_batches.load(Ordering::Relaxed),
            "not_transmitted_retries": self.not_transmitted_retries.load(Ordering::Relaxed),
            "ambiguous_batches": self.ambiguous_batches.load(Ordering::Relaxed),
            "status_reads": self.status_reads.load(Ordering::Relaxed),
            "resolved_after_deadline": self.resolved_after_deadline.load(Ordering::Relaxed),
        })
    }
}

async fn exact_status(
    client: &PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    request: &FencedTransitionV2Request,
) -> SessionConsumerV2FencedTransitionStatus {
    match client
        .execute_v2(&SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: Box::new(request.clone()),
            },
        ))
        .await
        .expect("public exact receipt transport")
    {
        SessionConsumerV2Response::FencedTransitionV2Status(Ok(status)) => status,
        response => panic!("exact receipt rejected: {response:?}"),
    }
}

async fn execute_batch(
    client: &PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    requests: &[FencedTransitionV2Request],
    effects: &Effects,
    deadline: Instant,
) -> Vec<FencedTransitionOutcome> {
    let mut resolved = vec![None; requests.len()];
    let mut returned = Vec::new();
    let result = AssertUnwindSafe(execute_batch_inner(
        client,
        scope,
        requests,
        effects,
        deadline,
        &mut resolved,
        &mut returned,
    ))
    .catch_unwind()
    .await;
    if let Err(panic) = result {
        effects.preserve_effect("failed_batch", requests, &resolved, &returned);
        std::panic::resume_unwind(panic);
    }
    resolved
        .into_iter()
        .map(|outcome| outcome.expect("every exact effect resolved"))
        .collect()
}

async fn execute_batch_inner(
    client: &PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    requests: &[FencedTransitionV2Request],
    effects: &Effects,
    deadline: Instant,
    resolved: &mut [Option<FencedTransitionOutcome>],
    returned: &mut Vec<SessionConsumerV2FencedTransitionBatchResult>,
) {
    assert!(!requests.is_empty() && requests.len() <= 256);
    let ids = requests
        .iter()
        .map(FencedTransitionV2Request::request_id)
        .collect::<Vec<_>>();
    let operation = SessionConsumerV2Request::new(
        scope,
        SessionConsumerV2Operation::FencedTransitionV2Batch {
            requests: requests.to_vec(),
        },
    );
    for attempt in 0..=RETRIES {
        assert!(Instant::now() < deadline, "original pre-dispatch deadline");
        effects.dispatched_batches.fetch_add(1, Ordering::Relaxed);
        // Keep ownership of every dispatched effect. No outer timeout may
        // turn a possibly transmitted mutation into a retry-safe operation.
        match client.execute_v2(&operation).await {
            Ok(SessionConsumerV2Response::FencedTransitionV2Batch(Ok(outcomes))) => {
                // Retain the whole typed reply before any validation can
                // fail, including errors distinct from unresolved effects.
                *returned = outcomes;
                assert_eq!(returned.len(), requests.len());
                let mut rejection = None;
                for (index, outcome) in returned.iter().enumerate() {
                    assert_eq!(outcome.request_id(), ids[index]);
                    match outcome.result().clone() {
                        Ok(outcome) => {
                            assert_exact_qualified_v2_success(&requests[index], &outcome);
                            resolved[index] = Some(outcome);
                        }
                        Err(SessionConsumerV2FencedTransitionError::OutcomeUnknown) => {}
                        Err(error) => {
                            rejection.get_or_insert(error);
                        }
                    }
                }
                if let Some(error) = rejection {
                    panic!("exact batch item rejected: {error:?}");
                }
                break;
            }
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Unavailable,
            }) if attempt < RETRIES => {
                effects
                    .not_transmitted_retries
                    .fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(
                    RETRY_BACKOFF.min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted { cause }) => {
                panic!(
                    "batch was not transmitted: cause={cause:?}; attempt={attempt}; remaining_ns={}; pool={:?}",
                    deadline.saturating_duration_since(Instant::now()).as_nanos(),
                    client.v2_diagnostics(),
                );
            }
            Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch { request_ids }) => {
                assert_eq!(request_ids, ids);
                break;
            }
            Ok(SessionConsumerV2Response::FencedTransitionV2Batch(Err(
                SessionConsumerV2FencedTransitionBatchError::OutcomeUnknown { request_ids },
            ))) => {
                assert_eq!(request_ids, ids);
                break;
            }
            outcome => panic!("batch effect cannot be safely retried: {outcome:?}"),
        }
    }
    if resolved.iter().any(Option::is_none) {
        effects.ambiguous_batches.fetch_add(1, Ordering::Relaxed);
        for round in 0..=RETRIES {
            assert!(
                Instant::now() < deadline,
                "original exact-status convergence deadline"
            );
            let pending = resolved
                .iter()
                .enumerate()
                .filter_map(|(index, value)| value.is_none().then_some(index))
                .collect::<Vec<_>>();
            let observations = futures_util::future::join_all(pending.iter().map(|index| async {
                effects.status_reads.fetch_add(1, Ordering::Relaxed);
                let response = client
                    .execute_v2(&SessionConsumerV2Request::new(
                        scope,
                        SessionConsumerV2Operation::FencedTransitionV2Status {
                            request: Box::new(requests[*index].clone()),
                        },
                    ))
                    .await;
                (*index, response)
            }));
            let observations =
                tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), observations)
                    .await
                    .expect("immutable status reads retain the original deadline");
            for (index, response) in observations {
                match response {
                    Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                        SessionConsumerV2FencedTransitionStatus::Recorded(outcome),
                    ))) => {
                        let outcome = outcome.expect("exact recorded mutation outcome");
                        assert_exact_qualified_v2_success(&requests[index], &outcome);
                        resolved[index] = Some(outcome);
                    }
                    Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                        SessionConsumerV2FencedTransitionStatus::NotFound,
                    ))) => {}
                    Err(
                        PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                            cause: SessionConsumerClientError::Unavailable,
                        }
                        | PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
                            cause: SessionConsumerClientError::Unavailable,
                        },
                    ) => {}
                    Ok(response)
                        if qualification_v2_batch_status_is_retryable_unavailable(&response) => {}
                    response => panic!("exact status cannot resolve this mutation: {response:?}"),
                }
            }
            if resolved.iter().all(Option::is_some) {
                break;
            }
            assert!(
                round < RETRIES,
                "original bounded status attempts exhausted"
            );
            tokio::time::sleep(
                RETRY_BACKOFF.min(deadline.saturating_duration_since(Instant::now())),
            )
            .await;
        }
    }
    if Instant::now() > deadline {
        effects
            .resolved_after_deadline
            .fetch_add(1, Ordering::Relaxed);
        eprintln!("sdk_isolated_late_effect={}", effects.json());
        panic!("classified exact effect exceeded the unchanged 800ms batch deadline");
    }
    assert!(
        resolved.iter().all(Option::is_some),
        "every exact effect resolved"
    );
}

fn schedule_offset(index: usize, rate: usize) -> Duration {
    assert!(rate > 0);
    Duration::from_nanos(
        u64::try_from((index as u128) * 1_000_000_000 / rate as u128)
            .expect("original schedule fits"),
    )
}

fn percentile(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
    assert!(!samples.is_empty() && numerator > 0 && numerator <= denominator);
    samples.sort_unstable();
    samples[(samples.len() * numerator).div_ceil(denominator) - 1]
}

struct CompletedBatch {
    requests: Vec<FencedTransitionV2Request>,
    outcomes: Vec<FencedTransitionOutcome>,
    slots: Vec<usize>,
    scheduled: Vec<Instant>,
    started: Instant,
    completed: Instant,
    first_in_epoch: bool,
}

fn history(fleet: &mut Fleet, leader: usize) -> opc_session_store::FencedTransitionV2HistoryState {
    match fleet.nodes[leader].invoke(&QualificationNodeCommand::IsolatedScaleHistoryState) {
        QualificationNodeReply::IsolatedScaleHistory { state } => state,
        response => panic!("public exact history state: {response:?}"),
    }
}

fn realtime_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("observation wall clock follows Unix epoch")
        .as_nanos()
}

enum MemorySamplePhase {
    Initial,
    Final,
}

fn memory_sample(
    fleet: &Fleet,
    scale: QualificationIsolatedScaleConfig,
    pids: &[u32],
    phase: MemorySamplePhase,
) -> serde_json::Value {
    let phase = match phase {
        MemorySamplePhase::Initial => "initial",
        MemorySamplePhase::Final => "final",
    };
    let requested = realtime_ns();
    let request = serde_json::json!({
        "sample_request_unix_ns": requested, "driver_pid": std::process::id(),
        "voter_pids": pids, "workspace": fleet.workspace.path(),
        "configuration": scale, "schedule_sha256": scale.schedule_sha256(),
    });
    eprintln!("sdk_isolated_scale_{phase}_sample_required={request}");
    // This is outside both timed workload phases. Keep every owner alive
    // until the external observer has captured each actual voter and driver.
    // The existing setup guard detects a missing observer, not an operation
    // or recovery failure, and grants no memory/performance acceptance.
    let deadline = Instant::now() + Duration::from_secs(10);
    let path = fleet
        .workspace
        .path()
        .join(format!("isolated-memory-{phase}.json"));
    loop {
        match fs::read(&path) {
            Ok(bytes) => {
                assert!(bytes.len() <= 4096);
                let ack: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("complete memory acknowledgement");
                assert_eq!(ack["request"], request);
                let samples = ack["samples"].as_array().expect("actual process samples");
                assert_eq!(samples.len(), pids.len() + 1);
                let expected = pids
                    .iter()
                    .copied()
                    .chain(std::iter::once(std::process::id()))
                    .collect::<BTreeSet<_>>();
                let observed = samples
                    .iter()
                    .map(|sample| {
                        assert!(
                            u128::from(
                                sample["sampled_unix_ns"]
                                    .as_u64()
                                    .expect("real sample timestamp")
                            ) >= requested
                        );
                        u32::try_from(sample["pid"].as_u64().expect("sampled process ID"))
                            .expect("process ID fits")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(observed, expected);
                return ack;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => panic!("read external memory acknowledgement: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "full workload memory observer did not acknowledge each live process"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn run_original(persistence: QualificationIsolatedPersistence) {
    if cfg!(debug_assertions) {
        panic!("full-scale measurements require the release build");
    }
    let scale = QualificationIsolatedScaleConfig {
        persistence,
        workload: QualificationIsolatedScaleWorkload::Original,
    };
    let mut fleet = Fleet::start_with_settings(3, scale.schedule_sha256(), None, Some(scale));
    let leader = fleet.wait_isolated_scale_ready(scale);
    let identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let (endpoint, scope) = fleet.start_stateless_consumer(leader, identities.clone());
    let (identity_source, client) = qualification_persistent_v2_client(
        Arc::new(Mutex::new(vec![endpoint; 3])),
        leader,
        fleet.stateless_consumer_voter_authorities()[leader].clone(),
        fleet.pki.consumer_identity_state(&identities[0]),
        PersistentSessionConsumerConfig::default(),
        Some(BATCH_BOUND),
    );
    let pids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    assert_eq!(pids.iter().collect::<BTreeSet<_>>().len(), 3);
    assert!(pids.iter().all(|pid| *pid != std::process::id()));
    // The external sampler must cover every owner before the workload starts.
    // Discovery runs independently and cannot be assumed to beat this process.
    let initial_memory = memory_sample(&fleet, scale, &pids, MemorySamplePhase::Initial);
    eprintln!(
        "sdk_isolated_scale_started={}",
        serde_json::json!({
            "configuration": scale, "schedule_sha256": scale.schedule_sha256(),
            "driver_pid": std::process::id(), "voter_pids": pids, "workspace": fleet.workspace.path(),
            "initial_memory_sample": initial_memory,
        "started_unix_ns": realtime_ns(),
            "full_cardinality": true, "performance_acceptance": false, "quiet_host_claim": false,
        })
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("isolated driver runtime");
    let effect_root = fleet.workspace.path().join("original-effect-evidence");
    fs::create_dir(&effect_root).expect("exclusive effect evidence directory");
    let effects = Arc::new(Effects {
        evidence_root: effect_root,
        ..Effects::default()
    });
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut epoch = FencedTransitionV2HistoryEpoch::new(1).expect("first epoch");
        let provider = sealing_provider();
        let mut sessions = Vec::with_capacity(SESSIONS);
        let preload_started = Instant::now();
        runtime.block_on(async {
        client.prewarm_v2().await.expect("real public mTLS lanes");
        client.prewarm().await.expect("real public observation lanes");
        for begin in std::iter::once(0).chain((1..SESSIONS).step_by(256)) {
            let end = if begin == 0 { 1 } else { (begin + 256).min(SESSIONS) };
            let mut requests = Vec::with_capacity(end - begin);
            for index in begin..end {
                let key = key(index);
                let observation = client.execute(&SessionConsumerRequest::new(scope,
                    SessionConsumerRequestId::from_bytes((index as u128).to_be_bytes()),
                    SessionConsumerOperation::ObserveFencedTransition { key: key.clone() },
                )).await.unwrap_or_else(|error| {
                    let cause = match &error {
                        PersistentSessionConsumerExecuteError::NotTransmitted { cause }
                        | PersistentSessionConsumerExecuteError::ReadUnavailable { cause } => Some(*cause),
                        _ => None,
                    };
                    panic!("public preload fence observation failed: index={index}; error={error:?}; cause={cause:?}; v2_pool={:?}", client.v2_diagnostics());
                });
                let SessionConsumerResponse::ObserveFencedTransition(Ok(observation)) = observation else {
                    panic!("preload requires its independent current fence");
                };
                requests.push(create_request(index, epoch, key, observation.current_fence(), &provider).await);
            }
            let outcomes = execute_batch(&client, scope, &requests, &effects, Instant::now() + BATCH_BOUND).await;
            sessions.extend(requests.into_iter().zip(outcomes));
            if begin / 4096 != end / 4096 || end == SESSIONS {
                eprintln!("sdk_isolated_scale_preload={}", serde_json::json!({"exact_outcomes": sessions.len(), "elapsed_ns": preload_started.elapsed().as_nanos()}));
            }
        }
    });
        assert_eq!(sessions.len(), SESSIONS);
        let mut representatives = vec![sessions[0].clone()];
        let mut active_entries = SESSIONS;
        let mut nonce = SESSIONS;
        let mut rotations = 0;
        let mut phases = Vec::new();
        for (name, rate, operations) in [
            ("sustained-500-per-second", 500, 900_000),
            ("burst-1000-per-second", 1000, 60_000),
        ] {
            let started = Instant::now();
            let mut submitted = 0;
            let mut completed = 0;
            let mut slots = BTreeSet::new();
            let mut pending = JoinSet::new();
            let mut item_times = Vec::with_capacity(operations);
            let mut batch_times = Vec::new();
            let mut max_slots = 0;
            let phase_result = runtime.block_on(AssertUnwindSafe(async {
            while completed < operations {
                if active_entries == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
                    assert!(pending.is_empty() && slots.is_empty());
                    let current = fleet.wait_isolated_scale_ready(scale);
                    let before = history(&mut fleet, current);
                    assert_eq!(before.active_epoch(), Some(epoch));
                    assert_eq!(before.bound_entries(), FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES);
                    let after = match fleet.nodes[current].invoke(&QualificationNodeCommand::IsolatedScaleMaintainHistory { expected_state: before }) {
                        QualificationNodeReply::IsolatedScaleHistory { state } => state,
                        response => panic!("exact local-leader history maintenance: {response:?}"),
                    };
                    epoch = FencedTransitionV2HistoryEpoch::new(epoch.get() + 1).expect("successor epoch");
                    assert_eq!(after.active_epoch(), Some(epoch));
                    assert_eq!(after.bound_entries(), 0);
                    assert_eq!(after.retired_through(), None);
                    assert_eq!(after.reclaim_epoch(), None);
                    rotations += 1;
                    assert!(rotations <= 7);
                    active_entries = 0;
                    for (request, outcome) in &representatives {
                        assert!(matches!(exact_status(&client, scope, request).await,
                            SessionConsumerV2FencedTransitionStatus::Recorded(result) if result.as_ref() == &Ok(outcome.clone())));
                        let replay = execute_batch(&client, scope, std::slice::from_ref(request), &effects, Instant::now() + BATCH_BOUND).await;
                        assert_eq!(&replay, &vec![outcome.clone()]);
                        assert!(matches!(exact_status(&client, scope, &request_with_changed_body(request)).await,
                            SessionConsumerV2FencedTransitionStatus::RequestConflict));
                    }
                }
                let capacity = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES.checked_sub(active_entries + slots.len()).expect("bounded active and outstanding receipts");
                if submitted < operations && pending.len() < DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS && capacity > 0 {
                    let count = 8.min(operations - submitted).min(capacity);
                    let first_in_epoch = active_entries == 0 && slots.is_empty();
                    let mut requests = Vec::with_capacity(count);
                    let mut scheduled = Vec::with_capacity(count);
                    let mut session_slots = Vec::with_capacity(count);
                    for offset in 0..count {
                        let due = started + schedule_offset(submitted + offset, rate);
                        if due > Instant::now() {
                            tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
                        }
                        scheduled.push(due);
                        let slot = nonce % SESSIONS;
                        assert!(slots.insert(slot), "at most one outstanding update per session");
                        let request = renew_update_request(nonce, epoch, &sessions[slot].1, &provider).await;
                        assert_exact_qualified_update_request(&sessions[slot].1, &request);
                        requests.push(request);
                        session_slots.push(slot);
                        nonce += 1;
                    }
                    let client = client.clone();
                    let effects = Arc::clone(&effects);
                    let batch_started = Instant::now();
                    pending.spawn(async move {
                        let outcomes = execute_batch(&client, scope, &requests, &effects, batch_started + BATCH_BOUND).await;
                        CompletedBatch { requests, outcomes, slots: session_slots, scheduled, started: batch_started, completed: Instant::now(), first_in_epoch }
                    });
                    submitted += count;
                    max_slots = max_slots.max(pending.len());
                    continue;
                }
                let batch = pending.join_next().await.expect("outstanding batch").expect("owned batch completion");
                let elapsed = batch.completed.duration_since(batch.started);
                assert!(elapsed <= BATCH_BOUND);
                batch_times.push(elapsed);
                for due in &batch.scheduled {
                    let total = batch.completed.checked_duration_since(*due).expect("completion follows scheduled arrival");
                    assert!(total >= elapsed);
                    item_times.push(total);
                }
                let count = batch.requests.len();
                if batch.first_in_epoch { representatives.push((batch.requests[0].clone(), batch.outcomes[0].clone())); }
                for ((request, outcome), slot) in batch.requests.into_iter().zip(batch.outcomes).zip(batch.slots) {
                    assert!(slots.remove(&slot));
                    assert_exact_qualified_v2_success(&request, &outcome);
                    sessions[slot] = (request, outcome);
                }
                active_entries += count;
                completed += count;
            }
        }).catch_unwind());
            if let Err(panic) = phase_result {
                let failure_observed = Instant::now();
                eprintln!(
                    "sdk_isolated_scale_failure_phase={}",
                    serde_json::json!({
                        "phase": name,
                        "phase_elapsed_ns": failure_observed.duration_since(started).as_nanos(),
                        "observed_unix_ns": realtime_ns(),
                        "submitted_operations": submitted,
                        "joined_operations": completed,
                        "unjoined_batches": pending.len(),
                    })
                );
                // The JoinSet remains owned outside the failing phase. Drain all
                // submitted calls before shutdown; retain successes too so an
                // unrelated failure cannot erase a sibling's exact result.
                runtime.block_on(async {
                    while let Some(batch) = pending.join_next().await {
                        if let Ok(batch) = batch {
                            // These are the original invocation timestamps, not
                            // the time at which failure cleanup joined the task.
                            eprintln!(
                                "sdk_isolated_scale_drained_sibling_timing={}",
                                serde_json::json!({
                                    "phase": name,
                                    "session_slots": batch.slots,
                                    "started_offset_ns": batch.started.checked_duration_since(started).map(|value| value.as_nanos()),
                                    "completed_offset_ns": batch.completed.checked_duration_since(started).map(|value| value.as_nanos()),
                                    "scheduled_offsets_ns": batch.scheduled.iter().map(|due| due.checked_duration_since(started).map(|value| value.as_nanos())).collect::<Vec<_>>(),
                                })
                            );
                            let resolved = batch.outcomes.into_iter().map(Some).collect::<Vec<_>>();
                            effects.preserve_effect("drained_sibling", &batch.requests, &resolved, &[]);
                        }
                    }
                });
                std::panic::resume_unwind(panic);
            }
            assert_eq!(submitted, operations);
            assert!(pending.is_empty() && slots.is_empty());
            assert_eq!(item_times.len(), operations);
            let elapsed = started.elapsed();
            let p99 = percentile(&mut item_times, 99, 100);
            let p999 = percentile(&mut item_times, 999, 1000);
            let max = *item_times.last().expect("real maximum");
            let maximum_phase_ms = (operations as u128 * 1_000_000) / (rate as u128 * 999);
            let phase = serde_json::json!({
                "phase": name, "offered_ops_per_second": rate, "completed_operations": completed,
                "elapsed_ns": elapsed.as_nanos(), "achieved_operations_per_second": completed as f64 / elapsed.as_secs_f64(),
                "item_samples": item_times.len(), "batch_samples": batch_times.len(), "max_unjoined_batches": max_slots,
                "item_p99_ns": p99.as_nanos(), "item_p999_ns": p999.as_nanos(), "item_max_ns": max.as_nanos(),
                "effect_counters": effects.json(), "quiet_host_claim": false, "performance_acceptance": false,
            });
            eprintln!("sdk_isolated_scale_phase={phase}");
            assert!(
                elapsed
                    <= Duration::from_millis(
                        u64::try_from(maximum_phase_ms).expect("original phase bound")
                    )
            );
            assert!(p99 <= Duration::from_millis(25));
            assert!(p999 <= Duration::from_millis(100));
            assert!(max <= BATCH_BOUND);
            phases.push(phase);
        }
        assert_eq!(nonce, 1_010_000);
        assert_eq!(rotations, 7);
        assert_eq!(representatives.len(), 8);
        let current = fleet.wait_isolated_scale_ready(scale);
        let state = history(&mut fleet, current);
        assert_eq!(
            state.active_epoch(),
            Some(FencedTransitionV2HistoryEpoch::new(8).expect("last epoch"))
        );
        assert_eq!(
            state.bound_entries(),
            1_010_000 % FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
        );
        assert_eq!(state.retired_through(), None);
        assert_eq!(state.reclaim_epoch(), None);
        let reports = fleet.isolated_scale_reports();
        assert!(reports.iter().all(|report| report.ready
            && report.engine_running
            && report.storage_running
            && !report.storage_failed
            && !report.background_failed
            && !report.saturated
            && report.completed_snapshot_count >= 2));
        if persistence == QualificationIsolatedPersistence::Async {
            assert!(reports
                .iter()
                .all(|report| report.async_active && report.completed_generation > Some(0)));
        }
        effects.assert_clean();
        let final_memory = memory_sample(&fleet, scale, &pids, MemorySamplePhase::Final);
        serde_json::json!({
            "configuration": scale, "schedule_sha256": scale.schedule_sha256(), "driver_pid": std::process::id(),
            "voter_pids": pids, "workspace": fleet.workspace.path(), "reports": reports, "phases": phases,
            "exact_workload_outcomes": nonce, "retained_epoch_representatives": representatives.len(), "successor_rotations": rotations,
            "effect_counters": effects.json(), "full_cardinality": true,
            "performance_acceptance": false, "quiet_host_claim": false,
            "cold_restart_qualification": false, "final_memory_sample": final_memory,
            "initial_memory_sample": initial_memory,
        })
    }));
    if result.is_err() {
        // Capture live progress after the failed workload has relinquished its
        // calls, before shutdown changes the observed engine/storage state.
        let reports = std::panic::catch_unwind(AssertUnwindSafe(|| fleet.isolated_scale_reports()));
        if let Ok(reports) = reports {
            eprintln!(
                "sdk_isolated_scale_failure_reports={}",
                serde_json::json!(reports)
            );
        }
        // The timed workload and its dispatched calls have already ended.
        // Ask the existing diagnostic command for bounded WAL stage counters
        // before shutdown; diagnostic failure must not replace the workload RED.
        let diagnostics =
            std::panic::catch_unwind(AssertUnwindSafe(|| fleet.all_consensus_diagnostics()));
        if let Ok(diagnostics) = diagnostics {
            eprintln!(
                "sdk_isolated_scale_failure_consensus={}",
                serde_json::json!(diagnostics)
            );
        }
        eprintln!(
            "sdk_isolated_scale_failure_node_stderr={}",
            serde_json::json!(fleet.stderr_diagnostics())
        );
    }
    runtime.block_on(client.shutdown());
    drop(identity_source);
    fleet.shutdown_isolated_scale_joined();
    let mut evidence = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    // Account for the selected generation after the real background writer
    // has drained. Include native, SQLite, pending and snapshot artifacts.
    let database_bytes = fleet
        .database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes = fleet
        ._snapshot_leaves
        .iter()
        .map(|leaf| directory_bytes(leaf.path()))
        .collect::<Vec<_>>();
    evidence["database_bytes_by_voter"] = serde_json::json!(database_bytes);
    evidence["snapshot_bytes_by_voter"] = serde_json::json!(snapshot_bytes);
    evidence["database_artifacts_by_voter"] = serde_json::json!(fleet
        .database_paths
        .iter()
        .map(|path| sqlite_database_family_artifacts(path))
        .collect::<Vec<_>>());
    evidence["snapshot_artifacts_by_voter"] = serde_json::json!(fleet
        ._snapshot_leaves
        .iter()
        .map(|leaf| directory_artifacts(leaf.path()))
        .collect::<Vec<_>>());
    evidence["database_ceiling_bytes_per_voter"] = serde_json::json!(DATABASE_CEILING);
    evidence["snapshot_ceiling_bytes_per_voter"] = serde_json::json!(SNAPSHOT_CEILING);
    evidence["joined_shutdown"] = serde_json::json!(true);
    // Preserve measurements before enforcing their original limits. A
    // failing limit gets no completed/accepted marker.
    eprintln!("sdk_isolated_scale_measured={evidence}");
    assert_voter_resource_ceiling(
        "isolated native database family",
        &database_bytes,
        DATABASE_CEILING,
    );
    assert_voter_resource_ceiling("isolated snapshots", &snapshot_bytes, SNAPSHOT_CEILING);
    eprintln!("sdk_isolated_scale_completed={evidence}");
}

#[test]
fn original_schedule_and_percentiles_preserve_submillisecond_boundaries() {
    assert_eq!(schedule_offset(499, 500), Duration::from_millis(998));
    assert_eq!(schedule_offset(999, 1000), Duration::from_millis(999));
    assert_eq!(
        schedule_offset(999_999, 1000),
        Duration::from_millis(999_999)
    );
    let mut samples = vec![Duration::from_millis(25); 1000];
    samples[989] += Duration::from_nanos(1);
    for value in &mut samples[990..] {
        *value = Duration::from_millis(100);
    }
    assert_eq!(
        percentile(&mut samples, 99, 100),
        Duration::from_millis(25) + Duration::from_nanos(1)
    );
    assert_eq!(
        percentile(&mut samples, 999, 1000),
        Duration::from_millis(100)
    );
}

#[test]
#[ignore = "original 1,010,000-operation separate-process Async diagnostic; requires release and designated fs-verity"]
fn isolated_async_original_workload() {
    run_original(QualificationIsolatedPersistence::Async);
}

#[test]
#[ignore = "original 1,010,000-operation separate-process Durable diagnostic; requires release and designated fs-verity"]
fn isolated_durable_original_workload() {
    run_original(QualificationIsolatedPersistence::Durable);
}

// Exercise the full workload's actual encryption and public batch protocol
// without claiming its cardinality, duration or memory acceptance.
fn original_wire_control(
    persistence: QualificationIsolatedPersistence,
    check_mixed_batch_failure: bool,
) {
    let scale = QualificationIsolatedScaleConfig {
        persistence,
        workload: QualificationIsolatedScaleWorkload::Original,
    };
    let mut fleet = Fleet::start_with_settings(3, scale.schedule_sha256(), None, Some(scale));
    let leader = fleet.wait_isolated_scale_ready(scale);
    let identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let identity = identities[0].clone();
    let (endpoint, scope) = fleet.start_stateless_consumer(leader, identities);
    let (source, client) = qualification_persistent_v2_client(
        Arc::new(Mutex::new(vec![endpoint; 3])),
        leader,
        fleet.stateless_consumer_voter_authorities()[leader].clone(),
        fleet.pki.consumer_identity_state(&identity),
        PersistentSessionConsumerConfig::default(),
        Some(BATCH_BOUND),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("wire control runtime");
    let effects = Effects {
        evidence_root: fleet.workspace.path().to_path_buf(),
        ..Effects::default()
    };
    let result = runtime.block_on(AssertUnwindSafe(async {
        client.prewarm().await.expect("public observation lane");
        client.prewarm_v2().await.expect("public batch lane");
        let provider = sealing_provider();
        let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("original first epoch");
        let mut requests = Vec::new();
        for index in 0..8 {
            let key = key(index);
            let response = client.execute(&SessionConsumerRequest::new(scope,
                SessionConsumerRequestId::from_bytes((index as u128).to_be_bytes()),
                SessionConsumerOperation::ObserveFencedTransition { key: key.clone() },
            )).await.expect("independent public current fence");
            let SessionConsumerResponse::ObserveFencedTransition(Ok(observed)) = response else {
                panic!("original scope must receive an authoritative fence");
            };
            requests.push(create_request(index, epoch, key, observed.current_fence(), &provider).await);
        }
        let created = execute_batch(&client, scope, &requests, &effects, Instant::now() + BATCH_BOUND).await;
        let mut updates = Vec::new();
        for (index, previous) in created.iter().enumerate() {
            let request = renew_update_request(index + 8, epoch, previous, &provider).await;
            assert_exact_qualified_update_request(previous, &request);
            updates.push(request);
        }
        let updated = execute_batch(&client, scope, &updates, &effects, Instant::now() + BATCH_BOUND).await;
        for (request, outcome) in requests.iter().zip(&created).chain(updates.iter().zip(&updated)) {
            assert!(matches!(exact_status(&client, scope, request).await,
                SessionConsumerV2FencedTransitionStatus::Recorded(result) if result.as_ref() == &Ok(outcome.clone())));
            assert!(matches!(exact_status(&client, scope, &request_with_changed_body(request)).await,
                SessionConsumerV2FencedTransitionStatus::RequestConflict));
        }
        assert_eq!(execute_batch(&client, scope, &requests, &effects, Instant::now() + BATCH_BOUND).await, created);
        assert_eq!(execute_batch(&client, scope, &updates, &effects, Instant::now() + BATCH_BOUND).await, updated);
        let mut forbidden = key(0);
        forbidden.tenant = TenantId::new("outside-the-original-qualification-grant").expect("ungranted test scope");
        let rejection = client.execute(&SessionConsumerRequest::new(scope,
            SessionConsumerRequestId::from_bytes([0xFF; 16]),
            SessionConsumerOperation::ObserveFencedTransition { key: forbidden },
        )).await.expect("real rejected public request");
        assert!(matches!(rejection, SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized)));
        effects.assert_clean();
        if check_mixed_batch_failure {
            let mut mixed = requests.clone();
            mixed[0] = request_with_changed_body(&mixed[0]);
            let evidence_root = fleet.workspace.path().join("mixed-item-failure");
            fs::create_dir(&evidence_root).expect("separate mixed-response evidence");
            let rejected_effects = Effects {
                evidence_root: evidence_root.clone(),
                ..Effects::default()
            };
            let failure = AssertUnwindSafe(execute_batch(
                &client, scope, &mixed, &rejected_effects, Instant::now() + BATCH_BOUND,
            )).catch_unwind().await;
            assert!(failure.is_err(), "a typed rejection must keep qualification RED");
            assert_eq!(rejected_effects.dispatched_batches.load(Ordering::Relaxed), 1);
            assert_eq!(rejected_effects.failure_records.load(Ordering::Relaxed), 1);
            assert_eq!(rejected_effects.not_transmitted_retries.load(Ordering::Relaxed), 0);
            assert_eq!(rejected_effects.ambiguous_batches.load(Ordering::Relaxed), 0);
            assert_eq!(rejected_effects.status_reads.load(Ordering::Relaxed), 0);
            let evidence: serde_json::Value = serde_json::from_slice(
                &fs::read(evidence_root.join("effect-0.json")).expect("failed batch ledger"),
            ).expect("typed failure ledger JSON");
            assert_eq!(evidence["kind"], "failed_batch");
            assert_eq!(evidence["resolved"][0], serde_json::Value::Null);
            for (index, outcome) in created.iter().enumerate().skip(1) {
                assert_eq!(evidence["resolved"][index], serde_json::to_value(outcome).unwrap(),
                    "an early rejection must retain every later exact sibling");
            }
            let returned: Vec<opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchResult> =
                serde_json::from_value(evidence["returned"].clone()).expect("complete typed batch reply");
            assert_eq!(returned.len(), mixed.len());
            assert_eq!(returned[0].request_id(), mixed[0].request_id());
            assert_eq!(returned[0].result(), &Err(SessionConsumerV2FencedTransitionError::RequestConflict));
            for ((request, outcome), result) in mixed.iter().zip(&created).zip(&returned).skip(1) {
                assert_eq!(result.request_id(), request.request_id());
                assert_eq!(result.result(), &Ok(outcome.clone()));
            }
        }
        if env::var_os("OPC_SESSION_ISOLATED_FINAL_CAPTURE_CONTROL").is_some() {
            let pids = fleet.nodes.iter().map(ChildNode::process_id).collect::<Vec<_>>();
            let capture = memory_sample(&fleet, scale, &pids, MemorySamplePhase::Final);
            eprintln!("sdk_isolated_scale_capture_control={}", serde_json::json!({
                "capture": capture, "full_cardinality": false, "performance_acceptance": false,
            }));
        }
    }).catch_unwind());
    runtime.block_on(client.shutdown());
    drop(source);
    fleet.shutdown_isolated_scale_joined();
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[test]
fn original_encrypted_async_batches_preserve_receipts_and_scope() {
    original_wire_control(QualificationIsolatedPersistence::Async, false);
}

#[test]
fn original_encrypted_durable_batches_preserve_receipts_and_scope() {
    original_wire_control(QualificationIsolatedPersistence::Durable, false);
}

#[test]
fn original_mixed_batch_failure_retains_typed_rejection_and_exact_successes() {
    original_wire_control(QualificationIsolatedPersistence::Durable, true);
}
