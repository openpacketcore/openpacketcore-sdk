//! Private, bounded SDK throughput evidence; the original qualification is unchanged.
//! The 65-session hot set, 1 ms item arrivals, eight-item batches, eight task
//! slots and complete 800 ms batch timer follow the existing bounded fixture.
//! Local peer transport is not remote TLS or singleton qualification.

use super::*;
use crate::fenced_transition::FencedTransitionV2Effect;
use crate::StoreError;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::task::JoinSet;

const OPERATIONS: usize = 60_000;
const BATCH: usize = 8;
const CLIENTS: usize = 8;
const SESSIONS: usize = 65;
const WINDOW: Duration = Duration::from_secs(60);
const DEADLINE: Duration = Duration::from_millis(800);
const UPDATE_PLAINTEXT: &[u8] = b"private WAL paced update";
type BatchEffect =
    FencedTransitionV2Effect<Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError>>;

#[derive(Debug)]
struct FixedClock(opc_types::Timestamp);
impl crate::Clock for FixedClock {
    fn now_utc(&self) -> opc_types::Timestamp {
        self.0
    }
}

#[derive(Default)]
struct Counters {
    admitted: AtomicU64,
    replied: AtomicU64,
    exact: AtomicU64,
    late_batches: AtomicU64,
    failed_batches: AtomicU64,
    active: AtomicU64,
    peak_active: AtomicU64,
    last_admission_ns: AtomicU64,
    last_completion_ns: AtomicU64,
    receipt_checks: AtomicU64,
    stage: AtomicU64,
}

struct Progress {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Progress {
    fn start(start: Instant, counters: Arc<Counters>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new().name("private-wal-paced-progress".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    let elapsed = start.elapsed();
                    let offered = offered(elapsed);
                    let admitted = counters.admitted.load(Ordering::Relaxed);
                    eprintln!("private_wal_paced_progress={}", serde_json::json!({
                        "elapsed_ns": ns(elapsed), "stage": counters.stage.load(Ordering::Relaxed),
                        "planned_operations": OPERATIONS, "offered": offered, "admitted": admitted,
                        "backlog": offered.saturating_sub(admitted),
                        "replied": counters.replied.load(Ordering::Relaxed),
                        "exact_successes": counters.exact.load(Ordering::Relaxed),
                        "late_batches": counters.late_batches.load(Ordering::Relaxed),
                        "failed_batches": counters.failed_batches.load(Ordering::Relaxed),
                        "active_clients": counters.active.load(Ordering::Relaxed),
                        "peak_active_clients": counters.peak_active.load(Ordering::Relaxed),
                        "last_admission_ns": counters.last_admission_ns.load(Ordering::Relaxed),
                        "last_completion_ns": counters.last_completion_ns.load(Ordering::Relaxed),
                        "receipt_checks": counters.receipt_checks.load(Ordering::Relaxed),
                    }));
                    std::thread::park_timeout(Duration::from_secs(1));
                }
            }).expect("bounded progress owner");
        Self {
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Progress {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            assert!(thread.join().is_ok(), "progress owner joined");
        }
    }
}

fn ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
fn offered(elapsed: Duration) -> u64 {
    (elapsed.as_millis() as u64 + 1).min(OPERATIONS as u64)
}

fn exact(request: &FencedTransitionV2Request, outcome: &FencedTransitionOutcome) -> bool {
    if !outcome.matches_v2_request(request) {
        return false;
    }
    match (request.lease(), request.mutation()) {
        (FencedTransitionLease::Acquire { .. }, FencedTransitionMutation::Create { record }) => {
            outcome.mutation() == FencedTransitionMutationResult::Created
                && outcome.committed_generation() == record.generation
        }
        (
            FencedTransitionLease::Renew { lease: prior, .. },
            FencedTransitionMutation::Update {
                expected_generation,
                record,
            },
        ) => {
            outcome.mutation() == FencedTransitionMutationResult::Updated
                && outcome.lease().key() == prior.key()
                && outcome.lease().owner() == prior.owner()
                && outcome.lease().fence() == prior.fence()
                && outcome.lease().acquired_at() == prior.acquired_at()
                && outcome.lease().credential_id() == prior.credential_id()
                && expected_generation.next() == Some(record.generation)
                && outcome.committed_generation() == record.generation
        }
        _ => false,
    }
}

async fn update_request(
    nonce: usize,
    previous: &FencedTransitionOutcome,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let expected_generation = previous.committed_generation();
    let mut record = record(
        previous.lease().key().clone(),
        previous.lease(),
        expected_generation
            .next()
            .expect("generation headroom")
            .get(),
    );
    record.payload = EncryptedSessionPayload::new(UPDATE_PLAINTEXT);
    record.payload = EncryptedSessionPayload::encrypt(provider, &record, "private-wal-sdk")
        .await
        .expect("actual AEAD update");
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("epoch"),
        FencedTransitionV2CallerNonce::from_bytes((nonce as u128).to_be_bytes()),
        FencedTransitionLease::renew(previous.lease().clone(), Duration::from_secs(60))
            .expect("exact prior lease"),
        FencedTransitionMutation::update(expected_generation, record),
    )
    .expect("exact conditional update")
}

fn effect_json(effect: &BatchEffect) -> serde_json::Value {
    match effect {
        FencedTransitionV2Effect::Resolved(Ok(outcomes)) => {
            serde_json::json!({ "kind": "resolved", "outcomes": outcomes.iter().map(|outcome| match outcome {
            Ok(value) => serde_json::json!({"ok": value}),
            Err(error) => serde_json::json!({"error": format!("{error:?}")}),
        }).collect::<Vec<_>>() })
        }
        FencedTransitionV2Effect::Resolved(Err(error)) => {
            serde_json::json!({"kind": "resolved_error", "error": format!("{error:?}")})
        }
        FencedTransitionV2Effect::NotTransmitted(error) => {
            serde_json::json!({"kind": "not_transmitted", "error": format!("{error:?}")})
        }
        FencedTransitionV2Effect::OutcomeUnknown { request_ids } => {
            serde_json::json!({"kind": "outcome_unknown", "request_ids": request_ids.iter().map(|id| id.to_bytes().to_vec()).collect::<Vec<_>>() })
        }
    }
}

struct Completion {
    admitted_at: Instant,
    completed_at: Instant,
    effect: Option<BatchEffect>,
    panic: Option<String>,
}
struct Attempt {
    requests: Vec<FencedTransitionV2Request>,
    slots: Vec<usize>,
    scheduled: Vec<Instant>,
    formed: Vec<Instant>,
    started: Instant,
    completion: Option<Completion>,
}

async fn invoke(
    store: ConsensusSessionStore,
    requests: Vec<FencedTransitionV2Request>,
    start: Instant,
    batch_start: Instant,
    counters: Arc<Counters>,
) -> Completion {
    let admitted_at = Instant::now();
    counters
        .admitted
        .fetch_add(requests.len() as u64, Ordering::Relaxed);
    counters
        .last_admission_ns
        .store(ns(admitted_at.duration_since(start)), Ordering::Relaxed);
    let active = counters.active.fetch_add(1, Ordering::Relaxed) + 1;
    counters.peak_active.fetch_max(active, Ordering::Relaxed);
    // Await the original invocation to completion even after 800 ms. The
    // deadline classifies the complete result; it never cancels or retries a mutation.
    let observed = AssertUnwindSafe(store.fenced_transition_v2_batch_effect(requests.clone()))
        .catch_unwind()
        .await;
    let completed_at = Instant::now();
    let (effect, panic) = match observed {
        Ok(effect) => (Some(effect), None),
        Err(panic) => (None, Some(panic_text(panic.as_ref()))),
    };
    let exact_count = match &effect {
        Some(FencedTransitionV2Effect::Resolved(Ok(outcomes)))
            if outcomes.len() == requests.len() =>
        {
            requests
                .iter()
                .zip(outcomes)
                .filter(|(request, outcome)| {
                    outcome
                        .as_ref()
                        .is_ok_and(|outcome| exact(request, outcome))
                })
                .count()
        }
        _ => 0,
    };
    counters
        .replied
        .fetch_add(requests.len() as u64, Ordering::Relaxed);
    counters
        .exact
        .fetch_add(exact_count as u64, Ordering::Relaxed);
    if exact_count != requests.len() {
        counters.failed_batches.fetch_add(1, Ordering::Relaxed);
    }
    if completed_at.duration_since(batch_start) > DEADLINE {
        counters.late_batches.fetch_add(1, Ordering::Relaxed);
    }
    counters
        .last_completion_ns
        .fetch_max(ns(completed_at.duration_since(start)), Ordering::Relaxed);
    counters.active.fetch_sub(1, Ordering::Relaxed);
    Completion {
        admitted_at,
        completed_at,
        effect,
        panic,
    }
}

fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "non-string panic".to_owned()
    }
}

fn accept_completion(
    index: usize,
    completion: Completion,
    attempts: &mut [Attempt],
    sessions: &mut [(FencedTransitionV2Request, FencedTransitionOutcome)],
    busy: &mut BTreeSet<usize>,
) -> bool {
    let attempt = &mut attempts[index];
    let mut all_exact = false;
    if let Some(FencedTransitionV2Effect::Resolved(Ok(outcomes))) = &completion.effect {
        if outcomes.len() == attempt.requests.len() {
            all_exact = true;
            for ((request, slot), outcome) in
                attempt.requests.iter().zip(&attempt.slots).zip(outcomes)
            {
                if let Ok(outcome) = outcome {
                    if exact(request, outcome) {
                        sessions[*slot] = (request.clone(), outcome.clone());
                    } else {
                        all_exact = false;
                    }
                } else {
                    all_exact = false;
                }
            }
        }
    }
    for slot in &attempt.slots {
        busy.remove(slot);
    }
    attempt.completion = Some(completion);
    all_exact
}

async fn setup(
    fleet: &Fleet,
    ingress: usize,
    provider: &MemoryKeyProvider,
    retained: &mut Vec<(FencedTransitionV2Request, FencedTransitionOutcome)>,
) {
    let store = &fleet.stores[ingress];
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("epoch");
    let mut requests = Vec::with_capacity(SESSIONS);
    for index in 0..SESSIONS {
        let observed = store
            .observe_fenced_transition(&key(100 + index))
            .await
            .expect("public setup fence");
        requests.push(v2_create_request(index, epoch, observed.current_fence(), provider).await);
    }
    for (batch_index, batch) in std::iter::once(&requests[..1])
        .chain(requests[1..].chunks(BATCH))
        .enumerate()
    {
        let started = Instant::now();
        let effect = store
            .fenced_transition_v2_batch_effect(batch.to_vec())
            .await;
        let elapsed = started.elapsed();
        eprintln!(
            "private_wal_paced_setup={}",
            serde_json::json!({"batch": batch_index, "elapsed_ns": ns(elapsed), "requests": batch, "effect": effect_json(&effect)})
        );
        let FencedTransitionV2Effect::Resolved(Ok(outcomes)) = effect else {
            panic!("setup effect did not resolve exactly");
        };
        assert_eq!(outcomes.len(), batch.len());
        for (request, outcome) in batch.iter().zip(outcomes) {
            let outcome = outcome.expect("setup create succeeded");
            assert_v2_create(request, &outcome);
            retained.push((request.clone(), outcome));
        }
        assert!(
            elapsed <= DEADLINE,
            "setup exceeded original batch deadline"
        );
    }
}

async fn measure(
    store: &ConsensusSessionStore,
    provider: &MemoryKeyProvider,
    start: Instant,
    counters: &Arc<Counters>,
    sessions: &mut [(FencedTransitionV2Request, FencedTransitionOutcome)],
    attempts: &mut Vec<Attempt>,
    tasks: &mut JoinSet<(usize, Completion)>,
) {
    let end = start + WINDOW;
    let mut busy = BTreeSet::new();
    let mut stop_admission = false;
    let mut peak_unjoined = 0;
    while Instant::now() < end && attempts.len() < OPERATIONS / BATCH && !stop_admission {
        if tasks.len() < CLIENTS {
            let mut requests = Vec::with_capacity(BATCH);
            let mut slots = Vec::with_capacity(BATCH);
            let mut scheduled = Vec::with_capacity(BATCH);
            let mut formed = Vec::with_capacity(BATCH);
            let index = attempts.len();
            for offset in 0..BATCH {
                let item = index * BATCH + offset;
                let due = start + Duration::from_millis(item as u64);
                tokio::time::sleep_until(due.into()).await;
                if Instant::now() >= end {
                    break;
                }
                let slot = (0..sessions.len())
                    .find(|slot| !busy.contains(slot))
                    .expect("65 distinct sessions cover eight clients");
                busy.insert(slot);
                requests.push(update_request(SESSIONS + item, &sessions[slot].1, provider).await);
                slots.push(slot);
                scheduled.push(due);
                formed.push(Instant::now());
            }
            if requests.len() != BATCH || Instant::now() >= end {
                eprintln!(
                    "private_wal_paced_unadmitted_formation={}",
                    serde_json::json!({"batch": index, "formed_items": requests.len(), "elapsed_ns": ns(start.elapsed()), "requests": requests})
                );
                break;
            }
            let started = Instant::now();
            attempts.push(Attempt {
                requests: requests.clone(),
                slots,
                scheduled,
                formed,
                started,
                completion: None,
            });
            let task_store = store.clone();
            let task_counters = Arc::clone(counters);
            tasks.spawn(async move {
                (
                    index,
                    invoke(task_store, requests, start, started, task_counters).await,
                )
            });
            peak_unjoined = peak_unjoined.max(tasks.len());
        } else {
            tokio::select! {
                result = tasks.join_next() => {
                    let (index, completion) = result.expect("active tasks").expect("owned task joined");
                    stop_admission = !accept_completion(index, completion, attempts, sessions, &mut busy);
                }
                _ = tokio::time::sleep_until(end.into()) => { break; }
            }
        }
    }
    // The offered clock remains fixed through all 60 seconds, including
    // overload or an ambiguous effect. No new mutation is admitted after an error.
    counters.stage.store(2, Ordering::Relaxed);
    while let Some(result) = tasks.join_next().await {
        let (index, completion) = result.expect("every original task joined");
        accept_completion(index, completion, attempts, sessions, &mut busy);
    }
    let completions_drained_ns = ns(start.elapsed());
    tokio::time::sleep_until(end.into()).await;
    eprintln!(
        "private_wal_paced_admission_end={}",
        serde_json::json!({"offered": OPERATIONS, "admitted": counters.admitted.load(Ordering::Relaxed), "stop_admission_on_error": stop_admission, "peak_unjoined_client_tasks": peak_unjoined, "client_limit": CLIENTS, "drained_at_ns": completions_drained_ns, "interval_elapsed_ns": ns(start.elapsed())})
    );
}

fn percentiles(mut samples: Vec<Duration>) -> serde_json::Value {
    samples.sort_unstable();
    if samples.is_empty() {
        return serde_json::json!({"count": 0});
    }
    let percentile =
        |percent: usize| ns(samples[(samples.len() * percent).div_ceil(100).saturating_sub(1)]);
    serde_json::json!({"count": samples.len(), "unit": "nanoseconds", "p50": percentile(50), "p95": percentile(95), "p99": percentile(99), "max": ns(*samples.last().expect("nonempty"))})
}

fn summarize(start: Instant, attempts: &[Attempt], counters: &Counters) -> bool {
    let mut batch_latency = Vec::new();
    let mut item_latency = Vec::new();
    let mut admission_latency = Vec::new();
    let mut exact_before_cutoff = 0;
    let mut admitted_before_cutoff = 0;
    let mut last_completion = WINDOW;
    for (index, attempt) in attempts.iter().enumerate() {
        let Some(completion) = &attempt.completion else {
            eprintln!(
                "private_wal_paced_unfinished={}",
                serde_json::json!({"batch": index, "requests": attempt.requests})
            );
            continue;
        };
        let batch_elapsed = completion.completed_at.duration_since(attempt.started);
        batch_latency.push(batch_elapsed);
        last_completion = last_completion.max(completion.completed_at.duration_since(start));
        if completion.admitted_at < start + WINDOW {
            admitted_before_cutoff += attempt.requests.len();
        }
        let exact_count =
            if let Some(FencedTransitionV2Effect::Resolved(Ok(outcomes))) = &completion.effect {
                attempt
                    .requests
                    .iter()
                    .zip(outcomes)
                    .filter(|(request, outcome)| {
                        outcome
                            .as_ref()
                            .is_ok_and(|outcome| exact(request, outcome))
                    })
                    .count()
            } else {
                0
            };
        if completion.completed_at <= start + WINDOW {
            exact_before_cutoff += exact_count;
        }
        let logical = attempt
            .scheduled
            .iter()
            .map(|scheduled| completion.completed_at.duration_since(*scheduled))
            .collect::<Vec<_>>();
        item_latency.extend(logical.iter().copied());
        admission_latency.extend(
            attempt
                .scheduled
                .iter()
                .map(|scheduled| completion.admitted_at.duration_since(*scheduled)),
        );
        eprintln!(
            "private_wal_paced_batch={}",
            serde_json::json!({
                "batch": index, "slots": attempt.slots, "requests": attempt.requests,
                "scheduled_ns": attempt.scheduled.iter().map(|time| ns(time.duration_since(start))).collect::<Vec<_>>(),
                "formed_ns": attempt.formed.iter().map(|time| ns(time.duration_since(start))).collect::<Vec<_>>(),
                "spawned_ns": ns(attempt.started.duration_since(start)), "admitted_ns": ns(completion.admitted_at.duration_since(start)),
                "completed_ns": ns(completion.completed_at.duration_since(start)), "batch_elapsed_ns": ns(batch_elapsed),
                "item_elapsed_ns": logical.into_iter().map(ns).collect::<Vec<_>>(), "deadline_ns": ns(DEADLINE),
                "deadline_missed": batch_elapsed > DEADLINE, "exact_successes": exact_count,
                "effect": completion.effect.as_ref().map(effect_json), "panic": completion.panic,
            })
        );
    }
    let admitted = counters.admitted.load(Ordering::Relaxed);
    let exact = counters.exact.load(Ordering::Relaxed);
    let late = counters.late_batches.load(Ordering::Relaxed);
    let failed = counters.failed_batches.load(Ordering::Relaxed);
    let complete = admitted == OPERATIONS as u64
        && exact == OPERATIONS as u64
        && late == 0
        && failed == 0
        && admitted_before_cutoff == OPERATIONS
        && last_completion <= WINDOW + Duration::from_millis(60);
    eprintln!(
        "private_wal_paced_summary={}",
        serde_json::json!({
            "scope": "private_fixed_sdk_local_in_process_three_file_voters_strict_fsverity",
            "planned_operations": OPERATIONS, "offered_operations": OPERATIONS, "offered_ops_per_second": 1000,
            "arrival_window_ns": ns(WINDOW), "batch_size": BATCH, "client_limit": CLIENTS, "deadline_ns": ns(DEADLINE),
            "maximum_completion_interval_ns": ns(WINDOW + Duration::from_millis(60)),
            "admitted_operations": admitted, "admitted_before_cutoff": admitted_before_cutoff,
            "backlog_at_cutoff": OPERATIONS - admitted_before_cutoff, "exact_successes": exact,
            "exact_successes_before_cutoff": exact_before_cutoff, "late_batches": late, "failed_batches": failed,
            "completion_interval_ns": ns(last_completion), "exact_completed_ops_per_second_in_arrival_window": exact_before_cutoff as f64 / WINDOW.as_secs_f64(),
            "exact_completed_ops_per_second_including_drain": exact as f64 / last_completion.as_secs_f64(),
            "batch_latency": percentiles(batch_latency), "logical_item_latency": percentiles(item_latency),
            "scheduled_to_admission_latency": percentiles(admission_latency), "all_offered_work_completed_within_original_batch_deadlines": complete,
            "mutation_retries": 0, "mutation_deadline_cancellations": 0,
        })
    );
    complete
}

async fn verify_latest(
    fleet: &Fleet,
    sessions: &[(FencedTransitionV2Request, FencedTransitionOutcome)],
    provider: &Arc<MemoryKeyProvider>,
    expected_entries: usize,
) {
    for (voter, store) in fleet.stores.iter().enumerate() {
        let history = store
            .fenced_transition_v2_history_state()
            .await
            .expect("public history after load");
        assert_eq!(
            history.active_epoch(),
            Some(FencedTransitionV2HistoryEpoch::new(1).expect("epoch"))
        );
        assert_eq!(history.bound_entries(), expected_entries);
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(store.clone()),
            provider.clone(),
            "private-wal-sdk",
        );
        for (request, outcome) in sessions {
            assert!(
                matches!(store.fenced_transition_v2_status(request).await.expect("latest public receipt"), FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone()))
            );
            let (record, plaintext) = match request.mutation() {
                FencedTransitionMutation::Create { record } => (
                    record,
                    b"private WAL real SDK V2 plaintext round trip".as_slice(),
                ),
                FencedTransitionMutation::Update { record, .. } => (record, UPDATE_PLAINTEXT),
                _ => panic!("bounded workload mutation"),
            };
            let mut expected = record.as_ref().clone();
            expected.payload = EncryptedSessionPayload::new(plaintext);
            assert_eq!(
                encrypted.get(&record.key).await.expect("actual AEAD read"),
                Some(expected)
            );
        }
        eprintln!(
            "private_wal_paced_latest_verified={}",
            serde_json::json!({"voter": voter, "sessions": sessions.len(), "history_entries": history.bound_entries(), "status": store.status()})
        );
    }
}

// Reconciliation is read-only, occurs after the original timing window and
// never changes the original effect, success counters or deadline result.
async fn reconcile_latest(
    fleet: &Fleet,
    sessions: &mut [(FencedTransitionV2Request, FencedTransitionOutcome)],
    attempts: &[Attempt],
    expected_entries: usize,
) -> usize {
    let mut entries = expected_entries;
    let store = fleet
        .stores
        .first()
        .expect("live voter for public reconciliation");
    for (batch, attempt) in attempts.iter().enumerate() {
        for (item, request) in attempt.requests.iter().enumerate() {
            let original = match attempt
                .completion
                .as_ref()
                .and_then(|completion| completion.effect.as_ref())
            {
                Some(FencedTransitionV2Effect::Resolved(Ok(outcomes))) => outcomes.get(item),
                _ => None,
            };
            if original
                .is_some_and(|result| result.as_ref().is_ok_and(|outcome| exact(request, outcome)))
            {
                continue;
            }
            let status = store
                .fenced_transition_v2_status(request)
                .await
                .expect("public read-only original request reconciliation");
            if let FencedTransitionV2Status::Recorded(result) = &status {
                entries += 1;
                if let Ok(outcome) = result.as_ref() {
                    assert!(exact(request, outcome));
                    sessions[attempt.slots[item]] = (request.clone(), outcome.clone());
                }
            }
            eprintln!(
                "private_wal_paced_public_reconciliation={}",
                serde_json::json!({"batch":batch,"item":item,"request":request,"status":status,"recovery_outside_original_deadline":true})
            );
        }
    }
    entries
}

fn verify_retained(
    wals: &[Arc<Wal>],
    snapshot_root: &std::path::Path,
    setup: &[(FencedTransitionV2Request, FencedTransitionOutcome)],
    attempts: &[Attempt],
    counters: &Counters,
) {
    for (voter, wal) in wals.iter().enumerate() {
        wal.native_audit_closed(
            |current,origin| super::native_flow::admit_native_snapshots(&snapshot_root.join(format!("snapshots-{voter}")), current,origin),
            super::native_flow::AdmittedNativeSnapshots::install_source,
            super::native_flow::AdmittedNativeSnapshots::verify,
            |state| {
        let mut exact_receipts = 0;
        let mut recovered = 0;
        let check = |request: &FencedTransitionV2Request| state.status(request);
        for (request, outcome) in setup {
            assert!(
                matches!(check(request).expect("setup receipt"), FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone()))
            );
            exact_receipts += 1;
            counters.receipt_checks.fetch_add(1, Ordering::Relaxed);
        }
        for (batch_index, attempt) in attempts.iter().enumerate() {
            for (item, request) in attempt.requests.iter().enumerate() {
                let expected = match attempt
                    .completion
                    .as_ref()
                    .and_then(|completion| completion.effect.as_ref())
                {
                    Some(FencedTransitionV2Effect::Resolved(Ok(outcomes))) => outcomes.get(item),
                    _ => None,
                };
                let status = check(request).expect("original full exact-body receipt lookup");
                match expected {
                    Some(Ok(outcome)) if exact(request, outcome) => {
                        assert!(
                            matches!(status, FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone()))
                        );
                        exact_receipts += 1;
                    }
                    _ => {
                        let status = match status {
                            FencedTransitionV2Status::Recorded(result) => {
                                if result
                                    .as_ref()
                                    .as_ref()
                                    .is_ok_and(|outcome| exact(request, outcome))
                                {
                                    recovered += 1;
                                }
                                serde_json::json!({"recorded": match result.as_ref() { Ok(outcome) => serde_json::json!({"ok": outcome}), Err(error) => serde_json::json!({"error": format!("{error:?}")}) }})
                            }
                            value => serde_json::json!({"status": value}),
                        };
                        eprintln!(
                            "private_wal_paced_failure_receipt={}",
                            serde_json::json!({"voter": voter, "batch": batch_index, "item": item, "request": request, "status": status, "recovery_outside_original_deadline": true})
                        );
                    }
                }
                counters.receipt_checks.fetch_add(1, Ordering::Relaxed);
            }
        }
        let rows = state.receipt_count() as u64;
        if counters.failed_batches.load(Ordering::Relaxed) == 0 {
            assert_eq!(rows, exact_receipts);
        }
        eprintln!(
            "private_wal_paced_all_receipts_verified={}",
            serde_json::json!({"voter": voter, "exact_success_receipts": exact_receipts, "late_read_only_recovered_successes": recovered, "total_receipt_rows": rows, "native_full_validator_passed": true, "native_durable_recovery_read_only_after_all_writers_joined": true, "selected_snapshots_strictly_admitted": true, "live_sql_fallbacks": wal.native_sql_fallback_count().expect("native fallback counter")})
        );
        Ok(())
            },
        ).expect("complete native durable image, published WAL and strict snapshot validation");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "private release 60s SDK 1000 logical ops/s viability; not final qualification"]
async fn paced_three_voter_sdk_1000_ops_per_second_for_60s() {
    assert_eq!(
        (
            env!("OPC_SESSION_STORE_CARGO_PROFILE_FAMILY"),
            env!("OPC_SESSION_STORE_CARGO_OPT_LEVEL"),
            cfg!(debug_assertions),
        ),
        ("release", "3", false),
        "paced viability requires the original optimized release configuration",
    );
    let snapshot_parent =
        std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").expect("strict root required");
    let mut snapshot_root =
        tempfile::tempdir_in(snapshot_parent).expect("strict snapshot directory");
    snapshot_root.disable_cleanup(true);
    let mut fleet = Fleet::new_native("paced_1000");
    fleet.directory.disable_cleanup(true);
    fleet.snapshot_root = Some(snapshot_root.path().to_path_buf());
    fleet.clock = Some(Arc::new(FixedClock(
        opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
                .expect("qualification logical clock"),
        ),
    )));
    let provider = provider();
    let mut retained_setup = Vec::with_capacity(SESSIONS);
    let mut sessions = Vec::with_capacity(SESSIONS);
    let mut attempts = Vec::with_capacity(OPERATIONS / BATCH);
    let mut tasks = JoinSet::new();
    let counters = Arc::new(Counters::default());
    let mut progress = None;
    let mut workload_start = None;
    let result = AssertUnwindSafe(async {
        Box::pin(fleet.open()).await;
        let ingress = fleet.stores.iter().position(|store| store.status().leader_id == Some(store.status().node_id)).expect("ready leader");
        eprintln!("private_wal_paced_config={}", serde_json::json!({"ingress": ingress, "voters": 3, "peer_transport": "in_process", "live_state": "native_memory", "durability": "native_image_and_sequential_wal", "snapshot_integrity": "FsVerity", "automatic_snapshot_policy": "production_default", "sessions": SESSIONS, "lease_seconds": 60, "logical_clock_unix_seconds": 1_900_000_000_u64, "cargo_profile": env!("OPC_SESSION_STORE_CARGO_PROFILE_FAMILY"), "cargo_opt_level": env!("OPC_SESSION_STORE_CARGO_OPT_LEVEL"), "native_sdk_operation_timeout_ns": ns(super::super::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT), "original_complete_batch_deadline_ns": ns(DEADLINE), "mutable_path": fleet.directory.path(), "snapshot_path": snapshot_root.path()}));
        Box::pin(setup(&fleet, ingress, &provider, &mut retained_setup)).await;
        sessions.clone_from(&retained_setup);
        fleet.observe_costs("paced_before");
        for (voter, store) in fleet.stores.iter().enumerate() { eprintln!("private_wal_paced_voter_before={}", serde_json::json!({"voter": voter, "status": store.status(), "diagnostics": store.diagnostic_snapshot()})); }
        let start = Instant::now();
        workload_start = Some(start);
        counters.stage.store(1, Ordering::Relaxed);
        progress = Some(Progress::start(start, Arc::clone(&counters)));
        Box::pin(measure(&fleet.stores[ingress], &provider, start, &counters, &mut sessions, &mut attempts, &mut tasks)).await;
    }).catch_unwind().await;
    // The task set lives outside the catch: a fixture panic must still join
    // every original invocation and preserve every returned effect.
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((index, completion)) => {
                attempts[index].completion = Some(completion);
            }
            Err(error) => eprintln!("private_wal_paced_join_error={error:?}"),
        }
    }
    if let Some(start) = workload_start {
        tokio::time::sleep_until((start + WINDOW).into()).await;
    }
    counters.stage.store(3, Ordering::Relaxed);
    let summary = std::panic::catch_unwind(AssertUnwindSafe(|| {
        workload_start.is_some_and(|start| summarize(start, &attempts, &counters))
    }));
    let complete = summary.as_ref().is_ok_and(|complete| *complete);
    let after_costs = std::panic::catch_unwind(AssertUnwindSafe(|| {
        fleet.observe_costs("paced_after_measurement");
        for (voter, store) in fleet.stores.iter().enumerate() {
            assert_eq!(
                store
                    .inner
                    .private_wal
                    .as_ref()
                    .expect("native owner")
                    .native_sql_fallback_count()
                    .expect("native fallback counter"),
                0,
                "native workload must execute no live SQL fallback"
            );
            eprintln!(
                "private_wal_paced_voter_after={}",
                serde_json::json!({"voter": voter, "status": store.status(), "diagnostics": store.diagnostic_snapshot()})
            );
        }
    }));
    let latest = AssertUnwindSafe(async {
        let expected = reconcile_latest(
            &fleet,
            &mut sessions,
            &attempts,
            retained_setup.len() + counters.exact.load(Ordering::Relaxed) as usize,
        )
        .await;
        verify_latest(&fleet, &sessions, &provider, expected).await;
    })
    .catch_unwind()
    .await;
    counters.stage.store(4, Ordering::Relaxed);
    let closed = AssertUnwindSafe(Box::pin(fleet.close()))
        .catch_unwind()
        .await;
    counters.stage.store(5, Ordering::Relaxed);
    let receipts = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let wals = closed
            .as_ref()
            .expect("receipt scan requires completed shutdown");
        assert_eq!(wals.len(), 3, "all voter WAL owners returned");
        for wal in wals {
            assert_eq!(
                wal.integration_observations()
                    .expect("closed owner observation")["writer_joined"],
                true
            );
        }
        verify_retained(
            wals,
            snapshot_root.path(),
            &retained_setup,
            &attempts,
            &counters,
        )
    }));
    drop(progress);
    if std::env::var_os("OPC_SESSION_NATIVE_ALLOCATION_DIAGNOSTIC").as_deref()
        == Some(std::ffi::OsStr::new("required"))
    {
        assert!(
            receipts.is_ok(),
            "memory teardown follows complete cold receipt validation"
        );
        for (voter, wal) in closed
            .as_ref()
            .expect("closed owners for allocation diagnostic")
            .iter()
            .enumerate()
        {
            let before =
                std::fs::read_to_string("/proc/self/status").expect("RSS before native release");
            let mut roots = Vec::new();
            let mut total_released_bytes = 0_i128;
            let counts = wal
                .release_closed_native_memory_for_test(|root, release| {
                    let info = allocation_counter::measure(release);
                    let bytes = i128::from(info.bytes_total) - i128::from(info.bytes_current);
                    total_released_bytes += bytes;
                    roots.push(serde_json::json!({"root":root,"allocated_bytes_during_drop":info.bytes_total,"released_bytes":bytes,"released_allocations":i128::from(info.count_total)-i128::from(info.count_current)}));
                })
                .expect("fully drained native owner");
            let released = serde_json::json!({"counts_before_release":counts,"roots_in_release_order":roots,"total_released_bytes":total_released_bytes,"scope":"Rust allocations released on this thread by the closed native owner; excludes SQLite C allocations and allocator retained pages"});
            let after =
                std::fs::read_to_string("/proc/self/status").expect("RSS after native release");
            let rss = |status: &str| {
                status
                    .lines()
                    .filter(|line| {
                        line.starts_with("VmRSS:")
                            || line.starts_with("RssAnon:")
                            || line.starts_with("VmHWM:")
                    })
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            eprintln!(
                "private_wal_paced_memory_owners={}",
                serde_json::json!({"voter":voter,"before":rss(&before),"released":released,"after":rss(&after),"cold_receipt_validation_complete":true,"original_allocator":std::env::var_os("LD_PRELOAD").is_none()})
            );
        }
    }
    let mutable_path = fleet.directory.keep();
    let snapshot_path = snapshot_root.keep();
    eprintln!(
        "private_wal_paced_terminal={}",
        serde_json::json!({"measured_workload_complete": complete, "fixture_result": result.as_ref().map(|_| "ok").map_err(|panic| panic_text(panic.as_ref())), "latest_result": latest.as_ref().map(|_| "ok").map_err(|panic| panic_text(panic.as_ref())), "shutdown_result": closed.as_ref().map(|_| "ok").map_err(|panic| panic_text(panic.as_ref())), "all_receipts_result": receipts.as_ref().map(|_| "ok").map_err(|panic| panic_text(panic.as_ref())), "mutable_path": mutable_path, "snapshot_path": snapshot_path, "progress_owner_joined": true, "original_mutation_tasks_remaining": tasks.len()})
    );
    assert!(result.is_ok() && after_costs.is_ok() && latest.is_ok() && closed.is_ok() && receipts.is_ok() && complete, "private paced viability diagnostic failed; full original effects and preserved paths are in the raw evidence");
}
