//! Leader-loss timing under a live stream of fenced writes.
//!
//! One OS process per voter. A persistent V2 consumer attached to a surviving
//! voter streams sequential epoch-fenced transitions on one record. In the
//! unplanned-loss tests the elected leader is killed with SIGKILL while that
//! stream is in flight; a write retries only its own self-authenticating
//! request after a not-transmitted, unavailable, or ambiguous attempt, so the
//! SDK's exact replay contract, never a fresh request, resolves every
//! ambiguity. The contention test instead keeps every voter alive on two
//! shared CPUs and requires that no voter campaigns.

use std::collections::BTreeMap;
use std::fmt;

use opc_session_store::FencedTransitionOutcome;
use rustix::thread::{sched_getaffinity, sched_setaffinity, CpuSet, Pid};

use super::*;

/// Sequential writes committed through the stable leader before the fault.
const WARM_WRITES_BEFORE_FAULT: usize = 3;
/// Writes that must commit after the fault, through the replacement leader.
const WRITES_AFTER_FAULT: usize = 4;
/// Pause before a write retries its own retained request.
const WRITE_RETRY_PAUSE: Duration = Duration::from_millis(25);
/// Observation cap for one write. It only keeps a failing run finite and
/// reports the real stall; the documented bound below is the assertion.
const WRITE_OBSERVATION_CAP: Duration = Duration::from_secs(90);
/// Lease lifetime for the streamed record. Far above any stall under test so a
/// slow failover is reported as a stall, not as an expired lease.
const STREAM_LEASE_TTL: Duration = Duration::from_secs(600);
/// Bounded attempts for each post-run exact status readback.
const STATUS_READBACK_ATTEMPTS: usize = 40;

/// The guarantee under test: a write in flight at an unplanned leader loss
/// reaches its committed outcome inside the documented stall bound, which
/// itself must fit inside one SDK operation timeout.
fn unplanned_leader_loss_stall_bound() -> Duration {
    DURABLE_CONSENSUS_TIMING_PROFILE
        .unplanned_leader_loss_write_stall()
        .min(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout())
}

struct FencedStreamWrite {
    index: usize,
    request: FencedTransitionV2Request,
    outcome: FencedTransitionOutcome,
    issued_at: Instant,
    completed_at: Instant,
    attempts: usize,
    retries: BTreeMap<&'static str, usize>,
}

impl FencedStreamWrite {
    fn stall(&self) -> Duration {
        self.completed_at.saturating_duration_since(self.issued_at)
    }
}

impl fmt::Debug for FencedStreamWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FencedStreamWrite")
            .field("index", &self.index)
            .field("stall_millis", &self.stall().as_millis())
            .field("attempts", &self.attempts)
            .field("retries", &self.retries)
            .field(
                "committed_generation",
                &self.outcome.committed_generation().get(),
            )
            .finish()
    }
}

enum WriteAttempt {
    Committed(Box<FencedTransitionOutcome>),
    Retry(&'static str),
    Definite(String),
}

fn classify_write_attempt(
    request: &FencedTransitionV2Request,
    attempt: Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError>,
) -> WriteAttempt {
    match attempt {
        Ok(SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)))
            if outcome.matches_v2_request(request) =>
        {
            WriteAttempt::Committed(Box::new(outcome))
        }
        Ok(SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::OutcomeUnknown,
        ))) => WriteAttempt::Retry("server_outcome_unknown"),
        Ok(SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::Store(SessionConsumerStoreError::Unavailable),
        ))) => WriteAttempt::Retry("server_unavailable"),
        Ok(SessionConsumerV2Response::FencedTransitionV2(Err(
            SessionConsumerV2FencedTransitionError::Store(
                SessionConsumerStoreError::OutcomeUnavailable,
            ),
        ))) => WriteAttempt::Retry("server_outcome_unavailable"),
        Ok(SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)) => {
            WriteAttempt::Retry("rejected_unavailable")
        }
        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted { .. }) => {
            WriteAttempt::Retry("client_not_transmitted")
        }
        Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id })
            if request_id == request.request_id() =>
        {
            WriteAttempt::Retry("client_outcome_unknown")
        }
        Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable { .. }) => {
            WriteAttempt::Retry("client_read_unavailable")
        }
        other => WriteAttempt::Definite(format!("{other:?}")),
    }
}

/// Build the next transition of the single streamed record. The first write
/// acquires its lease and creates generation one; every later write renews
/// that exact lease and updates the exact generation committed before it, so a
/// write applied twice would desynchronize the chain and fail its successor.
async fn fenced_stream_request(
    member_count: usize,
    index: usize,
    previous: Option<&FencedTransitionOutcome>,
) -> FencedTransitionV2Request {
    let key = qualification_fenced_transition_key(0x1037);
    let owner = OwnerId::new("unplanned-leader-loss-stream-owner").expect("stream owner");
    let (lease, generation, expected_generation) = match previous {
        None => (
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                STREAM_LEASE_TTL,
            )
            .expect("stream acquire action"),
            Generation::new(1),
            None,
        ),
        Some(previous) => (
            FencedTransitionLease::renew(previous.lease().clone(), STREAM_LEASE_TTL)
                .expect("stream renew action"),
            previous
                .committed_generation()
                .next()
                .expect("bounded stream generation"),
            Some(previous.committed_generation()),
        ),
    };
    let mut record = StoredSessionRecord {
        key,
        generation,
        owner,
        fence: lease.committed_fence().expect("stream committed fence"),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("qualification-unplanned-leader-loss"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(format!("unplanned-leader-loss-{index}")),
    };
    seal_qualification_consensus_record(member_count, &mut record).await;
    let mutation = match expected_generation {
        None => FencedTransitionMutation::create(record),
        Some(expected) => FencedTransitionMutation::update(expected, record),
    };
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&0x1037_u64.to_be_bytes());
    nonce[8..].copy_from_slice(&(index as u64).to_be_bytes());
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("initial stream V2 epoch"),
        FencedTransitionV2CallerNonce::from_bytes(nonce),
        lease,
        mutation,
    )
    .expect("self-authenticating stream V2 request")
}

/// Shared progress between the writer task and the fault-injecting thread.
#[derive(Default)]
struct StreamProgress {
    committed: AtomicUsize,
    fault_at: Mutex<Option<Instant>>,
    stop: AtomicBool,
}

impl StreamProgress {
    fn fault_at(&self) -> Option<Instant> {
        *self
            .fault_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Stream sequential fenced writes until enough have committed after the
/// fault. Returns every committed write, or the committed prefix and the
/// first failure.
async fn stream_fenced_writes(
    client: PersistentSessionConsumerClient,
    scope: SessionConsumerScope,
    member_count: usize,
    progress: Arc<StreamProgress>,
) -> Result<Vec<FencedStreamWrite>, (Vec<FencedStreamWrite>, String)> {
    let mut writes: Vec<FencedStreamWrite> = Vec::new();
    loop {
        if progress.stop.load(Ordering::SeqCst) {
            return Ok(writes);
        }
        if let Some(fault_at) = progress.fault_at() {
            let committed_after_fault = writes
                .iter()
                .filter(|write| write.completed_at > fault_at)
                .count();
            if committed_after_fault >= WRITES_AFTER_FAULT {
                return Ok(writes);
            }
        }
        let index = writes.len();
        let request = fenced_stream_request(
            member_count,
            index,
            writes.last().map(|write| &write.outcome),
        )
        .await;
        let execute = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(request.clone()),
            },
        );
        let issued_at = Instant::now();
        let mut attempts = 0;
        let mut retries = BTreeMap::new();
        let outcome = loop {
            attempts += 1;
            match classify_write_attempt(&request, client.execute_v2(&execute).await) {
                WriteAttempt::Committed(outcome) => break *outcome,
                WriteAttempt::Retry(class) => *retries.entry(class).or_insert(0) += 1,
                WriteAttempt::Definite(response) => {
                    return Err((
                        writes,
                        format!(
                            "write {index} ended with an unexpected definite response after \
                             {attempts} attempts: {response}"
                        ),
                    ));
                }
            }
            if issued_at.elapsed() >= WRITE_OBSERVATION_CAP {
                return Err((
                    writes,
                    format!(
                        "write {index} did not commit within the {}s observation cap \
                         ({attempts} attempts, retries {retries:?})",
                        WRITE_OBSERVATION_CAP.as_secs()
                    ),
                ));
            }
            tokio::time::sleep(WRITE_RETRY_PAUSE).await;
        };
        writes.push(FencedStreamWrite {
            index,
            request,
            outcome,
            issued_at,
            completed_at: Instant::now(),
            attempts,
            retries,
        });
        progress.committed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Wait for two identical all-voter observations of one ready leader, term,
/// and fully applied log head, so the fault lands on a settled cluster.
fn settled_leader_reports(fleet: &mut Fleet) -> Vec<FleetReadiness> {
    let all_nodes = (0..fleet.member_count()).collect::<Vec<_>>();
    let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    let mut previous = None;
    loop {
        let reports = fleet.readiness_reports(&all_nodes);
        let first = reports[0];
        let settled = first.ready
            && first.leader_id.is_some()
            && first.committed_index.is_some()
            && first.committed_index == first.applied_index
            && reports.iter().all(|report| {
                report.ready
                    && report.reason_code == QualificationReadinessCode::Ready
                    && report.term == first.term
                    && report.leader_id == first.leader_id
                    && report.committed_index == first.committed_index
                    && report.applied_index == first.applied_index
            });
        let signature = settled.then_some((first.term, first.leader_id, first.committed_index));
        if signature.is_some() && signature == previous {
            return reports;
        }
        previous = signature;
        assert!(
            Instant::now() < deadline,
            "fleet did not settle one leader before the fault: reports={reports:?}"
        );
        thread::sleep(DURABLE_CONSENSUS_TIMING_PROFILE.engine_tick());
    }
}

fn leader_node_index(reports: &[FleetReadiness]) -> usize {
    reports
        .iter()
        .find(|report| report.leader_id == Some(report.node_id))
        .map(|report| report.node_index)
        .expect("settled fleet has one leader")
}

fn run_unplanned_leader_loss_fenced_write_stream(member_count: usize) {
    let mut fleet = Fleet::start(member_count);
    let consumer_identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let consumer_identity = consumer_identities[0].clone();
    let mut endpoints = Vec::with_capacity(member_count);
    let mut scope = None;
    for node_index in 0..member_count {
        let (endpoint, node_scope) =
            fleet.start_stateless_consumer(node_index, consumer_identities.clone());
        assert!(
            scope.is_none_or(|expected| expected == node_scope),
            "every voter must serve the same consumer scope"
        );
        scope = Some(node_scope);
        endpoints.push(endpoint);
    }
    let scope = scope.expect("one consumer scope per fleet");
    let voter_authorities = fleet.stateless_consumer_voter_authorities();

    let before_fault = settled_leader_reports(&mut fleet);
    let old_term = before_fault[0].term;
    let old_leader_id = before_fault[0].leader_id.expect("settled leader identity");
    let leader = leader_node_index(&before_fault);
    // Attach the consumer to a surviving voter: the measured stall is then the
    // consensus failover itself, not the consumer's own voter selection.
    let writer_voter = (0..member_count)
        .find(|node_index| *node_index != leader)
        .expect("a surviving follower");

    let (_identity_source, identity_receiver) =
        watch::channel(Some(fleet.pki.consumer_identity_state(&consumer_identity)));
    let tls = TlsConfigBuilder::new(identity_receiver)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("stream consumer mTLS configuration");
    let client = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new(
            endpoints[writer_voter],
            rustls_pki_types::ServerName::IpAddress(endpoints[writer_voter].ip().into()),
            voter_authorities[writer_voter].clone(),
            tls,
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("fixed persistent stream consumer configuration");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("unplanned leader-loss consumer runtime");
    runtime
        .block_on(client.prewarm_v2())
        .expect("prewarm the stream consumer");
    assert_eq!(
        runtime
            .block_on(client.execute_v2(&SessionConsumerV2Request::new(
                scope,
                SessionConsumerV2Operation::FencedTransitionV2Capability,
            )))
            .expect("V2 capability response"),
        SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2
        )),
    );

    let progress = Arc::new(StreamProgress::default());
    let writer = runtime.spawn(stream_fenced_writes(
        client.clone(),
        scope,
        member_count,
        Arc::clone(&progress),
    ));
    let warm_deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
    while progress.committed.load(Ordering::SeqCst) < WARM_WRITES_BEFORE_FAULT {
        assert!(
            !writer.is_finished() && Instant::now() < warm_deadline,
            "the stream did not commit its warm writes through the stable leader"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let fault_at = Instant::now();
    *progress
        .fault_at
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fault_at);
    let _ = fleet.kill_node_unclean(leader);

    let writes = match runtime.block_on(writer).expect("stream task joins") {
        Ok(writes) => writes,
        Err((writes, failure)) => panic!(
            "{member_count}-voter fenced stream failed across an unplanned leader loss: \
             {failure}; fault after write {}; committed writes: {writes:#?}",
            WARM_WRITES_BEFORE_FAULT
        ),
    };

    let bound = unplanned_leader_loss_stall_bound();
    let first_after_fault = writes
        .iter()
        .find(|write| write.completed_at > fault_at)
        .expect("a write commits after the fault");
    let outage = first_after_fault
        .completed_at
        .saturating_duration_since(fault_at);
    let slowest = writes
        .iter()
        .max_by_key(|write| write.stall())
        .expect("nonempty stream");
    let survivors = (0..member_count)
        .filter(|node_index| *node_index != leader)
        .collect::<Vec<_>>();
    let after_fault = fleet.readiness_reports(&survivors);
    eprintln!(
        "unplanned leader loss: voters={member_count} old_term={old_term} \
         new_terms={:?} outage_ms={} slowest_write={} slowest_stall_ms={} \
         slowest_attempts={} slowest_retries={:?} bound_ms={} \
         first_campaign_bound_ms={}",
        after_fault
            .iter()
            .map(|report| report.term)
            .collect::<Vec<_>>(),
        outage.as_millis(),
        slowest.index,
        slowest.stall().as_millis(),
        slowest.attempts,
        slowest.retries,
        bound.as_millis(),
        DURABLE_CONSENSUS_TIMING_PROFILE
            .leader_loss_first_campaign_bound()
            .as_millis(),
    );

    // Exactly one application per write: the sequential chain advances one
    // generation per committed request, under one unchanged lease fence.
    let fence = writes[0].outcome.lease().fence();
    for (position, write) in writes.iter().enumerate() {
        assert_eq!(write.index, position);
        assert_eq!(
            write.outcome.committed_generation(),
            Generation::new(position as u64 + 1),
            "write {position} must commit exactly the next generation"
        );
        assert_eq!(write.outcome.lease().fence(), fence);
    }
    // Every write's exact retained receipt matches the outcome it returned.
    for write in &writes {
        let status = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: Box::new(write.request.clone()),
            },
        );
        let expected = SessionConsumerV2Response::FencedTransitionV2Status(Ok(
            SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Ok(write.outcome.clone()))),
        ));
        let observed = (0..STATUS_READBACK_ATTEMPTS)
            .find_map(|_| match runtime.block_on(client.execute_v2(&status)) {
                Ok(response) => Some(response),
                Err(_) => {
                    thread::sleep(WRITE_RETRY_PAUSE);
                    None
                }
            })
            .expect("exact status readback");
        assert_eq!(
            observed, expected,
            "write {} has exactly its own committed receipt",
            write.index
        );
    }
    assert!(
        after_fault.iter().all(|report| {
            report.ready
                && report.term > old_term
                && report
                    .leader_id
                    .is_some_and(|leader| leader != old_leader_id)
        }),
        "survivors serve a replacement leader in a later term: {after_fault:?}"
    );

    // The documented guarantee: the leader-loss outage, and every write in the
    // stream, stay inside the stall bound, itself inside one operation timeout.
    assert!(
        outage <= bound,
        "{member_count}-voter outage after an unplanned leader loss was {}ms, above the \
         documented {}ms bound: {writes:#?}",
        outage.as_millis(),
        bound.as_millis()
    );
    for write in &writes {
        assert!(
            write.stall() <= bound,
            "{member_count}-voter write {} stalled {}ms across an unplanned leader loss, above \
             the documented {}ms bound: {writes:#?}",
            write.index,
            write.stall().as_millis(),
            bound.as_millis()
        );
    }
}

#[test]
fn three_process_projected_mtls_unplanned_leader_loss_fenced_write_stream() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_unplanned_leader_loss_fenced_write_stream(3);
}

#[test]
fn five_process_projected_mtls_unplanned_leader_loss_fenced_write_stream() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_unplanned_leader_loss_fenced_write_stream(5);
}

/// The two lowest-numbered CPUs this test process may run on.
fn contended_cpu_set() -> (CpuSet, usize) {
    let allowed = sched_getaffinity(None).expect("read this process's CPU affinity");
    let mut cpus = CpuSet::new();
    let mut count = 0;
    for cpu in 0..CpuSet::MAX_CPU {
        if allowed.is_set(cpu) {
            cpus.set(cpu);
            count += 1;
            if count == 2 {
                break;
            }
        }
    }
    assert!(count > 0, "this process may run on at least one CPU");
    (cpus, count)
}

/// Confine every thread of one voter process to `cpus`. A thread the voter
/// creates later inherits the mask of its pinned creator; a second pass
/// covers a thread created while the first pass ran.
fn pin_voter_threads(process_id: u32, cpus: &CpuSet) {
    for _ in 0..2 {
        let tasks =
            fs::read_dir(format!("/proc/{process_id}/task")).expect("list the voter's threads");
        for task in tasks {
            let Some(thread_id) = task
                .expect("voter thread entry")
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .and_then(Pid::from_raw)
            else {
                continue;
            };
            // A thread that exits between listing and pinning needs no mask.
            let _ = sched_setaffinity(Some(thread_id), cpus);
        }
    }
}

/// Spinning threads that share the voters' CPUs for the observation window.
struct CpuHogs {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl CpuHogs {
    fn start(cpus: &CpuSet, count: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let threads = (0..count)
            .map(|_| {
                let stop = Arc::clone(&stop);
                let cpus = *cpus;
                thread::spawn(move || {
                    sched_setaffinity(None, &cpus).expect("pin a CPU hog");
                    while !stop.load(Ordering::Relaxed) {
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();
        Self { stop, threads }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for hog in self.threads {
            hog.join().expect("CPU hog exits");
        }
    }
}

/// A healthy fleet whose voters share two CPUs with spinning threads must
/// keep its leader and term for several election windows while it serves a
/// stream of fenced writes. Contention delays every task but suspends none,
/// so the voters keep hearing heartbeats well inside their campaign window.
fn run_healthy_fleet_keeps_its_leader_under_cpu_contention(member_count: usize) {
    let mut fleet = Fleet::start(member_count);
    let consumer_identities = (0..12).map(stateless_consumer_identity).collect::<Vec<_>>();
    let consumer_identity = consumer_identities[0].clone();
    let mut endpoints = Vec::with_capacity(member_count);
    let mut scope = None;
    for node_index in 0..member_count {
        let (endpoint, node_scope) =
            fleet.start_stateless_consumer(node_index, consumer_identities.clone());
        assert!(
            scope.is_none_or(|expected| expected == node_scope),
            "every voter must serve the same consumer scope"
        );
        scope = Some(node_scope);
        endpoints.push(endpoint);
    }
    let scope = scope.expect("one consumer scope per fleet");
    let voter_authorities = fleet.stateless_consumer_voter_authorities();
    let before = settled_leader_reports(&mut fleet);
    let term = before[0].term;
    let leader_id = before[0].leader_id.expect("settled leader identity");
    let leader = leader_node_index(&before);
    let writer_voter = (0..member_count)
        .find(|node_index| *node_index != leader)
        .expect("a follower");

    let (_identity_source, identity_receiver) =
        watch::channel(Some(fleet.pki.consumer_identity_state(&consumer_identity)));
    let tls = TlsConfigBuilder::new(identity_receiver)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("stream consumer mTLS configuration");
    let client = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new(
            endpoints[writer_voter],
            rustls_pki_types::ServerName::IpAddress(endpoints[writer_voter].ip().into()),
            voter_authorities[writer_voter].clone(),
            tls,
        ),
        PersistentSessionConsumerConfig::default(),
    )
    .expect("fixed persistent stream consumer configuration");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("CPU contention consumer runtime");
    runtime
        .block_on(client.prewarm_v2())
        .expect("prewarm the stream consumer");

    let (cpus, cpu_count) = contended_cpu_set();
    for node in &fleet.nodes {
        pin_voter_threads(node.process_id(), &cpus);
    }
    let hogs = CpuHogs::start(&cpus, cpu_count * 2);
    let progress = Arc::new(StreamProgress::default());
    let writer = runtime.spawn(stream_fenced_writes(
        client.clone(),
        scope,
        member_count,
        Arc::clone(&progress),
    ));
    // Three complete campaign windows of continuous contention.
    let window = DURABLE_CONSENSUS_TIMING_PROFILE.leader_loss_first_campaign_bound() * 3;
    thread::sleep(window);
    progress.stop.store(true, Ordering::SeqCst);
    let writes = runtime.block_on(writer).expect("stream task joins");
    hogs.stop();
    let writes = writes.unwrap_or_else(|(writes, failure)| {
        panic!("the contended stream failed: {failure}; committed writes: {writes:#?}")
    });
    let slowest = writes
        .iter()
        .map(FencedStreamWrite::stall)
        .max()
        .unwrap_or_default();

    let after = fleet.readiness_reports(&(0..member_count).collect::<Vec<_>>());
    eprintln!(
        "CPU contention: voters={member_count} cpus={cpu_count} hogs={} window_ms={} \
         writes={} slowest_write_ms={} terms={:?}",
        cpu_count * 2,
        window.as_millis(),
        writes.len(),
        slowest.as_millis(),
        after.iter().map(|report| report.term).collect::<Vec<_>>(),
    );
    assert!(
        !writes.is_empty(),
        "the contended fleet must keep committing fenced writes"
    );
    assert!(
        after.iter().all(|report| report.ready
            && report.term == term
            && report.leader_id == Some(leader_id)),
        "no voter may campaign while its leader is healthy: before term {term}, after {after:?}"
    );
}

#[test]
fn three_process_projected_mtls_healthy_fleet_keeps_its_leader_under_cpu_contention() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_healthy_fleet_keeps_its_leader_under_cpu_contention(3);
}
