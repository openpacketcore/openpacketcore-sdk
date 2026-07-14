#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::net::SocketAddr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_identity::projected_svid::MIN_PROJECTED_SVID_POLL_INTERVAL;
use opc_identity::{
    build_identity_state, parse_certs_pem, parse_key_pem, IdentityState, TrustBundle,
    TrustBundleSet, TrustDomain,
};
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId,
    SessionConfigurationEpoch, SessionConfigurationGeneration, SessionReplicationManifest,
    DEFAULT_MAX_AUTHENTICATION_AGE, DEFAULT_RECONNECT_BACKOFF_MAX, DEFAULT_RECONNECT_BACKOFF_MIN,
    DEFAULT_ROTATION_DRAIN_WINDOW, DEFAULT_ROTATION_JITTER,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusWireRequest,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_traffic_schedule_sha256, qualification_traffic_seed,
    qualification_traffic_value, qualification_value_sha256, read_bounded_json_line,
    write_json_line, QualificationConnectionLifecycleConfig,
    QualificationConnectionLifecycleMetrics, QualificationMember, QualificationNodeCommand,
    QualificationNodeConfig, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationProjectedMtlsConfig, QualificationProjectedSvidAvailability,
    QualificationProjectedSvidStatus, QualificationReadinessCode,
    QualificationTlsMaterialAvailability, QualificationTlsMaterialStatus,
    QualificationTrafficState, QualificationTrafficStatus, QualificationTransportConfig,
    QUALIFICATION_INBOUND_CONNECTION_SLOTS, QUALIFICATION_NODE_SCHEMA_VERSION,
    QUALIFICATION_OPERATION_TIMEOUT_MILLIS, QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS,
    QUALIFICATION_RESOLVER_PROOF_MILLIS, QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE,
    QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE, QUALIFICATION_RESOURCE_SAMPLE_MILLIS,
    QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB, QUALIFICATION_RESOURCE_SETTLE_MILLIS,
    QUALIFICATION_RESOURCE_STABLE_SAMPLES, QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE,
    QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB, QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR,
    QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE,
    QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR,
    QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND, QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER,
    QUALIFICATION_TRAFFIC_TRANSITION_MILLIS,
};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use tempfile::TempDir;
use tokio::sync::watch;

use opc_tls::TlsConfigBuilder;

const CLUSTER_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
);
const CHILD_TIMEOUT: Duration =
    Duration::from_millis(DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout_millis);
const CANARY_TTL_MILLIS: u64 = 60 * 60 * 1_000;
const CANARY_STABLE_ID: &str = "rotation-core-canary";
const CANARY_LEASE_HANDLE: &str = "rotation-core-lease";
const CANARY_OWNER: &str = "rotation-core-owner";
const ROTATION_PLAINTEXT_CANARY_PREFIX: &[u8] = b"opc-rotation-plaintext-canary/";
const TRAFFIC_PLAINTEXT_CANARY_PREFIX: &[u8] = b"opc-rotation-traffic-canary/";
const PLAINTEXT_CANARY_PREFIXES: [&[u8]; 2] = [
    ROTATION_PLAINTEXT_CANARY_PREFIX,
    TRAFFIC_PLAINTEXT_CANARY_PREFIX,
];

static FLEET_TEST_LOCK: Mutex<()> = Mutex::new(());

fn single_attempt_removed_root_probe_lifecycle() -> ConnectionLifecyclePolicy {
    let cold_connect_timeout = DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    ConnectionLifecyclePolicy::try_new(
        DEFAULT_MAX_AUTHENTICATION_AGE,
        DEFAULT_ROTATION_DRAIN_WINDOW,
        cold_connect_timeout,
        cold_connect_timeout,
        Duration::ZERO,
    )
    .expect("single-attempt removed-root probe lifecycle policy")
}

struct Issuer {
    certificate: Certificate,
    key: KeyPair,
}

#[derive(Debug, Clone, Copy)]
struct ProcessResourceSnapshot {
    file_descriptors: usize,
    socket_file_descriptors: usize,
    nontransport_file_descriptors: usize,
    threads: usize,
    vm_rss_kib: u64,
    vm_hwm_kib: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProcessResourceHighWater {
    samples: u64,
    file_descriptors: usize,
    threads: usize,
    vm_hwm_kib: u64,
}

struct ResourceSampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<io::Result<Vec<ProcessResourceHighWater>>>,
}

impl ResourceSampler {
    fn start(process_ids: Vec<u32>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("qualification-resource-sampler".to_owned())
            .spawn(move || {
                let mut high_water = vec![
                    ProcessResourceHighWater {
                        samples: 0,
                        file_descriptors: 0,
                        threads: 0,
                        vm_hwm_kib: 0,
                    };
                    process_ids.len()
                ];
                loop {
                    for (index, process_id) in process_ids.iter().copied().enumerate() {
                        let snapshot = read_process_resources(process_id, false)?;
                        let current = &mut high_water[index];
                        current.samples = current.samples.saturating_add(1);
                        current.file_descriptors =
                            current.file_descriptors.max(snapshot.file_descriptors);
                        current.threads = current.threads.max(snapshot.threads);
                        current.vm_hwm_kib = current.vm_hwm_kib.max(snapshot.vm_hwm_kib);
                    }
                    if stop_for_thread.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(QUALIFICATION_RESOURCE_SAMPLE_MILLIS));
                }
                Ok(high_water)
            })
            .expect("start qualification resource sampler");
        Self { stop, handle }
    }

    fn finish(self) -> Vec<ProcessResourceHighWater> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .join()
            .expect("join qualification resource sampler")
            .expect("sample live qualification processes")
    }
}

fn read_process_resources(
    process_id: u32,
    classify_file_descriptors: bool,
) -> io::Result<ProcessResourceSnapshot> {
    let process_root = PathBuf::from(format!("/proc/{process_id}"));
    let descriptor_directory = process_root.join("fd");
    let mut file_descriptors = 0_usize;
    let mut socket_file_descriptors = 0_usize;
    let mut nontransport_file_descriptors = 0_usize;
    for entry in fs::read_dir(&descriptor_directory)? {
        let entry = entry?;
        file_descriptors = file_descriptors.saturating_add(1);
        if classify_file_descriptors {
            let target = fs::read_link(entry.path())?;
            if target.to_string_lossy().starts_with("socket:[") {
                socket_file_descriptors = socket_file_descriptors.saturating_add(1);
            } else {
                nontransport_file_descriptors = nontransport_file_descriptors.saturating_add(1);
            }
        }
    }
    let threads = fs::read_dir(process_root.join("task"))?
        .collect::<Result<Vec<_>, _>>()?
        .len();
    let status = fs::read_to_string(process_root.join("status"))?;
    let vm_rss_kib = parse_status_kib(&status, "VmRSS:")?;
    let vm_hwm_kib = parse_status_kib(&status, "VmHWM:")?;
    Ok(ProcessResourceSnapshot {
        file_descriptors,
        socket_file_descriptors,
        nontransport_file_descriptors,
        threads,
        vm_rss_kib,
        vm_hwm_kib,
    })
}

fn read_classified_process_resources(process_id: u32) -> ProcessResourceSnapshot {
    let mut last_error = None;
    for _ in 0..5 {
        match read_process_resources(process_id, true) {
            Ok(snapshot) => return snapshot,
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    panic!(
        "failed to classify qualification process resources: process_id={process_id}, error={:?}",
        last_error
    );
}

fn parse_status_kib(status: &str, field: &str) -> io::Result<u64> {
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing process status field")
        })?;
    let mut values = line[field.len()..].split_whitespace();
    let value = values
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid process status value")
        })?;
    if values.next() != Some("kB") || values.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid process status unit",
        ));
    }
    Ok(value)
}

fn assert_completed_traffic_cycles(status: &QualificationTrafficStatus) {
    assert!(status.mutation_cycles >= 1);
    assert_eq!(status.linearizable_reads, status.mutation_cycles);
    assert_eq!(status.lease_renewals, status.mutation_cycles);
    assert_eq!(status.lease_reacquisitions, status.mutation_cycles);
    assert_eq!(status.complete_restore_scans, status.mutation_cycles);
    assert_eq!(status.durable_readiness_probes, status.mutation_cycles);
    assert_eq!(status.last_generation, status.mutation_cycles);
    assert!(status.last_record_fence >= 1);
    assert!(status.watch_entries >= 1);
    assert!(status.watch_applied_records >= 1);
    assert!(matches!(status.watch_traffic_generations.len(), 3 | 5));
}

fn traffic_status_made_semantic_progress(
    before: &QualificationTrafficStatus,
    after: &QualificationTrafficStatus,
    member_count: usize,
) -> bool {
    before.watch_traffic_generations.len() == member_count
        && after.watch_traffic_generations.len() == member_count
        && after.mutation_cycles > before.mutation_cycles
        && after.watch_entries > before.watch_entries
        && after.watch_applied_records > before.watch_applied_records
        && after.watch_sequence > before.watch_sequence
        && after
            .watch_traffic_generations
            .iter()
            .zip(&before.watch_traffic_generations)
            .all(|(after, before)| after > before)
}

fn traffic_stable_id(node_index: usize) -> String {
    format!("rotation-traffic-{node_index}")
}

fn traffic_owner(node_index: usize) -> String {
    format!("rotation-traffic-owner-{node_index}")
}

fn assert_round_lifecycle_bounds(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
) {
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    let required_successes = u64::try_from(QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND)
        .expect("bounded generation count")
        .saturating_mul(remote_peers);
    assert_lifecycle_delta_bounds(member_count, before, after, required_successes);
}

fn assert_lifecycle_delta_bounds(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    minimum_successes_per_node: u64,
) {
    let expected_authentication_failures = vec![0; member_count];
    assert_lifecycle_delta_bounds_with_authentication(
        member_count,
        before,
        after,
        minimum_successes_per_node,
        &expected_authentication_failures,
    );
}

fn assert_lifecycle_delta_bounds_with_authentication(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
    minimum_successes_per_node: u64,
    expected_authentication_failures: &[u64],
) {
    assert_eq!(before.len(), member_count);
    assert_eq!(after.len(), member_count);
    assert_eq!(expected_authentication_failures.len(), member_count);
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    let bound = QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR
        .saturating_mul(remote_peers)
        .saturating_add(QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE);
    for (node_index, ((before, after), expected_authentication_failures)) in before
        .iter()
        .zip(after)
        .zip(expected_authentication_failures)
        .enumerate()
    {
        let attempts = lifecycle_counter_delta(
            before.connection_attempts,
            after.connection_attempts,
            node_index,
            "connection_attempts",
        );
        let successes = lifecycle_counter_delta(
            before.connection_successes,
            after.connection_successes,
            node_index,
            "connection_successes",
        );
        let reconnect_attempts = lifecycle_counter_delta(
            before.reconnect_attempts,
            after.reconnect_attempts,
            node_index,
            "reconnect_attempts",
        );
        let idle_retirements = lifecycle_counter_delta(
            before.retirement_idle_timeout,
            after.retirement_idle_timeout,
            node_index,
            "retirement_idle_timeout",
        );
        assert!(
            attempts <= bound,
            "connection-attempt bound exceeded: node={node_index}, attempts={attempts}, bound={bound}"
        );
        assert!(
            reconnect_attempts <= bound,
            "reconnect-attempt bound exceeded: node={node_index}, reconnect_attempts={reconnect_attempts}, bound={bound}"
        );
        assert!(
            idle_retirements <= bound,
            "authenticated idle-retirement bound exceeded: node={node_index}, idle_retirements={idle_retirements}, bound={bound}"
        );
        // A complete authenticated bootstrap-retirement control is a
        // successful attempt and is retried before Openraft bytes are sent.
        // Zero classified failures plus exact cumulative outstanding-handler
        // accounting are the fleet regression for the pre-admission rotation
        // race fixed by #223. A live inbound persistent handler records its
        // success only when it closes, so interval attempt/success deltas are
        // intentionally not required to be equal.
        assert_connection_attempts_accounted(after, node_index);
        assert!(
            lifecycle_transition_is_settled(after, member_count),
            "connection lifecycle did not settle inside the transition: node={node_index}, metrics={after:?}"
        );
        assert!(
            successes >= minimum_successes_per_node,
            "fresh reauthentication lacked successful connections: node={node_index}, successes={successes}, required={minimum_successes_per_node}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_transport,
                after.connection_failure_transport,
                node_index,
                "connection_failure_transport",
            ),
            0,
            "transport-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_authentication,
                after.connection_failure_authentication,
                node_index,
                "connection_failure_authentication",
            ),
            *expected_authentication_failures,
            "authentication-failure ledger mismatch: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_timeout,
                after.connection_failure_timeout,
                node_index,
                "connection_failure_timeout",
            ),
            0,
            "timeout-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_protocol,
                after.connection_failure_protocol,
                node_index,
                "connection_failure_protocol",
            ),
            0,
            "protocol-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_backend,
                after.connection_failure_backend,
                node_index,
                "connection_failure_backend",
            ),
            0,
            "backend-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.reconnect_failures,
                after.reconnect_failures,
                node_index,
                "reconnect_failures",
            ),
            0,
            "reconnect-failure budget exceeded: node={node_index}"
        );
        assert_eq!(
            lifecycle_counter_delta(
                before.drain_overruns,
                after.drain_overruns,
                node_index,
                "drain_overruns",
            ),
            0,
            "drain-overrun budget exceeded: node={node_index}"
        );
    }
}

fn lifecycle_counter_delta(before: u64, after: u64, node_index: usize, counter: &str) -> u64 {
    after.checked_sub(before).unwrap_or_else(|| {
        panic!(
            "lifecycle counter regressed: node={node_index}, counter={counter}, before={before}, after={after}"
        )
    })
}

fn lifecycle_active_connection_bound(member_count: usize) -> i64 {
    QUALIFICATION_TRAFFIC_ACTIVE_CONNECTION_FACTOR
        .saturating_mul(i64::try_from(member_count - 1).expect("bounded member count"))
}

fn lifecycle_transition_is_settled(
    metrics: &QualificationConnectionLifecycleMetrics,
    member_count: usize,
) -> bool {
    let active_bound = lifecycle_active_connection_bound(member_count);
    metrics.active_connections >= 0
        && metrics.active_connections <= active_bound
        && metrics.draining_connections == 0
        && metrics.drain_started == metrics.drain_completed
        && metrics.drain_overruns == 0
        && connection_attempts_accounted(metrics)
}

fn deadline_allows_completion(now: Instant, deadline: Instant) -> bool {
    now <= deadline
}

fn assert_transition_completed_by(started: Instant, deadline: Instant, phase: &str) {
    let now = Instant::now();
    assert!(
        deadline_allows_completion(now, deadline),
        "qualification transition exceeded its absolute fail-safe: phase={phase}, elapsed={:?}",
        now.duration_since(started)
    );
}

fn removed_root_authentication_failure_budget(member_count: usize) -> Vec<u64> {
    let mut expected = vec![0_u64; member_count];
    for source in 0..member_count {
        expected[(source + 1) % member_count] += 1;
    }
    expected
}

fn assert_campaign_lifecycle_failure_ledger(
    member_count: usize,
    before: &[QualificationConnectionLifecycleMetrics],
    after: &[QualificationConnectionLifecycleMetrics],
) {
    assert_eq!(before.len(), member_count);
    assert_eq!(after.len(), member_count);
    let expected_authentication_failures = removed_root_authentication_failure_budget(member_count);
    for (node_index, ((before, after), expected_authentication_failures)) in before
        .iter()
        .zip(after)
        .zip(&expected_authentication_failures)
        .enumerate()
    {
        assert_connection_attempts_accounted(after, node_index);
        assert!(
            lifecycle_transition_is_settled(after, member_count),
            "campaign final lifecycle state is not settled: node={node_index}, metrics={after:?}"
        );
        for (counter, before, after) in [
            (
                "connection_failure_transport",
                before.connection_failure_transport,
                after.connection_failure_transport,
            ),
            (
                "connection_failure_timeout",
                before.connection_failure_timeout,
                after.connection_failure_timeout,
            ),
            (
                "connection_failure_protocol",
                before.connection_failure_protocol,
                after.connection_failure_protocol,
            ),
            (
                "connection_failure_backend",
                before.connection_failure_backend,
                after.connection_failure_backend,
            ),
            (
                "reconnect_failures",
                before.reconnect_failures,
                after.reconnect_failures,
            ),
            (
                "drain_overruns",
                before.drain_overruns,
                after.drain_overruns,
            ),
        ] {
            assert_eq!(
                lifecycle_counter_delta(before, after, node_index, counter),
                0,
                "campaign-wide zero-failure ledger rejected {counter}: node={node_index}"
            );
        }
        assert_eq!(
            lifecycle_counter_delta(
                before.connection_failure_authentication,
                after.connection_failure_authentication,
                node_index,
                "connection_failure_authentication",
            ),
            *expected_authentication_failures,
            "campaign authentication ledger must contain exactly the deliberate removed-root ring probe: node={node_index}"
        );
    }
}

fn assert_connection_attempts_accounted(
    metrics: &QualificationConnectionLifecycleMetrics,
    node_index: usize,
) {
    let Some((terminal, outstanding, live_handlers)) = connection_attempt_accounting(metrics)
    else {
        panic!("connection accounting overflow/underflow: node={node_index}, metrics={metrics:?}");
    };
    assert_eq!(
        metrics.connection_attempts,
        terminal + outstanding,
        "connection conservation equation failed: node={node_index}"
    );
    assert!(
        outstanding <= live_handlers,
        "connection attempts lacked a terminal outcome or live handler: node={node_index}, outstanding={outstanding}, live_handlers={live_handlers}, metrics={metrics:?}"
    );
}

fn connection_attempts_accounted(metrics: &QualificationConnectionLifecycleMetrics) -> bool {
    connection_attempt_accounting(metrics)
        .is_some_and(|(_, outstanding, live_handlers)| outstanding <= live_handlers)
}

fn connection_attempt_accounting(
    metrics: &QualificationConnectionLifecycleMetrics,
) -> Option<(u64, u64, u64)> {
    let terminal = metrics
        .connection_successes
        .checked_add(metrics.connection_failure_transport)?
        .checked_add(metrics.connection_failure_authentication)?
        .checked_add(metrics.connection_failure_timeout)?
        .checked_add(metrics.connection_failure_protocol)?
        .checked_add(metrics.connection_failure_backend)?;
    let outstanding = metrics.connection_attempts.checked_sub(terminal)?;
    let live_handlers = u64::try_from(
        metrics
            .active_connections
            .saturating_add(metrics.draining_connections)
            .max(0),
    )
    .ok()?;
    Some((terminal, outstanding, live_handlers))
}

fn assert_process_resource_bounds(
    member_count: usize,
    warmed: &[ProcessResourceSnapshot],
    high_water: &[ProcessResourceHighWater],
    settled: &[ProcessResourceSnapshot],
) {
    assert_eq!(warmed.len(), member_count);
    assert_eq!(high_water.len(), member_count);
    assert_eq!(settled.len(), member_count);
    for (node_index, ((warmed, high_water), settled)) in
        warmed.iter().zip(high_water).zip(settled).enumerate()
    {
        assert!(high_water.samples >= 1);
        let file_descriptor_bound = warmed
            .nontransport_file_descriptors
            .saturating_add(QUALIFICATION_INBOUND_CONNECTION_SLOTS)
            .saturating_add(member_count - 1)
            .saturating_add(QUALIFICATION_RESOURCE_FD_MISC_ALLOWANCE);
        assert!(
            high_water.file_descriptors <= file_descriptor_bound,
            "FD high-water bound exceeded: node={node_index}, high_water={}, bound={file_descriptor_bound}, warmed={warmed:?}",
            high_water.file_descriptors
        );
        assert!(
            settled.file_descriptors
                <= warmed
                    .file_descriptors
                    .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE),
            "settled FD bound exceeded: node={node_index}, settled={}, warmed={}",
            settled.file_descriptors,
            warmed.file_descriptors
        );
        assert!(
            settled.socket_file_descriptors
                <= warmed
                    .socket_file_descriptors
                    .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE),
            "settled socket-FD bound exceeded: node={node_index}, settled={}, warmed={}",
            settled.socket_file_descriptors,
            warmed.socket_file_descriptors
        );
        assert!(
            high_water.threads
                <= warmed
                    .threads
                    .saturating_add(QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE),
            "thread high-water bound exceeded: node={node_index}, high_water={}, warmed={}",
            high_water.threads,
            warmed.threads
        );
        assert!(
            high_water.vm_hwm_kib
                <= warmed
                    .vm_hwm_kib
                    .saturating_add(QUALIFICATION_RESOURCE_VMHWM_GROWTH_KIB),
            "VmHWM growth bound exceeded: node={node_index}, high_water_kib={}, warmed_kib={}",
            high_water.vm_hwm_kib,
            warmed.vm_hwm_kib
        );
        assert!(
            settled.vm_rss_kib
                <= warmed
                    .vm_rss_kib
                    .saturating_add(QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB),
            "settled VmRSS growth bound exceeded: node={node_index}, settled_kib={}, warmed_kib={}",
            settled.vm_rss_kib,
            warmed.vm_rss_kib
        );
    }
}

impl Issuer {
    fn root(common_name: &str) -> Self {
        let key = KeyPair::generate().expect("generate qualification root key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let certificate = parameters
            .self_signed(&key)
            .expect("sign qualification root");
        Self { certificate, key }
    }

    fn intermediate(common_name: &str, root: &Self) -> Self {
        let key = KeyPair::generate().expect("generate qualification intermediate key");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let certificate = parameters
            .signed_by(&key, &root.certificate, &root.key)
            .expect("sign qualification intermediate");
        Self { certificate, key }
    }

    fn issue_workload(&self, spiffe_id: &str) -> ProjectedCredential {
        let key = KeyPair::generate().expect("generate qualification workload key");
        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "session qualification workload");
        parameters.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("valid qualification SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::hours(1);
        parameters.not_after = now + time::Duration::hours(1);
        let certificate = parameters
            .signed_by(&key, &self.certificate, &self.key)
            .expect("sign qualification workload certificate");
        ProjectedCredential {
            certificate_chain_pem: certificate.pem() + &self.certificate.pem(),
            private_key_pem: key.serialize_pem(),
        }
    }
}

struct ProjectedCredential {
    certificate_chain_pem: String,
    private_key_pem: String,
}

struct MemberCredentials {
    initial: ProjectedCredential,
    renewed_leaf: ProjectedCredential,
    rotated_intermediate: ProjectedCredential,
    new_root: ProjectedCredential,
    traffic_leaves: Vec<ProjectedCredential>,
}

#[derive(Clone, Copy)]
enum CredentialGeneration {
    Initial,
    RenewedLeaf,
    RotatedIntermediate,
    NewRoot,
    TrafficLeaf(usize),
}

#[derive(Clone, Copy)]
enum TrustGeneration {
    OldOnly,
    Overlap,
    NewOnly,
}

struct TestPki {
    old_root_pem: String,
    new_root_pem: String,
    members: Vec<MemberCredentials>,
}

impl TestPki {
    fn new(member_count: usize) -> Self {
        let old_root = Issuer::root("session qualification old root");
        let new_root = Issuer::root("session qualification new root");
        let old_intermediate =
            Issuer::intermediate("session qualification old intermediate", &old_root);
        let rotated_intermediate =
            Issuer::intermediate("session qualification rotated intermediate", &old_root);
        let new_intermediate =
            Issuer::intermediate("session qualification new intermediate", &new_root);
        let members = (0..member_count)
            .map(|node_index| MemberCredentials {
                initial: old_intermediate.issue_workload(&spiffe_id(node_index)),
                renewed_leaf: old_intermediate.issue_workload(&spiffe_id(node_index)),
                rotated_intermediate: rotated_intermediate.issue_workload(&spiffe_id(node_index)),
                new_root: new_intermediate.issue_workload(&spiffe_id(node_index)),
                traffic_leaves: (0..QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER)
                    .map(|_| old_intermediate.issue_workload(&spiffe_id(node_index)))
                    .collect(),
            })
            .collect();
        Self {
            old_root_pem: old_root.certificate.pem(),
            new_root_pem: new_root.certificate.pem(),
            members,
        }
    }

    fn credential(
        &self,
        node_index: usize,
        generation: CredentialGeneration,
    ) -> &ProjectedCredential {
        match generation {
            CredentialGeneration::Initial => &self.members[node_index].initial,
            CredentialGeneration::RenewedLeaf => &self.members[node_index].renewed_leaf,
            CredentialGeneration::RotatedIntermediate => {
                &self.members[node_index].rotated_intermediate
            }
            CredentialGeneration::NewRoot => &self.members[node_index].new_root,
            CredentialGeneration::TrafficLeaf(rotation) => self.members[node_index]
                .traffic_leaves
                .get(rotation)
                .expect("bounded traffic leaf rotation"),
        }
    }

    fn trust_bundle(&self, generation: TrustGeneration) -> String {
        match generation {
            TrustGeneration::OldOnly => self.old_root_pem.clone(),
            TrustGeneration::Overlap => self.old_root_pem.clone() + &self.new_root_pem,
            TrustGeneration::NewOnly => self.new_root_pem.clone(),
        }
    }

    fn identity_state(
        &self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
    ) -> IdentityState {
        let credential = self.credential(node_index, credential_generation);
        let trust_domain =
            TrustDomain::new("qualification.invalid").expect("qualification trust domain is valid");
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&self.trust_bundle(trust_generation))
                .expect("parse qualification trust bundle"),
        });
        build_identity_state(
            parse_certs_pem(&credential.certificate_chain_pem)
                .expect("parse qualification certificate chain"),
            parse_key_pem(&credential.private_key_pem).expect("parse qualification private key"),
            trust_bundles,
        )
        .expect("build qualification identity state")
    }
}

enum ReaderMessage {
    Reply(QualificationNodeReply),
    Invalid,
}

struct ChildNode {
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    replies: Receiver<ReaderMessage>,
    reader: Option<JoinHandle<()>>,
}

impl ChildNode {
    fn spawn(config: &Path, node_index: usize, stderr: &Path) -> (Self, SocketAddr) {
        let stderr = File::create(stderr).expect("create qualification stderr");
        let mut child = Command::new(env!("CARGO_BIN_EXE_opc-session-quorum-node"))
            .arg("--config")
            .arg(config)
            .arg("--node-index")
            .arg(node_index.to_string())
            .arg("--bind-addr")
            .arg("127.0.0.1:0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn mTLS qualification node");
        let stdin = child.stdin.take().expect("qualification child stdin");
        let stdout = child.stdout.take().expect("qualification child stdout");
        let (sender, replies) = mpsc::sync_channel(32);
        let reader = thread::Builder::new()
            .name(format!("qualification-mtls-node-{node_index}"))
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let message = match read_bounded_json_line(&mut stdout) {
                        Ok(Some(reply)) => ReaderMessage::Reply(reply),
                        Ok(None) => break,
                        Err(_) => ReaderMessage::Invalid,
                    };
                    let invalid = matches!(message, ReaderMessage::Invalid);
                    if sender.send(message).is_err() || invalid {
                        break;
                    }
                }
            })
            .expect("start qualification stdout reader");
        let mut node = Self {
            child,
            stdin: Some(BufWriter::new(stdin)),
            replies,
            reader: Some(reader),
        };
        let reply = node.receive();
        let QualificationNodeReply::Bound {
            node_index: actual,
            bind_addr,
        } = reply
        else {
            panic!("qualification child did not bind")
        };
        assert_eq!(actual, node_index);
        assert!(bind_addr.ip().is_loopback());
        (node, bind_addr)
    }

    fn send(&mut self, command: &QualificationNodeCommand) {
        write_json_line(
            self.stdin.as_mut().expect("qualification child stdin open"),
            command,
        )
        .expect("send qualification command");
    }

    fn receive(&mut self) -> QualificationNodeReply {
        match self.replies.recv_timeout(CHILD_TIMEOUT) {
            Ok(ReaderMessage::Reply(reply)) => reply,
            Ok(ReaderMessage::Invalid) => panic!("invalid qualification child response"),
            Err(error) => panic!("qualification child response unavailable: {error}"),
        }
    }

    fn invoke(&mut self, command: &QualificationNodeCommand) -> QualificationNodeReply {
        self.send(command);
        self.receive()
    }

    fn process_id(&self) -> u32 {
        self.child.id()
    }

    fn shutdown(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let reply = self.invoke(&QualificationNodeCommand::Shutdown);
            assert!(matches!(reply, QualificationNodeReply::ShuttingDown));
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join qualification stdout reader");
        }
    }
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.stdin.take();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

struct Fleet {
    nodes: Vec<ChildNode>,
    // Keep the workspace alive until every child has been killed on panic.
    workspace: TempDir,
    stderr_paths: Vec<PathBuf>,
    projected_roots: Vec<PathBuf>,
    database_paths: Vec<PathBuf>,
    projected_generation: Vec<u64>,
    pki: TestPki,
    members: Vec<QualificationMember>,
    canary_generation: u64,
    canary_values: Vec<String>,
}

impl Fleet {
    fn start(member_count: usize) -> Self {
        Self::start_with_schedule(member_count, format!("sha256:{}", "a".repeat(64)))
    }

    fn start_traffic(member_count: usize) -> Self {
        let schedule = qualification_traffic_schedule_sha256(member_count)
            .expect("supported traffic qualification topology");
        Self::start_with_schedule(member_count, schedule)
    }

    fn start_with_schedule(member_count: usize, workload_schedule_sha256: String) -> Self {
        assert!(matches!(member_count, 3 | 5));
        let workspace = tempfile::tempdir().expect("create mTLS qualification workspace");
        let root = workspace.path();
        let mut configs = Vec::with_capacity(member_count);
        let mut nodes = Vec::with_capacity(member_count);
        let mut addresses = Vec::with_capacity(member_count);
        let mut stderr_paths = Vec::with_capacity(member_count);
        for node_index in 0..member_count {
            let node_root = root.join(format!("node-{node_index}"));
            fs::create_dir(&node_root).expect("create qualification node directory");
            let config = node_root.join("config.json");
            let stderr = node_root.join("stderr.log");
            let (node, address) = ChildNode::spawn(&config, node_index, &stderr);
            configs.push(config);
            nodes.push(node);
            addresses.push(address);
            stderr_paths.push(stderr);
        }

        let members = addresses
            .iter()
            .enumerate()
            .map(|(node_index, dial_addr)| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: dial_addr.port(),
                dial_addr: *dial_addr,
                tls_identity: spiffe_id(node_index),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect::<Vec<_>>();
        let pki = TestPki::new(member_count);
        let mut projected_roots = Vec::with_capacity(member_count);
        let mut database_paths = Vec::with_capacity(member_count);
        let mut projected_generation = vec![0; member_count];
        for (node_index, config_path) in configs.iter().enumerate() {
            let node_root = root.join(format!("node-{node_index}"));
            let projected_root = node_root.join("projected");
            let snapshots = node_root.join("snapshots");
            let database_path = node_root.join("session.sqlite");
            fs::create_dir(&projected_root).expect("create projected root");
            fs::create_dir(&snapshots).expect("create snapshots root");
            publish_projected_generation(
                &projected_root,
                &mut projected_generation[node_index],
                pki.credential(node_index, CredentialGeneration::Initial),
                &pki.trust_bundle(TrustGeneration::OldOnly),
            );
            let config = QualificationNodeConfig {
                schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
                node_index,
                cluster_id: format!("qualification-mtls-{member_count}-cluster"),
                configuration_generation: "v1".to_owned(),
                configuration_epoch: 1,
                backend_namespace: format!("qualification-mtls-{member_count}-cluster"),
                workload_schedule_sha256: workload_schedule_sha256.clone(),
                members: members.clone(),
                workspace_directory: root.to_path_buf(),
                database_path: database_path.clone(),
                snapshot_directory: snapshots,
                operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
                transport: QualificationTransportConfig::ProjectedMtls(
                    QualificationProjectedMtlsConfig {
                        projected_volume_root: projected_root.clone(),
                        certificate_file: PathBuf::from("tls.crt"),
                        private_key_file: PathBuf::from("tls.key"),
                        trust_bundle_files: vec![PathBuf::from("ca.crt")],
                        poll_interval_millis: duration_millis(MIN_PROJECTED_SVID_POLL_INTERVAL),
                        lifecycle: production_lifecycle_config(),
                    },
                ),
            };
            config.validate().expect("valid mTLS node configuration");
            fs::write(
                config_path,
                serde_json::to_vec_pretty(&config).expect("encode node configuration"),
            )
            .expect("write node configuration");
            projected_roots.push(projected_root);
            database_paths.push(database_path);
        }

        for node in &mut nodes {
            node.send(&QualificationNodeCommand::Configure);
        }
        for (node_index, node) in nodes.iter_mut().enumerate() {
            assert!(matches!(
                node.receive(),
                QualificationNodeReply::Started { node_index: actual } if actual == node_index
            ));
        }
        for node in &mut nodes {
            node.send(&QualificationNodeCommand::Initialize);
        }
        for node in &mut nodes {
            assert!(matches!(
                node.receive(),
                QualificationNodeReply::Initialized
            ));
        }

        let mut fleet = Self {
            nodes,
            workspace,
            stderr_paths,
            projected_roots,
            database_paths,
            projected_generation,
            pki,
            members,
            canary_generation: 0,
            canary_values: Vec::new(),
        };
        fleet.wait_ready();
        fleet.assert_all_material_ready();
        assert!(matches!(
            fleet.nodes[0].invoke(&QualificationNodeCommand::DirectedHandshake {
                remote_node_index: 1,
            }),
            QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
            }
        ));
        fleet.acquire_canary_lease();
        fleet.advance_canary("initial-old-chain");
        fleet
    }

    fn member_count(&self) -> usize {
        self.nodes.len()
    }

    fn required_quorum(&self) -> usize {
        self.member_count() / 2 + 1
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let mut ready = true;
            let member_count = self.member_count();
            let required_quorum = self.required_quorum();
            for node in &mut self.nodes {
                node.send(&QualificationNodeCommand::Probe);
            }
            let mut reports = Vec::with_capacity(member_count);
            for node in &mut self.nodes {
                let reply = node.receive();
                reports.push(format!("{reply:?}"));
                match reply {
                    QualificationNodeReply::Readiness {
                        ready: node_ready,
                        reason_code,
                        configured_voters,
                        required_quorum: actual_quorum,
                        ..
                    } => {
                        assert_eq!(configured_voters, member_count);
                        assert_eq!(actual_quorum, required_quorum);
                        ready &= node_ready && reason_code == QualificationReadinessCode::Ready;
                    }
                    reply => panic!("unexpected readiness response: {reply:?}"),
                }
            }
            if ready {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "mTLS fleet readiness deadline: reports={reports:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn projected_status(&mut self, node_index: usize) -> QualificationProjectedSvidStatus {
        match self.nodes[node_index].invoke(&QualificationNodeCommand::ProjectedSourceStatus) {
            QualificationNodeReply::ProjectedSourceStatus { status } => status,
            reply => panic!("unexpected projected-source response: {reply:?}"),
        }
    }

    fn material_status(&mut self, node_index: usize) -> QualificationTlsMaterialStatus {
        match self.nodes[node_index].invoke(&QualificationNodeCommand::MaterialStatus) {
            QualificationNodeReply::MaterialStatus { status } => status,
            reply => panic!("unexpected material response: {reply:?}"),
        }
    }

    fn lifecycle_metrics(&mut self, node_index: usize) -> QualificationConnectionLifecycleMetrics {
        match self.nodes[node_index].invoke(&QualificationNodeCommand::LifecycleMetrics) {
            QualificationNodeReply::LifecycleMetrics { metrics } => metrics,
            reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
        }
    }

    fn all_lifecycle_metrics(&mut self) -> Vec<QualificationConnectionLifecycleMetrics> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::LifecycleMetrics);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive() {
                QualificationNodeReply::LifecycleMetrics { metrics } => metrics,
                reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
            })
            .collect()
    }

    fn wait_for_round_lifecycle_completion(
        &mut self,
        before: &[QualificationConnectionLifecycleMetrics],
        deadline: Instant,
        phase: &str,
    ) -> Vec<QualificationConnectionLifecycleMetrics> {
        let expected_authentication_failures = vec![0; self.member_count()];
        self.wait_for_lifecycle_completion_with_authentication(
            before,
            deadline,
            phase,
            &expected_authentication_failures,
        )
    }

    fn wait_for_lifecycle_completion_with_authentication(
        &mut self,
        before: &[QualificationConnectionLifecycleMetrics],
        deadline: Instant,
        phase: &str,
        expected_authentication_failures: &[u64],
    ) -> Vec<QualificationConnectionLifecycleMetrics> {
        assert_eq!(before.len(), self.member_count());
        assert_eq!(expected_authentication_failures.len(), self.member_count());
        loop {
            let after = self.all_lifecycle_metrics();
            let unexpected_failure = before
                .iter()
                .zip(&after)
                .zip(expected_authentication_failures)
                .any(|((before, after), expected_authentication_failures)| {
                    after.connection_failure_transport > before.connection_failure_transport
                        || after.connection_failure_authentication
                            > before
                                .connection_failure_authentication
                                .saturating_add(*expected_authentication_failures)
                        || after.connection_failure_timeout > before.connection_failure_timeout
                        || after.connection_failure_protocol > before.connection_failure_protocol
                        || after.connection_failure_backend > before.connection_failure_backend
                        || after.reconnect_failures > before.reconnect_failures
                        || after.drain_overruns > before.drain_overruns
                });
            let authentication_ledger_reached = before
                .iter()
                .zip(&after)
                .zip(expected_authentication_failures)
                .all(|((before, after), expected_authentication_failures)| {
                    after.connection_failure_authentication
                        == before
                            .connection_failure_authentication
                            .saturating_add(*expected_authentication_failures)
                });
            let completed = authentication_ledger_reached
                && after
                    .iter()
                    .all(|metrics| lifecycle_transition_is_settled(metrics, self.member_count()));
            let now = Instant::now();
            if completed || unexpected_failure {
                assert!(
                    deadline_allows_completion(now, deadline),
                    "connection lifecycle completed only after the absolute transition deadline: phase={phase}, before={before:?}, after={after:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return after;
            }
            assert!(
                deadline_allows_completion(now, deadline),
                "connection handlers did not complete inside the transition fail-safe: phase={phase}, before={before:?}, after={after:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn all_traffic_statuses(&mut self) -> Vec<QualificationTrafficStatus> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::TrafficStatus);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => status,
                reply => panic!("unexpected traffic status response: {reply:?}"),
            })
            .collect()
    }

    fn start_traffic_tasks(&mut self) {
        let member_count = self.member_count();
        let seed = qualification_traffic_seed(member_count)
            .expect("supported traffic qualification topology");
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StartTrafficWatch);
        }
        for node in &mut self.nodes {
            match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::WatchReady);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.seed, seed);
                    assert_eq!(status.owned_async_tasks, 1);
                    assert_eq!(status.watch_traffic_generations, vec![0; member_count]);
                }
                reply => panic!("traffic watch did not start: {reply:?}"),
            }
        }
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StartTrafficMutation);
        }
        for node in &mut self.nodes {
            match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::Running);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.seed, seed);
                    assert_eq!(status.owned_async_tasks, 2);
                }
                reply => panic!("traffic mutation did not start: {reply:?}"),
            }
        }

        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let statuses = self.all_traffic_statuses();
            if statuses.iter().all(|status| {
                status.state == QualificationTrafficState::Running
                    && status.failure.is_none()
                    && status.owned_async_tasks == 2
                    && status.mutation_cycles >= 1
                    && status.watch_entries >= 1
                    && status.watch_applied_records >= 1
            }) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "traffic tasks did not reach the warmed state: statuses={statuses:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_traffic_progress(
        &mut self,
        before: &[QualificationTrafficStatus],
        phase: &str,
        deadline: Instant,
    ) -> Vec<QualificationTrafficStatus> {
        assert_eq!(before.len(), self.member_count());
        loop {
            let statuses = self.all_traffic_statuses();
            for (node_index, status) in statuses.iter().enumerate() {
                assert_eq!(
                    status.state,
                    QualificationTrafficState::Running,
                    "traffic state failed during {phase}: node={node_index}, status={status:?}, stderr={}",
                    self.node_stderr(node_index)
                );
                assert_eq!(status.failure, None);
                assert_eq!(status.owned_async_tasks, 2);
                assert_eq!(status.watch_traffic_generations.len(), self.member_count());
            }
            if statuses.iter().zip(before).all(|(after, before)| {
                traffic_status_made_semantic_progress(before, after, self.member_count())
            }) {
                assert!(
                    deadline_allows_completion(Instant::now(), deadline),
                    "traffic made semantic progress only after the absolute transition deadline: phase={phase}, before={before:?}, after={statuses:?}, stderr={:?}",
                    self.stderr_diagnostics()
                );
                return statuses;
            }
            assert!(
                deadline_allows_completion(Instant::now(), deadline),
                "traffic did not make semantic progress during {phase}: before={before:?}, after={statuses:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_traffic_mutations(&mut self) -> Vec<QualificationTrafficStatus> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StopTrafficMutation);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::MutationStopped);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.owned_async_tasks, 1);
                    assert_completed_traffic_cycles(&status);
                    status
                }
                reply => panic!("traffic mutation task did not stop: {reply:?}"),
            })
            .collect()
    }

    fn wait_for_watch_heads(&mut self) -> Vec<QualificationTrafficStatus> {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let statuses = self.all_traffic_statuses();
            if statuses.iter().all(|status| {
                status.state == QualificationTrafficState::MutationStopped
                    && status.failure.is_none()
                    && status.owned_async_tasks == 1
                    && status.watch_sequence == status.replication_head
            }) {
                return statuses;
            }
            assert!(
                Instant::now() < deadline,
                "protected watches did not reach every local applied head: statuses={statuses:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_traffic_watches(&mut self) -> Vec<QualificationTrafficStatus> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::StopTrafficWatch);
        }
        self.nodes
            .iter_mut()
            .map(|node| match node.receive() {
                QualificationNodeReply::TrafficStatus { status } => {
                    assert_eq!(status.state, QualificationTrafficState::Stopped);
                    assert_eq!(status.failure, None);
                    assert_eq!(status.owned_async_tasks, 0);
                    status
                }
                reply => panic!("traffic watch task did not stop: {reply:?}"),
            })
            .collect()
    }

    fn transition_traffic_leaf(&mut self, node_index: usize, rotation: usize) {
        let source_before = self.projected_status(node_index);
        let controller_before = self.material_status(node_index);
        publish_projected_generation(
            &self.projected_roots[node_index],
            &mut self.projected_generation[node_index],
            self.pki
                .credential(node_index, CredentialGeneration::TrafficLeaf(rotation)),
            &self.pki.trust_bundle(TrustGeneration::OldOnly),
        );
        self.wait_for_member_publication(
            node_index,
            source_before.generation,
            controller_before.epoch,
        );
    }

    fn prove_all_directed_paths_parallel(&mut self, generations: &[u64]) {
        let member_count = self.member_count();
        assert_eq!(generations.len(), member_count);
        for offset in 1..member_count {
            let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
            let mut pending = vec![true; member_count];
            while pending.iter().any(|pending| *pending) {
                for (source, node) in self.nodes.iter_mut().enumerate() {
                    if pending[source] {
                        node.send(&QualificationNodeCommand::DirectedHandshake {
                            remote_node_index: (source + offset) % member_count,
                        });
                    }
                }
                for (source, node) in self.nodes.iter_mut().enumerate() {
                    if !pending[source] {
                        continue;
                    }
                    let target = (source + offset) % member_count;
                    match node.receive() {
                        QualificationNodeReply::DirectedHandshake {
                            remote_node_index,
                            reauthentication_generation,
                        } => {
                            assert_eq!(remote_node_index, target);
                            assert_eq!(reauthentication_generation, generations[source]);
                            pending[source] = false;
                        }
                        QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
                        } if Instant::now() < deadline => {}
                        reply => panic!(
                            "parallel directed current-generation handshake {source}->{target} failed: {reply:?}, source_stderr={}, target_stderr={}",
                            self.node_stderr(source),
                            self.node_stderr(target)
                        ),
                    }
                }
                if pending.iter().any(|pending| *pending) {
                    assert!(
                        Instant::now() < deadline,
                        "parallel directed current-generation handshake deadline"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    fn fresh_all_directed_generation(&mut self) {
        let generations = self.request_fleet_reauthentication();
        self.prove_all_directed_paths_parallel(&generations);
    }

    fn verify_all_traffic_records(&mut self, statuses: &[QualificationTrafficStatus]) {
        assert_eq!(statuses.len(), self.member_count());
        let seed = qualification_traffic_seed(self.member_count())
            .expect("supported traffic qualification topology");
        for (source, status) in statuses.iter().enumerate() {
            let stable_id = traffic_stable_id(source);
            let owner = traffic_owner(source);
            let expected_owner = qualification_owner_sha256(&owner);
            let value = qualification_traffic_value(
                seed,
                self.member_count(),
                source,
                status.last_generation,
            );
            let expected_value = qualification_value_sha256(value.as_bytes());
            for node in &mut self.nodes {
                node.send(&QualificationNodeCommand::Get {
                    stable_id: stable_id.clone(),
                });
            }
            for node in &mut self.nodes {
                match node.receive() {
                    QualificationNodeReply::Record {
                        present: true,
                        generation: Some(generation),
                        owner_sha256: Some(ref owner_sha256),
                        fence: Some(fence),
                        value_sha256: Some(ref value_sha256),
                    } => {
                        assert_eq!(generation, status.last_generation);
                        assert_eq!(owner_sha256, &expected_owner);
                        assert_eq!(fence, status.last_record_fence);
                        assert_eq!(value_sha256, &expected_value);
                    }
                    reply => panic!("all-voter traffic read failed: {reply:?}"),
                }
            }
        }
    }

    fn retain_traffic_plaintext_canaries(&mut self, statuses: &[QualificationTrafficStatus]) {
        let member_count = self.member_count();
        let seed = qualification_traffic_seed(member_count)
            .expect("supported traffic qualification topology");
        for (node_index, status) in statuses.iter().enumerate() {
            for generation in 1..=status.last_generation {
                self.canary_values.push(qualification_traffic_value(
                    seed,
                    member_count,
                    node_index,
                    generation,
                ));
            }
        }
    }

    fn assert_all_material_ready(&mut self) {
        for node_index in 0..self.member_count() {
            let source = self.projected_status(node_index);
            assert!(source.generation >= 1);
            assert_eq!(
                source.availability,
                QualificationProjectedSvidAvailability::Ready
            );
            assert!(source.reason.is_none());

            let controller = self.material_status(node_index);
            assert!(controller.epoch >= 1);
            assert_eq!(
                controller.availability,
                QualificationTlsMaterialAvailability::Ready
            );
            assert!(controller.reason.is_none());
            assert!(controller.leaf_expires_at.is_some());
            assert!(controller.certificate_chain_expires_at.is_some());
        }
    }

    fn wait_for_member_publication(
        &mut self,
        node_index: usize,
        previous_source_generation: u64,
        previous_material_epoch: u64,
    ) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            let source = self.projected_status(node_index);
            let controller = self.material_status(node_index);
            if matches!(
                source.availability,
                QualificationProjectedSvidAvailability::RetainingLastGood
                    | QualificationProjectedSvidAvailability::Unavailable
            ) || matches!(
                controller.availability,
                QualificationTlsMaterialAvailability::RetainingLastGood
                    | QualificationTlsMaterialAvailability::Unavailable
            ) {
                panic!(
                    "valid projected candidate was rejected: node={node_index}, source={source:?}, controller={controller:?}, stderr={}",
                    self.node_stderr(node_index)
                );
            }
            if source.generation > previous_source_generation
                && source.availability == QualificationProjectedSvidAvailability::Ready
                && source.reason.is_none()
                && controller.epoch > previous_material_epoch
                && controller.availability == QualificationTlsMaterialAvailability::Ready
                && controller.reason.is_none()
                && controller.leaf_expires_at.is_some()
                && controller.certificate_chain_expires_at.is_some()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "projected source and TLS controller did not publish a new ready generation: node={node_index}, source={source:?}, controller={controller:?}, stderr={}",
                self.node_stderr(node_index)
            );
            thread::sleep(MIN_PROJECTED_SVID_POLL_INTERVAL);
        }
    }

    fn transition_member(
        &mut self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
        phase: &str,
    ) {
        let source_before = self.projected_status(node_index);
        let controller_before = self.material_status(node_index);
        let credential = self.pki.credential(node_index, credential_generation);
        let trust_bundle = self.pki.trust_bundle(trust_generation);
        publish_projected_generation(
            &self.projected_roots[node_index],
            &mut self.projected_generation[node_index],
            credential,
            &trust_bundle,
        );
        self.wait_for_member_publication(
            node_index,
            source_before.generation,
            controller_before.epoch,
        );
        self.assert_all_material_ready();
        self.reauthenticate_and_prove_member_paths(node_index);
        self.wait_ready();
        self.verify_canary();
        assert!(!phase.is_empty());
    }

    fn transition_member_under_traffic(
        &mut self,
        node_index: usize,
        credential_generation: CredentialGeneration,
        trust_generation: TrustGeneration,
        phase: &str,
        lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        let started = Instant::now();
        let transition_deadline =
            started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        let source_before = self.projected_status(node_index);
        let controller_before = self.material_status(node_index);
        let credential = self.pki.credential(node_index, credential_generation);
        let trust_bundle = self.pki.trust_bundle(trust_generation);
        publish_projected_generation(
            &self.projected_roots[node_index],
            &mut self.projected_generation[node_index],
            credential,
            &trust_bundle,
        );
        self.wait_for_member_publication(
            node_index,
            source_before.generation,
            controller_before.epoch,
        );
        self.assert_all_material_ready();
        self.fresh_all_directed_generation();
        self.wait_ready();
        self.verify_canary();
        // Only work committed after publication, resolver-fresh directed
        // handshakes, readiness, and canary verification counts for this
        // transition's continuity proof.
        let traffic_after_reauthentication = self.all_traffic_statuses();
        self.wait_for_traffic_progress(&traffic_after_reauthentication, phase, transition_deadline);
        let lifecycle_after = self.wait_for_round_lifecycle_completion(
            lifecycle_checkpoint,
            transition_deadline,
            phase,
        );
        let remote_peers = u64::try_from(self.member_count() - 1).expect("bounded member count");
        assert_lifecycle_delta_bounds(
            self.member_count(),
            lifecycle_checkpoint,
            &lifecycle_after,
            remote_peers,
        );
        assert!(!phase.is_empty());
        assert_transition_completed_by(started, transition_deadline, phase);
        *lifecycle_checkpoint = lifecycle_after;
    }

    fn request_fleet_reauthentication(&mut self) -> Vec<u64> {
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::RequestReauthentication);
        }
        let mut generations = Vec::with_capacity(self.member_count());
        for node in &mut self.nodes {
            let generation = match node.receive() {
                QualificationNodeReply::ReauthenticationRequested { generation } => generation,
                reply => panic!("unexpected reauthentication response: {reply:?}"),
            };
            assert!(generation >= 1);
            generations.push(generation);
        }
        generations
    }

    fn reauthenticate_and_prove_member_paths(&mut self, member: usize) {
        let generations = self.request_fleet_reauthentication();
        let paths = (0..self.member_count())
            .flat_map(|source| (0..self.member_count()).map(move |target| (source, target)))
            .filter(|(source, target)| source != target && (*source == member || *target == member))
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 2 * (self.member_count() - 1));
        self.prove_directed_paths(&generations, paths);
    }

    fn complete_fleet_phase(&mut self, phase: &str) {
        let generations = self.request_fleet_reauthentication();
        let paths = (0..self.member_count())
            .flat_map(|source| (0..self.member_count()).map(move |target| (source, target)))
            .filter(|(source, target)| source != target)
            .collect::<Vec<_>>();
        assert_eq!(
            paths.len(),
            self.member_count() * (self.member_count() - 1),
            "a completed fleet phase must cover every directed path"
        );
        self.prove_directed_paths(&generations, paths);
        self.wait_ready();
        self.advance_canary(phase);
    }

    fn complete_fleet_phase_under_traffic(
        &mut self,
        phase: &str,
        lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        let started = Instant::now();
        let transition_deadline =
            started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        // The immediately preceding last member transition already proved a
        // fresh full directed generation after that exact publication. The
        // phase checkpoint adds an acknowledged canary CAS/read and sustained
        // workload progress without introducing a redundant reauthentication
        // generation that would distort the connection-rate measurement.
        self.advance_canary(phase);
        self.wait_ready();
        let traffic_after_checkpoint = self.all_traffic_statuses();
        self.wait_for_traffic_progress(&traffic_after_checkpoint, phase, transition_deadline);
        let lifecycle_after = self.wait_for_round_lifecycle_completion(
            lifecycle_checkpoint,
            transition_deadline,
            phase,
        );
        assert_lifecycle_delta_bounds(
            self.member_count(),
            lifecycle_checkpoint,
            &lifecycle_after,
            0,
        );
        assert_transition_completed_by(started, transition_deadline, phase);
        *lifecycle_checkpoint = lifecycle_after;
    }

    fn prove_directed_paths(&mut self, generations: &[u64], paths: Vec<(usize, usize)>) {
        for (source, target) in paths {
            self.wait_for_directed_handshake(source, target, generations[source]);
        }
    }

    fn wait_for_directed_handshake(
        &mut self,
        source: usize,
        target: usize,
        expected_generation: u64,
    ) {
        let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
        loop {
            match self.nodes[source].invoke(&QualificationNodeCommand::DirectedHandshake {
                remote_node_index: target,
            }) {
                QualificationNodeReply::DirectedHandshake {
                    remote_node_index,
                    reauthentication_generation,
                } => {
                    assert_eq!(remote_node_index, target);
                    assert_eq!(reauthentication_generation, expected_generation);
                    return;
                }
                QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
                } if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                reply => panic!(
                    "directed current-generation handshake {source}->{target} failed: {reply:?}, source_stderr={}, target_stderr={}",
                    self.node_stderr(source),
                    self.node_stderr(target)
                ),
            }
        }
    }

    fn acquire_canary_lease(&mut self) {
        match self.nodes[0].invoke(&QualificationNodeCommand::Acquire {
            lease_handle: CANARY_LEASE_HANDLE.to_owned(),
            stable_id: CANARY_STABLE_ID.to_owned(),
            owner: CANARY_OWNER.to_owned(),
            ttl_millis: CANARY_TTL_MILLIS,
        }) {
            QualificationNodeReply::LeaseAcquired { fence } => assert!(fence >= 1),
            reply => panic!("failed to acquire rotation canary lease: {reply:?}"),
        }
    }

    fn advance_canary(&mut self, phase: &str) {
        let expected_generation = (self.canary_generation != 0).then_some(self.canary_generation);
        self.canary_generation += 1;
        let value = format!(
            "opc-rotation-plaintext-canary/{}/{}/{phase}",
            self.member_count(),
            self.canary_generation
        );
        match self.nodes[0].invoke(&QualificationNodeCommand::CompareAndSet {
            lease_handle: CANARY_LEASE_HANDLE.to_owned(),
            stable_id: CANARY_STABLE_ID.to_owned(),
            expected_generation,
            new_generation: self.canary_generation,
            value: value.clone(),
        }) {
            QualificationNodeReply::CompareAndSet {
                applied: true,
                current_generation: Some(actual),
            } => assert_eq!(actual, self.canary_generation),
            reply => panic!("rotation canary CAS failed: {reply:?}"),
        }

        self.canary_values.push(value);
        self.verify_canary();
    }

    fn verify_canary(&mut self) {
        let expected_owner = qualification_owner_sha256(CANARY_OWNER);
        let expected_value = qualification_value_sha256(
            self.canary_values
                .last()
                .expect("seeded rotation canary")
                .as_bytes(),
        );
        for node in &mut self.nodes {
            node.send(&QualificationNodeCommand::Get {
                stable_id: CANARY_STABLE_ID.to_owned(),
            });
        }
        for node in &mut self.nodes {
            match node.receive() {
                QualificationNodeReply::Record {
                    present: true,
                    generation: Some(actual_generation),
                    owner_sha256: Some(ref actual_owner),
                    fence: Some(fence),
                    value_sha256: Some(ref actual_value),
                } => {
                    assert_eq!(actual_generation, self.canary_generation);
                    assert_eq!(actual_owner, &expected_owner);
                    assert!(fence >= 1);
                    assert_eq!(actual_value, &expected_value);
                }
                reply => panic!("rotation canary read failed: {reply:?}"),
            }
        }
    }

    fn assert_old_client_chains_rejected(&mut self) {
        let descriptors = self
            .members
            .iter()
            .map(|member| {
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(member.replica_id.clone()).expect("qualification replica ID"),
                    ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                        .expect("qualification endpoint"),
                    ReplicaTlsIdentity::new(member.tls_identity.clone())
                        .expect("qualification TLS identity"),
                    ReplicaFailureDomain::new(member.failure_domain.clone())
                        .expect("qualification failure domain"),
                    ReplicaBackingIdentity::new(member.backing_identity.clone())
                        .expect("qualification backing identity"),
                )
            })
            .collect::<Vec<_>>();
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new(format!(
                    "qualification-mtls-{}-cluster",
                    self.member_count()
                ))
                .expect("qualification cluster ID"),
                SessionConfigurationGeneration::new("v1")
                    .expect("qualification configuration generation"),
                SessionConfigurationEpoch::new(1).expect("qualification configuration epoch"),
                descriptors,
            )
            .expect("qualification replication manifest"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("removed-root rejection runtime");

        for source in 0..self.member_count() {
            let target = (source + 1) % self.member_count();
            let target_metrics_before = self.lifecycle_metrics(target);
            let identity = self.pki.identity_state(
                source,
                CredentialGeneration::RenewedLeaf,
                TrustGeneration::Overlap,
            );
            let (identity_tx, identity_rx) = watch::channel(Some(identity));
            let client = TlsConfigBuilder::new(identity_rx)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("old-chain rejection client");
            let binding = manifest
                .bind_local(
                    ReplicaId::new(self.members[source].replica_id.clone())
                        .expect("old-chain local replica"),
                )
                .expect("old-chain local binding")
                .bind_remote(
                    ReplicaId::new(self.members[target].replica_id.clone())
                        .expect("old-chain remote replica"),
                )
                .expect("old-chain remote binding");
            let address = self.members[target].dial_addr;
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls_for_probe = Arc::clone(&resolver_calls);
            let resolver: RemoteAddrResolver = Arc::new(move || {
                resolver_calls_for_probe.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(address) })
            });
            let peer =
                RemoteSessionConsensusPeer::new_profiled_with_resolver(binding, resolver, client)
                    .with_connection_lifecycle(single_attempt_removed_root_probe_lifecycle());
            let request = SessionConsensusWireRequest::try_new(
                manifest.consensus_identity(),
                manifest
                    .consensus_node_id(
                        &ReplicaId::new(self.members[source].replica_id.clone())
                            .expect("old-chain request replica"),
                    )
                    .expect("old-chain request node ID"),
                SessionConsensusRpcFamily::Vote,
                Vec::new(),
            )
            .expect("old-chain rejection request");
            let outcome = runtime.block_on(peer.call(request));
            assert!(
                matches!(
                    outcome,
                    Err(
                        SessionConsensusPeerError::Authentication
                            | SessionConsensusPeerError::Timeout
                    )
                ),
                "new-only server trust must reject removed old-root client chain: source={source}, target={target}, outcome={outcome:?}"
            );
            assert_eq!(
                resolver_calls.load(Ordering::SeqCst),
                1,
                "qualification-only removed-root probe must make exactly one connection attempt: source={source}, target={target}"
            );
            drop(identity_tx);

            let deadline = Instant::now() + CLUSTER_TRANSITION_TIMEOUT;
            loop {
                let target_metrics_after = self.lifecycle_metrics(target);
                let authentication_failures_after =
                    target_metrics_after.connection_failure_authentication;
                if authentication_failures_after
                    > target_metrics_before.connection_failure_authentication
                {
                    assert_eq!(
                        authentication_failures_after,
                        target_metrics_before.connection_failure_authentication + 1,
                        "removed-root probe must produce exactly one target authentication failure: source={source}, target={target}"
                    );
                    assert_eq!(
                        target_metrics_after.empty_vote_dispatches,
                        target_metrics_before.empty_vote_dispatches,
                        "removed-root probe must fail before consensus application dispatch: source={source}, target={target}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "removed old-root rejection did not reach the target TLS boundary"
                );
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn assert_old_client_chains_rejected_under_traffic(
        &mut self,
        lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        let phase = "traffic-stale-old-root-rejection";
        let started = Instant::now();
        let transition_deadline =
            started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
        self.assert_old_client_chains_rejected();
        let traffic_after_rejection = self.all_traffic_statuses();
        self.wait_for_traffic_progress(&traffic_after_rejection, phase, transition_deadline);
        let expected_authentication_failures =
            removed_root_authentication_failure_budget(self.member_count());
        let lifecycle_after = self.wait_for_lifecycle_completion_with_authentication(
            lifecycle_checkpoint,
            transition_deadline,
            phase,
            &expected_authentication_failures,
        );
        assert_lifecycle_delta_bounds_with_authentication(
            self.member_count(),
            lifecycle_checkpoint,
            &lifecycle_after,
            0,
            &expected_authentication_failures,
        );
        assert_transition_completed_by(started, transition_deadline, phase);
        *lifecycle_checkpoint = lifecycle_after;
    }

    fn assert_three_member_resolver_backoff_profile(&self) {
        assert_eq!(self.member_count(), 3);
        let descriptors = self
            .members
            .iter()
            .map(|member| {
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(member.replica_id.clone()).expect("qualification replica ID"),
                    ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                        .expect("qualification endpoint"),
                    ReplicaTlsIdentity::new(member.tls_identity.clone())
                        .expect("qualification TLS identity"),
                    ReplicaFailureDomain::new(member.failure_domain.clone())
                        .expect("qualification failure domain"),
                    ReplicaBackingIdentity::new(member.backing_identity.clone())
                        .expect("qualification backing identity"),
                )
            })
            .collect::<Vec<_>>();
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("qualification-mtls-3-cluster")
                    .expect("qualification cluster ID"),
                SessionConfigurationGeneration::new("v1")
                    .expect("qualification configuration generation"),
                SessionConfigurationEpoch::new(1).expect("qualification configuration epoch"),
                descriptors,
            )
            .expect("qualification replication manifest"),
        );
        let identity =
            self.pki
                .identity_state(0, CredentialGeneration::Initial, TrustGeneration::OldOnly);
        let (_identity_tx, identity_rx) = watch::channel(Some(identity));
        let client = TlsConfigBuilder::new(identity_rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("resolver proof client config");
        let calls = Arc::new(AtomicUsize::new(0));
        let timestamps = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(4)));
        let address = self.members[1].dial_addr;
        let resolver: RemoteAddrResolver = {
            let calls = Arc::clone(&calls);
            let timestamps = Arc::clone(&timestamps);
            Arc::new(move || {
                let attempt = calls.fetch_add(1, Ordering::SeqCst);
                timestamps
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Instant::now());
                Box::pin(async move {
                    if attempt < QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS.len() {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "qualification resolver fault",
                        ))
                    } else {
                        Ok(address)
                    }
                })
            })
        };
        let binding = manifest
            .bind_local(
                ReplicaId::new(self.members[0].replica_id.clone())
                    .expect("resolver proof local replica"),
            )
            .expect("resolver proof local binding")
            .bind_remote(
                ReplicaId::new(self.members[1].replica_id.clone())
                    .expect("resolver proof remote replica"),
            )
            .expect("resolver proof remote binding");
        let peer =
            RemoteSessionConsensusPeer::new_profiled_with_resolver(binding, resolver, client)
                .with_connection_lifecycle(
                    production_lifecycle_config()
                        .to_policy()
                        .expect("production lifecycle policy"),
                );
        let request = SessionConsensusWireRequest::try_new(
            manifest.consensus_identity(),
            manifest
                .consensus_node_id(
                    &ReplicaId::new(self.members[0].replica_id.clone())
                        .expect("resolver proof request replica"),
                )
                .expect("resolver proof request node ID"),
            SessionConsensusRpcFamily::ReadBarrier,
            Vec::new(),
        )
        .expect("resolver proof request");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("resolver proof runtime");
        let started = Instant::now();
        let outcome = runtime.block_on(peer.call(request));
        let elapsed = started.elapsed();
        let response = outcome.expect("resolver retries must reach the real mTLS server");
        response.validate().expect("resolver proof response");
        assert!(
            response.result.is_ok()
                || matches!(&response.result, Err(SessionConsensusPeerError::Protocol)),
            "resolver proof must complete authenticated bootstrap: {response:?}"
        );
        assert!(
            elapsed < Duration::from_millis(QUALIFICATION_RESOLVER_PROOF_MILLIS),
            "resolver proof exceeded the real-mTLS completion bound: elapsed={elapsed:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        let timestamps = timestamps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(timestamps.len(), 4);
        for (index, lower_bound_millis) in QUALIFICATION_RESOLVER_BACKOFF_LOWER_BOUNDS_MILLIS
            .into_iter()
            .enumerate()
        {
            let actual = timestamps[index + 1].duration_since(timestamps[index]);
            assert!(
                actual >= Duration::from_millis(lower_bound_millis),
                "resolver retry {index} violated exponential backoff: actual={actual:?}, lower_bound_millis={lower_bound_millis}"
            );
        }
    }

    fn wait_for_resources_to_settle(
        &mut self,
        process_ids: &[u32],
        warmed: &[ProcessResourceSnapshot],
    ) -> (
        Vec<ProcessResourceSnapshot>,
        Vec<QualificationConnectionLifecycleMetrics>,
    ) {
        assert_eq!(process_ids.len(), self.member_count());
        assert_eq!(warmed.len(), self.member_count());
        let deadline = Instant::now() + Duration::from_millis(QUALIFICATION_RESOURCE_SETTLE_MILLIS);
        let member_count = self.member_count();
        let mut previous = None;
        let mut stable_samples = 0_usize;
        loop {
            let metrics = self.all_lifecycle_metrics();
            let snapshots = process_ids
                .iter()
                .copied()
                .map(read_classified_process_resources)
                .collect::<Vec<_>>();
            // Openraft heartbeats intentionally remain live after the
            // qualification-owned workload tasks stop, so an inbound handler
            // may remain outstanding. It must be covered by the bounded active
            // gauge; every draining handler must have reached zero.
            let lifecycle_settled = metrics
                .iter()
                .all(|metrics| lifecycle_transition_is_settled(metrics, member_count));
            let resources_within_final_bounds =
                warmed.iter().zip(&snapshots).all(|(warmed, settled)| {
                    settled.file_descriptors
                        <= warmed
                            .file_descriptors
                            .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE)
                        && settled.socket_file_descriptors
                            <= warmed
                                .socket_file_descriptors
                                .saturating_add(QUALIFICATION_RESOURCE_FINAL_FD_ALLOWANCE)
                        && settled.threads
                            <= warmed
                                .threads
                                .saturating_add(QUALIFICATION_RESOURCE_THREAD_GROWTH_ALLOWANCE)
                        && settled.vm_rss_kib
                            <= warmed
                                .vm_rss_kib
                                .saturating_add(QUALIFICATION_RESOURCE_SETTLED_RSS_GROWTH_KIB)
                });
            let stable =
                previous
                    .as_ref()
                    .is_some_and(|previous: &Vec<ProcessResourceSnapshot>| {
                        previous.iter().zip(&snapshots).all(|(previous, current)| {
                            previous.file_descriptors == current.file_descriptors
                                && previous.socket_file_descriptors
                                    == current.socket_file_descriptors
                                && previous.threads == current.threads
                        })
                    });
            if lifecycle_settled && resources_within_final_bounds && stable {
                stable_samples = stable_samples.saturating_add(1);
                if stable_samples >= QUALIFICATION_RESOURCE_STABLE_SAMPLES {
                    return (snapshots, metrics);
                }
            } else {
                stable_samples = 0;
            }
            assert!(
                Instant::now() < deadline,
                "process resources did not semantically settle: metrics={metrics:?}, snapshots={snapshots:?}, warmed={warmed:?}, stderr={:?}",
                self.stderr_diagnostics()
            );
            previous = Some(snapshots);
            thread::sleep(Duration::from_millis(QUALIFICATION_RESOURCE_SAMPLE_MILLIS));
        }
    }

    fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown();
        }
    }

    fn assert_plaintext_canaries_absent_from_sqlite(&self) {
        assert!(
            retained_plaintext_canary_domain_counts(&self.canary_values).is_some(),
            "every retained plaintext canary must belong to exactly one fixed qualification domain"
        );
        for database_path in &self.database_paths {
            let artifacts = read_sqlite_family(database_path).unwrap_or_else(|error| {
                panic!(
                    "rotation SQLite family must be readable after shutdown: database={}, error={error}",
                    database_path.display()
                )
            });
            for (path, bytes) in artifacts {
                for prefix_present in plaintext_canary_prefix_presence(&bytes) {
                    assert!(
                        !prefix_present,
                        "plaintext canary reached SQLite persistence at {}",
                        path.display()
                    );
                }
            }
        }
    }

    fn node_stderr(&self, node_index: usize) -> String {
        let Ok(bytes) = fs::read(&self.stderr_paths[node_index]) else {
            return "unavailable".to_owned();
        };
        let tail = &bytes[bytes.len().saturating_sub(8 * 1024)..];
        String::from_utf8_lossy(tail).into_owned()
    }

    fn stderr_diagnostics(&self) -> Vec<String> {
        (0..self.member_count())
            .map(|node_index| self.node_stderr(node_index))
            .collect()
    }
}

fn production_lifecycle_config() -> QualificationConnectionLifecycleConfig {
    QualificationConnectionLifecycleConfig {
        maximum_authentication_age_millis: duration_millis(DEFAULT_MAX_AUTHENTICATION_AGE),
        rotation_drain_window_millis: duration_millis(DEFAULT_ROTATION_DRAIN_WINDOW),
        reconnect_backoff_min_millis: duration_millis(DEFAULT_RECONNECT_BACKOFF_MIN),
        reconnect_backoff_max_millis: duration_millis(DEFAULT_RECONNECT_BACKOFF_MAX),
        rotation_jitter_millis: duration_millis(DEFAULT_ROTATION_JITTER),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).expect("production duration fits milliseconds")
}

fn publish_projected_generation(
    root: &Path,
    generation_counter: &mut u64,
    credential: &ProjectedCredential,
    trust_bundle_pem: &str,
) {
    *generation_counter += 1;
    let generation_name = format!("..2026_07_13_{generation_counter:04}");
    let generation = root.join(&generation_name);
    fs::create_dir(&generation).expect("create immutable projected generation");
    fs::write(
        generation.join("tls.crt"),
        &credential.certificate_chain_pem,
    )
    .expect("write projected certificate chain");
    fs::write(generation.join("tls.key"), &credential.private_key_pem)
        .expect("write projected private key");
    fs::write(generation.join("ca.crt"), trust_bundle_pem).expect("write projected trust bundle");

    let next_link = root.join(format!("..data-next-{generation_counter:04}"));
    symlink(&generation_name, &next_link).expect("stage projected generation link");
    fs::rename(&next_link, root.join("..data")).expect("atomically publish projected generation");
}

fn sqlite_family_paths(database_path: &Path) -> [PathBuf; 3] {
    let database = database_path.as_os_str().to_string_lossy();
    [
        database_path.to_path_buf(),
        PathBuf::from(format!("{database}-wal")),
        PathBuf::from(format!("{database}-shm")),
    ]
}

fn read_sqlite_family(database_path: &Path) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut artifacts = Vec::with_capacity(3);
    for (index, path) in sqlite_family_paths(database_path).into_iter().enumerate() {
        match fs::read(&path) {
            Ok(bytes) => artifacts.push((path, bytes)),
            Err(error) if index != 0 && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(artifacts)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn retained_plaintext_canary_domain_counts(values: &[String]) -> Option<[usize; 2]> {
    if values.is_empty() {
        return None;
    }
    let mut counts = [0_usize; 2];
    for value in values {
        let matches = PLAINTEXT_CANARY_PREFIXES.map(|prefix| value.as_bytes().starts_with(prefix));
        if matches.into_iter().filter(|matches| *matches).count() != 1 {
            return None;
        }
        for (index, matches) in matches.into_iter().enumerate() {
            if matches {
                counts[index] = counts[index].checked_add(1)?;
            }
        }
    }
    Some(counts)
}

fn plaintext_canary_prefix_presence(bytes: &[u8]) -> [bool; 2] {
    PLAINTEXT_CANARY_PREFIXES.map(|prefix| contains_bytes(bytes, prefix))
}

fn spiffe_id(node_index: usize) -> String {
    format!(
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
    )
}

fn run_projected_mtls_rotation_core(member_count: usize) {
    let mut fleet = Fleet::start(member_count);

    // Publish trust overlap to every member before any member changes issuer.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::Initial,
            TrustGeneration::Overlap,
            &format!("overlap-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("overlap-complete");

    // Renew only each leaf/key while retaining the old presented intermediate.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("renew-leaf-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("leaf-renewal-complete");

    // Rotate the old-root intermediate one member at a time, then perform an
    // exact fleet rollback before any trust-anchor cutover.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RotatedIntermediate,
            TrustGeneration::Overlap,
            &format!("rotate-intermediate-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("intermediate-rotation-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("rollback-intermediate-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("intermediate-rollback-complete");

    // Move to chains under the new root, roll the entire fleet back while
    // overlap remains, and move forward again before removing old trust.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("forward-new-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("new-root-forward-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("rollback-new-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("new-root-rollback-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("resume-new-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("new-root-resume-complete");

    // Remove the old root one member at a time only after every member serves
    // the new chain.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("remove-old-root-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("old-root-removal-complete");
    fleet.assert_old_client_chains_rejected();

    // A rollback after removal is overlap-first: restore old trust everywhere
    // while all members still present the new chain, then roll chains back one
    // member at a time. No plaintext or weakened identity mode is introduced.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("restore-overlap-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("overlap-restore-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("rollback-after-removal-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("post-removal-rollback-complete");

    // Exit in the intended new-only state after proving the rollback path.
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("final-forward-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("final-forward-complete");
    for node_index in 0..member_count {
        fleet.transition_member(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("final-new-only-node-{node_index}"),
        );
    }
    fleet.complete_fleet_phase("final-new-only-complete");
    assert_eq!(
        fleet.canary_generation, 13,
        "initial canary plus every completed fleet phase"
    );

    for node in &mut fleet.nodes {
        match node.invoke(&QualificationNodeCommand::LifecycleMetrics) {
            QualificationNodeReply::LifecycleMetrics { metrics } => {
                assert!(metrics.connection_attempts >= (member_count - 1) as u64);
                assert!(metrics.connection_successes >= (member_count - 1) as u64);
                assert!(
                    metrics.connection_successes > metrics.connection_failure_authentication,
                    "successful reauthentication must dominate rejected transitional attempts"
                );
            }
            reply => panic!("unexpected lifecycle metrics response: {reply:?}"),
        }
    }

    fleet.shutdown();
    fleet.assert_plaintext_canaries_absent_from_sqlite();
    assert!(fleet.workspace.path().is_dir());
}

fn run_projected_mtls_rotation_campaign_under_traffic(
    fleet: &mut Fleet,
    member_count: usize,
    lifecycle_checkpoint: &mut Vec<QualificationConnectionLifecycleMetrics>,
) {
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::Initial,
            TrustGeneration::Overlap,
            &format!("traffic-overlap-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic("traffic-overlap-complete", lifecycle_checkpoint);

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-renew-leaf-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic("traffic-leaf-renewal-complete", lifecycle_checkpoint);

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RotatedIntermediate,
            TrustGeneration::Overlap,
            &format!("traffic-rotate-intermediate-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-intermediate-rotation-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-rollback-intermediate-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-intermediate-rollback-complete",
        lifecycle_checkpoint,
    );

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-forward-new-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-new-root-forward-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-rollback-new-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-new-root-rollback-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-resume-new-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-new-root-resume-complete",
        lifecycle_checkpoint,
    );

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("traffic-remove-old-root-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-old-root-removal-complete",
        lifecycle_checkpoint,
    );
    fleet.assert_old_client_chains_rejected_under_traffic(lifecycle_checkpoint);

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-restore-overlap-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-overlap-restore-complete",
        lifecycle_checkpoint,
    );
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::RenewedLeaf,
            TrustGeneration::Overlap,
            &format!("traffic-rollback-after-removal-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-post-removal-rollback-complete",
        lifecycle_checkpoint,
    );

    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::Overlap,
            &format!("traffic-final-forward-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet
        .complete_fleet_phase_under_traffic("traffic-final-forward-complete", lifecycle_checkpoint);
    for node_index in 0..member_count {
        fleet.transition_member_under_traffic(
            node_index,
            CredentialGeneration::NewRoot,
            TrustGeneration::NewOnly,
            &format!("traffic-final-new-only-node-{node_index}"),
            lifecycle_checkpoint,
        );
    }
    fleet.complete_fleet_phase_under_traffic(
        "traffic-final-new-only-complete",
        lifecycle_checkpoint,
    );
    assert_eq!(
        fleet.canary_generation, 13,
        "traffic campaign must advance the same complete rotation phase set"
    );
}

fn run_projected_mtls_traffic_resources(member_count: usize) {
    let mut fleet = Fleet::start_traffic(member_count);
    if member_count == 3 {
        fleet.assert_three_member_resolver_backoff_profile();
    }
    // This post-formation snapshot is the immutable campaign ledger baseline.
    // Every subsequent lifecycle interval chains from the prior exact
    // checkpoint, so failures or attempt storms between named phases cannot
    // disappear behind a newly sampled baseline.
    let campaign_lifecycle_baseline = fleet.all_lifecycle_metrics();
    let mut lifecycle_checkpoint = campaign_lifecycle_baseline.clone();
    let warmup_started = Instant::now();
    let warmup_deadline =
        warmup_started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    fleet.start_traffic_tasks();
    for _ in 0..QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND {
        fleet.fresh_all_directed_generation();
    }
    fleet.wait_ready();
    let traffic_after_warmup_reauthentication = fleet.all_traffic_statuses();
    let warmed_statuses = fleet.wait_for_traffic_progress(
        &traffic_after_warmup_reauthentication,
        "resource-baseline-warmup",
        warmup_deadline,
    );
    let warmup_lifecycle = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_checkpoint,
        warmup_deadline,
        "resource-baseline-warmup",
    );
    assert_round_lifecycle_bounds(member_count, &lifecycle_checkpoint, &warmup_lifecycle);
    lifecycle_checkpoint = warmup_lifecycle;
    assert_transition_completed_by(warmup_started, warmup_deadline, "resource-baseline-warmup");
    assert!(warmed_statuses.iter().all(|status| {
        status.state == QualificationTrafficState::Running
            && status.failure.is_none()
            && status.owned_async_tasks == 2
    }));

    let process_ids = fleet
        .nodes
        .iter()
        .map(ChildNode::process_id)
        .collect::<Vec<_>>();
    let warmed = process_ids
        .iter()
        .copied()
        .map(read_classified_process_resources)
        .collect::<Vec<_>>();
    let sampler = ResourceSampler::start(process_ids.clone());
    let seed =
        qualification_traffic_seed(member_count).expect("supported traffic qualification topology");
    let transition_bound = Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    let total_rounds = member_count * QUALIFICATION_TRAFFIC_ROTATIONS_PER_MEMBER;
    for round in 0..total_rounds {
        let started = Instant::now();
        let round_deadline = started + transition_bound;
        let node_index = ((seed as usize) % member_count + round) % member_count;
        let rotation = round / member_count;
        fleet.transition_traffic_leaf(node_index, rotation);
        for _ in 0..QUALIFICATION_TRAFFIC_REAUTHENTICATIONS_PER_ROUND {
            fleet.fresh_all_directed_generation();
        }
        fleet.wait_ready();
        let traffic_after_reauthentication = fleet.all_traffic_statuses();
        fleet.wait_for_traffic_progress(
            &traffic_after_reauthentication,
            "repeated-same-issuer-leaf-rotation",
            round_deadline,
        );
        let metrics_after = fleet.wait_for_round_lifecycle_completion(
            &lifecycle_checkpoint,
            round_deadline,
            "repeated-same-issuer-leaf-rotation",
        );
        assert_round_lifecycle_bounds(member_count, &lifecycle_checkpoint, &metrics_after);
        lifecycle_checkpoint = metrics_after;
        assert_transition_completed_by(
            started,
            round_deadline,
            "repeated-same-issuer-leaf-rotation",
        );
    }

    run_projected_mtls_rotation_campaign_under_traffic(
        &mut fleet,
        member_count,
        &mut lifecycle_checkpoint,
    );

    let final_generation_started = Instant::now();
    let final_generation_deadline =
        final_generation_started + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    let mutation_statuses = fleet.stop_traffic_mutations();
    let caught_up = fleet.wait_for_watch_heads();
    for (mutation, watch) in mutation_statuses.iter().zip(&caught_up) {
        assert_eq!(mutation.last_generation, watch.last_generation);
        assert_eq!(mutation.last_record_fence, watch.last_record_fence);
    }
    fleet.fresh_all_directed_generation();
    fleet.wait_ready();
    let final_watch_statuses = fleet.wait_for_watch_heads();
    fleet.verify_all_traffic_records(&final_watch_statuses);
    let expected_generations = mutation_statuses
        .iter()
        .map(|status| status.last_generation)
        .collect::<Vec<_>>();
    for (node_index, status) in final_watch_statuses.iter().enumerate() {
        assert_eq!(
            status.watch_traffic_generations, expected_generations,
            "watch did not apply each traffic generation exactly once and in order: node={node_index}"
        );
    }
    let stopped = fleet.stop_traffic_watches();
    for (before, after) in final_watch_statuses.iter().zip(&stopped) {
        assert_eq!(after.watch_sequence, before.watch_sequence);
        assert_eq!(after.replication_head, before.replication_head);
        assert_completed_traffic_cycles(after);
    }
    fleet.retain_traffic_plaintext_canaries(&stopped);
    let final_generation_lifecycle = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_checkpoint,
        final_generation_deadline,
        "final-fresh-generation-and-traffic-stop",
    );
    let remote_peers = u64::try_from(member_count - 1).expect("bounded member count");
    assert_lifecycle_delta_bounds(
        member_count,
        &lifecycle_checkpoint,
        &final_generation_lifecycle,
        remote_peers,
    );
    lifecycle_checkpoint = final_generation_lifecycle;
    assert_transition_completed_by(
        final_generation_started,
        final_generation_deadline,
        "final-fresh-generation-and-traffic-stop",
    );

    let (settled, settled_lifecycle) = fleet.wait_for_resources_to_settle(&process_ids, &warmed);
    assert_lifecycle_delta_bounds(member_count, &lifecycle_checkpoint, &settled_lifecycle, 0);
    lifecycle_checkpoint = settled_lifecycle;
    let high_water = sampler.finish();
    assert_process_resource_bounds(member_count, &warmed, &high_water, &settled);

    let final_ledger_deadline =
        Instant::now() + Duration::from_millis(QUALIFICATION_TRAFFIC_TRANSITION_MILLIS);
    let final_lifecycle = fleet.wait_for_round_lifecycle_completion(
        &lifecycle_checkpoint,
        final_ledger_deadline,
        "campaign-final-lifecycle-ledger",
    );
    assert_lifecycle_delta_bounds(member_count, &lifecycle_checkpoint, &final_lifecycle, 0);
    assert_campaign_lifecycle_failure_ledger(
        member_count,
        &campaign_lifecycle_baseline,
        &final_lifecycle,
    );

    fleet.shutdown();
    fleet.assert_plaintext_canaries_absent_from_sqlite();
    assert!(fleet.workspace.path().is_dir());
}

#[test]
fn three_process_projected_mtls_rotation_core() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_rotation_core(3);
}

#[test]
fn five_process_projected_mtls_rotation_core() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_rotation_core(5);
}

#[test]
#[ignore = "manual long-running projected-mTLS traffic/resource qualification"]
fn three_process_projected_mtls_traffic_and_resource_bounds() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_traffic_resources(3);
}

#[test]
#[ignore = "manual long-running projected-mTLS traffic/resource qualification"]
fn five_process_projected_mtls_traffic_and_resource_bounds() {
    let _guard = FLEET_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_projected_mtls_traffic_resources(5);
}

fn lifecycle_metrics_fixture() -> QualificationConnectionLifecycleMetrics {
    QualificationConnectionLifecycleMetrics {
        retirement_maximum_age: 0,
        retirement_local_leaf_expiry: 0,
        retirement_peer_leaf_expiry: 0,
        retirement_local_certificate_chain_expiry: 0,
        retirement_peer_certificate_chain_expiry: 0,
        retirement_material_epoch: 0,
        retirement_explicit: 0,
        retirement_idle_timeout: 0,
        active_connections: 0,
        draining_connections: 0,
        drain_started: 0,
        drain_completed: 0,
        drain_overruns: 0,
        connection_attempts: 0,
        connection_successes: 0,
        connection_failure_transport: 0,
        connection_failure_authentication: 0,
        connection_failure_timeout: 0,
        connection_failure_protocol: 0,
        connection_failure_backend: 0,
        reconnect_attempts: 0,
        reconnect_failures: 0,
        empty_vote_dispatches: 0,
    }
}

fn traffic_status_fixture(member_count: usize) -> QualificationTrafficStatus {
    QualificationTrafficStatus {
        state: QualificationTrafficState::Running,
        failure: None,
        seed: 1,
        owned_async_tasks: 2,
        mutation_cycles: 10,
        linearizable_reads: 10,
        lease_renewals: 10,
        lease_reacquisitions: 10,
        complete_restore_scans: 10,
        durable_readiness_probes: 10,
        last_generation: 10,
        last_record_fence: 10,
        watch_entries: 10,
        watch_applied_records: 10,
        watch_sequence: 10,
        watch_traffic_generations: vec![10; member_count],
        replication_head: 10,
    }
}

#[test]
fn campaign_ledger_rejects_an_interstitial_failure_outside_leaf_rounds() {
    let member_count = 3;
    let before = vec![lifecycle_metrics_fixture(); member_count];
    let mut valid_after = before.clone();
    for metrics in &mut valid_after {
        metrics.connection_attempts = 1;
        metrics.connection_failure_authentication = 1;
    }
    assert_campaign_lifecycle_failure_ledger(member_count, &before, &valid_after);

    let mut failed_after = valid_after.clone();
    failed_after[1].connection_attempts += 1;
    failed_after[1].connection_failure_timeout += 1;
    let rejected = std::panic::catch_unwind(|| {
        assert_campaign_lifecycle_failure_ledger(member_count, &before, &failed_after);
    });
    assert!(rejected.is_err());
}

#[test]
fn chained_interval_bounds_reject_an_attempt_storm_between_named_phases() {
    let member_count = 3;
    let before = vec![lifecycle_metrics_fixture(); member_count];
    let mut after = before.clone();
    let bound = QUALIFICATION_TRAFFIC_CONNECTION_BOUND_FACTOR
        * u64::try_from(member_count - 1).expect("bounded member count")
        + QUALIFICATION_TRAFFIC_CONNECTION_BOUND_ALLOWANCE;
    after[0].connection_attempts = bound + 1;
    after[0].connection_successes = bound + 1;
    let rejected = std::panic::catch_unwind(|| {
        assert_lifecycle_delta_bounds(member_count, &before, &after, 0);
    });
    assert!(rejected.is_err());
}

#[test]
fn traffic_progress_requires_every_observer_watch_dimension_and_key_to_advance() {
    let before = traffic_status_fixture(3);
    let mut after = before.clone();
    after.mutation_cycles += 1;
    after.watch_entries += 3;
    after.watch_applied_records += 3;
    after.watch_sequence += 3;
    for generation in &mut after.watch_traffic_generations {
        *generation += 1;
    }
    assert!(traffic_status_made_semantic_progress(&before, &after, 3));

    for stalled in ["mutation", "entries", "applied", "sequence", "key"] {
        let mut candidate = after.clone();
        match stalled {
            "mutation" => candidate.mutation_cycles = before.mutation_cycles,
            "entries" => candidate.watch_entries = before.watch_entries,
            "applied" => candidate.watch_applied_records = before.watch_applied_records,
            "sequence" => candidate.watch_sequence = before.watch_sequence,
            "key" => candidate.watch_traffic_generations[1] = before.watch_traffic_generations[1],
            _ => unreachable!(),
        }
        assert!(
            !traffic_status_made_semantic_progress(&before, &candidate, 3),
            "stalled semantic watch dimension was accepted: {stalled}"
        );
    }
}

#[test]
fn transition_deadline_never_accepts_a_late_success() {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(10);
    assert!(deadline_allows_completion(deadline, deadline));
    assert!(!deadline_allows_completion(
        deadline + Duration::from_nanos(1),
        deadline
    ));
}

#[test]
fn transition_completion_requires_drained_epochs_and_bounded_live_handlers() {
    let member_count = 3;
    let settled = lifecycle_metrics_fixture();
    assert!(lifecycle_transition_is_settled(&settled, member_count));

    let mut draining = settled;
    draining.draining_connections = 1;
    assert!(!lifecycle_transition_is_settled(&draining, member_count));
    let mut incomplete_drain = settled;
    incomplete_drain.drain_started = 1;
    assert!(!lifecycle_transition_is_settled(
        &incomplete_drain,
        member_count
    ));
    let mut overrun = settled;
    overrun.drain_started = 1;
    overrun.drain_completed = 1;
    overrun.drain_overruns = 1;
    assert!(!lifecycle_transition_is_settled(&overrun, member_count));
    let mut too_many_active = settled;
    too_many_active.active_connections = lifecycle_active_connection_bound(member_count) + 1;
    assert!(!lifecycle_transition_is_settled(
        &too_many_active,
        member_count
    ));
}

#[test]
fn persistent_connection_attempt_accounting_is_non_overlapping() {
    let mut metrics = lifecycle_metrics_fixture();
    metrics.active_connections = 5;
    metrics.connection_attempts = 8;
    metrics.connection_successes = 5;
    assert_eq!(connection_attempt_accounting(&metrics), Some((5, 3, 5)));
    assert!(connection_attempts_accounted(&metrics));

    // Two successful outbound connections can remain active alongside three
    // unterminated inbound handlers. Adding all five active gauges to the five
    // terminal successes would double-count those outbound connections.
    metrics.active_connections = 2;
    assert!(!connection_attempts_accounted(&metrics));
    metrics.active_connections = 2;
    metrics.draining_connections = 1;
    assert!(connection_attempts_accounted(&metrics));

    metrics.connection_attempts = 4;
    assert_eq!(connection_attempt_accounting(&metrics), None);
}

#[test]
fn sqlite_family_reader_requires_primary_and_rejects_sidecar_read_errors() {
    let directory = tempfile::tempdir().expect("SQLite family helper directory");
    let database = directory.path().join("session.sqlite");

    let missing = read_sqlite_family(&database).expect_err("missing primary must fail");
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);

    fs::create_dir(&database).expect("create non-file primary fixture");
    let unreadable_primary = read_sqlite_family(&database).expect_err("non-file primary must fail");
    assert_ne!(unreadable_primary.kind(), std::io::ErrorKind::NotFound);
    fs::remove_dir(&database).expect("remove non-file primary fixture");

    fs::write(&database, b"primary").expect("write primary SQLite fixture");
    let primary_only = read_sqlite_family(&database).expect("absent sidecars are optional");
    assert_eq!(primary_only, [(database.clone(), b"primary".to_vec())]);

    let wal = PathBuf::from(format!("{}-wal", database.display()));
    fs::create_dir(&wal).expect("create unreadable WAL fixture");
    let unreadable = read_sqlite_family(&database).expect_err("non-file WAL must fail");
    assert_ne!(unreadable.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn plaintext_canary_domain_validation_covers_both_fixed_prefixes() {
    let values = vec![
        "opc-rotation-plaintext-canary/3/1/fixture".to_owned(),
        qualification_traffic_value(1, 3, 0, 1),
    ];
    assert_eq!(
        retained_plaintext_canary_domain_counts(&values),
        Some([1, 1])
    );
    assert_eq!(
        retained_plaintext_canary_domain_counts(&["unknown-canary/fixture".to_owned()]),
        None
    );
}

#[test]
fn plaintext_canary_prefix_scan_detects_each_domain() {
    for (index, prefix) in PLAINTEXT_CANARY_PREFIXES.into_iter().enumerate() {
        let mut artifact = b"bounded-prefix-fixture/".to_vec();
        artifact.extend_from_slice(prefix);
        artifact.extend_from_slice(b"suffix");
        let presence = plaintext_canary_prefix_presence(&artifact);
        assert!(presence[index]);
    }
}

#[test]
fn plaintext_canary_prefix_scan_accepts_clean_similar_artifacts() {
    assert_eq!(
        plaintext_canary_prefix_presence(
            b"opc-rotation-plaintext-canary;opc-rotation-traffic-canary;encrypted"
        ),
        [false, false]
    );
}
