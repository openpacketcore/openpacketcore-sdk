//! In-process quorum-fleet mTLS rotation fault-matrix qualification (#164).
//!
//! The merged rotation-mechanism evidence (`three_member_openraft_fleet_rotates_and_rolls_back_real_mtls`
//! and its five-member sibling in `consensus_transport.rs`) proves the forward
//! and rollback rotation phases over real mTLS with fresh directed handshakes,
//! durable probes, and an acknowledged encrypted canary. This file extends that
//! campaign with the fault matrix the issue still owed in-process:
//!
//! - a follower partition (listener stop + resolver fence + lane retirement)
//!   overlapping a survivor leaf rotation, with continuous acknowledged canary
//!   traffic and a bounded catch-up recovery;
//! - one unavailable member plus one member rejecting malformed reloads
//!   (identity-mismatched, empty, over-limit) inside the declared topology
//!   failure budget, proving retained-last-good material never publishes
//!   mixed or invalid chains and a later coherent reload still rotates;
//! - repeated leaf-rotation cycles bounded by per-path handshake (resolver)
//!   accounting (fresh handshakes on affected paths, bounded transition and
//!   per-path campaign totals, a final settle window with zero redials), a
//!   Linux file-descriptor growth allowance, and zero authentication
//!   failures;
//! - a member listener restart while fleet trust advances to the overlap
//!   bundle, rejoining under the overlap and completing the root cutover to
//!   new-only trust with an old-chain rejection proof.
//!
//! Every campaign emits a deterministic `opc.session-net.rotation-fault-evidence.v1`
//! JSON document (topology, pinned lifecycle/timing values, phase plan digest,
//! per-phase SLO durations, canary generation accounting, resource/handshake
//! bounds, artifact digests, timestamps, and checker provenance) and validates
//! it with the independent stdlib checker
//! `scripts/check-session-rotation-fleet-evidence.py`. The per-kind duration
//! SLOs are the profile-derived envelopes documented in
//! `docs/rotation-qualification-plan.md`: the 26-second two-election-plus-operation
//! transition envelope, the 37-second member-recovery stage, and the
//! (members + 1) x operation-timeout traffic-round envelope.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::{DURABLE_CONSENSUS_OPERATION_TIMEOUT, DURABLE_CONSENSUS_TIMING_PROFILE};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId,
    SessionConfigurationEpoch, SessionConfigurationGeneration, SessionConsensusServer,
    SessionConsensusServerHandle, SessionReauthenticationControl, SessionReplicationManifest,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, EncryptedSessionPayload,
    EncryptingSessionBackend, Generation, LeaseGuard, OwnerId, QuorumReplicaDescriptor,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, SessionBackend, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend, StateClass, StateType,
    StoredSessionRecord, SystemClock, ValidatedQuorumTopology,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder,
    TlsMaterialAvailability, TlsMaterialEpoch, TlsMaterialReloadReason,
};
use opc_types::{NetworkFunctionKind, TenantId};
use sha2::Digest as _;

/// Two election windows plus one operation timeout: the documented member
/// transition and durable-readiness envelope (runbook restart-stage table).
const TRANSITION_ENVELOPE: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);
/// The member-recovery stage: transition envelope plus one backend operation
/// and one delivery second (runbook Openraft-recovery stage).
const RECOVERY_ENVELOPE: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis)
        .saturating_add(1_000),
);
/// Isolation, rejection, and measurement phases are local actions bounded by
/// one operation timeout.
const LOCAL_ACTION_BOUND: Duration = DURABLE_CONSENSUS_OPERATION_TIMEOUT;
/// Linux file-descriptor growth allowance across a repeated-rotation campaign
/// (mirrors the testkit miscellaneous-descriptor allowance).
const FD_GROWTH_ALLOWANCE: usize = 8;
/// Upper bound on the summed resolver deltas of every healthy directed path
/// in one member transition window (lane replacements, directed probes, and
/// any late retirement redial attributable to an earlier transition).
const TRANSITION_RESOLVER_ALLOWANCE: usize = 16;
/// Upper bound on the summed resolver deltas of one directed path across a
/// whole campaign: two cached lanes plus one bounded retry per endpoint
/// rotation of the path's two members (3 x 2 x 3 rotation cycles; measured
/// campaigns total 9-13 per path). A reconnect storm exceeds it by orders of
/// magnitude.
const PATH_TOTAL_ALLOWANCE: usize = 18;
/// Campaigns prove no background redial churn with a final settle window
/// after the last transition, when no lane retirement remains in flight.
const FINAL_SETTLE_WINDOW: Duration = Duration::from_millis(500);
/// Settle before the descriptor baseline so the measurement starts from a
/// quiet fleet.
const QUIET_WINDOW: Duration = Duration::from_millis(250);

const EVIDENCE_SCHEMA: &str = "opc.session-net.rotation-fault-evidence.v1";
const CHECKER_RELATIVE_PATH: &str = "scripts/check-session-rotation-fleet-evidence.py";

// Each scenario starts a complete Openraft fleet in its own Tokio runtime;
// keep them sequential inside this binary (same rationale as the merged
// rotation campaign in consensus_transport.rs).
static FLEET_TEST_GUARD: StdMutex<()> = StdMutex::new(());

fn run_fleet_test(worker_threads: usize, scenario: impl std::future::Future<Output = ()>) {
    let _fleet_test_guard = FLEET_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("fault-matrix fleet test runtime");
    runtime.block_on(scenario);
    drop(runtime);
}

struct RotationRoot {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl RotationRoot {
    fn new(label: &str) -> Self {
        let key = rcgen::KeyPair::generate().expect("rotation root key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("{label} fault-matrix root"),
        );
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        let issuer =
            rcgen::CertifiedIssuer::self_signed(params, key).expect("rotation root certificate");
        Self { issuer }
    }

    fn issue_intermediate(&self, label: &str) -> RotationIntermediate {
        let key = rcgen::KeyPair::generate().expect("rotation intermediate key");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("{label} fault-matrix intermediate"),
        );
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(14);
        let issuer = rcgen::CertifiedIssuer::signed_by(params, key, &self.issuer)
            .expect("rotation intermediate certificate");
        RotationIntermediate { issuer }
    }
}

struct RotationIntermediate {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl RotationIntermediate {
    fn issue_leaf(&self, replica: u16) -> RotationLeaf {
        let key = rcgen::KeyPair::generate().expect("rotation leaf key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("replica-{replica}"));
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(replica_spiffe(replica)).expect("SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(1);
        let certificate = params
            .signed_by(&key, &self.issuer)
            .expect("rotation leaf certificate");
        RotationLeaf { certificate, key }
    }
}

struct RotationLeaf {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl RotationLeaf {
    fn identity_state(
        &self,
        intermediate: &RotationIntermediate,
        trust_roots: &[&RotationRoot],
    ) -> opc_identity::IdentityState {
        let cert_chain = parse_certs_pem(&(self.certificate.pem() + &intermediate.issuer.pem()))
            .expect("rotation certificate chain PEM");
        let private_key = parse_key_pem(&self.key.serialize_pem()).expect("rotation key PEM");
        identity_state_with_trust(cert_chain, private_key, trust_roots)
    }
}

fn identity_state_with_trust(
    cert_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    private_key: rustls_pki_types::PrivateKeyDer<'static>,
    trust_roots: &[&RotationRoot],
) -> opc_identity::IdentityState {
    let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
    let trust_pem = trust_roots
        .iter()
        .map(|root| root.issuer.pem())
        .collect::<String>();
    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain,
        certificates: parse_certs_pem(&trust_pem).expect("rotation trust PEM"),
    });
    build_identity_state(cert_chain, private_key, trust_bundles).expect("rotation identity state")
}

/// A reload that exceeds the fixed trust-bundle count bound must be rejected
/// with `MaterialLimitExceeded` and never presented on any lane.
fn oversized_bundle_identity_state(
    leaf: &RotationLeaf,
    intermediate: &RotationIntermediate,
    trust_roots: &[&RotationRoot],
) -> opc_identity::IdentityState {
    let cert_chain = parse_certs_pem(&(leaf.certificate.pem() + &intermediate.issuer.pem()))
        .expect("oversized certificate chain PEM");
    let private_key = parse_key_pem(&leaf.key.serialize_pem()).expect("oversized key PEM");
    let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
    let trust_pem = trust_roots
        .iter()
        .map(|root| root.issuer.pem())
        .collect::<String>();
    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain,
        certificates: parse_certs_pem(&trust_pem).expect("oversized trust PEM"),
    });
    for index in 0..opc_tls::MAX_TLS_MATERIAL_TRUST_BUNDLES {
        let trust_domain =
            opc_identity::TrustDomain::new(format!("unused-{index}.test")).expect("unused domain");
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: parse_certs_pem(&trust_pem).expect("oversized trust PEM"),
        });
    }
    build_identity_state(cert_chain, private_key, trust_bundles).expect("oversized identity state")
}

fn replica_id(replica: u16) -> ReplicaId {
    ReplicaId::new(format!("replica-{replica}")).expect("replica ID")
}

fn replica_spiffe(replica: u16) -> String {
    format!("spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/{replica}")
}

fn descriptor(replica: u16) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(replica),
        ReplicaEndpoint::new(format!("replica-{replica}-g1.session.invalid"), 7443)
            .expect("endpoint"),
        ReplicaTlsIdentity::new(replica_spiffe(replica)).expect("TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
    )
}

fn manifest_for_replicas(cluster: &str, replicas: &[u16]) -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).expect("cluster ID"),
            SessionConfigurationGeneration::new("fault-matrix-v1").expect("generation"),
            SessionConfigurationEpoch::new(29).expect("configuration epoch"),
            replicas
                .iter()
                .map(|replica| descriptor(*replica))
                .collect(),
        )
        .expect("fault-matrix manifest"),
    )
}

fn fenced_deferred_resolver(
    address: Arc<StdRwLock<Option<SocketAddr>>>,
    enabled: Arc<AtomicBool>,
    resolutions: Arc<AtomicUsize>,
) -> RemoteAddrResolver {
    Arc::new(move || {
        let address = Arc::clone(&address);
        let enabled = Arc::clone(&enabled);
        let resolutions = Arc::clone(&resolutions);
        Box::pin(async move {
            resolutions.fetch_add(1, Ordering::SeqCst);
            if !enabled.load(Ordering::Acquire) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "fault-matrix test path fenced",
                ));
            }
            address
                .read()
                .map_err(|_| std::io::Error::other("fault-matrix address lock poisoned"))?
                .as_ref()
                .copied()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "fault-matrix server is not listening",
                    )
                })
        })
    })
}

fn direct_resolver(addr: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(addr) }))
}

fn fleet_lifecycle() -> ConnectionLifecyclePolicy {
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_millis(100),
        Duration::from_millis(1),
        Duration::from_millis(20),
        Duration::ZERO,
    )
    .expect("fault-matrix lifecycle policy")
}

fn single_attempt_probe_lifecycle() -> ConnectionLifecyclePolicy {
    let cold_connect_timeout = DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_millis(100),
        cold_connect_timeout,
        cold_connect_timeout,
        Duration::ZERO,
    )
    .expect("single-attempt probe lifecycle policy")
}

#[derive(Debug, Default)]
struct TransportStats {
    outcomes: StdMutex<BTreeMap<String, usize>>,
}

impl TransportStats {
    fn record(&self, outcome: String) {
        let mut outcomes = self
            .outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *outcomes.entry(outcome).or_default() += 1;
    }

    fn total_matching(&self, suffix: &str) -> usize {
        self.outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(outcome, _)| outcome.ends_with(suffix))
            .map(|(_, count)| *count)
            .sum()
    }
}

#[derive(Debug, Clone)]
struct InstrumentedConsensusPeer {
    inner: RemoteSessionConsensusPeer,
    stats: Arc<TransportStats>,
}

impl InstrumentedConsensusPeer {
    fn record_result(
        &self,
        family: &str,
        result: &Result<SessionConsensusWireResponse, SessionConsensusPeerError>,
    ) {
        let status = match result {
            Ok(response) if response.result.is_ok() => "ok",
            Ok(response) => match response.result {
                Err(SessionConsensusPeerError::Unavailable) => "remote_unavailable",
                Err(SessionConsensusPeerError::Timeout) => "remote_timeout",
                Err(SessionConsensusPeerError::Authentication) => "remote_authentication",
                Err(_) => "remote_other",
                Ok(_) => "ok",
            },
            Err(SessionConsensusPeerError::Unavailable) => "unavailable",
            Err(SessionConsensusPeerError::Timeout) => "timeout",
            Err(SessionConsensusPeerError::Authentication) => "authentication",
            Err(_) => "other",
        };
        self.stats.record(format!("{family}:{status}"));
    }
}

#[async_trait]
impl SessionConsensusPeer for InstrumentedConsensusPeer {
    fn node_id(&self) -> opc_session_store::SessionConsensusNodeId {
        self.inner.node_id()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let family = request.family.as_str();
        let result = self.inner.call(request).await;
        self.record_result(family, &result);
        result
    }

    async fn call_with_timeout(
        &self,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let family = request.family.as_str();
        let result = self.inner.call_with_timeout(request, timeout).await;
        self.record_result(family, &result);
        result
    }
}

fn vote_probe(
    manifest: &Arc<SessionReplicationManifest>,
    sender: u16,
) -> SessionConsensusWireRequest {
    let binding = manifest
        .bind_local(replica_id(sender))
        .expect("probe sender binding");
    SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        SessionConsensusRpcFamily::Vote,
        Vec::new(),
    )
    .expect("bounded probe request")
}

struct FaultNodeMaterial {
    source: tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
    client: AuthenticatedClientConfig,
    server: AuthenticatedServerConfig,
    reauthentication: SessionReauthenticationControl,
}

impl FaultNodeMaterial {
    fn new(initial: opc_identity::IdentityState) -> Self {
        let (source, receiver) = tokio::sync::watch::channel(Some(initial));
        let client = TlsConfigBuilder::new(receiver.clone())
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("fault-matrix client config");
        let server = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("fault-matrix server config");
        Self {
            source,
            client,
            server,
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    async fn publish(&self, state: opc_identity::IdentityState) {
        let client_epoch = self.client.material_status().epoch();
        let server_epoch = self.server.material_status().epoch();
        self.source.send_replace(Some(state));
        wait_for_material_epoch_change(|| self.client.material_status(), client_epoch).await;
        wait_for_material_epoch_change(|| self.server.material_status(), server_epoch).await;
        self.reauthentication
            .request_reauthentication()
            .expect("request fault-matrix reauthentication");
    }
}

async fn wait_for_material_epoch_change(
    status: impl Fn() -> opc_tls::TlsMaterialStatus,
    previous: TlsMaterialEpoch,
) {
    tokio::time::timeout(LOCAL_ACTION_BOUND, async {
        loop {
            let current = status();
            if current.epoch() != previous
                && current.availability() == TlsMaterialAvailability::Ready
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fault-matrix material epoch update");
}

async fn wait_for_material_rejection(
    status: impl Fn() -> opc_tls::TlsMaterialStatus,
    epoch: TlsMaterialEpoch,
    reason: TlsMaterialReloadReason,
) {
    tokio::time::timeout(LOCAL_ACTION_BOUND, async {
        loop {
            let current = status();
            if current.epoch() == epoch
                && current.availability() == TlsMaterialAvailability::RetainingLastGood
                && current.reason() == Some(reason)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("a rejected reload must retain the last known-good material");
}

struct RotationCanary {
    key: SessionKey,
    lease: LeaseGuard,
    generation: u64,
}

fn canary_record(key: SessionKey, lease: &LeaseGuard, generation: u64) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("mtls-fault-matrix"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(
            format!("fault-matrix-generation-{generation}").into_bytes(),
        ),
    }
}

fn utc_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_secs()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("hex write");
    }
    hex
}

fn fd_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate directory has a workspace root")
        .to_path_buf()
}

/// The per-phase fields recorded by a campaign: what ran, which member it
/// touched, the acknowledged canary generation after it, how many directed
/// paths proved a fresh handshake, and which members were verified ready.
#[derive(Debug)]
struct PhaseObservation {
    name: String,
    kind: &'static str,
    member: Option<usize>,
    canary_generation: u64,
    fresh_handshake_paths: usize,
    ready_members: Vec<usize>,
}

#[derive(Debug)]
struct PhaseRecord {
    name: String,
    kind: &'static str,
    member: Option<usize>,
    canary_generation: u64,
    fresh_handshake_paths: usize,
    ready_members: Vec<usize>,
    duration: Duration,
    completed_epoch_seconds: u64,
}

/// The deterministic evidence document every campaign emits and the
/// independent checker validates. All bounds are asserted live in the test
/// first; the document only records what the test already proved.
#[derive(Debug)]
struct CampaignEvidence {
    campaign_id: &'static str,
    cluster: String,
    members: usize,
    started_epoch_seconds: u64,
    phases: Vec<PhaseRecord>,
    fd_growth: Option<usize>,
    max_transition_resolver_deltas: usize,
    max_path_total_resolver_deltas: usize,
    final_quiet_window_deltas: usize,
    authentication_failure_outcomes: usize,
    rejected_reload_retentions: usize,
    trust_anchor_digests: Vec<String>,
}

impl CampaignEvidence {
    fn new(campaign_id: &'static str, cluster: String, members: usize) -> Self {
        Self {
            campaign_id,
            cluster,
            members,
            started_epoch_seconds: utc_epoch_seconds(),
            phases: Vec::new(),
            fd_growth: None,
            max_transition_resolver_deltas: 0,
            max_path_total_resolver_deltas: 0,
            final_quiet_window_deltas: 0,
            authentication_failure_outcomes: 0,
            rejected_reload_retentions: 0,
            trust_anchor_digests: Vec::new(),
        }
    }

    /// Bind the exact trust anchors used by the campaign. The PKI keys are
    /// drawn fresh from the OS CSPRNG on every run, so the evidence pins the
    /// run's anchors by digest instead of by seed; the phase plan, fixed
    /// configuration, and closed bounds keep the outcome reproducible.
    fn record_trust_anchors(&mut self, roots: &[&RotationRoot]) {
        self.trust_anchor_digests = roots
            .iter()
            .map(|root| sha256_hex(root.issuer.pem().as_bytes()))
            .collect();
        self.trust_anchor_digests.sort_unstable();
        self.trust_anchor_digests.dedup();
    }

    fn record(&mut self, observation: PhaseObservation, started: Instant) {
        self.phases.push(PhaseRecord {
            name: observation.name,
            kind: observation.kind,
            member: observation.member,
            canary_generation: observation.canary_generation,
            fresh_handshake_paths: observation.fresh_handshake_paths,
            ready_members: observation.ready_members,
            duration: started.elapsed(),
            completed_epoch_seconds: utc_epoch_seconds(),
        });
    }

    fn plan_digest(&self) -> String {
        let mut plan = format!("{}|{}|", self.campaign_id, self.members);
        for (index, phase) in self.phases.iter().enumerate() {
            if index > 0 {
                plan.push(',');
            }
            let member = phase
                .member
                .map_or_else(|| "-".to_string(), |member| member.to_string());
            plan.push_str(&format!("{}:{}:{member}", phase.name, phase.kind));
        }
        sha256_hex(plan.as_bytes())
    }

    fn to_json(&self, checker_path: &Path, finished_epoch_seconds: u64) -> serde_json::Value {
        let checker_sha256 = sha256_hex(
            &std::fs::read(checker_path).expect("read independent checker for digest binding"),
        );
        let test_binary_sha256 = std::env::current_exe()
            .ok()
            .and_then(|exe| std::fs::read(exe).ok())
            .map(|bytes| sha256_hex(&bytes));
        let phases = self
            .phases
            .iter()
            .map(|phase| {
                serde_json::json!({
                    "name": phase.name,
                    "kind": phase.kind,
                    "member": phase.member,
                    "canary_generation": phase.canary_generation,
                    "fresh_handshake_paths": phase.fresh_handshake_paths,
                    "ready_members": phase.ready_members,
                    "duration_millis": phase.duration.as_millis() as u64,
                    "completed_epoch_seconds": phase.completed_epoch_seconds,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema": EVIDENCE_SCHEMA,
            "campaign_id": self.campaign_id,
            "topology": {
                "members": self.members,
                "cluster": self.cluster,
                "failure_budget_unavailable": (self.members - 1) / 2,
            },
            "artifacts": {
                "test_binary_sha256": test_binary_sha256,
                "checker_path": CHECKER_RELATIVE_PATH,
                "checker_sha256": checker_sha256,
                "trust_anchor_digests": self.trust_anchor_digests,
            },
            "configuration": {
                "lifecycle": {
                    "max_connection_age_seconds": 60,
                    "drain_window_millis": 100,
                    "reconnect_min_millis": 1,
                    "reconnect_max_millis": 20,
                },
                "timing_profile": {
                    "cold_connect_timeout_millis": DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout_millis,
                    "heartbeat_millis": DURABLE_CONSENSUS_TIMING_PROFILE.append_entries_timeout_millis,
                    "election_timeout_max_millis": DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis,
                    "operation_timeout_millis": DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
                },
            },
            "plan_sha256": self.plan_digest(),
            "started_epoch_seconds": self.started_epoch_seconds,
            "finished_epoch_seconds": finished_epoch_seconds,
            "phases": phases,
            "bounds": {
                "fd_growth": self.fd_growth,
                "fd_allowance": FD_GROWTH_ALLOWANCE,
                "max_transition_resolver_deltas": self.max_transition_resolver_deltas,
                "resolver_delta_allowance": TRANSITION_RESOLVER_ALLOWANCE,
                "max_path_total_resolver_deltas": self.max_path_total_resolver_deltas,
                "path_total_allowance": PATH_TOTAL_ALLOWANCE,
                "final_quiet_window_deltas": self.final_quiet_window_deltas,
                "authentication_failure_outcomes": self.authentication_failure_outcomes,
                "rejected_reload_retentions": self.rejected_reload_retentions,
            },
            "outcome": "pass",
        })
    }

    /// Write the document and validate it with the independent stdlib
    /// checker. With `OPC_ROTATION_EVIDENCE_DIR` set, also persist a copy for
    /// archival (0600), mirroring the operator campaign's durable evidence
    /// publication step.
    fn emit_and_check(&self) {
        let checker_path = repo_root().join(CHECKER_RELATIVE_PATH);
        let finished = utc_epoch_seconds();
        let document = self.to_json(&checker_path, finished);
        let directory = tempfile::tempdir().expect("evidence directory");
        let path = directory
            .path()
            .join(format!("{}-evidence.json", self.campaign_id));
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&document).expect("serialize evidence"),
        )
        .expect("write evidence document");
        run_checker(&path, finished).unwrap_or_else(|error| {
            panic!("independent checker rejected emitted evidence: {error}")
        });
        if let Ok(archive) = std::env::var("OPC_ROTATION_EVIDENCE_DIR") {
            let archive = PathBuf::from(archive);
            std::fs::create_dir_all(&archive).expect("create evidence archive directory");
            let target = archive.join(format!("{}-evidence.json", self.campaign_id));
            std::fs::copy(&path, &target).expect("archive evidence document");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                    .expect("restrict archived evidence permissions");
            }
        }
    }
}

fn run_checker(evidence: &Path, now_epoch: u64) -> Result<(), String> {
    let checker_path = repo_root().join(CHECKER_RELATIVE_PATH);
    let output = Command::new("python3")
        .arg(&checker_path)
        .arg(evidence)
        .arg("--now-epoch")
        .arg(now_epoch.to_string())
        .output()
        .expect("spawn independent rotation-fault evidence checker");
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "status={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn write_json_document(directory: &Path, name: &str, document: &serde_json::Value) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(document).expect("serialize document"),
    )
    .expect("write JSON document");
    path
}

struct FaultFleet {
    _directory: tempfile::TempDir,
    replicas: Vec<u16>,
    manifest: Arc<SessionReplicationManifest>,
    stores: Vec<ConsensusSessionStore>,
    materials: Vec<FaultNodeMaterial>,
    address_slots: Vec<Arc<StdRwLock<Option<SocketAddr>>>>,
    path_enabled: BTreeMap<(usize, usize), Arc<AtomicBool>>,
    resolver_calls: BTreeMap<(usize, usize), Arc<AtomicUsize>>,
    transport_stats: BTreeMap<(usize, usize), Arc<TransportStats>>,
    probes: BTreeMap<(usize, usize), Arc<InstrumentedConsensusPeer>>,
    servers: Vec<Option<SessionConsensusServerHandle>>,
    provider: Arc<MemoryKeyProvider>,
    canary: Option<RotationCanary>,
    down: BTreeSet<usize>,
    path_totals: BTreeMap<(usize, usize), usize>,
    evidence: CampaignEvidence,
}

impl FaultFleet {
    async fn start(
        campaign_id: &'static str,
        initial_states: Vec<opc_identity::IdentityState>,
    ) -> Self {
        let member_count = initial_states.len();
        assert!(matches!(member_count, 3 | 5), "qualification topology");
        let replicas = (1..=member_count)
            .map(|replica| u16::try_from(replica).expect("bounded test replica"))
            .collect::<Vec<_>>();
        let cluster = format!("mtls-fault-matrix-{member_count}");
        let manifest = manifest_for_replicas(&cluster, &replicas);
        let descriptors = replicas
            .iter()
            .map(|replica| descriptor(*replica))
            .collect::<Vec<_>>();
        let topologies = replicas
            .iter()
            .map(|replica| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(*replica),
                    descriptors.clone(),
                    manifest.consensus_identity(),
                ))
                .expect("validated fault-matrix topology")
            })
            .collect::<Vec<_>>();
        let directory = tempfile::tempdir().expect("fault-matrix fleet directory");
        let backends = replicas
            .iter()
            .map(|replica| {
                SqliteSessionBackend::open(
                    directory
                        .path()
                        .join(format!("fault-replica-{replica}.sqlite")),
                )
                .expect("fault-matrix SQLite backend")
            })
            .collect::<Vec<_>>();
        let address_slots = replicas
            .iter()
            .map(|_| Arc::new(StdRwLock::new(None)))
            .collect::<Vec<_>>();
        let materials = initial_states
            .into_iter()
            .map(FaultNodeMaterial::new)
            .collect::<Vec<_>>();
        let mut path_enabled = BTreeMap::new();
        let mut resolver_calls = BTreeMap::new();
        let mut transport_stats = BTreeMap::new();
        let mut probes = BTreeMap::new();
        let mut stores = Vec::with_capacity(member_count);

        for (source, replica) in replicas.iter().copied().enumerate() {
            let local = manifest
                .bind_local(replica_id(replica))
                .expect("fault-matrix local binding");
            let mut peers = BTreeMap::<_, Arc<dyn SessionConsensusPeer>>::new();
            for (target, remote_replica) in replicas.iter().copied().enumerate() {
                if source == target {
                    continue;
                }
                let binding = local
                    .bind_remote(replica_id(remote_replica))
                    .expect("fault-matrix remote binding");
                let node_id = binding.remote_consensus_node_id();
                let enabled = Arc::new(AtomicBool::new(true));
                let resolutions = Arc::new(AtomicUsize::new(0));
                let remote = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                    binding,
                    fenced_deferred_resolver(
                        Arc::clone(&address_slots[target]),
                        Arc::clone(&enabled),
                        Arc::clone(&resolutions),
                    ),
                    materials[source].client.clone(),
                )
                .with_connection_lifecycle(fleet_lifecycle())
                .with_reauthentication_control(materials[source].reauthentication.clone());
                let stats = Arc::new(TransportStats::default());
                let remote = Arc::new(InstrumentedConsensusPeer {
                    inner: remote,
                    stats: Arc::clone(&stats),
                });
                path_enabled.insert((source, target), enabled);
                resolver_calls.insert((source, target), resolutions);
                transport_stats.insert((source, target), stats);
                probes.insert((source, target), Arc::clone(&remote));
                peers.insert(node_id, remote);
            }
            stores.push(
                ConsensusSessionStore::open_with_clock(
                    topologies[source].clone(),
                    backends[source].clone(),
                    directory.path().join(format!("fault-snapshots-{replica}")),
                    peers,
                    Arc::new(SystemClock),
                    DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
                .expect("open fault-matrix consensus store"),
            );
        }

        let mut servers = Vec::with_capacity(member_count);
        for (index, replica) in replicas.iter().copied().enumerate() {
            let binding = manifest
                .bind_local(replica_id(replica))
                .expect("fault-matrix server binding");
            let (server, address) = SessionConsensusServer::new(
                stores[index].rpc_handler(),
                materials[index].server.clone(),
                binding,
            )
            .with_connection_lifecycle(fleet_lifecycle())
            .with_reauthentication_control(materials[index].reauthentication.clone())
            .listen("127.0.0.1:0".parse().expect("fault-matrix listen address"))
            .await
            .expect("start fault-matrix consensus listener");
            *address_slots[index]
                .write()
                .expect("fault-matrix address lock") = Some(address);
            servers.push(Some(server));
        }

        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new(format!("mtls-fault-matrix-{member_count}")).expect("key ID"),
                KeyPurpose::Session,
                TenantId::from_static("mtls-fault-matrix-tenant"),
                Zeroizing::new([0x4d; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install fault-matrix payload key");
        let mut fleet = Self {
            _directory: directory,
            replicas,
            manifest,
            stores,
            materials,
            address_slots,
            path_enabled,
            resolver_calls,
            transport_stats,
            probes,
            servers,
            provider,
            canary: None,
            down: BTreeSet::new(),
            path_totals: BTreeMap::new(),
            evidence: CampaignEvidence::new(campaign_id, cluster, member_count),
        };
        let started = Instant::now();
        fleet.probe_all_paths().await;
        let initialized = futures_util::future::join_all(
            fleet
                .stores
                .iter()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        for result in initialized {
            result.expect("initialize fault-matrix consensus fleet");
        }
        fleet.wait_ready(&fleet.reachable_members()).await;
        fleet.seed_canary(started).await;
        fleet
    }

    fn member_count(&self) -> usize {
        self.replicas.len()
    }

    fn reachable_members(&self) -> Vec<usize> {
        (0..self.member_count())
            .filter(|member| !self.down.contains(member))
            .collect()
    }

    fn resolver_snapshot(&self) -> BTreeMap<(usize, usize), usize> {
        self.resolver_calls
            .iter()
            .map(|(path, calls)| (*path, calls.load(Ordering::SeqCst)))
            .collect()
    }

    fn resolver_deltas(
        &self,
        before: &BTreeMap<(usize, usize), usize>,
    ) -> BTreeMap<(usize, usize), usize> {
        self.resolver_calls
            .iter()
            .map(|(path, calls)| {
                (
                    *path,
                    calls.load(Ordering::SeqCst) - before.get(path).copied().unwrap_or(0),
                )
            })
            .collect()
    }

    async fn wait_ready(&self, members: &[usize]) {
        let deadline = Instant::now() + TRANSITION_ENVELOPE;
        loop {
            let reports = futures_util::future::join_all(
                members
                    .iter()
                    .map(|index| self.stores[*index].probe_durable_readiness()),
            )
            .await;
            if reports.iter().all(|report| report.is_ready()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fault-matrix members {members:?} must become durably ready within the transition envelope: {reports:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// All reachable stores agree on one leader; returns that leader's index.
    async fn wait_stable_leader(&self, members: &[usize]) -> usize {
        let deadline = Instant::now() + TRANSITION_ENVELOPE;
        loop {
            let leaders = members
                .iter()
                .map(|index| self.stores[*index].status().leader_id)
                .collect::<Vec<_>>();
            if let Some(leader) = leaders.first().copied().flatten() {
                if leaders.iter().all(|candidate| *candidate == Some(leader)) {
                    return self
                        .stores
                        .iter()
                        .position(|store| store.status().node_id == leader)
                        .expect("observed leader belongs to the fault-matrix fleet");
                }
            }
            assert!(
                Instant::now() < deadline,
                "fault-matrix fleet must agree on one leader within the transition envelope: {leaders:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_converged(&self, members: &[usize]) {
        let deadline = Instant::now() + RECOVERY_ENVELOPE;
        loop {
            let applied = members
                .iter()
                .map(|index| self.stores[*index].status().applied_index)
                .collect::<Vec<_>>();
            if let Some(first) = applied.first().copied().flatten() {
                if applied.iter().all(|candidate| *candidate == Some(first)) {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "fault-matrix members {members:?} must converge within the recovery envelope: {applied:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Fresh bidirectional mTLS handshake proof on one directed path: the
    /// qualification-only empty Vote is idempotent and may retry availability
    /// failures until the operation deadline, but it must complete on a
    /// connection resolved after the probe began.
    async fn probe_path(&self, source: usize, target: usize) {
        let peer = self.probes.get(&(source, target)).expect("probe path");
        let resolutions = self
            .resolver_calls
            .get(&(source, target))
            .expect("probe resolver counter");
        let baseline = resolutions.load(Ordering::SeqCst);
        let deadline = Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
        let mut unavailable_attempts = 0usize;
        let outcome = loop {
            match peer
                .call(vote_probe(&self.manifest, self.replicas[source]))
                .await
            {
                Ok(response) if resolutions.load(Ordering::SeqCst) > baseline => {
                    break Ok(response);
                }
                Ok(_) => {}
                Err(SessionConsensusPeerError::Unavailable) => {
                    unavailable_attempts += 1;
                }
                Err(error) => break Err(error),
            }
            if Instant::now() >= deadline {
                break Err(SessionConsensusPeerError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert!(
            outcome.is_ok(),
            "fresh fault-matrix handshake failed: path=({source},{target}), outcome={outcome:?}, unavailable_attempts={unavailable_attempts}"
        );
    }

    async fn probe_all_paths(&self) -> usize {
        let paths = self
            .probes
            .keys()
            .copied()
            .filter(|path| self.path_enabled(path))
            .collect::<Vec<_>>();
        let count = paths.len();
        futures_util::future::join_all(
            paths
                .into_iter()
                .map(|(source, target)| self.probe_path(source, target)),
        )
        .await;
        count
    }

    fn path_enabled(&self, path: &(usize, usize)) -> bool {
        self.path_enabled
            .get(path)
            .is_some_and(|enabled| enabled.load(Ordering::Acquire))
    }

    async fn probe_member_paths(&self, member: usize) -> usize {
        let paths = self
            .probes
            .keys()
            .copied()
            .filter(|(source, target)| {
                (*source == member || *target == member) && self.path_enabled(&(*source, *target))
            })
            .collect::<Vec<_>>();
        let count = paths.len();
        futures_util::future::join_all(
            paths
                .into_iter()
                .map(|(source, target)| self.probe_path(source, target)),
        )
        .await;
        count
    }

    fn protected_store(
        &self,
        index: usize,
    ) -> EncryptingSessionBackend<ConsensusSessionStore, MemoryKeyProvider> {
        EncryptingSessionBackend::new(
            Arc::new(self.stores[index].clone()),
            Arc::clone(&self.provider),
            "mtls-fault-matrix",
        )
    }

    async fn seed_canary(&mut self, started: Instant) {
        let key = SessionKey {
            tenant: TenantId::from_static("mtls-fault-matrix-tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"mtls-fault-matrix-canary")
                .try_into()
                .expect("fault-matrix canary stable ID"),
        };
        let leader = self.wait_stable_leader(&self.reachable_members()).await;
        let writer = self.protected_store(leader);
        let lease = writer
            .acquire(
                &key,
                OwnerId::new("mtls-fault-matrix-owner").expect("canary owner"),
                Duration::from_secs(900),
            )
            .await
            .expect("acquire fault-matrix canary lease");
        let result = writer
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: canary_record(key.clone(), &lease, 1),
            })
            .await
            .expect("seed fault-matrix canary");
        assert_eq!(result, CompareAndSetResult::Success);
        self.canary = Some(RotationCanary {
            key,
            lease,
            generation: 1,
        });
        let reachable = self.reachable_members();
        self.verify_canary(&reachable).await;
        self.evidence.record(
            PhaseObservation {
                name: "seed-canary".to_string(),
                kind: "traffic",
                member: None,
                canary_generation: 1,
                fresh_handshake_paths: 0,
                ready_members: reachable,
            },
            started,
        );
    }

    /// One acknowledged encrypted canary advance on the current leader plus a
    /// linearizable read from every reachable voter. This is the continuous
    /// traffic unit: every round is exactly one acknowledged committed write,
    /// and the evidence checker enforces the exact +1 generation accounting.
    async fn traffic_round(&mut self, name: &str) {
        let started = Instant::now();
        let reachable = self.reachable_members();
        let leader = self.wait_stable_leader(&reachable).await;
        let canary = self.canary.as_ref().expect("seeded fault-matrix canary");
        let key = canary.key.clone();
        let lease = canary.lease.clone();
        let previous = canary.generation;
        let generation = previous
            .checked_add(1)
            .expect("bounded fault-matrix generation");
        let writer = self.protected_store(leader);
        let result = writer
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: Some(Generation::new(previous)),
                new_record: canary_record(key, &lease, generation),
            })
            .await
            .expect("advance fault-matrix canary");
        assert_eq!(result, CompareAndSetResult::Success);
        self.canary
            .as_mut()
            .expect("seeded fault-matrix canary")
            .generation = generation;
        self.verify_canary(&reachable).await;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "traffic",
                member: None,
                canary_generation: generation,
                fresh_handshake_paths: 0,
                ready_members: reachable,
            },
            started,
        );
    }

    async fn verify_canary(&self, members: &[usize]) {
        let canary = self.canary.as_ref().expect("seeded fault-matrix canary");
        for index in members {
            let record = tokio::time::timeout(
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                self.protected_store(*index).get(&canary.key),
            )
            .await
            .expect("fault-matrix canary read finishes within the operation SLO")
            .expect("linearizable fault-matrix canary read")
            .expect("fault-matrix canary remains present");
            assert_eq!(record.generation, Generation::new(canary.generation));
            assert_eq!(
                record.payload.as_bytes(),
                format!("fault-matrix-generation-{}", canary.generation).as_bytes()
            );
        }
    }

    /// Rotate one member's published material, then prove fresh bidirectional
    /// handshakes on every enabled directed path touching it and its fresh
    /// durable readiness. Returns the per-path resolver deltas for handshake
    /// rate accounting; the affected-path total and the untouched-path count
    /// are folded into the campaign evidence bounds automatically.
    async fn publish_member(
        &mut self,
        member: usize,
        state: opc_identity::IdentityState,
        name: &str,
    ) -> BTreeMap<(usize, usize), usize> {
        let started = Instant::now();
        let before = self.resolver_snapshot();
        self.materials[member].publish(state).await;
        let fresh = self.probe_member_paths(member).await;
        self.wait_ready(&[member]).await;
        let generation = self.canary.as_ref().expect("seeded canary").generation;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "rotation",
                member: Some(member),
                canary_generation: generation,
                fresh_handshake_paths: fresh,
                ready_members: vec![member],
            },
            started,
        );
        self.account_transition(&before);
        self.resolver_deltas(&before)
    }

    /// Fold one transition window's resolver deltas into the campaign
    /// accounting: the per-path campaign totals (bounded by
    /// PATH_TOTAL_ALLOWANCE per path) and the maximum single-transition
    /// handshake cost (bounded by TRANSITION_RESOLVER_ALLOWANCE). Paths to an
    /// isolated member are fault-retry traffic bounded by the
    /// per-directed-peer reconnect gate and stay outside this accounting.
    fn account_transition(&mut self, before: &BTreeMap<(usize, usize), usize>) {
        let deltas = self.resolver_deltas(before);
        let mut transition_total = 0_usize;
        for ((source, target), delta) in deltas {
            if self.down.contains(&source) || self.down.contains(&target) {
                continue;
            }
            transition_total += delta;
            let total = self.path_totals.entry((source, target)).or_default();
            *total += delta;
            self.evidence.max_path_total_resolver_deltas =
                self.evidence.max_path_total_resolver_deltas.max(*total);
        }
        self.evidence.max_transition_resolver_deltas = self
            .evidence
            .max_transition_resolver_deltas
            .max(transition_total);
    }

    /// Final no-churn settle: after the last transition, when no lane
    /// retirement remains in flight, a full settle window must not dial
    /// anything. This is the deterministic no-reconnect-storm proof; the
    /// observed delta (always zero) is recorded in the evidence.
    async fn settle_no_churn(&mut self, name: &str) {
        let started = Instant::now();
        let baseline = self.resolver_snapshot();
        tokio::time::sleep(FINAL_SETTLE_WINDOW).await;
        let deltas = self.resolver_deltas(&baseline);
        let observed = deltas.values().sum::<usize>();
        assert_eq!(
            observed, 0,
            "no lane may redial once the campaign has settled: {deltas:?}"
        );
        self.evidence.final_quiet_window_deltas = observed;
        let generation = self.canary.as_ref().expect("seeded canary").generation;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "bounds",
                member: None,
                canary_generation: generation,
                fresh_handshake_paths: 0,
                ready_members: self.reachable_members(),
            },
            started,
        );
    }

    /// Publish new material to every member (fleet-wide trust transitions),
    /// then prove fresh handshakes on every enabled directed path and durable
    /// readiness on every reachable member.
    async fn publish_fleet(&mut self, states: Vec<opc_identity::IdentityState>, name: &str) {
        let started = Instant::now();
        let before = self.resolver_snapshot();
        assert_eq!(states.len(), self.materials.len());
        for (material, state) in self.materials.iter().zip(states) {
            material.publish(state).await;
        }
        let fresh = self.probe_all_paths().await;
        let reachable = self.reachable_members();
        self.wait_ready(&reachable).await;
        let generation = self.canary.as_ref().expect("seeded canary").generation;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "rotation",
                member: None,
                canary_generation: generation,
                fresh_handshake_paths: fresh,
                ready_members: reachable,
            },
            started,
        );
        self.account_transition(&before);
    }

    /// Deliver new material to a member whose listener is down (a projected
    /// update during an outage). No handshake or readiness proof is possible
    /// until the member rejoins; the proof happens at heal time.
    async fn publish_material_only(&mut self, member: usize, state: opc_identity::IdentityState) {
        self.materials[member].publish(state).await;
    }

    /// A malformed reload must be rejected with the exact typed reason on both
    /// the client and server material, retain the last known-good epoch, and
    /// cause zero connection churn (no resolver deltas across a quiet window).
    async fn publish_rejected(
        &mut self,
        member: usize,
        state: Option<opc_identity::IdentityState>,
        reason: TlsMaterialReloadReason,
        name: &str,
    ) {
        let started = Instant::now();
        let material = &self.materials[member];
        let client_epoch = material.client.material_status().epoch();
        let server_epoch = material.server.material_status().epoch();
        let before = self.resolver_snapshot();
        material.source.send_replace(state);
        wait_for_material_rejection(
            || self.materials[member].client.material_status(),
            client_epoch,
            reason,
        )
        .await;
        wait_for_material_rejection(
            || self.materials[member].server.material_status(),
            server_epoch,
            reason,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let deltas = self.resolver_deltas(&before);
        assert!(
            deltas.values().all(|delta| *delta == 0),
            "a rejected reload must not recycle any connection: member={member}, deltas={deltas:?}"
        );
        self.evidence.rejected_reload_retentions += 2;
        let generation = self.canary.as_ref().expect("seeded canary").generation;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "fault",
                member: Some(member),
                canary_generation: generation,
                fresh_handshake_paths: 0,
                ready_members: self.reachable_members(),
            },
            started,
        );
    }

    /// A fresh one-shot client from `source` must still complete a full
    /// handshake against `member`: the retained last-known-good chain keeps
    /// the exact pinned SPIFFE identity, so any published mismatched material
    /// would fail admission here instead.
    async fn assert_member_serves_retained(&self, source: usize, member: usize) {
        let address = self.address_slots[member]
            .read()
            .expect("retained address lock")
            .expect("retained member is listening");
        let peer = RemoteSessionConsensusPeer::new_with_resolver(
            self.manifest
                .bind_local(replica_id(self.replicas[source]))
                .expect("retained source binding")
                .bind_remote(replica_id(self.replicas[member]))
                .expect("retained member binding"),
            direct_resolver(address),
            self.materials[source].client.clone(),
            Some(DURABLE_CONSENSUS_OPERATION_TIMEOUT),
        )
        .with_connection_lifecycle(single_attempt_probe_lifecycle());
        let outcome = peer
            .call(vote_probe(&self.manifest, self.replicas[source]))
            .await;
        assert!(
            outcome.is_ok(),
            "member retaining last-known-good material must keep serving its exact identity: source={source}, member={member}, outcome={outcome:?}"
        );
    }

    /// A one-shot client still presenting a chain under the removed old root
    /// must be rejected before application admission by a member whose trust
    /// is now new-only.
    async fn assert_old_chain_rejected(
        &self,
        source: u16,
        target: usize,
        old_state: opc_identity::IdentityState,
    ) {
        let address = self.address_slots[target]
            .read()
            .expect("old-chain probe address lock")
            .expect("old-chain probe target is listening");
        let client = TlsConfigBuilder::new(tokio::sync::watch::channel(Some(old_state)).1)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("old-chain probe client");
        let peer = RemoteSessionConsensusPeer::new_with_resolver(
            self.manifest
                .bind_local(replica_id(source))
                .expect("old-chain probe source binding")
                .bind_remote(replica_id(self.replicas[target]))
                .expect("old-chain probe target binding"),
            direct_resolver(address),
            client,
            Some(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout()),
        )
        .with_connection_lifecycle(single_attempt_probe_lifecycle());
        let outcome = peer.call(vote_probe(&self.manifest, source)).await;
        assert!(
            matches!(
                outcome,
                Err(
                    SessionConsensusPeerError::Authentication
                        | SessionConsensusPeerError::Timeout
                )
            ),
            "new-only member trust must reject the removed old issuer: target={target}, outcome={outcome:?}"
        );
    }

    /// Isolate one member the strongest way expressible in-process: fence
    /// every directed resolver path touching it, stop its listener (killing
    /// inbound lanes), and retire its outbound lanes so its votes cannot
    /// leave. Its store keeps running, so it observes its own isolation and
    /// campaigns; the surviving quorum is undisturbed.
    async fn isolate_member(&mut self, member: usize, name: &str) {
        let started = Instant::now();
        assert!(self.down.insert(member), "member is not already isolated");
        for ((source, target), enabled) in &self.path_enabled {
            if *source == member || *target == member {
                enabled.store(false, Ordering::Release);
            }
        }
        self.servers[member]
            .take()
            .expect("isolated member listener")
            .abort_and_wait()
            .await;
        *self.address_slots[member]
            .write()
            .expect("isolated address lock") = None;
        self.materials[member]
            .reauthentication
            .request_reauthentication()
            .expect("retire isolated member lanes");
        let generation = self.canary.as_ref().expect("seeded canary").generation;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "fault",
                member: Some(member),
                canary_generation: generation,
                fresh_handshake_paths: 0,
                ready_members: self.reachable_members(),
            },
            started,
        );
    }

    /// Bring an isolated member back: re-listen with its current (possibly
    /// advanced-while-down) material, unfence its paths, prove fresh
    /// handshakes in both directions, and wait for log convergence plus fresh
    /// durable readiness within the recovery envelope.
    async fn heal_member(&mut self, member: usize, name: &str) {
        let started = Instant::now();
        assert!(self.down.remove(&member), "member is isolated");
        let binding = self
            .manifest
            .bind_local(replica_id(self.replicas[member]))
            .expect("healed member binding");
        let (server, address) = SessionConsensusServer::new(
            self.stores[member].rpc_handler(),
            self.materials[member].server.clone(),
            binding,
        )
        .with_connection_lifecycle(fleet_lifecycle())
        .with_reauthentication_control(self.materials[member].reauthentication.clone())
        .listen("127.0.0.1:0".parse().expect("healed listen address"))
        .await
        .expect("restart healed member listener");
        self.servers[member] = Some(server);
        *self.address_slots[member]
            .write()
            .expect("healed address lock") = Some(address);
        for ((source, target), enabled) in &self.path_enabled {
            if *source == member || *target == member {
                enabled.store(true, Ordering::Release);
            }
        }
        let fresh = self.probe_member_paths(member).await;
        let all = (0..self.member_count()).collect::<Vec<_>>();
        self.wait_converged(&all).await;
        self.wait_ready(&all).await;
        let generation = self.canary.as_ref().expect("seeded canary").generation;
        self.evidence.record(
            PhaseObservation {
                name: name.to_string(),
                kind: "recovery",
                member: Some(member),
                canary_generation: generation,
                fresh_handshake_paths: fresh,
                ready_members: all,
            },
            started,
        );
    }

    /// The isolated member must not hold the entries the surviving quorum
    /// committed while it was cut off: its applied index trails the leader's.
    fn assert_member_fell_behind(&self, member: usize) {
        let leader = self
            .stores
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.down.contains(index))
            .find_map(|(_, store)| store.status().leader_id)
            .expect("reachable members observe a leader");
        let leader_applied = self
            .stores
            .iter()
            .find(|store| store.status().node_id == leader)
            .and_then(|store| store.status().applied_index)
            .expect("leader applied index");
        let isolated_applied = self.stores[member]
            .status()
            .applied_index
            .expect("isolated member applied index");
        assert!(
            isolated_applied < leader_applied,
            "isolated member must trail the surviving quorum: member={member}, isolated={isolated_applied}, leader={leader_applied}"
        );
    }

    fn authentication_failures(&self) -> usize {
        // "family:authentication" and "family:remote_authentication" both end
        // with ":authentication"; one suffix pass counts each exactly once.
        self.transport_stats
            .values()
            .map(|stats| stats.total_matching(":authentication"))
            .sum()
    }

    async fn finish(self) {
        for server in self.servers.into_iter().flatten() {
            server.abort_and_wait().await;
        }
    }
}

/// T1 (#164): a follower partition overlapping a survivor leaf rotation.
/// Continuous acknowledged canary traffic stays inside the transition SLO on
/// the surviving quorum, the isolated member trails and then catches up
/// within the recovery envelope, and no acknowledged write is lost.
async fn three_member_partition_recovery_case() {
    let old_root = RotationRoot::new("partition old");
    let old_intermediate = old_root.issue_intermediate("old");
    let old_only = [&old_root];
    let replicas = [1_u16, 2, 3];
    let initial = replicas
        .iter()
        .map(|replica| {
            old_intermediate
                .issue_leaf(*replica)
                .identity_state(&old_intermediate, &old_only)
        })
        .collect::<Vec<_>>();
    let mut fleet = FaultFleet::start("three-member-partition-recovery", initial).await;
    fleet.traffic_round("traffic-baseline").await;

    let leader = fleet.wait_stable_leader(&fleet.reachable_members()).await;
    let isolated = (0..3).find(|member| *member != leader).expect("a follower");
    let rotated = (0..3)
        .find(|member| *member != leader && *member != isolated)
        .expect("a second follower to rotate");
    fleet
        .isolate_member(isolated, "fault-partition-follower")
        .await;
    fleet.traffic_round("traffic-under-partition-a").await;

    // Rotate one survivor's leaf under the unchanged issuer while the third
    // voter is cut off. Fresh handshakes are only required on the enabled
    // paths; fenced paths see only bounded reconnect-gate retries against the
    // isolated member and stay outside the rotation handshake accounting.
    let renewed = old_intermediate.issue_leaf(replicas[rotated]);
    fleet
        .publish_member(
            rotated,
            renewed.identity_state(&old_intermediate, &old_only),
            "rotate-leaf-survivor",
        )
        .await;
    fleet.traffic_round("traffic-under-partition-b").await;
    fleet.assert_member_fell_behind(isolated);

    fleet
        .heal_member(isolated, "recovery-rejoin-and-catch-up")
        .await;
    fleet.traffic_round("traffic-after-heal").await;
    let all = vec![0, 1, 2];
    fleet.verify_canary(&all).await;
    assert!(fleet.evidence.max_path_total_resolver_deltas <= PATH_TOTAL_ALLOWANCE);
    fleet.settle_no_churn("bounds-final-settle").await;

    fleet.evidence.fd_growth = None;
    fleet.evidence.record_trust_anchors(&[&old_root]);
    fleet.evidence.emit_and_check();
    fleet.finish().await;
}

#[test]
fn three_member_fleet_rotation_continues_through_follower_partition_and_recovery() {
    run_fleet_test(8, three_member_partition_recovery_case());
}

/// T2 (#164): one unavailable member plus one member rejecting malformed
/// reloads stays inside the declared topology failure budget (floor((N-1)/2)
/// unavailable voters, quorum preserved), never publishes mixed or invalid
/// material, and a later coherent reload still rotates.
async fn five_member_failure_budget_case() {
    let old_root = RotationRoot::new("budget old");
    let old_intermediate = old_root.issue_intermediate("old");
    let old_only = [&old_root];
    let replicas = [1_u16, 2, 3, 4, 5];
    let initial = replicas
        .iter()
        .map(|replica| {
            old_intermediate
                .issue_leaf(*replica)
                .identity_state(&old_intermediate, &old_only)
        })
        .collect::<Vec<_>>();
    let mut fleet = FaultFleet::start("five-member-unavailable-and-malformed", initial).await;
    fleet.traffic_round("traffic-baseline").await;

    let leader = fleet.wait_stable_leader(&fleet.reachable_members()).await;
    let mut followers = (0..5).filter(|member| *member != leader);
    let unavailable = followers.next().expect("a follower to take down");
    let degraded = followers.next().expect("a second follower to degrade");
    fleet
        .isolate_member(unavailable, "fault-member-unavailable")
        .await;

    // Three malformed reload kinds against the degraded member. Each is
    // rejected with the exact typed reason, retains the last-known-good
    // epoch on both the client and server material, and causes zero lane
    // churn (asserted inside publish_rejected).
    let mismatched = old_intermediate.issue_leaf(replicas[leader]);
    fleet
        .publish_rejected(
            degraded,
            Some(mismatched.identity_state(&old_intermediate, &old_only)),
            TlsMaterialReloadReason::LocalIdentityChanged,
            "fault-malformed-identity-mismatch",
        )
        .await;
    fleet
        .publish_rejected(
            degraded,
            None,
            TlsMaterialReloadReason::MaterialUnavailable,
            "fault-malformed-empty",
        )
        .await;
    let degraded_leaf = old_intermediate.issue_leaf(replicas[degraded]);
    let oversized = oversized_bundle_identity_state(&degraded_leaf, &old_intermediate, &old_only);
    fleet
        .publish_rejected(
            degraded,
            Some(oversized),
            TlsMaterialReloadReason::MaterialLimitExceeded,
            "fault-malformed-over-limit",
        )
        .await;

    // The degraded member never published the mismatched chain: a fresh
    // one-shot handshake from the leader still completes against its exact
    // pinned identity under the retained material.
    fleet.assert_member_serves_retained(leader, degraded).await;

    // Continuous traffic inside the failure budget: four healthy voters plus
    // the retained degraded member keep quorum and every acknowledged write
    // is linearizable from all of them.
    fleet.traffic_round("traffic-within-budget-a").await;
    fleet.traffic_round("traffic-within-budget-b").await;
    fleet.assert_member_fell_behind(unavailable);

    // A later coherent reload still rotates the degraded member; retention
    // never latches the controller into a rejected state.
    let renewed = old_intermediate.issue_leaf(replicas[degraded]);
    fleet
        .publish_member(
            degraded,
            renewed.identity_state(&old_intermediate, &old_only),
            "rotate-repaired-member",
        )
        .await;
    fleet
        .heal_member(unavailable, "recovery-unavailable-member")
        .await;
    fleet.traffic_round("traffic-after-recovery").await;
    let all = vec![0, 1, 2, 3, 4];
    fleet.verify_canary(&all).await;
    assert!(fleet.evidence.max_path_total_resolver_deltas <= PATH_TOTAL_ALLOWANCE);
    fleet.settle_no_churn("bounds-final-settle").await;

    fleet.evidence.fd_growth = None;
    fleet.evidence.record_trust_anchors(&[&old_root]);
    fleet.evidence.emit_and_check();
    fleet.finish().await;
}

#[test]
fn five_member_fleet_rotation_stays_within_failure_budget_with_one_unavailable_and_one_rejected_reload(
) {
    run_fleet_test(8, five_member_failure_budget_case());
}

/// T3 (#164): repeated one-member-at-a-time leaf rotations stay within the
/// handshake-rate, reconnect-churn, and file-descriptor bounds. Every member
/// transition proves fresh handshakes on every directed path touching it and
/// keeps its total handshake cost within the storm bound; per-path campaign
/// totals stay within the two-lanes-per-endpoint-rotation allowance (a late
/// retirement redial is legitimate but accounted); a final settle window
/// after the last transition dials nothing at all; the Linux descriptor
/// growth stays within the allowance; and no authentication failure outcome
/// is recorded anywhere.
async fn three_member_repeated_rotation_bounds_case() {
    let old_root = RotationRoot::new("bounds old");
    let old_intermediate = old_root.issue_intermediate("old");
    let old_only = [&old_root];
    let replicas = [1_u16, 2, 3];
    let initial = replicas
        .iter()
        .map(|replica| {
            old_intermediate
                .issue_leaf(*replica)
                .identity_state(&old_intermediate, &old_only)
        })
        .collect::<Vec<_>>();
    let mut fleet = FaultFleet::start("three-member-repeated-rotation-bounds", initial).await;
    fleet.traffic_round("traffic-baseline").await;
    tokio::time::sleep(QUIET_WINDOW).await;
    let fd_baseline = fd_count();

    for cycle in 0..3 {
        for (member, replica) in replicas.iter().enumerate() {
            let leaf = old_intermediate.issue_leaf(*replica);
            let deltas = fleet
                .publish_member(
                    member,
                    leaf.identity_state(&old_intermediate, &old_only),
                    &format!("rotate-cycle-{cycle}-member-{member}"),
                )
                .await;
            // Every directed path touching the rotated member must complete
            // a fresh handshake, and the whole transition window (lane
            // replacements, probes, and any late retirement redial from an
            // earlier transition) stays within the storm bound. A late
            // redial is legitimate only on a path an earlier transition
            // retired; it is bounded by the per-path campaign totals below.
            let mut transition_total = 0_usize;
            for ((source, target), delta) in &deltas {
                if *source == member || *target == member {
                    assert!(
                        *delta >= 1,
                        "affected path must establish a fresh handshake: path=({source},{target})"
                    );
                }
                transition_total += delta;
            }
            assert!(
                transition_total <= TRANSITION_RESOLVER_ALLOWANCE,
                "member transition handshake rate stays bounded: total={transition_total}"
            );
        }
        fleet
            .traffic_round(&format!("traffic-after-cycle-{cycle}"))
            .await;
    }

    // Per-path campaign totals: each directed path is retired once per
    // rotation of each of its two endpoints (two cached lanes each), so
    // three cycles bound it to exactly twelve replacements; fewer than six
    // means some rotation never forced a fresh handshake on it.
    for ((source, target), total) in &fleet.path_totals {
        assert!(
            (6..=PATH_TOTAL_ALLOWANCE).contains(total),
            "directed path ({source},{target}) redialed {total} times across the campaign"
        );
    }
    assert!(
        fleet.evidence.max_path_total_resolver_deltas <= PATH_TOTAL_ALLOWANCE,
        "per-path handshake totals stay within the campaign bound"
    );
    fleet.settle_no_churn("bounds-final-settle").await;

    let bounds_started = Instant::now();
    let fd_final = fd_count();
    let fd_growth = match (fd_baseline, fd_final) {
        (Some(before), Some(after)) => Some(after.saturating_sub(before)),
        _ => None,
    };
    if let Some(growth) = fd_growth {
        assert!(
            growth <= FD_GROWTH_ALLOWANCE,
            "repeated rotation descriptor growth {growth} exceeds allowance {FD_GROWTH_ALLOWANCE}"
        );
    }
    let authentication_failures = fleet.authentication_failures();
    assert_eq!(
        authentication_failures, 0,
        "repeated graceful rotations must not record authentication failures"
    );
    fleet.evidence.fd_growth = fd_growth;
    fleet.evidence.authentication_failure_outcomes = authentication_failures;
    let generation = fleet.canary.as_ref().expect("seeded canary").generation;
    fleet.evidence.record(
        PhaseObservation {
            name: "bounds-measurement".to_string(),
            kind: "bounds",
            member: None,
            canary_generation: generation,
            fresh_handshake_paths: 0,
            ready_members: fleet.reachable_members(),
        },
        bounds_started,
    );

    fleet.evidence.record_trust_anchors(&[&old_root]);
    fleet.evidence.emit_and_check();
    fleet.finish().await;
}

#[test]
fn three_member_fleet_repeated_rotation_stays_within_handshake_and_descriptor_bounds() {
    run_fleet_test(8, three_member_repeated_rotation_bounds_case());
}

/// T4 (#164): a member listener restart while fleet trust advances. The
/// fleet moves to the old+new overlap bundle and rotates leaves to the new
/// root while the member is down; the member rejoins under the overlap (its
/// material advanced while down, as a projected update), catches up within
/// the recovery envelope, and the campaign completes the old-anchor removal
/// with an explicit old-chain rejection proof against the restarted member.
async fn three_member_restart_mid_rotation_case() {
    let old_root = RotationRoot::new("restart old");
    let new_root = RotationRoot::new("restart new");
    let old_intermediate = old_root.issue_intermediate("old");
    let new_intermediate = new_root.issue_intermediate("new");
    let old_only = [&old_root];
    let overlap = [&old_root, &new_root];
    let new_only = [&new_root];
    let replicas = [1_u16, 2, 3];
    let old_leaves = replicas
        .iter()
        .map(|replica| old_intermediate.issue_leaf(*replica))
        .collect::<Vec<_>>();
    let new_leaves = replicas
        .iter()
        .map(|replica| new_intermediate.issue_leaf(*replica))
        .collect::<Vec<_>>();
    let state_for =
        |leaf: &RotationLeaf, intermediate: &RotationIntermediate, roots: &[&RotationRoot]| {
            leaf.identity_state(intermediate, roots)
        };
    let initial = old_leaves
        .iter()
        .map(|leaf| state_for(leaf, &old_intermediate, &old_only))
        .collect::<Vec<_>>();
    let mut fleet = FaultFleet::start("three-member-restart-mid-rotation", initial).await;
    fleet.traffic_round("traffic-baseline").await;

    let leader = fleet.wait_stable_leader(&fleet.reachable_members()).await;
    let restarted = (0..3).find(|member| *member != leader).expect("a follower");
    fleet
        .isolate_member(restarted, "fault-member-restart")
        .await;

    // While the member is down, add the new trust anchor to every survivor
    // with the old leaves unchanged (trust overlap must be fleet-wide before
    // any leaf changes issuer), then rotate every survivor leaf to the new
    // root. The down member receives the same projected material updates but
    // cannot prove them until it rejoins.
    let survivors = fleet.reachable_members();
    for member in &survivors {
        fleet
            .publish_member(
                *member,
                state_for(&old_leaves[*member], &old_intermediate, &overlap),
                &format!("add-overlap-trust-survivor-{member}"),
            )
            .await;
    }
    fleet
        .publish_material_only(
            restarted,
            state_for(&old_leaves[restarted], &old_intermediate, &overlap),
        )
        .await;
    for member in &survivors {
        fleet
            .publish_member(
                *member,
                state_for(&new_leaves[*member], &new_intermediate, &overlap),
                &format!("rotate-survivor-new-root-{member}"),
            )
            .await;
    }
    fleet
        .publish_material_only(
            restarted,
            state_for(&new_leaves[restarted], &new_intermediate, &overlap),
        )
        .await;
    fleet.traffic_round("traffic-during-restart").await;
    fleet.assert_member_fell_behind(restarted);

    // The restarted member returns presenting the new chain under the
    // overlap bundle: the survivors still trust both roots, so its fresh
    // handshakes complete and it catches up.
    fleet
        .heal_member(restarted, "recovery-rejoin-under-overlap")
        .await;
    fleet.traffic_round("traffic-after-rejoin").await;

    // Remove the old trust anchor fleet-wide, then prove the restarted
    // member rejects a client still presenting the removed old chain (the
    // probe presents the source's own old leaf so identity stays coherent
    // and only the trust anchor fails).
    fleet
        .publish_fleet(
            new_leaves
                .iter()
                .map(|leaf| state_for(leaf, &new_intermediate, &new_only))
                .collect(),
            "remove-old-trust-anchor",
        )
        .await;
    fleet
        .assert_old_chain_rejected(
            replicas[leader],
            restarted,
            state_for(&old_leaves[leader], &old_intermediate, &overlap),
        )
        .await;
    fleet.traffic_round("traffic-new-only").await;
    let all = vec![0, 1, 2];
    fleet.verify_canary(&all).await;
    assert!(fleet.evidence.max_path_total_resolver_deltas <= PATH_TOTAL_ALLOWANCE);
    fleet.settle_no_churn("bounds-final-settle").await;

    fleet.evidence.fd_growth = None;
    fleet.evidence.record_trust_anchors(&[&old_root, &new_root]);
    fleet.evidence.emit_and_check();
    fleet.finish().await;
}

#[test]
fn three_member_fleet_member_restarts_mid_rotation_and_rejoins_under_overlap_trust() {
    run_fleet_test(8, three_member_restart_mid_rotation_case());
}

/// The independent checker is part of the qualification contract: a valid
/// document passes, and every structural, digest, freshness, SLO,
/// accounting, or provenance violation fails closed.
#[test]
fn rotation_fault_evidence_checker_binds_digests_bounds_and_provenance() {
    // The checker subprocesses open pipes in this process; serialize against
    // the fleet campaigns so their descriptor measurements stay exact.
    let _fleet_test_guard = FLEET_TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut evidence =
        CampaignEvidence::new("checker-fixture", "mtls-fault-matrix-3".to_string(), 3);
    let now = utc_epoch_seconds();
    let phase = |name: &str, kind: &'static str, generation: u64| PhaseRecord {
        name: name.to_string(),
        kind,
        member: None,
        canary_generation: generation,
        fresh_handshake_paths: 0,
        ready_members: vec![0, 1, 2],
        duration: Duration::from_millis(10),
        completed_epoch_seconds: now,
    };
    evidence.phases.push(phase("seed-canary", "traffic", 1));
    evidence.phases.push(phase("fault-partition", "fault", 1));
    evidence.phases.push(phase("rotate-leaf", "rotation", 1));
    evidence
        .phases
        .push(phase("traffic-under-partition", "traffic", 2));
    evidence
        .phases
        .push(phase("recovery-rejoin", "recovery", 2));
    evidence
        .phases
        .push(phase("traffic-after-heal", "traffic", 3));
    evidence.evidence_bounds_for_fixture();
    let checker_path = repo_root().join(CHECKER_RELATIVE_PATH);
    let document = evidence.to_json(&checker_path, now);

    let directory = tempfile::tempdir().expect("checker fixture directory");
    let valid = write_json_document(directory.path(), "valid.json", &document);
    run_checker(&valid, now).expect("checker accepts the valid fixture document");

    let must_reject = |name: &str, mutate: &dyn Fn(&mut serde_json::Value)| {
        let mut tampered = document.clone();
        mutate(&mut tampered);
        let path = write_json_document(directory.path(), name, &tampered);
        assert!(
            run_checker(&path, now).is_err(),
            "checker unexpectedly accepted tampered evidence: {name}"
        );
    };
    must_reject("schema.json", &|doc| {
        doc["schema"] = serde_json::json!("other");
    });
    must_reject("unknown-top-key.json", &|doc| {
        doc["unexpected"] = serde_json::json!(1);
    });
    must_reject("missing-key.json", &|doc| {
        doc.as_object_mut().expect("object").remove("plan_sha256");
    });
    must_reject("members.json", &|doc| {
        doc["topology"]["members"] = serde_json::json!(4);
    });
    must_reject("budget.json", &|doc| {
        doc["topology"]["failure_budget_unavailable"] = serde_json::json!(2);
    });
    must_reject("checker-digest.json", &|doc| {
        doc["artifacts"]["checker_sha256"] = serde_json::json!("0".repeat(64));
    });
    must_reject("plan-digest.json", &|doc| {
        doc["phases"][0]["name"] = serde_json::json!("renamed");
    });
    must_reject("phase-kind.json", &|doc| {
        doc["phases"][1]["kind"] = serde_json::json!("unknown-kind");
    });
    must_reject("phase-slo.json", &|doc| {
        doc["phases"][2]["duration_millis"] = serde_json::json!(27_000_u64);
    });
    must_reject("canary-gap.json", &|doc| {
        doc["phases"][3]["canary_generation"] = serde_json::json!(3);
    });
    must_reject("canary-regress.json", &|doc| {
        doc["phases"][2]["canary_generation"] = serde_json::json!(2);
    });
    must_reject("path-total-overrun.json", &|doc| {
        doc["bounds"]["max_path_total_resolver_deltas"] = serde_json::json!(19);
    });
    must_reject("settled-churn.json", &|doc| {
        doc["bounds"]["final_quiet_window_deltas"] = serde_json::json!(1);
    });
    must_reject("auth-failures.json", &|doc| {
        doc["bounds"]["authentication_failure_outcomes"] = serde_json::json!(1);
    });
    must_reject("fd-growth.json", &|doc| {
        doc["bounds"]["fd_growth"] = serde_json::json!(9);
    });
    must_reject("resolver-overrun.json", &|doc| {
        doc["bounds"]["max_transition_resolver_deltas"] = serde_json::json!(17);
    });
    must_reject("allowance-above-max.json", &|doc| {
        doc["bounds"]["resolver_delta_allowance"] = serde_json::json!(17);
    });
    must_reject("outcome.json", &|doc| {
        doc["outcome"] = serde_json::json!("fail");
    });
    must_reject("ready-range.json", &|doc| {
        doc["phases"][0]["ready_members"] = serde_json::json!([0, 1, 3]);
    });
    must_reject("float-value.json", &|doc| {
        doc["started_epoch_seconds"] = serde_json::json!(1.5);
    });

    // Freshness: a document finished 61 seconds ago is stale; one 6 seconds
    // in the future is impossible.
    must_reject("stale.json", &|doc| {
        doc["finished_epoch_seconds"] = serde_json::json!(now - 61);
    });
    must_reject("future.json", &|doc| {
        doc["finished_epoch_seconds"] = serde_json::json!(now + 6);
    });

    // Duplicate keys fail closed at parse time even with an otherwise valid
    // document.
    let raw = serde_json::to_string(&document).expect("serialize valid document");
    let duplicate = raw.replacen(
        "\"campaign_id\":\"checker-fixture\"",
        "\"campaign_id\":\"checker-fixture\",\"campaign_id\":\"checker-fixture\"",
        1,
    );
    let duplicate_path = directory.path().join("duplicate.json");
    std::fs::write(&duplicate_path, duplicate).expect("write duplicate-key document");
    assert!(run_checker(&duplicate_path, now).is_err());

    // Provenance: a modified checker copy has a different self-digest and
    // must reject the document that binds the pristine checker.
    let checker_bytes = std::fs::read(&checker_path).expect("read checker");
    let mut tampered_checker = checker_bytes.clone();
    tampered_checker.extend_from_slice(b"\n# tampered copy\n");
    let tampered_checker_path = directory.path().join("tampered-checker.py");
    std::fs::write(&tampered_checker_path, tampered_checker).expect("write tampered checker");
    let output = Command::new("python3")
        .arg(&tampered_checker_path)
        .arg(&valid)
        .arg("--now-epoch")
        .arg(now.to_string())
        .output()
        .expect("spawn tampered checker copy");
    assert!(
        !output.status.success(),
        "a tampered checker copy must reject the digest-bound document"
    );
}

impl CampaignEvidence {
    fn evidence_bounds_for_fixture(&mut self) {
        self.trust_anchor_digests = vec!["a".repeat(64)];
        self.fd_growth = Some(2);
        self.max_transition_resolver_deltas = 6;
        self.max_path_total_resolver_deltas = 9;
        self.final_quiet_window_deltas = 0;
        self.authentication_failure_outcomes = 0;
        self.rejected_reload_retentions = 0;
    }
}
