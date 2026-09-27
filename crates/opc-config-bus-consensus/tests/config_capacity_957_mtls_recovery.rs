//! Independent scenarios execute in separate processes at the original CI concurrency.
//! Ordinary exact-operation recovery over the SDK's real mTLS transport.
//! Native retained Durable stores exercise a 256 KiB Legacy control and a
//! separate at-limit BoundedV1 ordinary commit/recovery scenario. The bounded
//! case also checks logical one-over rejection before provider access or effects,
//! and a real receiver capacity rejection after the original result is lost.
//! A separate scenario exercises a real multi-chunk snapshot and retained
//! restoration. Joint encryption/replay maxima and ordinary/audited routes have
//! separate fixtures; exact aggregate metadata boundaries have component tests.
//! Process-loss fixtures kill only their own child and reopen the original stores.
//! A nine-member case checks saturated preparations and native replication.
//! Its capacity observations do not establish complete aggregate memory,
//! accepted-work cancellation/shutdown, snapshot overlap or power loss.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::{
    ConsensusIdentity, ConsensusNodeId, ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily,
    ConsensusRpcHandler, ConsensusWireRequest, ConsensusWireResponse,
    DURABLE_CONSENSUS_OPERATION_TIMEOUT, DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_crypto::{ConfigCapacityError, ConfigCapacityProfile, CONFIG_CAPACITY_V1_LOGICAL_BYTES};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{
    ConfigAad, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, Zeroizing,
};
use opc_persist::{
    AttestedConfigCommit, AuditKey, CommitRecord, CommitSource, ConfigCommitRecoveryHandle,
    ConfigCommitRecoveryOutcome, ConfigConsensusRequestId, ConfigConsensusTopology, ConfigStore,
    ConsensusConfigStore, PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions, SqliteBackend,
};
use opc_session_net::{
    RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConsensusServer, SessionReplicationManifest,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

macro_rules! native_case {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            crate::fixture_process::run(
                concat!(module_path!(), "::", stringify!($name)),
                async $body,
            );
        }
    };
}

#[path = "config_capacity_957_mtls_recovery/fixture_process.rs"]
mod fixture_process;

#[path = "config_capacity_957_mtls_recovery/snapshot.rs"]
mod snapshot;

#[path = "config_capacity_957_mtls_recovery/joint_metadata.rs"]
mod joint_metadata;

#[path = "config_capacity_957_mtls_recovery/election.rs"]
mod election;

#[path = "config_capacity_957_mtls_recovery/profile_rejection.rs"]
mod profile_rejection;

#[path = "config_capacity_957_mtls_recovery/nine_member.rs"]
mod nine_member;

#[path = "config_capacity_957_mtls_recovery/response_profile.rs"]
mod response_profile;

const CALLER: &str =
    "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/client";
const LEGACY_LOGICAL_BYTES: usize = 262_144;
const BOUNDED_LOGICAL_BYTES: usize = 1_572_864;
// Test-stage convergence budget, distinct from each unchanged operation deadline.
// This uses the existing session qualification transition formula; it is not a
// guarantee for every possible election path or a ten-second failover claim.
const CONFIG_CAPACITY_CLUSTER_RECOVERY_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis * 2
        + DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis,
);

struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "synthetic config recovery CA");
        Self {
            issuer: rcgen::CertifiedIssuer::self_signed(
                params,
                rcgen::KeyPair::generate().expect("synthetic CA key"),
            )
            .expect("synthetic CA"),
        }
    }

    fn identity(&self, replica: usize) -> opc_identity::IdentityState {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe(replica)).expect("synthetic URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("synthetic leaf key");
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("synthetic certificate");
        let certificates = parse_certs_pem(&(cert.pem() + &self.issuer.pem()))
            .expect("synthetic certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("synthetic private key");
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("qualification.invalid")
                .expect("synthetic trust domain"),
            certificates: parse_certs_pem(&self.issuer.pem()).expect("synthetic root"),
        });
        build_identity_state(certificates, private_key, bundles).expect("synthetic identity")
    }

    fn client(&self, replica: usize) -> AuthenticatedClientConfig {
        let (_sender, receiver) = tokio::sync::watch::channel(Some(self.identity(replica)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("authenticated client")
    }

    fn server(&self, replica: usize) -> AuthenticatedServerConfig {
        let (_sender, receiver) = tokio::sync::watch::channel(Some(self.identity(replica)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("authenticated server")
    }
}

fn spiffe(replica: usize) -> String {
    format!(
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/{replica}"
    )
}

fn replica_id(replica: usize) -> ReplicaId {
    ReplicaId::new(format!("config-{replica}")).expect("synthetic replica")
}

fn manifest() -> Arc<SessionReplicationManifest> {
    let descriptors = (0..3)
        .map(|replica| {
            QuorumReplicaDescriptor::new(
                replica_id(replica),
                ReplicaEndpoint::new(format!("config-{replica}.qualification.invalid"), 7443)
                    .expect("synthetic endpoint"),
                ReplicaTlsIdentity::new(spiffe(replica)).expect("synthetic TLS binding"),
                ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
                ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
            )
        })
        .collect();
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("synthetic-config-recovery").expect("cluster"),
            SessionConfigurationGeneration::new("config-recovery-control").expect("generation"),
            SessionConfigurationEpoch::new(1).expect("epoch"),
            descriptors,
        )
        .expect("three-member authenticated manifest"),
    )
}

// Each origin shares one fault control across its outbound peers. The Legacy
// case discards one response and blocks further sends. The bounded case lets
// the SDK retry the same operation against a genuinely exhausted receiver.
// Vote, replication and read barriers continue through the real transport.
#[derive(Debug, Default)]
struct Fault {
    armed: AtomicBool,
    lost: AtomicBool,
    actual_forwards: AtomicUsize,
    lost_responses: AtomicUsize,
    allow_capacity_rejection: AtomicBool,
    resource_rejections: AtomicUsize,
    response_loss_gate: Mutex<Option<ResponseLossGate>>,
    read_barriers: AtomicUsize,
    rpc_observations: [[RpcObservation; 3]; 3],
    snapshots: [snapshot::Observation; 3],
    election: election::Observation,
    profile_rejection: profile_rejection::Observation,
}

#[derive(Debug)]
struct ResponseLossGate {
    observed: tokio::sync::oneshot::Sender<()>,
    reserved: tokio::sync::oneshot::Receiver<()>,
}

#[derive(Debug, Default)]
struct RpcObservation {
    started: AtomicUsize,
    completed: AtomicUsize,
    transport_errors: AtomicUsize,
    service_errors: AtomicUsize,
}

#[derive(Debug)]
struct ObservedPeer {
    inner: RemoteSessionConsensusPeer,
    fault: Arc<Fault>,
    target: usize,
}

impl ObservedPeer {
    async fn invoke(
        &self,
        request: ConsensusWireRequest,
        timeout: Option<Duration>,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.fault.profile_rejection.capture(&request, self.target);
        let snapshot_chunk = self.fault.snapshots[self.target].capture(&request);
        let election = self.fault.election.capture(&request, self.target);
        let forwarded = request.family == ConsensusRpcFamily::ForwardMutation;
        let after_loss = forwarded && self.fault.lost.load(Ordering::SeqCst);
        if request.family == ConsensusRpcFamily::ReadBarrier {
            self.fault.read_barriers.fetch_add(1, Ordering::SeqCst);
        }
        if forwarded {
            if after_loss && !self.fault.allow_capacity_rejection.load(Ordering::SeqCst) {
                return Err(ConsensusPeerError::Unavailable);
            }
            self.fault.actual_forwards.fetch_add(1, Ordering::SeqCst);
        }
        let observation = match request.family {
            ConsensusRpcFamily::Vote => Some(0),
            ConsensusRpcFamily::AppendEntries => Some(1),
            ConsensusRpcFamily::ReadBarrier => Some(2),
            _ => None,
        }
        .map(|family| &self.fault.rpc_observations[self.target][family]);
        if let Some(observation) = observation {
            observation.started.fetch_add(1, Ordering::SeqCst);
        }
        let response = match timeout {
            Some(timeout) => self.inner.call_with_timeout(request, timeout).await,
            None => self.inner.call(request).await,
        };
        if let Some(election) = election {
            self.fault.election.record(election, &response);
        }
        if let Some(observation) = observation {
            observation.completed.fetch_add(1, Ordering::SeqCst);
            match &response {
                Err(_) => {
                    observation.transport_errors.fetch_add(1, Ordering::SeqCst);
                }
                Ok(response) if response.result.is_err() => {
                    observation.service_errors.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_) => {}
            }
        }
        let response = response?;
        if let Some(chunk) = snapshot_chunk {
            self.fault.snapshots[self.target].record(chunk, &response);
        }
        if after_loss {
            // Exact revision-eight postcard reply: Rejected (variant 3),
            // ResourceAdmission (variant 2). This observes the authenticated
            // production reply; the fault never manufactures a rejection.
            assert_eq!(
                response.result.as_deref(),
                Ok([8, 3, 2].as_slice()),
                "real receiver must reject only the later attempt for capacity"
            );
            self.fault
                .resource_rejections
                .fetch_add(1, Ordering::SeqCst);
        }
        if forwarded && self.fault.armed.swap(false, Ordering::SeqCst) {
            assert!(
                response.result.is_ok(),
                "fault requires a real authenticated service response"
            );
            self.fault.lost.store(true, Ordering::SeqCst);
            self.fault.lost_responses.fetch_add(1, Ordering::SeqCst);
            let gate = self
                .fault
                .response_loss_gate
                .lock()
                .expect("response loss observation")
                .take();
            if let Some(gate) = gate {
                assert!(
                    response
                        .result
                        .as_ref()
                        .expect("authenticated reply")
                        .starts_with(&[8, 0]),
                    "lose the actual bounded Applied response"
                );
                gate.observed.send(()).expect("live capacity observer");
                gate.reserved.await.expect("real receiver slots occupied");
            }
            return Err(ConsensusPeerError::Unavailable);
        }
        Ok(response)
    }
}

#[async_trait]
impl ConsensusPeer for ObservedPeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.inner.node_id()
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        self.inner.scope_identity()
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.invoke(request, None).await
    }

    async fn call_with_timeout(
        &self,
        request: ConsensusWireRequest,
        timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        self.invoke(request, Some(timeout)).await
    }
}

// The transport intentionally lets already-accepted handlers complete after
// connection cancellation. Observe release of every handler Arc before reopening
// retained storage. Delegation preserves the authenticated sender and request.
#[derive(Debug)]
struct HandlerLifetime {
    // Fields drop in declaration order: release the actual service/store before
    // sending the test-only lifetime observation.
    inner: Arc<dyn ConsensusRpcHandler>,
    _released: HandlerReleased,
}

#[derive(Debug)]
struct HandlerReleased(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for HandlerReleased {
    fn drop(&mut self) {
        if let Some(released) = self.0.take() {
            let _ = released.send(());
        }
    }
}

#[async_trait]
impl ConsensusRpcHandler for HandlerLifetime {
    async fn handle(
        &self,
        authenticated_sender: ConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        self.inner.handle(authenticated_sender, request).await
    }
}

fn observed_handler(
    store: &ConsensusConfigStore,
) -> (
    Arc<dyn ConsensusRpcHandler>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (released, receiver) = tokio::sync::oneshot::channel();
    (
        Arc::new(HandlerLifetime {
            inner: store.rpc_handler(),
            _released: HandlerReleased(Some(released)),
        }),
        receiver,
    )
}

async fn all_handlers_released(receivers: Vec<tokio::sync::oneshot::Receiver<()>>) {
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        for receiver in receivers {
            receiver
                .await
                .expect("all accepted handler owners released");
        }
    })
    .await
    .expect("handler ownership ends inside existing operation bound");
}

fn resolver(address: Arc<RwLock<Option<SocketAddr>>>) -> RemoteAddrResolver {
    Arc::new(move || {
        let address = address.clone();
        Box::pin(async move {
            address
                .read()
                .map_err(|_| std::io::Error::other("fixture address unavailable"))?
                .as_ref()
                .copied()
                .ok_or_else(|| std::io::Error::other("fixture listener unavailable"))
        })
    })
}

fn disk_fixture() -> PathBuf {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk-backed scratch root");
    let directory = tempfile::Builder::new()
        .prefix("config-capacity-mtls-recovery-")
        .tempdir_in(scratch)
        .expect("private retained fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&directory)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success(), "filesystem detector succeeded");
    let kind = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem encoding")
        .trim();
    assert!(!kind.is_empty() && !matches!(kind, "tmpfs" | "ramfs"));
    directory
}

fn fixture_key() -> KeyHandle {
    KeyHandle::new(
        KeyId::new("synthetic-config-recovery").expect("key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xD2; 32]),
    )
}

struct Provider {
    active_calls: AtomicUsize,
}

#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.active_calls.fetch_add(1, Ordering::SeqCst);
        let key = fixture_key();
        if purpose == key.purpose() && tenant == key.tenant() {
            Ok(key)
        } else {
            Err(KeyError::Unavailable)
        }
    }

    async fn get_key_by_id(&self, id: &KeyId) -> Result<KeyHandle, KeyError> {
        let key = fixture_key();
        if id == key.key_id() {
            Ok(key)
        } else {
            Err(KeyError::Unavailable)
        }
    }

    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        Err(KeyError::Unavailable)
    }
}

fn logical_bytes(profile: ConfigCapacityProfile) -> usize {
    match profile {
        ConfigCapacityProfile::Legacy => LEGACY_LOGICAL_BYTES,
        ConfigCapacityProfile::BoundedV1 => BOUNDED_LOGICAL_BYTES,
        _ => panic!("unsupported fixture profile"),
    }
}

async fn commit(
    store: &ConsensusConfigStore,
    version: u64,
    parent: Option<TxId>,
) -> (AttestedConfigCommit, EnvelopeAad, Vec<u8>) {
    // Obtain the real destination-store reservation before allocating plaintext.
    // Legacy still has no reservation and uses its original deterministic codec.
    let reservation = store
        .try_reserve_config_preparation()
        .expect("destination preparation admission");
    let tx_id = TxId::new();
    let committed_at = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("synthetic commit time"),
    );
    let schema_digest = SchemaDigest::from_bytes([0xD1; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        ConfigAad::new(
            tx_id,
            parent,
            committed_at,
            CALLER,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let bytes = logical_bytes(store.capacity_profile());
    let plaintext = serde_json::to_vec(&"x".repeat(bytes - 2)).expect("actual logical JSON");
    assert_eq!(plaintext.len(), bytes);
    let encrypted = match store.capacity_profile() {
        ConfigCapacityProfile::Legacy => {
            assert!(reservation.is_none());
            let mut nonce = [0; opc_key::AES_256_GCM_SIV_NONCE_LEN];
            nonce[..8].copy_from_slice(&version.to_be_bytes());
            opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
                &fixture_key(),
                &aad,
                &plaintext,
                nonce,
            )
            .expect("real encrypted Legacy control")
        }
        ConfigCapacityProfile::BoundedV1 => {
            let provider = Provider {
                active_calls: AtomicUsize::new(0),
            };
            let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
                reservation.expect("real bounded store reservation"),
                &provider,
                &aad,
                &plaintext,
            )
            .await
            .expect("real encrypted at-limit bounded configuration");
            assert_eq!(provider.active_calls.load(Ordering::SeqCst), 1);
            envelope
        }
        _ => panic!("unsupported fixture profile"),
    };
    let attested = AttestedConfigCommit::try_new(
        CommitRecord {
            tx_id,
            parent_tx_id: parent,
            version: ConfigVersion::new(version),
            committed_at,
            principal: CALLER.into(),
            source: CommitSource::LocalOperator,
            schema_digest,
            plaintext_digest: Sha256::digest(&plaintext).to_vec(),
            encrypted_blob: encrypted.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        },
        Vec::new(),
        encrypted.claim().expect("one fresh encryption claim"),
    )
    .expect("actual attested control");
    (attested, aad, plaintext)
}

fn assert_decrypted(record: &CommitRecord, aad: &EnvelopeAad, plaintext: &[u8]) {
    let decrypted =
        opc_crypto::decrypt_envelope_with_handle(&fixture_key(), aad, &record.encrypted_blob)
            .expect("authenticate exact expected AAD and decrypt retained bytes");
    assert!(
        decrypted.as_slice() == plaintext,
        "exact logical plaintext readback"
    );
    assert!(
        record.plaintext_digest == Sha256::digest(plaintext).as_slice(),
        "retained digest binds the complete plaintext"
    );
}

async fn reject_logical_one_over_before_initialization(
    stores: &[ConsensusConfigStore],
    databases: &[PathBuf; 3],
    faults: &[Arc<Fault>; 3],
) {
    // No voter has been initialized and no listener/address is published. This
    // removes election/replication activity from the four-table effect check.
    let before = databases.each_ref().map(|database| effect_counts(database));
    let provider = Provider {
        active_calls: AtomicUsize::new(0),
    };
    for store in stores {
        assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
        let reservation = store
            .try_reserve_config_preparation()
            .expect("one-over preparation admission")
            .expect("real bounded destination reservation");
        let plaintext = serde_json::to_vec(&"x".repeat(BOUNDED_LOGICAL_BYTES - 1))
            .expect("actual one-over logical JSON");
        assert_eq!(plaintext.len(), BOUNDED_LOGICAL_BYTES + 1);
        let aad = EnvelopeAad::config(
            TenantId::from_static("test"),
            1,
            ConfigAad::new(
                TxId::new(),
                None,
                Timestamp::from_offset_datetime(
                    time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
                        .expect("synthetic commit time"),
                ),
                CALLER,
                SchemaDigest::from_bytes([0xD1; 32]),
                "running",
            )
            .expect("synthetic one-over AAD"),
        );
        let result = opc_crypto::encrypt_reserved_bounded_config_envelope(
            reservation,
            &provider,
            &aad,
            &plaintext,
        )
        .await;
        assert!(
            matches!(result, Err(ConfigCapacityError::LogicalBytes)),
            "logical one-over must reject at the plaintext boundary"
        );
        assert_eq!(provider.active_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            databases.each_ref().map(|database| effect_counts(database)),
            before
        );
        assert!(faults.iter().all(|fault| {
            fault.actual_forwards.load(Ordering::SeqCst) == 0
                && fault.lost_responses.load(Ordering::SeqCst) == 0
                && fault.read_barriers.load(Ordering::SeqCst) == 0
        }));
        let reservations = (0..8)
            .map(|_| {
                store
                    .try_reserve_config_preparation()
                    .expect("all eight slots remain after rejected encryption")
                    .expect("bounded reservation")
            })
            .collect::<Vec<_>>();
        assert!(store.try_reserve_config_preparation().is_err());
        drop(reservations);
    }
}

fn effect_counts(database: &Path) -> [i64; 4] {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only native effect inspection");
    [
        "config_history",
        "audit_trail",
        "config_raft_log",
        "config_raft_request_outcomes",
    ]
    .map(|table| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("native effect count")
    })
}

// Each phase constructs fresh stores and transport clients over the exact
// original member identities, native storage paths, budgets and key epoch.
async fn open_members(
    directory: &Path,
    manifest: &Arc<SessionReplicationManifest>,
    pki: &Pki,
    addresses: &[Arc<RwLock<Option<SocketAddr>>>; 3],
    faults: &[Arc<Fault>; 3],
    reopen: bool,
    profile: ConfigCapacityProfile,
) -> Vec<ConsensusConfigStore> {
    let node_ids = [0, 1, 2].map(|replica| {
        manifest
            .bind_local(replica_id(replica))
            .expect("local binding")
            .local_consensus_node_id()
    });
    let members = node_ids.into_iter().collect::<BTreeSet<_>>();
    let identity = manifest.consensus_identity();
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let open = |source: usize| {
        let node_ids = &node_ids;
        let members = &members;
        let databases = &databases;
        async move {
            let local = manifest
                .bind_local(replica_id(source))
                .expect("local binding");
            let peers = (0..3)
                .filter(|target| *target != source)
                .map(|target| {
                    let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                        local
                            .clone()
                            .bind_remote(replica_id(target))
                            .expect("exact remote binding"),
                        resolver(addresses[target].clone()),
                        pki.client(source),
                    );
                    (
                        node_ids[target],
                        Arc::new(ObservedPeer {
                            inner: peer,
                            fault: faults[source].clone(),
                            target,
                        }) as Arc<dyn ConsensusPeer>,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let topology =
                ConfigConsensusTopology::try_new(identity, node_ids[source], members.clone())
                    .expect("three-voter topology");
            let options = RetainedConfigOptions::new(
                &databases[source],
                RetainedConfigBinding::new(
                    topology.clone(),
                    [0xD3 + source as u8; 32],
                    [0xD6 + source as u8; 32],
                )
                .expect("immutable native binding")
                .with_capacity_profile(profile),
                RetainedConfigDurability::Durable {
                    min_free_bytes: 128 * 1024 * 1024,
                },
                256 * 1024 * 1024,
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            )
            .expect("native Durable options");
            let key = AuditKey::new([0xD9; 32]).expect("synthetic shared audit key");
            let backend = if reopen {
                SqliteBackend::reopen_config_authority(options, key).await
            } else {
                SqliteBackend::provision_config_authority(options, key).await
            }
            .expect("native retained authority");
            ConsensusConfigStore::open(
                topology,
                backend,
                directory.join(format!("snapshots-{source}")),
                peers,
            )
            .await
            .expect("native consensus member")
        }
    };
    if reopen {
        // Retained engines start election clocks during open. Construct the
        // three independent native members concurrently so one member does
        // not spend two complete peer validations without any mTLS listener.
        // No validation, transport, operation deadline or readiness assertion
        // changes; this is the fixture's startup-order hypothesis only.
        let (first, second, third) = tokio::join!(open(0), open(1), open(2));
        vec![first, second, third]
    } else {
        let mut stores = Vec::new();
        for source in 0..3 {
            stores.push(open(source).await);
        }
        stores
    }
}

fn report_failover_observation(
    stores: &[ConsensusConfigStore],
    faults: &[Arc<Fault>; 3],
    live: &[usize],
    old_leader: ConsensusNodeId,
    original_term: u64,
) {
    for (cohort, index) in live.iter().copied().enumerate() {
        let status = stores[index].status();
        eprintln!(
            "CONFIG_CAPACITY_FAILOVER cohort={cohort} admitted={} term_advanced={} leader_known={} leader_changed={} local_leader={} applied_matches_committed={}",
            status.admitted,
            status.term > original_term,
            status.leader_id.is_some(),
            status.leader_id.is_some_and(|leader| leader != old_leader),
            status.leader_id == Some(status.node_id),
            status.applied_index.is_some() && status.applied_index == status.committed_index,
        );
        for (target, observations) in faults[index].rpc_observations.iter().enumerate() {
            for (family, observation) in ["vote", "append", "read"].into_iter().zip(observations) {
                eprintln!(
                    "CONFIG_CAPACITY_FAILOVER_RPC cohort={cohort} target={target} family={family} started={} completed={} transport_errors={} service_errors={}",
                    observation.started.load(Ordering::SeqCst),
                    observation.completed.load(Ordering::SeqCst),
                    observation.transport_errors.load(Ordering::SeqCst),
                    observation.service_errors.load(Ordering::SeqCst),
                );
            }
        }
    }
}

native_case!(
    config_capacity_957_exact_recovery_after_mtls_response_loss_and_leader_loss,
    {
        run_recovery(ConfigCapacityProfile::Legacy).await;
    }
);

native_case!(
    config_capacity_957_at_limit_mtls_recovery_and_retained_reopen,
    {
        run_recovery(ConfigCapacityProfile::BoundedV1).await;
    }
);

async fn run_recovery(profile: ConfigCapacityProfile) {
    assert_eq!(CONFIG_CAPACITY_V1_LOGICAL_BYTES, BOUNDED_LOGICAL_BYTES);
    let directory = disk_fixture();
    let pki = Pki::new();
    let manifest = manifest();
    let node_ids = [0, 1, 2].map(|replica| {
        manifest
            .bind_local(replica_id(replica))
            .expect("local binding")
            .local_consensus_node_id()
    });
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, false, profile,
    )
    .await;
    assert!(stores
        .iter()
        .all(|store| store.capacity_profile() == profile));
    if profile == ConfigCapacityProfile::BoundedV1 {
        reject_logical_one_over_before_initialization(&stores, &databases, &faults).await;
    }
    let mut servers = Vec::new();
    let mut released_handlers = Vec::new();
    for source in 0..3 {
        let (handler, released) = observed_handler(&stores[source]);
        released_handlers.push(released);
        let (server, address) = SessionConsensusServer::new(
            handler,
            pki.server(source),
            manifest
                .bind_local(replica_id(source))
                .expect("server binding"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback socket"))
        .await
        .expect("real mTLS consensus listener");
        *addresses[source].write().expect("address publication") = Some(address);
        servers.push(Some(server));
    }

    // Initialize all voters, then observe quorum through the production
    // event-driven read-index path, sharing the original operation budget.
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        let (one, two, three) = tokio::join!(
            stores[0].initialize_cluster(),
            stores[1].initialize_cluster(),
            stores[2].initialize_cluster(),
        );
        one.expect("first voter initialization");
        two.expect("second voter initialization");
        three.expect("third voter initialization");
        let (one, two, three) = tokio::join!(
            stores[0].probe_durable_readiness(),
            stores[1].probe_durable_readiness(),
            stores[2].probe_durable_readiness(),
        );
        one.expect("first voter ready");
        two.expect("second voter ready");
        three.expect("third voter ready");
    })
    .await
    .expect("formation inside original operation budget");
    let leader_id = stores[0].status().leader_id.expect("elected leader");
    let leader = node_ids
        .iter()
        .position(|node| *node == leader_id)
        .expect("member leader");
    let follower = (leader + 1) % 3;
    assert!(stores.iter().all(|store| {
        let status = store.status();
        status.admitted && status.leader_id == Some(leader_id)
    }));

    let (control, control_aad, control_plaintext) = commit(&stores[leader], 1, None).await;
    let control_record = control.record().clone();
    let control = stores[leader]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xDA; 16]),
            control,
            CALLER,
        )
        .expect("prepare leader-local positive control");
    stores[leader]
        .append_prepared_commit_local(control)
        .await
        .expect("Durable leader-local positive control");
    let readback = stores[follower]
        .load_latest()
        .await
        .expect("quorum read")
        .expect("control");
    assert!(
        readback.record == control_record,
        "exact encrypted positive readback"
    );

    assert_decrypted(&readback.record, &control_aad, &control_plaintext);
    drop((control_aad, control_plaintext));

    let (successor, successor_aad, successor_plaintext) =
        commit(&stores[follower], 2, Some(control_record.tx_id)).await;
    let expected = successor.record().clone();
    let before_prepare = effect_counts(&databases[follower]);
    let operation = stores[follower]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xDB; 16]),
            successor,
            CALLER,
        )
        .expect("prepare original successor once");
    let handle = ConfigCommitRecoveryHandle::from_bytes(operation.recovery_handle().as_bytes())
        .expect("retain exact original handle before any send");
    assert_eq!(effect_counts(&databases[follower]), before_prepare);
    let loss_gate = if profile == ConfigCapacityProfile::BoundedV1 {
        let (observed, observation) = tokio::sync::oneshot::channel();
        let (reserved, reservation) = tokio::sync::oneshot::channel();
        *faults[follower]
            .response_loss_gate
            .lock()
            .expect("install response observation") = Some(ResponseLossGate {
            observed,
            reserved: reservation,
        });
        faults[follower]
            .allow_capacity_rejection
            .store(true, Ordering::SeqCst);
        Some((observation, reserved))
    } else {
        None
    };
    faults[follower].armed.store(true, Ordering::SeqCst);
    let operation_deadline = tokio::time::Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
    let (result, rejection_state) =
        tokio::join!(stores[follower].append_prepared_commit(operation), async {
            let (observation, reserved) = loss_gate?;
            tokio::time::timeout_at(operation_deadline, observation)
                .await
                .expect("original response observed inside original operation bound")
                .expect("original authenticated Applied reply");
            let reservations = (0..8)
                .map(|_| {
                    stores[leader]
                        .try_reserve_config_preparation()
                        .expect("real receiver preparation slot")
                        .expect("bounded receiver reservation")
                })
                .collect::<Vec<_>>();
            assert!(stores[leader].try_reserve_config_preparation().is_err());
            let before = effect_counts(&databases[leader]);
            reserved
                .send(())
                .expect("release lost response after real admission is full");
            Some((reservations, before))
        },);
    let error = result.expect_err("deliberately lost original result");
    assert!(
        matches!(error.kind(), PersistErrorKind::OutcomeUnknown),
        "CONFIG_CAPACITY_RECOVERY_MTLS_RED: a sent operation stays ambiguous"
    );
    assert_eq!(faults[follower].lost_responses.load(Ordering::SeqCst), 1);
    if let Some((reservations, before)) = rejection_state {
        assert_eq!(faults[follower].actual_forwards.load(Ordering::SeqCst), 2);
        assert_eq!(
            faults[follower].resource_rejections.load(Ordering::SeqCst),
            1
        );
        assert_eq!(effect_counts(&databases[leader]), before);
        assert!(stores[leader].try_reserve_config_preparation().is_err());
        assert!(
            matches!(
                stores[follower]
                    .lookup_commit_operation(&handle, CALLER)
                    .await
                    .expect("read-only recovery while receiver preparation is full"),
                ConfigCommitRecoveryOutcome::Committed
            ),
            "CONFIG_CAPACITY_LATE_REJECTION_RED: later rejection cannot erase original commit"
        );
        assert_eq!(effect_counts(&databases[leader]), before);
        drop(reservations);
        let released = (0..8)
            .map(|_| {
                stores[leader]
                    .try_reserve_config_preparation()
                    .expect("all receiver slots released")
                    .expect("bounded receiver reservation")
            })
            .collect::<Vec<_>>();
        assert!(stores[leader].try_reserve_config_preparation().is_err());
        drop(released);
        println!(
            "CONFIG_CAPACITY_LATE_REJECTION original_committed=true real_capacity_rejection=true ambiguity_preserved=true read_only_recovery=true slots_released=8"
        );
    } else {
        assert_eq!(faults[follower].actual_forwards.load(Ordering::SeqCst), 1);
        assert_eq!(
            faults[follower].resource_rejections.load(Ordering::SeqCst),
            0
        );
    }
    let readback = stores[follower]
        .load_latest()
        .await
        .expect("quorum read")
        .expect("successor");
    assert!(
        readback.record == expected,
        "fault followed the exact committed successor"
    );
    assert_decrypted(&readback.record, &successor_aad, &successor_plaintext);

    // Stop the old leader and all its authenticated connections. This is a
    // leader-loss control, not a process-crash or power-loss assertion.
    election::begin(&faults);
    let original_term = stores[leader].status().term;
    servers[leader]
        .take()
        .expect("old leader listener")
        .abort_and_wait()
        .await;
    stores[leader]
        .shutdown()
        .await
        .expect("stop original leader");
    let live = (0..3).filter(|index| *index != leader).collect::<Vec<_>>();
    let convergence_deadline =
        tokio::time::Instant::now() + CONFIG_CAPACITY_CLUSTER_RECOVERY_TIMEOUT;
    let readiness = tokio::time::timeout_at(convergence_deadline, async {
        // Each read-only probe retains the fixed production operation deadline.
        // Only Unavailable may start another round within this one stage bound.
        for round in 1..=3 {
            let (one, two) = tokio::join!(
                stores[live[0]].probe_durable_readiness(),
                stores[live[1]].probe_durable_readiness(),
            );
            eprintln!(
                "CONFIG_CAPACITY_CONVERGENCE round={round} first_ready={} second_ready={}",
                one.is_ok(),
                two.is_ok(),
            );
            if one.is_ok() && two.is_ok() {
                assert!(
                    tokio::time::Instant::now() <= convergence_deadline,
                    "new quorum must be observed inside the convergence bound"
                );
                return;
            }
            report_failover_observation(&stores, &faults, &live, leader_id, original_term);
            for result in [&one, &two] {
                if let Err(error) = result {
                    assert!(
                        matches!(error.kind(), PersistErrorKind::Unavailable),
                        "unexpected surviving voter readiness error class"
                    );
                }
            }
        }
        panic!("surviving voters did not become ready in three read-only rounds");
    })
    .await;
    if readiness.is_err() {
        report_failover_observation(&stores, &faults, &live, leader_id, original_term);
    }
    election::report(&faults);
    readiness.expect("new quorum inside the fixed cluster convergence bound");
    let successor_leader = stores[follower]
        .status()
        .leader_id
        .expect("successor leader");
    assert!(
        successor_leader != leader_id,
        "recovery must cross leader loss"
    );

    let before = live
        .iter()
        .map(|index| effect_counts(&databases[*index]))
        .collect::<Vec<_>>();
    let forwards_before = faults
        .iter()
        .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
        .sum::<usize>();
    let reads_before = faults
        .iter()
        .map(|fault| fault.read_barriers.load(Ordering::SeqCst))
        .sum::<usize>();
    assert!(stores[follower]
        .lookup_commit_operation(&handle, "different caller")
        .await
        .is_err());
    let mut changed = handle.as_bytes().to_vec();
    let last = changed.last_mut().expect("bounded handle");
    *last ^= 1;
    let changed = ConfigCommitRecoveryHandle::from_bytes(&changed).expect("structural handle");
    assert!(stores[follower]
        .lookup_commit_operation(&changed, CALLER)
        .await
        .is_err());
    assert_eq!(
        faults
            .iter()
            .map(|fault| fault.read_barriers.load(Ordering::SeqCst))
            .sum::<usize>(),
        reads_before,
        "invalid caller or MAC must reject before any read RPC"
    );

    for index in &live {
        assert!(
            matches!(
                stores[*index]
                    .lookup_commit_operation(&handle, CALLER)
                    .await
                    .expect("original recovery"),
                ConfigCommitRecoveryOutcome::Committed
            ),
            "CONFIG_CAPACITY_RECOVERY_MTLS_RED: recover the exact committed operation"
        );
        let readback = stores[*index]
            .load_latest()
            .await
            .expect("quorum read")
            .expect("successor");
        assert!(
            readback.record == expected,
            "atomic full encrypted readback after leader loss"
        );
        assert_decrypted(&readback.record, &successor_aad, &successor_plaintext);
    }
    assert_eq!(
        live.iter()
            .map(|index| effect_counts(&databases[*index]))
            .collect::<Vec<_>>(),
        before,
        "recovery leaves configuration, audit, native log and outcome counts unchanged"
    );
    assert_eq!(
        faults
            .iter()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
            .sum::<usize>(),
        forwards_before,
        "read-only recovery never submits another mutation"
    );
    for index in live {
        servers[index]
            .take()
            .expect("surviving listener")
            .abort_and_wait()
            .await;
        stores[index]
            .shutdown()
            .await
            .expect("stop surviving member");
    }

    let retained_handle = handle.as_bytes().to_vec();
    drop(servers);
    all_handlers_released(released_handlers).await;
    drop(stores);
    for address in &addresses {
        *address.write().expect("retire old listener address") = None;
    }
    let retained_effects = databases
        .iter()
        .map(|database| {
            let counts = effect_counts(database);
            [counts[0], counts[1], counts[3]]
        })
        .collect::<Vec<_>>();

    // Reopen every original store and recreate every mTLS client/listener.
    // No authority is provisioned, source commit is reconstructed, or mutation
    // resubmitted. This is an orderly full restart, not a process-crash claim.
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, true, profile,
    )
    .await;
    assert!(stores
        .iter()
        .all(|store| store.capacity_profile() == profile));
    let mut servers = Vec::new();
    let mut released_handlers = Vec::new();
    for source in 0..3 {
        let (handler, released) = observed_handler(&stores[source]);
        released_handlers.push(released);
        let (server, address) = SessionConsensusServer::new(
            handler,
            pki.server(source),
            manifest
                .bind_local(replica_id(source))
                .expect("original server binding"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback socket"))
        .await
        .expect("new mTLS listener on original retained authority");
        *addresses[source].write().expect("new address publication") = Some(address);
        servers.push(server);
    }
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        let (one, two, three) = tokio::join!(
            stores[0].initialize_cluster(),
            stores[1].initialize_cluster(),
            stores[2].initialize_cluster(),
        );
        one.expect("first retained voter readmission");
        two.expect("second retained voter readmission");
        three.expect("third retained voter readmission");
        let (one, two, three) = tokio::join!(
            stores[0].probe_durable_readiness(),
            stores[1].probe_durable_readiness(),
            stores[2].probe_durable_readiness(),
        );
        one.expect("first retained voter ready");
        two.expect("second retained voter ready");
        three.expect("third retained voter ready");
    })
    .await
    .expect("retained readmission inside original operation budget");
    let retained_leader = stores[0]
        .status()
        .leader_id
        .expect("retained quorum leader");
    assert!(stores.iter().all(|store| {
        let status = store.status();
        status.admitted && status.leader_id == Some(retained_leader)
    }));
    assert!(
        databases
            .iter()
            .map(|database| {
                let counts = effect_counts(database);
                [counts[0], counts[1], counts[3]]
            })
            .collect::<Vec<_>>()
            == retained_effects,
        "configuration, audit and outcome effects survive original-store reopen"
    );
    // Elections may append engine entries during readmission. Capture the
    // complete four-table baseline after that phase, before read-only recovery.
    let before = databases
        .iter()
        .map(|database| effect_counts(database))
        .collect::<Vec<_>>();
    let handle = ConfigCommitRecoveryHandle::from_bytes(&retained_handle)
        .expect("decode only the originally retained recovery handle");
    for store in &stores {
        assert!(
            matches!(
                store
                    .lookup_commit_operation(&handle, CALLER)
                    .await
                    .expect("same original operation after retained restart"),
                ConfigCommitRecoveryOutcome::Committed
            ),
            "CONFIG_CAPACITY_RECOVERY_REOPEN_RED: original committed evidence survives full retained restart"
        );
        let readback = store
            .load_latest()
            .await
            .expect("retained quorum read")
            .expect("retained successor");
        assert!(
            readback.record == expected,
            "complete encrypted successor survives full retained restart"
        );
        assert_decrypted(&readback.record, &successor_aad, &successor_plaintext);
    }
    assert!(
        databases
            .iter()
            .map(|database| effect_counts(database))
            .collect::<Vec<_>>()
            == before,
        "recovery after readmission leaves all four effect tables unchanged"
    );
    assert_eq!(
        faults
            .iter()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
            .sum::<usize>(),
        forwards_before,
        "retained restart and exact recovery never forward another mutation"
    );
    assert_eq!(faults[follower].lost_responses.load(Ordering::SeqCst), 1);
    for server in servers {
        server.abort_and_wait().await;
    }
    for store in &stores {
        store.shutdown().await.expect("stop reopened member");
    }
    all_handlers_released(released_handlers).await;
    println!(
        "CONFIG_CAPACITY_RECOVERY_REOPEN profile={} logical_bytes={} all_members=true original_handle=true resubmitted=false",
        profile.revision(),
        logical_bytes(profile),
    );
}
