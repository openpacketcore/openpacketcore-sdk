//! Ordinary exact-operation recovery over the SDK's real mTLS transport.
//! Native retained Durable stores use a synthetic 256 KiB logical control.
//! This does not qualify larger-profile admission, nine-member resources,
//! process crash, power loss, or snapshot transfer.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::{
    ConsensusIdentity, ConsensusNodeId, ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily,
    ConsensusRpcHandler, ConsensusWireRequest, ConsensusWireResponse,
    DURABLE_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
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

const CALLER: &str =
    "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/client";
const LOGICAL_BYTES: usize = 262_144;

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

// Each origin shares one fault control across its outbound peers. After one
// actual mTLS response is discarded, no additional mutation goes onto the wire.
// Ordinary Vote, replication and read barriers continue through real transport.
#[derive(Debug, Default)]
struct Fault {
    armed: AtomicBool,
    lost: AtomicBool,
    actual_forwards: AtomicUsize,
    lost_responses: AtomicUsize,
    read_barriers: AtomicUsize,
}

#[derive(Debug)]
struct ObservedPeer {
    inner: RemoteSessionConsensusPeer,
    fault: Arc<Fault>,
}

impl ObservedPeer {
    async fn invoke(
        &self,
        request: ConsensusWireRequest,
        timeout: Option<Duration>,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let forwarded = request.family == ConsensusRpcFamily::ForwardMutation;
        if request.family == ConsensusRpcFamily::ReadBarrier {
            self.fault.read_barriers.fetch_add(1, Ordering::SeqCst);
        }
        if forwarded {
            if self.fault.lost.load(Ordering::SeqCst) {
                return Err(ConsensusPeerError::Unavailable);
            }
            self.fault.actual_forwards.fetch_add(1, Ordering::SeqCst);
        }
        let response = match timeout {
            Some(timeout) => self.inner.call_with_timeout(request, timeout).await,
            None => self.inner.call(request).await,
        }?;
        if forwarded && self.fault.armed.swap(false, Ordering::SeqCst) {
            assert!(
                response.result.is_ok(),
                "fault requires a real authenticated service response"
            );
            self.fault.lost.store(true, Ordering::SeqCst);
            self.fault.lost_responses.fetch_add(1, Ordering::SeqCst);
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

fn commit(version: u64, parent: Option<TxId>) -> AttestedConfigCommit {
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
    let key = KeyHandle::new(
        KeyId::new("synthetic-config-recovery").expect("key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xD2; 32]),
    );
    let plaintext =
        serde_json::to_vec(&"x".repeat(LOGICAL_BYTES - 2)).expect("actual logical JSON");
    assert_eq!(plaintext.len(), LOGICAL_BYTES);
    let mut nonce = [0; opc_key::AES_256_GCM_SIV_NONCE_LEN];
    nonce[..8].copy_from_slice(&version.to_be_bytes());
    let encrypted =
        opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(&key, &aad, &plaintext, nonce)
            .expect("real encrypted control");
    AttestedConfigCommit::try_new(
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
    .expect("actual attested control")
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
    let mut stores = Vec::new();
    for source in 0..3 {
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
            .expect("immutable native binding"),
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
        stores.push(
            ConsensusConfigStore::open(
                topology,
                backend,
                directory.join(format!("snapshots-{source}")),
                peers,
            )
            .await
            .expect("native consensus member"),
        );
    }
    stores
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_capacity_957_exact_recovery_after_mtls_response_loss_and_leader_loss() {
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
    let stores = open_members(&directory, &manifest, &pki, &addresses, &faults, false).await;
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

    let control = commit(1, None);
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

    let successor = commit(2, Some(control_record.tx_id));
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
    faults[follower].armed.store(true, Ordering::SeqCst);
    let error = stores[follower]
        .append_prepared_commit(operation)
        .await
        .expect_err("deliberately lost original result");
    assert!(
        matches!(error.kind(), PersistErrorKind::OutcomeUnknown),
        "CONFIG_CAPACITY_RECOVERY_MTLS_RED: a sent operation stays ambiguous"
    );
    assert_eq!(faults[follower].lost_responses.load(Ordering::SeqCst), 1);
    assert_eq!(faults[follower].actual_forwards.load(Ordering::SeqCst), 1);
    let readback = stores[follower]
        .load_latest()
        .await
        .expect("quorum read")
        .expect("successor");
    assert!(
        readback.record == expected,
        "fault followed the exact committed successor"
    );

    // Stop the old leader and all its authenticated connections. This is a
    // leader-loss control, not a process-crash or power-loss assertion.
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
    tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
        let (one, two) = tokio::join!(
            stores[live[0]].probe_durable_readiness(),
            stores[live[1]].probe_durable_readiness(),
        );
        one.expect("first surviving voter readiness");
        two.expect("second surviving voter readiness");
    })
    .await
    .expect("new quorum inside original operation budget");
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
    drop(handle);
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
    let stores = open_members(&directory, &manifest, &pki, &addresses, &faults, true).await;
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
        "CONFIG_CAPACITY_RECOVERY_REOPEN all_members=true original_handle=true resubmitted=false"
    );
}
