//! Required audit recovery through the SDK's authenticated consensus adapter.
//! The checkpoint owner survives; this does not qualify provider restart.

use super::*;
use futures_util::FutureExt;
use opc_consensus::ConsensusRpcFamily;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_persist::ConfigStore;
use opc_session_net::{
    RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConsensusServer, SessionConsensusServerHandle,
    SessionReplicationManifest,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::RwLock;

struct Pki(rcgen::CertifiedIssuer<'static, rcgen::KeyPair>);

impl Pki {
    fn new() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "Synthetic configuration audit CA",
        );
        Self(
            rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap())
                .unwrap(),
        )
    }

    fn identity(&self, replica: u16) -> opc_identity::IdentityState {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe(replica)).unwrap(),
        ));
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now - ::time::Duration::days(1);
        params.not_after = now + ::time::Duration::days(1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.0).unwrap();
        let mut trust = opc_identity::TrustBundleSet::new();
        trust.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test-domain").unwrap(),
            certificates: parse_certs_pem(&self.0.pem()).unwrap(),
        });
        build_identity_state(
            parse_certs_pem(&(cert.pem() + &self.0.pem())).unwrap(),
            parse_key_pem(&key.serialize_pem()).unwrap(),
            trust,
        )
        .unwrap()
    }

    fn client(&self, replica: u16) -> AuthenticatedClientConfig {
        let (_tx, rx) = tokio::sync::watch::channel(Some(self.identity(replica)));
        TlsConfigBuilder::new(rx)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .unwrap()
    }

    fn server(&self, replica: u16) -> AuthenticatedServerConfig {
        let (_tx, rx) = tokio::sync::watch::channel(Some(self.identity(replica)));
        TlsConfigBuilder::new(rx)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .unwrap()
    }
}

fn replica_id(replica: u16) -> ReplicaId {
    ReplicaId::new(format!("audit-replica-{replica}")).unwrap()
}

fn spiffe(replica: u16) -> String {
    format!("spiffe://test-domain/tenant/tenant-a/ns/default/sa/config/nf/amf/instance/{replica}")
}

fn manifest(
    cluster: &str,
    epoch: u64,
    endpoint_generation: u16,
) -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new(cluster).unwrap(),
            SessionConfigurationGeneration::new("audit-v1").unwrap(),
            SessionConfigurationEpoch::new(epoch).unwrap(),
            (1..=3)
                .map(|replica| {
                    QuorumReplicaDescriptor::new(
                        replica_id(replica),
                        ReplicaEndpoint::new(
                            format!("audit-{replica}-{endpoint_generation}.invalid"),
                            7443,
                        )
                        .unwrap(),
                        ReplicaTlsIdentity::new(spiffe(replica)).unwrap(),
                        ReplicaFailureDomain::new(format!("zone-{replica}")).unwrap(),
                        ReplicaBackingIdentity::new(format!("disk-{replica}")).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap(),
    )
}

fn resolver(address: Arc<RwLock<Option<SocketAddr>>>) -> RemoteAddrResolver {
    Arc::new(move || {
        let address = address.clone();
        Box::pin(async move {
            let current = *address.read().unwrap();
            current.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "synthetic consensus listener unavailable",
                )
            })
        })
    })
}

#[derive(Debug)]
struct NetworkPath {
    remote: RemoteSessionConsensusPeer,
    enabled: AtomicBool,
    activity: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl ConsensusPeer for NetworkPath {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.remote.node_id()
    }

    fn scope_identity(&self) -> Option<ConfigConsensusIdentity> {
        self.remote.scope_identity()
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(ConsensusPeerError::Unavailable);
        }
        let result = self.remote.call(request).await;
        self.activity.notify_one();
        result
    }

    async fn call_with_timeout(
        &self,
        request: ConsensusWireRequest,
        timeout: Duration,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(ConsensusPeerError::Unavailable);
        }
        // Preserve the caller's remaining timeout and the adapter's fixed
        // family/cold-connection bounds. Never fall back to direct RPCs.
        let result = self.remote.call_with_timeout(request, timeout).await;
        self.activity.notify_one();
        result
    }
}

#[derive(Debug)]
struct ObservedHandler {
    inner: Arc<dyn ConsensusRpcHandler>,
    admissions: Arc<AtomicU64>,
    activity: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl ConsensusRpcHandler for ObservedHandler {
    async fn handle(
        &self,
        authenticated_sender: ConfigConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        assert!(
            authenticated_sender == request.sender,
            "transport admitted a mismatched sender"
        );
        self.admissions.fetch_add(1, Ordering::AcqRel);
        let response = self.inner.handle(authenticated_sender, request).await;
        self.activity.notify_one();
        response
    }
}

struct NetworkQuorum {
    _directory: tempfile::TempDir,
    pki: Pki,
    manifest: Arc<SessionReplicationManifest>,
    identity: ConfigConsensusIdentity,
    stores: Vec<Arc<ConsensusConfigStore>>,
    paths: BTreeMap<(usize, usize), Arc<NetworkPath>>,
    servers: Vec<SessionConsensusServerHandle>,
    checkpoints: Arc<Checkpoints>,
    admissions: Arc<AtomicU64>,
    activity: Arc<tokio::sync::Notify>,
}

impl NetworkQuorum {
    async fn open() -> Self {
        let pki = Pki::new();
        let manifest = manifest("netconf-required-authenticated-voters", 1, 1);
        let directory = tempfile::tempdir().unwrap();
        let activity = Arc::new(tokio::sync::Notify::new());
        let checkpoints = Arc::new(Checkpoints::default());
        let admissions = Arc::new(AtomicU64::new(0));
        let bindings = [1, 2, 3].map(|replica| manifest.bind_local(replica_id(replica)).unwrap());
        let nodes = bindings
            .each_ref()
            .map(|binding| binding.local_consensus_node_id());
        let identity = bindings[0].consensus_identity();
        let addresses: Vec<_> = (0..3).map(|_| Arc::new(RwLock::new(None))).collect();
        let mut paths = BTreeMap::new();
        let mut stores = Vec::new();
        for (source, binding) in bindings.iter().enumerate() {
            let mut peers = BTreeMap::new();
            for (target, address) in addresses.iter().enumerate() {
                if source == target {
                    continue;
                }
                let path = Arc::new(NetworkPath {
                    remote: RemoteSessionConsensusPeer::new_profiled_with_resolver(
                        binding
                            .clone()
                            .bind_remote(replica_id(target as u16 + 1))
                            .unwrap(),
                        resolver(address.clone()),
                        pki.client(source as u16 + 1),
                    ),
                    enabled: AtomicBool::new(true),
                    activity: activity.clone(),
                });
                assert!(path.scope_identity() == Some(identity));
                paths.insert((source, target), path.clone());
                let peer: Arc<dyn ConsensusPeer> = path;
                peers.insert(nodes[target], peer);
            }
            let topology = ConfigConsensusTopology::try_new(
                identity,
                nodes[source],
                nodes.into_iter().collect(),
            )
            .unwrap();
            let options = RetainedConfigOptions::new(
                directory.path().join(format!("node-{source}.sqlite")),
                RetainedConfigBinding::new(topology.clone(), [0x72; 32], [0x73; 32]).unwrap(),
                RetainedConfigDurability::Durable {
                    min_free_bytes: 16 * 1024 * 1024,
                },
                64 * 1024 * 1024,
                Duration::from_secs(30),
            )
            .unwrap();
            let backend = SqliteBackend::provision_config_authority(
                options,
                AuditKey::new([0x71; 32]).unwrap(),
            )
            .await
            .unwrap();
            let keys =
                AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap();
            stores.push(Arc::new(
                ConsensusConfigStore::open_with_audit_continuity(
                    topology,
                    backend,
                    directory.path().join(format!("snapshots-{source}")),
                    peers,
                    AuditContinuityPolicy::new(keys, checkpoints.clone(), 1, 1).unwrap(),
                )
                .await
                .unwrap(),
            ));
        }
        let mut servers = Vec::new();
        for (index, binding) in bindings.into_iter().enumerate() {
            let (handle, address) = SessionConsensusServer::new(
                Arc::new(ObservedHandler {
                    inner: stores[index].rpc_handler(),
                    admissions: admissions.clone(),
                    activity: activity.clone(),
                }),
                pki.server(index as u16 + 1),
                binding,
            )
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
            *addresses[index].write().unwrap() = Some(address);
            servers.push(handle);
        }

        Self {
            _directory: directory,
            pki,
            manifest,
            identity,
            stores,
            paths,
            servers,
            checkpoints,
            admissions,
            activity,
        }
    }

    async fn leader_except(&self, excluded: Option<usize>) -> usize {
        tokio::time::timeout(TRANSITION_TIMEOUT, async {
            loop {
                let activity = self.activity.notified();
                tokio::pin!(activity);
                activity.as_mut().enable();
                for (index, store) in self.stores.iter().enumerate() {
                    if Some(index) == excluded {
                        continue;
                    }
                    let status = store.status();
                    if status.leader_id == Some(status.node_id)
                        && matches!(
                            store.ensure_local_authority().await,
                            ConfigLocalAuthorityOutcome::LocalAuthority
                        )
                    {
                        return index;
                    }
                }
                activity.await;
            }
        })
        .await
        .expect("authenticated quorum did not establish fresh local authority")
    }

    fn isolate(&self, node: usize) {
        for ((source, target), path) in &self.paths {
            if *source == node || *target == node {
                path.enabled.store(false, Ordering::Release);
            }
        }
    }

    async fn shutdown(self) {
        for server in self.servers {
            server.abort_and_wait().await;
        }
        let (one, two, three) = tokio::join!(
            self.stores[0].shutdown(),
            self.stores[1].shutdown(),
            self.stores[2].shutdown(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
    }
}

fn probe_request(manifest: &Arc<SessionReplicationManifest>, sender: u16) -> ConsensusWireRequest {
    let binding = manifest.bind_local(replica_id(sender)).unwrap();
    // Deliberately malformed engine JSON: authenticated dispatch must reach the
    // real handler, but it cannot introduce a vote or configuration effect.
    ConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        ConsensusRpcFamily::Vote,
        Vec::new(),
    )
    .unwrap()
}

async fn assert_authentication_controls(
    pki: &Pki,
    accepted: &Arc<SessionReplicationManifest>,
    handler: Arc<dyn ConsensusRpcHandler>,
) {
    let admissions = Arc::new(AtomicU64::new(0));
    let (server, address) = SessionConsensusServer::new(
        Arc::new(ObservedHandler {
            inner: handler,
            admissions: admissions.clone(),
            activity: Arc::new(tokio::sync::Notify::new()),
        }),
        pki.server(2),
        accepted.bind_local(replica_id(2)).unwrap(),
    )
    .listen("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();
    let peer = |scope: &Arc<SessionReplicationManifest>, certificate: u16| {
        RemoteSessionConsensusPeer::new_profiled_with_resolver(
            scope
                .bind_local(replica_id(1))
                .unwrap()
                .bind_remote(replica_id(2))
                .unwrap(),
            resolver(Arc::new(RwLock::new(Some(address)))),
            pki.client(certificate),
        )
    };
    let result = AssertUnwindSafe(async {
        let correct = peer(accepted, 1);
        assert_eq!(
            correct
                .call(probe_request(accepted, 1))
                .await
                .unwrap()
                .result,
            Err(ConsensusPeerError::Protocol)
        );
        assert_eq!(admissions.load(Ordering::Acquire), 1);
        let wrong_certificate = peer(accepted, 3);
        assert_eq!(
            wrong_certificate.call(probe_request(accepted, 1)).await,
            Err(ConsensusPeerError::Authentication)
        );
        assert_eq!(admissions.load(Ordering::Acquire), 1);
        assert_eq!(
            correct.call(probe_request(accepted, 3)).await,
            Err(ConsensusPeerError::ScopeMismatch)
        );
        assert_eq!(admissions.load(Ordering::Acquire), 1);
        for wrong_scope in [
            manifest("netconf-required-other-cluster", 1, 1),
            manifest("netconf-required-authenticated-voters", 2, 1),
            manifest("netconf-required-authenticated-voters", 1, 2),
        ] {
            assert_eq!(
                peer(&wrong_scope, 1)
                    .call(probe_request(&wrong_scope, 1))
                    .await,
                Err(ConsensusPeerError::ScopeMismatch)
            );
            assert_eq!(admissions.load(Ordering::Acquire), 1);
        }
        // The first malformed probe retires its connection. A fresh positive
        // control proves admission without waiting out reconnect backoff.
        assert_eq!(
            peer(accepted, 1)
                .call(probe_request(accepted, 1))
                .await
                .unwrap()
                .result,
            Err(ConsensusPeerError::Protocol)
        );
        assert_eq!(admissions.load(Ordering::Acquire), 2);
    })
    .catch_unwind()
    .await;
    server.abort_and_wait().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_running_terminal_debt_survives_authenticated_voter_leadership_change() {
    let quorum = NetworkQuorum::open().await;
    let result = AssertUnwindSafe(async {
        // Use a dedicated counter/listener around the actual config handler.
        // Background Raft traffic cannot hide a rejected call in this counter.
        // Keep admission/formation within the fleet's failure cleanup boundary.
        assert_authentication_controls(
            &quorum.pki,
            &quorum.manifest,
            quorum.stores[1].rpc_handler(),
        )
        .await;
        let (one, two, three) = tokio::join!(
            quorum.stores[0].initialize_cluster(),
            quorum.stores[1].initialize_cluster(),
            quorum.stores[2].initialize_cluster(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        let old_leader = quorum.leader_except(None).await;
        assert!(quorum.stores[old_leader]
            .load_latest()
            .await
            .unwrap()
            .is_none());
        quorum.stores[old_leader]
            .initialize_audit_authority(
                &AuditPrivacyKey::new([0x81; 32]).unwrap(),
                AuditLedgerLimits::new(90, 30).unwrap(),
            )
            .await
            .unwrap();
        let old_owner = Owner::open(quorum.stores[old_leader].clone(), true).await;
        assert_eq!(quorum.checkpoints.sequence(), 3);
        let old_server = running::required_server_for_bus(old_owner.bus.clone());
        let old_sessions = SessionRegistry::new();
        let old_registration = old_sessions.register(1).unwrap();
        let request_id = RequestId::new();
        quorum.checkpoints.refuse_from.store(6, Ordering::Release);
        let reply = old_server
            .handle_rpc_for_session_async(
                request_id,
                &principal(),
                &edit("fixture-before-election"),
                &MgmtLimits::default(),
                1,
                &old_sessions,
            )
            .await;
        assert!(reply.reply_xml.contains("<ok/>"));
        let committed = old_owner
            .source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.version, ConfigVersion::new(2));
        assert!(
            committed.request_id == Some(request_id),
            "effect lost request"
        );
        assert_eq!(quorum.checkpoints.sequence(), 4);
        assert!(quorum.admissions.load(Ordering::Acquire) > 0);

        quorum.isolate(old_leader);
        let new_leader = quorum.leader_except(Some(old_leader)).await;
        assert_ne!(old_leader, new_leader);
        let new_owner = Owner::open(quorum.stores[new_leader].clone(), false).await;
        let exact = new_owner
            .bus
            .resolve_request_id(request_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            exact.tx_id == committed.tx_id,
            "election changed exact result"
        );
        assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
        let new_server = running::required_server_for_bus(new_owner.bus.clone());
        let new_sessions = SessionRegistry::new();
        let new_registration = new_sessions.register(2).unwrap();
        for (server, sessions, session_id) in [
            (&new_server, &new_sessions, 2),
            (&old_server, &old_sessions, 1),
        ] {
            let refused_request = RequestId::new();
            let refused = server
                .handle_rpc_for_session_async(
                    refused_request,
                    &principal(),
                    &edit("fixture-fenced"),
                    &MgmtLimits::default(),
                    session_id,
                    sessions,
                )
                .await;
            assert!(refused.reply_xml.contains("operation-failed"));
            assert!(new_owner
                .bus
                .resolve_request_id(refused_request)
                .await
                .unwrap()
                .is_none());
            let latest = new_owner
                .source
                .load_committed_latest()
                .await
                .unwrap()
                .unwrap();
            assert!(
                latest.tx_id == committed.tx_id,
                "fenced write changed effect"
            );
            assert_eq!(latest.version, ConfigVersion::new(2));
            assert_eq!(latest.config.hostname, "fixture-before-election");
            assert_eq!(quorum.checkpoints.sequence(), 4);
        }
        let pending = quorum.stores[new_leader]
            .reconcile_audit_obligations(30)
            .await
            .unwrap();
        assert_eq!(
            (pending.completed, pending.pending, pending.unknown),
            (0, 0, 1)
        );
        quorum.checkpoints.refuse_from.store(0, Ordering::Release);
        let settled = quorum.stores[new_leader]
            .reconcile_audit_obligations(30)
            .await
            .unwrap();
        assert_eq!(
            (settled.completed, settled.pending, settled.unknown),
            (1, 0, 0)
        );
        assert_eq!(quorum.checkpoints.sequence(), 6);
        let exact = new_owner
            .bus
            .resolve_request_id(request_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            exact.tx_id == committed.tx_id,
            "recovery replaced original effect"
        );
        assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
        assert_original_terminal(
            quorum.stores[new_leader].as_ref(),
            quorum.identity,
            request_id,
            &committed,
        )
        .await;

        let later_request = RequestId::new();
        let permitted = new_server
            .handle_rpc_for_session_async(
                later_request,
                &principal(),
                &edit("fixture-after-election"),
                &MgmtLimits::default(),
                2,
                &new_sessions,
            )
            .await;
        assert!(permitted.reply_xml.contains("<ok/>"));
        let latest = new_owner
            .source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.version, ConfigVersion::new(3));
        assert_eq!(latest.config.hostname, "fixture-after-election");
        assert!(
            latest.request_id == Some(later_request),
            "later request changed"
        );
        assert!(
            latest.tx_id != committed.tx_id,
            "later write reused recovery"
        );
        assert_eq!(quorum.checkpoints.sequence(), 9);
        drop(old_registration);
        drop(new_registration);
        drop(old_server);
        drop(new_server);
        old_owner.close().await;
        new_owner.close().await;
    })
    .catch_unwind()
    .await;
    quorum.shutdown().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
