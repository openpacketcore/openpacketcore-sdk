use super::identity::{consensus_peer_policy, parse_spiffe_id};
use super::types::{
    AppendEntriesRequest, AppendEntriesResponse, ClusterMembership, ConsensusClock,
    InstallSnapshotRequest, InstallSnapshotResponse, NodeIdentity, RequestVoteRequest,
    RequestVoteResponse, TimeoutNowRequest, TimeoutNowResponse,
};
use super::{ConsensusConfigStore, ConsensusPeer};
use crate::{
    AuditKey, PersistError, PersistErrorKind, RollbackTarget, SqliteBackend, StoredConfig,
};
use async_trait::async_trait;
use opc_identity::{Namespace, ServiceAccount, TrustDomain, WorkloadIdentity};
use opc_types::{InstanceId, NfKind, SpiffeId, TenantId, Timestamp};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn parse_spiffe_id_accepts_canonical_profile() {
    let parsed = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/17",
    )
    .unwrap();

    assert_eq!(parsed.trust_domain, "prod.example.org");
    assert!(parsed.legacy_path_prefix.is_empty());
    assert_eq!(parsed.tenant_id, "carrier");
    assert_eq!(parsed.namespace, "core");
    assert_eq!(parsed.service_account, "opc-consensus");
    assert_eq!(parsed.nf_kind, "amf");
    assert_eq!(parsed.instance_id, 17);
}

#[test]
fn parse_spiffe_id_keeps_legacy_test_profile_compatible() {
    let parsed = parse_spiffe_id(
        "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1",
    )
    .unwrap();

    assert_eq!(parsed.trust_domain, "test");
    assert_eq!(parsed.legacy_path_prefix, vec!["trust-domain"]);
    assert_eq!(parsed.instance_id, 1);
}

#[test]
fn spiffe_workload_profile_ignores_instance_only() {
    let node_a = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    )
    .unwrap();
    let node_b = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/2",
    )
    .unwrap();
    let other_workload = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/other/nf/amf/instance/2",
    )
    .unwrap();

    assert!(node_a.same_workload_profile(&node_b));
    assert!(!node_a.same_workload_profile(&other_workload));
}

fn node_identity(spiffe_id: &str) -> NodeIdentity {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Consensus Test CA");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut node_params = CertificateParams::default();
    node_params
        .distinguished_name
        .push(DnType::CommonName, "Consensus Node");
    node_params.subject_alt_names.push(SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("spiffe san"),
    ));
    let now = ::time::OffsetDateTime::now_utc();
    node_params.not_before = now - ::time::Duration::days(1);
    node_params.not_after = now + ::time::Duration::days(1);

    let node_key = KeyPair::generate().expect("node key");
    let node_cert = node_params
        .signed_by(&node_key, &ca_cert, &ca_key)
        .expect("node cert");

    NodeIdentity {
        cert_chain_pem: format!("{}{}", node_cert.pem(), ca_cert.pem()),
        private_key_pem: node_key.serialize_pem(),
        ca_cert_pem: ca_cert.pem(),
    }
}

fn workload(
    trust_domain: &str,
    tenant: &str,
    namespace: &str,
    service_account: &str,
    nf_kind: &str,
    instance: &str,
) -> WorkloadIdentity {
    WorkloadIdentity {
        trust_domain: TrustDomain::new(trust_domain).expect("trust domain"),
        tenant: TenantId::new(tenant).expect("tenant"),
        namespace: Namespace::new(namespace).expect("namespace"),
        service_account: ServiceAccount::new(service_account).expect("service account"),
        nf_kind: NfKind::new(nf_kind).expect("nf kind"),
        instance: InstanceId::new(instance).expect("instance"),
        spiffe_id: SpiffeId::new(format!(
            "spiffe://{trust_domain}/tenant/{tenant}/ns/{namespace}/sa/{service_account}/nf/{nf_kind}/instance/{instance}"
        ))
        .expect("spiffe id"),
        expires_at: Timestamp::now_utc(),
    }
}

#[test]
fn consensus_server_tls_policy_is_workload_profile_constrained() {
    let identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    let policy = consensus_peer_policy(&identity, None).expect("policy");

    assert!(!policy.is_unconstrained());
    assert!(policy.allowed_instances.is_none());
    assert!(policy
        .check(&workload(
            "prod.example.org",
            "carrier",
            "core",
            "opc-consensus",
            "amf",
            "2",
        ))
        .is_ok());
    assert!(policy
        .check(&workload(
            "prod.example.org",
            "other-tenant",
            "core",
            "opc-consensus",
            "amf",
            "2",
        ))
        .is_err());
    assert!(policy
        .check(&workload(
            "prod.example.org",
            "carrier",
            "core",
            "opc-consensus",
            "smf",
            "2",
        ))
        .is_err());
    assert!(policy
        .check(&workload(
            "other.example.org",
            "carrier",
            "core",
            "opc-consensus",
            "amf",
            "2",
        ))
        .is_err());
}

#[test]
fn consensus_client_tls_policy_fences_expected_peer_instance() {
    let identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    let policy = consensus_peer_policy(&identity, Some(2)).expect("policy");

    assert!(!policy.is_unconstrained());
    assert!(policy
        .check(&workload(
            "prod.example.org",
            "carrier",
            "core",
            "opc-consensus",
            "amf",
            "2",
        ))
        .is_ok());
    assert!(policy
        .check(&workload(
            "prod.example.org",
            "carrier",
            "core",
            "opc-consensus",
            "amf",
            "3",
        ))
        .is_err());
}

async fn identity_test_store(temp_dir: &tempfile::TempDir) -> Arc<ConsensusConfigStore> {
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(
            temp_dir.path().join("identity-race.db"),
            true,
            0,
            AuditKey::new([0x5A; 32]).unwrap(),
        )
        .await
        .unwrap(),
    );
    Arc::new(
        ConsensusConfigStore::new(
            1,
            backend,
            Some(ClusterMembership {
                cluster_id: "identity-race".to_string(),
                node_id: 1,
                voting_members: vec![1, 2],
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 1,
            }),
            Some(ConsensusClock {
                enable_timers: false,
                ..ConsensusClock::default()
            }),
        )
        .await
        .unwrap(),
    )
}

fn identities_match(left: &NodeIdentity, right: &NodeIdentity) -> bool {
    left.cert_chain_pem == right.cert_chain_pem
        && left.private_key_pem == right.private_key_pem
        && left.ca_cert_pem == right.ca_cert_pem
}

#[derive(Debug)]
struct BlockingIdentityPeer {
    node_id: usize,
    blocked_identity_call: Option<usize>,
    reject_auth: bool,
    reject_identity: bool,
    identity_calls: AtomicUsize,
    identity_call_entered: tokio::sync::Semaphore,
    release_blocked_identity_call: tokio::sync::Semaphore,
    applied_identities: tokio::sync::Mutex<Vec<NodeIdentity>>,
}

impl BlockingIdentityPeer {
    fn blocking(node_id: usize, blocked_identity_call: usize) -> Self {
        Self {
            node_id,
            blocked_identity_call: Some(blocked_identity_call),
            reject_auth: false,
            reject_identity: false,
            identity_calls: AtomicUsize::new(0),
            identity_call_entered: tokio::sync::Semaphore::new(0),
            release_blocked_identity_call: tokio::sync::Semaphore::new(0),
            applied_identities: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    fn rejecting(node_id: usize, reject_auth: bool, reject_identity: bool) -> Self {
        Self {
            node_id,
            blocked_identity_call: None,
            reject_auth,
            reject_identity,
            identity_calls: AtomicUsize::new(0),
            identity_call_entered: tokio::sync::Semaphore::new(0),
            release_blocked_identity_call: tokio::sync::Semaphore::new(0),
            applied_identities: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    async fn wait_for_identity_call(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.identity_call_entered.acquire())
            .await
            .expect("identity application did not start")
            .expect("identity call semaphore was closed")
            .forget();
    }

    fn release_blocked_identity_call(&self) {
        self.release_blocked_identity_call.add_permits(1);
    }
}

#[async_trait]
impl ConsensusPeer for BlockingIdentityPeer {
    fn node_id(&self) -> usize {
        self.node_id
    }

    async fn request_vote(
        &self,
        _req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError> {
        Err(PersistError::io("unused identity test RPC"))
    }

    async fn append_entries(
        &self,
        _req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError> {
        Err(PersistError::io("unused identity test RPC"))
    }

    async fn install_snapshot(
        &self,
        _req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError> {
        Err(PersistError::io("unused identity test RPC"))
    }

    async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError> {
        Err(PersistError::io("unused identity test RPC"))
    }

    async fn load_rollback_consensus_rpc(
        &self,
        _target: RollbackTarget,
    ) -> Result<StoredConfig, PersistError> {
        Err(PersistError::io("unused identity test RPC"))
    }

    async fn timeout_now(
        &self,
        _req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, PersistError> {
        Err(PersistError::io("unused identity test RPC"))
    }

    async fn set_auth(
        &self,
        _local_node_id: usize,
        _local_cluster_id: String,
        _client_cert_pem: String,
    ) -> Result<(), PersistError> {
        if self.reject_auth {
            return Err(PersistError::io("adapter-secret-should-not-escape"));
        }
        Ok(())
    }

    async fn set_identity(&self, identity: NodeIdentity) -> Result<(), PersistError> {
        let call = self.identity_calls.fetch_add(1, Ordering::SeqCst);
        self.identity_call_entered.add_permits(1);
        if self.blocked_identity_call == Some(call) {
            self.release_blocked_identity_call
                .acquire()
                .await
                .expect("identity release semaphore was closed")
                .forget();
        }
        if self.reject_identity {
            return Err(PersistError::io("adapter-secret-should-not-escape"));
        }
        self.applied_identities.lock().await.push(identity);
        Ok(())
    }
}

#[tokio::test]
async fn peer_registration_and_rotation_serialize_identity_application() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = identity_test_store(&temp_dir).await;
    let old_identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    let new_identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    store.set_identity(old_identity.clone()).await.unwrap();

    let peer = Arc::new(BlockingIdentityPeer::blocking(2, 0));
    let add_store = Arc::clone(&store);
    let added_peer = Arc::clone(&peer);
    let add_handle = tokio::spawn(async move {
        add_store.add_peer(2, added_peer).await;
    });
    peer.wait_for_identity_call().await;

    let rotation_store = Arc::clone(&store);
    let rotated_identity = new_identity.clone();
    let rotation_handle =
        tokio::spawn(async move { rotation_store.set_identity(rotated_identity).await });
    tokio::task::yield_now().await;
    assert!(!rotation_handle.is_finished());
    assert!(store.peers.try_read().is_err());

    peer.release_blocked_identity_call();
    peer.wait_for_identity_call().await;
    tokio::time::timeout(Duration::from_secs(2), add_handle)
        .await
        .expect("peer registration did not finish")
        .expect("peer registration task panicked");
    tokio::time::timeout(Duration::from_secs(2), rotation_handle)
        .await
        .expect("identity rotation did not finish")
        .expect("identity rotation task panicked")
        .unwrap();

    assert!(store.peers.read().await.contains_key(&2));
    let applied = peer.applied_identities.lock().await;
    assert_eq!(applied.len(), 2);
    assert!(identities_match(&applied[0], &old_identity));
    assert!(identities_match(&applied[1], &new_identity));
}

#[tokio::test]
async fn concurrent_rotations_cannot_finish_peer_propagation_out_of_order() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = identity_test_store(&temp_dir).await;
    let old_identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    let identity_a = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    let identity_b = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    store.set_identity(old_identity.clone()).await.unwrap();

    let peer = Arc::new(BlockingIdentityPeer::blocking(2, 1));
    store
        .try_add_peer(2, Arc::clone(&peer) as Arc<dyn ConsensusPeer>)
        .await
        .unwrap();
    peer.wait_for_identity_call().await;

    let store_a = Arc::clone(&store);
    let attempted_a = identity_a.clone();
    let rotation_a = tokio::spawn(async move { store_a.set_identity(attempted_a).await });
    peer.wait_for_identity_call().await;

    let store_b = Arc::clone(&store);
    let attempted_b = identity_b.clone();
    let (rotation_b_started_tx, rotation_b_started_rx) = tokio::sync::oneshot::channel();
    let rotation_b = tokio::spawn(async move {
        let _ = rotation_b_started_tx.send(());
        store_b.set_identity(attempted_b).await
    });
    rotation_b_started_rx.await.unwrap();
    tokio::task::yield_now().await;

    let published_identity = store.identity.read().await;
    assert!(identities_match(
        published_identity.as_ref().unwrap(),
        &identity_a
    ));
    drop(published_identity);
    assert!(!rotation_b.is_finished());

    peer.release_blocked_identity_call();
    peer.wait_for_identity_call().await;
    tokio::time::timeout(Duration::from_secs(2), rotation_a)
        .await
        .expect("first identity rotation did not finish")
        .expect("first identity rotation task panicked")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), rotation_b)
        .await
        .expect("second identity rotation did not finish")
        .expect("second identity rotation task panicked")
        .unwrap();

    let published_identity = store.identity.read().await;
    assert!(identities_match(
        published_identity.as_ref().unwrap(),
        &identity_b
    ));
    let applied = peer.applied_identities.lock().await;
    assert_eq!(applied.len(), 3);
    assert!(identities_match(&applied[0], &old_identity));
    assert!(identities_match(&applied[1], &identity_a));
    assert!(identities_match(&applied[2], &identity_b));
}

#[tokio::test]
async fn peer_registration_errors_are_fixed_and_never_publish_the_adapter() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = identity_test_store(&temp_dir).await;
    let identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    store.set_identity(identity).await.unwrap();

    let auth_rejecting_peer = Arc::new(BlockingIdentityPeer::rejecting(2, true, false));
    let error = store
        .try_add_peer(
            2,
            Arc::clone(&auth_rejecting_peer) as Arc<dyn ConsensusPeer>,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        PersistErrorKind::Io(message)
            if message == "failed to configure consensus peer authentication"
    ));
    assert!(!error.to_string().contains("adapter-secret"));
    assert!(store.peers.read().await.is_empty());

    let identity_rejecting_peer = Arc::new(BlockingIdentityPeer::rejecting(2, false, true));
    store
        .add_peer(
            2,
            Arc::clone(&identity_rejecting_peer) as Arc<dyn ConsensusPeer>,
        )
        .await;
    assert!(store.peers.read().await.is_empty());

    let mismatched_peer = Arc::new(BlockingIdentityPeer::rejecting(3, false, false));
    let error = store
        .try_add_peer(2, mismatched_peer as Arc<dyn ConsensusPeer>)
        .await
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        PersistErrorKind::InconsistentState(message)
            if message == "consensus peer id does not match registration"
    ));
    assert!(store.peers.read().await.is_empty());
}

#[tokio::test]
async fn cancelled_local_identity_publication_preserves_the_pair_for_a_waiting_reader() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store = identity_test_store(&temp_dir).await;
    let old_identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    let new_identity = node_identity(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    );
    store.set_identity(old_identity.clone()).await.unwrap();

    let acceptor_guard = store.tls_acceptor.write().await;
    assert!(acceptor_guard.is_some());

    let rotation_store = Arc::clone(&store);
    let attempted_identity = new_identity.clone();
    let rotation_handle =
        tokio::spawn(async move { rotation_store.set_identity(attempted_identity).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if store.identity.try_read().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("identity rotation did not wait on the held acceptor lock");

    let reader_store = Arc::clone(&store);
    let (reader_started_tx, reader_started_rx) = tokio::sync::oneshot::channel();
    let reader_handle = tokio::spawn(async move {
        let _ = reader_started_tx.send(());
        reader_store.build_tls_acceptor().await
    });
    reader_started_rx.await.unwrap();
    tokio::task::yield_now().await;
    assert!(!reader_handle.is_finished());

    rotation_handle.abort();
    assert!(rotation_handle.await.unwrap_err().is_cancelled());
    let published_identity = store.identity.read().await;
    assert!(identities_match(
        published_identity.as_ref().unwrap(),
        &old_identity
    ));
    drop(published_identity);
    assert!(acceptor_guard.is_some());
    assert!(!reader_handle.is_finished());

    drop(acceptor_guard);
    tokio::time::timeout(Duration::from_secs(2), reader_handle)
        .await
        .expect("acceptor reader did not resume")
        .expect("acceptor reader task panicked")
        .unwrap();

    store.set_identity(new_identity.clone()).await.unwrap();
    let published_identity = store.identity.read().await;
    assert!(identities_match(
        published_identity.as_ref().unwrap(),
        &new_identity
    ));
    assert!(store.tls_acceptor.read().await.is_some());
}
