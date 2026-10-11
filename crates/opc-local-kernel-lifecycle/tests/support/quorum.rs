//! Real durable three-voter fixture. Only admission and loopback transport are
//! test policy; opaque committed capabilities come from production services.

use async_trait::async_trait;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity};
use opc_session_store::scope_authority::*;
use opc_session_store::scope_batch::*;
use opc_session_store::{
    ConsensusSessionStore, QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, SessionConsensusNodeId,
    SessionConsensusPeer, SessionConsensusPeerError, SessionConsensusRpcHandler,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionConsumerIdentity,
    SnapshotIntegrityPolicy, SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

#[derive(Debug)]
struct Peer {
    node: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    enabled: Arc<AtomicBool>,
    drop_reply: Arc<AtomicBool>,
    handler: RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>,
}
#[async_trait]
impl SessionConsensusPeer for Peer {
    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node
    }
    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .unwrap()
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        let family = request.family;
        let response = handler.handle(request.sender, request).await;
        if family == opc_session_store::SessionConsensusRpcFamily::ForwardMutation
            && self.drop_reply.swap(false, Ordering::AcqRel)
        {
            self.enabled.store(false, Ordering::Release);
            return Err(SessionConsensusPeerError::Unavailable);
        }
        Ok(response)
    }
}
fn replica(index: usize) -> ReplicaId {
    ReplicaId::new(format!("local-scope-voter-{index}")).unwrap()
}
fn member(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica(index),
        ReplicaEndpoint::new(format!("local-scope-voter-{index}.invalid"), 7443).unwrap(),
        ReplicaTlsIdentity::new(format!("spiffe://local-scope.test/voter/{index}")).unwrap(),
        ReplicaFailureDomain::new(format!("zone-{index}")).unwrap(),
        ReplicaBackingIdentity::new(format!("disk-{index}")).unwrap(),
    )
}
pub(crate) fn execution() -> ScopeExecution {
    ScopeExecution::new(
        SessionConsumerIdentity::new("spiffe://local-scope.test/worker").unwrap(),
        1,
        [1; 16],
        [2; 16],
        [3; 32],
    )
    .unwrap()
}
struct Admission(ScopeId);
#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeId,
        claim: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        let boot = execution();
        if scope != &self.0
            || authenticated != boot.identity()
            || claim.is_some_and(|claim| claim != &boot)
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        Ok(ScopeAuthorityRole::Worker)
    }
    async fn verify_closure(
        &self,
        authenticated: &SessionConsumerIdentity,
        predecessor: &ScopeAuthorityStamp,
        _: &ScopeClosureEvidence,
        _: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        if predecessor.scope() != &self.0 || predecessor.execution().identity() != authenticated {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        Ok(())
    }
}
pub(crate) struct Quorum {
    pub(crate) stores: Vec<ConsensusSessionStore>,
    paths: BTreeMap<(usize, usize), Arc<Peer>>,
    pub(crate) authority: ScopeAuthorityStore,
    pub(crate) batches: ScopeBatchStore,
    pub(crate) committed: CommittedScopeAuthority,
    _directory: tempfile::TempDir,
}
impl Drop for Quorum {
    fn drop(&mut self) {
        for peer in self.paths.values() {
            *peer.handler.write().unwrap() = None;
        }
    }
}
impl Quorum {
    pub(crate) async fn open() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let members = (0..3).map(member).collect::<Vec<_>>();
        let cluster = ConsensusClusterId::new("local-kernel-lifecycle-tests").unwrap();
        let epoch = ConsensusConfigurationEpoch::new(1).unwrap();
        let fingerprints = members
            .iter()
            .map(QuorumReplicaDescriptor::configuration_fingerprint)
            .collect::<Vec<_>>();
        let identity = opc_session_store::derive_fixed_durable_quorum_consensus_identity(
            cluster,
            epoch,
            &fingerprints,
            opc_session_store::PlacementResiliencePolicy::default(),
        );
        let topologies = (0..3)
            .map(|index| {
                ValidatedQuorumTopology::try_from_fixed_durable_quorum(
                    QuorumTopologyConfig::new_consensus(replica(index), members.clone(), identity),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let nodes = topologies
            .iter()
            .map(|topology| topology.local_consensus_node_id().unwrap())
            .collect::<Vec<_>>();
        let mut paths = BTreeMap::new();
        let enabled = Arc::new(AtomicBool::new(true));
        let drop_reply = Arc::new(AtomicBool::new(false));
        for source in 0..3 {
            for (target, node) in nodes.iter().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(Peer {
                            node: *node,
                            identity,
                            enabled: enabled.clone(),
                            drop_reply: drop_reply.clone(),
                            handler: RwLock::new(None),
                        }),
                    );
                }
            }
        }
        let mut stores = vec![];
        for index in 0..3 {
            let peers = (0..3)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> = paths[&(index, target)].clone();
                    (nodes[target], peer)
                })
                .collect();
            stores.push(
                ConsensusSessionStore::open_fixed_durable_quorum_with_snapshot_integrity(
                    topologies[index].clone(),
                    SqliteSessionBackend::open(
                        directory.path().join(format!("voter-{index}.sqlite")),
                    )
                    .unwrap(),
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                    SnapshotIntegrityPolicy::PortableVerified,
                )
                .await
                .unwrap(),
            );
        }
        for ((_, target), peer) in &paths {
            *peer.handler.write().unwrap() = Some(stores[*target].rpc_handler());
        }
        for result in futures_util::future::join_all(
            stores.iter().map(ConsensusSessionStore::initialize_cluster),
        )
        .await
        {
            result.unwrap();
        }
        loop {
            if futures_util::future::join_all(
                stores
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await
            .iter()
            .all(|report| report.is_ready())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        stores[0].activate_scope_profile().await.unwrap();
        let serving = stores
            .iter()
            .position(|store| {
                let status = store.status();
                status
                    .leader_id
                    .is_some_and(|leader| leader != status.node_id)
            })
            .expect("one of three voters is a follower");
        let scope = ScopeId::new(
            stores[0].consumer_scope().unwrap().consensus_identity(),
            TenantId::new("local-kernel-tests").unwrap(),
            NetworkFunctionKind::new("test").unwrap(),
            [27; 32],
        )
        .unwrap();
        let admission = Arc::new(Admission(scope.clone()));
        let authority = ScopeAuthorityStore::new(
            Arc::new(stores[serving].clone()),
            scope.clone(),
            admission.clone(),
        )
        .unwrap();
        let committed = authority
            .admit(
                execution().identity(),
                &ScopeAuthorityRequest::new(
                    scope,
                    [1; 16],
                    0,
                    ScopeAuthorityOperation::AdmitInitial {
                        execution: execution(),
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let batches = ScopeBatchStore::new(
            Arc::new(stores[serving].clone()),
            committed.stamp().namespace().clone(),
            admission,
        )
        .unwrap();
        Self {
            stores,
            paths,
            authority,
            batches,
            committed,
            _directory: directory,
        }
    }
    pub(crate) fn lose_next_commit_reply(&self) {
        self.paths
            .values()
            .next()
            .unwrap()
            .drop_reply
            .store(true, Ordering::Release);
    }
    pub(crate) fn lost_commit_reply(&self) -> bool {
        !self
            .paths
            .values()
            .next()
            .unwrap()
            .drop_reply
            .load(Ordering::Acquire)
    }
    pub(crate) fn set_available(&self, available: bool) {
        for peer in self.paths.values() {
            peer.enabled.store(available, Ordering::Release);
        }
    }
    pub(crate) async fn close(&self) {
        for peer in self.paths.values() {
            *peer.handler.write().unwrap() = None;
        }
        for result in
            futures_util::future::join_all(self.stores.iter().map(ConsensusSessionStore::shutdown))
                .await
        {
            result.unwrap();
        }
    }
    pub(crate) async fn create_request(&self, child: u8) -> ScopeBatchRequest {
        let revision = self
            .batches
            .current(execution().identity())
            .await
            .unwrap()
            .revision();
        ScopeBatchRequest::new(
            self.committed.stamp(),
            [child; 16],
            revision,
            vec![ScopeChildMutation::Create {
                key: child_key(child),
                value: value(child),
                claims: vec![],
            }],
            vec![],
        )
        .unwrap()
    }
}
pub(crate) fn child_key(n: u8) -> ScopeChildKey {
    ScopeChildKey::new([n; 32]).unwrap()
}
pub(crate) fn value(n: u8) -> ScopeSealedValue {
    ScopeSealedValue::new(
        opc_crypto::CryptoEnvelopeV1 {
            algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
            key_id: opc_key::KeyId::new("local-scope-fixture").unwrap(),
            nonce: vec![n; 12],
            aad: vec![n; 32],
            ciphertext_and_tag: vec![n; 32],
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
}
