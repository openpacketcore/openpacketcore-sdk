use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};

pub mod election;
pub mod identity;
pub mod membership;
pub mod metrics;
pub mod pem;
pub mod read_index;
pub mod replication;
mod rpc_timing;
pub mod snapshot;
pub mod transport;
pub mod types;

#[cfg(test)]
mod tests;

// Re-exports
pub use types::{
    AppendEntriesRequest, AppendEntriesResponse, ClusterMembership, ConsensusClock,
    ConsensusMetrics, ConsensusMetricsDump, ConsensusNodeState, ConsensusOp, ConsensusPeer,
    InstallSnapshotRequest, InstallSnapshotResponse, LogEntry, NodeIdentity, PeerStatusDump,
    RequestVoteRequest, RequestVoteResponse, Role, SnapshotPayload, TimeoutNowRequest,
    TimeoutNowResponse,
};

pub use transport::{TcpPeer, TcpRpcServer};

use crate::backend::SqliteBackend;
use crate::error::PersistError;

#[derive(Clone)]
pub struct ConsensusConfigStore {
    pub node_id: usize,
    pub inner: Arc<SqliteBackend>,
    pub peers: Arc<RwLock<HashMap<usize, Arc<dyn ConsensusPeer>>>>,
    pub state: Arc<Mutex<ConsensusNodeState>>,
    pub commit_notifier: Arc<tokio::sync::Notify>,
    pub clock: ConsensusClock,
    pub metrics: Arc<ConsensusMetrics>,
    pub server_shutdown: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    pub identity: Arc<RwLock<Option<NodeIdentity>>>,
    pub tls_acceptor: Arc<RwLock<Option<tokio_rustls::TlsAcceptor>>>,
}

impl std::fmt::Debug for ConsensusConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusConfigStore")
            .field("node_id", &self.node_id)
            .finish()
    }
}

impl ConsensusConfigStore {
    pub async fn new(
        node_id: usize,
        inner: Arc<SqliteBackend>,
        initial_membership: Option<ClusterMembership>,
        clock: Option<ConsensusClock>,
    ) -> Result<Self, PersistError> {
        let (term, vote) = inner.consensus_get_state().await?;
        let applied = inner.consensus_get_applied_index().await?;
        let c = clock.unwrap_or_default();

        let membership = inner.consensus_get_active_membership().await?;
        if let Some(ref m) = membership {
            if m.node_id != node_id {
                return Err(PersistError::inconsistent_state(format!(
                    "configured node_id {} does not match persisted node_id {}",
                    node_id, m.node_id
                )));
            }
            if let Some(ref init_m) = initial_membership {
                if m.cluster_id != init_m.cluster_id {
                    return Err(PersistError::inconsistent_state(format!(
                        "configured cluster_id {} does not match persisted cluster_id {}",
                        init_m.cluster_id, m.cluster_id
                    )));
                }
            }
        } else {
            let m = initial_membership.unwrap_or_else(|| ClusterMembership {
                cluster_id: "default-cluster".to_string(),
                node_id,
                voting_members: vec![node_id],
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 1,
            });
            if m.node_id != node_id {
                return Err(PersistError::inconsistent_state(format!(
                    "initial membership node_id {} does not match configured node_id {}",
                    m.node_id, node_id
                )));
            }
            inner.consensus_set_membership(&m).await?;
        }

        let state = Arc::new(Mutex::new(ConsensusNodeState {
            current_term: term,
            voted_for: vote,
            leader_id: None,
            role: Role::Follower,
            commit_index: applied,
            last_applied: applied,
            online: true,
            last_contact: Instant::now(),
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            partitioned_peers: HashSet::new(),
            finalization_in_progress: false,
            last_finalized_epoch: None,
        }));

        let peers = Arc::new(RwLock::new(HashMap::new()));
        let commit_notifier = Arc::new(tokio::sync::Notify::new());
        let metrics = Arc::new(ConsensusMetrics::default());

        Self::start_timers(
            Arc::clone(&inner),
            Arc::clone(&peers),
            Arc::clone(&state),
            Arc::clone(&commit_notifier),
            c.clone(),
            node_id,
            Arc::clone(&metrics),
        );

        Ok(Self {
            node_id,
            inner,
            peers,
            state,
            commit_notifier,
            clock: c,
            metrics,
            server_shutdown: Arc::new(tokio::sync::Mutex::new(None)),
            identity: Arc::new(RwLock::new(None)),
            tls_acceptor: Arc::new(RwLock::new(None)),
        })
    }

    pub fn get_spiffe_id(&self) -> String {
        format!(
            "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/{}",
            self.node_id
        )
    }

    pub fn get_client_cert_pem(&self) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\nSubjectAltName: {}\n-----END CERTIFICATE-----",
            self.get_spiffe_id()
        )
    }

    pub async fn add_peer(&self, peer_id: usize, peer: Arc<dyn ConsensusPeer>) {
        // Compatibility wrapper for the original infallible API. Setup errors
        // never publish the peer; callers that need the reason should use
        // `try_add_peer`, which returns fixed, non-secret failure messages.
        if self.try_add_peer(peer_id, peer).await.is_err() {
            tracing::warn!("consensus peer registration failed");
        }
    }

    /// Configure and publish a peer, failing closed if adapter setup fails.
    pub async fn try_add_peer(
        &self,
        peer_id: usize,
        peer: Arc<dyn ConsensusPeer>,
    ) -> Result<(), PersistError> {
        if peer_id == self.node_id || peer.node_id() != peer_id {
            return Err(PersistError::inconsistent_state(
                "consensus peer id does not match registration",
            ));
        }
        SqliteBackend::consensus_node_id_to_sqlite(peer_id)?;
        let membership = self
            .inner
            .consensus_get_active_membership()
            .await
            .map_err(|_| PersistError::io("failed to load consensus membership"))?
            .ok_or_else(|| PersistError::inconsistent_state("consensus membership missing"))?;
        peer.set_auth(
            self.node_id,
            membership.cluster_id,
            self.get_client_cert_pem(),
        )
        .await
        .map_err(|_| PersistError::io("failed to configure consensus peer authentication"))?;

        // This write lock is also the identity-rotation serialization gate.
        // Applying the current identity and inserting the adapter while it is
        // held prevents a rotation from missing this peer, and prevents two
        // rotations from completing peer propagation out of order.
        let mut peers_guard = self.peers.write().await;
        let identity = self.identity.read().await.clone();
        if let Some(identity) = identity {
            peer.set_identity(identity)
                .await
                .map_err(|_| PersistError::io("failed to configure consensus peer identity"))?;
        }
        peers_guard.insert(peer_id, peer);
        Ok(())
    }

    pub async fn set_partition(&self, peer_id: usize, partitioned: bool) {
        let mut state = self.state.lock().await;
        if partitioned {
            state.partitioned_peers.insert(peer_id);
        } else {
            state.partitioned_peers.remove(&peer_id);
        }
    }

    pub async fn is_partitioned(&self, peer_id: usize) -> bool {
        let state = self.state.lock().await;
        state.partitioned_peers.contains(&peer_id)
    }

    pub(crate) async fn is_voting_member(&self, node_id: usize) -> Result<bool, PersistError> {
        let membership = self
            .inner
            .consensus_get_active_membership()
            .await?
            .ok_or_else(|| PersistError::inconsistent_state("consensus membership missing"))?;
        Ok(membership.voting_members.contains(&node_id)
            || membership
                .old_voting_members
                .as_ref()
                .map(|old| old.contains(&node_id))
                .unwrap_or(false))
    }

    pub async fn set_online(&self, online: bool) {
        let mut state = self.state.lock().await;
        state.online = online;
        if online {
            state.last_contact = Instant::now();
        }
    }

    pub async fn is_online(&self) -> bool {
        self.state.lock().await.online
    }

    pub async fn get_role(&self) -> Role {
        self.state.lock().await.role
    }

    pub async fn get_leader_id(&self) -> Option<usize> {
        self.state.lock().await.leader_id
    }

    pub async fn get_term(&self) -> u64 {
        self.state.lock().await.current_term
    }
}
