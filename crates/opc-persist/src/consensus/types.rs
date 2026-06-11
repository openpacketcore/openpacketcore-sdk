use crate::error::PersistError;
use crate::types::{AuditRecord, CommitRecord, RollbackTarget, StoredConfig};
use async_trait::async_trait;
use opc_types::TxId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::time::Instant;

#[async_trait]
pub trait ConsensusPeer: Send + Sync + std::fmt::Debug {
    fn node_id(&self) -> usize;
    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError>;
    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError>;
    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError>;
    async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError>;
    async fn load_rollback_consensus_rpc(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig, PersistError>;
    async fn timeout_now(&self, req: TimeoutNowRequest)
        -> Result<TimeoutNowResponse, PersistError>;
    async fn set_auth(
        &self,
        _local_node_id: usize,
        _local_cluster_id: String,
        _client_cert_pem: String,
    ) -> Result<(), PersistError> {
        Ok(())
    }
    async fn set_identity(&self, _identity: NodeIdentity) -> Result<(), PersistError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub cert_chain_pem: String,
    pub private_key_pem: String,
    pub ca_cert_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpiffeId {
    pub trust_domain: String,
    pub legacy_path_prefix: Vec<String>,
    pub tenant_id: String,
    pub namespace: String,
    pub service_account: String,
    pub nf_kind: String,
    pub instance_id: usize,
}

impl ParsedSpiffeId {
    pub fn same_workload_profile(&self, other: &Self) -> bool {
        self.trust_domain == other.trust_domain
            && self.legacy_path_prefix == other.legacy_path_prefix
            && self.tenant_id == other.tenant_id
            && self.namespace == other.namespace
            && self.service_account == other.service_account
            && self.nf_kind == other.nf_kind
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClusterMembership {
    pub cluster_id: String,
    pub node_id: usize,
    pub voting_members: Vec<usize>,
    pub non_voting_members: Vec<usize>,
    pub old_voting_members: Option<Vec<usize>>,
    pub removed_members: Vec<usize>,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPayload {
    pub cluster_id: String,
    pub membership_epoch: u64,
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub config: StoredConfig,
    pub membership: ClusterMembership,
    pub payload_hmac: [u8; 32],
}

impl SnapshotPayload {
    pub fn calculate_hmac(&self, audit_key: &crate::types::AuditKey) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(audit_key.as_bytes()).unwrap();
        mac.update(self.cluster_id.as_bytes());
        mac.update(&self.membership_epoch.to_be_bytes());
        mac.update(&self.last_included_index.to_be_bytes());
        mac.update(&self.last_included_term.to_be_bytes());
        if let Ok(config_bytes) = serde_json::to_vec(&self.config) {
            mac.update(&config_bytes);
        }
        if let Ok(membership_bytes) = serde_json::to_vec(&self.membership) {
            mac.update(&membership_bytes);
        }
        let result = mac.finalize();
        result.into_bytes().into()
    }
}

#[derive(Default, Debug)]
pub struct ConsensusMetrics {
    pub election_count: AtomicU64,
    pub leader_changes: AtomicU64,
    pub rpc_failures: AtomicU64,
    pub rpc_timeouts: AtomicU64,
    pub snapshot_installs: AtomicU64,
    pub snapshot_failures: AtomicU64,
    pub read_quorum_failures: AtomicU64,
    pub write_quorum_failures: AtomicU64,
    pub auth_failures: AtomicU64,
    pub membership_change_attempts: AtomicU64,
    pub membership_change_success: AtomicU64,
    pub membership_change_failures: AtomicU64,
    pub server_active_connections: AtomicU64,
    pub server_rejected_connections: AtomicU64,
    pub server_shutdown_failures: AtomicU64,
    pub server_start_failures: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct ConsensusMetricsDump {
    pub node_id: usize,
    pub role: String,
    pub term: u64,
    pub commit_index: u64,
    pub applied_index: u64,
    pub last_log_index: u64,
    pub membership_epoch: u64,
    pub election_count: u64,
    pub leader_changes: u64,
    pub rpc_failures: u64,
    pub rpc_timeouts: u64,
    pub snapshot_installs: u64,
    pub snapshot_failures: u64,
    pub read_quorum_failures: u64,
    pub write_quorum_failures: u64,
    pub auth_failures: u64,
    pub membership_change_attempts: u64,
    pub membership_change_success: u64,
    pub membership_change_failures: u64,
    pub server_active_connections: u64,
    pub server_rejected_connections: u64,
    pub server_shutdown_failures: u64,
    pub server_start_failures: u64,
    pub peer_status: HashMap<usize, PeerStatusDump>,
}

#[derive(Debug, Serialize)]
pub struct PeerStatusDump {
    pub next_index: u64,
    pub match_index: u64,
    pub lag: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ConsensusOp {
    AppendCommit {
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    },
    MarkConfirmed {
        tx_id: TxId,
    },
    CreateRollbackPoint {
        tx_id: TxId,
        label: Option<String>,
    },
    ChangeMembership {
        membership: ClusterMembership,
    },
    NoOp,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub op: ConsensusOp,
}

impl LogEntry {
    pub fn op_name(&self) -> &'static str {
        match &self.op {
            ConsensusOp::AppendCommit { .. } => "APPEND_COMMIT",
            ConsensusOp::MarkConfirmed { .. } => "MARK_CONFIRMED",
            ConsensusOp::CreateRollbackPoint { .. } => "CREATE_ROLLBACK_POINT",
            ConsensusOp::ChangeMembership { .. } => "CHANGE_MEMBERSHIP",
            ConsensusOp::NoOp => "NO_OP",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: usize,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    pub term: u64,
    pub candidate_id: usize,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotRequest {
    pub term: u64,
    pub leader_id: usize,
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotResponse {
    pub term: u64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutNowRequest {
    pub term: u64,
    pub candidate_id: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutNowResponse {
    pub term: u64,
    pub success: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

#[derive(Clone, Debug)]
pub struct ConsensusClock {
    pub election_timeout_min: std::time::Duration,
    pub election_timeout_max: std::time::Duration,
    pub heartbeat_interval: std::time::Duration,
    pub enable_timers: bool,
}

impl Default for ConsensusClock {
    fn default() -> Self {
        Self {
            election_timeout_min: std::time::Duration::from_millis(150),
            election_timeout_max: std::time::Duration::from_millis(300),
            heartbeat_interval: std::time::Duration::from_millis(50),
            enable_timers: true,
        }
    }
}

pub struct ConsensusNodeState {
    pub current_term: u64,
    pub voted_for: Option<usize>,
    pub leader_id: Option<usize>,
    pub role: Role,
    pub commit_index: u64,
    pub last_applied: u64,
    pub online: bool,
    pub last_contact: Instant,
    pub next_index: HashMap<usize, u64>,
    pub match_index: HashMap<usize, u64>,
    pub partitioned_peers: HashSet<usize>,
    pub finalization_in_progress: bool,
    pub last_finalized_epoch: Option<u64>,
}
