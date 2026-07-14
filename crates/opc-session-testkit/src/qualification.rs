//! Experimental qualification profile and multi-process node protocol.
//!
//! The node protocol supports a production-constructor projected-SVID mTLS
//! candidate path. Its older loopback plaintext foundation remains available
//! only behind the testkit's explicit `foundation-insecure` feature and never
//! counts as TLS-rotation evidence.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_identity::projected_svid::{
    ProjectedSvidAvailability, ProjectedSvidReloadReason, ProjectedSvidReloadStatus,
    MAX_PROJECTED_SVID_BUNDLE_FILES, MIN_PROJECTED_SVID_POLL_INTERVAL,
};
use opc_session_net::{
    ConnectionLifecyclePolicy, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration,
};
use opc_session_store::{
    validate_session_ttl, OwnerId, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, STABLE_ID_MAX_BYTES,
};
use opc_tls::{TlsMaterialAvailability, TlsMaterialReloadReason, TlsMaterialStatus};
use opc_types::{SpiffeId, Timestamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Exact profile inventory consumed by qualification tooling.
pub const SESSION_HA_PROFILE_JSON: &str =
    include_str!("../qualification/v2/session-ha-profile.json");
/// JSON Schema for the exact experimental profile inventory.
pub const SESSION_HA_PROFILE_SCHEMA_JSON: &str =
    include_str!("../qualification/v2/session-ha-profile.schema.json");
/// JSON Schema for one independent history-checker input operation.
pub const SESSION_HA_HISTORY_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-ha-history.schema.json");
/// JSON Schema for one immutable qualification workload invocation.
pub const SESSION_HA_SCHEDULE_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-ha-schedule.schema.json");
/// JSON Schema for one experimental qualification evidence record.
pub const SESSION_HA_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../qualification/v2/session-ha-evidence.schema.json");
/// Strict schema for one incomplete production-mTLS harness checkpoint.
pub const SESSION_MTLS_CANDIDATE_EVIDENCE_SCHEMA_JSON: &str =
    include_str!("../qualification/v1/session-mtls-candidate-evidence.schema.json");

/// Version of the private node-control protocol.
pub const QUALIFICATION_NODE_SCHEMA_VERSION: u16 = 1;
/// Maximum accepted node configuration document.
pub const QUALIFICATION_MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Maximum accepted control request or response line.
pub const QUALIFICATION_MAX_CONTROL_LINE_BYTES: usize = 16 * 1024;
/// Maximum number of synthetic payload bytes admitted by the node harness.
pub const QUALIFICATION_MAX_VALUE_BYTES: usize = 512;
/// Maximum retained lease handles in one qualification child.
pub const QUALIFICATION_MAX_LEASE_HANDLES: usize = 1024;
/// Exact operation timeout pinned by the experimental profile.
pub const QUALIFICATION_OPERATION_TIMEOUT_MILLIS: u64 =
    DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis;
/// Largest accepted finite lifecycle field in the private harness config.
pub const QUALIFICATION_MAX_LIFECYCLE_MILLIS: u64 = 24 * 60 * 60 * 1_000;

/// Machine-readable experimental session-HA profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHaQualificationProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub maturity: String,
    pub qualification_complete: bool,
    pub workspace: QualificationWorkspace,
    pub source_build_gate: QualificationSourceBuildGate,
    pub artifacts: Vec<QualificationArtifact>,
    pub platforms: Vec<QualificationPlatform>,
    pub topology: QualificationTopology,
    pub protocol: QualificationProtocol,
    pub consensus_timing: QualificationConsensusTiming,
    pub bounds: QualificationBounds,
    pub provisional_test_thresholds: QualificationThresholds,
    pub evidence: QualificationEvidenceRequirements,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationWorkspace {
    pub version: String,
    pub rust_msrv: String,
    pub source_revision: String,
}

/// Exact interim source and publication gate for the patched consensus engine.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationSourceBuildGate {
    pub tracking_issue: u64,
    pub openraft_git: String,
    pub openraft_rev: String,
    pub affected_workspace_crates: Vec<String>,
    pub crates_io_check_date: String,
    pub crates_io_exact_matches: Vec<String>,
    pub removal_condition: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifact {
    pub crate_name: String,
    pub version: String,
    pub publish: bool,
    pub required_features: Vec<String>,
    pub excluded_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationPlatform {
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTopology {
    pub member_counts: Vec<usize>,
    pub maximum_members: usize,
    pub quorum_rule: String,
    pub distinct_failure_domain_per_voter: bool,
    pub distinct_backing_store_per_voter: bool,
    pub stable_identity_independent_of_route: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProtocol {
    pub consensus_alpn: String,
    pub transport_revision: u16,
    pub wire_schema_revision: u16,
    pub error_set_revision: u16,
    pub consensus_schema_version: u16,
    pub min_frame_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_rpc_payload_bytes: usize,
    pub legacy_direct_backend_enabled: bool,
}

/// Fixed non-operator-tunable consensus timing inventory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConsensusTiming {
    pub cold_connect_budget_composition: String,
    pub cold_connect_timeout_millis: u64,
    pub append_entries_timeout_millis: u64,
    pub heartbeat_interval_millis: u64,
    pub vote_timeout_millis: u64,
    pub election_timeout_min_millis: u64,
    pub election_timeout_max_millis: u64,
    pub install_snapshot_timeout_millis: u64,
    pub forward_mutation_timeout_millis: u64,
    pub read_barrier_timeout_millis: u64,
    pub server_idle_timeout_millis: u64,
    pub server_handler_timeout_millis: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationBounds {
    pub operation_timeout_millis: u64,
    pub max_session_ttl_seconds: u64,
    pub max_stable_id_bytes: usize,
    pub max_replication_transaction_id_bytes: usize,
    pub max_replication_operation_depth: usize,
    pub max_replication_operations_per_entry: usize,
    pub max_replication_log_page_entries: usize,
    pub max_watch_backlog_entries: usize,
    pub max_restore_page_records: usize,
    pub max_restore_page_payload_bytes: usize,
    pub max_restore_examined_rows: usize,
    pub max_restore_sqlite_work_millis: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationThresholds {
    pub acknowledged_write_loss: u64,
    pub stale_owner_mutation_successes: u64,
    pub conflicting_committed_entries: u64,
    pub watch_gaps: u64,
    pub max_startup_millis: u64,
    pub max_single_member_stop_service_continuity_millis: u64,
    pub max_restart_catchup_millis: u64,
    pub max_leader_failover_millis: u64,
    pub max_leader_restart_catchup_millis: u64,
    pub minimum_soak_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationEvidenceRequirements {
    pub schedule_schema: String,
    pub history_schema: String,
    pub evidence_schema: String,
    pub independent_checker: String,
    pub required_topologies: Vec<usize>,
    pub required_transport_modes: Vec<String>,
    pub foundation_transport_mode: String,
    pub foundation_counts_for_tls_rotation: bool,
    pub foundation_payload_protection: String,
    pub foundation_counts_for_production_encryption: bool,
    pub unresolved_dependencies: Vec<u64>,
}

/// Configuration for one real process in the qualification fleet.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationNodeConfig {
    pub schema_version: u16,
    pub node_index: usize,
    pub cluster_id: String,
    pub configuration_generation: String,
    pub configuration_epoch: u64,
    pub backend_namespace: String,
    pub workload_schedule_sha256: String,
    pub members: Vec<QualificationMember>,
    pub workspace_directory: PathBuf,
    pub database_path: PathBuf,
    pub snapshot_directory: PathBuf,
    pub operation_timeout_millis: u64,
    #[serde(default)]
    pub transport: QualificationTransportConfig,
}

impl QualificationNodeConfig {
    /// Validate all allocation, path, topology, and transport boundaries.
    pub fn validate(&self) -> Result<(), QualificationConfigError> {
        if self.schema_version != QUALIFICATION_NODE_SCHEMA_VERSION {
            return Err(QualificationConfigError::Schema);
        }
        if !matches!(self.members.len(), 3 | 5) {
            return Err(QualificationConfigError::Topology);
        }
        if self.node_index >= self.members.len()
            || self.operation_timeout_millis != QUALIFICATION_OPERATION_TIMEOUT_MILLIS
            || self.configuration_epoch == 0
            || !is_bounded_label(&self.backend_namespace, 128)
            || !is_exact_sha256(&self.workload_schedule_sha256)
            || SessionClusterId::new(self.cluster_id.clone()).is_err()
            || SessionConfigurationGeneration::new(self.configuration_generation.clone()).is_err()
            || SessionConfigurationEpoch::new(self.configuration_epoch).is_err()
            || !self.workspace_directory.is_absolute()
            || !self.database_path.is_absolute()
            || !self.snapshot_directory.is_absolute()
            || self.workspace_directory.parent().is_none()
            || self.database_path == self.snapshot_directory
            || !self.database_path.starts_with(&self.workspace_directory)
            || !self
                .snapshot_directory
                .starts_with(&self.workspace_directory)
            || self
                .transport
                .validate(&self.workspace_directory, self.operation_timeout_millis)
                .is_err()
        {
            return Err(QualificationConfigError::Configuration);
        }

        let mut replica_ids = HashSet::<ReplicaId>::with_capacity(self.members.len());
        let mut endpoints = HashSet::<ReplicaEndpoint>::with_capacity(self.members.len());
        let mut routes = HashSet::with_capacity(self.members.len());
        let mut tls_identities = HashSet::<ReplicaTlsIdentity>::with_capacity(self.members.len());
        let mut failure_domains =
            HashSet::<ReplicaFailureDomain>::with_capacity(self.members.len());
        let mut backing_identities =
            HashSet::<ReplicaBackingIdentity>::with_capacity(self.members.len());
        for (expected_index, member) in self.members.iter().enumerate() {
            let replica_id = ReplicaId::new(member.replica_id.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            let endpoint = ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                .map_err(|_| QualificationConfigError::Member)?;
            let tls_identity = ReplicaTlsIdentity::new(member.tls_identity.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            SpiffeId::new(member.tls_identity.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            let failure_domain = ReplicaFailureDomain::new(member.failure_domain.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            let backing_identity = ReplicaBackingIdentity::new(member.backing_identity.clone())
                .map_err(|_| QualificationConfigError::Member)?;
            if member.node_index != expected_index
                || member.endpoint_port == 0
                || member.dial_addr.port() == 0
                || !member.dial_addr.ip().is_loopback()
                || member.replica_id.is_empty()
                || member.endpoint_host.is_empty()
                || member.tls_identity.is_empty()
                || member.failure_domain.is_empty()
                || member.backing_identity.is_empty()
                || !replica_ids.insert(replica_id)
                || !endpoints.insert(endpoint)
                || !routes.insert(member.dial_addr)
                || !tls_identities.insert(tls_identity)
                || !failure_domains.insert(failure_domain)
                || !backing_identities.insert(backing_identity)
            {
                return Err(QualificationConfigError::Member);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for QualificationNodeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationNodeConfig")
            .field("schema_version", &self.schema_version)
            .field("node_index", &self.node_index)
            .field("configured_members", &self.members.len())
            .field("cluster_scope", &"<redacted>")
            .field("workload_schedule", &"<redacted>")
            .field("workspace_directory", &"<redacted>")
            .field("database_path", &"<redacted>")
            .field("snapshot_directory", &"<redacted>")
            .field("operation_timeout_millis", &self.operation_timeout_millis)
            .field("transport", &self.transport)
            .finish()
    }
}

/// Transport selected by one qualification node.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "configuration",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum QualificationTransportConfig {
    /// Historical loopback-only foundation. Runtime support is feature-gated.
    #[default]
    LoopbackPlaintextTestOnly,
    /// Production mTLS constructors backed by one coherent projected source.
    ProjectedMtls(QualificationProjectedMtlsConfig),
}

impl fmt::Debug for QualificationTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoopbackPlaintextTestOnly => {
                formatter.write_str("QualificationTransportConfig::LoopbackPlaintextTestOnly")
            }
            Self::ProjectedMtls(config) => formatter
                .debug_tuple("QualificationTransportConfig::ProjectedMtls")
                .field(config)
                .finish(),
        }
    }
}

impl QualificationTransportConfig {
    fn validate(
        &self,
        workspace_directory: &Path,
        operation_timeout_millis: u64,
    ) -> Result<(), QualificationConfigError> {
        match self {
            Self::LoopbackPlaintextTestOnly => Ok(()),
            Self::ProjectedMtls(config) => {
                config.validate(workspace_directory, operation_timeout_millis)
            }
        }
    }
}

/// Bounded projected-SVID and connection-lifecycle settings for mTLS.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProjectedMtlsConfig {
    pub projected_volume_root: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_bundle_files: Vec<PathBuf>,
    pub poll_interval_millis: u64,
    pub lifecycle: QualificationConnectionLifecycleConfig,
}

impl fmt::Debug for QualificationProjectedMtlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationProjectedMtlsConfig")
            .field("projected_volume_root", &"<redacted>")
            .field("certificate_file", &"<redacted>")
            .field("private_key_file", &"<redacted>")
            .field("trust_bundle_file_count", &self.trust_bundle_files.len())
            .field("poll_interval_millis", &self.poll_interval_millis)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

impl QualificationProjectedMtlsConfig {
    fn validate(
        &self,
        workspace_directory: &Path,
        operation_timeout_millis: u64,
    ) -> Result<(), QualificationConfigError> {
        let poll_interval = Duration::from_millis(self.poll_interval_millis);
        if !self.projected_volume_root.is_absolute()
            || !self.projected_volume_root.starts_with(workspace_directory)
            || self.projected_volume_root == workspace_directory
            || !is_normalized_relative_path(&self.certificate_file)
            || !is_normalized_relative_path(&self.private_key_file)
            || self.trust_bundle_files.is_empty()
            || self.trust_bundle_files.len() > MAX_PROJECTED_SVID_BUNDLE_FILES
            || self
                .trust_bundle_files
                .iter()
                .any(|path| !is_normalized_relative_path(path))
            || self.certificate_file == self.private_key_file
            || self
                .trust_bundle_files
                .iter()
                .any(|path| path == &self.certificate_file || path == &self.private_key_file)
            || self.trust_bundle_files.iter().collect::<HashSet<_>>().len()
                != self.trust_bundle_files.len()
            || poll_interval < MIN_PROJECTED_SVID_POLL_INTERVAL
            || self.poll_interval_millis > operation_timeout_millis
            || self.lifecycle.to_policy().is_err()
        {
            return Err(QualificationConfigError::Transport);
        }
        Ok(())
    }
}

/// Exact finite connection retirement and reconnect policy used by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConnectionLifecycleConfig {
    pub maximum_authentication_age_millis: u64,
    pub rotation_drain_window_millis: u64,
    pub reconnect_backoff_min_millis: u64,
    pub reconnect_backoff_max_millis: u64,
    pub rotation_jitter_millis: u64,
}

impl QualificationConnectionLifecycleConfig {
    /// Validate and construct the production transport lifecycle policy.
    pub fn to_policy(self) -> Result<ConnectionLifecyclePolicy, QualificationConfigError> {
        let values = [
            self.maximum_authentication_age_millis,
            self.rotation_drain_window_millis,
            self.reconnect_backoff_min_millis,
            self.reconnect_backoff_max_millis,
            self.rotation_jitter_millis,
        ];
        if values
            .into_iter()
            .any(|value| value > QUALIFICATION_MAX_LIFECYCLE_MILLIS)
        {
            return Err(QualificationConfigError::Transport);
        }
        ConnectionLifecyclePolicy::try_new(
            Duration::from_millis(self.maximum_authentication_age_millis),
            Duration::from_millis(self.rotation_drain_window_millis),
            Duration::from_millis(self.reconnect_backoff_min_millis),
            Duration::from_millis(self.reconnect_backoff_max_millis),
            Duration::from_millis(self.rotation_jitter_millis),
        )
        .map_err(|_| QualificationConfigError::Transport)
    }
}

fn is_normalized_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_bounded_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Return the exact evidence digest for one synthetic qualification key.
pub fn qualification_key_sha256(value: &str) -> String {
    qualification_digest("key", value.as_bytes())
}

/// Return the exact evidence digest for one synthetic qualification owner.
pub fn qualification_owner_sha256(value: &str) -> String {
    qualification_digest("owner", value.as_bytes())
}

/// Return the exact evidence digest for a synthetic qualification value.
pub fn qualification_value_sha256(value: &[u8]) -> String {
    qualification_digest("value", value)
}

fn qualification_digest(kind: &str, value: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(b"opc-session-ha/");
    hasher.update(kind.as_bytes());
    hasher.update(b"/v1\0");
    hasher.update(value);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn is_exact_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// One immutable fleet member descriptor plus its local test dial route.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationMember {
    pub node_index: usize,
    pub replica_id: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub dial_addr: SocketAddr,
    pub tls_identity: String,
    pub failure_domain: String,
    pub backing_identity: String,
}

impl fmt::Debug for QualificationMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationMember")
            .field("node_index", &self.node_index)
            .field("descriptor", &"<redacted>")
            .field("dial_route", &"<redacted>")
            .finish()
    }
}

/// Fixed, non-sensitive configuration failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationConfigError {
    #[error("qualification configuration schema is unsupported")]
    Schema,
    #[error("qualification topology is unsupported")]
    Topology,
    #[error("qualification configuration is invalid")]
    Configuration,
    #[error("qualification member descriptor is invalid")]
    Member,
    #[error("qualification transport configuration is invalid")]
    Transport,
}

/// Bounded commands accepted by one qualification child process.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationNodeCommand {
    Configure,
    Initialize,
    Probe,
    ProjectedSourceStatus,
    MaterialStatus,
    RequestReauthentication,
    /// Prove one fresh authenticated TLS connection and exact manifest-bound
    /// consensus bootstrap to a configured remote node.
    ///
    /// An exact authenticated `Protocol` application result also satisfies
    /// this transport proof; this command does not claim valid private
    /// ReadBarrier handler execution.
    DirectedHandshake {
        remote_node_index: usize,
    },
    LifecycleMetrics,
    Acquire {
        lease_handle: String,
        stable_id: String,
        owner: String,
        ttl_millis: u64,
    },
    CompareAndSet {
        lease_handle: String,
        stable_id: String,
        expected_generation: Option<u64>,
        new_generation: u64,
        value: String,
    },
    Get {
        stable_id: String,
    },
    Release {
        lease_handle: String,
    },
    Shutdown,
}

impl fmt::Debug for QualificationNodeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configure => formatter.write_str("QualificationNodeCommand::Configure"),
            Self::Initialize => formatter.write_str("QualificationNodeCommand::Initialize"),
            Self::Probe => formatter.write_str("QualificationNodeCommand::Probe"),
            Self::ProjectedSourceStatus => {
                formatter.write_str("QualificationNodeCommand::ProjectedSourceStatus")
            }
            Self::MaterialStatus => formatter.write_str("QualificationNodeCommand::MaterialStatus"),
            Self::RequestReauthentication => {
                formatter.write_str("QualificationNodeCommand::RequestReauthentication")
            }
            Self::DirectedHandshake { remote_node_index } => formatter
                .debug_struct("QualificationNodeCommand::DirectedHandshake")
                .field("remote_node_index", remote_node_index)
                .finish(),
            Self::LifecycleMetrics => {
                formatter.write_str("QualificationNodeCommand::LifecycleMetrics")
            }
            Self::Acquire { .. } => formatter.write_str("QualificationNodeCommand::Acquire"),
            Self::CompareAndSet { value, .. } => formatter
                .debug_struct("QualificationNodeCommand::CompareAndSet")
                .field("value_bytes", &value.len())
                .finish(),
            Self::Get { .. } => formatter.write_str("QualificationNodeCommand::Get"),
            Self::Release { .. } => formatter.write_str("QualificationNodeCommand::Release"),
            Self::Shutdown => formatter.write_str("QualificationNodeCommand::Shutdown"),
        }
    }
}

impl QualificationNodeCommand {
    /// Validate all attacker-controlled fields before a backend or provider is
    /// consulted by the child process.
    pub fn validate(&self) -> Result<(), QualificationCommandError> {
        match self {
            Self::Configure
            | Self::Initialize
            | Self::Probe
            | Self::ProjectedSourceStatus
            | Self::MaterialStatus
            | Self::RequestReauthentication
            | Self::LifecycleMetrics
            | Self::Shutdown => Ok(()),
            Self::DirectedHandshake { remote_node_index } => {
                if *remote_node_index < 5 {
                    Ok(())
                } else {
                    Err(QualificationCommandError::NodeIndex)
                }
            }
            Self::Acquire {
                lease_handle,
                stable_id,
                owner,
                ttl_millis,
            } => {
                validate_handle(lease_handle)?;
                validate_stable_id(stable_id)?;
                OwnerId::new(owner.clone()).map_err(|_| QualificationCommandError::Owner)?;
                validate_session_ttl(Duration::from_millis(*ttl_millis))
                    .map_err(|_| QualificationCommandError::Ttl)
            }
            Self::CompareAndSet {
                lease_handle,
                stable_id,
                expected_generation,
                new_generation,
                value,
            } => {
                validate_handle(lease_handle)?;
                validate_stable_id(stable_id)?;
                if *new_generation == 0
                    || expected_generation.is_some_and(|current| current >= *new_generation)
                {
                    return Err(QualificationCommandError::Generation);
                }
                if value.len() > QUALIFICATION_MAX_VALUE_BYTES {
                    return Err(QualificationCommandError::Value);
                }
                Ok(())
            }
            Self::Get { stable_id } => validate_stable_id(stable_id),
            Self::Release { lease_handle } => validate_handle(lease_handle),
        }
    }
}

fn validate_handle(value: &str) -> Result<(), QualificationCommandError> {
    if value.is_empty()
        || value.len() > 64
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(QualificationCommandError::LeaseHandle);
    }
    Ok(())
}

fn validate_stable_id(value: &str) -> Result<(), QualificationCommandError> {
    if value.is_empty() || value.len() > STABLE_ID_MAX_BYTES {
        return Err(QualificationCommandError::StableId);
    }
    Ok(())
}

/// Fixed validation failures for the child control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationCommandError {
    #[error("qualification node index is invalid")]
    NodeIndex,
    #[error("qualification lease handle is invalid")]
    LeaseHandle,
    #[error("qualification stable ID is invalid")]
    StableId,
    #[error("qualification owner is invalid")]
    Owner,
    #[error("qualification TTL is invalid")]
    Ttl,
    #[error("qualification generation is invalid")]
    Generation,
    #[error("qualification value is invalid")]
    Value,
}

/// Fixed response categories emitted by a qualification child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationNodeReply {
    Bound {
        node_index: usize,
        bind_addr: SocketAddr,
    },
    Started {
        node_index: usize,
    },
    Initialized,
    Readiness {
        ready: bool,
        reason_code: QualificationReadinessCode,
        node_id: u64,
        term: u64,
        leader_id: Option<u64>,
        configured_voters: usize,
        required_quorum: usize,
        committed_index: Option<u64>,
        applied_index: Option<u64>,
    },
    ProjectedSourceStatus {
        status: QualificationProjectedSvidStatus,
    },
    MaterialStatus {
        status: QualificationTlsMaterialStatus,
    },
    ReauthenticationRequested {
        generation: u64,
    },
    /// Successful authenticated TLS plus exact manifest-bootstrap proof.
    /// This reply does not attest to valid ReadBarrier handler execution.
    DirectedHandshake {
        remote_node_index: usize,
        reauthentication_generation: u64,
    },
    LifecycleMetrics {
        metrics: QualificationConnectionLifecycleMetrics,
    },
    LeaseAcquired {
        fence: u64,
    },
    CompareAndSet {
        applied: bool,
        current_generation: Option<u64>,
    },
    Record {
        present: bool,
        generation: Option<u64>,
        owner_sha256: Option<String>,
        fence: Option<u64>,
        value_sha256: Option<String>,
    },
    Released,
    ShuttingDown,
    Error {
        code: QualificationNodeErrorCode,
    },
}

/// Redaction-safe status from the projected-volume source, kept separate from
/// the TLS controller status so a coherent file publication cannot be
/// mistaken for handshake-ready material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationProjectedSvidStatus {
    pub generation: u64,
    pub availability: QualificationProjectedSvidAvailability,
    pub reason: Option<QualificationProjectedSvidReason>,
}

impl From<ProjectedSvidReloadStatus> for QualificationProjectedSvidStatus {
    fn from(status: ProjectedSvidReloadStatus) -> Self {
        Self {
            generation: status.generation(),
            availability: status.availability().into(),
            reason: status.reason().map(Into::into),
        }
    }
}

/// Closed projected-volume source availability vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationProjectedSvidAvailability {
    Initializing,
    Ready,
    RetainingLastGood,
    Unavailable,
}

impl From<ProjectedSvidAvailability> for QualificationProjectedSvidAvailability {
    fn from(availability: ProjectedSvidAvailability) -> Self {
        match availability {
            ProjectedSvidAvailability::Initializing => Self::Initializing,
            ProjectedSvidAvailability::Ready => Self::Ready,
            ProjectedSvidAvailability::RetainingLastGood => Self::RetainingLastGood,
            ProjectedSvidAvailability::Unavailable => Self::Unavailable,
        }
    }
}

/// Closed, redaction-safe projected-volume reload reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationProjectedSvidReason {
    AwaitingInitialMaterial,
    GenerationUnavailable,
    InvalidGenerationLink,
    GenerationChanged,
    GenerationRetryLimit,
    ReadAttemptTimeout,
    MaterialUnavailable,
    MaterialNotRegular,
    MaterialFileTooLarge,
    TotalMaterialTooLarge,
    CertificateCountExceeded,
    TrustAnchorCountExceeded,
    MalformedCertificate,
    MalformedPrivateKey,
    MalformedTrustBundle,
    InvalidCertificateChain,
    PrivateKeyMismatch,
    ExpiredSvid,
    NotYetValidSvid,
    InvalidWorkloadIdentity,
    LastGoodExpired,
    GenerationExhausted,
}

impl From<ProjectedSvidReloadReason> for QualificationProjectedSvidReason {
    fn from(reason: ProjectedSvidReloadReason) -> Self {
        match reason {
            ProjectedSvidReloadReason::AwaitingInitialMaterial => Self::AwaitingInitialMaterial,
            ProjectedSvidReloadReason::GenerationUnavailable => Self::GenerationUnavailable,
            ProjectedSvidReloadReason::InvalidGenerationLink => Self::InvalidGenerationLink,
            ProjectedSvidReloadReason::GenerationChanged => Self::GenerationChanged,
            ProjectedSvidReloadReason::GenerationRetryLimit => Self::GenerationRetryLimit,
            ProjectedSvidReloadReason::ReadAttemptTimeout => Self::ReadAttemptTimeout,
            ProjectedSvidReloadReason::MaterialUnavailable => Self::MaterialUnavailable,
            ProjectedSvidReloadReason::MaterialNotRegular => Self::MaterialNotRegular,
            ProjectedSvidReloadReason::MaterialFileTooLarge => Self::MaterialFileTooLarge,
            ProjectedSvidReloadReason::TotalMaterialTooLarge => Self::TotalMaterialTooLarge,
            ProjectedSvidReloadReason::CertificateCountExceeded => Self::CertificateCountExceeded,
            ProjectedSvidReloadReason::TrustAnchorCountExceeded => Self::TrustAnchorCountExceeded,
            ProjectedSvidReloadReason::MalformedCertificate => Self::MalformedCertificate,
            ProjectedSvidReloadReason::MalformedPrivateKey => Self::MalformedPrivateKey,
            ProjectedSvidReloadReason::MalformedTrustBundle => Self::MalformedTrustBundle,
            ProjectedSvidReloadReason::InvalidCertificateChain => Self::InvalidCertificateChain,
            ProjectedSvidReloadReason::PrivateKeyMismatch => Self::PrivateKeyMismatch,
            ProjectedSvidReloadReason::ExpiredSvid => Self::ExpiredSvid,
            ProjectedSvidReloadReason::NotYetValidSvid => Self::NotYetValidSvid,
            ProjectedSvidReloadReason::InvalidWorkloadIdentity => Self::InvalidWorkloadIdentity,
            ProjectedSvidReloadReason::LastGoodExpired => Self::LastGoodExpired,
            ProjectedSvidReloadReason::GenerationExhausted => Self::GenerationExhausted,
        }
    }
}

/// Closed durable-readiness result carried across the test control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationReadinessCode {
    Ready,
    NoQuorum,
    TopologyInvalid,
    RecoveryRequired,
}

/// Redaction-safe TLS material state emitted by a qualification child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTlsMaterialStatus {
    pub epoch: u64,
    pub availability: QualificationTlsMaterialAvailability,
    pub reason: Option<QualificationTlsMaterialReason>,
    pub leaf_expires_at: Option<Timestamp>,
    pub certificate_chain_expires_at: Option<Timestamp>,
}

impl From<TlsMaterialStatus> for QualificationTlsMaterialStatus {
    fn from(status: TlsMaterialStatus) -> Self {
        Self {
            epoch: status.epoch().get(),
            availability: status.availability().into(),
            reason: status.reason().map(Into::into),
            leaf_expires_at: status.leaf_expires_at(),
            certificate_chain_expires_at: status.certificate_chain_expires_at(),
        }
    }
}

/// Closed TLS material availability vocabulary for qualification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTlsMaterialAvailability {
    Initializing,
    Ready,
    RetainingLastGood,
    Unavailable,
}

impl From<TlsMaterialAvailability> for QualificationTlsMaterialAvailability {
    fn from(availability: TlsMaterialAvailability) -> Self {
        match availability {
            TlsMaterialAvailability::Initializing => Self::Initializing,
            TlsMaterialAvailability::Ready => Self::Ready,
            TlsMaterialAvailability::RetainingLastGood => Self::RetainingLastGood,
            TlsMaterialAvailability::Unavailable => Self::Unavailable,
        }
    }
}

/// Closed TLS material reason vocabulary for qualification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationTlsMaterialReason {
    AwaitingInitialMaterial,
    MaterialUnavailable,
    SourceClosed,
    MaterialLimitExceeded,
    InvalidCertificateChain,
    PrivateKeyMismatch,
    ExpiredMaterial,
    NotYetValidMaterial,
    InvalidWorkloadIdentity,
    LocalIdentityChanged,
    LastGoodExpired,
    EpochExhausted,
}

impl From<TlsMaterialReloadReason> for QualificationTlsMaterialReason {
    fn from(reason: TlsMaterialReloadReason) -> Self {
        match reason {
            TlsMaterialReloadReason::AwaitingInitialMaterial => Self::AwaitingInitialMaterial,
            TlsMaterialReloadReason::MaterialUnavailable => Self::MaterialUnavailable,
            TlsMaterialReloadReason::SourceClosed => Self::SourceClosed,
            TlsMaterialReloadReason::MaterialLimitExceeded => Self::MaterialLimitExceeded,
            TlsMaterialReloadReason::InvalidCertificateChain => Self::InvalidCertificateChain,
            TlsMaterialReloadReason::PrivateKeyMismatch => Self::PrivateKeyMismatch,
            TlsMaterialReloadReason::ExpiredMaterial => Self::ExpiredMaterial,
            TlsMaterialReloadReason::NotYetValidMaterial => Self::NotYetValidMaterial,
            TlsMaterialReloadReason::InvalidWorkloadIdentity => Self::InvalidWorkloadIdentity,
            TlsMaterialReloadReason::LocalIdentityChanged => Self::LocalIdentityChanged,
            TlsMaterialReloadReason::LastGoodExpired => Self::LastGoodExpired,
            TlsMaterialReloadReason::EpochExhausted => Self::EpochExhausted,
        }
    }
}

/// Fixed-cardinality process-local lifecycle metrics captured at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationConnectionLifecycleMetrics {
    pub retirement_maximum_age: u64,
    pub retirement_local_leaf_expiry: u64,
    pub retirement_peer_leaf_expiry: u64,
    pub retirement_local_certificate_chain_expiry: u64,
    pub retirement_peer_certificate_chain_expiry: u64,
    pub retirement_material_epoch: u64,
    pub retirement_explicit: u64,
    pub active_connections: i64,
    pub draining_connections: i64,
    pub drain_started: u64,
    pub drain_completed: u64,
    pub drain_overruns: u64,
    pub connection_attempts: u64,
    pub connection_successes: u64,
    pub connection_failure_transport: u64,
    pub connection_failure_authentication: u64,
    pub connection_failure_timeout: u64,
    pub connection_failure_protocol: u64,
    pub connection_failure_backend: u64,
    pub reconnect_attempts: u64,
    pub reconnect_failures: u64,
}

/// Low-cardinality child-process error codes; raw backend errors never cross
/// the control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationNodeErrorCode {
    InvalidRequest,
    InitializationUnavailable,
    BackendUnavailable,
    LeaseRejected,
    LeaseHandleDuplicate,
    LeaseHandleMissing,
    MutationRejected,
    TransportUnavailable,
    MaterialUnavailable,
    DirectedHandshakeUnavailable,
}

/// Bounded JSON-line decoding failure.
#[derive(Debug, thiserror::Error)]
pub enum QualificationLineError {
    #[error("qualification control I/O failed")]
    Io(#[from] io::Error),
    #[error("qualification control line exceeds its bound")]
    TooLarge,
    #[error("qualification control line is invalid")]
    Invalid,
}

/// Read and strictly decode one bounded JSON line.
pub fn read_bounded_json_line<R, T>(reader: &mut R) -> Result<Option<T>, QualificationLineError>
where
    R: BufRead,
    T: DeserializeOwned,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len().saturating_add(newline) > QUALIFICATION_MAX_CONTROL_LINE_BYTES {
                reader.consume(newline + 1);
                return Err(QualificationLineError::TooLarge);
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            break;
        }

        if line.len().saturating_add(available.len()) > QUALIFICATION_MAX_CONTROL_LINE_BYTES {
            let consumed = available.len();
            reader.consume(consumed);
            drain_to_newline(reader)?;
            return Err(QualificationLineError::TooLarge);
        }
        line.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }

    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.is_empty() {
        return Err(QualificationLineError::Invalid);
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|_| QualificationLineError::Invalid)
}

fn drain_to_newline<R: BufRead>(reader: &mut R) -> Result<(), io::Error> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            reader.consume(newline + 1);
            return Ok(());
        }
        let consumed = available.len();
        reader.consume(consumed);
    }
}

/// Encode and flush one bounded control response.
pub fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<(), QualificationLineError>
where
    W: Write,
    T: Serialize,
{
    let encoded = serde_json::to_vec(value).map_err(|_| QualificationLineError::Invalid)?;
    if encoded.len() > QUALIFICATION_MAX_CONTROL_LINE_BYTES {
        return Err(QualificationLineError::TooLarge);
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_line_reader_rejects_oversize_before_next_frame() {
        let input = format!(
            "{}\n{{\"command\":\"probe\"}}\n",
            "x".repeat(QUALIFICATION_MAX_CONTROL_LINE_BYTES + 1)
        );
        let mut reader = io::BufReader::new(input.as_bytes());
        let first = read_bounded_json_line::<_, QualificationNodeCommand>(&mut reader);
        assert!(matches!(first, Err(QualificationLineError::TooLarge)));
        let second = read_bounded_json_line::<_, QualificationNodeCommand>(&mut reader)
            .expect("read bounded frame")
            .expect("frame present");
        assert!(matches!(second, QualificationNodeCommand::Probe));
    }

    #[test]
    fn projected_source_status_has_a_distinct_strict_control_frame() {
        let reply = QualificationNodeReply::ProjectedSourceStatus {
            status: QualificationProjectedSvidStatus {
                generation: 7,
                availability: QualificationProjectedSvidAvailability::Ready,
                reason: None,
            },
        };
        let mut encoded = Vec::new();
        write_json_line(&mut encoded, &reply).expect("encode projected status");
        let text = std::str::from_utf8(&encoded).expect("status is JSON");
        assert!(text.contains("projected_source_status"));
        assert!(!text.contains("material_status"));
        assert!(!text.contains("tls.crt"));
        assert!(!text.contains("..data"));

        let mut reader = io::BufReader::new(encoded.as_slice());
        let decoded = read_bounded_json_line::<_, QualificationNodeReply>(&mut reader)
            .expect("decode projected status")
            .expect("projected status frame");
        assert!(matches!(
            decoded,
            QualificationNodeReply::ProjectedSourceStatus {
                status: QualificationProjectedSvidStatus {
                    generation: 7,
                    availability: QualificationProjectedSvidAvailability::Ready,
                    reason: None,
                },
            }
        ));

        let with_unknown = text
            .trim_end()
            .replace("\"reason\":null}", "\"reason\":null,\"path\":\"secret\"}");
        assert!(serde_json::from_str::<QualificationNodeReply>(&with_unknown).is_err());
    }

    #[test]
    fn config_rejects_non_loopback_plaintext_routes() {
        let members = (0..3)
            .map(|node_index| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: 7443 + node_index as u16,
                dial_addr: format!("192.0.2.1:{}", 7443 + node_index as u16)
                    .parse()
                    .expect("test address"),
                tls_identity: format!("spiffe://qualification.invalid/node/{node_index}"),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect();
        let config = QualificationNodeConfig {
            schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            node_index: 0,
            cluster_id: "qualification-cluster".to_owned(),
            configuration_generation: "v1".to_owned(),
            configuration_epoch: 1,
            backend_namespace: "qualification-cluster".to_owned(),
            workload_schedule_sha256: format!("sha256:{}", "a".repeat(64)),
            members,
            workspace_directory: PathBuf::from("/qualification"),
            database_path: PathBuf::from("/qualification/node.sqlite"),
            snapshot_directory: PathBuf::from("/qualification/snapshots"),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
        };
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
    }

    fn valid_config() -> QualificationNodeConfig {
        let members = (0..3)
            .map(|node_index| QualificationMember {
                node_index,
                replica_id: format!("node-{node_index}"),
                endpoint_host: format!("node-{node_index}.qualification.invalid"),
                endpoint_port: 7443 + node_index as u16,
                dial_addr: format!("127.0.0.1:{}", 7443 + node_index as u16)
                    .parse()
                    .expect("test address"),
                tls_identity: format!(
                    "spiffe://qualification.invalid/tenant/test/ns/test/sa/session/nf/test/instance/{node_index}"
                ),
                failure_domain: format!("zone-{node_index}"),
                backing_identity: format!("disk-{node_index}"),
            })
            .collect();
        QualificationNodeConfig {
            schema_version: QUALIFICATION_NODE_SCHEMA_VERSION,
            node_index: 0,
            cluster_id: "qualification-cluster".to_owned(),
            configuration_generation: "v1".to_owned(),
            configuration_epoch: 1,
            backend_namespace: "qualification-cluster".to_owned(),
            workload_schedule_sha256: format!("sha256:{}", "a".repeat(64)),
            members,
            workspace_directory: PathBuf::from("/qualification"),
            database_path: PathBuf::from("/qualification/node.sqlite"),
            snapshot_directory: PathBuf::from("/qualification/snapshots"),
            operation_timeout_millis: QUALIFICATION_OPERATION_TIMEOUT_MILLIS,
            transport: QualificationTransportConfig::LoopbackPlaintextTestOnly,
        }
    }

    #[test]
    fn config_requires_distinct_vote_and_route_identities() {
        let mut config = valid_config();
        assert_eq!(config.validate(), Ok(()));

        config.members[2].dial_addr = config.members[1].dial_addr;
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
        config = valid_config();
        config.members[2].failure_domain = config.members[1].failure_domain.clone();
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
        config = valid_config();
        config.members[2].backing_identity = config.members[1].backing_identity.clone();
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
        config = valid_config();
        config.members[2].endpoint_host = config.members[1].endpoint_host.to_uppercase();
        config.members[2].endpoint_port = config.members[1].endpoint_port;
        assert_eq!(config.validate(), Err(QualificationConfigError::Member));
    }

    #[test]
    fn commands_fail_before_backend_on_every_bounded_field() {
        let valid = QualificationNodeCommand::Acquire {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            owner: "owner-1".to_owned(),
            ttl_millis: 60_000,
        };
        assert_eq!(valid.validate(), Ok(()));

        let oversized_value = QualificationNodeCommand::CompareAndSet {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            expected_generation: None,
            new_generation: 1,
            value: "x".repeat(QUALIFICATION_MAX_VALUE_BYTES + 1),
        };
        assert_eq!(
            oversized_value.validate(),
            Err(QualificationCommandError::Value)
        );
        let oversized_ttl = QualificationNodeCommand::Acquire {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            owner: "owner-1".to_owned(),
            ttl_millis: (opc_session_store::MAX_SESSION_TTL.as_millis() as u64) + 1,
        };
        assert_eq!(
            oversized_ttl.validate(),
            Err(QualificationCommandError::Ttl)
        );
        let invalid_generation = QualificationNodeCommand::CompareAndSet {
            lease_handle: "lease-1".to_owned(),
            stable_id: "session-1".to_owned(),
            expected_generation: Some(1),
            new_generation: 1,
            value: String::new(),
        };
        assert_eq!(
            invalid_generation.validate(),
            Err(QualificationCommandError::Generation)
        );

        assert_eq!(
            QualificationNodeCommand::DirectedHandshake {
                remote_node_index: 5,
            }
            .validate(),
            Err(QualificationCommandError::NodeIndex)
        );
    }

    #[test]
    fn projected_mtls_config_is_bounded_and_redacts_material_paths() {
        let mut config = valid_config();
        config.transport =
            QualificationTransportConfig::ProjectedMtls(QualificationProjectedMtlsConfig {
                projected_volume_root: PathBuf::from("/qualification/projected"),
                certificate_file: PathBuf::from("tls.crt"),
                private_key_file: PathBuf::from("tls.key"),
                trust_bundle_files: vec![PathBuf::from("ca.crt")],
                poll_interval_millis: 100,
                lifecycle: QualificationConnectionLifecycleConfig {
                    maximum_authentication_age_millis: 60_000,
                    rotation_drain_window_millis: 5_000,
                    reconnect_backoff_min_millis: 25,
                    reconnect_backoff_max_millis: 250,
                    rotation_jitter_millis: 1_000,
                },
            });
        assert_eq!(config.validate(), Ok(()));
        let rendered = format!("{config:?}");
        for path in ["/qualification/projected", "tls.crt", "tls.key", "ca.crt"] {
            assert!(!rendered.contains(path));
        }

        let QualificationTransportConfig::ProjectedMtls(projected) = &mut config.transport else {
            panic!("projected transport")
        };
        projected.certificate_file = PathBuf::from("../tls.crt");
        assert_eq!(
            config.validate(),
            Err(QualificationConfigError::Configuration)
        );
    }

    #[test]
    fn config_debug_redacts_paths_routes_and_identities() {
        let config = valid_config();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("qualification.invalid"));
        assert!(!rendered.contains("node.sqlite"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn command_debug_never_exposes_control_fields_or_values() {
        let command = QualificationNodeCommand::CompareAndSet {
            lease_handle: "private-lease".to_owned(),
            stable_id: "private-session".to_owned(),
            expected_generation: Some(1),
            new_generation: 2,
            value: "private-payload".to_owned(),
        };
        let rendered = format!("{command:?}");
        assert!(rendered.contains("CompareAndSet"));
        for secret in [
            "private-lease",
            "private-session",
            "private-payload",
            "expected_generation",
            "new_generation",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn qualification_digests_match_the_independent_checker_domains() {
        assert_eq!(
            qualification_key_sha256("session-a"),
            "sha256:7689422ed433cc7ee36ce78ed7f5b7d30e3c1d39a6a2a2c72df5b7260ffb8c73"
        );
        assert_eq!(
            qualification_owner_sha256("owner-a"),
            "sha256:12a3b845112c3df86bd8f7658d6c9394622c66b4f50f3bdb951b7185b253f4ba"
        );
        assert_eq!(
            qualification_value_sha256(b"value-1"),
            "sha256:eec72ba1a373f38b17ec083cb92efdef4e526cc8d2d987079d3f336a4ec2f7f5"
        );
    }
}
