//! Explicit configuration for separate-process storage measurements.

use opc_session_store::SessionPersistenceMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Application time used by the original 50,000-session workload.
/// Wall-clock operation deadlines and TLS validity still use real time.
pub const QUALIFICATION_ISOLATED_SCALE_UNIX_SECONDS: i64 = 1_900_000_000;

/// Closed persistence choice for an explicitly configured measurement fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationIsolatedPersistence {
    /// Public majority-durable acknowledgements.
    Durable,
    /// Public Async acknowledgements with background persistence.
    Async,
}

impl QualificationIsolatedPersistence {
    /// The public store construction policy named by this configuration.
    pub const fn store_mode(self) -> SessionPersistenceMode {
        match self {
            Self::Durable => SessionPersistenceMode::Durable,
            Self::Async => SessionPersistenceMode::Async,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Async => "async",
        }
    }
}

/// Distinguish full-cardinality measurements from short boundary controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationIsolatedScaleWorkload {
    /// Original 50,000 sessions and 1,010,000 exact workload outcomes.
    Original,
    /// Functional construction, operation, shutdown and reconstruction control.
    BoundaryControl,
}

/// Opt-in configuration; omission preserves every legacy Durable node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationIsolatedScaleConfig {
    /// Immutable persistence policy for all three configured voters.
    pub persistence: QualificationIsolatedPersistence,
    /// Workload identity; boundary controls cannot attest original scale.
    pub workload: QualificationIsolatedScaleWorkload,
}

impl QualificationIsolatedScaleConfig {
    /// Bind mode, logical clock and exact workload to a distinct schedule.
    pub fn schedule_sha256(self) -> String {
        let workload = match self.workload {
            QualificationIsolatedScaleWorkload::Original => {
                "sessions=50000;preload=50000;steady=500x1800;burst=1000x60;epochs=8"
            }
            QualificationIsolatedScaleWorkload::BoundaryControl => "boundary-control",
        };
        let descriptor = format!(
            "opc-session-isolated-scale/v1;voters=3;mode={};clock={QUALIFICATION_ISOLATED_SCALE_UNIX_SECONDS};{workload}",
            self.persistence.label(),
        );
        format!("sha256:{:x}", Sha256::digest(descriptor.as_bytes()))
    }
}

/// Mode-aware quorum proof and passive local progress from one scale voter.
/// Persistence counters alone never grant application or recovery authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationIsolatedScaleReadiness {
    /// Result of the public mode-aware quorum and local-application probe.
    pub ready: bool,
    /// Construction policy bound into the immutable node configuration.
    pub persistence: QualificationIsolatedPersistence,
    /// Local canonical node identity.
    pub node_id: u64,
    /// Current elected leader, if observed.
    pub leader_id: Option<u64>,
    /// Term observed with the leader identity, for exact maintenance selection.
    pub term: u64,
    /// Exact sorted voter identities admitted by this node configuration.
    pub configured_voter_ids: Vec<u64>,
    /// Committed barrier supplied by this probe.
    pub committed_index: Option<u64>,
    /// Passive local applied frontier after the probe.
    pub applied_index: Option<u64>,
    /// Whether the local consensus engine is running.
    pub engine_running: bool,
    /// Whether persistence has recorded a terminal storage failure.
    pub storage_failed: bool,
    /// Whether the native storage lifecycle is Running.
    pub storage_running: bool,
    /// A distinct terminal error from the asynchronous background writer.
    pub background_failed: bool,
    /// Whether the asynchronous persistence backlog is saturated.
    pub saturated: bool,
    /// Whether an Async root has completed the live-quorum recovery fence.
    pub async_active: bool,
    /// Completed automatic consensus snapshot publications.
    pub completed_snapshot_count: u64,
    /// Whether an existing Async root still requires a surviving live quorum.
    pub awaiting_live_quorum: bool,
    /// Currently detached Async generation, if any.
    pub captured_generation: Option<u64>,
    /// Most recently selected Async generation, if any.
    pub completed_generation: Option<u64>,
    /// Passive elapsed Async persistence lag, if applicable.
    pub persistence_lag_millis: Option<u64>,
}
