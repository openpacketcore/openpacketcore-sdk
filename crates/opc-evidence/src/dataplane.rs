//! Generic dataplane snapshot vocabulary for packet-core evidence.
//!
//! These structs describe installed state and proof status. They deliberately
//! do not perform live forwarding checks or convert intent into readiness.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Per-session dataplane snapshot summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataplaneSessionSummary {
    /// Redaction-safe session reference or digest.
    pub session_ref: String,
    /// Number of bearers associated with the session.
    pub bearer_count: u64,
    /// Number of dataplane objects installed for the session.
    pub installed_object_count: u64,
    /// Highest generation observed for the session.
    pub highest_generation: Option<u64>,
    /// Highest fence observed for the session.
    pub highest_fence: Option<u64>,
}

/// Per-bearer dataplane snapshot summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataplaneBearerSummary {
    /// Redaction-safe bearer reference or digest.
    pub bearer_ref: String,
    /// Redaction-safe parent session reference or digest.
    pub session_ref: String,
    /// Number of dataplane objects installed for the bearer.
    pub installed_object_count: u64,
    /// Highest generation observed for the bearer.
    pub highest_generation: Option<u64>,
    /// Highest fence observed for the bearer.
    pub highest_fence: Option<u64>,
}

/// Generic packet-core dataplane snapshot evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataplaneSnapshot {
    /// Number of sessions represented by this snapshot.
    pub session_count: u64,
    /// Number of bearers represented by this snapshot.
    pub bearer_count: u64,
    /// Total installed dataplane object count.
    pub installed_object_count: u64,
    /// Highest fence observed by the dataplane.
    pub highest_fence: Option<u64>,
    /// Highest generation observed by the dataplane.
    pub highest_generation: Option<u64>,
    /// Counters for stale or fenced mutation attempts rejected by the dataplane.
    pub stale_mutation_counters: BTreeMap<String, u64>,
    /// Sorted per-session summaries.
    #[serde(default)]
    pub sessions: Vec<DataplaneSessionSummary>,
    /// Sorted per-bearer summaries.
    #[serde(default)]
    pub bearers: Vec<DataplaneBearerSummary>,
    /// Whether live forwarding has been proven by the producing system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarding_proven: Option<bool>,
    /// Whether kernel or fast-path state was reconciled with intended state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_state_reconciled: Option<bool>,
    /// Whether packet continuity has been proven by the producing system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_continuity_proven: Option<bool>,
}

impl DataplaneSnapshot {
    /// Return a copy with per-session and per-bearer summaries in stable order.
    pub fn canonicalized(mut self) -> Self {
        self.sessions
            .sort_by(|left, right| left.session_ref.cmp(&right.session_ref));
        self.bearers.sort_by(|left, right| {
            left.session_ref
                .cmp(&right.session_ref)
                .then_with(|| left.bearer_ref.cmp(&right.bearer_ref))
        });
        self
    }

    /// Validate that evidence is strong enough for a traffic-readiness claim.
    pub fn validate_traffic_readiness_claim(&self) -> Result<(), DataplaneEvidenceError> {
        validate_proof_field(
            "traffic readiness",
            "forwarding_proven",
            self.forwarding_proven,
        )?;
        validate_proof_field(
            "traffic readiness",
            "kernel_state_reconciled",
            self.kernel_state_reconciled,
        )?;
        validate_proof_field(
            "traffic readiness",
            "packet_continuity_proven",
            self.packet_continuity_proven,
        )
    }

    /// Project missing or false traffic-readiness proof into stable blocker codes.
    ///
    /// Reasons are returned in SDK priority order: forwarding proof first,
    /// kernel reconciliation second, and packet continuity last. Both `None`
    /// and `Some(false)` are treated as not proven.
    #[must_use]
    pub fn traffic_readiness_blockers(&self) -> Vec<DataplaneTrafficBlockReasonCode> {
        let mut blockers = Vec::with_capacity(3);
        if self.forwarding_proven != Some(true) {
            blockers.push(DataplaneTrafficBlockReasonCode::ForwardingNotProven);
        }
        if self.kernel_state_reconciled != Some(true) {
            blockers.push(DataplaneTrafficBlockReasonCode::KernelStateNotReconciled);
        }
        if self.packet_continuity_proven != Some(true) {
            blockers.push(DataplaneTrafficBlockReasonCode::PacketContinuityNotProven);
        }
        blockers
    }

    /// Return the highest-priority traffic-readiness blocker, if any.
    #[must_use]
    pub fn first_traffic_readiness_blocker(&self) -> Option<DataplaneTrafficBlockReasonCode> {
        if self.forwarding_proven != Some(true) {
            Some(DataplaneTrafficBlockReasonCode::ForwardingNotProven)
        } else if self.kernel_state_reconciled != Some(true) {
            Some(DataplaneTrafficBlockReasonCode::KernelStateNotReconciled)
        } else if self.packet_continuity_proven != Some(true) {
            Some(DataplaneTrafficBlockReasonCode::PacketContinuityNotProven)
        } else {
            None
        }
    }

    /// Whether the snapshot has any traffic-readiness proof blocker.
    #[must_use]
    pub fn blocks_traffic_readiness(&self) -> bool {
        self.first_traffic_readiness_blocker().is_some()
    }

    /// Validate that evidence is strong enough for a packet-continuity claim.
    pub fn validate_packet_continuity_claim(&self) -> Result<(), DataplaneEvidenceError> {
        validate_proof_field(
            "packet continuity",
            "forwarding_proven",
            self.forwarding_proven,
        )?;
        validate_proof_field(
            "packet continuity",
            "kernel_state_reconciled",
            self.kernel_state_reconciled,
        )?;
        validate_proof_field(
            "packet continuity",
            "packet_continuity_proven",
            self.packet_continuity_proven,
        )
    }

    /// Build a redaction-safe one-line summary for evidence bundles.
    pub fn redaction_safe_summary(&self) -> String {
        format!(
            "dataplane snapshot: sessions={}, bearers={}, installed_objects={}, highest_generation={:?}, highest_fence={:?}, stale_mutation_counter_keys={}, forwarding_proven={:?}, kernel_state_reconciled={:?}, packet_continuity_proven={:?}",
            self.session_count,
            self.bearer_count,
            self.installed_object_count,
            self.highest_generation,
            self.highest_fence,
            self.stale_mutation_counters.len(),
            self.forwarding_proven,
            self.kernel_state_reconciled,
            self.packet_continuity_proven
        )
    }
}

/// Stable machine-readable reason for blocking traffic-readiness claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataplaneTrafficBlockReasonCode {
    /// Live forwarding has not been proven.
    ForwardingNotProven,
    /// Kernel or fast-path state has not been reconciled with intended state.
    KernelStateNotReconciled,
    /// Packet continuity has not been proven.
    PacketContinuityNotProven,
}

impl DataplaneTrafficBlockReasonCode {
    /// Return the stable snake_case reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForwardingNotProven => "forwarding_not_proven",
            Self::KernelStateNotReconciled => "kernel_state_not_reconciled",
            Self::PacketContinuityNotProven => "packet_continuity_not_proven",
        }
    }

    /// Return the proof field that produced this blocker.
    #[must_use]
    pub const fn proof_field(self) -> &'static str {
        match self {
            Self::ForwardingNotProven => "forwarding_proven",
            Self::KernelStateNotReconciled => "kernel_state_reconciled",
            Self::PacketContinuityNotProven => "packet_continuity_proven",
        }
    }

    /// Return a redaction-safe operator message for this blocker.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ForwardingNotProven => "traffic readiness blocked: forwarding is not proven",
            Self::KernelStateNotReconciled => {
                "traffic readiness blocked: kernel state is not reconciled"
            }
            Self::PacketContinuityNotProven => {
                "traffic readiness blocked: packet continuity is not proven"
            }
        }
    }
}

impl fmt::Display for DataplaneTrafficBlockReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when dataplane evidence cannot support a claim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DataplaneEvidenceError {
    /// A required proof field was absent.
    #[error("{claim} claim requires proof field {field}")]
    MissingProofField {
        /// Claim being validated.
        claim: &'static str,
        /// Missing field.
        field: &'static str,
    },
    /// A required proof field was present but false.
    #[error("{claim} claim requires {field}=true")]
    FalseProofField {
        /// Claim being validated.
        claim: &'static str,
        /// False field.
        field: &'static str,
    },
}

impl DataplaneEvidenceError {
    /// Return the traffic blocker reason associated with this proof failure.
    #[must_use]
    pub fn traffic_block_reason_code(&self) -> Option<DataplaneTrafficBlockReasonCode> {
        match self {
            Self::MissingProofField { field, .. } | Self::FalseProofField { field, .. } => {
                traffic_block_reason_for_field(field)
            }
        }
    }
}

/// Fluent assertions for dataplane snapshot evidence.
pub struct DataplaneSnapshotAsserter<'a> {
    snapshot: &'a DataplaneSnapshot,
}

impl<'a> DataplaneSnapshotAsserter<'a> {
    /// Create an asserter for one dataplane snapshot.
    pub fn new(snapshot: &'a DataplaneSnapshot) -> Self {
        Self { snapshot }
    }

    /// Assert that a traffic-readiness claim is allowed by proof fields.
    pub fn traffic_readiness_claim_allowed(self) -> Self {
        assert_traffic_readiness_claim_allowed(self.snapshot);
        self
    }

    /// Assert that a packet-continuity claim is allowed by proof fields.
    pub fn packet_continuity_claim_allowed(self) -> Self {
        assert_packet_continuity_claim_allowed(self.snapshot);
        self
    }
}

/// Assert that dataplane evidence allows a traffic-readiness claim.
pub fn assert_traffic_readiness_claim_allowed(snapshot: &DataplaneSnapshot) {
    snapshot
        .validate_traffic_readiness_claim()
        .unwrap_or_else(|err| panic!("traffic-readiness claim rejected: {err}"));
}

/// Assert that dataplane evidence allows a packet-continuity claim.
pub fn assert_packet_continuity_claim_allowed(snapshot: &DataplaneSnapshot) {
    snapshot
        .validate_packet_continuity_claim()
        .unwrap_or_else(|err| panic!("packet-continuity claim rejected: {err}"));
}

fn validate_proof_field(
    claim: &'static str,
    field: &'static str,
    value: Option<bool>,
) -> Result<(), DataplaneEvidenceError> {
    match value {
        Some(true) => Ok(()),
        Some(false) => Err(DataplaneEvidenceError::FalseProofField { claim, field }),
        None => Err(DataplaneEvidenceError::MissingProofField { claim, field }),
    }
}

fn traffic_block_reason_for_field(field: &str) -> Option<DataplaneTrafficBlockReasonCode> {
    match field {
        "forwarding_proven" => Some(DataplaneTrafficBlockReasonCode::ForwardingNotProven),
        "kernel_state_reconciled" => {
            Some(DataplaneTrafficBlockReasonCode::KernelStateNotReconciled)
        }
        "packet_continuity_proven" => {
            Some(DataplaneTrafficBlockReasonCode::PacketContinuityNotProven)
        }
        _ => None,
    }
}
