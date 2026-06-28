//! Generic dataplane snapshot vocabulary for packet-core evidence.
//!
//! These structs describe installed state and proof status. They deliberately
//! do not perform live forwarding checks or convert intent into readiness.

use std::collections::BTreeMap;

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
