//! Packet-continuity evidence report and projection helpers.

use std::collections::BTreeMap;
use std::fmt;

use opc_evidence::{has_raw_sensitive_identifier, DataplaneSnapshot};
use serde::{Deserialize, Serialize};

use crate::DataplaneTestkitError;

/// Stable schema version for packet-continuity reports produced by this crate.
pub const PACKET_CONTINUITY_SCHEMA_VERSION: &str =
    "opc-dataplane-testkit/v1/packet-continuity-report";

/// SLO budget used to evaluate packet continuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketContinuityBudget {
    /// Maximum lost packets allowed in the measurement window.
    pub max_lost_packets: u64,
    /// Maximum consecutive missing packet count allowed.
    pub max_consecutive_lost_packets: u64,
    /// Maximum outage duration allowed for a missing-packet run.
    pub outage_budget_ns: u64,
}

impl PacketContinuityBudget {
    /// Strict budget requiring no loss and no missing-packet gaps.
    #[must_use]
    pub const fn zero_loss() -> Self {
        Self {
            max_lost_packets: 0,
            max_consecutive_lost_packets: 0,
            outage_budget_ns: 0,
        }
    }
}

/// Latency summary in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencySummary {
    /// Minimum observed latency in nanoseconds.
    pub min_ns: u64,
    /// Maximum observed latency in nanoseconds.
    pub max_ns: u64,
    /// Integer average observed latency in nanoseconds.
    pub avg_ns: u64,
}

/// Redaction-safe packet continuity report.
///
/// The report intentionally omits raw packets, TEIDs, subscriber identifiers,
/// and inner IP addresses. `Debug` summarizes counters and booleans without
/// rendering the caller-provided flow label.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketContinuityReport {
    /// Schema version.
    pub schema_version: String,
    /// Caller-provided redaction-safe flow label.
    pub flow_id: String,
    /// Measurement window start timestamp in caller-injected nanoseconds.
    pub window_start_ns: u64,
    /// Measurement window end timestamp in caller-injected nanoseconds.
    pub window_end_ns: u64,
    /// T-PDUs handed to the send path.
    pub sent_packets: u64,
    /// Distinct sequence numbers observed on the return path.
    pub received_packets: u64,
    /// Sent minus distinct received.
    pub lost_packets: u64,
    /// Duplicate returned sequence numbers observed.
    pub duplicate_packets: u64,
    /// Returned sequence numbers that arrived after a higher sequence number.
    pub out_of_order_packets: u64,
    /// GTP-U Error Indications observed on the return path.
    pub gtpu_error_indications: u64,
    /// Maximum consecutive missing sequence numbers.
    pub max_consecutive_lost_packets: u64,
    /// Longest missing-run duration in caller-injected nanoseconds.
    pub max_gap_duration_ns: u64,
    /// Latency summary, absent when no packets returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencySummary>,
    /// SLO budget used for this evaluation.
    pub budget: PacketContinuityBudget,
    /// At least one sent packet returned through the datapath.
    pub forwarding_proven: bool,
    /// Loss and continuity gap were within budget.
    pub packet_continuity_proven: bool,
}

impl fmt::Debug for PacketContinuityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketContinuityReport")
            .field("schema_version", &self.schema_version)
            .field("flow_id", &"<redacted>")
            .field("window_start_ns", &self.window_start_ns)
            .field("window_end_ns", &self.window_end_ns)
            .field("sent_packets", &self.sent_packets)
            .field("received_packets", &self.received_packets)
            .field("lost_packets", &self.lost_packets)
            .field("duplicate_packets", &self.duplicate_packets)
            .field("out_of_order_packets", &self.out_of_order_packets)
            .field("gtpu_error_indications", &self.gtpu_error_indications)
            .field(
                "max_consecutive_lost_packets",
                &self.max_consecutive_lost_packets,
            )
            .field("max_gap_duration_ns", &self.max_gap_duration_ns)
            .field("latency", &self.latency)
            .field("budget", &self.budget)
            .field("forwarding_proven", &self.forwarding_proven)
            .field("packet_continuity_proven", &self.packet_continuity_proven)
            .finish()
    }
}

impl PacketContinuityReport {
    /// Validate that report string fields are redaction-safe.
    pub fn validate_redaction(&self) -> Result<(), DataplaneTestkitError> {
        if let Some(reason) = has_raw_sensitive_identifier(&self.flow_id) {
            return Err(DataplaneTestkitError::RedactionViolation(format!(
                "flow_id {reason}"
            )));
        }
        Ok(())
    }

    /// Project continuity proof into the existing dataplane snapshot evidence
    /// consumed by traffic-readiness and HA gates.
    #[must_use]
    pub fn to_dataplane_snapshot(&self, kernel_state_reconciled: bool) -> DataplaneSnapshot {
        DataplaneSnapshot {
            session_count: 0,
            bearer_count: 0,
            installed_object_count: 0,
            highest_fence: None,
            highest_generation: None,
            stale_mutation_counters: BTreeMap::new(),
            sessions: Vec::new(),
            bearers: Vec::new(),
            forwarding_proven: Some(self.forwarding_proven),
            kernel_state_reconciled: Some(kernel_state_reconciled),
            packet_continuity_proven: Some(self.packet_continuity_proven),
        }
    }
}
