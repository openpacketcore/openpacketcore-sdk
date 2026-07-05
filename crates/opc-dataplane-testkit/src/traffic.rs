//! Deterministic traffic generation and continuity observation.

use std::collections::{BTreeMap, BTreeSet};

use crate::evidence::{
    LatencySummary, PacketContinuityBudget, PacketContinuityReport,
    PACKET_CONTINUITY_SCHEMA_VERSION,
};
use crate::gtpu::{
    decode_gtpu, validate_error_indication_ies, GTPU_MSG_ECHO_RESPONSE, GTPU_MSG_END_MARKER,
    GTPU_MSG_ERROR_INDICATION, GTPU_MSG_GPDU, GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
};
use crate::measurement::{build_measurement_tpdu, decode_measurement_tpdu, InnerIpFlow};
use crate::DataplaneTestkitError;

/// Deterministic packet generation plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficPlan {
    /// Number of packets to generate.
    pub packet_count: u64,
    /// Target send rate in packets per second.
    pub target_rate_pps: u64,
    /// Timestamp for the first packet in caller-injected nanoseconds.
    pub first_send_timestamp_ns: u64,
}

impl TrafficPlan {
    /// Return the interval between generated packet timestamps.
    pub fn interval_ns(self) -> Result<u64, DataplaneTestkitError> {
        if self.target_rate_pps == 0 {
            return Err(DataplaneTestkitError::invalid_packet(
                "target rate must be non-zero",
            ));
        }
        let interval = 1_000_000_000u64 / self.target_rate_pps;
        if interval == 0 {
            return Err(DataplaneTestkitError::invalid_packet(
                "target rate exceeds nanosecond timestamp resolution",
            ));
        }
        Ok(interval)
    }
}

/// One generated measurement packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedPacket {
    /// Measurement sequence number.
    pub sequence: u64,
    /// Caller-injected send timestamp.
    pub send_timestamp_ns: u64,
    /// Raw inner T-PDU bytes.
    pub tpdu: Vec<u8>,
}

/// Deterministic sequenced T-PDU generator.
#[derive(Debug, Clone, Default)]
pub struct TrafficEngine {
    next_sequence: u64,
}

impl TrafficEngine {
    /// Create a traffic engine starting at sequence zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { next_sequence: 0 }
    }

    /// Create a traffic engine with an explicit first sequence.
    #[must_use]
    pub const fn with_first_sequence(first_sequence: u64) -> Self {
        Self {
            next_sequence: first_sequence,
        }
    }

    /// Generate a deterministic batch of measurement T-PDUs.
    pub fn generate(
        &mut self,
        flow: InnerIpFlow,
        plan: TrafficPlan,
    ) -> Result<Vec<GeneratedPacket>, DataplaneTestkitError> {
        let interval_ns = plan.interval_ns()?;
        let capacity =
            usize::try_from(plan.packet_count).map_err(|_| DataplaneTestkitError::Overflow {
                field: "packet_count",
            })?;
        let mut packets = Vec::with_capacity(capacity);
        for offset in 0..plan.packet_count {
            let sequence = self.next_sequence;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(DataplaneTestkitError::Overflow { field: "sequence" })?;
            let offset_ns =
                offset
                    .checked_mul(interval_ns)
                    .ok_or(DataplaneTestkitError::Overflow {
                        field: "send_timestamp_ns",
                    })?;
            let send_timestamp_ns = plan.first_send_timestamp_ns.checked_add(offset_ns).ok_or(
                DataplaneTestkitError::Overflow {
                    field: "send_timestamp_ns",
                },
            )?;
            let tpdu = build_measurement_tpdu(flow, sequence, send_timestamp_ns)?;
            packets.push(GeneratedPacket {
                sequence,
                send_timestamp_ns,
                tpdu,
            });
        }
        Ok(packets)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceivedPacket {
    latency_ns: u64,
}

/// Outcome from recording an inbound GTP-U return-path datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuReturnDatagramOutcome {
    /// A G-PDU carried a measurement T-PDU and was recorded.
    MeasurementTpdu,
    /// A path-management Echo Response was observed.
    EchoResponse,
    /// A GTP-U Error Indication was observed and counted as a teardown signal.
    ErrorIndication,
    /// A supported control-plane message was decoded and ignored.
    Ignored {
        /// GTP-U message type.
        message_type: u8,
    },
}

/// Observes sent and returned measurement T-PDUs and produces continuity evidence.
#[derive(Debug, Clone, Default)]
pub struct ContinuityObserver {
    sent: BTreeMap<u64, u64>,
    received: BTreeMap<u64, ReceivedPacket>,
    duplicate_packets: u64,
    out_of_order_packets: u64,
    gtpu_error_indications: u64,
    highest_received_sequence: Option<u64>,
}

impl ContinuityObserver {
    /// Create an empty observer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sent: BTreeMap::new(),
            received: BTreeMap::new(),
            duplicate_packets: 0,
            out_of_order_packets: 0,
            gtpu_error_indications: 0,
            highest_received_sequence: None,
        }
    }

    /// Record a generated packet as sent.
    pub fn record_sent(&mut self, packet: &GeneratedPacket) {
        self.sent.insert(packet.sequence, packet.send_timestamp_ns);
    }

    /// Record a returned T-PDU at a caller-injected timestamp.
    pub fn record_received_tpdu(
        &mut self,
        return_timestamp_ns: u64,
        tpdu: &[u8],
    ) -> Result<(), DataplaneTestkitError> {
        let decoded = decode_measurement_tpdu(tpdu)?;
        let sequence = decoded.measurement.sequence;
        let Some(send_timestamp_ns) = self.sent.get(&sequence).copied() else {
            return Err(DataplaneTestkitError::invalid_packet(
                "received sequence was not sent",
            ));
        };
        let latency_ns = return_timestamp_ns
            .checked_sub(send_timestamp_ns)
            .ok_or(DataplaneTestkitError::TimestampReversed)?;

        if self.received.contains_key(&sequence) {
            self.duplicate_packets = self.duplicate_packets.saturating_add(1);
            return Ok(());
        }

        if self
            .highest_received_sequence
            .is_some_and(|highest| sequence < highest)
        {
            self.out_of_order_packets = self.out_of_order_packets.saturating_add(1);
        }
        self.highest_received_sequence = Some(
            self.highest_received_sequence
                .map_or(sequence, |highest| highest.max(sequence)),
        );
        self.received
            .insert(sequence, ReceivedPacket { latency_ns });
        Ok(())
    }

    /// Decode a returned GTP-U datagram and record any measurement or teardown signal.
    pub fn record_return_gtpu_datagram(
        &mut self,
        return_timestamp_ns: u64,
        datagram: &[u8],
    ) -> Result<GtpuReturnDatagramOutcome, DataplaneTestkitError> {
        let message = decode_gtpu(datagram)?;
        match message.header.message_type {
            GTPU_MSG_GPDU => {
                self.record_received_tpdu(return_timestamp_ns, message.payload.as_ref())?;
                Ok(GtpuReturnDatagramOutcome::MeasurementTpdu)
            }
            GTPU_MSG_ERROR_INDICATION => {
                validate_error_indication_ies(message.payload.as_ref())?;
                self.gtpu_error_indications = self.gtpu_error_indications.saturating_add(1);
                Ok(GtpuReturnDatagramOutcome::ErrorIndication)
            }
            GTPU_MSG_ECHO_RESPONSE => Ok(GtpuReturnDatagramOutcome::EchoResponse),
            GTPU_MSG_END_MARKER | GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => {
                Ok(GtpuReturnDatagramOutcome::Ignored {
                    message_type: message.header.message_type,
                })
            }
            _ => Err(DataplaneTestkitError::invalid_packet(
                "unsupported GTP-U return message type",
            )),
        }
    }

    /// Build a packet-continuity report.
    pub fn report(
        &self,
        flow_id: impl Into<String>,
        window_start_ns: u64,
        window_end_ns: u64,
        budget: PacketContinuityBudget,
    ) -> PacketContinuityReport {
        let sent_packets = self.sent.len() as u64;
        let received_packets = self.received.len() as u64;
        let lost_packets = sent_packets.saturating_sub(received_packets);
        let (max_consecutive_lost_packets, max_gap_duration_ns) = self.gap_summary(window_end_ns);
        let forwarding_proven = received_packets > 0;
        let packet_continuity_proven = lost_packets <= budget.max_lost_packets
            && max_consecutive_lost_packets <= budget.max_consecutive_lost_packets
            && max_gap_duration_ns <= budget.outage_budget_ns
            && self.gtpu_error_indications == 0;

        PacketContinuityReport {
            schema_version: PACKET_CONTINUITY_SCHEMA_VERSION.to_string(),
            flow_id: flow_id.into(),
            window_start_ns,
            window_end_ns,
            sent_packets,
            received_packets,
            lost_packets,
            duplicate_packets: self.duplicate_packets,
            out_of_order_packets: self.out_of_order_packets,
            gtpu_error_indications: self.gtpu_error_indications,
            max_consecutive_lost_packets,
            max_gap_duration_ns,
            latency: self.latency_summary(),
            budget,
            forwarding_proven,
            packet_continuity_proven,
        }
    }

    fn latency_summary(&self) -> Option<LatencySummary> {
        let mut values = self
            .received
            .values()
            .map(|packet| packet.latency_ns)
            .peekable();
        values.peek()?;

        let mut min_ns = u64::MAX;
        let mut max_ns = 0u64;
        let mut sum = 0u128;
        let mut count = 0u128;
        for latency in values {
            min_ns = min_ns.min(latency);
            max_ns = max_ns.max(latency);
            sum = sum.saturating_add(u128::from(latency));
            count = count.saturating_add(1);
        }
        let avg_ns = (sum / count) as u64;
        Some(LatencySummary {
            min_ns,
            max_ns,
            avg_ns,
        })
    }

    fn gap_summary(&self, window_end_ns: u64) -> (u64, u64) {
        if self.sent.is_empty() {
            return (0, 0);
        }
        let received: BTreeSet<u64> = self.received.keys().copied().collect();
        let mut current_count = 0u64;
        let mut current_start_ts = 0u64;
        let mut max_count = 0u64;
        let mut max_duration = 0u64;

        for (sequence, send_ts) in &self.sent {
            if received.contains(sequence) {
                if current_count > 0 {
                    let duration = send_ts.saturating_sub(current_start_ts);
                    max_count = max_count.max(current_count);
                    max_duration = max_duration.max(duration);
                    current_count = 0;
                }
                continue;
            }

            if current_count == 0 {
                current_start_ts = *send_ts;
            }
            current_count = current_count.saturating_add(1);
        }

        if current_count > 0 {
            let duration = window_end_ns.saturating_sub(current_start_ts);
            max_count = max_count.max(current_count);
            max_duration = max_duration.max(duration);
        }

        (max_count, max_duration)
    }
}
