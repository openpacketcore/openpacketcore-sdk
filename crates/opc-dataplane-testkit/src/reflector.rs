//! Pure GTP-U reflector/forwarder building block.

use std::net::{IpAddr, SocketAddr};

use crate::gtpu::{
    decode_gtpu, encode_echo_response, encode_error_indication, encode_gpdu, GTPU_MSG_ECHO_REQUEST,
    GTPU_MSG_ECHO_RESPONSE, GTPU_MSG_END_MARKER, GTPU_MSG_ERROR_INDICATION, GTPU_MSG_GPDU,
    GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
};
use crate::measurement::echo_tpdu;
use crate::DataplaneTestkitError;

/// Target used by route-mode reflection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteTarget {
    /// Destination UDP socket for the re-encapsulated G-PDU.
    pub destination: SocketAddr,
    /// Receiver TEID to place in the outbound G-PDU.
    pub teid: u32,
}

/// Reflector behavior for valid G-PDUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflectorPolicy {
    /// Swap the inner T-PDU source/destination and return to the configured peer.
    Echo,
    /// Count valid G-PDUs but do not emit return traffic.
    SinkAndCount,
    /// Re-encapsulate unchanged T-PDUs to a supplied next hop.
    Route(RouteTarget),
}

/// Configuration for one TEID-scoped GTP-U reflector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectorConfig {
    /// Local TEID expected on inbound G-PDUs.
    pub local_teid: u32,
    /// Peer TEID used for echo-mode return G-PDUs.
    pub peer_teid: u32,
    /// Peer UDP socket used for echo-mode return G-PDUs.
    pub peer_addr: SocketAddr,
    /// Recovery IE restart counter used in Echo Response.
    pub recovery_counter: u8,
    /// Forwarding policy.
    pub policy: ReflectorPolicy,
}

/// Reflector counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReflectorStats {
    /// Total successfully decoded G-PDUs.
    pub gpdu_received: u64,
    /// G-PDUs reflected or routed.
    pub gpdu_forwarded: u64,
    /// G-PDUs consumed by Sink+count policy.
    pub gpdu_sunk: u64,
    /// Echo Requests answered.
    pub echo_requests_answered: u64,
    /// Error Indications emitted.
    pub error_indications_sent: u64,
    /// Malformed datagrams rejected before action.
    pub malformed_rejected: u64,
}

/// Reason for an emitted reflector datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflectorSendReason {
    /// Echo-mode G-PDU return path.
    ReflectedGpdu,
    /// Route-mode G-PDU forwarding.
    RoutedGpdu,
    /// Echo Response path-management reply.
    EchoResponse,
    /// Error Indication for an unknown TEID.
    ErrorIndication,
}

/// Result of handling one inbound datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflectorAction {
    /// No datagram should be emitted.
    Noop {
        /// Stable redaction-safe reason.
        reason: &'static str,
    },
    /// Send a datagram to `destination`.
    Send {
        /// Destination UDP socket.
        destination: SocketAddr,
        /// Encoded GTP-U datagram.
        packet: Vec<u8>,
        /// Why this datagram is being emitted.
        reason: ReflectorSendReason,
    },
}

/// In-memory GTP-U reflector/forwarder.
#[derive(Debug, Clone)]
pub struct GtpuReflector {
    config: ReflectorConfig,
    stats: ReflectorStats,
    next_error_sequence: u16,
}

impl GtpuReflector {
    /// Create a new reflector.
    #[must_use]
    pub const fn new(config: ReflectorConfig) -> Self {
        Self {
            config,
            stats: ReflectorStats {
                gpdu_received: 0,
                gpdu_forwarded: 0,
                gpdu_sunk: 0,
                echo_requests_answered: 0,
                error_indications_sent: 0,
                malformed_rejected: 0,
            },
            next_error_sequence: 1,
        }
    }

    /// Return current reflector counters.
    #[must_use]
    pub const fn stats(&self) -> ReflectorStats {
        self.stats
    }

    /// Decode and process one inbound GTP-U datagram.
    pub fn handle_datagram(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
    ) -> Result<ReflectorAction, DataplaneTestkitError> {
        let message = match decode_gtpu(datagram) {
            Ok(message) => message,
            Err(err) => {
                self.stats.malformed_rejected = self.stats.malformed_rejected.saturating_add(1);
                return Err(err);
            }
        };

        match message.header.message_type {
            GTPU_MSG_GPDU => {
                if message.header.teid != self.config.local_teid {
                    self.stats.error_indications_sent =
                        self.stats.error_indications_sent.saturating_add(1);
                    let sequence = self.take_error_sequence();
                    let payload = error_indication_payload(message.header.teid, source.ip());
                    let packet = encode_error_indication(sequence, &payload)?;
                    return Ok(ReflectorAction::Send {
                        destination: source,
                        packet,
                        reason: ReflectorSendReason::ErrorIndication,
                    });
                }
                self.stats.gpdu_received = self.stats.gpdu_received.saturating_add(1);
                self.handle_gpdu(message.payload.as_ref())
            }
            GTPU_MSG_ECHO_REQUEST => {
                if message.header.teid != 0 {
                    self.stats.malformed_rejected = self.stats.malformed_rejected.saturating_add(1);
                    return Err(DataplaneTestkitError::invalid_packet(
                        "Echo Request TEID must be zero",
                    ));
                }
                let Some(sequence) = message.header.sequence_number else {
                    self.stats.malformed_rejected = self.stats.malformed_rejected.saturating_add(1);
                    return Err(DataplaneTestkitError::invalid_packet(
                        "Echo Request missing sequence number",
                    ));
                };
                self.stats.echo_requests_answered =
                    self.stats.echo_requests_answered.saturating_add(1);
                let packet = encode_echo_response(sequence, self.config.recovery_counter)?;
                Ok(ReflectorAction::Send {
                    destination: source,
                    packet,
                    reason: ReflectorSendReason::EchoResponse,
                })
            }
            GTPU_MSG_ECHO_RESPONSE => Ok(ReflectorAction::Noop {
                reason: "echo response observed",
            }),
            GTPU_MSG_ERROR_INDICATION => Ok(ReflectorAction::Noop {
                reason: "error indication observed",
            }),
            GTPU_MSG_END_MARKER => Ok(ReflectorAction::Noop {
                reason: "end marker ignored",
            }),
            GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => Ok(ReflectorAction::Noop {
                reason: "supported extension headers notification ignored",
            }),
            _ => {
                self.stats.malformed_rejected = self.stats.malformed_rejected.saturating_add(1);
                Err(DataplaneTestkitError::invalid_packet(
                    "unsupported GTP-U message type",
                ))
            }
        }
    }

    fn handle_gpdu(&mut self, tpdu: &[u8]) -> Result<ReflectorAction, DataplaneTestkitError> {
        match self.config.policy {
            ReflectorPolicy::Echo => {
                let echoed = echo_tpdu(tpdu)?;
                let packet = encode_gpdu(self.config.peer_teid, &echoed)?;
                self.stats.gpdu_forwarded = self.stats.gpdu_forwarded.saturating_add(1);
                Ok(ReflectorAction::Send {
                    destination: self.config.peer_addr,
                    packet,
                    reason: ReflectorSendReason::ReflectedGpdu,
                })
            }
            ReflectorPolicy::SinkAndCount => {
                self.stats.gpdu_sunk = self.stats.gpdu_sunk.saturating_add(1);
                Ok(ReflectorAction::Noop {
                    reason: "G-PDU sunk",
                })
            }
            ReflectorPolicy::Route(target) => {
                let packet = encode_gpdu(target.teid, tpdu)?;
                self.stats.gpdu_forwarded = self.stats.gpdu_forwarded.saturating_add(1);
                Ok(ReflectorAction::Send {
                    destination: target.destination,
                    packet,
                    reason: ReflectorSendReason::RoutedGpdu,
                })
            }
        }
    }

    fn take_error_sequence(&mut self) -> u16 {
        let sequence = self.next_error_sequence;
        self.next_error_sequence = self.next_error_sequence.wrapping_add(1).max(1);
        sequence
    }
}

fn error_indication_payload(offending_teid: u32, peer_ip: IpAddr) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 4 + 1 + 2 + 16);
    // TEID Data I: TV IE type 16 with a fixed 4-octet TEID value.
    payload.push(16);
    payload.extend_from_slice(&offending_teid.to_be_bytes());

    // GTP-U Peer Address: TLV IE type 133 with IPv4 or IPv6 address bytes.
    payload.push(133);
    match peer_ip {
        IpAddr::V4(addr) => {
            payload.extend_from_slice(&4u16.to_be_bytes());
            payload.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            payload.extend_from_slice(&16u16.to_be_bytes());
            payload.extend_from_slice(&addr.octets());
        }
    }
    payload
}
