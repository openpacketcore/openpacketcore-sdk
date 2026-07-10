//! Pure GTP-U reflector/forwarder building block.

use std::net::{IpAddr, SocketAddr};

use crate::gtpu::{
    decode_gtpu, encode_echo_response, encode_error_indication, encode_gpdu, GTPU_MSG_ECHO_REQUEST,
    GTPU_MSG_ECHO_RESPONSE, GTPU_MSG_END_MARKER, GTPU_MSG_ERROR_INDICATION, GTPU_MSG_GPDU,
    GTPU_MSG_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
};
use crate::measurement::echo_tpdu;
use crate::DataplaneTestkitError;

/// Hard upper bound for one reflector's configured session table.
pub const MAX_REFLECTOR_SESSIONS: usize = 4_096;

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

/// One uplink-to-downlink GTP-U session mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectorSession {
    /// Local PGW/UPF-side TEID expected on the uplink G-PDU.
    pub local_teid: u32,
    /// Peer ePDG/gateway-side TEID stamped on the reflected downlink G-PDU.
    pub peer_teid: u32,
    /// Peer UDP socket receiving the reflected downlink G-PDU.
    pub peer_addr: SocketAddr,
}

impl From<ReflectorConfig> for ReflectorSession {
    fn from(config: ReflectorConfig) -> Self {
        Self {
            local_teid: config.local_teid,
            peer_teid: config.peer_teid,
            peer_addr: config.peer_addr,
        }
    }
}

/// Configuration for a bounded multi-session GTP-U reflector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiSessionReflectorConfig {
    /// Maximum concurrently configured session mappings.
    pub max_sessions: usize,
    /// Recovery IE restart counter used in Echo Response.
    pub recovery_counter: u8,
    /// Forwarding policy shared by configured sessions.
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
    sessions: ReflectorSessions,
    max_sessions: usize,
    recovery_counter: u8,
    policy: ReflectorPolicy,
    stats: ReflectorStats,
    next_error_sequence: u16,
}

#[derive(Debug, Clone)]
enum ReflectorSessions {
    Single(Option<ReflectorSession>),
    Multiple(Vec<ReflectorSession>),
}

impl ReflectorSessions {
    fn find(&self, local_teid: u32) -> Option<ReflectorSession> {
        match self {
            Self::Single(session) => session.filter(|session| session.local_teid == local_teid),
            Self::Multiple(sessions) => sessions
                .iter()
                .copied()
                .find(|session| session.local_teid == local_teid),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Single(session) => usize::from(session.is_some()),
            Self::Multiple(sessions) => sessions.len(),
        }
    }

    fn push(&mut self, session: ReflectorSession) {
        match self {
            Self::Single(slot) => *slot = Some(session),
            Self::Multiple(sessions) => sessions.push(session),
        }
    }

    fn remove(&mut self, local_teid: u32) -> Option<ReflectorSession> {
        match self {
            Self::Single(session) => {
                if session.is_some_and(|session| session.local_teid == local_teid) {
                    session.take()
                } else {
                    None
                }
            }
            Self::Multiple(sessions) => {
                let index = sessions
                    .iter()
                    .position(|session| session.local_teid == local_teid)?;
                Some(sessions.swap_remove(index))
            }
        }
    }
}

impl GtpuReflector {
    /// Create a new reflector.
    #[must_use]
    pub const fn new(config: ReflectorConfig) -> Self {
        Self {
            sessions: ReflectorSessions::Single(Some(ReflectorSession {
                local_teid: config.local_teid,
                peer_teid: config.peer_teid,
                peer_addr: config.peer_addr,
            })),
            max_sessions: 1,
            recovery_counter: config.recovery_counter,
            policy: config.policy,
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

    /// Create an empty bounded multi-session reflector.
    ///
    /// # Errors
    ///
    /// Returns [`DataplaneTestkitError::InvalidReflectorCapacity`] when the
    /// configured capacity is zero or above [`MAX_REFLECTOR_SESSIONS`].
    pub fn new_multi(config: MultiSessionReflectorConfig) -> Result<Self, DataplaneTestkitError> {
        if config.max_sessions == 0 || config.max_sessions > MAX_REFLECTOR_SESSIONS {
            return Err(DataplaneTestkitError::InvalidReflectorCapacity);
        }
        Ok(Self {
            sessions: ReflectorSessions::Multiple(Vec::new()),
            max_sessions: config.max_sessions,
            recovery_counter: config.recovery_counter,
            policy: config.policy,
            stats: ReflectorStats::default(),
            next_error_sequence: 1,
        })
    }

    /// Create a multi-session reflector and register an initial mapping set.
    ///
    /// # Errors
    ///
    /// Returns the same capacity/session errors as [`Self::new_multi`] and
    /// [`Self::register_session`]. No partially constructed reflector escapes
    /// on failure.
    pub fn with_sessions(
        config: MultiSessionReflectorConfig,
        sessions: impl IntoIterator<Item = ReflectorSession>,
    ) -> Result<Self, DataplaneTestkitError> {
        let mut reflector = Self::new_multi(config)?;
        for session in sessions {
            reflector.register_session(session)?;
        }
        Ok(reflector)
    }

    /// Register one uplink TEID to downlink peer mapping.
    ///
    /// Re-registering the exact mapping is idempotent and returns `false`.
    /// Reusing a local TEID with different peer metadata fails closed.
    ///
    /// # Errors
    ///
    /// Returns an invalid-session, conflicting-session, or capacity error.
    pub fn register_session(
        &mut self,
        session: ReflectorSession,
    ) -> Result<bool, DataplaneTestkitError> {
        validate_session(session)?;
        if let Some(existing) = self.sessions.find(session.local_teid) {
            return if existing == session {
                Ok(false)
            } else {
                Err(DataplaneTestkitError::ReflectorSessionConflict)
            };
        }
        if self.sessions.len() >= self.max_sessions {
            return Err(DataplaneTestkitError::ReflectorSessionCapacityExceeded);
        }
        self.sessions.push(session);
        Ok(true)
    }

    /// Remove a mapping by its local uplink TEID.
    ///
    /// Returns the removed mapping, or `None` when it was not configured.
    pub fn remove_session(&mut self, local_teid: u32) -> Option<ReflectorSession> {
        self.sessions.remove(local_teid)
    }

    /// Return the number of currently configured session mappings.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
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
                let Some(session) = self.sessions.find(message.header.teid) else {
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
                };
                self.stats.gpdu_received = self.stats.gpdu_received.saturating_add(1);
                self.handle_gpdu(session, message.payload.as_ref())
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
                let packet = encode_echo_response(sequence, self.recovery_counter)?;
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

    fn handle_gpdu(
        &mut self,
        session: ReflectorSession,
        tpdu: &[u8],
    ) -> Result<ReflectorAction, DataplaneTestkitError> {
        match self.policy {
            ReflectorPolicy::Echo => {
                let echoed = echo_tpdu(tpdu)?;
                let packet = encode_gpdu(session.peer_teid, &echoed)?;
                self.stats.gpdu_forwarded = self.stats.gpdu_forwarded.saturating_add(1);
                Ok(ReflectorAction::Send {
                    destination: session.peer_addr,
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

fn validate_session(session: ReflectorSession) -> Result<(), DataplaneTestkitError> {
    if session.local_teid == 0 || session.peer_teid == 0 || session.peer_addr.port() == 0 {
        return Err(DataplaneTestkitError::InvalidReflectorSession);
    }
    Ok(())
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
