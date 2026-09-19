//! Bounded receive demultiplexing and response plans for a shared GTP-U socket.
//!
//! These values describe received UDP datagrams, not authenticated peers,
//! installed tunnels, restart authority, or permission to change a session.
//! Peer admission, aggregate rate limits and unknown-tunnel lookup remain
//! caller policy. A response plan consumes its receive event and is bound to
//! the exact socket that received it. No response is sent automatically.

#[cfg(all(test, target_os = "linux"))]
mod native_tests;

#[cfg(any(test, target_os = "linux"))]
use std::sync::Arc;
use std::{fmt, net::SocketAddrV4, num::NonZeroU32};

use bytes::Bytes;
use opc_proto_gtpu::{
    GtpuControlMessage, GtpuEchoResponse, GtpuErrorIndication, GtpuExtensionHeaderTypeList,
    GtpuSupportedExtensionHeadersNotification, GTPU_MESSAGE_ECHO_REQUEST, GTPU_MESSAGE_G_PDU,
};
#[cfg(any(test, target_os = "linux"))]
use opc_proto_gtpu::{GtpuExtensionHeaderRecipient, GtpuMessage};
use opc_protocol::EncodeContext;
#[cfg(any(test, target_os = "linux"))]
use opc_protocol::{BorrowDecode, DecodeContext, UnknownIePolicy, ValidationLevel};

use crate::{DownlinkOuterProvenance, GTPU_PORT};

/// Maximum UDP payload admitted by this IPv4 socket profile.
///
/// This is the IPv4/UDP envelope limit, not a path-MTU or fragmentation claim.
pub const GTPU_CONTROL_MAX_DATAGRAM: usize = 65_507;

/// Backend-neutral nonblocking access to one shared GTP-U receive queue.
///
/// A single consumer demultiplexes controls and G-PDUs. An implementation
/// must preserve the original socket's tuple and ingress provenance and
/// reject response plans from other socket instances. This port provides
/// no installed-tunnel or peer-admission authority.
pub trait GtpuControlPort: fmt::Debug + Send + Sync {
    /// Receive at most one complete datagram, bounded by `maximum_bytes`.
    /// `Ok(None)` means no datagram is currently queued.
    ///
    /// # Errors
    /// Refuses invalid limits, truncation or an unverifiable socket binding.
    fn try_receive_datagram(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<GtpuControlDatagram>, GtpuControlPortError>;

    /// Consume and send one response plan through its receiving socket.
    /// The result counts bytes accepted by the local kernel, not peer receipt.
    ///
    /// # Errors
    /// Refuses a foreign plan, lost binding, or a nonblocking send failure.
    fn send_control_response(
        &self,
        plan: GtpuControlSendPlan,
    ) -> Result<usize, GtpuControlPortError>;
}

/// Stable failures without peer, packet, tunnel or deployment values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GtpuControlPortError {
    /// The managed attachment/backend no longer admits this port instance.
    #[error("GTP-U control port is unavailable")]
    Unavailable,
    /// Attachment mutation currently holds the port's serialization boundary.
    #[error("GTP-U control port is busy")]
    Busy,
    /// Caller-selected receive or response limits are invalid.
    #[error("invalid GTP-U control port limits")]
    InvalidLimits,
    /// The datagram does not authorize the requested response procedure.
    #[error("GTP-U control response has no matching receive event")]
    WrongProcedure,
    /// A response exceeds the caller's per-datagram byte/amplification cap.
    #[error("GTP-U control response budget exceeded")]
    ResponseBudgetExceeded,
    /// A plan belongs to a different socket instance.
    #[error("GTP-U control response socket mismatch")]
    SocketMismatch,
    /// A peer or local UDP tuple cannot be used for this response.
    #[error("invalid GTP-U control response tuple")]
    InvalidTuple,
    /// A typed response could not be encoded within this profile.
    #[error("GTP-U control response encoding refused")]
    Encoding,
    /// Socket I/O or exact binding readback failed.
    #[error("GTP-U control socket operation failed ({kind:?})")]
    Io {
        /// Error class only; the original error text is discarded.
        kind: std::io::ErrorKind,
    },
}

impl From<std::io::Error> for GtpuControlPortError {
    fn from(error: std::io::Error) -> Self {
        Self::Io { kind: error.kind() }
    }
}

/// Explicit caller policy for one response, excluding IP/UDP headers.
///
/// A cap is not peer authentication or an aggregate rate limiter. Ratios use
/// integer byte counts; no rounding or floating-point arithmetic is involved.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuControlResponseBudget {
    maximum_bytes: usize,
    maximum_amplification: u8,
}

impl fmt::Debug for GtpuControlResponseBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GtpuControlResponseBudget(<redacted>)")
    }
}

impl GtpuControlResponseBudget {
    /// Select positive limits, with an SDK ceiling of 16 times amplification
    /// and the IPv4 UDP payload ceiling. Neither ceiling is a 3GPP policy.
    ///
    /// # Errors
    /// Returns [`GtpuControlPortError::InvalidLimits`] outside these bounds.
    pub fn new(
        maximum_bytes: usize,
        maximum_amplification: u8,
    ) -> Result<Self, GtpuControlPortError> {
        if !(1..=GTPU_CONTROL_MAX_DATAGRAM).contains(&maximum_bytes)
            || !(1..=16).contains(&maximum_amplification)
        {
            return Err(GtpuControlPortError::InvalidLimits);
        }
        Ok(Self {
            maximum_bytes,
            maximum_amplification,
        })
    }

    fn admits(self, received: usize, response: usize) -> bool {
        response <= self.maximum_bytes
            && received
                .checked_mul(usize::from(self.maximum_amplification))
                .is_some_and(|limit| response <= limit)
    }
}

/// Classification of one complete UDP payload from the shared receive queue.
///
/// Only `Gpdu` may be offered to the existing reassembly consumer. Even that
/// case is framing evidence only: the consumer must still validate its exact
/// installed selectors, endpoint binding and current authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GtpuControlDatagramKind {
    /// One of the existing typed control messages, fully decoded.
    Control,
    /// A structurally complete G-PDU with no unsupported required extension.
    Gpdu,
    /// A required extension cannot be understood by an endpoint.
    UnsupportedRequiredExtension,
    /// A structurally complete but unmodelled GTP-U message type.
    Unmodelled,
    /// Malformed framing or a malformed typed control procedure; no reply.
    Malformed,
}

/// One received datagram with exact socket provenance and bounded payload.
///
/// Not `Clone`: response planning consumes this event. Explicit getters are
/// for packet processing and admission policy, not logging. `Debug` redacts
/// the packet, addresses, TEID, sequence, ports and interface identity.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::control_port::GtpuControlDatagram;
/// fn replay(event: GtpuControlDatagram) { let _ = event.clone(); }
/// ```
pub struct GtpuControlDatagram {
    bytes: Bytes,
    provenance: DownlinkOuterProvenance,
    #[cfg(any(test, target_os = "linux"))]
    socket_identity: Arc<()>,
    kind: GtpuControlDatagramKind,
    control: Option<GtpuControlMessage>,
    message_type: Option<u8>,
    teid: Option<NonZeroU32>,
}

impl fmt::Debug for GtpuControlDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuControlDatagram")
            .field("kind", &self.kind)
            .field("received_length", &self.bytes.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl GtpuControlDatagram {
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn received(
        bytes: Bytes,
        provenance: DownlinkOuterProvenance,
        socket_identity: Arc<()>,
    ) -> Self {
        let mut result = Self {
            bytes,
            provenance,
            socket_identity,
            kind: GtpuControlDatagramKind::Malformed,
            control: None,
            message_type: None,
            teid: None,
        };
        // The network receiver ignores spare bits while retaining exact
        // framing and bounded walks. The shared typed codec applies its own
        // procedure checks, independently of this structural decoder.
        let ctx = DecodeContext {
            max_message_len: GTPU_CONTROL_MAX_DATAGRAM,
            max_ies: 256,
            max_depth: 256,
            unknown_ie_policy: UnknownIePolicy::Preserve,
            validation_level: ValidationLevel::Structural,
            ..DecodeContext::default()
        };
        let Ok((tail, message)) = GtpuMessage::decode(&result.bytes, ctx) else {
            return result;
        };
        if !tail.is_empty() || message.header.version != 1 || !message.header.protocol_type {
            return result;
        }
        result.message_type = Some(message.header.message_type);
        result.teid = NonZeroU32::new(message.header.teid);
        match message.first_unsupported_required_extension(GtpuExtensionHeaderRecipient::Endpoint) {
            Ok(Some(_)) => {
                result.kind = GtpuControlDatagramKind::UnsupportedRequiredExtension;
                return result;
            }
            Err(_) => return result,
            Ok(None) => {}
        }
        if message.header.message_type == GTPU_MESSAGE_G_PDU {
            result.kind = GtpuControlDatagramKind::Gpdu;
        } else {
            match GtpuControlMessage::from_message(&message, ctx) {
                Ok(control) => {
                    result.control = Some(control);
                    result.kind = GtpuControlDatagramKind::Control;
                }
                Err(error)
                    if matches!(
                        error.code(),
                        opc_proto_gtpu::GtpuControlCodecErrorCode::UnsupportedMessageType { .. }
                    ) =>
                {
                    result.kind = GtpuControlDatagramKind::Unmodelled;
                }
                Err(_) => {}
            }
        }
        result
    }

    /// Disposition of this complete UDP datagram.
    #[must_use]
    pub const fn kind(&self) -> GtpuControlDatagramKind {
        self.kind
    }

    /// Exact received UDP payload length, excluding IP/UDP headers.
    #[must_use]
    pub fn received_length(&self) -> usize {
        self.bytes.len()
    }

    /// Exact peer/local/ingress metadata established by the socket.
    #[must_use]
    pub const fn provenance(&self) -> &DownlinkOuterProvenance {
        &self.provenance
    }

    /// Local destination tuple. This socket profile binds UDP/2152.
    #[must_use]
    pub fn local(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.provenance.local_address(), GTPU_PORT)
    }

    /// Peer source tuple, including a dynamic source port.
    #[must_use]
    pub fn peer(&self) -> SocketAddrV4 {
        SocketAddrV4::new(
            self.provenance.peer_address(),
            self.provenance.source_port(),
        )
    }

    /// Type from a structurally complete GTP-U header, if one was admitted.
    #[must_use]
    pub const fn message_type(&self) -> Option<u8> {
        self.message_type
    }

    /// Meaningful sequence metadata from a fully validated typed control.
    /// Received Recovery values never acquire restart-authority semantics.
    #[must_use]
    pub fn sequence_number(&self) -> Option<u16> {
        self.control
            .as_ref()
            .and_then(GtpuControlMessage::sequence_number)
    }

    /// Decoded typed control, when its entire procedure was accepted.
    #[must_use]
    pub const fn control(&self) -> Option<&GtpuControlMessage> {
        self.control.as_ref()
    }

    /// Original untrusted datagram. Inspect `kind` before choosing a consumer;
    /// malformed or required-extension events must never be decapsulated.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Plan one canonical Echo Response to the exact request tuple, retaining
    /// the request sequence and transmitting Recovery zero.
    ///
    /// # Errors
    /// Refuses other procedures, invalid tuples or the explicit byte budget.
    pub fn echo_response(
        self,
        budget: GtpuControlResponseBudget,
    ) -> Result<GtpuControlSendPlan, GtpuControlPortError> {
        let Some(GtpuControlMessage::EchoRequest(request)) = self.control.as_ref() else {
            return Err(GtpuControlPortError::WrongProcedure);
        };
        let message = GtpuControlMessage::EchoResponse(GtpuEchoResponse::for_request(request));
        let peer = self.peer();
        self.response(message, peer, budget)
    }

    /// Plan an Error Indication after the caller has established that this
    /// G-PDU has no tunnel. Includes the triggering UDP source-port extension.
    ///
    /// This method does not perform a tunnel lookup. The destination is the
    /// triggering peer's service port, not its possibly dynamic source port.
    ///
    /// # Errors
    /// Refuses non-G-PDU events, TEID zero, invalid tuples or an exceeded cap.
    pub fn unknown_tunnel_error(
        self,
        budget: GtpuControlResponseBudget,
    ) -> Result<GtpuControlSendPlan, GtpuControlPortError> {
        if self.kind != GtpuControlDatagramKind::Gpdu {
            return Err(GtpuControlPortError::WrongProcedure);
        }
        let teid = self.teid.ok_or(GtpuControlPortError::WrongProcedure)?;
        let error = GtpuErrorIndication::new(teid, (*self.local().ip()).into())
            .with_triggering_udp_source_port(self.peer().port())
            .map_err(|_| GtpuControlPortError::Encoding)?;
        let peer = SocketAddrV4::new(*self.peer().ip(), GTPU_PORT);
        self.response(GtpuControlMessage::ErrorIndication(error), peer, budget)
    }

    /// Plan a bounded notification only for a request/G-PDU carrying an
    /// unsupported required extension. The caller supplies the supported list.
    ///
    /// # Errors
    /// Refuses unrelated/malformed events, invalid tuples or an exceeded cap.
    pub fn extension_notification(
        self,
        supported: GtpuExtensionHeaderTypeList,
        budget: GtpuControlResponseBudget,
    ) -> Result<GtpuControlSendPlan, GtpuControlPortError> {
        if self.kind != GtpuControlDatagramKind::UnsupportedRequiredExtension
            || !matches!(
                self.message_type,
                Some(GTPU_MESSAGE_ECHO_REQUEST | GTPU_MESSAGE_G_PDU)
            )
        {
            return Err(GtpuControlPortError::WrongProcedure);
        }
        let peer = SocketAddrV4::new(*self.peer().ip(), GTPU_PORT);
        self.response(
            GtpuControlMessage::SupportedExtensionHeadersNotification(
                GtpuSupportedExtensionHeadersNotification::new(supported),
            ),
            peer,
            budget,
        )
    }

    fn response(
        self,
        message: GtpuControlMessage,
        peer: SocketAddrV4,
        budget: GtpuControlResponseBudget,
    ) -> Result<GtpuControlSendPlan, GtpuControlPortError> {
        let source = self.local();
        if peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
            || peer.ip().is_broadcast()
            || source.ip().is_multicast()
            || source.ip().is_broadcast()
        {
            return Err(GtpuControlPortError::InvalidTuple);
        }
        let bytes = message
            .to_bytes(EncodeContext::default())
            .map_err(|_| GtpuControlPortError::Encoding)?;
        if !budget.admits(self.bytes.len(), bytes.len()) {
            return Err(GtpuControlPortError::ResponseBudgetExceeded);
        }
        Ok(GtpuControlSendPlan {
            bytes,
            source,
            peer,
            #[cfg(any(test, target_os = "linux"))]
            socket_identity: self.socket_identity,
            received_length: self.bytes.len(),
        })
    }
}

/// Affine response plan bound to one exact receiving socket.
///
/// Sending consumes the plan even if I/O fails; retries require a new received
/// event. Successful UDP send means local kernel acceptance, not peer receipt.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::control_port::GtpuControlSendPlan;
/// fn replay(plan: GtpuControlSendPlan) { let _ = plan.clone(); }
/// ```
pub struct GtpuControlSendPlan {
    pub(crate) bytes: Bytes,
    pub(crate) source: SocketAddrV4,
    pub(crate) peer: SocketAddrV4,
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) socket_identity: Arc<()>,
    received_length: usize,
}

impl GtpuControlSendPlan {
    /// Exact source tuple selected by the message-specific response rule.
    #[must_use]
    pub const fn source(&self) -> SocketAddrV4 {
        self.source
    }
    /// Exact destination tuple selected by that rule.
    #[must_use]
    pub const fn destination(&self) -> SocketAddrV4 {
        self.peer
    }
    /// Encoded UDP payload length to charge to the caller's aggregate limiter.
    #[must_use]
    pub fn response_length(&self) -> usize {
        self.bytes.len()
    }
    /// Received payload length used for the amplification bound.
    #[must_use]
    pub const fn received_length(&self) -> usize {
        self.received_length
    }
}

impl fmt::Debug for GtpuControlSendPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuControlSendPlan")
            .field("received_length", &self.received_length)
            .field("response_length", &self.bytes.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_proto_gtpu::GtpuExtensionHeaderType;
    use std::net::Ipv4Addr;

    const ECHO: &[u8] = &[0x32, 1, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
    const GPDU: &[u8] = &[0x30, 255, 0, 1, 1, 2, 3, 4, 0x45];

    fn receive(bytes: &[u8], port: u16) -> GtpuControlDatagram {
        GtpuControlDatagram::received(
            Bytes::copy_from_slice(bytes),
            DownlinkOuterProvenance::new(
                Ipv4Addr::new(127, 0, 0, 3),
                Ipv4Addr::new(127, 0, 0, 2),
                1,
                port,
            )
            .unwrap(),
            Arc::new(()),
        )
    }
    fn budget() -> GtpuControlResponseBudget {
        GtpuControlResponseBudget::new(1024, 4).unwrap()
    }

    #[test]
    fn control_echo_uses_received_dynamic_tuple_sequence_and_zero_recovery() {
        for port in [1, 2152, 49152, 65535] {
            let event = receive(ECHO, port);
            assert_eq!(event.kind(), GtpuControlDatagramKind::Control);
            assert_eq!(event.message_type(), Some(1));
            assert_eq!(event.sequence_number(), Some(0x1234));
            let identity = Arc::clone(&event.socket_identity);
            let plan = event.echo_response(budget()).unwrap();
            assert!(Arc::ptr_eq(&identity, &plan.socket_identity));
            assert_eq!(
                plan.source(),
                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 2152)
            );
            assert_eq!(
                plan.destination(),
                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), port)
            );
            assert_eq!(
                &plan.bytes[..],
                &[0x32, 2, 0, 6, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 14, 0]
            );
            assert_eq!(plan.received_length(), 12);
            assert_eq!(plan.response_length(), 14);
        }
        assert_eq!(
            receive(ECHO, 0).echo_response(budget()).unwrap_err(),
            GtpuControlPortError::InvalidTuple
        );
    }

    #[test]
    fn control_error_indication_uses_service_port_and_exact_trigger_fields() {
        let event = receive(GPDU, 49152);
        assert_eq!(event.kind(), GtpuControlDatagramKind::Gpdu);
        assert_eq!(event.sequence_number(), None);
        let plan = event.unknown_tunnel_error(budget()).unwrap();
        assert_eq!(plan.destination().port(), 2152);
        assert_eq!(
            &plan.bytes[..],
            &[
                0x36, 26, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, 0xc0, 0, 0, 16, 1, 2, 3, 4, 133, 0,
                4, 127, 0, 0, 2,
            ]
        );
        let mut zero = GPDU.to_vec();
        zero[4..8].fill(0);
        assert_eq!(
            receive(&zero, 49152)
                .unknown_tunnel_error(budget())
                .unwrap_err(),
            GtpuControlPortError::WrongProcedure
        );
    }

    #[test]
    fn control_required_extension_does_not_enter_gpdu_or_echo_paths() {
        // Type 0x80 is currently unmodelled and requires endpoint comprehension.
        let required = [0x34, 255, 0, 9, 1, 2, 3, 4, 0, 0, 0, 0x80, 1, 0, 0, 0, 0x45];
        let event = receive(&required, 49152);
        assert_eq!(
            event.kind(),
            GtpuControlDatagramKind::UnsupportedRequiredExtension
        );
        let supported =
            GtpuExtensionHeaderTypeList::new([GtpuExtensionHeaderType::new(0x40)]).unwrap();
        let plan = event.extension_notification(supported, budget()).unwrap();
        assert_eq!(plan.destination().port(), 2152);
        assert_eq!(
            &plan.bytes[..],
            &[0x32, 31, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 141, 1, 0x40]
        );
        assert!(receive(&required, 49152)
            .unknown_tunnel_error(budget())
            .is_err());
        assert!(receive(&required, 49152).echo_response(budget()).is_err());
        let mut optional = required;
        optional[11] = 0x20;
        assert_eq!(
            receive(&optional, 49152).kind(),
            GtpuControlDatagramKind::Gpdu
        );
    }

    #[test]
    fn control_malformed_lengths_and_procedures_never_plan_a_response() {
        for length in 0..ECHO.len() {
            let event = receive(&ECHO[..length], 49152);
            assert_eq!(event.kind(), GtpuControlDatagramKind::Malformed);
            assert!(event.echo_response(budget()).is_err());
        }
        let mut tail = ECHO.to_vec();
        tail.push(0);
        assert_eq!(
            receive(&tail, 49152).kind(),
            GtpuControlDatagramKind::Malformed
        );
        for index in [0, 4, 6] {
            let mut changed = ECHO.to_vec();
            changed[index] ^= if index == 0 { 2 } else { 1 };
            assert!(receive(&changed, 49152).echo_response(budget()).is_err());
        }
        let mut response = ECHO.to_vec();
        response[1] = 2;
        assert!(receive(&response, 49152).echo_response(budget()).is_err());
        let mut unmodelled = GPDU.to_vec();
        unmodelled[1] = 99;
        assert_eq!(
            receive(&unmodelled, 49152).kind(),
            GtpuControlDatagramKind::Unmodelled
        );
        assert!(receive(&unmodelled, 49152)
            .unknown_tunnel_error(budget())
            .is_err());
    }

    #[test]
    fn control_budgets_bound_both_bytes_and_amplification() {
        for (bytes, ratio) in [(0, 1), (65_508, 1), (1, 0), (1, 17), (usize::MAX, 255)] {
            assert_eq!(
                GtpuControlResponseBudget::new(bytes, ratio).unwrap_err(),
                GtpuControlPortError::InvalidLimits
            );
        }
        for bytes in 1..14 {
            assert_eq!(
                receive(ECHO, 49152)
                    .echo_response(GtpuControlResponseBudget::new(bytes, 2).unwrap())
                    .unwrap_err(),
                GtpuControlPortError::ResponseBudgetExceeded
            );
        }
        assert_eq!(
            receive(ECHO, 49152)
                .echo_response(GtpuControlResponseBudget::new(14, 1).unwrap())
                .unwrap_err(),
            GtpuControlPortError::ResponseBudgetExceeded
        );
        assert!(receive(ECHO, 49152)
            .echo_response(GtpuControlResponseBudget::new(14, 2).unwrap())
            .is_ok());
    }

    #[test]
    fn control_debug_redacts_all_values() {
        let event = receive(ECHO, 49152);
        let debug = format!("{event:?}");
        let plan = event.echo_response(budget()).unwrap();
        let debug = debug + &format!("{plan:?}");
        for value in ["127.0.0.2", "127.0.0.3", "49152", "2152", "4660", "1234"] {
            assert!(!debug.contains(value), "{debug}");
        }
        assert!(debug.contains("<redacted>"));
        assert_eq!(
            format!("{:?}", budget()),
            "GtpuControlResponseBudget(<redacted>)"
        );
    }

    #[test]
    fn control_echo_preserves_complete_source_port_domain_and_sequence_boundaries() {
        for port in 0..=u16::MAX {
            for sequence in [0_u16, 1, 32768, u16::MAX] {
                let mut request = ECHO.to_vec();
                request[8..10].copy_from_slice(&sequence.to_be_bytes());
                let result = receive(&request, port).echo_response(budget());
                if port == 0 {
                    assert_eq!(result.unwrap_err(), GtpuControlPortError::InvalidTuple);
                } else {
                    let plan = result.unwrap();
                    let [hi, lo] = sequence.to_be_bytes();
                    assert_eq!(plan.destination().port(), port);
                    assert_eq!(
                        plan.bytes.as_ref(),
                        &[0x32, 2, 0, 6, 0, 0, 0, 0, hi, lo, 0, 0, 14, 0]
                    );
                }
            }
        }
    }

    #[test]
    fn control_receiver_ignored_fields_and_recovery_never_gain_reply_authority() {
        // The PN/reserved bits and unused N-PDU octet do not prevent Echo.
        for flags in [0x32, 0x33, 0x3a, 0x3b] {
            for unused in [0, 1, 255] {
                let mut request = ECHO.to_vec();
                request[0] = flags;
                request[10] = unused;
                let plan = receive(&request, 49152).echo_response(budget()).unwrap();
                assert_eq!(
                    plan.bytes.as_ref(),
                    &[0x32, 2, 0, 6, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 14, 0]
                );
            }
        }
        for recovery in 0..=u8::MAX {
            let response = [0x32, 2, 0, 6, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 14, recovery];
            let event = receive(&response, 49152);
            assert_eq!(event.kind(), GtpuControlDatagramKind::Control);
            assert_eq!(event.sequence_number(), Some(0x1234));
            assert!(matches!(
                event.control(),
                Some(GtpuControlMessage::EchoResponse(_))
            ));
            assert_eq!(
                event.echo_response(budget()).unwrap_err(),
                GtpuControlPortError::WrongProcedure
            );
            assert!(receive(&response, 49152)
                .unknown_tunnel_error(budget())
                .is_err());
        }
    }

    #[test]
    fn control_endpoint_comprehension_domain_preserves_optional_bytes() {
        for extension in 1..=u8::MAX {
            let packet = [
                0x34, 255, 0, 9, 1, 2, 3, 4, 0, 0, 0, extension, 1, 0, 0, 0, 0x45,
            ];
            let event = receive(&packet, 49152);
            // Endpoint comprehension bits (TS 29.281 5.2.1); the shared
            // codec additionally implements PSC (0x85) and UDP Port (0x40).
            let required = extension >= 0x80 && extension != 0x85;
            assert_eq!(event.bytes(), packet);
            assert_eq!(
                event.kind(),
                if required {
                    GtpuControlDatagramKind::UnsupportedRequiredExtension
                } else {
                    GtpuControlDatagramKind::Gpdu
                }
            );
            let result = event
                .extension_notification(GtpuExtensionHeaderTypeList::new([]).unwrap(), budget());
            if required {
                assert_eq!(
                    result.unwrap().bytes.as_ref(),
                    &[0x32, 31, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 141, 0]
                );
            } else {
                assert_eq!(result.unwrap_err(), GtpuControlPortError::WrongProcedure);
            }
        }
    }

    #[test]
    fn control_independent_receive_and_echo_response_corpus() {
        fn hex(value: &str) -> Vec<u8> {
            let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
            assert!(remainder.is_empty());
            pairs
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        }
        let mut count = 0;
        for row in include_str!("../tests/fixtures/control_port.tsv")
            .lines()
            .filter(|row| !row.starts_with('#'))
        {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 4);
            let wire = hex(fields[2]);
            let event = receive(&wire, 49152);
            let kind = match fields[1] {
                "C" => GtpuControlDatagramKind::Control,
                "G" => GtpuControlDatagramKind::Gpdu,
                "R" => GtpuControlDatagramKind::UnsupportedRequiredExtension,
                "U" => GtpuControlDatagramKind::Unmodelled,
                "M" => GtpuControlDatagramKind::Malformed,
                _ => panic!("unknown corpus disposition"),
            };
            assert_eq!(event.kind(), kind, "{}", fields[0]);
            let response = event.echo_response(budget());
            if fields[3] == "-" {
                assert_eq!(
                    response.unwrap_err(),
                    GtpuControlPortError::WrongProcedure,
                    "{}",
                    fields[0]
                );
            } else {
                assert_eq!(
                    response.unwrap().bytes.as_ref(),
                    hex(fields[3]),
                    "{}",
                    fields[0]
                );
            }
            count += 1;
        }
        assert_eq!(count, 1204);
    }
}
