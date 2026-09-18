//! Experimental N3 tunnel intent and G-PDU packet boundary.
//!
//! These are software packet helpers, not installed forwarding state. They
//! confer no peer authentication, selector authority, generation receipt,
//! readiness, or protection-policy decision. All shipped backends report
//! [`crate::GtpuCapability::Missing`] for N3 forwarding. Runtime integration
//! must use the existing opaque selector-authority ports and the separately
//! tracked backend-neutral control-datagram work.
//!
//! Received uplink TNL information names the UPF destination. Locally supplied
//! downlink TNL information names the N3IWF receive endpoint. Neither is a
//! Linux GTP netdevice role or evidence that an address is bound locally.
//!
//! Packet reception reuses `opc-proto-gtpu` framing, extension comprehension,
//! and the QFI/RQI/PPI PSC subset. One complete G-PDU, a nonzero TEID, exactly
//! one PSC of the caller's expected direction, and a nonempty opaque T-PDU
//! are required. The last requirement is this SDK forwarding-input contract;
//! a generic PSC-only GTP-U message can still be valid. Optional unknown
//! extensions may precede or follow the PSC. Required unknown extensions and
//! unmodelled PSC conditional fields are refused. The header reserved bit is
//! ignored on receive as TS 29.281 section 5.1 requires.
//!
//! `DecodeContext` byte, extension-count and depth limits remain enforced at
//! every validation level. Duplicate/unknown policies cannot weaken this
//! endpoint profile. Decoding allocates no memory; its allocation budget is
//! advisory. The on-wire version is checked regardless of the version hint.
//! The borrowed view retains the original datagram, including optional
//! extensions; it does not re-encode a received message.
//!
//! Uplink construction uses the shared PSC and GTP-U encoders, emits one PSC
//! first, clears sequence/N-PDU/reserved fields, and preflights length before
//! writing. It does not construct UDP/IP headers, controls, or checksums.
//! `Debug` and errors contain no endpoint, TEID, mark, QoS, or packet values.

use std::{fmt, net::IpAddr};

use bytes::BytesMut;
use opc_proto_gtpu::{
    GtpuExtensionChain, GtpuHeader, GtpuMessage, PduSessionContainer,
    GTPU_EXT_PDU_SESSION_CONTAINER,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext,
    UnknownIePolicy, ValidationLevel,
};
use thiserror::Error;

use crate::{GtpBearerMark, Teid};

/// N3 function role, distinct from the Linux `GtpRole` netdevice setting.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N3ForwardingRole {
    /// Uplink toward a UPF and downlink toward the NWu-facing endpoint.
    N3iwf,
}

/// Direction relative to the core network, supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N3Direction {
    /// Toward the UPF; PDU Session Information type 1.
    Uplink,
    /// Toward the N3IWF; PDU Session Information type 0.
    Downlink,
}

/// Stable, value-free refusal at the N3 packet/intent boundary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum N3PacketError {
    /// The caller's byte cap was exceeded.
    #[error("N3 message exceeds byte limit")]
    MessageTooLarge,
    /// GTP-U framing is invalid, truncated, or followed by trailing bytes.
    #[error("invalid N3 datagram framing")]
    InvalidFraming,
    /// The extension count or depth exceeds the caller's bound.
    #[error("N3 extension limit exceeded")]
    ExtensionLimitExceeded,
    /// A required extension is not understood by this endpoint.
    #[error("unsupported required N3 extension")]
    UnsupportedExtension,
    /// No PDU Session Container is present.
    #[error("N3 PDU Session Container missing")]
    MissingPsc,
    /// More than one PDU Session Container is present.
    #[error("duplicate N3 PDU Session Container")]
    DuplicatePsc,
    /// The PSC is malformed or outside the shared codec's supported subset.
    #[error("invalid or unsupported N3 PDU Session Container")]
    InvalidPsc,
    /// The PSC's direction disagrees with the caller's expected direction.
    #[error("N3 direction mismatch")]
    DirectionMismatch,
    /// This is a control message rather than a G-PDU.
    #[error("N3 user packet requires G-PDU")]
    NotGpdu,
    /// A user packet has the reserved zero TEID.
    #[error("N3 user packet requires nonzero TEID")]
    ZeroTeid,
    /// This forwarding-input contract requires a nonempty inner payload.
    #[error("N3 user packet requires inner payload")]
    EmptyPayload,
    /// A length cannot be represented by the GTP-U length field or buffer.
    #[error("N3 packet length overflow")]
    LengthOverflow,
    /// The QFI cannot be represented in six bits.
    #[error("N3 QFI out of range")]
    InvalidQfi,
    /// An endpoint is unspecified, multicast, or IPv4 limited broadcast.
    #[error("N3 tunnel requires a concrete unicast address")]
    InvalidAddress,
}

/// Checked six-bit QFI; zero is representable and is not silently remapped.
///
/// @spec 3GPP TS38415 R18 5.5.3.3
/// @req REQ-3GPP-TS38415-R18-5.5.3.3-001
/// @conformance qfi-subset
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct N3Qfi(u8);

impl N3Qfi {
    /// Check representability without truncation or policy selection.
    ///
    /// # Errors
    /// Returns [`N3PacketError::InvalidQfi`] above 63.
    pub const fn new(value: u8) -> Result<Self, N3PacketError> {
        if value <= 63 {
            Ok(Self(value))
        } else {
            Err(N3PacketError::InvalidQfi)
        }
    }

    /// Explicit raw access for protocol processing; do not log this value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for N3Qfi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3Qfi(<redacted>)")
    }
}

fn check_address(address: IpAddr) -> Result<(), N3PacketError> {
    if address.is_unspecified()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(value) if value.is_broadcast())
    {
        Err(N3PacketError::InvalidAddress)
    } else {
        Ok(())
    }
}

/// UPF destination TNL received by the caller through N2 signalling.
///
/// Construction checks only a concrete unicast IP and the existing nonzero
/// [`Teid`] type. It does not authenticate the signalling or test reachability.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReceivedN3UplinkTnl {
    address: IpAddr,
    teid: Teid,
}

impl ReceivedN3UplinkTnl {
    /// Record received uplink destination information.
    ///
    /// # Errors
    /// Returns [`N3PacketError::InvalidAddress`] for an unsuitable address.
    pub fn new(address: IpAddr, teid: Teid) -> Result<Self, N3PacketError> {
        check_address(address)?;
        Ok(Self { address, teid })
    }

    /// Destination IP for uplink traffic; sensitive, never log it.
    #[must_use]
    pub const fn destination(self) -> IpAddr {
        self.address
    }

    /// Destination TEID for uplink traffic.
    #[must_use]
    pub const fn teid(self) -> Teid {
        self.teid
    }
}

impl fmt::Debug for ReceivedN3UplinkTnl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceivedN3UplinkTnl(<redacted>)")
    }
}

/// Locally supplied N3IWF receive TNL advertised for downlink traffic.
///
/// This value proves neither local address ownership nor selector allocation.
/// It cannot be substituted for received uplink TNL information.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::n3::{LocalN3DownlinkTnl, N3Qfi, N3UplinkEncapsulation};
/// use opc_gtpu_dataplane::Teid;
/// let local = LocalN3DownlinkTnl::new("192.0.2.2".parse().unwrap(), Teid::new(7).unwrap()).unwrap();
/// N3UplinkEncapsulation::new(local, N3Qfi::new(9).unwrap());
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalN3DownlinkTnl {
    address: IpAddr,
    teid: Teid,
}

impl LocalN3DownlinkTnl {
    /// Record the caller's locally supplied downlink receive information.
    ///
    /// # Errors
    /// Returns [`N3PacketError::InvalidAddress`] for an unsuitable address.
    pub fn new(address: IpAddr, teid: Teid) -> Result<Self, N3PacketError> {
        check_address(address)?;
        Ok(Self { address, teid })
    }

    /// Local receive IP; sensitive, never log it.
    #[must_use]
    pub const fn local_address(self) -> IpAddr {
        self.address
    }

    /// Local receive TEID.
    #[must_use]
    pub const fn teid(self) -> Teid {
        self.teid
    }
}

impl fmt::Debug for LocalN3DownlinkTnl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalN3DownlinkTnl(<redacted>)")
    }
}

/// Caller-selected QFI/complete-mark association for one session flow.
///
/// `None` explicitly denotes mark zero, not preserve-current-mark. A nonzero
/// mark owns all 32 bits, as in the existing [`GtpBearerMark`] contract. This
/// is desired intent only: it chooses no SA, applies no mark, and establishes
/// no match priority, fallback, packet provenance, or protection policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct N3FlowMarking {
    qfi: N3Qfi,
    mark: Option<GtpBearerMark>,
}

impl N3FlowMarking {
    /// Record the caller's exact QFI-to-mark intent.
    #[must_use]
    pub const fn new(qfi: N3Qfi, mark: Option<GtpBearerMark>) -> Self {
        Self { qfi, mark }
    }

    /// QoS flow associated with the mark.
    #[must_use]
    pub const fn qfi(self) -> N3Qfi {
        self.qfi
    }

    /// Complete mark; `None` explicitly means zero.
    #[must_use]
    pub const fn mark(self) -> Option<GtpBearerMark> {
        self.mark
    }
}

impl fmt::Debug for N3FlowMarking {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3FlowMarking(<redacted>)")
    }
}

/// Directional TNL and flow-marking intent for a caller-scoped session flow.
///
/// This is neither an install request nor readback. In particular it contains
/// no caller-manufactured generation or removal receipt. Address families may
/// differ; backend capability and route/attachment validation remain required.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct N3ForwardingIntent {
    role: N3ForwardingRole,
    received_uplink: ReceivedN3UplinkTnl,
    local_downlink: LocalN3DownlinkTnl,
    flow: N3FlowMarking,
}

impl N3ForwardingIntent {
    /// Record both directions without converting or swapping tunnel roles.
    #[must_use]
    pub const fn new(
        role: N3ForwardingRole,
        received_uplink: ReceivedN3UplinkTnl,
        local_downlink: LocalN3DownlinkTnl,
        flow: N3FlowMarking,
    ) -> Self {
        Self {
            role,
            received_uplink,
            local_downlink,
            flow,
        }
    }

    /// Requested N3 function role.
    #[must_use]
    pub const fn role(self) -> N3ForwardingRole {
        self.role
    }

    /// Received UPF destination information.
    #[must_use]
    pub const fn received_uplink(self) -> ReceivedN3UplinkTnl {
        self.received_uplink
    }

    /// Locally supplied N3IWF receive information.
    #[must_use]
    pub const fn local_downlink(self) -> LocalN3DownlinkTnl {
        self.local_downlink
    }

    /// Caller-selected flow marking intent.
    #[must_use]
    pub const fn flow(self) -> N3FlowMarking {
        self.flow
    }
}

impl fmt::Debug for N3ForwardingIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3ForwardingIntent(<redacted>)")
    }
}

/// Validated PSC metadata from the shared QFI/RQI/PPI receive subset.
///
/// RQI and PPI are downlink-only. A received PPI is wire information; applying
/// it requires caller knowledge of the PDU session type (TS 38.415 5.5.3.7).
#[derive(Clone, PartialEq, Eq)]
pub struct N3Qos(PduSessionContainer);

impl N3Qos {
    /// Direction carried by this validated PSC.
    #[must_use]
    pub const fn direction(&self) -> N3Direction {
        if self.0.pdu_type == 1 {
            N3Direction::Uplink
        } else {
            N3Direction::Downlink
        }
    }

    /// Validated QFI, without exposing it through `Debug`.
    #[must_use]
    pub const fn qfi(&self) -> N3Qfi {
        N3Qfi(self.0.qfi)
    }

    /// Downlink RQI, always false for uplink.
    #[must_use]
    pub const fn rqi(&self) -> bool {
        self.0.rqi
    }

    /// Optional downlink PPI, always absent for uplink.
    #[must_use]
    pub const fn ppi(&self) -> Option<u8> {
        self.0.ppi
    }
}

impl fmt::Debug for N3Qos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3Qos(<redacted>)")
    }
}

/// Borrowed complete N3 G-PDU and its untrusted classification metadata.
///
/// Decoding does not associate this packet with a session: the caller must
/// separately authenticate endpoint/attachment provenance and exact selectors.
#[derive(Clone, PartialEq, Eq)]
pub struct N3PacketView<'a> {
    datagram: &'a [u8],
    payload: &'a [u8],
    teid: Teid,
    qos: N3Qos,
}

impl<'a> N3PacketView<'a> {
    /// Decode one complete datagram, preserving the original borrowed bytes.
    ///
    /// # Errors
    /// Returns a value-free refusal for framing, limits, missing/duplicate or
    /// unsupported PSC, wrong direction, zero TEID, controls, or empty payload.
    ///
    /// @spec 3GPP TS29281 R18 5.2.2.7
    /// @req REQ-3GPP-TS29281-R18-5.2.2.7-004
    /// @conformance n3-qfi-ppi-rqi-subset
    pub fn decode(
        datagram: &'a [u8],
        direction: N3Direction,
        ctx: DecodeContext,
    ) -> Result<Self, N3PacketError> {
        // Structural framing retains every resource limit while avoiding the
        // generic Strict decoder's reserved-bit rejection. This endpoint
        // boundary independently enforces PSC semantics and cardinality.
        let receiver_ctx = DecodeContext {
            validation_level: ValidationLevel::Structural,
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..ctx
        };
        let (tail, message) =
            GtpuMessage::decode(datagram, receiver_ctx).map_err(map_decode_error)?;
        if !tail.is_empty() {
            return Err(N3PacketError::InvalidFraming);
        }
        if message.header.message_type != 255 {
            return Err(N3PacketError::NotGpdu);
        }
        let teid = Teid::new(message.header.teid).ok_or(N3PacketError::ZeroTeid)?;
        let mut psc = None;
        for extension in message.extensions() {
            let extension = extension.map_err(map_decode_error)?;
            if extension.ext_type == GTPU_EXT_PDU_SESSION_CONTAINER {
                if psc.is_some() {
                    return Err(N3PacketError::DuplicatePsc);
                }
                psc = Some(
                    PduSessionContainer::decode(&extension)
                        .map_err(|_| N3PacketError::InvalidPsc)?,
                );
            }
        }
        let qos = N3Qos(psc.ok_or(N3PacketError::MissingPsc)?);
        if qos.direction() != direction {
            return Err(N3PacketError::DirectionMismatch);
        }
        if message.payload.is_empty() {
            return Err(N3PacketError::EmptyPayload);
        }
        Ok(Self {
            datagram,
            payload: message.payload,
            teid,
            qos,
        })
    }

    /// Original datagram, including any ignored optional extension bytes.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// Opaque inner payload; no IP or subscriber semantics are inferred.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Unbound receive TEID; session ownership requires separate provenance.
    #[must_use]
    pub const fn teid(&self) -> Teid {
        self.teid
    }

    /// Validated PSC classification metadata.
    #[must_use]
    pub const fn qos(&self) -> &N3Qos {
        &self.qos
    }
}

impl fmt::Debug for N3PacketView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3PacketView(<redacted>)")
    }
}

fn map_decode_error(error: DecodeError) -> N3PacketError {
    match error.code() {
        DecodeErrorCode::MessageLengthExceeded => N3PacketError::MessageTooLarge,
        DecodeErrorCode::DepthExceeded | DecodeErrorCode::IeCountExceeded => {
            N3PacketError::ExtensionLimitExceeded
        }
        DecodeErrorCode::UnknownCriticalIe => N3PacketError::UnsupportedExtension,
        _ => N3PacketError::InvalidFraming,
    }
}

/// Constructed uplink PSC insertion for a caller-selected UPF tunnel and QFI.
///
/// This helper only appends a G-PDU to a byte buffer. It performs no packet
/// transmission, installation, classifier lookup, marking, or UDP/IP work.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct N3UplinkEncapsulation {
    tunnel: ReceivedN3UplinkTnl,
    qfi: N3Qfi,
}

impl N3UplinkEncapsulation {
    /// Use the received uplink destination; a local downlink TNL is a different type.
    #[must_use]
    pub const fn new(tunnel: ReceivedN3UplinkTnl, qfi: N3Qfi) -> Self {
        Self { tunnel, qfi }
    }

    /// Destination for a caller-owned transport implementation.
    #[must_use]
    pub const fn tunnel(self) -> ReceivedN3UplinkTnl {
        self.tunnel
    }

    /// QFI inserted into the uplink PSC.
    #[must_use]
    pub const fn qfi(self) -> N3Qfi {
        self.qfi
    }

    /// Required G-PDU length, checked against the wire field and caller cap.
    ///
    /// # Errors
    /// Returns a refusal for an empty payload, length overflow, or exceeded cap.
    pub fn wire_len(&self, payload: &[u8], max_message_len: usize) -> Result<usize, N3PacketError> {
        if payload.is_empty() {
            return Err(N3PacketError::EmptyPayload);
        }
        let len = payload
            .len()
            .checked_add(16)
            .ok_or(N3PacketError::LengthOverflow)?;
        if len - 8 > usize::from(u16::MAX) {
            return Err(N3PacketError::LengthOverflow);
        }
        if len > max_message_len {
            return Err(N3PacketError::MessageTooLarge);
        }
        Ok(len)
    }

    /// Append canonical GTP-U and one uplink PSC, then the opaque payload.
    ///
    /// The cap counts this G-PDU, excluding any existing output prefix. All
    /// fallible validation and length checks complete before writing; the
    /// shared encoder then uses a validated non-overflowing header. Allocation
    /// failure follows `BytesMut`/allocator behaviour and is not recoverable.
    ///
    /// # Errors
    /// Returns a value-free refusal without changing `dst` on validation failure.
    ///
    /// @spec 3GPP TS29281 R18 5.2.2.7
    /// @req REQ-3GPP-TS29281-R18-5.2.2.7-005
    /// @conformance n3-uplink-qfi-subset
    pub fn encode_gpdu(
        &self,
        payload: &[u8],
        dst: &mut BytesMut,
        max_message_len: usize,
    ) -> Result<(), N3PacketError> {
        let len = self.wire_len(payload, max_message_len)?;
        dst.len()
            .checked_add(len)
            .ok_or(N3PacketError::LengthOverflow)?;
        let psc = PduSessionContainer::new_uplink(self.qfi.get())
            .map_err(|_| N3PacketError::InvalidPsc)?;
        let chain = GtpuExtensionChain::from_pdu_session_container(psc)
            .map_err(|_| N3PacketError::InvalidPsc)?;
        let message = GtpuMessage {
            header: GtpuHeader {
                version: 1,
                protocol_type: true,
                reserved: 0,
                ext_hdr_flag: true,
                seq_num_flag: false,
                npdu_num_flag: false,
                message_type: 255,
                length: 0,
                teid: self.tunnel.teid().get(),
                sequence_number: None,
                npdu_number: None,
                next_ext_type: chain.first_extension_type,
                raw_sequence_number: None,
                raw_npdu_number: None,
                raw_next_ext_type: None,
            },
            raw_extension_headers: &chain.raw_headers,
            payload,
        };
        message
            .encode(
                dst,
                EncodeContext {
                    max_message_len,
                    ..EncodeContext::default()
                },
            )
            .map_err(|_| N3PacketError::LengthOverflow)
    }
}

impl fmt::Debug for N3UplinkEncapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3UplinkEncapsulation(<redacted>)")
    }
}
