//! Bounded EAP-5G bootstrap envelopes (TS 24.502 V18.8.0, clause 9.3.2).
//!
//! NAS is opaque. Parsing allocates nothing; encoding checks the complete EAP
//! length before allocation or output mutation. Spare fields and spare parameter
//! types are ignored on receive and omitted by the canonical encoder. Caller
//! limits and duplicate policy are distinct from protocol requirements.
//! UE identity parameters and TNGF contact information are explicitly unsupported.
//!
//! ```
//! use opc_proto_eap::eap5g::{Limits, Message, Packet};
//! let bytes = Packet::new(1, Message::Start).encode(Limits::default())?;
//! let packet = Packet::parse(&bytes, Limits::default())?;
//! assert!(matches!(packet.message(), Message::Start));
//! # Ok::<(), opc_proto_eap::eap5g::Error>(())
//! ```

use std::fmt;

use crate::EapCode;

/// Expanded EAP header, Message-Id and spare octet, in octets.
pub const HEADER_LEN: usize = 14;
const METHOD: [u8; 8] = [254, 0, 0x28, 0xaf, 0, 0, 0, 3];

/// Stable errors containing no packet or AN-parameter values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A header, length field or declared body is incomplete.
    #[error("eap5g_truncated")]
    Truncated,
    /// The EAP length does not describe exactly the supplied packet.
    #[error("eap5g_length_mismatch")]
    LengthMismatch,
    /// The EAP expanded method is not 3GPP EAP-5G.
    #[error("eap5g_unsupported_method")]
    UnsupportedMethod,
    /// The Code/Message-Id pair is not supported.
    #[error("eap5g_unsupported_message")]
    UnsupportedMessage,
    /// A caller limit or the 16-bit EAP length would be exceeded.
    #[error("eap5g_limit_exceeded")]
    LimitExceeded,
    /// A recognized parameter has an invalid length or encoding.
    #[error("eap5g_invalid_parameter")]
    InvalidParameter,
    /// A recognized parameter is outside this codec's declared subset.
    #[error("eap5g_unsupported_parameter")]
    UnsupportedParameter,
    /// The caller's duplicate-singleton policy rejected the packet.
    #[error("eap5g_duplicate_parameter")]
    DuplicateParameter,
    /// The caller's explicit bootstrap presence requirements were not met.
    #[error("eap5g_parameter_presence")]
    ParameterPresence,
    /// NAS transport requires a nonempty opaque NAS body.
    #[error("eap5g_empty_nas")]
    EmptyNas,
    /// The output buffer cannot hold the entire encoded packet.
    #[error("eap5g_output_too_small")]
    OutputTooSmall,
    /// Reserving the bounded output allocation failed.
    #[error("eap5g_allocation_failed")]
    AllocationFailed,
}

/// Caller policy for repeated recognized singleton AN parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicatePolicy {
    /// Reject duplicates, including identical values.
    #[default]
    Reject,
    /// Validate every occurrence, retain the first and count the duplicates.
    FirstWins,
}

/// Inclusive resource limits, chosen by the caller rather than the standard.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum complete EAP packet length (including all headers).
    pub max_packet_len: u16,
    /// Maximum combined ordinary and extended AN-parameter octets.
    pub max_an_bytes: u16,
    /// Maximum total AN parameters, including ignored and duplicate entries.
    pub max_parameters: u16,
    /// Policy for recognized singleton duplicates.
    pub duplicates: DuplicatePolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_packet_len: u16::MAX,
            max_an_bytes: 256,
            max_parameters: 64,
            duplicates: DuplicatePolicy::Reject,
        }
    }
}

/// Opaque NAS bytes. Debug exposes only the length.
#[derive(Clone, Copy)]
pub struct NasPdu<'a>(&'a [u8]);

impl<'a> NasPdu<'a> {
    /// Borrow nonempty NAS without inspecting its content.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyNas);
        }
        // The smallest NAS envelope is the 16-octet request header.
        if bytes.len() > usize::from(u16::MAX) - HEADER_LEN - 2 {
            return Err(Error::LimitExceeded);
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact opaque NAS for forwarding; never include it in logs.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for NasPdu<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NasPdu")
            .field("length", &self.0.len())
            .finish()
    }
}

/// BCD PLMN value, with the two-digit MNC filler preserved.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PlmnId([u8; 3]);

impl PlmnId {
    /// Validate the value part of TS 24.502 clause 9.2.3 (without IEI/length).
    pub fn from_octets(value: [u8; 3]) -> Result<Self, Error> {
        let digits = [
            value[0] & 15,
            value[0] >> 4,
            value[1] & 15,
            value[2] & 15,
            value[2] >> 4,
        ];
        if digits.iter().any(|digit| *digit > 9) || !matches!(value[1] >> 4, 0..=9 | 15) {
            return Err(Error::InvalidParameter);
        }
        Ok(Self(value))
    }

    /// Return the validated wire value for routing, without diagnostic formatting.
    #[must_use]
    pub const fn to_octets(self) -> [u8; 3] {
        self.0
    }
}

impl fmt::Debug for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PlmnId([REDACTED])")
    }
}

/// GUAMI value with validated PLMN and exact AMF identifier bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guami([u8; 6]);

impl Guami {
    /// Validate the six-octet value part of TS 24.502 clause 9.2.1.
    pub fn from_octets(value: [u8; 6]) -> Result<Self, Error> {
        PlmnId::from_octets([value[0], value[1], value[2]])?;
        Ok(Self(value))
    }

    /// Return the wire value for routing; Debug always redacts it.
    #[must_use]
    pub const fn to_octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Debug for Guami {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Guami([REDACTED])")
    }
}

/// Selected NID value. The receive-side spare nibble is canonicalized to zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nid([u8; 6]);

impl Nid {
    /// Read TS 24.502 clause 9.2.7; assignment policy remains with the caller.
    #[must_use]
    pub const fn from_octets(mut value: [u8; 6]) -> Self {
        value[5] &= 15;
        Self(value)
    }

    /// Return the canonical wire value, with sender-zero spare bits.
    #[must_use]
    pub const fn to_octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Debug for Nid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nid([REDACTED])")
    }
}

/// Requested NSSAI: one through eight bounded S-NSSAI length/value entries.
#[derive(Clone, Copy)]
pub struct RequestedNssai<'a> {
    value: &'a [u8],
    count: u8,
}

impl<'a> RequestedNssai<'a> {
    /// Validate TS 24.501 V18.11.1 clauses 9.11.3.37 and 9.11.2.8 framing.
    /// Slice selection and mapped-home-network interpretation remain caller-owned.
    pub fn from_value(value: &'a [u8]) -> Result<Self, Error> {
        let mut tail = value;
        let mut count = 0;
        while !tail.is_empty() {
            let length = usize::from(tail[0]);
            if !matches!(length, 1 | 2 | 4 | 5 | 8) || count == 8 {
                return Err(Error::InvalidParameter);
            }
            tail = tail.get(1 + length..).ok_or(Error::InvalidParameter)?;
            count += 1;
        }
        if count == 0 {
            return Err(Error::InvalidParameter);
        }
        Ok(Self { value, count })
    }

    /// Borrow the validated value (including per-S-NSSAI lengths, without IEI).
    #[must_use]
    pub fn as_value(self) -> &'a [u8] {
        self.value
    }

    /// Number of S-NSSAI entries.
    #[must_use]
    pub const fn count(self) -> u8 {
        self.count
    }
}

impl fmt::Debug for RequestedNssai<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestedNssai")
            .field("count", &self.count)
            .finish()
    }
}

/// Non-3GPP establishment cause (TS 24.502 clause 9.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstablishmentCause {
    /// Emergency access.
    Emergency = 0,
    /// High-priority access.
    HighPriorityAccess = 1,
    /// Mobile-originated signalling.
    MoSignalling = 3,
    /// Mobile-originated data, also the required receive fallback for spare values.
    MoData = 4,
    /// Multimedia priority service.
    MpsPriorityAccess = 8,
    /// Mission-critical service.
    McsPriorityAccess = 9,
    /// Mobile-originated SMS.
    MoSms = 10,
    /// Mobile-originated voice call.
    MoVoiceCall = 11,
    /// Mobile-originated video call.
    MoVideoCall = 12,
}

impl EstablishmentCause {
    /// Ignore spare bits and map spare cause values to mobile-originated data.
    #[must_use]
    pub const fn from_octet(value: u8) -> Self {
        match value & 15 {
            0 => Self::Emergency,
            1 => Self::HighPriorityAccess,
            3 => Self::MoSignalling,
            8 => Self::MpsPriorityAccess,
            9 => Self::McsPriorityAccess,
            10 => Self::MoSms,
            11 => Self::MoVoiceCall,
            12 => Self::MoVideoCall,
            _ => Self::MoData,
        }
    }
}

/// The origin of a GUAMI. Spare receive values are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GuamiType {
    /// Derived from native 5G-GUTI.
    Native = 1,
    /// Derived from 4G-GUTI.
    Mapped = 2,
}

/// Conditional presence supplied by the caller's bootstrap context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Presence {
    /// The parameter must be present.
    Required,
    /// Either presence or absence is permitted.
    #[default]
    Optional,
    /// The parameter must be absent.
    Absent,
}

impl Presence {
    fn check(self, present: bool) -> Result<(), Error> {
        if matches!(
            (self, present),
            (Self::Required, false) | (Self::Absent, true)
        ) {
            Err(Error::ParameterPresence)
        } else {
            Ok(())
        }
    }
}

/// Context for the supported initial response profile, without decoding NAS.
///
/// The profile requires selected PLMN and establishment cause. The caller
/// supplies conditional presence from its access context (clause 7.3.3.1A),
/// including required NID for SNPN access and NSSAI inclusion mode. Optional
/// defaults make no claim that those external conditions have been checked.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootstrapRequirements {
    /// Availability of a GUAMI in the caller's context.
    pub guami: Presence,
    /// Requested NSSAI inclusion mode.
    pub requested_nssai: Presence,
    /// Selected NID requirement (required for the applicable SNPN cases).
    pub selected_nid: Presence,
    /// Whether access is for onboarding.
    pub onboarding: Presence,
}

/// Typed, bounded AN parameters. Every value-bearing field redacts its Debug.
///
/// Construct with `Default`, then set typed fields. The encoder emits one
/// occurrence per field in type order; the parser accepts every wire order.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnParameters<'a> {
    /// GUAMI value, when available.
    pub guami: Option<Guami>,
    /// Selected PLMN value.
    pub selected_plmn: Option<PlmnId>,
    /// Requested NSSAI, when the caller's inclusion mode requires it.
    pub requested_nssai: Option<RequestedNssai<'a>>,
    /// Non-3GPP establishment cause.
    pub establishment_cause: Option<EstablishmentCause>,
    /// Selected NID for applicable SNPN access.
    pub selected_nid: Option<Nid>,
    /// Presence of the zero-length onboarding indication.
    pub onboarding: bool,
    /// GUAMI origin, when supplied with a GUAMI.
    pub guami_type: Option<GuamiType>,
    ignored: u16,
    duplicates: u16,
}

impl AnParameters<'_> {
    /// Count ignored spare parameter types, including extended parameters.
    #[must_use]
    pub const fn ignored_count(&self) -> u16 {
        self.ignored
    }

    /// Count duplicate recognized parameters accepted under `FirstWins`.
    #[must_use]
    pub const fn duplicate_count(&self) -> u16 {
        self.duplicates
    }

    /// Check the initial-response profile using explicit external conditions.
    pub fn validate_bootstrap(&self, requirements: BootstrapRequirements) -> Result<(), Error> {
        Presence::Required.check(self.selected_plmn.is_some())?;
        Presence::Required.check(self.establishment_cause.is_some())?;
        requirements.guami.check(self.guami.is_some())?;
        requirements
            .requested_nssai
            .check(self.requested_nssai.is_some())?;
        requirements
            .selected_nid
            .check(self.selected_nid.is_some())?;
        requirements.onboarding.check(self.onboarding)?;
        self.validate()
    }

    fn validate(&self) -> Result<(), Error> {
        if self.guami_type.is_some() && self.guami.is_none() {
            return Err(Error::ParameterPresence);
        }
        Ok(())
    }

    fn visit(&self, mut f: impl FnMut(u8, &[u8])) {
        if let Some(v) = self.guami {
            f(1, &v.0);
        }
        if let Some(v) = self.selected_plmn {
            f(2, &v.0);
        }
        if let Some(v) = self.requested_nssai {
            f(3, v.value);
        }
        if let Some(v) = self.establishment_cause {
            f(4, &[v as u8]);
        }
        if let Some(v) = self.selected_nid {
            f(5, &v.0);
        }
        if self.onboarding {
            f(7, &[]);
        }
        if let Some(v) = self.guami_type {
            f(8, &[v as u8]);
        }
    }

    fn size(&self, limits: Limits) -> Result<usize, Error> {
        self.validate()?;
        let (mut size, mut count) = (0, 0);
        self.visit(|_, value| {
            size += 2 + value.len();
            count += 1;
        });
        if size > usize::from(limits.max_an_bytes) || count > usize::from(limits.max_parameters) {
            return Err(Error::LimitExceeded);
        }
        Ok(size)
    }
}

/// Admitted messages, with NAS content kept separate from envelope metadata.
#[derive(Debug, Clone, Copy)]
pub enum Message<'a> {
    /// Request/5G-Start.
    Start,
    /// Request/5G-NAS, from the network.
    NasRequest(NasPdu<'a>),
    /// Response/5G-NAS, for bootstrap or subsequent opaque NAS forwarding.
    NasResponse {
        /// Ordinary typed AN parameters; subsequent responses may be empty.
        parameters: AnParameters<'a>,
        /// Opaque NAS bytes.
        nas: NasPdu<'a>,
    },
    /// Response/5G-Stop; no authentication or session-lifecycle decision.
    Stop,
    /// Request/5G-Notification with no TNGF contact parameters.
    NotificationRequest,
    /// Response/5G-Notification acknowledgement.
    NotificationResponse,
}

impl Message<'_> {
    fn header(self) -> (EapCode, u8) {
        match self {
            Self::Start => (EapCode::Request, 1),
            Self::NasRequest(_) => (EapCode::Request, 2),
            Self::NasResponse { .. } => (EapCode::Response, 2),
            Self::Stop => (EapCode::Response, 4),
            Self::NotificationRequest => (EapCode::Request, 3),
            Self::NotificationResponse => (EapCode::Response, 3),
        }
    }
}

/// Complete EAP-5G envelope. Debug omits the identifier and private values.
#[derive(Clone, Copy)]
pub struct Packet<'a> {
    identifier: u8,
    message: Message<'a>,
}

impl fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Eap5gPacket")
            .field("message", &self.message)
            .finish()
    }
}

impl<'a> Packet<'a> {
    /// Construct an envelope; encoding checks lengths, limits and combinations.
    #[must_use]
    pub const fn new(identifier: u8, message: Message<'a>) -> Self {
        Self {
            identifier,
            message,
        }
    }

    /// EAP Identifier for caller-owned request/response correlation.
    #[must_use]
    pub const fn identifier(self) -> u8 {
        self.identifier
    }

    /// Typed envelope contents. This is structural evidence only.
    #[must_use]
    pub const fn message(self) -> Message<'a> {
        self.message
    }

    /// EAP Request or Response code.
    #[must_use]
    pub fn code(self) -> EapCode {
        self.message.header().0
    }

    /// Parse exactly one complete EAP-5G packet without allocating.
    pub fn parse(wire: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if wire.len() > usize::from(limits.max_packet_len) {
            return Err(Error::LimitExceeded);
        }
        if wire.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if usize::from(u16::from_be_bytes([wire[2], wire[3]])) != wire.len() {
            return Err(Error::LengthMismatch);
        }
        if wire[4..12] != METHOD {
            return Err(Error::UnsupportedMethod);
        }
        let mut tail = &wire[HEADER_LEN..];
        let message = match (wire[0], wire[12]) {
            (1, 1) => Message::Start,
            (2, 4) => Message::Stop,
            (2, 3) => Message::NotificationResponse,
            (1, 2) => Message::NasRequest(NasPdu::new(take_length_value(&mut tail)?)?),
            (2, 2) => {
                let an = take_length_value(&mut tail)?;
                let (mut parameters, mut count) = parse_parameters(an, limits)?;
                let nas = NasPdu::new(take_length_value(&mut tail)?)?;
                if !tail.is_empty() {
                    let extended = take_length_value(&mut tail)?;
                    if an.len() + extended.len() > usize::from(limits.max_an_bytes) {
                        return Err(Error::LimitExceeded);
                    }
                    let mut ext = extended;
                    while !ext.is_empty() {
                        count += 1;
                        if count > usize::from(limits.max_parameters) {
                            return Err(Error::LimitExceeded);
                        }
                        let kind = take(&mut ext, 1)?[0];
                        let value = take_length_value(&mut ext)?;
                        if value.is_empty() {
                            return Err(Error::InvalidParameter);
                        }
                        if kind == 6 {
                            return Err(Error::UnsupportedParameter);
                        }
                        parameters.ignored += 1;
                    }
                }
                Message::NasResponse { parameters, nas }
            }
            (1, 3) => {
                let an = take_length_value(&mut tail)?;
                if an.len() > usize::from(limits.max_an_bytes) {
                    return Err(Error::LimitExceeded);
                }
                let mut rest = an;
                let mut count = 0;
                while !rest.is_empty() {
                    count += 1;
                    if count > usize::from(limits.max_parameters) {
                        return Err(Error::LimitExceeded);
                    }
                    let header = take(&mut rest, 2)?;
                    take(&mut rest, usize::from(header[1]))?;
                    if matches!(header[0], 1 | 2) {
                        return Err(Error::UnsupportedParameter);
                    }
                }
                Message::NotificationRequest
            }
            _ => return Err(Error::UnsupportedMessage),
        };
        // Clause 9.3.2.1: all remaining extension octets and spare bits are ignored.
        Ok(Self::new(wire[1], message))
    }

    /// Exact canonical encoded size, checked against the full 16-bit EAP bound.
    pub fn encoded_len(self, limits: Limits) -> Result<usize, Error> {
        let body = match self.message {
            Message::Start | Message::Stop | Message::NotificationResponse => 0,
            Message::NotificationRequest => 2,
            Message::NasRequest(nas) => 2 + nas.0.len(),
            Message::NasResponse { parameters, nas } => 4 + parameters.size(limits)? + nas.0.len(),
        };
        let size = HEADER_LEN + body;
        if size > usize::from(limits.max_packet_len) {
            return Err(Error::LimitExceeded);
        }
        Ok(size)
    }

    /// Encode canonically with a single bounded, fallible allocation.
    pub fn encode(self, limits: Limits) -> Result<Vec<u8>, Error> {
        let size = self.encoded_len(limits)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(size)
            .map_err(|_| Error::AllocationFailed)?;
        output.resize(size, 0);
        self.encode_into(&mut output, limits)?;
        Ok(output)
    }

    /// Encode into caller storage. On any error the output is unchanged.
    ///
    /// Unknown parameters and receive-side spare fields are not retransmitted;
    /// NAS and the supported AN values retain their exact opaque contents.
    pub fn encode_into(self, output: &mut [u8], limits: Limits) -> Result<usize, Error> {
        let size = self.encoded_len(limits)?;
        if output.len() < size {
            return Err(Error::OutputTooSmall);
        }
        let (code, id) = self.message.header();
        let mut writer = Writer {
            output: &mut output[..size],
            position: 0,
        };
        writer.bytes(&[code.as_u8(), self.identifier]);
        writer.length(size);
        writer.bytes(&METHOD);
        writer.bytes(&[id, 0]);
        match self.message {
            Message::NasRequest(nas) => {
                writer.length(nas.0.len());
                writer.bytes(nas.0);
            }
            Message::NasResponse { parameters, nas } => {
                // Preflight succeeded before the first output write.
                let mut size = 0;
                parameters.visit(|_, value| size += 2 + value.len());
                writer.length(size);
                parameters.visit(|kind, value| {
                    writer.bytes(&[kind, value.len() as u8]);
                    writer.bytes(value);
                });
                writer.length(nas.0.len());
                writer.bytes(nas.0);
            }
            Message::NotificationRequest => writer.length(0),
            _ => {}
        }
        Ok(size)
    }
}

fn take<'a>(tail: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    let (value, remaining) = tail.split_at_checked(length).ok_or(Error::Truncated)?;
    *tail = remaining;
    Ok(value)
}

fn take_length_value<'a>(tail: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let header = take(tail, 2)?;
    take(
        tail,
        usize::from(u16::from_be_bytes([header[0], header[1]])),
    )
}

fn array<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    value.try_into().map_err(|_| Error::InvalidParameter)
}

fn parse_parameters(an: &[u8], limits: Limits) -> Result<(AnParameters<'_>, usize), Error> {
    if an.len() > usize::from(limits.max_an_bytes) {
        return Err(Error::LimitExceeded);
    }
    let mut parameters = AnParameters::default();
    let (mut tail, mut seen, mut count) = (an, 0u16, 0);
    while !tail.is_empty() {
        count += 1;
        if count > usize::from(limits.max_parameters) {
            return Err(Error::LimitExceeded);
        }
        let header = take(&mut tail, 2)?;
        let kind = header[0];
        let value = take(&mut tail, usize::from(header[1]))?;
        let duplicate = (1..=8).contains(&kind) && seen & (1 << kind) != 0;
        // Even ignored duplicate values must be structurally valid.
        let mut current = AnParameters::default();
        match kind {
            1 => current.guami = Some(Guami::from_octets(array(value)?)?),
            2 => current.selected_plmn = Some(PlmnId::from_octets(array(value)?)?),
            3 => current.requested_nssai = Some(RequestedNssai::from_value(value)?),
            4 => {
                current.establishment_cause =
                    Some(EstablishmentCause::from_octet(array::<1>(value)?[0]))
            }
            5 => current.selected_nid = Some(Nid::from_octets(array(value)?)),
            6 => return Err(Error::UnsupportedParameter),
            7 => {
                if !value.is_empty() {
                    return Err(Error::InvalidParameter);
                }
                current.onboarding = true;
            }
            8 => {
                current.guami_type = match array::<1>(value)?[0] {
                    1 => Some(GuamiType::Native),
                    2 => Some(GuamiType::Mapped),
                    _ => None,
                }
            }
            _ => {
                parameters.ignored += 1;
                continue;
            }
        }
        if duplicate {
            if limits.duplicates == DuplicatePolicy::Reject {
                return Err(Error::DuplicateParameter);
            }
            parameters.duplicates += 1;
        } else {
            seen |= 1 << kind;
            parameters.guami = parameters.guami.or(current.guami);
            parameters.selected_plmn = parameters.selected_plmn.or(current.selected_plmn);
            parameters.requested_nssai = parameters.requested_nssai.or(current.requested_nssai);
            parameters.establishment_cause = parameters
                .establishment_cause
                .or(current.establishment_cause);
            parameters.selected_nid = parameters.selected_nid.or(current.selected_nid);
            parameters.onboarding |= current.onboarding;
            parameters.guami_type = parameters.guami_type.or(current.guami_type);
        }
    }
    parameters.validate()?;
    Ok((parameters, count))
}

// The caller preflights all sizes; each typed parameter has a bounded value.
struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8]) {
        self.output[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
    }
    fn length(&mut self, length: usize) {
        self.bytes(&(length as u16).to_be_bytes());
    }
}
