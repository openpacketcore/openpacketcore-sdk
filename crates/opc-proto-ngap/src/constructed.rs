//! Aligned-PER framing for the admitted root message/IE containers.
//!
//! X.691 10.9, 11.9 and 11.5: the extensible message SEQUENCE is octet
//! aligned before the constrained 16-bit IE count; each IE has a 16-bit ID,
//! two-bit criticality (then alignment), and a fragmented open type. This
//! deliberately avoids the generated encoder's inner-container alignment bug.

use super::*;

/// One borrowed protocol IE with an already APER-encoded, opaque value.
///
/// The value must contain the encoding of the IE's ASN.1 type, without the
/// surrounding open-type length determinant. Construction validates container
/// policy, not the nested value's semantics or mandatory/conditional presence.
/// Formatting reveals only the identifier, criticality and value length.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProtocolIe<'a> {
    id: u16,
    criticality: Criticality,
    value: &'a [u8],
}

impl<'a> ProtocolIe<'a> {
    /// Borrow a pre-encoded IE value without copying it.
    pub const fn new(id: u16, criticality: Criticality, value: &'a [u8]) -> Self {
        Self {
            id,
            criticality,
            value,
        }
    }
}

impl fmt::Debug for ProtocolIe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolIe")
            .field("id", &self.id)
            .field("criticality", &self.criticality)
            .field("value_len", &self.value.len())
            .finish()
    }
}

// Keep construction, canonical dispatch, and borrowed field traversal together.
// The receive policy tables remain the sole source of IE criticality metadata.
macro_rules! message_types {
    ($($variant:ident, $outcome:ident, $code:ident, $crit:ident, $profile:ident $(, $inner:tt)?;)+) => {
        /// A supported message outcome for structural container construction.
        ///
        /// This selects the procedure code, outcome and procedure criticality
        /// together. It does not establish N3IWF semantic admission. Paging has
        /// structural coverage only; the other fifteen outcomes have independent
        /// Release 18 complete-message evidence.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum MessageType {
            $(#[doc = concat!(stringify!($variant), " message outcome.")]
            $variant,)+
        }

        impl MessageType {
            fn metadata(self) -> (Outcome, u8, Criticality, policy::IeProfile) {
                match self {
                    $(Self::$variant => (Outcome::$outcome, $code, Criticality::$crit, policy::$profile),)+
                }
            }
        }

        impl Message {
            /// Identify a supported typed message; unknown bodies return `None`.
            pub const fn message_type(&self) -> Option<MessageType> {
                match self {
                    $(Self::$variant(_) => Some(MessageType::$variant),)+
                    Self::Unknown(_) => None,
                }
            }

            fn ie_count(&self) -> usize {
                match self {
                    $(Self::$variant(value) => value.protocol_ies.0.len(),)+
                    Self::Unknown(_) => 0,
                }
            }

            fn visit_ies(&self, mut visit: impl FnMut(u16, u8, &[u8]) -> Result<(), EncodeError>) -> Result<(), EncodeError> {
                match self {
                    $(Self::$variant(value) => {
                        for ie in &value.protocol_ies.0 {
                            visit(ie.id$(.$inner)?, ie.criticality as u8, ie.value.as_bytes())?;
                        }
                        Ok(())
                    },)+
                    Self::Unknown(_) => Err(structural("canonical ngap encoding requires a typed message")),
                }
            }
        }
    };
}

message_types! {
    NgSetupRequest, Initiating, PROCEDURE_CODE_NG_SETUP, reject, NG_SETUP_REQUEST;
    NgSetupResponse, Successful, PROCEDURE_CODE_NG_SETUP, reject, NG_SETUP_RESPONSE;
    NgSetupFailure, Unsuccessful, PROCEDURE_CODE_NG_SETUP, reject, NG_SETUP_FAILURE;
    InitialUeMessage, Initiating, PROCEDURE_CODE_INITIAL_UE, ignore, INITIAL_UE_MESSAGE;
    DownlinkNasTransport, Initiating, PROCEDURE_CODE_DOWNLINK_NAS_TRANSPORT, ignore, DOWNLINK_NAS_TRANSPORT;
    UplinkNasTransport, Initiating, PROCEDURE_CODE_UPLINK_NAS_TRANSPORT, ignore, UPLINK_NAS_TRANSPORT, 0;
    InitialContextSetupRequest, Initiating, PROCEDURE_CODE_INITIAL_CONTEXT_SETUP, reject, INITIAL_CONTEXT_SETUP_REQUEST;
    InitialContextSetupResponse, Successful, PROCEDURE_CODE_INITIAL_CONTEXT_SETUP, reject, INITIAL_CONTEXT_SETUP_RESPONSE;
    InitialContextSetupFailure, Unsuccessful, PROCEDURE_CODE_INITIAL_CONTEXT_SETUP, reject, INITIAL_CONTEXT_SETUP_FAILURE;
    PduSessionResourceSetupRequest, Initiating, PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP, reject, PDU_SESSION_RESOURCE_SETUP_REQUEST;
    PduSessionResourceSetupResponse, Successful, PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP, reject, PDU_SESSION_RESOURCE_SETUP_RESPONSE;
    PduSessionResourceReleaseCommand, Initiating, PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE, reject, PDU_SESSION_RESOURCE_RELEASE_COMMAND;
    PduSessionResourceReleaseResponse, Successful, PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE, reject, PDU_SESSION_RESOURCE_RELEASE_RESPONSE;
    UeContextReleaseCommand, Initiating, PROCEDURE_CODE_UE_CONTEXT_RELEASE, reject, UE_CONTEXT_RELEASE_COMMAND, 0;
    UeContextReleaseComplete, Successful, PROCEDURE_CODE_UE_CONTEXT_RELEASE, reject, UE_CONTEXT_RELEASE_COMPLETE, 0;
    Paging, Initiating, PROCEDURE_CODE_PAGING, ignore, PAGING;
}

impl Pdu {
    /// Construct a supported typed container from borrowed, encoded IE values.
    ///
    /// The message type fixes the procedure/outcome/criticality tuple. The
    /// existing receive policies apply to IE criticality, unknown identifiers,
    /// duplicates and depth. IE count and complete wire length are checked
    /// before any payload allocation. `allocation_budget` remains advisory.
    ///
    /// The returned `raw` is empty. Use canonical [`crate::encode`] (the default),
    /// which serializes the resulting policy-filtered typed view. Canonical
    /// output rejects duplicate singletons and unknown reject-criticality IEs
    /// even if a permissive receive context preserved them during construction.
    /// The caller remains responsible for mandatory/conditional fields and
    /// valid nested ASN.1 values; this is a structural construction boundary.
    ///
    /// @spec 3GPP TS38413 R18 9.4
    /// @req REQ-3GPP-TS38413-R18-9.4-001
    pub fn from_protocol_ies(
        message_type: MessageType,
        ies: &[ProtocolIe<'_>],
        ctx: DecodeContext,
    ) -> Result<Self, DecodeError> {
        enforce_depth(NGAP_TYPED_MESSAGE_DEPTH, ctx)?;
        if ies.len() > ctx.max_ies || ies.len() > usize::from(u16::MAX) {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        let mut body_len = 3usize;
        for ie in ies {
            body_len = add_ie_len(body_len, ie.value.len()).map_err(construction_length_error)?;
        }
        let total = pdu_len(body_len).map_err(construction_length_error)?;
        if total > ctx.max_message_len {
            return Err(length_error(total, ctx.max_message_len));
        }
        let mut body = Vec::with_capacity(body_len);
        write_prefix(&mut body, ies.len());
        for ie in ies {
            write_ie(&mut body, ie.id, ie.criticality as u8, ie.value);
        }
        let (outcome, procedure_code, criticality, _) = message_type.metadata();
        let message = decode_message(outcome, procedure_code, criticality, &body, ctx)?;
        let kind = match outcome {
            Outcome::Initiating => PduKind::Initiating {
                procedure_code,
                criticality,
                message,
            },
            Outcome::Successful => PduKind::Successful {
                procedure_code,
                criticality,
                message,
            },
            Outcome::Unsuccessful => PduKind::Unsuccessful {
                procedure_code,
                criticality,
                message,
            },
        };
        Ok(Self {
            raw: Bytes::new(),
            kind,
        })
    }
}

fn construction_length_error(_: EncodeError) -> DecodeError {
    DecodeError::new(DecodeErrorCode::LengthOverflow, 0)
}

fn structural(reason: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
}

fn add(a: usize, b: usize) -> Result<usize, EncodeError> {
    a.checked_add(b)
        .ok_or_else(|| EncodeError::new(EncodeErrorCode::LengthOverflow))
}

// X.691 11.9: emit the largest 16K multiple up to 64K per fragment, then a
// final short/two-octet determinant (including zero after exact multiples).
pub(super) fn open_type_len(len: usize) -> Result<usize, EncodeError> {
    let remainder = len % 65536;
    let fragments = add(len / 65536, usize::from(remainder >= 16384))?;
    let final_len = remainder % 16384;
    add(add(len, fragments)?, if final_len < 128 { 1 } else { 2 })
}

fn add_ie_len(body: usize, value: usize) -> Result<usize, EncodeError> {
    add(add(body, 3)?, open_type_len(value)?)
}

fn pdu_len(body: usize) -> Result<usize, EncodeError> {
    add(3, open_type_len(body)?)
}

fn parts(kind: &PduKind) -> (Outcome, u8, Criticality, &Message) {
    match kind {
        PduKind::Initiating {
            procedure_code,
            criticality,
            message,
        } => (Outcome::Initiating, *procedure_code, *criticality, message),
        PduKind::Successful {
            procedure_code,
            criticality,
            message,
        } => (Outcome::Successful, *procedure_code, *criticality, message),
        PduKind::Unsuccessful {
            procedure_code,
            criticality,
            message,
        } => (
            Outcome::Unsuccessful,
            *procedure_code,
            *criticality,
            message,
        ),
    }
}

pub(super) fn checked_len(pdu: &Pdu, ctx: EncodeContext) -> Result<usize, EncodeError> {
    let (outcome, code, criticality, message) = parts(&pdu.kind);
    let message_type = message
        .message_type()
        .ok_or_else(|| structural("canonical ngap encoding requires a typed message"))?;
    let (expected_outcome, expected_code, expected_criticality, profile) = message_type.metadata();
    if outcome != expected_outcome || code != expected_code || criticality != expected_criticality {
        return Err(structural("ngap procedure and message mismatch"));
    }
    if message.ie_count() > usize::from(u16::MAX) {
        return Err(structural("ngap protocol ie count exceeds wire range"));
    }
    // Fixed, bounded bitset avoids allocating while calculating wire_len.
    let mut seen = [0u64; 1024];
    let mut body_len = 3;
    message.visit_ies(|id, crit, value| {
        profile.validate_send_ie(id, crit)?;
        let word = usize::from(id) / 64;
        let bit = 1u64 << (id % 64);
        if seen[word] & bit != 0 {
            return Err(structural("duplicate ngap protocol ie"));
        }
        seen[word] |= bit;
        body_len = add_ie_len(body_len, value.len())?;
        Ok(())
    })?;
    let total = pdu_len(body_len)?;
    ctx.check_capacity(total)?;
    Ok(total)
}

pub(super) fn encode(pdu: &Pdu, ctx: EncodeContext) -> Result<Vec<u8>, EncodeError> {
    let total = checked_len(pdu, ctx)?;
    let (outcome, code, criticality, message) = parts(&pdu.kind);
    // The body is smaller than the fully validated complete output bound.
    let mut body = Vec::with_capacity(total);
    write_prefix(&mut body, message.ie_count());
    message.visit_ies(|id, crit, value| {
        write_ie(&mut body, id, crit, value);
        Ok(())
    })?;
    let mut result = Vec::with_capacity(total);
    result.push(match outcome {
        Outcome::Initiating => 0x00,
        Outcome::Successful => 0x20,
        Outcome::Unsuccessful => 0x40,
    });
    result.push(code);
    result.push((criticality as u8) << 6);
    write_open_type(&mut result, &body);
    Ok(result)
}

fn write_prefix(out: &mut Vec<u8>, count: usize) {
    out.push(0); // No SEQUENCE extension additions; zero alignment bits.
    out.extend_from_slice(&(count as u16).to_be_bytes()); // preflighted
}

fn write_ie(out: &mut Vec<u8>, id: u16, criticality: u8, value: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.push(criticality << 6);
    write_open_type(out, value);
}

pub(super) fn write_open_type(out: &mut Vec<u8>, mut value: &[u8]) {
    while value.len() >= 16384 {
        let units = (value.len() / 16384).min(4);
        let size = units * 16384;
        out.push(0xc0 | units as u8);
        out.extend_from_slice(&value[..size]);
        value = &value[size..];
    }
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        out.extend_from_slice(&(0x8000 | value.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(value);
}
