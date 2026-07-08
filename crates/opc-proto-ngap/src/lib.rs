#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! NGAP protocol codec (3GPP TS 38.413) for OpenPacketCore — v1 subset.
//!
//! Scope (see CONFORMANCE.md): NGAP-PDU framing (initiating / successful /
//! unsuccessful outcomes), fixture-proven NGSetupRequest decoding, and
//! structural typed dispatch for the first AMF N2 procedure subset. Encoding is
//! raw-preserving only: the PDU bytes captured during decoding are re-emitted
//! byte-identically. This works around an APER encoder alignment issue in
//! `rasn` 0.28 that prevents canonical typed encoding from meeting ADR 0015
//! byte-exact requirements.
//!
//! @spec 3GPP TS38413 R18
//! @req REQ-3GPP-TS38413-R18-001
//! @conformance v1-subset — see CONFORMANCE.md

use bytes::{Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode, UnknownIePolicy, ValidationLevel,
};

mod generated;

pub use generated::ngap_common_data_types::{Criticality, ProcedureCode};

/// Generated NGAP message types that can appear in [`Message`].
///
/// These are generated from the pinned TS 38.413 R18 ASN.1 source. The SDK
/// wrapper controls dispatch, error handling, and raw-preserving encode policy;
/// this module exposes the selected generated types so downstream code can
/// inspect typed decodes without depending on private module paths.
pub mod messages {
    pub use super::generated::ngap_pdu_contents::{
        DownlinkNASTransport, InitialContextSetupFailure, InitialContextSetupRequest,
        InitialContextSetupResponse, InitialUEMessage, NGSetupFailure, NGSetupRequest,
        NGSetupResponse, PDUSessionResourceReleaseCommand, PDUSessionResourceReleaseResponse,
        PDUSessionResourceSetupRequest, PDUSessionResourceSetupResponse, Paging,
        UEContextReleaseCommand, UEContextReleaseComplete, UplinkNASTransport,
    };
}

/// A decoded NGAP PDU with raw-preserving re-encode support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// Original PDU bytes, preserved for byte-exact re-emission.
    pub raw: Bytes,
    /// Decoded PDU kind and message body.
    pub kind: PduKind,
}

/// NGAP PDU outcome kind and decoded message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduKind {
    /// Initiating message.
    Initiating {
        /// Procedure code from the NGAP-PDU wrapper.
        procedure_code: u8,
        /// Criticality from the NGAP-PDU wrapper.
        criticality: Criticality,
        /// Decoded message body.
        message: Message,
    },
    /// Successful outcome.
    Successful {
        /// Procedure code from the NGAP-PDU wrapper.
        procedure_code: u8,
        /// Criticality from the NGAP-PDU wrapper.
        criticality: Criticality,
        /// Decoded message body.
        message: Message,
    },
    /// Unsuccessful outcome.
    Unsuccessful {
        /// Procedure code from the NGAP-PDU wrapper.
        procedure_code: u8,
        /// Criticality from the NGAP-PDU wrapper.
        criticality: Criticality,
        /// Decoded message body.
        message: Message,
    },
}

/// Decoded NGAP message body for the supported typed subset.
///
/// See CONFORMANCE.md for which variants are fixture-proven and which are
/// structural typed-dispatch coverage only. Unsupported procedure/outcome
/// combinations are surfaced as [`Message::Unknown`] with body bytes preserved
/// raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// NG Setup Request (initiating message, procedure code 21).
    NgSetupRequest(messages::NGSetupRequest),
    /// NG Setup Response (successful outcome, procedure code 21).
    NgSetupResponse(messages::NGSetupResponse),
    /// NG Setup Failure (unsuccessful outcome, procedure code 21).
    NgSetupFailure(messages::NGSetupFailure),
    /// Initial UE Message (initiating message, procedure code 15).
    InitialUeMessage(messages::InitialUEMessage),
    /// Downlink NAS Transport (initiating message, procedure code 4).
    DownlinkNasTransport(messages::DownlinkNASTransport),
    /// Uplink NAS Transport (initiating message, procedure code 46).
    UplinkNasTransport(messages::UplinkNASTransport),
    /// Initial Context Setup Request (initiating message, procedure code 14).
    InitialContextSetupRequest(messages::InitialContextSetupRequest),
    /// Initial Context Setup Response (successful outcome, procedure code 14).
    InitialContextSetupResponse(messages::InitialContextSetupResponse),
    /// Initial Context Setup Failure (unsuccessful outcome, procedure code 14).
    InitialContextSetupFailure(messages::InitialContextSetupFailure),
    /// PDU Session Resource Setup Request (initiating message, procedure code 29).
    PduSessionResourceSetupRequest(messages::PDUSessionResourceSetupRequest),
    /// PDU Session Resource Setup Response (successful outcome, procedure code 29).
    PduSessionResourceSetupResponse(messages::PDUSessionResourceSetupResponse),
    /// PDU Session Resource Release Command (initiating message, procedure code 28).
    PduSessionResourceReleaseCommand(messages::PDUSessionResourceReleaseCommand),
    /// PDU Session Resource Release Response (successful outcome, procedure code 28).
    PduSessionResourceReleaseResponse(messages::PDUSessionResourceReleaseResponse),
    /// UE Context Release Command (initiating message, procedure code 41).
    UeContextReleaseCommand(messages::UEContextReleaseCommand),
    /// UE Context Release Complete (successful outcome, procedure code 41).
    UeContextReleaseComplete(messages::UEContextReleaseComplete),
    /// Paging (initiating message, procedure code 24).
    Paging(messages::Paging),
    /// Message not in the typed subset; raw bytes are preserved.
    Unknown(Bytes),
}

const PROCEDURE_CODE_NG_SETUP: u8 = 21;
const PROCEDURE_CODE_INITIAL_UE: u8 = 15;
const PROCEDURE_CODE_DOWNLINK_NAS_TRANSPORT: u8 = 4;
const PROCEDURE_CODE_INITIAL_CONTEXT_SETUP: u8 = 14;
const PROCEDURE_CODE_PAGING: u8 = 24;
const PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE: u8 = 28;
const PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP: u8 = 29;
const PROCEDURE_CODE_UE_CONTEXT_RELEASE: u8 = 41;
const PROCEDURE_CODE_UPLINK_NAS_TRANSPORT: u8 = 46;

const NGAP_PDU_WRAPPER_DEPTH: usize = 2;
const NGAP_UNKNOWN_MESSAGE_DEPTH: usize = 3;
const NGAP_TYPED_MESSAGE_DEPTH: usize = 5;

fn length_error(len: usize, limit: usize) -> DecodeError {
    DecodeError::new(DecodeErrorCode::MessageLengthExceeded, len.min(limit))
}

fn enforce_depth(required: usize, ctx: DecodeContext) -> Result<(), DecodeError> {
    if ctx.max_depth < required {
        Err(DecodeError::new(DecodeErrorCode::DepthExceeded, 0))
    } else {
        Ok(())
    }
}

/// Decode an NGAP PDU from a byte slice.
///
/// @spec 3GPP TS38413 R18 9.1
/// @req REQ-3GPP-TS38413-R18-9.1-001
/// @conformance v1-subset
pub fn decode(buf: &[u8], ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    if buf.len() > ctx.max_message_len {
        return Err(length_error(buf.len(), ctx.max_message_len));
    }
    enforce_depth(NGAP_PDU_WRAPPER_DEPTH, ctx)?;

    // Decode a single PDU and capture the unconsumed remainder. `raw` must
    // cover ONLY the bytes this PDU actually consumed: copying the whole input
    // would make `encode` re-emit any trailing attacker-controlled bytes
    // byte-for-byte, a parse-vs-forward (request-smuggling) discrepancy.
    let (pdu, remainder): (generated::ngap_pdu_descriptions::NGAPPDU, &[u8]) =
        rasn::aper::decode_with_remainder(buf)
            .map_err(|_| DecodeError::new(DecodeErrorCode::Structural { reason: "ngap pdu" }, 0))?;
    let consumed = buf.len() - remainder.len();
    let raw = Bytes::copy_from_slice(&buf[..consumed]);

    match pdu {
        generated::ngap_pdu_descriptions::NGAPPDU::initiatingMessage(im) => {
            let message = decode_message(
                Outcome::Initiating,
                im.procedure_code.0,
                im.criticality,
                im.value.as_bytes(),
                ctx,
            )?;
            Ok(Pdu {
                raw,
                kind: PduKind::Initiating {
                    procedure_code: im.procedure_code.0,
                    criticality: im.criticality,
                    message,
                },
            })
        }
        generated::ngap_pdu_descriptions::NGAPPDU::successfulOutcome(so) => {
            let message = decode_message(
                Outcome::Successful,
                so.procedure_code.0,
                so.criticality,
                so.value.as_bytes(),
                ctx,
            )?;
            Ok(Pdu {
                raw,
                kind: PduKind::Successful {
                    procedure_code: so.procedure_code.0,
                    criticality: so.criticality,
                    message,
                },
            })
        }
        generated::ngap_pdu_descriptions::NGAPPDU::unsuccessfulOutcome(uo) => {
            let message = decode_message(
                Outcome::Unsuccessful,
                uo.procedure_code.0,
                uo.criticality,
                uo.value.as_bytes(),
                ctx,
            )?;
            Ok(Pdu {
                raw,
                kind: PduKind::Unsuccessful {
                    procedure_code: uo.procedure_code.0,
                    criticality: uo.criticality,
                    message,
                },
            })
        }
    }
}

/// NGAP-PDU outcome class, used to dispatch message-body decoding: the same
/// procedure code carries different message types per outcome (procedure 21
/// is NGSetupRequest when initiating but NGSetupResponse/NGSetupFailure on
/// the successful/unsuccessful outcomes).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Initiating,
    Successful,
    Unsuccessful,
}

fn decode_message(
    outcome: Outcome,
    procedure_code: u8,
    criticality: Criticality,
    value: &[u8],
    ctx: DecodeContext,
) -> Result<Message, DecodeError> {
    if value.len() > ctx.max_message_len {
        return Err(length_error(value.len(), ctx.max_message_len));
    }

    macro_rules! decode_as {
        ($ty:ty, $variant:ident, $reason:literal) => {{
            enforce_depth(NGAP_TYPED_MESSAGE_DEPTH, ctx)?;
            let msg: $ty = rasn::aper::decode(value).map_err(|_| {
                DecodeError::new(DecodeErrorCode::Structural { reason: $reason }, 0)
            })?;
            enforce_ie_count(msg.protocol_ies.0.len(), ctx)?;
            Ok(Message::$variant(msg))
        }};
    }

    match (outcome, procedure_code) {
        (Outcome::Initiating, PROCEDURE_CODE_NG_SETUP) => {
            decode_as!(messages::NGSetupRequest, NgSetupRequest, "ngsetup request")
        }
        (Outcome::Successful, PROCEDURE_CODE_NG_SETUP) => {
            decode_as!(
                messages::NGSetupResponse,
                NgSetupResponse,
                "ngsetup response"
            )
        }
        (Outcome::Unsuccessful, PROCEDURE_CODE_NG_SETUP) => {
            decode_as!(messages::NGSetupFailure, NgSetupFailure, "ngsetup failure")
        }
        (Outcome::Initiating, PROCEDURE_CODE_INITIAL_UE) => decode_as!(
            messages::InitialUEMessage,
            InitialUeMessage,
            "initial ue message"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_DOWNLINK_NAS_TRANSPORT) => decode_as!(
            messages::DownlinkNASTransport,
            DownlinkNasTransport,
            "downlink nas transport"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_UPLINK_NAS_TRANSPORT) => decode_as!(
            messages::UplinkNASTransport,
            UplinkNasTransport,
            "uplink nas transport"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_INITIAL_CONTEXT_SETUP) => decode_as!(
            messages::InitialContextSetupRequest,
            InitialContextSetupRequest,
            "initial context setup request"
        ),
        (Outcome::Successful, PROCEDURE_CODE_INITIAL_CONTEXT_SETUP) => decode_as!(
            messages::InitialContextSetupResponse,
            InitialContextSetupResponse,
            "initial context setup response"
        ),
        (Outcome::Unsuccessful, PROCEDURE_CODE_INITIAL_CONTEXT_SETUP) => decode_as!(
            messages::InitialContextSetupFailure,
            InitialContextSetupFailure,
            "initial context setup failure"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP) => decode_as!(
            messages::PDUSessionResourceSetupRequest,
            PduSessionResourceSetupRequest,
            "pdu session resource setup request"
        ),
        (Outcome::Successful, PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP) => decode_as!(
            messages::PDUSessionResourceSetupResponse,
            PduSessionResourceSetupResponse,
            "pdu session resource setup response"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE) => decode_as!(
            messages::PDUSessionResourceReleaseCommand,
            PduSessionResourceReleaseCommand,
            "pdu session resource release command"
        ),
        (Outcome::Successful, PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE) => decode_as!(
            messages::PDUSessionResourceReleaseResponse,
            PduSessionResourceReleaseResponse,
            "pdu session resource release response"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_UE_CONTEXT_RELEASE) => decode_as!(
            messages::UEContextReleaseCommand,
            UeContextReleaseCommand,
            "ue context release command"
        ),
        (Outcome::Successful, PROCEDURE_CODE_UE_CONTEXT_RELEASE) => decode_as!(
            messages::UEContextReleaseComplete,
            UeContextReleaseComplete,
            "ue context release complete"
        ),
        (Outcome::Initiating, PROCEDURE_CODE_PAGING) => {
            decode_as!(messages::Paging, Paging, "paging")
        }
        _ if reject_unknown_message(ctx) => Err(unknown_message_error(criticality)),
        _ => {
            enforce_depth(NGAP_UNKNOWN_MESSAGE_DEPTH, ctx)?;
            Ok(Message::Unknown(Bytes::copy_from_slice(value)))
        }
    }
}

fn enforce_ie_count(count: usize, ctx: DecodeContext) -> Result<(), DecodeError> {
    if count > ctx.max_ies {
        Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0))
    } else {
        Ok(())
    }
}

const fn reject_unknown_message(ctx: DecodeContext) -> bool {
    matches!(ctx.unknown_ie_policy, UnknownIePolicy::Reject)
        || matches!(
            ctx.validation_level,
            ValidationLevel::Strict | ValidationLevel::ProcedureAware
        )
}

fn unknown_message_error(criticality: Criticality) -> DecodeError {
    if criticality == Criticality::reject {
        DecodeError::new(DecodeErrorCode::UnknownCriticalIe, 0)
    } else {
        DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "unknown ngap procedure",
            },
            0,
        )
    }
}

/// Encode a [`Pdu`] back to APER bytes.
///
/// The v1 subset only supports raw-preserving mode; any other mode returns an error
/// because `rasn` 0.28's APER encoder does not reproduce the byte alignment
/// used by the external fixtures for the inner message types.
///
/// @spec 3GPP TS38413 R18 9.1
/// @req REQ-3GPP-TS38413-R18-9.1-002
/// @conformance v1-subset
pub fn encode(pdu: &Pdu, ctx: EncodeContext) -> Result<Vec<u8>, EncodeError> {
    let len = checked_raw_preserving_len(pdu, ctx)?;
    Ok(pdu.raw[..len].to_vec())
}

fn checked_raw_preserving_len(pdu: &Pdu, ctx: EncodeContext) -> Result<usize, EncodeError> {
    if !ctx.raw_preserving {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "NGAP encode only supports raw-preserving mode",
        }));
    }
    if pdu.raw.is_empty() {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "raw-preserving NGAP encode requires decoded raw bytes",
        }));
    }

    ctx.check_capacity(pdu.raw.len())?;
    Ok(pdu.raw.len())
}

impl<'a> BorrowDecode<'a> for Pdu {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let pdu = decode(input, ctx)?;
        // Report the bytes this PDU did NOT consume rather than claiming the
        // whole input was used. `pdu.raw` is exactly the consumed prefix.
        let consumed = pdu.raw.len();
        Ok((&input[consumed..], pdu))
    }
}

impl OwnedDecode for Pdu {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (remainder, pdu) = Self::decode(&input, ctx)?;
        // An owned decode consumes a single, self-contained NGAP message;
        // trailing bytes after the PDU are rejected rather than discarded.
        if !remainder.is_empty() {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "trailing bytes after ngap pdu",
                },
                input.len() - remainder.len(),
            ));
        }
        Ok(pdu)
    }
}

impl Encode for Pdu {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let bytes = encode(self, ctx)?;
        dst.extend_from_slice(&bytes);
        Ok(())
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        checked_raw_preserving_len(self, ctx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Known-good NGSetupRequest APER PDU captured from an independent
    /// `asn1c`-based implementation (libngap). The outer NGAP-PDU wrapper is
    /// present; the message body contains GlobalRANNodeID, RANNodeName,
    /// SupportedTAList, and DefaultPagingDRX IEs.
    fn ngsetup_request_fixture() -> Vec<u8> {
        vec![
            0x00, 0x15, 0x40, 0x4a, 0x00, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x08, 0x40, 0x02, 0xf8,
            0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x40, 0x0f, 0x06, 0x00, 0x4d, 0x79, 0x20,
            0x6c, 0x69, 0x74, 0x74, 0x6c, 0x65, 0x20, 0x67, 0x4e, 0x42, 0x00, 0x66, 0x00, 0x1f,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xf8, 0x98, 0x00, 0x01, 0x00, 0x08, 0x00,
            0x80, 0x00, 0x00, 0x01, 0x00, 0x02, 0xf8, 0x39, 0x00, 0x01, 0x00, 0x18, 0x81, 0xc0,
            0x00, 0x13, 0x88, 0x00, 0x15, 0x40, 0x01, 0x40,
        ]
    }

    #[derive(Clone, Copy)]
    enum FixtureOutcome {
        Initiating,
        Successful,
        Unsuccessful,
    }

    impl FixtureOutcome {
        const fn choice_octet(self) -> u8 {
            match self {
                Self::Initiating => 0x00,
                Self::Successful => 0x20,
                Self::Unsuccessful => 0x40,
            }
        }
    }

    fn empty_ie_pdu(
        outcome: FixtureOutcome,
        procedure_code: u8,
        criticality: Criticality,
    ) -> Vec<u8> {
        let criticality_octet = match criticality {
            Criticality::reject => 0x00,
            Criticality::ignore => 0x40,
            Criticality::notify => 0x80,
        };

        // The body is an extensible SEQUENCE with extension-present bit 0
        // followed by a constrained SEQUENCE OF length determinant of zero:
        // 00 00 00. The outer open type length is therefore 3 octets.
        vec![
            outcome.choice_octet(),
            procedure_code,
            criticality_octet,
            0x03,
            0x00,
            0x00,
            0x00,
        ]
    }

    fn raw_preserving_context() -> EncodeContext {
        EncodeContext {
            raw_preserving: true,
            ..Default::default()
        }
    }

    #[test]
    fn trailing_bytes_after_pdu_are_rejected_and_not_re_emitted() {
        let mut bytes = ngsetup_request_fixture();
        let valid_len = bytes.len();

        // A clean PDU: raw covers exactly the consumed input.
        let pdu = decode(&bytes, DecodeContext::default()).unwrap();
        assert_eq!(pdu.raw.len(), valid_len);

        // Append attacker-controlled trailing bytes.
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        // BorrowDecode reports the trailing bytes as the unconsumed remainder
        // (not an empty slice), and raw still covers only the real PDU — so
        // re-encoding cannot smuggle the trailing bytes back out.
        let (remainder, pdu) = Pdu::decode(&bytes, DecodeContext::default()).unwrap();
        assert_eq!(remainder, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(pdu.raw.len(), valid_len);

        // Owned decode of a single message rejects the trailing bytes outright.
        let err = Pdu::decode_owned(Bytes::from(bytes), DecodeContext::default()).unwrap_err();
        assert!(matches!(
            err.code(),
            DecodeErrorCode::Structural { reason } if reason.contains("trailing")
        ));
    }

    #[test]
    fn roundtrip_ngsetup_request_external_fixture() {
        let bytes = ngsetup_request_fixture();
        let pdu = decode(&bytes, DecodeContext::default()).unwrap();
        match &pdu.kind {
            PduKind::Initiating {
                procedure_code,
                criticality,
                message,
            } => {
                assert_eq!(*procedure_code, PROCEDURE_CODE_NG_SETUP);
                assert_eq!(*criticality, Criticality::ignore);
                let req = match message {
                    Message::NgSetupRequest(req) => req,
                    other => panic!("expected NGSetupRequest, got {other:?}"),
                };

                // Content assertions: the decoder must map the IEs to the
                // values the independent implementation encoded, not merely
                // produce *something* of the right type.
                let ies = &req.protocol_ies.0;
                assert_eq!(ies.len(), 4, "fixture carries exactly four IEs");
                let ids: Vec<u16> = ies.iter().map(|ie| ie.id).collect();
                // id-GlobalRANNodeID(27), id-RANNodeName(82),
                // id-SupportedTAList(102), id-DefaultPagingDRX(21)
                assert_eq!(ids, vec![27, 82, 102, 21]);
                // RANNodeName open-type value carries the printable string.
                let name_ie = &ies[1];
                assert!(
                    name_ie.value.as_bytes().ends_with(b"My little gNB"),
                    "RANNodeName value must contain the fixture's node name"
                );
                // DefaultPagingDRX open-type value: APER enumerated v64.
                let drx_ie = &ies[3];
                assert_eq!(drx_ie.value.as_bytes(), &[0x40], "DefaultPagingDRX v64");
            }
            _ => panic!("expected initiating message"),
        }

        let encoded = encode(&pdu, raw_preserving_context()).unwrap();
        assert_eq!(encoded, bytes);
    }

    /// Hand-authored successfulOutcome wrapper per TS 38.413 §9.2 / X.691:
    /// octet 0 = 0x20 (extension bit 0, CHOICE index 01 = successfulOutcome,
    /// then padding to the octet boundary), octet 1 = procedureCode 21,
    /// octet 2 = criticality reject (00 in the top two bits), octet 3 = open
    /// type length 3, then the empty-IE body 00 00 00.
    #[test]
    fn ngsetup_response_framing_dispatch_and_roundtrip() {
        let bytes = empty_ie_pdu(
            FixtureOutcome::Successful,
            PROCEDURE_CODE_NG_SETUP,
            Criticality::reject,
        );
        let pdu = decode(&bytes, DecodeContext::default()).unwrap();
        match &pdu.kind {
            PduKind::Successful {
                procedure_code,
                criticality,
                message,
            } => {
                assert_eq!(*procedure_code, PROCEDURE_CODE_NG_SETUP);
                assert_eq!(*criticality, Criticality::reject);
                match message {
                    Message::NgSetupResponse(resp) => assert!(resp.protocol_ies.0.is_empty()),
                    other => panic!("expected NGSetupResponse, got {other:?}"),
                }
            }
            other => panic!("expected successful outcome, got {other:?}"),
        }
        let encoded = encode(&pdu, raw_preserving_context()).unwrap();
        assert_eq!(encoded, bytes);
    }

    /// Hand-authored unsuccessfulOutcome wrapper: octet 0 = 0x40 (CHOICE
    /// index 10 = unsuccessfulOutcome), then as above.
    #[test]
    fn ngsetup_failure_framing_dispatch_and_roundtrip() {
        let bytes = empty_ie_pdu(
            FixtureOutcome::Unsuccessful,
            PROCEDURE_CODE_NG_SETUP,
            Criticality::reject,
        );
        let pdu = decode(&bytes, DecodeContext::default()).unwrap();
        match &pdu.kind {
            PduKind::Unsuccessful {
                procedure_code,
                message,
                ..
            } => {
                assert_eq!(*procedure_code, PROCEDURE_CODE_NG_SETUP);
                match message {
                    Message::NgSetupFailure(failure) => assert!(failure.protocol_ies.0.is_empty()),
                    other => panic!("expected NGSetupFailure, got {other:?}"),
                }
            }
            other => panic!("expected unsuccessful outcome, got {other:?}"),
        }
        let encoded = encode(&pdu, raw_preserving_context()).unwrap();
        assert_eq!(encoded, bytes);
    }

    #[test]
    fn recognized_invalid_successful_outcome_fails_closed() {
        let bytes = vec![0x20, PROCEDURE_CODE_NG_SETUP, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let err = decode(&bytes, DecodeContext::default()).unwrap_err();
        assert!(matches!(
            err.code(),
            DecodeErrorCode::Structural { reason } if reason.contains("ngsetup response")
        ));
    }

    #[test]
    fn typed_decode_enforces_protocol_ie_count_limit() {
        let bytes = ngsetup_request_fixture();
        assert!(decode(&bytes, DecodeContext::default()).is_ok());

        let ctx = DecodeContext {
            max_ies: 3,
            ..DecodeContext::default()
        };
        let err = decode(&bytes, ctx).unwrap_err();
        assert_eq!(err.code(), &DecodeErrorCode::IeCountExceeded);
    }

    #[test]
    fn typed_decode_enforces_depth_limit() {
        let bytes = ngsetup_request_fixture();
        assert!(decode(&bytes, DecodeContext::default()).is_ok());

        let ctx = DecodeContext {
            max_depth: 4,
            ..DecodeContext::default()
        };
        let err = decode(&bytes, ctx).unwrap_err();
        assert_eq!(err.code(), &DecodeErrorCode::DepthExceeded);
    }

    #[test]
    fn strict_decode_rejects_unknown_reject_criticality_procedure() {
        let bytes = empty_ie_pdu(FixtureOutcome::Initiating, 200, Criticality::reject);
        let default = decode(&bytes, DecodeContext::default()).unwrap();
        match default.kind {
            PduKind::Initiating {
                message: Message::Unknown(body),
                ..
            } => assert_eq!(body.as_ref(), &[0x00, 0x00, 0x00]),
            other => panic!("expected unknown initiating message, got {other:?}"),
        }

        let err = decode(&bytes, DecodeContext::conservative()).unwrap_err();
        assert_eq!(err.code(), &DecodeErrorCode::UnknownCriticalIe);
    }

    #[test]
    fn first_cnf_n2_procedure_dispatch_is_outcome_aware() {
        let cases = [
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_INITIAL_UE,
                "initial ue message",
            ),
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_DOWNLINK_NAS_TRANSPORT,
                "downlink nas transport",
            ),
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_UPLINK_NAS_TRANSPORT,
                "uplink nas transport",
            ),
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_INITIAL_CONTEXT_SETUP,
                "initial context setup request",
            ),
            (
                FixtureOutcome::Successful,
                PROCEDURE_CODE_INITIAL_CONTEXT_SETUP,
                "initial context setup response",
            ),
            (
                FixtureOutcome::Unsuccessful,
                PROCEDURE_CODE_INITIAL_CONTEXT_SETUP,
                "initial context setup failure",
            ),
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP,
                "pdu session resource setup request",
            ),
            (
                FixtureOutcome::Successful,
                PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP,
                "pdu session resource setup response",
            ),
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE,
                "pdu session resource release command",
            ),
            (
                FixtureOutcome::Successful,
                PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE,
                "pdu session resource release response",
            ),
            (
                FixtureOutcome::Initiating,
                PROCEDURE_CODE_UE_CONTEXT_RELEASE,
                "ue context release command",
            ),
            (
                FixtureOutcome::Successful,
                PROCEDURE_CODE_UE_CONTEXT_RELEASE,
                "ue context release complete",
            ),
            (FixtureOutcome::Initiating, PROCEDURE_CODE_PAGING, "paging"),
        ];

        for (outcome, procedure_code, expected) in cases {
            let bytes = empty_ie_pdu(outcome, procedure_code, Criticality::reject);
            let pdu = decode(&bytes, DecodeContext::default()).unwrap();
            let message = match &pdu.kind {
                PduKind::Initiating { message, .. }
                | PduKind::Successful { message, .. }
                | PduKind::Unsuccessful { message, .. } => message,
            };

            let actual = match message {
                Message::InitialUeMessage(msg) if msg.protocol_ies.0.is_empty() => {
                    "initial ue message"
                }
                Message::DownlinkNasTransport(msg) if msg.protocol_ies.0.is_empty() => {
                    "downlink nas transport"
                }
                Message::UplinkNasTransport(msg) if msg.protocol_ies.0.is_empty() => {
                    "uplink nas transport"
                }
                Message::InitialContextSetupRequest(msg) if msg.protocol_ies.0.is_empty() => {
                    "initial context setup request"
                }
                Message::InitialContextSetupResponse(msg) if msg.protocol_ies.0.is_empty() => {
                    "initial context setup response"
                }
                Message::InitialContextSetupFailure(msg) if msg.protocol_ies.0.is_empty() => {
                    "initial context setup failure"
                }
                Message::PduSessionResourceSetupRequest(msg) if msg.protocol_ies.0.is_empty() => {
                    "pdu session resource setup request"
                }
                Message::PduSessionResourceSetupResponse(msg) if msg.protocol_ies.0.is_empty() => {
                    "pdu session resource setup response"
                }
                Message::PduSessionResourceReleaseCommand(msg) if msg.protocol_ies.0.is_empty() => {
                    "pdu session resource release command"
                }
                Message::PduSessionResourceReleaseResponse(msg)
                    if msg.protocol_ies.0.is_empty() =>
                {
                    "pdu session resource release response"
                }
                Message::UeContextReleaseCommand(msg) if msg.protocol_ies.0.is_empty() => {
                    "ue context release command"
                }
                Message::UeContextReleaseComplete(msg) if msg.protocol_ies.0.is_empty() => {
                    "ue context release complete"
                }
                Message::Paging(msg) if msg.protocol_ies.0.is_empty() => "paging",
                other => panic!("unexpected message for procedure {procedure_code}: {other:?}"),
            };

            assert_eq!(actual, expected);
            assert_eq!(encode(&pdu, raw_preserving_context()).unwrap(), bytes);
        }
    }

    #[test]
    fn generated_procedure_constants_match_dispatch_table() {
        assert_eq!(
            generated::ngap_constants::ID_NGSETUP.0,
            PROCEDURE_CODE_NG_SETUP
        );
        assert_eq!(
            generated::ngap_constants::ID_INITIAL_UEMESSAGE.0,
            PROCEDURE_CODE_INITIAL_UE
        );
        assert_eq!(
            generated::ngap_constants::ID_DOWNLINK_NASTRANSPORT.0,
            PROCEDURE_CODE_DOWNLINK_NAS_TRANSPORT
        );
        assert_eq!(
            generated::ngap_constants::ID_UPLINK_NASTRANSPORT.0,
            PROCEDURE_CODE_UPLINK_NAS_TRANSPORT
        );
        assert_eq!(
            generated::ngap_constants::ID_INITIAL_CONTEXT_SETUP.0,
            PROCEDURE_CODE_INITIAL_CONTEXT_SETUP
        );
        assert_eq!(
            generated::ngap_constants::ID_PDUSESSION_RESOURCE_SETUP.0,
            PROCEDURE_CODE_PDU_SESSION_RESOURCE_SETUP
        );
        assert_eq!(
            generated::ngap_constants::ID_PDUSESSION_RESOURCE_RELEASE.0,
            PROCEDURE_CODE_PDU_SESSION_RESOURCE_RELEASE
        );
        assert_eq!(
            generated::ngap_constants::ID_UECONTEXT_RELEASE.0,
            PROCEDURE_CODE_UE_CONTEXT_RELEASE
        );
        assert_eq!(
            generated::ngap_constants::ID_PAGING.0,
            PROCEDURE_CODE_PAGING
        );
    }

    #[test]
    fn raw_preserving_encode_requires_decoded_raw_bytes() {
        let pdu = Pdu {
            raw: Bytes::new(),
            kind: PduKind::Initiating {
                procedure_code: PROCEDURE_CODE_NG_SETUP,
                criticality: Criticality::ignore,
                message: Message::Unknown(Bytes::from_static(b"body")),
            },
        };
        let err = encode(&pdu, raw_preserving_context()).unwrap_err();
        assert!(matches!(
            err.code(),
            EncodeErrorCode::Structural { reason } if reason.contains("decoded raw")
        ));
        let err = pdu.wire_len(raw_preserving_context()).unwrap_err();
        assert!(matches!(
            err.code(),
            EncodeErrorCode::Structural { reason } if reason.contains("decoded raw")
        ));
    }

    #[test]
    fn canonical_wire_len_is_rejected_like_canonical_encode() {
        let bytes = ngsetup_request_fixture();
        let pdu = decode(&bytes, DecodeContext::default()).unwrap();
        assert_eq!(pdu.wire_len(raw_preserving_context()).unwrap(), bytes.len());

        let err = pdu.wire_len(EncodeContext::default()).unwrap_err();
        assert!(matches!(
            err.code(),
            EncodeErrorCode::Structural { reason } if reason.contains("raw-preserving")
        ));
    }

    #[test]
    fn decode_rejects_oversized_input() {
        let ctx = DecodeContext {
            max_message_len: 4,
            ..Default::default()
        };
        let result = decode(&[0; 10], ctx);
        assert!(result.is_err());
    }
}
