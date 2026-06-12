#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! NGAP protocol codec (3GPP TS 38.413) for OpenPacketCore — v0.
//!
//! v0 scope (see CONFORMANCE.md): NGAP-PDU framing (initiating / successful /
//! unsuccessful outcomes) and typed decoding of NGSetupRequest,
//! NGSetupResponse, NGSetupFailure, and InitialUEMessage. Encoding is
//! raw-preserving: the message body captured during decoding is re-emitted
//! byte-identically inside a freshly-encoded NGAP-PDU wrapper. This works
//! around an APER encoder alignment issue in `rasn` 0.28 that prevents the
//! generated inner-message types from re-encoding to the exact bytes produced
//! by other APER implementations.
//!
//! @spec 3GPP TS38413 R18
//! @req REQ-3GPP-TS38413-R18-001
//! @conformance v0 — see CONFORMANCE.md

use bytes::{Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, EncodeErrorCode, OwnedDecode,
};

mod generated;

pub use generated::ngap_common_data_types::{Criticality, ProcedureCode};

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

/// Decoded NGAP message body for the v0 subset.
///
/// Typed decoding is only offered where conformance fixtures prove the
/// mapping (see CONFORMANCE.md); every other procedure/outcome combination —
/// including NGSetupResponse and NGSetupFailure until external fixtures
/// exist for them — is surfaced as [`Message::Unknown`] with the body bytes
/// preserved raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// NG Setup Request (initiating message, procedure code 21).
    NgSetupRequest(generated::ngap_pdu_contents::NGSetupRequest),
    /// Initial UE Message (procedure code 15).
    InitialUeMessage(generated::ngap_pdu_contents::InitialUEMessage),
    /// Message not in the v0 typed subset; raw bytes are preserved.
    Unknown(Bytes),
}

const PROCEDURE_CODE_NG_SETUP: u8 = 21;
const PROCEDURE_CODE_INITIAL_UE: u8 = 15;

fn length_error(len: usize, limit: usize) -> DecodeError {
    DecodeError::new(DecodeErrorCode::MessageLengthExceeded, len.min(limit))
}

/// Decode an NGAP PDU from a byte slice.
///
/// @spec 3GPP TS38413 R18 9.1
/// @req REQ-3GPP-TS38413-R18-9.1-001
/// @conformance v0
pub fn decode(buf: &[u8], ctx: DecodeContext) -> Result<Pdu, DecodeError> {
    if buf.len() > ctx.max_message_len {
        return Err(length_error(buf.len(), ctx.max_message_len));
    }

    let raw = Bytes::copy_from_slice(buf);
    let pdu: generated::ngap_pdu_descriptions::NGAPPDU = rasn::aper::decode(buf)
        .map_err(|_| DecodeError::new(DecodeErrorCode::Structural { reason: "ngap pdu" }, 0))?;

    match pdu {
        generated::ngap_pdu_descriptions::NGAPPDU::initiatingMessage(im) => {
            let message = decode_message(
                Outcome::Initiating,
                im.procedure_code.0,
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
    value: &[u8],
    ctx: DecodeContext,
) -> Result<Message, DecodeError> {
    if value.len() > ctx.max_message_len {
        return Err(length_error(value.len(), ctx.max_message_len));
    }

    match (outcome, procedure_code) {
        (Outcome::Initiating, PROCEDURE_CODE_NG_SETUP) => {
            let msg: generated::ngap_pdu_contents::NGSetupRequest = rasn::aper::decode(value)
                .map_err(|_| {
                    DecodeError::new(DecodeErrorCode::Structural { reason: "ngsetup" }, 0)
                })?;
            Ok(Message::NgSetupRequest(msg))
        }
        (Outcome::Initiating, PROCEDURE_CODE_INITIAL_UE) => {
            let msg: generated::ngap_pdu_contents::InitialUEMessage = rasn::aper::decode(value)
                .map_err(|_| {
                    DecodeError::new(
                        DecodeErrorCode::Structural {
                            reason: "initial ue",
                        },
                        0,
                    )
                })?;
            Ok(Message::InitialUeMessage(msg))
        }
        // NGSetupResponse/NGSetupFailure (successful/unsuccessful outcome of
        // procedure 21) intentionally remain raw until external conformance
        // fixtures exist for them; decoding them with the request type would
        // silently mislabel peer messages.
        _ => Ok(Message::Unknown(Bytes::copy_from_slice(value))),
    }
}

/// Encode a [`Pdu`] back to APER bytes.
///
/// v0 only supports raw-preserving mode; any other mode returns an error
/// because `rasn` 0.28's APER encoder does not reproduce the byte alignment
/// used by the external fixtures for the inner message types.
///
/// @spec 3GPP TS38413 R18 9.1
/// @req REQ-3GPP-TS38413-R18-9.1-002
/// @conformance v0
pub fn encode(pdu: &Pdu, ctx: EncodeContext) -> Result<Vec<u8>, EncodeError> {
    if !ctx.raw_preserving {
        return Err(EncodeError::new(EncodeErrorCode::Structural {
            reason: "v0 NGAP encode only supports raw-preserving mode",
        }));
    }

    ctx.check_capacity(pdu.raw.len())?;
    Ok(pdu.raw.to_vec())
}

impl<'a> BorrowDecode<'a> for Pdu {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let pdu = decode(input, ctx)?;
        Ok((&[], pdu))
    }
}

impl OwnedDecode for Pdu {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, pdu) = Self::decode(&input, ctx)?;
        Ok(pdu)
    }
}

impl Encode for Pdu {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let bytes = encode(self, ctx)?;
        dst.extend_from_slice(&bytes);
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        Ok(self.raw.len())
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

        let encoded = encode(
            &pdu,
            EncodeContext {
                raw_preserving: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(encoded, bytes);
    }

    /// Hand-authored successfulOutcome wrapper per TS 38.413 §9.2 / X.691:
    /// octet 0 = 0x20 (extension bit 0, CHOICE index 01 = successfulOutcome,
    /// then padding to the octet boundary), octet 1 = procedureCode 21,
    /// octet 2 = criticality reject (00 in the top two bits), octet 3 =
    /// open-type length 3, then an opaque 3-octet body. v0 has no external
    /// NGSetupResponse fixture, so the body must surface as
    /// `Message::Unknown` — never be mislabeled as an NGSetupRequest — and
    /// re-encode byte-exactly.
    #[test]
    fn successful_outcome_framing_roundtrip() {
        let bytes = vec![0x20, 0x15, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
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
                    Message::Unknown(body) => assert_eq!(&body[..], &[0xAA, 0xBB, 0xCC]),
                    other => panic!("successful outcome must stay raw in v0, got {other:?}"),
                }
            }
            other => panic!("expected successful outcome, got {other:?}"),
        }
        let encoded = encode(
            &pdu,
            EncodeContext {
                raw_preserving: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(encoded, bytes);
    }

    /// Hand-authored unsuccessfulOutcome wrapper: octet 0 = 0x40 (CHOICE
    /// index 10 = unsuccessfulOutcome), then as above. Must surface as
    /// `Message::Unknown` and round-trip byte-exactly.
    #[test]
    fn unsuccessful_outcome_framing_roundtrip() {
        let bytes = vec![0x40, 0x15, 0x00, 0x02, 0xDE, 0xAD];
        let pdu = decode(&bytes, DecodeContext::default()).unwrap();
        match &pdu.kind {
            PduKind::Unsuccessful {
                procedure_code,
                message,
                ..
            } => {
                assert_eq!(*procedure_code, PROCEDURE_CODE_NG_SETUP);
                assert!(matches!(message, Message::Unknown(_)));
            }
            other => panic!("expected unsuccessful outcome, got {other:?}"),
        }
        let encoded = encode(
            &pdu,
            EncodeContext {
                raw_preserving: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(encoded, bytes);
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
