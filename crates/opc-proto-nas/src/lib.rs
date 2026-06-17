#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! NAS-5GS protocol codec (TS 24.501) for OpenPacketCore — v2.
//!
//! v2 scope (see CONFORMANCE.md): plain 5GMM and 5GSM header parsing,
//! security-protected envelope framing with algorithm hooks, 5GS mobile
//! identity decoding, BCD digit unpacking for PLMN/routing indicator/IMEI/
//! IMEISV, and first-CNF message body dispatch. Registration Request,
//! Registration Accept, Security Mode Command, and Security Mode Complete are
//! structurally decoded; other registered 5GMM/5GSM bodies are named and
//! preserved raw.
//!
//! NAS PDUs carry no internal length framing — the transport (NGAP, N1)
//! delimits them — so decoding consumes the entire input slice.
//!
//! @spec 3GPP TS24501 R18
//! @req REQ-3GPP-TS24501-R18-001
//! @conformance v2 — see CONFORMANCE.md

pub mod bcd;
pub mod identity;
pub mod messages;
pub mod security;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode, EncodeContext,
    EncodeError, OwnedDecode, SpecRef, ValidationLevel,
};

pub use bcd::{unpack_imei, unpack_plmn, unpack_routing_indicator, BcdError, Plmn};
pub use identity::{GutiView, IdentityType, IdentityView, MobileIdentity, SuciView};
pub use messages::{
    decode_mm_message_body, decode_sm_message_body, MmMessageBody, NasKeySetIdentifier, OptionalIe,
    RawMessageBody, RegistrationAccept, RegistrationRequest, RegistrationResult, RegistrationType,
    SecurityModeCommand, SecurityModeComplete, SelectedNasSecurityAlgorithms, SmMessageBody,
};
pub use security::{
    NasCipheringAlgorithm, NasCount, NasIntegrityAlgorithm, NasReplayWindow, NasSecurityAlgorithms,
    NasSecurityContext, NasSecurityDirection, NasSecurityError, NullNasSecurityAlgorithms,
    VerifiedNasPayload,
};

/// Extended protocol discriminator for 5GS mobility management (TS 24.007).
pub const EPD_5GMM: u8 = 0x7E;
/// Extended protocol discriminator for 5GS session management (TS 24.007).
pub const EPD_5GSM: u8 = 0x2E;

/// Security header type values (TS 24.501 §9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityHeaderType {
    /// Plain 5GS NAS message, not security protected (0).
    Plain = 0,
    /// Integrity protected (1).
    IntegrityProtected = 1,
    /// Integrity protected and ciphered (2).
    IntegrityProtectedAndCiphered = 2,
    /// Integrity protected with new 5G NAS security context (3).
    IntegrityProtectedNewContext = 3,
    /// Integrity protected and ciphered with new 5G NAS security context (4).
    IntegrityProtectedAndCipheredNewContext = 4,
}

impl SecurityHeaderType {
    fn from_nibble(value: u8) -> Option<Self> {
        match value & 0x0F {
            0 => Some(Self::Plain),
            1 => Some(Self::IntegrityProtected),
            2 => Some(Self::IntegrityProtectedAndCiphered),
            3 => Some(Self::IntegrityProtectedNewContext),
            4 => Some(Self::IntegrityProtectedAndCipheredNewContext),
            _ => None,
        }
    }

    /// `true` when the security header type carries a ciphered payload.
    pub const fn is_ciphered(self) -> bool {
        matches!(
            self,
            Self::IntegrityProtectedAndCiphered | Self::IntegrityProtectedAndCipheredNewContext
        )
    }
}

/// 5GMM message types (TS 24.501 Table 9.7.1), names and code points only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Names are 1:1 with the TS 24.501 table entries.
pub enum MmMessageType {
    RegistrationRequest = 0x41,
    RegistrationAccept = 0x42,
    RegistrationComplete = 0x43,
    RegistrationReject = 0x44,
    DeregistrationRequestUeOriginating = 0x45,
    DeregistrationAcceptUeOriginating = 0x46,
    DeregistrationRequestUeTerminated = 0x47,
    DeregistrationAcceptUeTerminated = 0x48,
    ServiceRequest = 0x4C,
    ServiceReject = 0x4D,
    ServiceAccept = 0x4E,
    ControlPlaneServiceRequest = 0x4F,
    ConfigurationUpdateCommand = 0x54,
    ConfigurationUpdateComplete = 0x55,
    AuthenticationRequest = 0x56,
    AuthenticationResponse = 0x57,
    AuthenticationReject = 0x58,
    AuthenticationFailure = 0x59,
    AuthenticationResult = 0x5A,
    IdentityRequest = 0x5B,
    IdentityResponse = 0x5C,
    SecurityModeCommand = 0x5D,
    SecurityModeComplete = 0x5E,
    SecurityModeReject = 0x5F,
    Status5gmm = 0x64,
    Notification = 0x65,
    NotificationResponse = 0x66,
    UlNasTransport = 0x67,
    DlNasTransport = 0x68,
}

impl MmMessageType {
    /// Look up a 5GMM message type by code point; `None` for codes not in
    /// the v2 registry (the message still decodes — the raw code is always
    /// available on the header).
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x41 => Self::RegistrationRequest,
            0x42 => Self::RegistrationAccept,
            0x43 => Self::RegistrationComplete,
            0x44 => Self::RegistrationReject,
            0x45 => Self::DeregistrationRequestUeOriginating,
            0x46 => Self::DeregistrationAcceptUeOriginating,
            0x47 => Self::DeregistrationRequestUeTerminated,
            0x48 => Self::DeregistrationAcceptUeTerminated,
            0x4C => Self::ServiceRequest,
            0x4D => Self::ServiceReject,
            0x4E => Self::ServiceAccept,
            0x4F => Self::ControlPlaneServiceRequest,
            0x54 => Self::ConfigurationUpdateCommand,
            0x55 => Self::ConfigurationUpdateComplete,
            0x56 => Self::AuthenticationRequest,
            0x57 => Self::AuthenticationResponse,
            0x58 => Self::AuthenticationReject,
            0x59 => Self::AuthenticationFailure,
            0x5A => Self::AuthenticationResult,
            0x5B => Self::IdentityRequest,
            0x5C => Self::IdentityResponse,
            0x5D => Self::SecurityModeCommand,
            0x5E => Self::SecurityModeComplete,
            0x5F => Self::SecurityModeReject,
            0x64 => Self::Status5gmm,
            0x65 => Self::Notification,
            0x66 => Self::NotificationResponse,
            0x67 => Self::UlNasTransport,
            0x68 => Self::DlNasTransport,
            _ => return None,
        })
    }
}

/// 5GSM message types (TS 24.501 Table 9.7.2), names and code points only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Names are 1:1 with the TS 24.501 table entries.
pub enum SmMessageType {
    PduSessionEstablishmentRequest = 0xC1,
    PduSessionEstablishmentAccept = 0xC2,
    PduSessionEstablishmentReject = 0xC3,
    PduSessionAuthenticationCommand = 0xC5,
    PduSessionAuthenticationComplete = 0xC6,
    PduSessionAuthenticationResult = 0xC7,
    PduSessionModificationRequest = 0xC9,
    PduSessionModificationReject = 0xCA,
    PduSessionModificationCommand = 0xCB,
    PduSessionModificationComplete = 0xCC,
    PduSessionModificationCommandReject = 0xCD,
    PduSessionReleaseRequest = 0xD1,
    PduSessionReleaseReject = 0xD2,
    PduSessionReleaseCommand = 0xD3,
    PduSessionReleaseComplete = 0xD4,
    Status5gsm = 0xD6,
}

impl SmMessageType {
    /// Look up a 5GSM message type by code point; `None` for codes not in
    /// the v2 registry.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0xC1 => Self::PduSessionEstablishmentRequest,
            0xC2 => Self::PduSessionEstablishmentAccept,
            0xC3 => Self::PduSessionEstablishmentReject,
            0xC5 => Self::PduSessionAuthenticationCommand,
            0xC6 => Self::PduSessionAuthenticationComplete,
            0xC7 => Self::PduSessionAuthenticationResult,
            0xC9 => Self::PduSessionModificationRequest,
            0xCA => Self::PduSessionModificationReject,
            0xCB => Self::PduSessionModificationCommand,
            0xCC => Self::PduSessionModificationComplete,
            0xCD => Self::PduSessionModificationCommandReject,
            0xD1 => Self::PduSessionReleaseRequest,
            0xD2 => Self::PduSessionReleaseReject,
            0xD3 => Self::PduSessionReleaseCommand,
            0xD4 => Self::PduSessionReleaseComplete,
            0xD6 => Self::Status5gsm,
            _ => return None,
        })
    }
}

/// Plain 5GMM message: EPD 0x7E with security header type 0.
///
/// @spec 3GPP TS24501 R18 9.1.1
/// @req REQ-3GPP-TS24501-R18-9.1.1-001
/// @conformance v2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainMm {
    /// Spare high nibble of the security-header octet (must be 0 in strict
    /// mode; preserved for byte-exact re-encode otherwise).
    pub spare: u8,
    /// Message type code point (consult [`MmMessageType::from_u8`]).
    pub message_type: u8,
    /// Everything after the 3-octet header, raw until [`PlainMm::decode_body`]
    /// is called.
    pub body: Bytes,
}

impl PlainMm {
    /// Decode the raw body according to this 5GMM message type.
    pub fn decode_body(&self, ctx: DecodeContext) -> Result<MmMessageBody, DecodeError> {
        messages::decode_mm_message_body(self.message_type, &self.body, ctx)
    }
}

/// Security-protected 5GS NAS envelope (TS 24.501 §9.1.1): framed with MAC,
/// sequence number, and protected payload.
///
/// @spec 3GPP TS24501 R18 9.1.1
/// @req REQ-3GPP-TS24501-R18-9.1.1-002
/// @conformance v2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityProtected {
    /// Security header type (1–4).
    pub security_header_type: SecurityHeaderType,
    /// Spare high nibble of the security-header octet.
    pub spare: u8,
    /// Message authentication code, as received.
    pub mac: [u8; 4],
    /// NAS sequence number.
    pub sequence_number: u8,
    /// The protected payload (a complete inner NAS message, possibly
    /// ciphered), raw.
    pub payload: Bytes,
}

/// 5GSM message: EPD 0x2E.
///
/// @spec 3GPP TS24501 R18 9.1.1
/// @req REQ-3GPP-TS24501-R18-9.1.1-003
/// @conformance v2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sm {
    /// PDU session identity (octet 2).
    pub pdu_session_id: u8,
    /// Procedure transaction identity (octet 3).
    pub pti: u8,
    /// Message type code point (consult [`SmMessageType::from_u8`]).
    pub message_type: u8,
    /// Everything after the 4-octet header, raw until [`Sm::decode_body`] is
    /// called.
    pub body: Bytes,
}

impl Sm {
    /// Decode the raw body according to this 5GSM message type.
    pub fn decode_body(&self, ctx: DecodeContext) -> Result<SmMessageBody, DecodeError> {
        messages::decode_sm_message_body(self.message_type, &self.body, ctx)
    }
}

/// A decoded 5GS NAS message at v2 granularity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NasMessage {
    /// Plain (unprotected) 5GMM message.
    PlainMm(PlainMm),
    /// Security-protected envelope (5GMM EPD with security header type 1–4).
    SecurityProtected(SecurityProtected),
    /// 5GSM message.
    Sm(Sm),
}

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS24501", "9.1.1")
}

impl<'a> BorrowDecode<'a> for NasMessage {
    /// Decode a NAS-5GS PDU.
    ///
    /// NAS has no internal length framing, so the entire input is consumed
    /// and the returned remainder is always empty.
    ///
    /// @spec 3GPP TS24501 R18 9.1.1
    /// @req REQ-3GPP-TS24501-R18-9.1.1-004
    /// @conformance v2
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(spec_ref()));
        }
        if input.is_empty() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref()));
        }

        let strict = ctx.validation_level == ValidationLevel::Strict
            || ctx.validation_level == ValidationLevel::ProcedureAware;

        let msg =
            match input[0] {
                EPD_5GMM => {
                    if input.len() < 3 {
                        return Err(DecodeError::new(DecodeErrorCode::Truncated, 1)
                            .with_spec_ref(spec_ref()));
                    }
                    let sht_octet = input[1];
                    let spare = sht_octet >> 4;
                    if strict && spare != 0 {
                        return Err(DecodeError::new(
                            DecodeErrorCode::Structural {
                                reason: "security header spare nibble must be zero",
                            },
                            1,
                        )
                        .with_spec_ref(spec_ref()));
                    }
                    let sht = SecurityHeaderType::from_nibble(sht_octet).ok_or_else(|| {
                        DecodeError::new(
                            DecodeErrorCode::InvalidEnumValue {
                                field: "security_header_type",
                                value: u64::from(sht_octet & 0x0F),
                            },
                            1,
                        )
                        .with_spec_ref(spec_ref())
                    })?;

                    match sht {
                        SecurityHeaderType::Plain => NasMessage::PlainMm(PlainMm {
                            spare,
                            message_type: input[2],
                            body: Bytes::copy_from_slice(&input[3..]),
                        }),
                        protected => {
                            // EPD + SHT + MAC(4) + SEQ = 7 octets minimum.
                            if input.len() < 7 {
                                return Err(DecodeError::new(DecodeErrorCode::Truncated, 2)
                                    .with_spec_ref(spec_ref()));
                            }
                            NasMessage::SecurityProtected(SecurityProtected {
                                security_header_type: protected,
                                spare,
                                mac: [input[2], input[3], input[4], input[5]],
                                sequence_number: input[6],
                                payload: Bytes::copy_from_slice(&input[7..]),
                            })
                        }
                    }
                }
                EPD_5GSM => {
                    if input.len() < 4 {
                        return Err(DecodeError::new(DecodeErrorCode::Truncated, 1)
                            .with_spec_ref(spec_ref()));
                    }
                    NasMessage::Sm(Sm {
                        pdu_session_id: input[1],
                        pti: input[2],
                        message_type: input[3],
                        body: Bytes::copy_from_slice(&input[4..]),
                    })
                }
                other => {
                    return Err(DecodeError::new(
                        DecodeErrorCode::InvalidEnumValue {
                            field: "extended_protocol_discriminator",
                            value: u64::from(other),
                        },
                        0,
                    )
                    .with_spec_ref(spec_ref()));
                }
            };

        Ok((&[], msg))
    }
}

impl OwnedDecode for NasMessage {
    /// Decode from an owned buffer; see the `BorrowDecode` impl for
    /// semantics.
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for NasMessage {
    /// Re-encode the message; byte-exact with the decoded input because all
    /// unparsed regions are preserved raw.
    fn encode(&self, dst: &mut BytesMut, _ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            NasMessage::PlainMm(m) => {
                dst.put_u8(EPD_5GMM);
                dst.put_u8(m.spare << 4); // security header type 0
                dst.put_u8(m.message_type);
                dst.put_slice(&m.body);
            }
            NasMessage::SecurityProtected(m) => {
                dst.put_u8(EPD_5GMM);
                dst.put_u8((m.spare << 4) | (m.security_header_type as u8));
                dst.put_slice(&m.mac);
                dst.put_u8(m.sequence_number);
                dst.put_slice(&m.payload);
            }
            NasMessage::Sm(m) => {
                dst.put_u8(EPD_5GSM);
                dst.put_u8(m.pdu_session_id);
                dst.put_u8(m.pti);
                dst.put_u8(m.message_type);
                dst.put_slice(&m.body);
            }
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        Ok(match self {
            NasMessage::PlainMm(m) => 3 + m.body.len(),
            NasMessage::SecurityProtected(m) => 7 + m.payload.len(),
            NasMessage::Sm(m) => 4 + m.body.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn decode(bytes: &[u8]) -> NasMessage {
        let (rest, msg) = NasMessage::decode(bytes, DecodeContext::default()).unwrap();
        assert!(rest.is_empty(), "NAS decode must consume the whole input");
        msg
    }

    fn assert_byte_exact_roundtrip(bytes: &[u8]) {
        let msg = decode(bytes);
        let mut buf = BytesMut::new();
        msg.encode(&mut buf, EncodeContext::default()).unwrap();
        assert_eq!(&buf[..], bytes, "round-trip not byte-exact");
        assert_eq!(msg.wire_len(EncodeContext::default()).unwrap(), bytes.len());
    }

    /// Hand-authored per TS 24.501 §8.2.6/§9.1.1: plain Registration
    /// Request frame (EPD 0x7E, SHT 0, message type 0x41).
    #[test]
    fn test_plain_mm_registration_request() {
        let bytes: &[u8] = &[0x7E, 0x00, 0x41, 0xAA, 0xBB];
        match decode(bytes) {
            NasMessage::PlainMm(m) => {
                assert_eq!(m.spare, 0);
                assert_eq!(m.message_type, 0x41);
                assert_eq!(
                    MmMessageType::from_u8(m.message_type),
                    Some(MmMessageType::RegistrationRequest)
                );
                assert_eq!(&m.body[..], &[0xAA, 0xBB]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_byte_exact_roundtrip(bytes);
    }

    /// Security-protected envelope (SHT 2 = integrity protected and
    /// ciphered): EPD, SHT, MAC(4), SEQ, payload.
    #[test]
    fn test_security_protected_envelope() {
        let bytes: &[u8] = &[0x7E, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x07, 0x7E, 0x00, 0x41];
        match decode(bytes) {
            NasMessage::SecurityProtected(m) => {
                assert_eq!(
                    m.security_header_type,
                    SecurityHeaderType::IntegrityProtectedAndCiphered
                );
                assert_eq!(m.mac, [0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(m.sequence_number, 0x07);
                assert_eq!(&m.payload[..], &[0x7E, 0x00, 0x41]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_byte_exact_roundtrip(bytes);
    }

    /// 5GSM PDU Session Establishment Request: EPD 0x2E, PSI, PTI, type.
    #[test]
    fn test_sm_establishment_request() {
        let bytes: &[u8] = &[0x2E, 0x01, 0x05, 0xC1, 0x99];
        match decode(bytes) {
            NasMessage::Sm(m) => {
                assert_eq!(m.pdu_session_id, 1);
                assert_eq!(m.pti, 5);
                assert_eq!(
                    SmMessageType::from_u8(m.message_type),
                    Some(SmMessageType::PduSessionEstablishmentRequest)
                );
                assert_eq!(&m.body[..], &[0x99]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_byte_exact_roundtrip(bytes);
    }

    #[test]
    fn test_unknown_epd_rejected() {
        let result = NasMessage::decode(&[0x99, 0x00, 0x41], DecodeContext::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_reserved_security_header_type_rejected() {
        let result = NasMessage::decode(&[0x7E, 0x0F, 0x41], DecodeContext::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_inputs_rejected() {
        for bytes in [
            &[][..],
            &[0x7E][..],
            &[0x7E, 0x00][..],
            &[0x7E, 0x02, 0xDE, 0xAD, 0xBE, 0xEF][..], // secured needs 7
            &[0x2E, 0x01, 0x05][..],
        ] {
            assert!(
                NasMessage::decode(bytes, DecodeContext::default()).is_err(),
                "should reject {bytes:02X?}"
            );
        }
    }

    /// Strict mode rejects a non-zero spare nibble; the default
    /// (Structural) level preserves it byte-exactly instead.
    #[test]
    fn test_spare_nibble_strict_vs_structural() {
        let bytes: &[u8] = &[0x7E, 0x10, 0x41];
        assert_byte_exact_roundtrip(bytes);

        let strict = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..Default::default()
        };
        assert!(NasMessage::decode(bytes, strict).is_err());
    }

    /// Hand-authored 5G-GUTI identity content (11 octets, §9.11.3.4):
    /// 0xF2 type octet, PLMN, AMF region/set/pointer, 5G-TMSI.
    #[test]
    fn test_mobile_identity_guti() {
        let content: &[u8] = &[
            0xF2, // spare 1111, even, type 2 (5G-GUTI)
            0x02, 0xF8, 0x39, // PLMN BCD
            0x11, // AMF region id
            0x01, 0x41, // AMF set id 0x005 (= 0b0000000101), pointer 0x01
            0xDE, 0xAD, 0xBE, 0xEF, // 5G-TMSI
        ];
        let id = MobileIdentity::decode(content).unwrap();
        assert_eq!(id.identity_type, IdentityType::Guti5g);
        match &id.view {
            IdentityView::Guti(g) => {
                assert_eq!(g.plmn, [0x02, 0xF8, 0x39]);
                assert_eq!(g.amf_region_id, 0x11);
                assert_eq!(g.amf_set_id, 0b00_0000_0101);
                assert_eq!(g.amf_pointer, 0x01);
                assert_eq!(g.tmsi, 0xDEAD_BEEF);
            }
            other => panic!("wrong view: {other:?}"),
        }
        let mut buf = BytesMut::new();
        id.encode(&mut buf).unwrap();
        assert_eq!(&buf[..], content);
    }

    /// Hand-authored IMSI-format SUCI with the null protection scheme.
    #[test]
    fn test_mobile_identity_suci_imsi() {
        let content: &[u8] = &[
            0x01, // supi format 0 (IMSI), type 1 (SUCI)
            0x02, 0xF8, 0x39, // PLMN BCD
            0x21, 0xF3, // routing indicator BCD
            0x00, // null protection scheme
            0x00, // home network public key id
            0x13, 0x57, 0x9A, // scheme output (MSIN BCD)
        ];
        let id = MobileIdentity::decode(content).unwrap();
        assert_eq!(id.identity_type, IdentityType::Suci);
        match &id.view {
            IdentityView::Suci(SuciView::Imsi {
                plmn,
                routing_indicator,
                protection_scheme_id,
                home_network_pki,
                scheme_output,
            }) => {
                assert_eq!(*plmn, [0x02, 0xF8, 0x39]);
                assert_eq!(*routing_indicator, [0x21, 0xF3]);
                assert_eq!(*protection_scheme_id, 0);
                assert_eq!(*home_network_pki, 0);
                assert_eq!(&scheme_output[..], &[0x13, 0x57, 0x9A]);
            }
            other => panic!("wrong view: {other:?}"),
        }
    }

    /// NAI-format SUCI (SUPI format 1) keeps the NAI raw.
    #[test]
    fn test_mobile_identity_suci_nai() {
        let mut content = vec![0x11]; // supi format 1, type 1
        content.extend_from_slice(b"user@example.com");
        let id = MobileIdentity::decode(&content).unwrap();
        match &id.view {
            IdentityView::Suci(SuciView::Nai { nai }) => {
                assert_eq!(&nai[..], b"user@example.com");
            }
            other => panic!("wrong view: {other:?}"),
        }
    }

    #[test]
    fn test_mobile_identity_guti_wrong_length_rejected() {
        assert!(MobileIdentity::decode(&[0xF2, 0x02, 0xF8]).is_err());
        assert!(MobileIdentity::decode(&[0xF2u8; 12]).is_err());
    }

    #[test]
    fn test_mobile_identity_empty_rejected() {
        assert!(MobileIdentity::decode(&[]).is_err());
    }

    #[test]
    fn test_mobile_identity_imei_odd_indicator() {
        // type 3 (IMEI), odd indicator set, first digit 9, plus BCD octets.
        let id = MobileIdentity::decode(&[0x9B, 0x10, 0x32]).unwrap();
        assert_eq!(id.identity_type, IdentityType::Imei);
        assert_eq!(id.odd_digit_indicator(), Some(true));
        assert!(matches!(id.view, IdentityView::Raw));
    }

    quickcheck::quickcheck! {
        /// Property: any well-formed security-protected frame round-trips
        /// byte-exactly (MAC, sequence, and opaque payload preserved).
        fn prop_secured_envelope_roundtrip(mac: (u8, u8, u8, u8), seq: u8, payload: Vec<u8>) -> bool {
            let mut bytes = vec![0x7E, 0x01, mac.0, mac.1, mac.2, mac.3, seq];
            bytes.extend_from_slice(&payload);

            let (rest, msg) = match NasMessage::decode(&bytes, DecodeContext::default()) {
                Ok(v) => v,
                Err(_) => return false,
            };
            if !rest.is_empty() {
                return false;
            }
            let mut buf = BytesMut::new();
            if msg.encode(&mut buf, EncodeContext::default()).is_err() {
                return false;
            }
            buf.freeze() == bytes
        }
    }
}
