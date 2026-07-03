//! Parsed 5GMM message bodies (TS 24.501 §8.2).
//!
//! v2 adds first-CNF message body dispatch plus selected IE-level decoding for
//! Registration Request, Registration Accept, Security Mode Command, and
//! Security Mode Complete. Message bodies outside the typed subset are
//! raw-preserved through named variants.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, DuplicateIePolicy,
    Encode, EncodeContext, EncodeError, OwnedDecode, SpecRef, UnknownIePolicy, ValidationLevel,
};

use crate::{
    identity::MobileIdentity, MmMessageType, NasCipheringAlgorithm, NasIntegrityAlgorithm,
    SmMessageType,
};

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS24501", "8.2")
}

fn message_spec_ref(section: &'static str) -> SpecRef {
    SpecRef::new("3gpp", "TS24501", section)
}

/// 5GS registration-type values (TS 24.501 §9.11.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationType {
    /// Initial registration (001).
    InitialRegistration = 0x01,
    /// Mobility registration updating (010).
    MobilityRegistrationUpdating = 0x02,
    /// Periodic registration updating (011).
    PeriodicRegistrationUpdating = 0x03,
    /// Emergency registration (100).
    EmergencyRegistration = 0x04,
}

impl RegistrationType {
    /// Map the 3-bit value to the enum; `None` for reserved codes.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value & 0x07 {
            0x01 => Self::InitialRegistration,
            0x02 => Self::MobilityRegistrationUpdating,
            0x03 => Self::PeriodicRegistrationUpdating,
            0x04 => Self::EmergencyRegistration,
            _ => return None,
        })
    }
}

/// 5GS registration-result values (TS 24.501 §9.11.3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResult {
    /// 3GPP access (001).
    Access3gpp = 0x01,
    /// Non-3GPP access (010).
    AccessNon3gpp = 0x02,
    /// 3GPP access and non-3GPP access (011).
    AccessBoth = 0x03,
}

impl RegistrationResult {
    /// Map the 3-bit value to the enum; `None` for reserved codes.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value & 0x07 {
            0x01 => Self::Access3gpp,
            0x02 => Self::AccessNon3gpp,
            0x03 => Self::AccessBoth,
            _ => return None,
        })
    }
}

/// Selected NAS security algorithms (TS 24.501 §9.11.3.34).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedNasSecurityAlgorithms {
    /// Selected ciphering algorithm.
    pub ciphering: NasCipheringAlgorithm,
    /// Selected integrity algorithm.
    pub integrity: NasIntegrityAlgorithm,
    /// Original algorithm octet.
    pub raw: u8,
}

impl SelectedNasSecurityAlgorithms {
    /// Decode selected algorithms from their single-octet representation.
    pub fn from_octet(raw: u8) -> Result<Self, DecodeError> {
        let ciphering = NasCipheringAlgorithm::from_nibble(raw >> 4).ok_or_else(|| {
            DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "nas_ciphering_algorithm",
                    value: u64::from(raw >> 4),
                },
                0,
            )
            .with_spec_ref(message_spec_ref("9.11.3.34"))
        })?;
        let integrity = NasIntegrityAlgorithm::from_nibble(raw & 0x0F).ok_or_else(|| {
            DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "nas_integrity_algorithm",
                    value: u64::from(raw & 0x0F),
                },
                0,
            )
            .with_spec_ref(message_spec_ref("9.11.3.34"))
        })?;
        Ok(Self {
            ciphering,
            integrity,
            raw,
        })
    }
}

/// Raw-preserved NAS message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessageBody {
    /// Original body bytes.
    pub raw: Bytes,
}

impl RawMessageBody {
    /// Capture a raw-preserved message body.
    pub fn new(input: &[u8]) -> Self {
        Self {
            raw: Bytes::copy_from_slice(input),
        }
    }
}

impl<'a> BorrowDecode<'a> for RawMessageBody {
    fn decode(input: &'a [u8], _ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Ok((&[], Self::new(input)))
    }
}

impl OwnedDecode for RawMessageBody {
    fn decode_owned(input: Bytes, _ctx: DecodeContext) -> Result<Self, DecodeError> {
        Ok(Self { raw: input })
    }
}

impl Encode for RawMessageBody {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        ctx.check_capacity(self.raw.len())?;
        dst.extend_from_slice(&self.raw);
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        Ok(self.raw.len())
    }
}

/// Decoded Security Mode Command body (TS 24.501 §8.2.20).
///
/// Mandatory fields are structurally decoded; optional IEs remain
/// raw-preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeCommand {
    /// Selected NAS security algorithms.
    pub selected_algorithms: SelectedNasSecurityAlgorithms,
    /// NAS key set identifier.
    pub ng_ksi: NasKeySetIdentifier,
    /// Original ngKSI octet.
    pub raw_ng_ksi: u8,
    /// Replayed UE security capability value.
    pub replayed_ue_security_capability: Bytes,
    /// Original LV bytes for replayed UE security capability.
    pub raw_replayed_ue_security_capability_lv: Bytes,
    /// Optional IEs in message order, raw-preserved.
    pub optional_ies: Vec<OptionalIe>,
}

impl SecurityModeCommand {
    /// Decode a Security Mode Command from its body bytes.
    pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(message_spec_ref("8.2.20")));
        }
        if input.len() < 4 {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("8.2.20")));
        }

        let selected_algorithms = SelectedNasSecurityAlgorithms::from_octet(input[0])?;
        let raw_ng_ksi = input[1];
        let ng_ksi = NasKeySetIdentifier {
            value: raw_ng_ksi & 0x07,
            no_key_available: (raw_ng_ksi & 0x08) != 0,
        };
        let capability_len = usize::from(input[2]);
        if capability_len == 0 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "replayed UE security capability must not be empty",
                },
                2,
            )
            .with_spec_ref(message_spec_ref("9.11.3.54")));
        }
        let capability_end = 3usize.saturating_add(capability_len);
        if capability_end > input.len() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 2)
                .with_spec_ref(message_spec_ref("9.11.3.54")));
        }

        let raw_replayed_ue_security_capability_lv =
            Bytes::copy_from_slice(&input[2..capability_end]);
        let replayed_ue_security_capability = Bytes::copy_from_slice(&input[3..capability_end]);
        let (_, optional_ies) = decode_optional_ies(&input[capability_end..], ctx)?;

        Ok((
            &[],
            Self {
                selected_algorithms,
                ng_ksi,
                raw_ng_ksi,
                replayed_ue_security_capability,
                raw_replayed_ue_security_capability_lv,
                optional_ies,
            },
        ))
    }
}

impl<'a> BorrowDecode<'a> for SecurityModeCommand {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_body(input, ctx)
    }
}

impl OwnedDecode for SecurityModeCommand {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for SecurityModeCommand {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        dst.put_u8(self.selected_algorithms.raw);
        dst.put_u8(self.raw_ng_ksi);
        dst.extend_from_slice(&self.raw_replayed_ue_security_capability_lv);
        for ie in &self.optional_ies {
            dst.extend_from_slice(&ie.raw);
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let mut len = 2usize.saturating_add(self.raw_replayed_ue_security_capability_lv.len());
        for ie in &self.optional_ies {
            len = len.saturating_add(ie.raw.len());
        }
        Ok(len)
    }
}

/// Decoded Security Mode Complete body (TS 24.501 §8.2.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeComplete {
    /// Optional IEs in message order, raw-preserved.
    pub optional_ies: Vec<OptionalIe>,
}

impl SecurityModeComplete {
    /// Decode a Security Mode Complete from its body bytes.
    pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(message_spec_ref("8.2.21")));
        }
        let (_, optional_ies) = decode_optional_ies(input, ctx)?;
        Ok((&[], Self { optional_ies }))
    }
}

impl<'a> BorrowDecode<'a> for SecurityModeComplete {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_body(input, ctx)
    }
}

impl OwnedDecode for SecurityModeComplete {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for SecurityModeComplete {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        for ie in &self.optional_ies {
            dst.extend_from_slice(&ie.raw);
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let mut len = 0usize;
        for ie in &self.optional_ies {
            len = len.saturating_add(ie.raw.len());
        }
        Ok(len)
    }
}

/// Decoded 5GMM message body for the first-CNF subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmMessageBody {
    /// Registration Request.
    RegistrationRequest(RegistrationRequest),
    /// Registration Accept.
    RegistrationAccept(RegistrationAccept),
    /// Registration Complete.
    RegistrationComplete(RawMessageBody),
    /// Registration Reject.
    RegistrationReject(RawMessageBody),
    /// Service Request.
    ServiceRequest(RawMessageBody),
    /// Service Accept.
    ServiceAccept(RawMessageBody),
    /// Service Reject.
    ServiceReject(RawMessageBody),
    /// Configuration Update Command.
    ConfigurationUpdateCommand(RawMessageBody),
    /// Configuration Update Complete.
    ConfigurationUpdateComplete(RawMessageBody),
    /// Authentication Request.
    AuthenticationRequest(RawMessageBody),
    /// Authentication Response.
    AuthenticationResponse(RawMessageBody),
    /// Authentication Reject.
    AuthenticationReject(RawMessageBody),
    /// Authentication Failure.
    AuthenticationFailure(RawMessageBody),
    /// Authentication Result.
    AuthenticationResult(RawMessageBody),
    /// Identity Request.
    IdentityRequest(RawMessageBody),
    /// Identity Response.
    IdentityResponse(RawMessageBody),
    /// Security Mode Command.
    SecurityModeCommand(SecurityModeCommand),
    /// Security Mode Complete.
    SecurityModeComplete(SecurityModeComplete),
    /// Security Mode Reject.
    SecurityModeReject(RawMessageBody),
    /// 5GMM Status.
    Status5gmm(RawMessageBody),
    /// Notification.
    Notification(RawMessageBody),
    /// Notification Response.
    NotificationResponse(RawMessageBody),
    /// Uplink NAS Transport.
    UlNasTransport(RawMessageBody),
    /// Downlink NAS Transport.
    DlNasTransport(RawMessageBody),
    /// Registered but not in the first-CNF typed subset, or unknown.
    Unknown(RawMessageBody),
}

/// Decoded 5GSM message body for the first-CNF subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmMessageBody {
    /// PDU Session Establishment Request.
    PduSessionEstablishmentRequest(RawMessageBody),
    /// PDU Session Establishment Accept.
    PduSessionEstablishmentAccept(RawMessageBody),
    /// PDU Session Establishment Reject.
    PduSessionEstablishmentReject(RawMessageBody),
    /// PDU Session Authentication Command.
    PduSessionAuthenticationCommand(RawMessageBody),
    /// PDU Session Authentication Complete.
    PduSessionAuthenticationComplete(RawMessageBody),
    /// PDU Session Authentication Result.
    PduSessionAuthenticationResult(RawMessageBody),
    /// PDU Session Modification Request.
    PduSessionModificationRequest(RawMessageBody),
    /// PDU Session Modification Reject.
    PduSessionModificationReject(RawMessageBody),
    /// PDU Session Modification Command.
    PduSessionModificationCommand(RawMessageBody),
    /// PDU Session Modification Complete.
    PduSessionModificationComplete(RawMessageBody),
    /// PDU Session Modification Command Reject.
    PduSessionModificationCommandReject(RawMessageBody),
    /// PDU Session Release Request.
    PduSessionReleaseRequest(RawMessageBody),
    /// PDU Session Release Reject.
    PduSessionReleaseReject(RawMessageBody),
    /// PDU Session Release Command.
    PduSessionReleaseCommand(RawMessageBody),
    /// PDU Session Release Complete.
    PduSessionReleaseComplete(RawMessageBody),
    /// 5GSM Status.
    Status5gsm(RawMessageBody),
    /// Unknown 5GSM message type.
    Unknown(RawMessageBody),
}

fn raw_body(input: &[u8]) -> RawMessageBody {
    RawMessageBody::new(input)
}

/// ngKSI carried in the first half-octet of a Registration Request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasKeySetIdentifier {
    /// Key set identifier value (0–7, bits 5–7).
    pub value: u8,
    /// `true` when no native 5G NAS security context is available (bit 8).
    pub no_key_available: bool,
}

/// A raw optional IE, preserving its original bytes for byte-exact re-encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalIe {
    /// Information-element identifier.
    pub iei: u8,
    /// Value bytes excluding IEI and length octets.
    ///
    /// For type-1 half-octet IEs this is empty because the value is part of
    /// the same octet as the IEI.
    pub value: Bytes,
    /// Full original IE bytes (iei + length + value, or the single type-1
    /// octet). Re-encoding writes this verbatim.
    pub raw: Bytes,
}

/// Format of an optional IE, used to locate its length field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionalIeFormat {
    /// Type 1: single octet, IEI in high nibble, value in low nibble.
    Type1,
    /// Type 3: IEI followed by a fixed-length value of `usize` octets.
    Type3(usize),
    /// Type 4: IEI followed by a one-octet length.
    Type4,
    /// Type 6 (extended): IEI followed by a two-octet length.
    Type6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OptionalIeDescriptor {
    format: OptionalIeFormat,
    registered: bool,
}

fn optional_ie_descriptor(iei: u8) -> OptionalIeDescriptor {
    let (format, registered) = match iei {
        // Known TLV-E IEs used by Registration Request/Accept.
        0x72 | 0x75 | 0x77 | 0x78 | 0x79 | 0x7A | 0x7B | 0x7C => (OptionalIeFormat::Type6, true),
        // Known type-3 TV IEs (value length after the IEI octet).
        0x52 => (OptionalIeFormat::Type3(6), true), // Last visited registered TAI
        // Known type-4 TLV IEs.
        0x10 | 0x11 | 0x15 | 0x17 | 0x18 | 0x21 | 0x25 | 0x26 | 0x27 | 0x2B | 0x2E | 0x2F
        | 0x31 | 0x34 | 0x40 | 0x4A | 0x50 | 0x54 | 0x5D | 0x5E => (OptionalIeFormat::Type4, true),
        // Type-1 half-octet IEIs have the high nibble in the range A-F.
        _ if (iei >> 4) >= 0x0A => (OptionalIeFormat::Type1, true),
        // Extended-length IEIs occupy the 0x70-0x7F range.
        _ if (0x70..=0x7F).contains(&iei) => (OptionalIeFormat::Type6, true),
        // Default: assume type-4 TLV only for contexts that explicitly allow
        // unknown IE preservation/drop. Strict or reject contexts fail before
        // this ambiguous length guess is used.
        _ => (OptionalIeFormat::Type4, false),
    };
    OptionalIeDescriptor { format, registered }
}

fn optional_ie_duplicate_key(iei: u8, format: OptionalIeFormat) -> u8 {
    if matches!(format, OptionalIeFormat::Type1) {
        iei & 0xF0
    } else {
        iei
    }
}

fn rejects_unknown_optional_ie(ctx: DecodeContext) -> bool {
    matches!(ctx.unknown_ie_policy, UnknownIePolicy::Reject)
        || matches!(
            ctx.validation_level,
            ValidationLevel::Strict | ValidationLevel::ProcedureAware
        )
}

fn decode_optional_ies(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Vec<OptionalIe>> {
    let mut out: Vec<OptionalIe> = Vec::new();
    let mut rest = input;
    let mut offset = 0usize;
    let mut ie_count = 0usize;
    let mut seen = [false; 256];

    while !rest.is_empty() {
        if ie_count >= ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                .with_spec_ref(spec_ref()));
        }
        ie_count += 1;
        let iei = rest[0];
        let descriptor = optional_ie_descriptor(iei);
        if !descriptor.registered && rejects_unknown_optional_ie(ctx) {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "unknown optional IE",
                },
                offset,
            )
            .with_spec_ref(spec_ref()));
        }
        let duplicate_key = optional_ie_duplicate_key(iei, descriptor.format);
        let duplicate = seen[usize::from(duplicate_key)];
        if duplicate && matches!(ctx.duplicate_ie_policy, DuplicateIePolicy::Reject) {
            return Err(
                DecodeError::new(DecodeErrorCode::DuplicateIe, offset).with_spec_ref(spec_ref())
            );
        }
        let ie = match descriptor.format {
            OptionalIeFormat::Type1 => {
                let raw = Bytes::copy_from_slice(&rest[..1]);
                rest = &rest[1..];
                offset += 1;
                OptionalIe {
                    iei,
                    value: Bytes::new(),
                    raw,
                }
            }
            OptionalIeFormat::Type3(value_len) => {
                let total = 1usize.saturating_add(value_len);
                if rest.len() < total {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let raw = Bytes::copy_from_slice(&rest[..total]);
                let value = Bytes::copy_from_slice(&rest[1..total]);
                rest = &rest[total..];
                offset += total;
                OptionalIe { iei, value, raw }
            }
            OptionalIeFormat::Type4 => {
                if rest.len() < 2 {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let value_len = usize::from(rest[1]);
                let total = 2usize.saturating_add(value_len);
                if rest.len() < total {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let raw = Bytes::copy_from_slice(&rest[..total]);
                let value = Bytes::copy_from_slice(&rest[2..total]);
                rest = &rest[total..];
                offset += total;
                OptionalIe { iei, value, raw }
            }
            OptionalIeFormat::Type6 => {
                if rest.len() < 3 {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let value_len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
                let total = 3usize.saturating_add(value_len);
                if rest.len() < total {
                    return Err(DecodeError::new(DecodeErrorCode::Truncated, offset)
                        .with_spec_ref(spec_ref()));
                }
                let raw = Bytes::copy_from_slice(&rest[..total]);
                let value = Bytes::copy_from_slice(&rest[3..total]);
                rest = &rest[total..];
                offset += total;
                OptionalIe { iei, value, raw }
            }
        };
        if !descriptor.registered && matches!(ctx.unknown_ie_policy, UnknownIePolicy::Drop) {
            continue;
        }
        if duplicate {
            match ctx.duplicate_ie_policy {
                DuplicateIePolicy::First => continue,
                DuplicateIePolicy::Last => {
                    if let Some(position) = out.iter().position(|existing| {
                        let existing_descriptor = optional_ie_descriptor(existing.iei);
                        optional_ie_duplicate_key(existing.iei, existing_descriptor.format)
                            == duplicate_key
                    }) {
                        out.remove(position);
                    }
                }
                DuplicateIePolicy::Reject => unreachable!("duplicate reject handled before parse"),
            }
        }
        seen[usize::from(duplicate_key)] = true;
        out.push(ie);
    }

    Ok((&[], out))
}

/// Decoded Registration Request body (TS 24.501 §8.2.6).
///
/// The first octet carries the 5GS registration type (low nibble) and ngKSI
/// (high nibble). The mandatory 5GS mobile identity follows as an LV-E
/// (two-octet length + value). All remaining bytes are optional IEs.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistrationRequest {
    /// 5GS registration type.
    pub registration_type: RegistrationType,
    /// Follow-on request pending bit (bit 4 of the first body octet).
    pub follow_on_request: bool,
    /// NAS key set identifier.
    pub ng_ksi: NasKeySetIdentifier,
    /// Decoded 5GS mobile identity.
    pub mobile_identity: MobileIdentity,
    /// Original first body octet (registration type + ngKSI).
    pub raw_first_octet: u8,
    /// Original LV-E bytes for the mobile identity (length + value).
    pub raw_mobile_identity_lv: Bytes,
    /// Optional IEs in message order, raw-preserved.
    pub optional_ies: Vec<OptionalIe>,
}

impl fmt::Debug for RegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationRequest")
            .field("registration_type", &self.registration_type)
            .field("follow_on_request", &self.follow_on_request)
            .field("ng_ksi", &self.ng_ksi)
            .field("mobile_identity", &self.mobile_identity)
            .field("raw_first_octet", &self.raw_first_octet)
            .field("mobile_identity_lv_len", &self.raw_mobile_identity_lv.len())
            .field("optional_ies_len", &self.optional_ies.len())
            .finish()
    }
}

impl RegistrationRequest {
    /// Decode a Registration Request from its body bytes (everything after the
    /// 3-octet plain 5GMM header).
    pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(message_spec_ref("8.2.6")));
        }
        if input.len() < 4 {
            // First octet + 2-octet LV-E length + at least one value octet.
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("8.2.6")));
        }

        let raw_first_octet = input[0];
        let registration_type =
            RegistrationType::from_u8(raw_first_octet & 0x07).ok_or_else(|| {
                DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "5gs_registration_type",
                        value: u64::from(raw_first_octet & 0x07),
                    },
                    0,
                )
                .with_spec_ref(message_spec_ref("9.11.3.7"))
            })?;
        let follow_on_request = (raw_first_octet & 0x08) != 0;
        let ng_ksi = NasKeySetIdentifier {
            value: (raw_first_octet >> 4) & 0x07,
            no_key_available: (raw_first_octet & 0x80) != 0,
        };

        let mi_len = usize::from(u16::from_be_bytes([input[1], input[2]]));
        let mi_end = 3usize.saturating_add(mi_len);
        if mi_end > input.len() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 1)
                .with_spec_ref(message_spec_ref("9.11.3.4")));
        }
        if mi_len < 6 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "5GS mobile identity length below minimum",
                },
                1,
            )
            .with_spec_ref(message_spec_ref("9.11.3.4")));
        }

        let raw_mobile_identity_lv = Bytes::copy_from_slice(&input[1..mi_end]);
        let mobile_identity = MobileIdentity::decode(&input[3..mi_end]).map_err(|e| {
            DecodeError::new(e.code().clone(), 3).with_spec_ref(
                e.spec_ref()
                    .cloned()
                    .unwrap_or_else(|| message_spec_ref("9.11.3.4")),
            )
        })?;

        let (_, optional_ies) = decode_optional_ies(&input[mi_end..], ctx)?;

        Ok((
            &[],
            Self {
                registration_type,
                follow_on_request,
                ng_ksi,
                mobile_identity,
                raw_first_octet,
                raw_mobile_identity_lv,
                optional_ies,
            },
        ))
    }
}

impl<'a> BorrowDecode<'a> for RegistrationRequest {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_body(input, ctx)
    }
}

impl OwnedDecode for RegistrationRequest {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for RegistrationRequest {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        dst.put_u8(self.raw_first_octet);
        dst.extend_from_slice(&self.raw_mobile_identity_lv);
        for ie in &self.optional_ies {
            dst.extend_from_slice(&ie.raw);
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let mut len = 1usize.saturating_add(self.raw_mobile_identity_lv.len());
        for ie in &self.optional_ies {
            len = len.saturating_add(ie.raw.len());
        }
        Ok(len)
    }
}

/// Decoded Registration Accept body (TS 24.501 §8.2.7).
///
/// The mandatory 5GS registration result is an LV IE (one-octet length +
/// one-octet value). All remaining bytes are optional IEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationAccept {
    /// 5GS registration result.
    pub registration_result: RegistrationResult,
    /// Original LV bytes for the registration result.
    pub raw_registration_result_lv: Bytes,
    /// Optional IEs in message order, raw-preserved.
    pub optional_ies: Vec<OptionalIe>,
}

impl RegistrationAccept {
    /// Decode a Registration Accept from its body bytes.
    pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
        if input.len() > ctx.max_message_len {
            return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0)
                .with_spec_ref(message_spec_ref("8.2.7")));
        }
        if input.len() < 2 {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("8.2.7")));
        }

        let result_len = usize::from(input[0]);
        let result_end = 1usize.saturating_add(result_len);
        if result_end > input.len() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0)
                .with_spec_ref(message_spec_ref("9.11.3.6")));
        }
        if result_len != 1 {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason: "5GS registration result length must be 1",
                },
                0,
            )
            .with_spec_ref(message_spec_ref("9.11.3.6")));
        }

        let raw_registration_result_lv = Bytes::copy_from_slice(&input[0..result_end]);
        let registration_result =
            RegistrationResult::from_u8(input[result_len]).ok_or_else(|| {
                DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "5gs_registration_result",
                        value: u64::from(input[result_len]),
                    },
                    result_len,
                )
                .with_spec_ref(message_spec_ref("9.11.3.6"))
            })?;

        let (_, optional_ies) = decode_optional_ies(&input[result_end..], ctx)?;

        Ok((
            &[],
            Self {
                registration_result,
                raw_registration_result_lv,
                optional_ies,
            },
        ))
    }
}

impl<'a> BorrowDecode<'a> for RegistrationAccept {
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        Self::decode_body(input, ctx)
    }
}

impl OwnedDecode for RegistrationAccept {
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let (_, msg) = Self::decode(&input, ctx)?;
        Ok(msg)
    }
}

impl Encode for RegistrationAccept {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        ctx.check_capacity(len)?;
        dst.reserve(len);
        dst.extend_from_slice(&self.raw_registration_result_lv);
        for ie in &self.optional_ies {
            dst.extend_from_slice(&ie.raw);
        }
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        let mut len = self.raw_registration_result_lv.len();
        for ie in &self.optional_ies {
            len = len.saturating_add(ie.raw.len());
        }
        Ok(len)
    }
}

/// Decode a 5GMM body according to the registered message type.
pub fn decode_mm_message_body(
    message_type: u8,
    body: &[u8],
    ctx: DecodeContext,
) -> Result<MmMessageBody, DecodeError> {
    if body.len() > ctx.max_message_len {
        return Err(
            DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0).with_spec_ref(spec_ref())
        );
    }

    Ok(match MmMessageType::from_u8(message_type) {
        Some(MmMessageType::RegistrationRequest) => {
            let (_, msg) = RegistrationRequest::decode_body(body, ctx)?;
            MmMessageBody::RegistrationRequest(msg)
        }
        Some(MmMessageType::RegistrationAccept) => {
            let (_, msg) = RegistrationAccept::decode_body(body, ctx)?;
            MmMessageBody::RegistrationAccept(msg)
        }
        Some(MmMessageType::RegistrationComplete) => {
            MmMessageBody::RegistrationComplete(raw_body(body))
        }
        Some(MmMessageType::RegistrationReject) => {
            MmMessageBody::RegistrationReject(raw_body(body))
        }
        Some(MmMessageType::ServiceRequest) => MmMessageBody::ServiceRequest(raw_body(body)),
        Some(MmMessageType::ServiceAccept) => MmMessageBody::ServiceAccept(raw_body(body)),
        Some(MmMessageType::ServiceReject) => MmMessageBody::ServiceReject(raw_body(body)),
        Some(MmMessageType::ConfigurationUpdateCommand) => {
            MmMessageBody::ConfigurationUpdateCommand(raw_body(body))
        }
        Some(MmMessageType::ConfigurationUpdateComplete) => {
            MmMessageBody::ConfigurationUpdateComplete(raw_body(body))
        }
        Some(MmMessageType::AuthenticationRequest) => {
            MmMessageBody::AuthenticationRequest(raw_body(body))
        }
        Some(MmMessageType::AuthenticationResponse) => {
            MmMessageBody::AuthenticationResponse(raw_body(body))
        }
        Some(MmMessageType::AuthenticationReject) => {
            MmMessageBody::AuthenticationReject(raw_body(body))
        }
        Some(MmMessageType::AuthenticationFailure) => {
            MmMessageBody::AuthenticationFailure(raw_body(body))
        }
        Some(MmMessageType::AuthenticationResult) => {
            MmMessageBody::AuthenticationResult(raw_body(body))
        }
        Some(MmMessageType::IdentityRequest) => MmMessageBody::IdentityRequest(raw_body(body)),
        Some(MmMessageType::IdentityResponse) => MmMessageBody::IdentityResponse(raw_body(body)),
        Some(MmMessageType::SecurityModeCommand) => {
            let (_, msg) = SecurityModeCommand::decode_body(body, ctx)?;
            MmMessageBody::SecurityModeCommand(msg)
        }
        Some(MmMessageType::SecurityModeComplete) => {
            let (_, msg) = SecurityModeComplete::decode_body(body, ctx)?;
            MmMessageBody::SecurityModeComplete(msg)
        }
        Some(MmMessageType::SecurityModeReject) => {
            MmMessageBody::SecurityModeReject(raw_body(body))
        }
        Some(MmMessageType::Status5gmm) => MmMessageBody::Status5gmm(raw_body(body)),
        Some(MmMessageType::Notification) => MmMessageBody::Notification(raw_body(body)),
        Some(MmMessageType::NotificationResponse) => {
            MmMessageBody::NotificationResponse(raw_body(body))
        }
        Some(MmMessageType::UlNasTransport) => MmMessageBody::UlNasTransport(raw_body(body)),
        Some(MmMessageType::DlNasTransport) => MmMessageBody::DlNasTransport(raw_body(body)),
        Some(
            MmMessageType::DeregistrationRequestUeOriginating
            | MmMessageType::DeregistrationAcceptUeOriginating
            | MmMessageType::DeregistrationRequestUeTerminated
            | MmMessageType::DeregistrationAcceptUeTerminated
            | MmMessageType::ControlPlaneServiceRequest,
        )
        | None => MmMessageBody::Unknown(raw_body(body)),
    })
}

/// Decode a 5GSM body according to the registered message type.
pub fn decode_sm_message_body(
    message_type: u8,
    body: &[u8],
    ctx: DecodeContext,
) -> Result<SmMessageBody, DecodeError> {
    if body.len() > ctx.max_message_len {
        return Err(
            DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0).with_spec_ref(spec_ref())
        );
    }

    Ok(match SmMessageType::from_u8(message_type) {
        Some(SmMessageType::PduSessionEstablishmentRequest) => {
            SmMessageBody::PduSessionEstablishmentRequest(raw_body(body))
        }
        Some(SmMessageType::PduSessionEstablishmentAccept) => {
            SmMessageBody::PduSessionEstablishmentAccept(raw_body(body))
        }
        Some(SmMessageType::PduSessionEstablishmentReject) => {
            SmMessageBody::PduSessionEstablishmentReject(raw_body(body))
        }
        Some(SmMessageType::PduSessionAuthenticationCommand) => {
            SmMessageBody::PduSessionAuthenticationCommand(raw_body(body))
        }
        Some(SmMessageType::PduSessionAuthenticationComplete) => {
            SmMessageBody::PduSessionAuthenticationComplete(raw_body(body))
        }
        Some(SmMessageType::PduSessionAuthenticationResult) => {
            SmMessageBody::PduSessionAuthenticationResult(raw_body(body))
        }
        Some(SmMessageType::PduSessionModificationRequest) => {
            SmMessageBody::PduSessionModificationRequest(raw_body(body))
        }
        Some(SmMessageType::PduSessionModificationReject) => {
            SmMessageBody::PduSessionModificationReject(raw_body(body))
        }
        Some(SmMessageType::PduSessionModificationCommand) => {
            SmMessageBody::PduSessionModificationCommand(raw_body(body))
        }
        Some(SmMessageType::PduSessionModificationComplete) => {
            SmMessageBody::PduSessionModificationComplete(raw_body(body))
        }
        Some(SmMessageType::PduSessionModificationCommandReject) => {
            SmMessageBody::PduSessionModificationCommandReject(raw_body(body))
        }
        Some(SmMessageType::PduSessionReleaseRequest) => {
            SmMessageBody::PduSessionReleaseRequest(raw_body(body))
        }
        Some(SmMessageType::PduSessionReleaseReject) => {
            SmMessageBody::PduSessionReleaseReject(raw_body(body))
        }
        Some(SmMessageType::PduSessionReleaseCommand) => {
            SmMessageBody::PduSessionReleaseCommand(raw_body(body))
        }
        Some(SmMessageType::PduSessionReleaseComplete) => {
            SmMessageBody::PduSessionReleaseComplete(raw_body(body))
        }
        Some(SmMessageType::Status5gsm) => SmMessageBody::Status5gsm(raw_body(body)),
        None => SmMessageBody::Unknown(raw_body(body)),
    })
}

impl Encode for MmMessageBody {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            Self::RegistrationRequest(body) => body.encode(dst, ctx),
            Self::RegistrationAccept(body) => body.encode(dst, ctx),
            Self::RegistrationComplete(body)
            | Self::RegistrationReject(body)
            | Self::ServiceRequest(body)
            | Self::ServiceAccept(body)
            | Self::ServiceReject(body)
            | Self::ConfigurationUpdateCommand(body)
            | Self::ConfigurationUpdateComplete(body)
            | Self::AuthenticationRequest(body)
            | Self::AuthenticationResponse(body)
            | Self::AuthenticationReject(body)
            | Self::AuthenticationFailure(body)
            | Self::AuthenticationResult(body)
            | Self::IdentityRequest(body)
            | Self::IdentityResponse(body)
            | Self::SecurityModeReject(body)
            | Self::Status5gmm(body)
            | Self::Notification(body)
            | Self::NotificationResponse(body)
            | Self::UlNasTransport(body)
            | Self::DlNasTransport(body)
            | Self::Unknown(body) => body.encode(dst, ctx),
            Self::SecurityModeCommand(body) => body.encode(dst, ctx),
            Self::SecurityModeComplete(body) => body.encode(dst, ctx),
        }
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        match self {
            Self::RegistrationRequest(body) => body.wire_len(ctx),
            Self::RegistrationAccept(body) => body.wire_len(ctx),
            Self::RegistrationComplete(body)
            | Self::RegistrationReject(body)
            | Self::ServiceRequest(body)
            | Self::ServiceAccept(body)
            | Self::ServiceReject(body)
            | Self::ConfigurationUpdateCommand(body)
            | Self::ConfigurationUpdateComplete(body)
            | Self::AuthenticationRequest(body)
            | Self::AuthenticationResponse(body)
            | Self::AuthenticationReject(body)
            | Self::AuthenticationFailure(body)
            | Self::AuthenticationResult(body)
            | Self::IdentityRequest(body)
            | Self::IdentityResponse(body)
            | Self::SecurityModeReject(body)
            | Self::Status5gmm(body)
            | Self::Notification(body)
            | Self::NotificationResponse(body)
            | Self::UlNasTransport(body)
            | Self::DlNasTransport(body)
            | Self::Unknown(body) => body.wire_len(ctx),
            Self::SecurityModeCommand(body) => body.wire_len(ctx),
            Self::SecurityModeComplete(body) => body.wire_len(ctx),
        }
    }
}

impl Encode for SmMessageBody {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            Self::PduSessionEstablishmentRequest(body)
            | Self::PduSessionEstablishmentAccept(body)
            | Self::PduSessionEstablishmentReject(body)
            | Self::PduSessionAuthenticationCommand(body)
            | Self::PduSessionAuthenticationComplete(body)
            | Self::PduSessionAuthenticationResult(body)
            | Self::PduSessionModificationRequest(body)
            | Self::PduSessionModificationReject(body)
            | Self::PduSessionModificationCommand(body)
            | Self::PduSessionModificationComplete(body)
            | Self::PduSessionModificationCommandReject(body)
            | Self::PduSessionReleaseRequest(body)
            | Self::PduSessionReleaseReject(body)
            | Self::PduSessionReleaseCommand(body)
            | Self::PduSessionReleaseComplete(body)
            | Self::Status5gsm(body)
            | Self::Unknown(body) => body.encode(dst, ctx),
        }
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        match self {
            Self::PduSessionEstablishmentRequest(body)
            | Self::PduSessionEstablishmentAccept(body)
            | Self::PduSessionEstablishmentReject(body)
            | Self::PduSessionAuthenticationCommand(body)
            | Self::PduSessionAuthenticationComplete(body)
            | Self::PduSessionAuthenticationResult(body)
            | Self::PduSessionModificationRequest(body)
            | Self::PduSessionModificationReject(body)
            | Self::PduSessionModificationCommand(body)
            | Self::PduSessionModificationComplete(body)
            | Self::PduSessionModificationCommandReject(body)
            | Self::PduSessionReleaseRequest(body)
            | Self::PduSessionReleaseReject(body)
            | Self::PduSessionReleaseCommand(body)
            | Self::PduSessionReleaseComplete(body)
            | Self::Status5gsm(body)
            | Self::Unknown(body) => body.wire_len(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use opc_protocol::{BorrowDecode, Encode};

    fn round_trip_body<T>(bytes: &[u8])
    where
        for<'a> T: BorrowDecode<'a> + Encode,
    {
        let (_, msg) = T::decode(bytes, DecodeContext::default()).unwrap();
        let mut buf = BytesMut::new();
        msg.encode(&mut buf, EncodeContext::default()).unwrap();
        assert_eq!(&buf[..], bytes, "{}", std::any::type_name::<T>());
    }

    #[test]
    fn optional_ies_honor_unknown_ie_policy() {
        let unknown_type4_guess = &[0x53, 0x01, 0xAA];

        let preserve = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            ..DecodeContext::default()
        };
        let (_, preserved) = decode_optional_ies(unknown_type4_guess, preserve).unwrap();
        assert_eq!(preserved.len(), 1);
        assert_eq!(preserved[0].iei, 0x53);
        assert_eq!(&preserved[0].value[..], &[0xAA]);

        let drop = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        };
        let (_, dropped) = decode_optional_ies(unknown_type4_guess, drop).unwrap();
        assert!(dropped.is_empty());

        let reject = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        };
        let err = decode_optional_ies(unknown_type4_guess, reject).unwrap_err();
        assert!(matches!(
            err.code(),
            DecodeErrorCode::Structural {
                reason: "unknown optional IE"
            }
        ));

        let strict_preserve = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        assert!(decode_optional_ies(unknown_type4_guess, strict_preserve).is_err());
    }

    #[test]
    fn optional_ies_honor_duplicate_ie_policy() {
        let duplicate = &[0x2E, 0x01, 0xAA, 0x2E, 0x01, 0xBB];

        let first = DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..DecodeContext::default()
        };
        let (_, first_ies) = decode_optional_ies(duplicate, first).unwrap();
        assert_eq!(first_ies.len(), 1);
        assert_eq!(&first_ies[0].value[..], &[0xAA]);

        let last = DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::Last,
            ..DecodeContext::default()
        };
        let (_, last_ies) = decode_optional_ies(duplicate, last).unwrap();
        assert_eq!(last_ies.len(), 1);
        assert_eq!(&last_ies[0].value[..], &[0xBB]);

        let reject = DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            ..DecodeContext::default()
        };
        let err = decode_optional_ies(duplicate, reject).unwrap_err();
        assert_eq!(err.code(), &DecodeErrorCode::DuplicateIe);
    }

    #[test]
    fn registration_request_minimal() {
        // 0x01 -> ngKSI=0, registration type=initial, FOR=0.
        // Mobile identity: LV-E length 7, SUCI type 1, SUPI format 0, PLMN
        // 0x02F839, routing indicator 0x21 0xF3, null scheme, pki 0, scheme
        // output 0x13 0x57.
        let body: &[u8] = &[
            0x01, // reg type + ngKSI
            0x00, 0x0A, // LV-E length
            0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57,
        ];
        let (_, req) = RegistrationRequest::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(req.registration_type, RegistrationType::InitialRegistration);
        assert!(!req.follow_on_request);
        assert_eq!(req.ng_ksi.value, 0);
        assert!(!req.ng_ksi.no_key_available);
        assert_eq!(
            req.mobile_identity.identity_type,
            crate::identity::IdentityType::Suci
        );
        assert!(req.optional_ies.is_empty());
        round_trip_body::<RegistrationRequest>(body);
    }

    #[test]
    fn registration_request_with_optional_ies() {
        // Minimal body plus a TLV IE (IEI 0x2E, length 2, value 0x80 0x00)
        // and a type-1 IE (IEI 0xB0).
        let body: &[u8] = &[
            0x01, 0x00, 0x0A, 0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57, 0x2E,
            0x02, 0x80, 0x00, 0xB0,
        ];
        let (_, req) = RegistrationRequest::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(req.optional_ies.len(), 2);
        assert_eq!(req.optional_ies[0].iei, 0x2E);
        assert_eq!(&req.optional_ies[0].value[..], &[0x80, 0x00]);
        assert_eq!(req.optional_ies[1].iei, 0xB0);
        round_trip_body::<RegistrationRequest>(body);
    }

    #[test]
    fn registration_request_debug_redacts_mobile_identity_and_raw_ies() {
        let body: &[u8] = &[
            0x01, 0x00, 0x0A, 0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57, 0x2E,
            0x02, 0x80, 0x00,
        ];
        let (_, req) = RegistrationRequest::decode_body(body, DecodeContext::default()).unwrap();

        let rendered = format!("{req:?}");
        assert!(rendered.contains("scheme_output: <redacted>"));
        assert!(rendered.contains("mobile_identity_lv_len"));
        assert!(rendered.contains("optional_ies_len"));
        assert!(!rendered.contains("raw_mobile_identity_lv"));
        assert!(!rendered.contains("optional_ies:"));
        assert!(!rendered.contains("13, 57"));
        assert!(!rendered.contains("128"));
    }

    #[test]
    fn registration_accept_minimal() {
        let body: &[u8] = &[0x01, 0x01]; // LV length=1, value=1 (3GPP access)
        let (_, acc) = RegistrationAccept::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(acc.registration_result, RegistrationResult::Access3gpp);
        assert!(acc.optional_ies.is_empty());
        round_trip_body::<RegistrationAccept>(body);
    }

    #[test]
    fn registration_accept_with_guti() {
        // 5GS registration result + 5G-GUTI TLV-E (IEI 0x77, length 13, 13
        // content octets).
        let guti_content = &[
            0xF2u8, 0x02, 0xF8, 0x39, 0x11, 0x01, 0x41, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let mut body = vec![0x01, 0x01];
        body.push(0x77);
        body.extend_from_slice(&(guti_content.len() as u16).to_be_bytes());
        body.extend_from_slice(guti_content);

        let (_, acc) = RegistrationAccept::decode_body(&body, DecodeContext::default()).unwrap();
        assert_eq!(acc.registration_result, RegistrationResult::Access3gpp);
        assert_eq!(acc.optional_ies.len(), 1);
        assert_eq!(acc.optional_ies[0].iei, 0x77);
        assert_eq!(&acc.optional_ies[0].value[..], guti_content);
        round_trip_body::<RegistrationAccept>(&body);
    }

    #[test]
    fn registration_request_truncated_identity_length_rejected() {
        let body: &[u8] = &[0x01, 0x00, 0x10, 0x01];
        assert!(RegistrationRequest::decode_body(body, DecodeContext::default()).is_err());
    }

    #[test]
    fn security_mode_command_round_trip() {
        let body: &[u8] = &[
            0x21, // NEA2 + NIA1
            0x00, // ngKSI
            0x02, 0x80, 0x00, // replayed UE security capability LV
            0xE0, // type-1 optional IE
        ];
        let (_, command) =
            SecurityModeCommand::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(
            command.selected_algorithms.ciphering,
            NasCipheringAlgorithm::Nea2
        );
        assert_eq!(
            command.selected_algorithms.integrity,
            NasIntegrityAlgorithm::Nia1
        );
        assert_eq!(command.ng_ksi.value, 0);
        assert!(!command.ng_ksi.no_key_available);
        assert_eq!(&command.replayed_ue_security_capability[..], &[0x80, 0x00]);
        assert_eq!(command.optional_ies.len(), 1);
        assert_eq!(command.optional_ies[0].iei, 0xE0);
        round_trip_body::<SecurityModeCommand>(body);
    }

    #[test]
    fn security_mode_complete_round_trip() {
        let body: &[u8] = &[
            0x77, 0x00, 0x02, 0x12, 0x34, // TLV-E optional IE
        ];
        let (_, complete) =
            SecurityModeComplete::decode_body(body, DecodeContext::default()).unwrap();
        assert_eq!(complete.optional_ies.len(), 1);
        assert_eq!(complete.optional_ies[0].iei, 0x77);
        assert_eq!(&complete.optional_ies[0].value[..], &[0x12, 0x34]);
        round_trip_body::<SecurityModeComplete>(body);
    }

    #[test]
    fn security_mode_command_rejects_truncated_or_empty_capability() {
        for body in [
            &[][..],
            &[0x21][..],
            &[0x21, 0x00][..],
            &[0x21, 0x00, 0x00][..],
        ] {
            assert!(
                SecurityModeCommand::decode_body(body, DecodeContext::default()).is_err(),
                "body should reject: {body:02X?}"
            );
        }

        assert!(SecurityModeCommand::decode_body(
            &[0x21, 0x00, 0x02, 0x80],
            DecodeContext::default()
        )
        .is_err());
    }

    #[test]
    fn mm_body_dispatch_covers_first_cnf_messages() {
        let smc = decode_mm_message_body(
            MmMessageType::SecurityModeCommand as u8,
            &[0x21, 0x00, 0x02, 0x80, 0x00],
            DecodeContext::default(),
        )
        .unwrap();
        assert!(matches!(smc, MmMessageBody::SecurityModeCommand(_)));

        let complete = decode_mm_message_body(
            MmMessageType::SecurityModeComplete as u8,
            &[0x77, 0x00, 0x01, 0xAA],
            DecodeContext::default(),
        )
        .unwrap();
        assert!(matches!(complete, MmMessageBody::SecurityModeComplete(_)));

        let raw_cases = [
            (
                MmMessageType::RegistrationComplete as u8,
                "registration complete",
            ),
            (
                MmMessageType::AuthenticationResponse as u8,
                "authentication response",
            ),
            (MmMessageType::UlNasTransport as u8, "uplink NAS transport"),
            (
                MmMessageType::DlNasTransport as u8,
                "downlink NAS transport",
            ),
        ];
        for (message_type, name) in raw_cases {
            let body =
                decode_mm_message_body(message_type, &[0xAA, 0xBB], DecodeContext::default())
                    .unwrap();
            let mut encoded = BytesMut::new();
            body.encode(&mut encoded, EncodeContext::default()).unwrap();
            assert_eq!(&encoded[..], &[0xAA, 0xBB], "{name}");
        }

        let unknown = decode_mm_message_body(0xFE, &[0x12], DecodeContext::default()).unwrap();
        assert!(matches!(unknown, MmMessageBody::Unknown(_)));
    }

    #[test]
    fn sm_body_dispatch_covers_first_cnf_messages() {
        let cases = [
            (
                SmMessageType::PduSessionEstablishmentRequest as u8,
                "establishment request",
            ),
            (
                SmMessageType::PduSessionEstablishmentAccept as u8,
                "establishment accept",
            ),
            (
                SmMessageType::PduSessionReleaseCommand as u8,
                "release command",
            ),
            (
                SmMessageType::PduSessionReleaseComplete as u8,
                "release complete",
            ),
            (SmMessageType::Status5gsm as u8, "status"),
        ];

        for (message_type, name) in cases {
            let body =
                decode_sm_message_body(message_type, &[0x01, 0x02], DecodeContext::default())
                    .unwrap();
            let mut encoded = BytesMut::new();
            body.encode(&mut encoded, EncodeContext::default()).unwrap();
            assert_eq!(&encoded[..], &[0x01, 0x02], "{name}");
        }

        let unknown = decode_sm_message_body(0xFE, &[0x12], DecodeContext::default()).unwrap();
        assert!(matches!(unknown, SmMessageBody::Unknown(_)));
    }
}
