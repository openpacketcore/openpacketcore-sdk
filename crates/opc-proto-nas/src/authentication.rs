//! Typed 5GMM authentication bodies (TS 24.501 §8.2.1–8.2.5).
//!
//! Default decoding follows the receiver rules in TS 24.007 and TS 24.501 §7:
//! optional presence is not enforced, malformed optional values are ignored,
//! and excess fixed-length/EAP padding is discarded. Strict and ProcedureAware
//! additionally enforce table order, exact lengths and sender presence rules.
//! Mandatory IEs and resource bounds are always checked. Procedure state, AKA
//! verification and EAP method processing belong to the caller. Unknown comprehension-required IEs
//! fail closed. Other unknown IEs follow [`UnknownIePolicy`]. Repeated IEs use
//! the first occurrence (§7.6.3), even with `DuplicateIePolicy::Last`; an explicit
//! `Reject` policy remains available. Encoding is canonical: known IEs in table
//! order, then preserved extensions; ignored duplicates and spare bits are not
//! emitted. Encoding always validates sender rules and is canonical, including
//! with `EncodeContext::raw_preserving`: these typed bodies do not retain the
//! original wire image. Keep [`crate::PlainMm::body`] for raw preservation.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, DuplicateIePolicy,
    Encode, EncodeContext, EncodeError, EncodeErrorCode, OwnedDecode, SpecRef, UnknownIePolicy,
    ValidationLevel,
};

use crate::OptionalIe;

fn decode_error(code: DecodeErrorCode, offset: usize, clause: &'static str) -> DecodeError {
    DecodeError::new(code, offset).with_spec_ref(SpecRef::new("3gpp", "TS24501", clause))
}

fn invalid(reason: &'static str, clause: &'static str) -> DecodeError {
    decode_error(DecodeErrorCode::Structural { reason }, 0, clause)
}

fn encode_error(reason: &'static str, clause: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS24501", clause))
}

fn strict(ctx: DecodeContext) -> bool {
    matches!(
        ctx.validation_level,
        ValidationLevel::Strict | ValidationLevel::ProcedureAware
    )
}

/// NAS key set identifier and native/mapped context flag (§9.11.3.32).
///
/// Bit 4 is the type of security context, not a no-key flag. Identifier 7 means
/// no key for UE-originated messages and is reserved in network-originated
/// authentication messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NgKsi(u8);

impl NgKsi {
    /// Construct an identifier (0–7) with its type-of-security-context flag.
    pub fn new(identifier: u8, mapped: bool) -> Result<Self, DecodeError> {
        if identifier > 7 {
            return Err(invalid("ngKSI identifier exceeds three bits", "9.11.3.32"));
        }
        Ok(Self(identifier | (u8::from(mapped) << 3)))
    }

    /// Three-bit key set identifier.
    pub const fn identifier(self) -> u8 {
        self.0 & 7
    }
    /// Whether the type-of-security-context bit indicates a mapped context.
    pub const fn is_mapped(self) -> bool {
        self.0 & 8 != 0
    }
    /// Whether the identifier is the UE-originated no-key value.
    pub const fn no_key_available(self) -> bool {
        self.identifier() == 7
    }
    /// Four-bit wire value; the spare half octet is zero.
    pub const fn as_nibble(self) -> u8 {
        self.0
    }
}

/// Anti-bidding-down parameter value, 2–255 octets (§9.11.3.10).
#[derive(Clone, PartialEq, Eq)]
pub struct Abba(Bytes);

impl Abba {
    /// Validate an ABBA value without its IEI or length octet.
    pub fn new(value: Bytes) -> Result<Self, DecodeError> {
        if !(2..=255).contains(&value.len()) {
            return Err(invalid("ABBA must contain 2 to 255 octets", "9.11.3.10"));
        }
        Ok(Self(value))
    }
    fn from_slice(value: &[u8]) -> Result<Self, DecodeError> {
        if !(2..=255).contains(&value.len()) {
            return Err(invalid("ABBA must contain 2 to 255 octets", "9.11.3.10"));
        }
        Ok(Self(Bytes::copy_from_slice(value)))
    }
    /// ABBA content, excluding framing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// EAP packet value, 4–1500 octets (§9.11.2.2).
///
/// The embedded RFC 3748 length matches this normalized value's length. Default
/// body decoding discards NAS IE padding beyond that length. EAP method
/// contents, unknown code handling and procedure semantics remain caller-owned.
/// Known Request/Response packets need a Type octet; Success/Failure are four octets.
#[derive(Clone, PartialEq, Eq)]
pub struct EapMessage(Bytes);

impl EapMessage {
    /// Validate an EAP packet without the NAS IEI or two-octet length.
    pub fn new(value: Bytes) -> Result<Self, DecodeError> {
        validate_eap(&value)?;
        Ok(Self(value))
    }
    fn from_slice(value: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        Ok(Self(Bytes::copy_from_slice(eap_value(value, ctx)?)))
    }
    /// Complete EAP packet, including its EAP header.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// EAP code octet, used for the Authentication Result ABBA presence rule.
    pub fn code(&self) -> u8 {
        self.0[0]
    }
}

fn eap_value(value: &[u8], ctx: DecodeContext) -> Result<&[u8], DecodeError> {
    let packet = if strict(ctx) {
        value
    } else {
        let header = value
            .get(..4)
            .ok_or_else(|| invalid("EAP header is truncated", "9.11.2.2"))?;
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        value
            .get(..length)
            .ok_or_else(|| invalid("EAP packet exceeds IE length", "9.11.2.2"))?
    };
    validate_eap(packet)?;
    Ok(packet)
}

fn validate_eap(value: &[u8]) -> Result<(), DecodeError> {
    if !(4..=1500).contains(&value.len()) {
        return Err(invalid(
            "EAP message must contain 4 to 1500 octets",
            "9.11.2.2",
        ));
    }
    if usize::from(u16::from_be_bytes([value[2], value[3]])) != value.len() {
        return Err(invalid(
            "EAP packet length differs from IE length",
            "9.11.2.2",
        ));
    }
    // RFC 3748 §4.1/§4.2: Requests/Responses include a Type octet;
    // Success/Failure packets consist only of their four-octet header.
    if (matches!(value[0], 1 | 2) && value.len() < 5)
        || (matches!(value[0], 3 | 4) && value.len() != 4)
    {
        return Err(invalid("EAP code has an invalid packet length", "9.11.2.2"));
    }
    Ok(())
}

/// 5GMM cause octet (§9.11.3.2), retaining unrecognized values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmCause(u8);

impl MmCause {
    /// MAC failure, cause 20.
    pub const MAC_FAILURE: Self = Self(20);
    /// Synchronization failure, cause 21; requires AUTS.
    pub const SYNCH_FAILURE: Self = Self(21);
    /// Non-5G authentication unacceptable, cause 26.
    pub const NON_5G_AUTHENTICATION_UNACCEPTABLE: Self = Self(26);
    /// ngKSI already in use, cause 71.
    pub const NG_KSI_ALREADY_IN_USE: Self = Self(71);
    /// Preserve a cause, including an unknown or future value.
    pub const fn new(value: u8) -> Self {
        Self(value)
    }
    /// Original cause octet.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// Authentication Request (§8.2.1): send either RAND and AUTN, or EAP.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    /// Network-selected key set identifier (§9.11.3.32).
    pub ng_ksi: NgKsi,
    /// Mandatory ABBA (§9.11.3.10).
    pub abba: Abba,
    /// RAND, IEI 0x21, TV, 16 value octets (TS 24.008 §10.5.3.1).
    pub rand: Option<[u8; 16]>,
    /// AUTN, IEI 0x20, TLV, 16 value octets (TS 24.008 §10.5.3.1.1).
    pub autn: Option<[u8; 16]>,
    /// EAP alternative, IEI 0x78, TLV-E (§9.11.2.2).
    pub eap_message: Option<EapMessage>,
    /// Preserved unknown, comprehension-not-required IEs; validated on encode.
    pub optional_ies: Vec<OptionalIe>,
}

/// Authentication Response (§8.2.2): send either RES* or EAP.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    /// RES*, IEI 0x2d, TLV, exactly 16 value octets (§9.11.3.17).
    pub res_star: Option<[u8; 16]>,
    /// EAP alternative, IEI 0x78, TLV-E (§9.11.2.2).
    pub eap_message: Option<EapMessage>,
    /// Preserved unknown, comprehension-not-required IEs; validated on encode.
    pub optional_ies: Vec<OptionalIe>,
}

/// Authentication Result (§8.2.3), including the mandatory EAP LV-E.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationResult {
    /// Network-selected key set identifier (§9.11.3.32).
    pub ng_ksi: NgKsi,
    /// Mandatory EAP result (§9.11.2.2), without a NAS IEI.
    pub eap_message: EapMessage,
    /// ABBA, IEI 0x38; required for EAP-Success (§8.2.3.2).
    pub abba: Option<Abba>,
    /// Preserved unknown, comprehension-not-required IEs; validated on encode.
    pub optional_ies: Vec<OptionalIe>,
}

/// Authentication Failure (§8.2.4).
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationFailure {
    /// Mandatory 5GMM cause (§9.11.3.2).
    pub cause: MmCause,
    /// AUTS, IEI 0x30, TLV, 14 value octets (TS 24.008 §10.5.3.2.2).
    /// Send if and only if the cause is synchronization failure (21).
    /// Default decoding ignores it for other causes.
    pub auts: Option<[u8; 14]>,
    /// Preserved unknown, comprehension-not-required IEs; validated on encode.
    pub optional_ies: Vec<OptionalIe>,
}

/// Authentication Reject (§8.2.5), optionally carrying EAP-Failure.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AuthenticationReject {
    /// Optional EAP-Failure, IEI 0x78, TLV-E (§8.2.5.2).
    pub eap_message: Option<EapMessage>,
    /// Preserved unknown, comprehension-not-required IEs; validated on encode.
    pub optional_ies: Vec<OptionalIe>,
}

// Authentication values and unknown extensions can carry credentials. Do not
// allow a derived Debug implementation to expose them through MmMessageBody.
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
redacted_debug!(
    Abba,
    EapMessage,
    AuthenticationRequest,
    AuthenticationResponse,
    AuthenticationResult,
    AuthenticationFailure,
    AuthenticationReject
);

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
    clause: &'static str,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            decode_error(DecodeErrorCode::LengthOverflow, self.offset, self.clause)
        })?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| decode_error(DecodeErrorCode::Truncated, self.offset, self.clause))?;
        self.offset = end;
        Ok(bytes)
    }
    fn octet(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn lv(&mut self, extended: bool) -> Result<&'a [u8], DecodeError> {
        let len = if extended {
            let bytes = self.take(2)?;
            usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        } else {
            usize::from(self.octet()?)
        };
        self.take(len)
    }
    fn ng_ksi(&mut self) -> Result<NgKsi, DecodeError> {
        let octet = self.octet()?;
        // Spare bits are ignored on reception (TS 24.501 §9.5).
        let value = NgKsi(octet & 0x0f);
        if value.no_key_available() {
            return Err(invalid(
                "network authentication ngKSI is reserved",
                "9.11.3.32",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Request,
    Response,
    Result,
    Failure,
    Reject,
}

impl Kind {
    fn known(self, iei: u8) -> bool {
        self.order(iei).is_some()
    }
    fn order(self, iei: u8) -> Option<u8> {
        match (self, iei) {
            (Self::Request, 0x21)
            | (Self::Response, 0x2d)
            | (Self::Result, 0x38)
            | (Self::Failure, 0x30)
            | (Self::Reject, 0x78) => Some(0),
            (Self::Request, 0x20) | (Self::Response, 0x78) => Some(1),
            (Self::Request, 0x78) => Some(2),
            _ => None,
        }
    }
}

fn critical(iei: u8) -> bool {
    iei <= 0x0f || matches!(iei, 0x7e | 0x7f)
}
fn duplicate_key(iei: u8) -> u8 {
    if iei & 0x80 != 0 {
        iei & 0xf0
    } else {
        iei
    }
}

struct Optionals(Vec<OptionalIe>);
impl Optionals {
    fn value(&self, iei: u8) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|ie| ie.iei == iei)
            .map(|ie| ie.value.as_ref())
    }
    fn array<const N: usize>(
        &self,
        iei: u8,
        clause: &'static str,
    ) -> Result<Option<[u8; N]>, DecodeError> {
        self.value(iei)
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| invalid("authentication parameter length is invalid", clause))
            })
            .transpose()
    }
    fn eap(&self) -> Result<Option<EapMessage>, DecodeError> {
        self.0
            .iter()
            .find(|ie| ie.iei == 0x78)
            .map(|ie| EapMessage::new(ie.value.clone()))
            .transpose()
    }
    fn extensions(self, kind: Kind) -> Vec<OptionalIe> {
        self.0
            .into_iter()
            .filter(|ie| !kind.known(ie.iei))
            .collect()
    }
}

fn known_value(iei: u8, value: &[u8], ctx: DecodeContext) -> Result<&[u8], DecodeError> {
    let (length, clause) = match iei {
        0x20 => (16, "9.11.3.15"),
        0x21 => (16, "9.11.3.16"),
        0x2d => (16, "9.11.3.17"),
        0x30 => (14, "9.11.3.14"),
        0x38 if (2..=255).contains(&value.len()) => return Ok(value),
        0x38 => (2, "9.11.3.10"),
        0x78 => return eap_value(value, ctx),
        _ => return Ok(value),
    };
    if value.len() < length || (strict(ctx) && value.len() != length) {
        return Err(invalid("authentication IE value length is invalid", clause));
    }
    Ok(&value[..length])
}

fn optionals(
    cursor: &mut Cursor<'_>,
    kind: Kind,
    ctx: DecodeContext,
) -> Result<Optionals, DecodeError> {
    let mut out = Vec::new();
    let mut seen = [false; 256];
    let mut count = 0;
    let mut last_order = None;
    while cursor.offset < cursor.input.len() {
        let offset = cursor.offset;
        if count >= ctx.max_ies {
            return Err(decode_error(
                DecodeErrorCode::IeCountExceeded,
                offset,
                cursor.clause,
            ));
        }
        count += 1;
        let iei = cursor.octet()?;
        let known = kind.known(iei);
        if !known && critical(iei) {
            return Err(decode_error(
                DecodeErrorCode::UnknownCriticalIe,
                offset,
                "7.5",
            ));
        }
        if !known && ctx.unknown_ie_policy == UnknownIePolicy::Reject {
            return Err(decode_error(
                DecodeErrorCode::Structural {
                    reason: "unknown optional authentication IE",
                },
                offset,
                "7.6.1",
            ));
        }
        // TS 24.007 §11.2.4: an unknown high-bit IE is one octet, 0x70–7f
        // has a two-octet length, all other unknown IEs have a one-octet length.
        // RAND is the only known fixed-size TV in these five messages.
        let value = if known && iei == 0x21 {
            cursor.take(16)
        } else if iei & 0x80 != 0 {
            Ok(&[][..])
        } else {
            cursor.lv((0x70..=0x7f).contains(&iei))
        };
        let value = match value {
            Ok(value) => value,
            Err(error) if strict(ctx) => return Err(error),
            // No trustworthy next IE boundary remains after truncated framing.
            // Treat the optional IE as absent without attempting resynchronization.
            Err(_) => break,
        };
        let key = usize::from(duplicate_key(iei));
        if seen[key] {
            if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject {
                return Err(decode_error(DecodeErrorCode::DuplicateIe, offset, "7.6.3"));
            }
            continue;
        }
        seen[key] = true;
        let value = if let Some(order) = kind.order(iei) {
            if last_order.is_some_and(|last| order < last) {
                if strict(ctx) {
                    return Err(decode_error(
                        DecodeErrorCode::Structural {
                            reason: "authentication IE is out of sequence",
                        },
                        offset,
                        "7.6.2",
                    ));
                }
                continue;
            }
            let value = match known_value(iei, value, ctx) {
                Ok(value) => value,
                Err(error) if strict(ctx) => return Err(error),
                Err(_) => continue,
            };
            last_order = Some(order);
            value
        } else {
            value
        };
        if known || ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
            out.push(OptionalIe {
                iei,
                value: Bytes::copy_from_slice(value),
                raw: if known {
                    Bytes::new()
                } else {
                    Bytes::copy_from_slice(&cursor.input[offset..cursor.offset])
                },
            });
        }
    }
    Ok(Optionals(out))
}

// Do not let caller-created raw extensions override typed fields or smuggle
// extra IEs through a mismatched length/value. Validation precedes all writes.
fn extensions_len(
    ies: &[OptionalIe],
    kind: Kind,
    clause: &'static str,
) -> Result<usize, EncodeError> {
    let mut len = 0usize;
    let mut seen = [false; 256];
    for ie in ies {
        let key = usize::from(duplicate_key(ie.iei));
        if kind.known(ie.iei) || critical(ie.iei) || seen[key] {
            return Err(encode_error("invalid authentication extension IEI", clause));
        }
        seen[key] = true;
        let mut cursor = Cursor {
            input: &ie.raw,
            offset: 0,
            clause,
        };
        let ctx = DecodeContext {
            max_ies: 1,
            ..DecodeContext::default()
        };
        let parsed = optionals(&mut cursor, kind, ctx)
            .map_err(|_| encode_error("invalid authentication extension framing", clause))?;
        if parsed.0.as_slice() != std::slice::from_ref(ie) {
            return Err(encode_error(
                "authentication extension differs from its wire value",
                clause,
            ));
        }
        len = len
            .checked_add(ie.raw.len())
            .ok_or_else(EncodeError::length_overflow)?;
    }
    Ok(len)
}

fn put_lv(dst: &mut BytesMut, value: &[u8], extended: bool) {
    // All callers use fixed-size values or validated Abba/EapMessage values.
    if extended {
        dst.put_u16(value.len() as u16);
    } else {
        dst.put_u8(value.len() as u8);
    }
    dst.extend_from_slice(value);
}
fn put_tlv(dst: &mut BytesMut, iei: u8, value: &[u8]) {
    dst.put_u8(iei);
    put_lv(dst, value, iei == 0x78);
}

trait Body: Sized {
    const CLAUSE: &'static str;
    const KIND: Kind;
    fn read(cursor: &mut Cursor<'_>, ctx: DecodeContext) -> Result<Self, DecodeError>;
    fn validate(&self) -> Result<(), &'static str>;
    fn fields_len(&self) -> usize;
    fn extensions(&self) -> &[OptionalIe];
    fn write_fields(&self, dst: &mut BytesMut);
}

macro_rules! body_codec {
    ($($ty:ty),+ $(,)?) => {$(
        impl $ty {
            /// Decode the complete body, excluding the three-octet plain 5GMM header.
            pub fn decode_body(input: &[u8], ctx: DecodeContext) -> DecodeResult<'_, Self> {
                if input.len() > ctx.max_message_len {
                    return Err(decode_error(DecodeErrorCode::MessageLengthExceeded, 0, Self::CLAUSE));
                }
                let mut cursor = Cursor { input, offset: 0, clause: Self::CLAUSE };
                let value = Self::read(&mut cursor, ctx)?;
                if strict(ctx) {
                    value.validate().map_err(|reason| invalid(reason, Self::CLAUSE))?;
                }
                Ok((&[], value))
            }
        }
        impl<'a> BorrowDecode<'a> for $ty {
            fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> { Self::decode_body(input, ctx) }
        }
        impl OwnedDecode for $ty {
            fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError> { Ok(Self::decode_body(&input, ctx)?.1) }
        }
        impl Encode for $ty {
            fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
                self.validate().map_err(|reason| encode_error(reason, Self::CLAUSE))?;
                self.fields_len().checked_add(extensions_len(self.extensions(), Self::KIND, Self::CLAUSE)?)
                    .ok_or_else(EncodeError::length_overflow)
            }
            fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
                let len = self.wire_len(ctx)?;
                ctx.check_capacity(len)?;
                dst.reserve(len);
                self.write_fields(dst);
                for ie in self.extensions() { dst.extend_from_slice(&ie.raw); }
                Ok(())
            }
        }
    )+};
}

impl Body for AuthenticationRequest {
    const CLAUSE: &'static str = "8.2.1";
    const KIND: Kind = Kind::Request;
    fn read(cursor: &mut Cursor<'_>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let ng_ksi = cursor.ng_ksi()?;
        let abba = Abba::from_slice(cursor.lv(false)?)?;
        let ies = optionals(cursor, Self::KIND, ctx)?;
        Ok(Self {
            ng_ksi,
            abba,
            rand: ies.array(0x21, "9.11.3.16")?,
            autn: ies.array(0x20, "9.11.3.15")?,
            eap_message: ies.eap()?,
            optional_ies: ies.extensions(Self::KIND),
        })
    }
    fn validate(&self) -> Result<(), &'static str> {
        if self.ng_ksi.no_key_available() {
            return Err("network authentication ngKSI is reserved");
        }
        match (&self.rand, &self.autn, &self.eap_message) {
            (Some(_), Some(_), None) | (None, None, Some(_)) => Ok(()),
            _ => Err("request requires RAND and AUTN, or EAP, exclusively"),
        }
    }
    fn fields_len(&self) -> usize {
        2 + self.abba.0.len()
            + self.rand.map_or(0, |_| 17)
            + self.autn.map_or(0, |_| 18)
            + self.eap_message.as_ref().map_or(0, |v| 3 + v.0.len())
    }
    fn extensions(&self) -> &[OptionalIe] {
        &self.optional_ies
    }
    fn write_fields(&self, dst: &mut BytesMut) {
        dst.put_u8(self.ng_ksi.as_nibble());
        put_lv(dst, self.abba.as_bytes(), false);
        if let Some(value) = &self.rand {
            dst.put_u8(0x21);
            dst.extend_from_slice(value);
        }
        if let Some(value) = &self.autn {
            put_tlv(dst, 0x20, value);
        }
        if let Some(value) = &self.eap_message {
            put_tlv(dst, 0x78, value.as_bytes());
        }
    }
}
impl Body for AuthenticationResponse {
    const CLAUSE: &'static str = "8.2.2";
    const KIND: Kind = Kind::Response;
    fn read(cursor: &mut Cursor<'_>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let ies = optionals(cursor, Self::KIND, ctx)?;
        Ok(Self {
            res_star: ies.array(0x2d, "9.11.3.17")?,
            eap_message: ies.eap()?,
            optional_ies: ies.extensions(Self::KIND),
        })
    }
    fn validate(&self) -> Result<(), &'static str> {
        if self.res_star.is_some() == self.eap_message.is_some() {
            return Err("response requires exactly one of RES* and EAP");
        }
        Ok(())
    }
    fn fields_len(&self) -> usize {
        self.res_star.map_or(0, |_| 18) + self.eap_message.as_ref().map_or(0, |v| 3 + v.0.len())
    }
    fn extensions(&self) -> &[OptionalIe] {
        &self.optional_ies
    }
    fn write_fields(&self, dst: &mut BytesMut) {
        if let Some(value) = &self.res_star {
            put_tlv(dst, 0x2d, value);
        }
        if let Some(value) = &self.eap_message {
            put_tlv(dst, 0x78, value.as_bytes());
        }
    }
}
impl Body for AuthenticationResult {
    const CLAUSE: &'static str = "8.2.3";
    const KIND: Kind = Kind::Result;
    fn read(cursor: &mut Cursor<'_>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let ng_ksi = cursor.ng_ksi()?;
        let eap_message = EapMessage::from_slice(cursor.lv(true)?, ctx)?;
        let ies = optionals(cursor, Self::KIND, ctx)?;
        let abba = ies.value(0x38).map(Abba::from_slice).transpose()?;
        Ok(Self {
            ng_ksi,
            eap_message,
            abba,
            optional_ies: ies.extensions(Self::KIND),
        })
    }
    fn validate(&self) -> Result<(), &'static str> {
        if self.ng_ksi.no_key_available() {
            return Err("network authentication ngKSI is reserved");
        }
        if self.eap_message.code() == 3 && self.abba.is_none() {
            return Err("EAP-Success result requires ABBA");
        }
        Ok(())
    }
    fn fields_len(&self) -> usize {
        3 + self.eap_message.0.len() + self.abba.as_ref().map_or(0, |v| 2 + v.0.len())
    }
    fn extensions(&self) -> &[OptionalIe] {
        &self.optional_ies
    }
    fn write_fields(&self, dst: &mut BytesMut) {
        dst.put_u8(self.ng_ksi.as_nibble());
        put_lv(dst, self.eap_message.as_bytes(), true);
        if let Some(value) = &self.abba {
            put_tlv(dst, 0x38, value.as_bytes());
        }
    }
}
impl Body for AuthenticationFailure {
    const CLAUSE: &'static str = "8.2.4";
    const KIND: Kind = Kind::Failure;
    fn read(cursor: &mut Cursor<'_>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let cause = MmCause::new(cursor.octet()?);
        let ies = optionals(cursor, Self::KIND, ctx)?;
        Ok(Self {
            cause,
            auts: if cause == MmCause::SYNCH_FAILURE || strict(ctx) {
                ies.array(0x30, "9.11.3.14")?
            } else {
                None
            },
            optional_ies: ies.extensions(Self::KIND),
        })
    }
    fn validate(&self) -> Result<(), &'static str> {
        if (self.cause == MmCause::SYNCH_FAILURE) != self.auts.is_some() {
            return Err("AUTS required if and only if cause is synchronization failure");
        }
        Ok(())
    }
    fn fields_len(&self) -> usize {
        1 + self.auts.map_or(0, |_| 16)
    }
    fn extensions(&self) -> &[OptionalIe] {
        &self.optional_ies
    }
    fn write_fields(&self, dst: &mut BytesMut) {
        dst.put_u8(self.cause.as_u8());
        if let Some(value) = &self.auts {
            put_tlv(dst, 0x30, value);
        }
    }
}
impl Body for AuthenticationReject {
    const CLAUSE: &'static str = "8.2.5";
    const KIND: Kind = Kind::Reject;
    fn read(cursor: &mut Cursor<'_>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let ies = optionals(cursor, Self::KIND, ctx)?;
        Ok(Self {
            eap_message: ies.eap()?,
            optional_ies: ies.extensions(Self::KIND),
        })
    }
    fn validate(&self) -> Result<(), &'static str> {
        if self
            .eap_message
            .as_ref()
            .is_some_and(|v| v.code() != 4 || v.0.len() != 4)
        {
            return Err("authentication reject may carry only EAP-Failure");
        }
        Ok(())
    }
    fn fields_len(&self) -> usize {
        self.eap_message.as_ref().map_or(0, |v| 3 + v.0.len())
    }
    fn extensions(&self) -> &[OptionalIe] {
        &self.optional_ies
    }
    fn write_fields(&self, dst: &mut BytesMut) {
        if let Some(value) = &self.eap_message {
            put_tlv(dst, 0x78, value.as_bytes());
        }
    }
}
body_codec!(
    AuthenticationRequest,
    AuthenticationResponse,
    AuthenticationResult,
    AuthenticationFailure,
    AuthenticationReject
);
