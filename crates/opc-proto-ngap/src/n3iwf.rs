//! Typed N3IWF IE values (TS 29.413 5.3; TS 38.413 9.3).
//!
//! Values encode without the enclosing ProtocolIE open-type determinant and
//! can be borrowed by [`crate::ProtocolIe`]. This boundary validates individual
//! fields. The optional [`nas`], [`release`] and [`setup`] modules admit
//! required fields for their documented outcomes; association authority and
//! policy stay outside.
//! Independently qualified generated ASN.1 encoders handle bounded leaf
//! structures. Explicit receive layout avoids the runtime's TAI alignment
//! defect; the without-port CHOICE wrapper also needs aligned framing. NAS
//! uses the shared fragment scanner for its unconstrained OCTET STRING.
//!
//! Location admission covers IPv4/IPv6 with/without a port and optional TAI.
//! Other location choices, SEQUENCE additions and nested extensions other than
//! the with-port TAI extension return an explicit unsupported-field error.
//! They remain available in the generic PDU's opaque IE view. This does not
//! change the generic decoder's unknown/duplicate policy.
//! `max_message_len` bounds each encoded field; locations require depth four
//! and bound their extension count by `max_ies`. Other fields require depth
//! one. The remaining context policies do not broaden this admitted subset;
//! `allocation_budget` remains advisory. These are field-local limits, not a
//! cumulative budget for an enclosing message. [`setup_fields`] documents its
//! additional nested-list counts, depth requirements and root layout exception.

use std::{borrow::Cow, fmt, net::IpAddr};

use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, EncodeErrorCode,
};
use opc_types::PlmnId;
use zeroize::Zeroizing;

use crate::{
    aper, constructed,
    generated::{ngap_common_data_types::ProtocolExtensionID, ngap_ies as asn},
    Criticality,
};

/// An APER IE value whose buffer is cleared on drop and whose diagnostics are redacted.
///
/// Borrow it through [`Self::as_bytes`] to construct a protocol IE. Copies made
/// by the caller, generic PDU construction and wire output are caller-owned;
/// clearing this buffer does not clear those copies.
pub struct EncodedValue(Zeroizing<Vec<u8>>);

impl EncodedValue {
    /// Explicitly expose the encoded value to the enclosing codec.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EncodedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedValue")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

fn invalid(reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, 0)
}

fn unsupported() -> DecodeError {
    invalid("unsupported n3iwf field extension or choice")
}

fn bound(input: &[u8], ctx: DecodeContext, depth: usize) -> Result<(), DecodeError> {
    if input.len() > ctx.max_message_len {
        return Err(DecodeError::new(DecodeErrorCode::MessageLengthExceeded, 0));
    }
    crate::enforce_depth(depth, ctx)
}

fn capacity(length: usize, ctx: EncodeContext) -> Result<(), EncodeError> {
    if length > ctx.max_message_len {
        return Err(EncodeError::new(EncodeErrorCode::CapacityExceeded {
            required: length,
            available: ctx.max_message_len,
        }));
    }
    Ok(())
}

fn decode_leaf<T: rasn::Decode>(input: &[u8]) -> Result<T, DecodeError> {
    let (value, rest) =
        rasn::aper::decode_with_remainder(input).map_err(|_| invalid("n3iwf field encoding"))?;
    if !rest.is_empty() {
        return Err(invalid("trailing n3iwf field bytes"));
    }
    Ok(value)
}

fn encode_leaf<T: rasn::Encode>(
    value: &T,
    ctx: EncodeContext,
) -> Result<EncodedValue, EncodeError> {
    // All callers use a bounded fixed-size leaf (at most 33 octets), never a
    // peer-controlled collection. NAS checks its length before allocating.
    let wire = Zeroizing::new(rasn::aper::encode(value).map_err(|_| {
        EncodeError::new(EncodeErrorCode::Structural {
            reason: "n3iwf field encoding",
        })
    })?);
    capacity(wire.len(), ctx)?;
    Ok(EncodedValue(wire))
}

macro_rules! redacted {
    ($name:ident $(<$lifetime:lifetime>)?) => {
        impl fmt::Debug for $name $(<$lifetime>)? {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

pub mod context_fields;
pub mod nas;
pub mod release;
pub mod resource_fields;
/// Bounded PDU Session Resource Release transfers, lists and messages.
pub mod resource_release;
pub mod resource_request;
pub mod resource_results;
/// Initial Context Setup and PDU Session Resource Setup field admission.
pub mod resource_setup;
pub mod session_lists;
pub mod setup;
pub mod setup_fields;
/// NAS Non-Delivery Indication and UE Context Release Request field admission.
pub mod ue_requests;

/// The locally assigned, 32-bit RAN UE NGAP identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RanUeId(u32);
redacted!(RanUeId);

impl RanUeId {
    /// Bind a local RAN identifier; this does not establish association ownership.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    /// Explicitly expose the local identifier.
    pub const fn value(self) -> u32 {
        self.0
    }
    /// Encode this IE's ASN.1 value.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_leaf(&asn::RANUENGAPID(self.0), ctx)
    }
    /// Decode exactly one bounded value, rejecting trailing bytes.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        Ok(Self(decode_leaf::<asn::RANUENGAPID>(input)?.0))
    }
}

/// The peer-assigned, 40-bit AMF UE NGAP identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AmfUeId(u64);
redacted!(AmfUeId);

impl AmfUeId {
    /// Reject values outside the ASN.1 40-bit range.
    pub fn new(value: u64) -> Result<Self, DecodeError> {
        if value >= (1u64 << 40) {
            return Err(invalid("amf ue id range"));
        }
        Ok(Self(value))
    }
    /// Explicitly expose the peer identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
    /// Encode this IE's ASN.1 value.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_leaf(&asn::AMFUENGAPID(self.0), ctx)
    }
    /// Decode exactly one bounded value, rejecting trailing bytes.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        Self::new(decode_leaf::<asn::AMFUENGAPID>(input)?.0)
    }
}

/// Borrowed or fragment-coalesced NAS bytes. Their contents remain opaque.
///
/// No NAS message, identity, security context or non-empty requirement is
/// inferred from NGAP's unconstrained OCTET STRING.
pub struct NasPdu<'a>(Cow<'a, [u8]>);
redacted!(NasPdu<'_>);

impl<'a> NasPdu<'a> {
    /// Borrow caller-owned NAS without copying or interpreting it.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(Cow::Borrowed(bytes))
    }
    /// Explicitly expose the opaque NAS to its consumer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Decode exactly one OCTET STRING; validate all fragments before allocation.
    pub fn decode(input: &'a [u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        let (rest, value) = aper::open_type(input)?;
        if !rest.is_empty() {
            return Err(invalid("trailing nas field bytes"));
        }
        Ok(Self(value))
    }
    /// Check the complete encoded length before allocating a NAS value.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = constructed::open_type_len(self.0.len())?;
        capacity(length, ctx)?;
        let mut wire = Zeroizing::new(Vec::with_capacity(length));
        constructed::write_open_type(&mut wire, &self.0);
        Ok(EncodedValue(wire))
    }
}

/// A borrowed 256-bit Security Key IE (K_N3IWF under TS 29.413 5.3).
///
/// This type does not derive keys, admit peers or import material into a key
/// provider. It has no Clone, equality, hashing or serialization implementation.
/// The owner must protect and clear the borrowed source and any wire copies.
pub struct SecurityKey<'a>(&'a [u8; 32]);
redacted!(SecurityKey<'_>);

impl<'a> SecurityKey<'a> {
    /// Borrow an exactly sized key; the caller retains custody.
    pub const fn new(bytes: &'a [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Decode the fixed BIT STRING without allocating or copying key material.
    pub fn decode(input: &'a [u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        Ok(Self(
            input
                .try_into()
                .map_err(|_| invalid("security key width"))?,
        ))
    }
    /// Explicit access for a separately authorized key consumer.
    pub const fn expose_bytes(&self) -> &[u8; 32] {
        self.0
    }
    /// Encode the aligned fixed BIT STRING into a buffer cleared on drop.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(32, ctx)?;
        Ok(EncodedValue(Zeroizing::new(self.0.to_vec())))
    }
}

/// N3IWF tracking area: validated PLMN identity and the three-octet TAC.
#[derive(Clone, PartialEq, Eq)]
pub struct TrackingArea {
    plmn: PlmnId,
    tac: [u8; 3],
}
redacted!(TrackingArea);

impl TrackingArea {
    /// Use the shared SDK PLMN model; TAC assignment policy belongs to the caller.
    pub fn new(plmn: PlmnId, tac: [u8; 3]) -> Self {
        Self { plmn, tac }
    }
    /// Explicit access to the shared PLMN identity.
    pub fn plmn(&self) -> &PlmnId {
        &self.plmn
    }
    /// Explicit access to the tracking area code.
    pub const fn tac(&self) -> [u8; 3] {
        self.tac
    }
    fn generated(&self) -> asn::TAI {
        asn::TAI::new(
            asn::PLMNIdentity(plmn_bytes(&self.plmn).into()),
            asn::TAC(self.tac.into()),
            None,
        )
    }
    /// Encode the root TAI with no extension additions.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        encode_leaf(&self.generated(), ctx)
    }
    /// Decode the root TAI; extensions are an explicit unsupported boundary.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        preflight_tai(input)?;
        // X.691 aligns a fixed OCTET STRING longer than two octets. The
        // generated rasn 0.28 decoder misses this alignment after TAI's flags.
        Ok(Self {
            plmn: decode_plmn(&input[1..4])?,
            tac: input[4..7].try_into().map_err(|_| invalid("tac width"))?,
        })
    }
}

fn plmn_bytes(plmn: &PlmnId) -> [u8; 3] {
    let c = plmn.mcc().as_bytes();
    let n = plmn.mnc().as_bytes();
    let third = n.get(2).map_or(15, |v| v - b'0');
    [
        (c[1] - b'0') << 4 | (c[0] - b'0'),
        third << 4 | (c[2] - b'0'),
        (n[1] - b'0') << 4 | (n[0] - b'0'),
    ]
}

fn decode_plmn(bytes: &[u8]) -> Result<PlmnId, DecodeError> {
    let bytes: &[u8; 3] = bytes.try_into().map_err(|_| invalid("plmn width"))?;
    let digits = [
        bytes[0] & 15,
        bytes[0] >> 4,
        bytes[1] & 15,
        bytes[2] & 15,
        bytes[2] >> 4,
        bytes[1] >> 4,
    ];
    if digits[..5].iter().any(|&digit| digit > 9) || (digits[5] > 9 && digits[5] != 15) {
        return Err(invalid("plmn decimal encoding"));
    }
    let mcc: String = digits[..3].iter().map(|d| char::from(b'0' + d)).collect();
    let mnc: String = digits[3..]
        .iter()
        .filter(|&&d| d != 15)
        .map(|d| char::from(b'0' + d))
        .collect();
    PlmnId::new(mcc, mnc).map_err(|_| invalid("plmn decimal encoding"))
}

fn preflight_tai(input: &[u8]) -> Result<(), DecodeError> {
    if input.first().is_some_and(|v| v & 0xc0 != 0) {
        return Err(unsupported());
    }
    if input.len() != 7 {
        return Err(invalid("tai width"));
    }
    Ok(())
}

/// N3IWF IP location, with an optional port and optional tracking area.
///
/// IPv4 and IPv6 are admitted. Socket reachability, address assignment, port
/// selection and whether TAI is required in a particular procedure are caller
/// obligations. Formatting reveals none of these values.
#[derive(Clone, PartialEq, Eq)]
pub struct N3iwfLocation {
    address: IpAddr,
    port: Option<u16>,
    tai: Option<TrackingArea>,
}
redacted!(N3iwfLocation);

impl N3iwfLocation {
    /// Construct the with-port or without-port choice explicitly.
    pub fn new(address: IpAddr, port: Option<u16>, tai: Option<TrackingArea>) -> Self {
        Self { address, port, tai }
    }
    /// Explicit access to the endpoint address.
    pub const fn address(&self) -> IpAddr {
        self.address
    }
    /// The port is absent for the without-port choice.
    pub const fn port(&self) -> Option<u16> {
        self.port
    }
    /// Optional tracking area; presence is not inferred from the endpoint.
    pub fn tai(&self) -> Option<&TrackingArea> {
        self.tai.as_ref()
    }
    /// Encode either independently qualified N3IWF location choice.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let bits = match self.address {
            IpAddr::V4(ip) => rasn::types::BitString::from_slice(&ip.octets()),
            IpAddr::V6(ip) => rasn::types::BitString::from_slice(&ip.octets()),
        };
        let address = asn::TransportLayerAddress(bits);
        let value = if let Some(port) = self.port {
            let extensions = self.tai.as_ref().map(|tai| {
                let wire = tai.encode(EncodeContext::default())?;
                Ok(asn::UserLocationInformationN3IWFWithPortNumberIEExtensions(vec![
                    asn::AnonymousUserLocationInformationN3IWFWithPortNumberIEExtensions::new(
                        ProtocolExtensionID(213), Criticality::ignore, rasn::types::Any::new(wire.as_bytes().to_vec()),
                    ),
                ]))
            }).transpose()?;
            asn::UserLocationInformation::userLocationInformationN3IWF_with_PortNumber(
                asn::UserLocationInformationN3IWFWithPortNumber::new(
                    address,
                    asn::PortNumber(port.to_be_bytes().into()),
                    extensions,
                ),
            )
        } else {
            let inner = asn::UserLocationInformationN3IWFWithoutPortNumber::new(
                address,
                self.tai.as_ref().map(TrackingArea::generated),
                None,
            );
            let wire = encode_leaf(&inner, EncodeContext::default())?;
            // The generated CHOICE extension encoder does not align its
            // ProtocolIE-SingleContainer ID. Keep the independently qualified
            // inner encoder and write the fixed outer framing explicitly.
            let length = 4 + constructed::open_type_len(wire.as_bytes().len())?;
            capacity(length, ctx)?;
            let mut output = Zeroizing::new(Vec::with_capacity(length));
            output.extend_from_slice(&[0xc0, 1, 183, 0x40]);
            constructed::write_open_type(&mut output, wire.as_bytes());
            return Ok(EncodedValue(output));
        };
        encode_leaf(&value, ctx)
    }
    /// Decode a bounded admitted location with a depth limit of at least four.
    /// Unsupported nested extensions fail explicitly; none is silently dropped.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 4)?;
        decode_location(input, ctx)
    }
}

fn ip(bytes: &[u8]) -> Result<IpAddr, DecodeError> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().map_err(|_| unsupported())?;
            Ok(octets.into())
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().map_err(|_| unsupported())?;
            Ok(octets.into())
        }
        _ => Err(unsupported()),
    }
}

// Explicit bounded receive layout avoids the generated decoder's fixed
// OCTET STRING alignment defect (TAI PLMN/TAC) and never allocates a
// wire-controlled SequenceOf. Generated encoders remain independently checked.
fn decode_location(input: &[u8], ctx: DecodeContext) -> Result<N3iwfLocation, DecodeError> {
    let first = *input.first().ok_or_else(|| invalid("location prefix"))?;
    if first >> 6 == 2 {
        if first & 0x28 != 0 {
            return Err(unsupported());
        }
        let second = *input.get(1).ok_or_else(|| invalid("location prefix"))?;
        let bits = (usize::from(first & 7) << 5 | usize::from(second >> 3)) + 1;
        if bits != 32 && bits != 128 {
            return Err(unsupported());
        }
        let fixed = 2 + bits / 8 + 2;
        if input.len() < fixed {
            return Err(invalid("location endpoint width"));
        }
        let address = ip(&input[2..fixed - 2])?;
        let port = u16::from_be_bytes([input[fixed - 2], input[fixed - 1]]);
        let tai = if first & 0x10 == 0 {
            if input.len() != fixed {
                return Err(invalid("trailing location bytes"));
            }
            None
        } else {
            let count_bytes: [u8; 2] = input
                .get(fixed..fixed + 2)
                .ok_or_else(|| invalid("location extension count"))?
                .try_into()
                .map_err(|_| invalid("location extension count"))?;
            let count = usize::from(u16::from_be_bytes(count_bytes)) + 1;
            if count > ctx.max_ies {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
            }
            if count != 1 {
                return Err(unsupported());
            }
            let extension = aper::ie(&input[fixed + 2..])?;
            if extension.header[..3] != [0, 213, 0x40] {
                return Err(unsupported());
            }
            if !extension.remainder.is_empty() {
                return Err(invalid("trailing location extension bytes"));
            }
            Some(TrackingArea::decode(&extension.value, ctx)?)
        };
        Ok(N3iwfLocation {
            address,
            port: Some(port),
            tai,
        })
    } else if first >> 6 == 3 {
        if ctx.max_ies == 0 {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, 0));
        }
        let extension = aper::ie(&input[1..])?;
        if extension.header[..3] != [1, 183, 0x40] {
            return Err(unsupported());
        }
        if !extension.remainder.is_empty() {
            return Err(invalid("trailing location bytes"));
        }
        let inner = &extension.value;
        let prefix = *inner.first().ok_or_else(|| invalid("location prefix"))?;
        if prefix & 0xb0 != 0 {
            return Err(unsupported());
        }
        let second = *inner.get(1).ok_or_else(|| invalid("location prefix"))?;
        let bits = (usize::from(prefix & 15) << 4 | usize::from(second >> 4)) + 1;
        if bits != 32 && bits != 128 {
            return Err(unsupported());
        }
        let fixed = 2 + bits / 8;
        let address = ip(inner
            .get(2..fixed)
            .ok_or_else(|| invalid("location width"))?)?;
        let tai = if prefix & 0x40 != 0 {
            Some(TrackingArea::decode(&inner[fixed..], ctx)?)
        } else {
            if inner.len() != fixed {
                return Err(invalid("location width"));
            }
            None
        };
        Ok(N3iwfLocation {
            address,
            port: None,
            tai,
        })
    } else {
        Err(unsupported())
    }
}
