//! Bounded NAS identity and AMF-reroute root fields, without identity,
//! subscriber, routing or AMF-selection authority. Diagnostics are redacted.
//! ASN.1 extensions fail explicitly; the generic PDU retains its raw bytes.

use super::*;

/// A fixed ten-bit AMF Set ID. Its enclosing message defines its meaning.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AmfSetId(u16);
redacted!(AmfSetId);
impl AmfSetId {
    /// Admit the ten-bit range without truncation or AMF selection.
    pub fn new(value: u16) -> Result<Self, DecodeError> {
        if value >= 1024 {
            return Err(invalid("amf set id range"));
        }
        Ok(Self(value))
    }
    /// Explicit access to the numeric identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
    /// Encode ten bits and six zero padding bits in two octets.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(2, ctx)?;
        Ok(EncodedValue(Zeroizing::new(
            (self.0 << 6).to_be_bytes().to_vec(),
        )))
    }
    /// Decode the exact two-octet root at depth one, rejecting padding.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        if input.len() != 2 || input[1] & 0x3f != 0 {
            return Err(invalid("amf set id extent or padding"));
        }
        Ok(Self(u16::from_be_bytes([input[0], input[1]]) >> 6))
    }
}

/// Root 5G-S-TMSI with distinct AMF Set ID, six-bit pointer and four TMSI octets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FiveGStmsi {
    set: AmfSetId,
    pointer: u8,
    tmsi: [u8; 4],
}
redacted!(FiveGStmsi);
impl FiveGStmsi {
    /// Bind caller-provided identity components, requiring a six-bit pointer.
    pub fn new(set: AmfSetId, pointer: u8, tmsi: [u8; 4]) -> Result<Self, DecodeError> {
        if pointer >= 64 {
            return Err(invalid("amf pointer range"));
        }
        Ok(Self { set, pointer, tmsi })
    }
    /// Explicit access to the identity's AMF Set ID.
    pub const fn amf_set_id(self) -> AmfSetId {
        self.set
    }
    /// Explicit access to the six-bit AMF pointer.
    pub const fn amf_pointer(self) -> u8 {
        self.pointer
    }
    /// Explicit access to the TMSI octets in their wire order.
    pub const fn tmsi(&self) -> &[u8; 4] {
        &self.tmsi
    }
    /// Encode the bounded root, retaining the alignment before the TMSI.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(7, ctx)?;
        let packed = ((u32::from(self.set.0) << 6) | u32::from(self.pointer)) << 6;
        let mut wire = Vec::with_capacity(7);
        wire.extend_from_slice(&packed.to_be_bytes()[1..]);
        wire.extend_from_slice(&self.tmsi);
        Ok(EncodedValue(Zeroizing::new(wire)))
    }
    /// Decode exactly seven octets at depth two. Extensions and nonzero
    /// alignment padding are rejected before exposing any identity component.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        if input.len() != 7 || input[0] & 0xc0 != 0 || input[2] & 0x3f != 0 {
            return Err(invalid("5g s-tmsi root extent flags or padding"));
        }
        let packed = u32::from_be_bytes([0, input[0], input[1], input[2]]) >> 6;
        Ok(Self {
            set: AmfSetId((packed >> 6) as u16),
            pointer: (packed & 0x3f) as u8,
            tmsi: [input[3], input[4], input[5], input[6]],
        })
    }
}

/// Fixed 64-bit Masked IMEISV, preserved without subscriber interpretation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MaskedImeisv([u8; 8]);
redacted!(MaskedImeisv);
impl MaskedImeisv {
    /// Preserve the fixed wire bits without reinterpreting or repairing them.
    pub const fn new(value: [u8; 8]) -> Self {
        Self(value)
    }
    /// Explicit access to the masked identity's wire octets.
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
    /// Encode the eight-octet root after exact capacity preflight.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(8, ctx)?;
        Ok(EncodedValue(Zeroizing::new(self.0.to_vec())))
    }
    /// Decode exactly eight octets at depth one.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        Ok(Self(
            input
                .try_into()
                .map_err(|_| invalid("masked imeisv extent"))?,
        ))
    }
}

/// Opaque source-to-target AMF reroute information. Fixed-size root containers
/// are preserved; this type does not interpret NSSF information or reroute NAS.
#[derive(Clone, PartialEq, Eq)]
pub struct AmfRerouteInformation {
    configured: Option<Box<[u8; 128]>>,
    rejected_plmn: Option<[u8; 32]>,
    rejected_ta: Option<[u8; 32]>,
}
redacted!(AmfRerouteInformation);
impl AmfRerouteInformation {
    /// Preserve each independent optional container; an empty root is valid.
    pub fn new(
        configured: Option<[u8; 128]>,
        rejected_plmn: Option<[u8; 32]>,
        rejected_ta: Option<[u8; 32]>,
    ) -> Self {
        Self {
            configured: configured.map(Box::new),
            rejected_plmn,
            rejected_ta,
        }
    }
    /// Explicit access to the opaque Configured NSSAI container.
    pub fn configured_nssai(&self) -> Option<&[u8; 128]> {
        self.configured.as_deref()
    }
    /// Explicit access to the opaque Rejected NSSAI in PLMN container.
    pub fn rejected_nssai_in_plmn(&self) -> Option<&[u8; 32]> {
        self.rejected_plmn.as_ref()
    }
    /// Explicit access to the opaque Rejected NSSAI in TA container.
    pub fn rejected_nssai_in_ta(&self) -> Option<&[u8; 32]> {
        self.rejected_ta.as_ref()
    }
    /// Encode the root presence bits and fixed containers, at most 193 octets.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let size = 1
            + 128 * usize::from(self.configured.is_some())
            + 32 * usize::from(self.rejected_plmn.is_some())
            + 32 * usize::from(self.rejected_ta.is_some());
        capacity(size, ctx)?;
        let mut wire = Vec::with_capacity(size);
        wire.push(
            (u8::from(self.configured.is_some()) << 6)
                | (u8::from(self.rejected_plmn.is_some()) << 5)
                | (u8::from(self.rejected_ta.is_some()) << 4),
        );
        if let Some(value) = &self.configured {
            wire.extend_from_slice(value.as_ref());
        }
        if let Some(value) = &self.rejected_plmn {
            wire.extend_from_slice(value);
        }
        if let Some(value) = &self.rejected_ta {
            wire.extend_from_slice(value);
        }
        Ok(EncodedValue(Zeroizing::new(wire)))
    }
    /// Decode the bounded root at depth two. Extensions, padding, truncated
    /// containers and trailing octets fail before any value is returned.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let (&flags, mut rest) = input
            .split_first()
            .ok_or_else(|| invalid("amf reroute extent"))?;
        if flags & 0x8f != 0 {
            return Err(invalid("amf reroute flags or padding"));
        }
        let configured = take_fixed::<128>(&mut rest, flags & 0x40 != 0)?;
        let rejected_plmn = take_fixed::<32>(&mut rest, flags & 0x20 != 0)?;
        let rejected_ta = take_fixed::<32>(&mut rest, flags & 0x10 != 0)?;
        if !rest.is_empty() {
            return Err(invalid("amf reroute trailing bytes"));
        }
        Ok(Self::new(configured, rejected_plmn, rejected_ta))
    }
}
fn take_fixed<const N: usize>(
    rest: &mut &[u8],
    present: bool,
) -> Result<Option<[u8; N]>, DecodeError> {
    if !present {
        return Ok(None);
    }
    let value = rest
        .get(..N)
        .ok_or_else(|| invalid("amf reroute truncated container"))?;
    let value = value
        .try_into()
        .map_err(|_| invalid("amf reroute container extent"))?;
    *rest = &rest[N..];
    Ok(Some(value))
}

/// Extended AMF Name root with independent optional VisibleString and UTF8
/// names. This is a SEQUENCE, not a choice; both present and both absent are
/// preserved. Each present name contains one through 150 ASN.1 characters.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedAmfName {
    visible: Option<String>,
    utf8: Option<String>,
}
redacted!(ExtendedAmfName);
impl ExtendedAmfName {
    /// Check byte/alphabet/character bounds before copying caller strings.
    pub fn new(visible: Option<&str>, utf8: Option<&str>) -> Result<Self, DecodeError> {
        if let Some(value) = visible {
            if value.is_empty()
                || value.len() > 150
                || !value.bytes().all(|c| (32..=126).contains(&c))
            {
                return Err(invalid("extended amf visible name root"));
            }
        }
        if let Some(value) = utf8 {
            if value.is_empty() || value.len() > 600 || value.chars().count() > 150 {
                return Err(invalid("extended amf utf8 name root"));
            }
        }
        Ok(Self {
            visible: visible.map(str::to_owned),
            utf8: utf8.map(str::to_owned),
        })
    }
    /// Explicit access to the optional VisibleString name.
    pub fn visible(&self) -> Option<&str> {
        self.visible.as_deref()
    }
    /// Explicit access to the optional UTF8String name.
    pub fn utf8(&self) -> Option<&str> {
        self.utf8.as_deref()
    }
    /// Encode at most 754 octets with exact-size capacity preflight.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let size = self.visible.as_ref().map_or(1, |v| 2 + v.len())
            + self
                .utf8
                .as_ref()
                .map_or(0, |v| v.len() + if v.len() < 128 { 1 } else { 2 });
        capacity(size, ctx)?;
        let mut wire = Vec::with_capacity(size);
        let flags = (u8::from(self.visible.is_some()) << 6) | (u8::from(self.utf8.is_some()) << 5);
        if let Some(value) = &self.visible {
            let length = value.len() - 1;
            wire.push(flags | (length >> 5) as u8);
            wire.push((length << 3) as u8);
            wire.extend_from_slice(value.as_bytes());
        } else {
            wire.push(flags);
        }
        if let Some(value) = &self.utf8 {
            if value.len() < 128 {
                wire.push(value.len() as u8);
            } else {
                wire.extend_from_slice(&(0x8000 | value.len() as u16).to_be_bytes());
            }
            wire.extend_from_slice(value.as_bytes());
        }
        Ok(EncodedValue(Zeroizing::new(wire)))
    }
    /// Decode at depth two, bounding UTF-8 octets before allocation. Reject
    /// non-root VisibleString lengths, invalid UTF-8, oversized character
    /// counts, noncanonical lengths, extensions, padding and trailing bytes.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let (&flags, mut rest) = input
            .split_first()
            .ok_or_else(|| invalid("extended amf name extent"))?;
        if flags & 0x90 != 0 {
            return Err(unsupported());
        }
        let visible = if flags & 0x40 != 0 {
            if flags & 0x08 != 0 {
                return Err(unsupported());
            }
            let (&second, tail) = rest
                .split_first()
                .ok_or_else(|| invalid("extended amf visible length"))?;
            let length = (usize::from(flags & 7) << 5 | usize::from(second >> 3)) + 1;
            if second & 7 != 0 || length > 150 {
                return Err(invalid("extended amf visible length or padding"));
            }
            let value = tail
                .get(..length)
                .ok_or_else(|| invalid("extended amf visible extent"))?;
            rest = &tail[length..];
            Some(std::str::from_utf8(value).map_err(|_| invalid("extended amf visible alphabet"))?)
        } else {
            if flags & 0x0f != 0 {
                return Err(invalid("extended amf name padding"));
            }
            None
        };
        let utf8 = if flags & 0x20 != 0 {
            let (&first, tail) = rest
                .split_first()
                .ok_or_else(|| invalid("extended amf utf8 length"))?;
            rest = tail;
            let length = if first & 0x80 == 0 {
                usize::from(first)
            } else {
                if first & 0x40 != 0 {
                    return Err(invalid("extended amf utf8 fragmented length"));
                }
                let (&second, tail) = rest
                    .split_first()
                    .ok_or_else(|| invalid("extended amf utf8 length"))?;
                rest = tail;
                let length = usize::from(first & 0x3f) << 8 | usize::from(second);
                if length < 128 {
                    return Err(invalid("extended amf utf8 noncanonical length"));
                }
                length
            };
            if length == 0 || length > 600 {
                return Err(invalid("extended amf utf8 octet bound"));
            }
            let value = rest
                .get(..length)
                .ok_or_else(|| invalid("extended amf utf8 extent"))?;
            rest = &rest[length..];
            Some(std::str::from_utf8(value).map_err(|_| invalid("extended amf invalid utf8"))?)
        } else {
            None
        };
        if !rest.is_empty() {
            return Err(invalid("extended amf name trailing bytes"));
        }
        Self::new(visible, utf8)
    }
}
