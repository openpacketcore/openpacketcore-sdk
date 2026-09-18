//! Qualified NG Setup root fields. No AMF or slice selection is performed.
//!
//! Generated encoders handle global N3IWF ID, served GUAMIs and AMF name.
//! The two PLMN/slice list shapes need explicit root framing: the generated
//! encoder loses the parent bit offset for constrained nested SEQUENCE OF.
//! All receivers reject unsupported extensions and bound field bytes/depth.
//! List receivers additionally charge every TA, PLMN, GUAMI and slice item
//! against the field-local `max_ies` budget before allocating each list.
use super::*;
use opc_types::Snssai;

/// Global RAN identifier restricted to the N3IWF choice.
#[derive(Clone, PartialEq, Eq)]
pub struct GlobalN3iwfId {
    plmn: PlmnId,
    id: u16,
}
redacted!(GlobalN3iwfId);
impl GlobalN3iwfId {
    /// Bind an explicit PLMN and 16-bit N3IWF identifier.
    pub const fn new(plmn: PlmnId, id: u16) -> Self {
        Self { plmn, id }
    }
    /// Explicit access to the PLMN.
    pub const fn plmn(&self) -> &PlmnId {
        &self.plmn
    }
    /// Explicit access to the N3IWF identifier.
    pub const fn id(&self) -> u16 {
        self.id
    }
    /// Encode the generated root choice.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(7, ctx)?;
        encode_leaf(
            &asn::GlobalRANNodeID::globalN3IWF_ID(asn::GlobalN3IWFID::new(
                asn::PLMNIdentity(plmn_bytes(&self.plmn).into()),
                asn::N3IWFID::n3IWF_ID(rasn::types::BitString::from_slice(&self.id.to_be_bytes())),
                None,
            )),
            ctx,
        )
    }
    /// Decode only the root N3IWF choice, rejecting extensions before allocation.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 4)?;
        let mut reader = Reader::new(input, ctx);
        if reader.bits(2)? != 2 {
            return Err(unsupported());
        }
        reader.flags(2)?;
        let plmn = reader.plmn()?;
        reader.flags(1)?;
        let id = reader.bits(16)?;
        reader.finish()?;
        Ok(Self { plmn, id })
    }
}

/// AMF identity without extension additions.
#[derive(Clone, PartialEq, Eq)]
pub struct Guami {
    plmn: PlmnId,
    region: u8,
    set: u16,
    pointer: u8,
}
redacted!(Guami);
impl Guami {
    /// Enforce the 10-bit AMF set and 6-bit AMF pointer ranges.
    pub fn new(plmn: PlmnId, region: u8, set: u16, pointer: u8) -> Result<Self, DecodeError> {
        if set > 1023 || pointer > 63 {
            return Err(invalid("guami range"));
        }
        Ok(Self {
            plmn,
            region,
            set,
            pointer,
        })
    }
    /// Explicit access to the PLMN.
    pub const fn plmn(&self) -> &PlmnId {
        &self.plmn
    }
    /// Explicit access to the AMF region.
    pub const fn region(&self) -> u8 {
        self.region
    }
    /// Explicit access to the AMF set.
    pub const fn set(&self) -> u16 {
        self.set
    }
    /// Explicit access to the AMF pointer.
    pub const fn pointer(&self) -> u8 {
        self.pointer
    }
    /// Encode the standalone root GUAMI IE, without extensions.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(7, ctx)?;
        encode_leaf(&self.generated(), ctx)
    }
    /// Decode a standalone root GUAMI; requires depth two.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let mut reader = Reader::new(input, ctx);
        let value = reader.guami()?;
        reader.finish()?;
        Ok(value)
    }
    fn generated(&self) -> asn::GUAMI {
        asn::GUAMI::new(
            asn::PLMNIdentity(plmn_bytes(&self.plmn).into()),
            asn::AMFRegionID(fixed_bits(u16::from(self.region))),
            asn::AMFSetID(fixed_bits(self.set)),
            asn::AMFPointer(fixed_bits(u16::from(self.pointer))),
            None,
        )
    }
}
fn fixed_bits<const N: usize>(value: u16) -> rasn::types::FixedBitString<N> {
    let mut bits = rasn::types::FixedBitString::<N>::ZERO;
    for i in 0..N {
        bits.set(i, value & (1 << (N - 1 - i)) != 0);
    }
    bits
}

/// PLMN and its supported slices. These are advertised values, not authorization.
#[derive(Clone, PartialEq, Eq)]
pub struct PlmnSlices {
    plmn: PlmnId,
    slices: Vec<Snssai>,
}
redacted!(PlmnSlices);
impl PlmnSlices {
    /// Require the ASN.1 root slice count (1..=1024).
    pub fn new(plmn: PlmnId, slices: Vec<Snssai>) -> Result<Self, DecodeError> {
        root_count(slices.len(), 1024)?;
        Ok(Self { plmn, slices })
    }
    /// Explicit access to the PLMN.
    pub const fn plmn(&self) -> &PlmnId {
        &self.plmn
    }
    /// Explicit access to the shared SDK slice identifiers.
    pub fn slices(&self) -> &[Snssai] {
        &self.slices
    }
}
fn sd_octets(sd: &str) -> [u8; 3] {
    // Snssai owns validated, normalized six-character hexadecimal text.
    fn digit(value: u8) -> u8 {
        if value <= b'9' {
            value - b'0'
        } else {
            value - b'a' + 10
        }
    }
    let bytes = sd.as_bytes();
    [
        digit(bytes[0]) << 4 | digit(bytes[1]),
        digit(bytes[2]) << 4 | digit(bytes[3]),
        digit(bytes[4]) << 4 | digit(bytes[5]),
    ]
}

/// Tracking area and its broadcast PLMNs.
#[derive(Clone, PartialEq, Eq)]
pub struct SupportedTa {
    tac: [u8; 3],
    plmns: Vec<PlmnSlices>,
}
redacted!(SupportedTa);
impl SupportedTa {
    /// Require 1..=12 broadcast PLMNs.
    pub fn new(tac: [u8; 3], plmns: Vec<PlmnSlices>) -> Result<Self, DecodeError> {
        root_count(plmns.len(), 12)?;
        Ok(Self { tac, plmns })
    }
    /// Explicit access to the TAC.
    pub const fn tac(&self) -> [u8; 3] {
        self.tac
    }
    /// Explicit access to broadcast PLMNs and slices.
    pub fn plmns(&self) -> &[PlmnSlices] {
        &self.plmns
    }
}

/// Served GUAMIs with independent optional backup AMF names; no extensions.
#[derive(Clone, PartialEq, Eq)]
pub struct ServedGuamiList {
    identities: Vec<Guami>,
    // Kept index-aligned by the two constructors and the bounded decoder.
    backups: Vec<Option<AmfName>>,
}
redacted!(ServedGuamiList);
impl ServedGuamiList {
    /// Require the ASN.1 root count (1..=256).
    pub fn new(values: Vec<Guami>) -> Result<Self, DecodeError> {
        root_count(values.len(), 256)?;
        let backups = vec![None; values.len()];
        Ok(Self {
            identities: values,
            backups,
        })
    }
    /// Require 1..=256 entries and preserve each optional backup name.
    /// Names advertise peer information; they do not select or activate an AMF.
    pub fn with_backups(values: Vec<(Guami, Option<AmfName>)>) -> Result<Self, DecodeError> {
        root_count(values.len(), 256)?;
        let (identities, backups) = values.into_iter().unzip();
        Ok(Self {
            identities,
            backups,
        })
    }
    /// Explicit access to the advertised identities.
    pub fn values(&self) -> &[Guami] {
        &self.identities
    }
    /// Explicit access to identities and their associated optional names.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (&Guami, Option<&AmfName>)> {
        self.identities
            .iter()
            .zip(self.backups.iter().map(Option::as_ref))
    }
    /// Preflight exact output size before allocating the field output.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = 1
            + 7 * self.identities.len()
            + self
                .backups
                .iter()
                .flatten()
                .map(|name| 2 + name.as_str().len())
                .sum::<usize>();
        capacity(length, ctx)?;
        let value = asn::ServedGUAMIList(
            self.entries()
                .map(|(v, name)| {
                    let name = name
                        .map(|name| {
                            rasn::types::PrintableString::try_from(name.as_str().as_bytes())
                                .map(asn::AMFName)
                                .map_err(|_| encode_invalid())
                        })
                        .transpose()?;
                    Ok(asn::ServedGUAMIItem::new(v.generated(), name, None))
                })
                .collect::<Result<_, EncodeError>>()?,
        );
        encode_collection(&value, length, ctx)
    }
    /// Bounds each list before allocating. `max_ies` also caps this field's
    /// cumulative list items; depth four is required.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 4)?;
        let mut reader = Reader::new(input, ctx);
        let count = reader.count(8, 256, 53)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            reader.flags(1)?;
            let backup = reader.bits(1)? != 0;
            reader.flags(1)?;
            let identity = reader.guami()?;
            let name = if backup {
                Some(reader.amf_name()?)
            } else {
                None
            };
            values.push((identity, name));
        }
        reader.finish()?;
        Self::with_backups(values)
    }
}

/// Supported PLMNs and slices in NG Setup Response.
#[derive(Clone, PartialEq, Eq)]
pub struct PlmnSupportList(Vec<PlmnSlices>);
redacted!(PlmnSupportList);
impl PlmnSupportList {
    /// Require the ASN.1 root count (1..=12).
    pub fn new(values: Vec<PlmnSlices>) -> Result<Self, DecodeError> {
        root_count(values.len(), 12)?;
        Ok(Self(values))
    }
    /// Explicit access to supported PLMNs.
    pub fn values(&self) -> &[PlmnSlices] {
        &self.0
    }
    /// Preflight exact output size before allocating the field output.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let mut size = Size(4);
        for value in &self.0 {
            size.plmn(value);
        }
        let length = size.bytes();
        capacity(length, ctx)?;
        let mut writer = Writer::new(length);
        writer.plmns(&self.0)?;
        writer.finish()
    }
    /// Bounds cumulative PLMN and slice items by `max_ies` before allocation;
    /// requires depth six. All nested extensions are unsupported.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 6)?;
        let mut reader = Reader::new(input, ctx);
        let values = reader.plmns()?;
        reader.finish()?;
        Ok(Self(values))
    }
}

/// Supported tracking areas, broadcast PLMNs and slices in NG Setup Request.
#[derive(Clone, PartialEq, Eq)]
pub struct SupportedTaList(Vec<SupportedTa>);
redacted!(SupportedTaList);
impl SupportedTaList {
    /// Require the ASN.1 root count (1..=256).
    pub fn new(values: Vec<SupportedTa>) -> Result<Self, DecodeError> {
        root_count(values.len(), 256)?;
        Ok(Self(values))
    }
    /// Explicit access to tracking areas.
    pub fn values(&self) -> &[SupportedTa] {
        &self.0
    }
    /// Preflight exact output size before allocating the field output.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let mut size = Size(8);
        for value in &self.0 {
            size.0 += 2;
            size.align();
            size.0 += 24 + 4;
            for plmn in &value.plmns {
                size.plmn(plmn);
            }
        }
        let length = size.bytes();
        capacity(length, ctx)?;
        let mut writer = Writer::new(length);
        writer.bits((self.0.len() - 1) as u16, 8)?;
        for ta in &self.0 {
            writer.bits(0, 2)?;
            writer.octets(ta.tac)?;
            writer.plmns(&ta.plmns)?;
        }
        writer.finish()
    }
    /// Bounds cumulative TA, PLMN and slice items by `max_ies` before each list
    /// allocation; requires depth eight. No extension lists are materialized.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 8)?;
        let mut reader = Reader::new(input, ctx);
        let count = reader.count(8, 256, 85)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            reader.flags(2)?;
            let tac = reader.octets()?;
            let plmns = reader.plmns()?;
            values.push(SupportedTa { tac, plmns });
        }
        reader.finish()?;
        Ok(Self(values))
    }
}

/// AMF name in the root PrintableString range, 1..=150 characters.
#[derive(Clone, PartialEq, Eq)]
pub struct AmfName(String);
redacted!(AmfName);
impl AmfName {
    /// Enforce the root length and PrintableString alphabet before copying.
    pub fn new(value: &str) -> Result<Self, DecodeError> {
        root_count(value.len(), 150)?;
        if !value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&v))
        {
            return Err(invalid("amf name alphabet"));
        }
        Ok(Self(value.to_owned()))
    }
    /// Explicit access to the advertised name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Encode the generated root PrintableString after capacity preflight.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = 2 + self.0.len();
        capacity(length, ctx)?;
        let name = rasn::types::PrintableString::try_from(self.0.as_bytes())
            .map_err(|_| encode_invalid())?;
        encode_collection(&asn::AMFName(name), length, ctx)
    }
    /// Reject an extension length before generated string decoding.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        if input.first().is_some_and(|v| v & 0x80 != 0) {
            return Err(unsupported());
        }
        let value: asn::AMFName = decode_leaf(input)?;
        let bytes: &[u8] = value.0.as_ref();
        Self::new(std::str::from_utf8(bytes).map_err(|_| invalid("amf name alphabet"))?)
    }
}

/// RAN node name with the same root PrintableString layout as AMFName.
#[derive(Clone, PartialEq, Eq)]
pub struct RanNodeName(AmfName);
redacted!(RanNodeName);
impl RanNodeName {
    /// Require one through 150 characters from the PrintableString alphabet.
    pub fn new(value: &str) -> Result<Self, DecodeError> {
        AmfName::new(value).map(Self)
    }
    /// Explicit access to the advertised name.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    /// Encode the independently qualified identical root layout.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.0.encode(ctx)
    }
    /// Decode the root at depth one; reject unsupported extension lengths.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        AmfName::decode(input, ctx).map(Self)
    }
}

/// Extended RAN node name preserving both independent optional name strings.
/// Its root layout and bounds match Extended-AMFName, with distinct IE binding.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedRanNodeName(super::nas_fields::ExtendedAmfName);
redacted!(ExtendedRanNodeName);
impl ExtendedRanNodeName {
    /// Check the independent VisibleString/UTF8String root bounds before copying.
    pub fn new(visible: Option<&str>, utf8: Option<&str>) -> Result<Self, DecodeError> {
        super::nas_fields::ExtendedAmfName::new(visible, utf8).map(Self)
    }
    /// Explicit access to the optional VisibleString name.
    pub fn visible(&self) -> Option<&str> {
        self.0.visible()
    }
    /// Explicit access to the optional UTF8String name.
    pub fn utf8(&self) -> Option<&str> {
        self.0.utf8()
    }
    /// Encode at most 754 octets after exact-size capacity preflight.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        self.0.encode(ctx)
    }
    /// Decode at depth two, rejecting extensions, invalid strings and padding.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        super::nas_fields::ExtendedAmfName::decode(input, ctx).map(Self)
    }
}

/// Root peer report that UE contexts were retained. It grants no local authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UeRetentionInformation {
    /// The sender reports retained UE contexts.
    UesRetained,
}
redacted!(UeRetentionInformation);
impl UeRetentionInformation {
    /// Encode the one root enumeration value with zero padding.
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(1, ctx)?;
        Ok(EncodedValue(Zeroizing::new(vec![0])))
    }
    /// Require exactly one zero octet at depth one. Extension enum values
    /// remain unsupported, and padding/trailing octets are never accepted.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        if input.first().is_some_and(|v| v & 0x80 != 0) {
            return Err(unsupported());
        }
        if input != [0] {
            return Err(invalid("ue retention root encoding"));
        }
        Ok(Self::UesRetained)
    }
}

fn root_count(count: usize, maximum: usize) -> Result<(), DecodeError> {
    if count == 0 || count > maximum {
        Err(invalid("setup root count"))
    } else {
        Ok(())
    }
}
fn encode_invalid() -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural {
        reason: "setup field encoding",
    })
}
fn encode_collection<T: rasn::Encode>(
    value: &T,
    expected: usize,
    ctx: EncodeContext,
) -> Result<EncodedValue, EncodeError> {
    let wire = Zeroizing::new(rasn::aper::encode(value).map_err(|_| encode_invalid())?);
    if wire.len() != expected {
        return Err(encode_invalid());
    }
    capacity(wire.len(), ctx)?;
    Ok(EncodedValue(wire))
}

// Exact root layout sizing is allocation-free. Constructors bound every list,
// so even the largest schema-valid shape fits usize on supported 32-bit hosts.
pub(super) struct Size(pub(super) usize);
impl Size {
    fn align(&mut self) {
        self.0 = self.0.div_ceil(8) * 8;
    }
    pub(super) fn bytes(&self) -> usize {
        self.0.div_ceil(8)
    }
    fn plmn(&mut self, value: &PlmnSlices) {
        self.0 += 2;
        self.align();
        self.0 += 24;
        self.align();
        self.0 += 16;
        for slice in &value.slices {
            self.0 += 2;
            self.snssai(slice);
        }
    }
    pub(super) fn snssai(&mut self, slice: &Snssai) {
        self.0 += 3 + 8;
        if slice.sd().is_some() {
            self.align();
            self.0 += 24;
        }
    }
}

// This is a reader for the above root shapes, not a general ASN.1 codec. The
// fixed >2-octet fields must align after flags (rasn 0.28 misses this on read).
// Padding must be zero; unknown extensions are rejected before their payloads.
pub(super) struct Reader<'a> {
    input: &'a [u8],
    bit: usize,
    items_left: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(input: &'a [u8], ctx: DecodeContext) -> Self {
        Self {
            input,
            bit: 0,
            items_left: ctx.max_ies,
        }
    }
    pub(super) fn bits(&mut self, width: usize) -> Result<u16, DecodeError> {
        let mut value = 0;
        for _ in 0..width {
            let byte = self
                .input
                .get(self.bit / 8)
                .ok_or_else(|| invalid("truncated setup field"))?;
            value = (value << 1) | u16::from((byte >> (7 - self.bit % 8)) & 1);
            self.bit += 1;
        }
        Ok(value)
    }
    pub(super) fn flags(&mut self, width: usize) -> Result<(), DecodeError> {
        if self.bits(width)? != 0 {
            return Err(unsupported());
        }
        Ok(())
    }
    pub(super) fn align(&mut self) -> Result<(), DecodeError> {
        let padding = (8 - self.bit % 8) % 8;
        if self.bits(padding)? != 0 {
            return Err(invalid("setup field padding"));
        }
        Ok(())
    }
    fn amf_name(&mut self) -> Result<AmfName, DecodeError> {
        self.flags(1)?; // PrintableString extension length.
        let length = usize::from(self.bits(8)?) + 1;
        root_count(length, 150)?;
        self.align()?;
        let start = self.bit / 8;
        let bytes = self
            .input
            .get(start..start + length)
            .ok_or_else(|| invalid("truncated backup amf name"))?;
        let name = AmfName::new(
            std::str::from_utf8(bytes).map_err(|_| invalid("backup amf name alphabet"))?,
        )?;
        self.bit += length * 8;
        Ok(name)
    }
    /// Borrow the determinant and all fragments after complete size preflight.
    pub(super) fn framed_octets(&mut self, maximum: usize) -> Result<&'a [u8], DecodeError> {
        self.align()?;
        let start = self.bit / 8;
        let tail = self
            .input
            .get(start..)
            .ok_or_else(|| invalid("truncated octets"))?;
        let (rest, length) = aper::scan_open_type(tail)?;
        if length > maximum {
            return Err(invalid("contained field length"));
        }
        self.bit = (self.input.len() - rest.len()) * 8;
        Ok(&tail[..tail.len() - rest.len()])
    }
    pub(super) fn open_octets(&mut self, maximum: usize) -> Result<Cow<'a, [u8]>, DecodeError> {
        self.align()?;
        let start = self.bit / 8;
        let tail = self
            .input
            .get(start..)
            .ok_or_else(|| invalid("truncated octets"))?;
        if matches!(tail, [0x80, second, ..] if *second < 128) {
            return Err(invalid("nonminimal contained field length"));
        }
        // A qualified small root cannot contain a 16K fragment. Reject before
        // the shared scanner would coalesce it; larger fields remain bounded
        // by the already checked enclosing input and physical fragment sizes.
        if maximum < 16384 && tail.first().is_some_and(|v| *v >= 192) {
            return Err(invalid("contained field length"));
        }
        let (rest, value) = aper::open_type(tail)?;
        if value.len() > maximum {
            return Err(invalid("contained field length"));
        }
        self.bit = (self.input.len() - rest.len()) * 8;
        Ok(value)
    }
    fn octets(&mut self) -> Result<[u8; 3], DecodeError> {
        self.align()?;
        Ok([
            self.bits(8)? as u8,
            self.bits(8)? as u8,
            self.bits(8)? as u8,
        ])
    }
    fn plmn(&mut self) -> Result<PlmnId, DecodeError> {
        decode_plmn(&self.octets()?)
    }
    pub(super) fn count(
        &mut self,
        width: usize,
        maximum: usize,
        minimum_bits: usize,
    ) -> Result<usize, DecodeError> {
        if width >= 8 {
            self.align()?;
        }
        let count = usize::from(self.bits(width)?) + 1;
        root_count(count, maximum)?;
        self.items_left = self
            .items_left
            .checked_sub(count)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::IeCountExceeded, 0))?;
        let available = self.input.len().saturating_mul(8).saturating_sub(self.bit);
        if count > available / minimum_bits {
            return Err(invalid("truncated setup list"));
        }
        Ok(count)
    }
    /// One aligned PER fragment of a SEQUENCE OF whose upper bound is at
    /// least 65536. Counts are elements, never octets. Reserve the cumulative
    /// caller budget and require physical minimum space before allocation.
    pub(super) fn fragment_count(
        &mut self,
        maximum_remaining: usize,
        minimum_bits: usize,
    ) -> Result<(usize, bool), DecodeError> {
        self.align()?;
        let first = self.bits(8)?;
        let (count, fragmented) = if first < 128 {
            (usize::from(first), false)
        } else if first < 192 {
            let count = usize::from((first & 127) * 256 + self.bits(8)?);
            if count < 128 {
                return Err(invalid("nonminimal list determinant"));
            }
            (count, false)
        } else {
            let blocks = first & 63;
            if !(1..=4).contains(&blocks) {
                return Err(invalid("list fragment multiplier"));
            }
            (usize::from(blocks) * 16384, true)
        };
        if count > maximum_remaining {
            return Err(invalid("list root count"));
        }
        self.items_left = self
            .items_left
            .checked_sub(count)
            .ok_or_else(|| DecodeError::new(DecodeErrorCode::IeCountExceeded, 0))?;
        let available = self.input.len().saturating_mul(8).saturating_sub(self.bit);
        if count > available / minimum_bits {
            return Err(invalid("truncated list fragment"));
        }
        Ok((count, fragmented))
    }
    fn plmns(&mut self) -> Result<Vec<PlmnSlices>, DecodeError> {
        let count = self.count(4, 12, 55)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            self.flags(2)?;
            let plmn = self.plmn()?;
            let slice_count = self.count(16, 1024, 13)?;
            let mut slices = Vec::with_capacity(slice_count);
            for _ in 0..slice_count {
                self.flags(2)?;
                slices.push(self.snssai()?);
            }
            values.push(PlmnSlices { plmn, slices });
        }
        Ok(values)
    }
    fn guami(&mut self) -> Result<Guami, DecodeError> {
        self.flags(2)?;
        let plmn = self.plmn()?;
        let region = self.bits(8)? as u8;
        let set = self.bits(10)?;
        let pointer = self.bits(6)? as u8;
        Ok(Guami {
            plmn,
            region,
            set,
            pointer,
        })
    }
    pub(super) fn snssai(&mut self) -> Result<Snssai, DecodeError> {
        let flags = self.bits(3)?;
        if flags & 5 != 0 {
            return Err(unsupported());
        }
        let sst = self.bits(8)? as u8;
        if flags & 2 == 0 {
            return Ok(Snssai::without_sd(sst));
        }
        let [a, b, c] = self.octets()?;
        Snssai::with_sd(sst, format!("{a:02x}{b:02x}{c:02x}"))
            .map_err(|_| invalid("slice differentiator"))
    }
    pub(super) fn finish(mut self) -> Result<(), DecodeError> {
        self.align()?;
        if self.bit / 8 != self.input.len() {
            return Err(invalid("trailing setup field bytes"));
        }
        Ok(())
    }
}

// Writes only independently qualified identity/slice and resource roots.
// Buffer allocation follows exact sizing; checked writes fail if those layouts
// ever diverge. It does not encode extension additions or arbitrary ASN.1.
pub(super) struct Writer {
    bytes: Zeroizing<Vec<u8>>,
    bit: usize,
}
impl Writer {
    pub(super) fn new(length: usize) -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; length]),
            bit: 0,
        }
    }
    pub(super) fn bits(&mut self, value: u16, width: usize) -> Result<(), EncodeError> {
        for shift in (0..width).rev() {
            let target = self
                .bytes
                .get_mut(self.bit / 8)
                .ok_or_else(encode_invalid)?;
            *target |= (((value >> shift) & 1) as u8) << (7 - self.bit % 8);
            self.bit += 1;
        }
        Ok(())
    }
    pub(super) fn align(&mut self) {
        self.bit = self.bit.div_ceil(8) * 8;
    }
    fn octets(&mut self, value: [u8; 3]) -> Result<(), EncodeError> {
        self.align();
        for byte in value {
            self.bits(u16::from(byte), 8)?;
        }
        Ok(())
    }
    fn plmns(&mut self, values: &[PlmnSlices]) -> Result<(), EncodeError> {
        self.bits((values.len() - 1) as u16, 4)?;
        for value in values {
            self.bits(0, 2)?;
            self.octets(plmn_bytes(&value.plmn))?;
            self.align();
            self.bits((value.slices.len() - 1) as u16, 16)?;
            for slice in &value.slices {
                self.bits(0, 2)?;
                self.snssai(slice)?;
            }
        }
        Ok(())
    }
    pub(super) fn snssai(&mut self, slice: &Snssai) -> Result<(), EncodeError> {
        self.bits(if slice.sd().is_some() { 2 } else { 0 }, 3)?;
        self.bits(u16::from(slice.sst()), 8)?;
        if let Some(sd) = slice.sd() {
            self.octets(sd_octets(sd))?;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<EncodedValue, EncodeError> {
        if self.bit.div_ceil(8) != self.bytes.len() {
            return Err(encode_invalid());
        }
        Ok(EncodedValue(self.bytes))
    }
}
