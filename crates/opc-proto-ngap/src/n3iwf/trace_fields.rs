//! Bounded Trace Activation root parameters. Admission does not start tracing,
//! interpret the collector address, select an interface or authorize reporting.
//! Optional MDT/URI and future ASN.1 extensions are explicitly unsupported.
use super::setup_fields::Reader;
use super::*;

/// The six root trace-depth reports, without local activation semantics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TraceDepth {
    /// Minimum trace depth.
    Minimum,
    /// Medium trace depth.
    Medium,
    /// Maximum trace depth.
    Maximum,
    /// Minimum depth excluding vendor-specific extensions.
    MinimumWithoutVendorSpecificExtension,
    /// Medium depth excluding vendor-specific extensions.
    MediumWithoutVendorSpecificExtension,
    /// Maximum depth excluding vendor-specific extensions.
    MaximumWithoutVendorSpecificExtension,
}
redacted!(TraceDepth);
impl TraceDepth {
    /// Require one of the six ASN.1 root indices; extensions are not mapped.
    pub fn new(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Minimum),
            1 => Ok(Self::Medium),
            2 => Ok(Self::Maximum),
            3 => Ok(Self::MinimumWithoutVendorSpecificExtension),
            4 => Ok(Self::MediumWithoutVendorSpecificExtension),
            5 => Ok(Self::MaximumWithoutVendorSpecificExtension),
            _ => Err(invalid("trace depth root index")),
        }
    }
    /// Explicit ASN.1 root index, without interpreting peer policy.
    pub const fn value(self) -> u8 {
        match self {
            Self::Minimum => 0,
            Self::Medium => 1,
            Self::Maximum => 2,
            Self::MinimumWithoutVendorSpecificExtension => 3,
            Self::MediumWithoutVendorSpecificExtension => 4,
            Self::MaximumWithoutVendorSpecificExtension => 5,
        }
    }
}

/// Root trace identifier, interface bitmap, depth and opaque collector address.
/// Transport address interpretation belongs to the caller's transport layer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TraceActivation {
    id: [u8; 8],
    interfaces: u8,
    depth: TraceDepth,
    address: [u8; 20],
    address_bits: u8,
}
redacted!(TraceActivation);
impl TraceActivation {
    /// Preserve eight trace-ID octets and all interface bits. Require an
    /// address root length of 1..=160 bits in exactly ceil(bits/8) octets,
    /// with unused low bits zero. No IP address or trace session is activated.
    pub fn new(
        id: [u8; 8],
        interfaces: u8,
        depth: TraceDepth,
        address_bits: u8,
        address: &[u8],
    ) -> Result<Self, DecodeError> {
        if !(1..=160).contains(&address_bits)
            || address.len() != usize::from(address_bits).div_ceil(8)
        {
            return Err(invalid("trace address root extent"));
        }
        let padding = (8 - address_bits % 8) % 8;
        if address
            .last()
            .is_some_and(|value| value & ((1u8 << padding) - 1) != 0)
        {
            return Err(invalid("trace address padding"));
        }
        let mut storage = [0; 20];
        storage[..address.len()].copy_from_slice(address);
        Ok(Self {
            id,
            interfaces,
            depth,
            address: storage,
            address_bits,
        })
    }
    /// Explicit access to the opaque trace identifier, in wire order.
    pub const fn trace_id(&self) -> &[u8; 8] {
        &self.id
    }
    /// Explicit interface bitmap; the first ASN.1 bit is bit seven.
    /// Reserved bits are preserved, without selecting trace interfaces.
    pub const fn interfaces(self) -> u8 {
        self.interfaces
    }
    /// Explicit root trace-depth report.
    pub const fn depth(self) -> TraceDepth {
        self.depth
    }
    /// Number of significant collector-address bits.
    pub const fn address_bits(self) -> u8 {
        self.address_bits
    }
    /// Opaque collector-address octets, with zero unused low bits.
    pub fn address(&self) -> &[u8] {
        &self.address[..usize::from(self.address_bits).div_ceil(8)]
    }
    /// Encode the generated root after exact-size preflight (13..=32 octets).
    pub fn encode(self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        capacity(12 + self.address().len(), ctx)?;
        let mut address = rasn::types::BitString::from_slice(self.address());
        address.truncate(usize::from(self.address_bits));
        let mut interfaces = rasn::types::FixedBitString::<8>::ZERO;
        for bit in 0..8 {
            interfaces.set(bit, self.interfaces & (1 << (7 - bit)) != 0);
        }
        let depth = match self.depth {
            TraceDepth::Minimum => asn::TraceDepth::minimum,
            TraceDepth::Medium => asn::TraceDepth::medium,
            TraceDepth::Maximum => asn::TraceDepth::maximum,
            TraceDepth::MinimumWithoutVendorSpecificExtension => {
                asn::TraceDepth::minimumWithoutVendorSpecificExtension
            }
            TraceDepth::MediumWithoutVendorSpecificExtension => {
                asn::TraceDepth::mediumWithoutVendorSpecificExtension
            }
            TraceDepth::MaximumWithoutVendorSpecificExtension => {
                asn::TraceDepth::maximumWithoutVendorSpecificExtension
            }
        };
        encode_leaf(
            &asn::TraceActivation::new(
                asn::NGRANTraceID(self.id.into()),
                asn::InterfacesToTrace(interfaces),
                depth,
                asn::TransportLayerAddress(address),
                None,
            ),
            ctx,
        )
    }
    /// Decode at depth two with fixed storage. Reject sequence/IE/address/
    /// enum extensions, invalid root indices, padding and trailing bytes.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 2)?;
        let mut reader = Reader::new(input, ctx);
        reader.flags(2)?;
        reader.align()?;
        let mut id = [0; 8];
        for value in &mut id {
            *value = reader.bits(8)? as u8;
        }
        let interfaces = reader.bits(8)? as u8;
        reader.flags(1)?;
        let depth = TraceDepth::new(reader.bits(3)? as u8)?;
        reader.flags(1)?;
        let bits = reader.bits(8)? + 1;
        if bits > 160 {
            return Err(invalid("trace address root extent"));
        }
        reader.align()?;
        let count = usize::from(bits).div_ceil(8);
        let mut address = [0; 20];
        for value in &mut address[..count] {
            *value = reader.bits(8)? as u8;
        }
        reader.finish()?;
        Self::new(id, interfaces, depth, bits as u8, &address[..count])
    }
}
