//! Network-instance request values without routing or installation authority.
use super::security_fields::NetworkInstance;
use super::*;

/// Opaque Common Network Instance identifier (TS 38.413 9.3.1.120).
///
/// TS 29.244 8.2.4 permits identifiers other than domain/APN encodings. This
/// boundary preserves the unconstrained OCTET STRING, including an empty
/// value, without interpreting it or resolving it against local configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct CommonNetworkInstance(Vec<u8>);
redacted!(CommonNetworkInstance);

impl CommonNetworkInstance {
    /// Take caller-owned opaque octets without allocating or selecting a network.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Explicit access for the caller's network-resolution policy.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Require depth one and bounded, complete canonical length framing before
    /// allocating. Fragmented values are coalesced only after the full scan.
    pub fn decode(input: &[u8], ctx: DecodeContext) -> Result<Self, DecodeError> {
        bound(input, ctx, 1)?;
        let (rest, _) = aper::scan_open_type(input)?;
        if !rest.is_empty() {
            return Err(invalid("trailing common network instance bytes"));
        }
        let (_, value) = aper::open_type(input)?;
        Ok(Self(value.into_owned()))
    }
    /// Check the complete fragmented encoding length before allocation.
    pub fn encode(&self, ctx: EncodeContext) -> Result<EncodedValue, EncodeError> {
        let length = constructed::open_type_len(self.0.len())?;
        capacity(length, ctx)?;
        let mut wire = Zeroizing::new(Vec::with_capacity(length));
        constructed::write_open_type(&mut wire, &self.0);
        Ok(EncodedValue(wire))
    }
}

/// Requested transport-network identifier, with Common taking precedence.
/// This describes the peer request, not a selected or authorized local network.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransportNetworkInstance<'a> {
    /// Common identifier supplied for the concerned NG-U transport bearer.
    Common(&'a CommonNetworkInstance),
    /// Numeric root identifier, used only when Common is absent.
    Network(NetworkInstance),
}
redacted!(TransportNetworkInstance<'_>);

impl<'a> TransportNetworkInstance<'a> {
    pub(super) fn preferred(
        network: Option<NetworkInstance>,
        common: Option<&'a CommonNetworkInstance>,
    ) -> Option<Self> {
        common
            .map(Self::Common)
            .or_else(|| network.map(Self::Network))
    }
}
