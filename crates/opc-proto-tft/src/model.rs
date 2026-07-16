use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use opc_protocol::AllocationBudget;

use crate::{TftError, TftErrorKind};

/// Minimum length of a TS 24.008 TFT value part (octet 3 only).
pub const TFT_MIN_VALUE_LEN: usize = 1;
/// Maximum length of a TS 24.008 TFT value part.
pub const TFT_MAX_VALUE_LEN: usize = 255;
/// Maximum packet-filter count representable by octet 3.
pub const TFT_MAX_PACKET_FILTERS: usize = 15;

/// Allocation profile for the bounded owned TFT codec.
///
/// A full decode allocates only model vectors whose aggregate source bytes are
/// bounded by [`TFT_MAX_VALUE_LEN`]. The fixed-header routing fast path is not
/// exposed separately, so its allocation target is zero.
pub const TFT_ALLOCATION_BUDGET: AllocationBudget = AllocationBudget {
    decode_heap_allocations_fast_path: 0,
    decode_max_temporary_bytes: TFT_MAX_VALUE_LEN,
    encode_max_temporary_bytes: TFT_MAX_VALUE_LEN,
};

/// TFT operation code from TS 24.008 table 10.5.162.
///
/// @spec 3GPP TS24008 R18 10.5.6.12 table 10.5.162
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftOperation {
    /// Ignore this IE (code 0).
    Ignore,
    /// Create a new TFT (code 1).
    CreateNew,
    /// Delete the existing TFT (code 2).
    DeleteExisting,
    /// Add packet filters to an existing TFT (code 3).
    AddPacketFilters,
    /// Replace packet filters in an existing TFT (code 4).
    ReplacePacketFilters,
    /// Delete packet filters from an existing TFT (code 5).
    DeletePacketFilters,
    /// Carry parameters without a packet-filter operation (code 6).
    NoOperation,
}

impl TftOperation {
    /// Return the three-bit TS 24.008 operation code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Ignore => 0,
            Self::CreateNew => 1,
            Self::DeleteExisting => 2,
            Self::AddPacketFilters => 3,
            Self::ReplacePacketFilters => 4,
            Self::DeletePacketFilters => 5,
            Self::NoOperation => 6,
        }
    }

    /// Decode a three-bit operation code, rejecting reserved code 7.
    pub fn from_code(code: u8) -> Result<Self, TftError> {
        match code {
            0 => Ok(Self::Ignore),
            1 => Ok(Self::CreateNew),
            2 => Ok(Self::DeleteExisting),
            3 => Ok(Self::AddPacketFilters),
            4 => Ok(Self::ReplacePacketFilters),
            5 => Ok(Self::DeletePacketFilters),
            6 => Ok(Self::NoOperation),
            value => Err(TftErrorKind::ReservedOperation { value }.into()),
        }
    }
}

/// Direction bits carried by a full packet filter.
///
/// `PreRelease7` has procedure-dependent interpretation. This codec preserves
/// it without guessing bearer-control-mode policy.
///
/// @spec 3GPP TS24008 R18 10.5.6.12
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketFilterDirection {
    /// Pre-Release-7 direction encoding (`00`).
    PreRelease7,
    /// Downlink only (`01`).
    DownlinkOnly,
    /// Uplink only (`10`).
    UplinkOnly,
    /// Both uplink and downlink (`11`).
    Bidirectional,
}

impl PacketFilterDirection {
    /// Return the two-bit wire value.
    pub const fn code(self) -> u8 {
        match self {
            Self::PreRelease7 => 0,
            Self::DownlinkOnly => 1,
            Self::UplinkOnly => 2,
            Self::Bidirectional => 3,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Self {
        match code & 0x03 {
            0 => Self::PreRelease7,
            1 => Self::DownlinkOnly,
            2 => Self::UplinkOnly,
            _ => Self::Bidirectional,
        }
    }
}

/// Four-bit packet-filter identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PacketFilterIdentifier(u8);

impl PacketFilterIdentifier {
    /// Construct an identifier in the inclusive range 0 through 15.
    pub fn new(value: u8) -> Result<Self, TftError> {
        if value > 0x0f {
            return Err(TftErrorKind::InvalidPacketFilterIdentifier { value }.into());
        }
        Ok(Self(value))
    }

    /// Return the four-bit identifier value.
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// Inclusive local or remote port range.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    low: u16,
    high: u16,
}

impl fmt::Debug for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortRange")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl PortRange {
    /// Construct a range, rejecting a low endpoint greater than the high endpoint.
    pub fn new(low: u16, high: u16) -> Result<Self, TftError> {
        if low > high {
            return Err(TftErrorKind::InvalidPortRange.into());
        }
        Ok(Self { low, high })
    }

    /// Inclusive low endpoint.
    pub const fn low(self) -> u16 {
        self.low
    }

    /// Inclusive high endpoint.
    pub const fn high(self) -> u16 {
        self.high
    }
}

/// IPv6 address paired with an inclusive prefix length of 0 through 128.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6AddressPrefix {
    address: Ipv6Addr,
    prefix_length: u8,
}

impl Ipv6AddressPrefix {
    /// Construct an IPv6 address/prefix pair.
    pub fn new(address: Ipv6Addr, prefix_length: u8) -> Result<Self, TftError> {
        if prefix_length > 128 {
            return Err(TftErrorKind::InvalidIpv6PrefixLength {
                value: prefix_length,
            }
            .into());
        }
        Ok(Self {
            address,
            prefix_length,
        })
    }

    /// Return the IPv6 address.
    pub const fn address(self) -> Ipv6Addr {
        self.address
    }

    /// Return the prefix length.
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }
}

impl fmt::Debug for Ipv6AddressPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv6AddressPrefix")
            .field("address", &"<redacted>")
            .field("prefix_length", &self.prefix_length)
            .finish()
    }
}

/// Valid 20-bit IPv6 flow label.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6FlowLabel(u32);

impl Ipv6FlowLabel {
    /// Construct a flow label in the inclusive range 0 through `0x0f_ffff`.
    pub fn new(value: u32) -> Result<Self, TftError> {
        if value > 0x000f_ffff {
            return Err(TftErrorKind::InvalidFlowLabel { value }.into());
        }
        Ok(Self(value))
    }

    /// Return the 20-bit value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for Ipv6FlowLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ipv6FlowLabel").field(&"<redacted>").finish()
    }
}

/// Valid 12-bit IEEE 802.1Q VLAN identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VlanIdentifier(u16);

impl VlanIdentifier {
    /// Construct a VLAN identifier in the inclusive range 0 through 4095.
    pub fn new(value: u16) -> Result<Self, TftError> {
        if value > 0x0fff {
            return Err(TftErrorKind::InvalidVlanIdentifier { value }.into());
        }
        Ok(Self(value))
    }

    /// Return the 12-bit identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for VlanIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VlanIdentifier")
            .field(&"<redacted>")
            .finish()
    }
}

/// IEEE 802.1Q priority-code-point and drop-eligible indication.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VlanPriority {
    pcp: u8,
    drop_eligible: bool,
}

impl fmt::Debug for VlanPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlanPriority")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl VlanPriority {
    /// Construct a VLAN priority with a three-bit PCP.
    pub fn new(pcp: u8, drop_eligible: bool) -> Result<Self, TftError> {
        if pcp > 7 {
            return Err(TftErrorKind::InvalidVlanPriority { value: pcp }.into());
        }
        Ok(Self { pcp, drop_eligible })
    }

    /// Return the three-bit priority-code point.
    pub const fn pcp(self) -> u8 {
        self.pcp
    }

    /// Return the drop-eligible indication.
    pub const fn drop_eligible(self) -> bool {
        self.drop_eligible
    }
}

/// Standardized TS 24.008 packet-filter component identifier.
///
/// @spec 3GPP TS24008 R18 10.5.6.12 table 10.5.162
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketFilterComponentKind {
    /// IPv4 remote address and mask (`0x10`).
    Ipv4RemoteAddress,
    /// IPv4 local address and mask (`0x11`).
    Ipv4LocalAddress,
    /// IPv6 remote address and mask (`0x20`).
    Ipv6RemoteAddress,
    /// IPv6 remote address and prefix (`0x21`).
    Ipv6RemoteAddressPrefix,
    /// IPv6 local address and prefix (`0x23`).
    Ipv6LocalAddressPrefix,
    /// IPv4 protocol identifier or IPv6 next header (`0x30`).
    ProtocolIdentifierNextHeader,
    /// Single local port (`0x40`).
    SingleLocalPort,
    /// Local port range (`0x41`).
    LocalPortRange,
    /// Single remote port (`0x50`).
    SingleRemotePort,
    /// Remote port range (`0x51`).
    RemotePortRange,
    /// IPsec security parameter index (`0x60`).
    SecurityParameterIndex,
    /// Type of service or traffic class plus mask (`0x70`).
    TypeOfServiceTrafficClass,
    /// IPv6 flow label (`0x80`).
    FlowLabel,
    /// Destination MAC address (`0x81`).
    DestinationMacAddress,
    /// Source MAC address (`0x82`).
    SourceMacAddress,
    /// Customer VLAN tag identifier (`0x83`).
    CustomerVlanId,
    /// Service VLAN tag identifier (`0x84`).
    ServiceVlanId,
    /// Customer VLAN PCP/DEI (`0x85`).
    CustomerVlanPriority,
    /// Service VLAN PCP/DEI (`0x86`).
    ServiceVlanPriority,
    /// Ethernet type (`0x87`).
    EtherType,
}

impl PacketFilterComponentKind {
    /// Return the one-octet component type identifier.
    pub const fn type_code(self) -> u8 {
        match self {
            Self::Ipv4RemoteAddress => 0x10,
            Self::Ipv4LocalAddress => 0x11,
            Self::Ipv6RemoteAddress => 0x20,
            Self::Ipv6RemoteAddressPrefix => 0x21,
            Self::Ipv6LocalAddressPrefix => 0x23,
            Self::ProtocolIdentifierNextHeader => 0x30,
            Self::SingleLocalPort => 0x40,
            Self::LocalPortRange => 0x41,
            Self::SingleRemotePort => 0x50,
            Self::RemotePortRange => 0x51,
            Self::SecurityParameterIndex => 0x60,
            Self::TypeOfServiceTrafficClass => 0x70,
            Self::FlowLabel => 0x80,
            Self::DestinationMacAddress => 0x81,
            Self::SourceMacAddress => 0x82,
            Self::CustomerVlanId => 0x83,
            Self::ServiceVlanId => 0x84,
            Self::CustomerVlanPriority => 0x85,
            Self::ServiceVlanPriority => 0x86,
            Self::EtherType => 0x87,
        }
    }

    pub(crate) fn from_type_code(type_code: u8) -> Result<Self, TftError> {
        match type_code {
            0x10 => Ok(Self::Ipv4RemoteAddress),
            0x11 => Ok(Self::Ipv4LocalAddress),
            0x20 => Ok(Self::Ipv6RemoteAddress),
            0x21 => Ok(Self::Ipv6RemoteAddressPrefix),
            0x23 => Ok(Self::Ipv6LocalAddressPrefix),
            0x30 => Ok(Self::ProtocolIdentifierNextHeader),
            0x40 => Ok(Self::SingleLocalPort),
            0x41 => Ok(Self::LocalPortRange),
            0x50 => Ok(Self::SingleRemotePort),
            0x51 => Ok(Self::RemotePortRange),
            0x60 => Ok(Self::SecurityParameterIndex),
            0x70 => Ok(Self::TypeOfServiceTrafficClass),
            0x80 => Ok(Self::FlowLabel),
            0x81 => Ok(Self::DestinationMacAddress),
            0x82 => Ok(Self::SourceMacAddress),
            0x83 => Ok(Self::CustomerVlanId),
            0x84 => Ok(Self::ServiceVlanId),
            0x85 => Ok(Self::CustomerVlanPriority),
            0x86 => Ok(Self::ServiceVlanPriority),
            0x87 => Ok(Self::EtherType),
            component_type => Err(TftErrorKind::ReservedComponentType { component_type }.into()),
        }
    }
}

/// Complete standardized TS 24.008 Release 18 packet-filter component model.
///
/// The custom `Debug` implementation reports only the component kind; address,
/// port, SPI, MAC, and classification values are not emitted.
///
/// @spec 3GPP TS24008 R18 10.5.6.12 table 10.5.162
#[derive(Clone, PartialEq, Eq)]
pub enum PacketFilterComponent {
    /// IPv4 remote address and mask.
    Ipv4RemoteAddress {
        /// Remote IPv4 address.
        address: Ipv4Addr,
        /// IPv4 address mask.
        mask: Ipv4Addr,
    },
    /// IPv4 local address and mask.
    Ipv4LocalAddress {
        /// Local IPv4 address.
        address: Ipv4Addr,
        /// IPv4 address mask.
        mask: Ipv4Addr,
    },
    /// IPv6 remote address and 128-bit mask.
    Ipv6RemoteAddress {
        /// Remote IPv6 address.
        address: Ipv6Addr,
        /// IPv6 address mask.
        mask: Ipv6Addr,
    },
    /// IPv6 remote address and prefix length.
    Ipv6RemoteAddressPrefix(Ipv6AddressPrefix),
    /// IPv6 local address and prefix length.
    Ipv6LocalAddressPrefix(Ipv6AddressPrefix),
    /// IPv4 protocol identifier or IPv6 next-header value.
    ProtocolIdentifierNextHeader(u8),
    /// Single local port.
    SingleLocalPort(u16),
    /// Inclusive local port range.
    LocalPortRange(PortRange),
    /// Single remote port.
    SingleRemotePort(u16),
    /// Inclusive remote port range.
    RemotePortRange(PortRange),
    /// Four-octet IPsec security parameter index.
    SecurityParameterIndex(u32),
    /// Type-of-service or traffic-class value and mask.
    TypeOfServiceTrafficClass {
        /// Type-of-service or traffic-class value.
        value: u8,
        /// Bits considered during matching.
        mask: u8,
    },
    /// IPv6 20-bit flow label.
    FlowLabel(Ipv6FlowLabel),
    /// Six-octet destination MAC address.
    DestinationMacAddress([u8; 6]),
    /// Six-octet source MAC address.
    SourceMacAddress([u8; 6]),
    /// Customer VLAN tag identifier.
    CustomerVlanId(VlanIdentifier),
    /// Service VLAN tag identifier.
    ServiceVlanId(VlanIdentifier),
    /// Customer VLAN priority and DEI.
    CustomerVlanPriority(VlanPriority),
    /// Service VLAN priority and DEI.
    ServiceVlanPriority(VlanPriority),
    /// Two-octet Ethernet type.
    EtherType(u16),
}

impl PacketFilterComponent {
    /// Return this component's standardized kind.
    pub const fn kind(&self) -> PacketFilterComponentKind {
        match self {
            Self::Ipv4RemoteAddress { .. } => PacketFilterComponentKind::Ipv4RemoteAddress,
            Self::Ipv4LocalAddress { .. } => PacketFilterComponentKind::Ipv4LocalAddress,
            Self::Ipv6RemoteAddress { .. } => PacketFilterComponentKind::Ipv6RemoteAddress,
            Self::Ipv6RemoteAddressPrefix(_) => PacketFilterComponentKind::Ipv6RemoteAddressPrefix,
            Self::Ipv6LocalAddressPrefix(_) => PacketFilterComponentKind::Ipv6LocalAddressPrefix,
            Self::ProtocolIdentifierNextHeader(_) => {
                PacketFilterComponentKind::ProtocolIdentifierNextHeader
            }
            Self::SingleLocalPort(_) => PacketFilterComponentKind::SingleLocalPort,
            Self::LocalPortRange(_) => PacketFilterComponentKind::LocalPortRange,
            Self::SingleRemotePort(_) => PacketFilterComponentKind::SingleRemotePort,
            Self::RemotePortRange(_) => PacketFilterComponentKind::RemotePortRange,
            Self::SecurityParameterIndex(_) => PacketFilterComponentKind::SecurityParameterIndex,
            Self::TypeOfServiceTrafficClass { .. } => {
                PacketFilterComponentKind::TypeOfServiceTrafficClass
            }
            Self::FlowLabel(_) => PacketFilterComponentKind::FlowLabel,
            Self::DestinationMacAddress(_) => PacketFilterComponentKind::DestinationMacAddress,
            Self::SourceMacAddress(_) => PacketFilterComponentKind::SourceMacAddress,
            Self::CustomerVlanId(_) => PacketFilterComponentKind::CustomerVlanId,
            Self::ServiceVlanId(_) => PacketFilterComponentKind::ServiceVlanId,
            Self::CustomerVlanPriority(_) => PacketFilterComponentKind::CustomerVlanPriority,
            Self::ServiceVlanPriority(_) => PacketFilterComponentKind::ServiceVlanPriority,
            Self::EtherType(_) => PacketFilterComponentKind::EtherType,
        }
    }

    pub(crate) const fn encoded_len(&self) -> usize {
        match self {
            Self::Ipv4RemoteAddress { .. } | Self::Ipv4LocalAddress { .. } => 9,
            Self::Ipv6RemoteAddress { .. } => 33,
            Self::Ipv6RemoteAddressPrefix(_) | Self::Ipv6LocalAddressPrefix(_) => 18,
            Self::ProtocolIdentifierNextHeader(_) => 2,
            Self::SingleLocalPort(_) | Self::SingleRemotePort(_) => 3,
            Self::LocalPortRange(_) | Self::RemotePortRange(_) => 5,
            Self::SecurityParameterIndex(_) => 5,
            Self::TypeOfServiceTrafficClass { .. } => 3,
            Self::FlowLabel(_) => 4,
            Self::DestinationMacAddress(_) | Self::SourceMacAddress(_) => 7,
            Self::CustomerVlanId(_) | Self::ServiceVlanId(_) | Self::EtherType(_) => 3,
            Self::CustomerVlanPriority(_) | Self::ServiceVlanPriority(_) => 2,
        }
    }
}

impl fmt::Debug for PacketFilterComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketFilterComponent")
            .field("kind", &self.kind())
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

/// One full packet filter used by create, add, and replace operations.
///
/// @spec 3GPP TS24008 R18 10.5.6.12 figure 10.5.144b
#[derive(Clone, PartialEq, Eq)]
pub struct PacketFilter {
    identifier: PacketFilterIdentifier,
    direction: PacketFilterDirection,
    evaluation_precedence: u8,
    components: Vec<PacketFilterComponent>,
}

impl PacketFilter {
    /// Construct and validate a complete packet filter.
    pub fn new(
        identifier: PacketFilterIdentifier,
        direction: PacketFilterDirection,
        evaluation_precedence: u8,
        components: Vec<PacketFilterComponent>,
    ) -> Result<Self, TftError> {
        let value = Self {
            identifier,
            direction,
            evaluation_precedence,
            components,
        };
        value.validate()?;
        Ok(value)
    }

    /// Packet-filter identifier.
    pub const fn identifier(&self) -> PacketFilterIdentifier {
        self.identifier
    }

    /// Packet-filter direction.
    pub const fn direction(&self) -> PacketFilterDirection {
        self.direction
    }

    /// Evaluation precedence; larger values have lower precedence.
    pub const fn evaluation_precedence(&self) -> u8 {
        self.evaluation_precedence
    }

    /// Standardized components in preserved wire/model order.
    pub fn components(&self) -> &[PacketFilterComponent] {
        &self.components
    }

    pub(crate) fn contents_len(&self) -> Result<usize, TftError> {
        self.components.iter().try_fold(0usize, |total, component| {
            total
                .checked_add(component.encoded_len())
                .ok_or_else(|| TftErrorKind::LengthOverflow.into())
        })
    }

    pub(crate) fn validate(&self) -> Result<(), TftError> {
        if self.components.is_empty() {
            return Err(TftErrorKind::EmptyPacketFilterContents.into());
        }

        let contents_len = self.contents_len()?;
        if contents_len > usize::from(u8::MAX) {
            return Err(TftErrorKind::PacketFilterContentsTooLong {
                actual: contents_len,
                maximum: usize::from(u8::MAX),
            }
            .into());
        }

        let mut seen = [false; 256];
        let mut remote_address: Option<u8> = None;
        let mut local_address: Option<u8> = None;
        let mut local_port: Option<u8> = None;
        let mut remote_port: Option<u8> = None;
        let mut ip_family: Option<(IpFamily, u8)> = None;
        let mut first_ip_component: Option<u8> = None;
        let mut protocol: Option<u8> = None;
        let mut any_port: Option<u8> = None;
        let mut spi: Option<u8> = None;
        let mut flow_label: Option<u8> = None;
        let mut ether_type: Option<(u16, u8)> = None;

        for component in &self.components {
            let kind = component.kind();
            let type_code = kind.type_code();
            let seen_index = usize::from(type_code);
            if seen[seen_index] {
                return Err(TftErrorKind::DuplicateComponent {
                    component_type: type_code,
                }
                .into());
            }
            seen[seen_index] = true;

            let family = match kind {
                PacketFilterComponentKind::Ipv4RemoteAddress
                | PacketFilterComponentKind::Ipv4LocalAddress => Some(IpFamily::V4),
                PacketFilterComponentKind::Ipv6RemoteAddress
                | PacketFilterComponentKind::Ipv6RemoteAddressPrefix
                | PacketFilterComponentKind::Ipv6LocalAddressPrefix
                | PacketFilterComponentKind::FlowLabel => Some(IpFamily::V6),
                _ => None,
            };
            if let Some(family) = family {
                if let Some((existing, existing_type)) = ip_family {
                    if existing != family {
                        return Err(TftErrorKind::ConflictingComponents {
                            first: existing_type,
                            second: type_code,
                        }
                        .into());
                    }
                } else {
                    ip_family = Some((family, type_code));
                }
            }

            let is_ip_component = matches!(
                kind,
                PacketFilterComponentKind::Ipv4RemoteAddress
                    | PacketFilterComponentKind::Ipv4LocalAddress
                    | PacketFilterComponentKind::Ipv6RemoteAddress
                    | PacketFilterComponentKind::Ipv6RemoteAddressPrefix
                    | PacketFilterComponentKind::Ipv6LocalAddressPrefix
                    | PacketFilterComponentKind::ProtocolIdentifierNextHeader
                    | PacketFilterComponentKind::SingleLocalPort
                    | PacketFilterComponentKind::LocalPortRange
                    | PacketFilterComponentKind::SingleRemotePort
                    | PacketFilterComponentKind::RemotePortRange
                    | PacketFilterComponentKind::SecurityParameterIndex
                    | PacketFilterComponentKind::TypeOfServiceTrafficClass
                    | PacketFilterComponentKind::FlowLabel
            );
            if is_ip_component && first_ip_component.is_none() {
                first_ip_component = Some(type_code);
            }

            match kind {
                PacketFilterComponentKind::Ipv4RemoteAddress
                | PacketFilterComponentKind::Ipv6RemoteAddress
                | PacketFilterComponentKind::Ipv6RemoteAddressPrefix => {
                    set_exclusive(&mut remote_address, type_code)?;
                }
                PacketFilterComponentKind::Ipv4LocalAddress
                | PacketFilterComponentKind::Ipv6LocalAddressPrefix => {
                    set_exclusive(&mut local_address, type_code)?;
                }
                PacketFilterComponentKind::SingleLocalPort
                | PacketFilterComponentKind::LocalPortRange => {
                    set_exclusive(&mut local_port, type_code)?;
                    any_port.get_or_insert(type_code);
                }
                PacketFilterComponentKind::SingleRemotePort
                | PacketFilterComponentKind::RemotePortRange => {
                    set_exclusive(&mut remote_port, type_code)?;
                    any_port.get_or_insert(type_code);
                }
                PacketFilterComponentKind::ProtocolIdentifierNextHeader => {
                    protocol = Some(type_code);
                }
                PacketFilterComponentKind::SecurityParameterIndex => spi = Some(type_code),
                PacketFilterComponentKind::FlowLabel => flow_label = Some(type_code),
                PacketFilterComponentKind::EtherType => {
                    if let PacketFilterComponent::EtherType(value) = component {
                        ether_type = Some((*value, type_code));
                    }
                }
                _ => {}
            }
        }

        if let (Some(port), Some(spi_type)) = (any_port, spi) {
            return conflicting(port, spi_type);
        }
        if let Some(flow_type) = flow_label {
            if let Some(protocol_type) = protocol {
                return conflicting(protocol_type, flow_type);
            }
            if let Some(port) = any_port {
                return conflicting(port, flow_type);
            }
            if let Some(spi_type) = spi {
                return conflicting(spi_type, flow_type);
            }
        }

        if let Some((ether_type_value, ether_type_code)) = ether_type {
            match ether_type_value {
                0x0800 => {
                    if let Some((IpFamily::V6, family_type)) = ip_family {
                        return conflicting(ether_type_code, family_type);
                    }
                }
                0x86dd => {
                    if let Some((IpFamily::V4, family_type)) = ip_family {
                        return conflicting(ether_type_code, family_type);
                    }
                }
                _ => {
                    if let Some(ip_type) = first_ip_component {
                        return conflicting(ether_type_code, ip_type);
                    }
                }
            }
        }

        Ok(())
    }
}

fn set_exclusive(slot: &mut Option<u8>, type_code: u8) -> Result<(), TftError> {
    if let Some(existing) = *slot {
        return conflicting(existing, type_code);
    }
    *slot = Some(type_code);
    Ok(())
}

fn conflicting(first: u8, second: u8) -> Result<(), TftError> {
    Err(TftErrorKind::ConflictingComponents { first, second }.into())
}

impl fmt::Debug for PacketFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketFilter")
            .field("identifier", &self.identifier)
            .field("direction", &self.direction)
            .field("evaluation_precedence", &self.evaluation_precedence)
            .field("component_count", &self.components.len())
            .finish()
    }
}

/// Packet-filter-list representation selected by the TFT operation.
#[derive(Clone, PartialEq, Eq)]
pub enum PacketFilterList {
    /// No packet-filter list (ignore, delete-existing, or no-operation).
    None,
    /// Full filters (create, add, or replace).
    Filters(Vec<PacketFilter>),
    /// Identifier-only entries (delete-packet-filters).
    Identifiers(Vec<PacketFilterIdentifier>),
}

impl PacketFilterList {
    /// Number of full filters or identifier-only entries.
    pub fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Filters(filters) => filters.len(),
            Self::Identifiers(identifiers) => identifiers.len(),
        }
    }

    /// Return `true` when the list contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return full filters when this is the full-filter representation.
    pub fn filters(&self) -> Option<&[PacketFilter]> {
        match self {
            Self::Filters(filters) => Some(filters),
            _ => None,
        }
    }

    /// Return identifier entries when this is the identifier-only representation.
    pub fn identifiers(&self) -> Option<&[PacketFilterIdentifier]> {
        match self {
            Self::Identifiers(identifiers) => Some(identifiers),
            _ => None,
        }
    }
}

impl fmt::Debug for PacketFilterList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("PacketFilterList::None"),
            Self::Filters(filters) => f
                .debug_struct("PacketFilterList::Filters")
                .field("count", &filters.len())
                .finish(),
            Self::Identifiers(identifiers) => f
                .debug_struct("PacketFilterList::Identifiers")
                .field("count", &identifiers.len())
                .finish(),
        }
    }
}

/// Redaction-safe authorization-token parameter contents.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationToken(Vec<u8>);

impl AuthorizationToken {
    /// Construct a non-empty token that fits the one-octet parameter length.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, TftError> {
        let bytes = bytes.into();
        validate_parameter_length(0x01, bytes.len(), 1, usize::from(u8::MAX))?;
        Ok(Self(bytes))
    }

    /// Borrow the token bytes for an explicitly authorized protocol boundary.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AuthorizationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationToken")
            .field("value", &"<redacted>")
            .field("length", &self.0.len())
            .finish()
    }
}

/// Four-octet Flow Identifier parameter contents.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowIdentifier {
    media_component_number: u16,
    ip_flow_number: u16,
}

impl fmt::Debug for FlowIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowIdentifier")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl FlowIdentifier {
    /// Construct a Flow Identifier from its two 16-bit fields.
    pub const fn new(media_component_number: u16, ip_flow_number: u16) -> Self {
        Self {
            media_component_number,
            ip_flow_number,
        }
    }

    /// Return the media-component number.
    pub const fn media_component_number(self) -> u16 {
        self.media_component_number
    }

    /// Return the IP-flow number.
    pub const fn ip_flow_number(self) -> u16 {
        self.ip_flow_number
    }
}

/// Valid contents of TFT parameter 3 (one or more unique filter identifiers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFilterIdentifierList(Vec<PacketFilterIdentifier>);

impl PacketFilterIdentifierList {
    /// Construct a non-empty identifier list that fits one parameter TLV.
    pub fn new(identifiers: Vec<PacketFilterIdentifier>) -> Result<Self, TftError> {
        validate_parameter_length(0x03, identifiers.len(), 1, usize::from(u8::MAX))?;
        validate_unique_identifiers(&identifiers, true)?;
        Ok(Self(identifiers))
    }

    /// Borrow the identifiers in preserved order.
    pub fn identifiers(&self) -> &[PacketFilterIdentifier] {
        &self.0
    }
}

/// Unsupported TFT parameter retained because TS 24.008 permits receivers to
/// discard unsupported parameter identifiers.
#[derive(Clone, PartialEq, Eq)]
pub struct UnknownTftParameter {
    identifier: u8,
    contents: Vec<u8>,
}

impl UnknownTftParameter {
    /// Construct an unknown parameter; identifiers 1, 2, and 3 are rejected.
    pub fn new(identifier: u8, contents: impl Into<Vec<u8>>) -> Result<Self, TftError> {
        if matches!(identifier, 0x01..=0x03) {
            return Err(TftErrorKind::StandardParameterAsUnknown { identifier }.into());
        }
        let contents = contents.into();
        validate_parameter_length(identifier, contents.len(), 0, usize::from(u8::MAX))?;
        Ok(Self {
            identifier,
            contents,
        })
    }

    /// Unsupported parameter identifier.
    pub const fn identifier(&self) -> u8 {
        self.identifier
    }

    /// Raw parameter contents preserved for byte-exact forwarding.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

impl fmt::Debug for UnknownTftParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownTftParameter")
            .field("identifier", &self.identifier)
            .field("contents", &"<redacted>")
            .field("contents_len", &self.contents.len())
            .finish()
    }
}

/// TFT parameter kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftParameterKind {
    /// Authorization Token (`0x01`).
    AuthorizationToken,
    /// Flow Identifier (`0x02`).
    FlowIdentifier,
    /// Packet Filter Identifier (`0x03`).
    PacketFilterIdentifiers,
    /// Unsupported identifier preserved under the TS extensibility rule.
    Unknown(u8),
}

/// Typed TFT parameter-list entry.
///
/// @spec 3GPP TS24008 R18 10.5.6.12 figure 10.5.144c
#[derive(Clone, PartialEq, Eq)]
pub enum TftParameter {
    /// Authorization Token parameter.
    AuthorizationToken(AuthorizationToken),
    /// Flow Identifier parameter.
    FlowIdentifier(FlowIdentifier),
    /// Packet Filter Identifier parameter.
    PacketFilterIdentifiers(PacketFilterIdentifierList),
    /// Unsupported parameter preserved exactly.
    Unknown(UnknownTftParameter),
}

impl TftParameter {
    /// Return the typed parameter kind.
    pub const fn kind(&self) -> TftParameterKind {
        match self {
            Self::AuthorizationToken(_) => TftParameterKind::AuthorizationToken,
            Self::FlowIdentifier(_) => TftParameterKind::FlowIdentifier,
            Self::PacketFilterIdentifiers(_) => TftParameterKind::PacketFilterIdentifiers,
            Self::Unknown(value) => TftParameterKind::Unknown(value.identifier),
        }
    }

    pub(crate) const fn identifier(&self) -> u8 {
        match self.kind() {
            TftParameterKind::AuthorizationToken => 0x01,
            TftParameterKind::FlowIdentifier => 0x02,
            TftParameterKind::PacketFilterIdentifiers => 0x03,
            TftParameterKind::Unknown(identifier) => identifier,
        }
    }

    pub(crate) fn contents_len(&self) -> usize {
        match self {
            Self::AuthorizationToken(token) => token.0.len(),
            Self::FlowIdentifier(_) => 4,
            Self::PacketFilterIdentifiers(value) => value.0.len(),
            Self::Unknown(value) => value.contents.len(),
        }
    }
}

impl fmt::Debug for TftParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftParameter")
            .field("kind", &self.kind())
            .field("contents", &"<redacted>")
            .field("contents_len", &self.contents_len())
            .finish()
    }
}

/// Complete immutable TFT value model.
///
/// Valid ordering of filters, components, parameters, and unknown parameter
/// bytes is preserved. The only opaque bytes are `Ignore` contents that the
/// specification explicitly requires receivers to ignore and unsupported
/// parameter contents that the specification explicitly permits.
///
/// @spec 3GPP TS24008 R18 10.5.6.12
/// @req REQ-3GPP-TFT-R18-MODEL-001
#[derive(Clone, PartialEq, Eq)]
pub struct TrafficFlowTemplate {
    operation: TftOperation,
    packet_filters: PacketFilterList,
    parameters: Vec<TftParameter>,
    ignored_contents: Vec<u8>,
}

impl TrafficFlowTemplate {
    /// Construct a TFT from an operation-specific list and optional parameters.
    pub fn new(
        operation: TftOperation,
        packet_filters: PacketFilterList,
        parameters: Vec<TftParameter>,
    ) -> Result<Self, TftError> {
        let value = Self {
            operation,
            packet_filters,
            parameters,
            ignored_contents: Vec::new(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Construct canonical `Ignore this IE` with no ignored trailing contents.
    pub fn ignore() -> Self {
        Self {
            operation: TftOperation::Ignore,
            packet_filters: PacketFilterList::None,
            parameters: Vec::new(),
            ignored_contents: Vec::new(),
        }
    }

    /// Construct `Ignore this IE` while preserving contents that TS 24.008
    /// explicitly instructs the receiver not to interpret.
    pub fn ignore_with_contents(contents: impl Into<Vec<u8>>) -> Result<Self, TftError> {
        let value = Self {
            operation: TftOperation::Ignore,
            packet_filters: PacketFilterList::None,
            parameters: Vec::new(),
            ignored_contents: contents.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Construct a create-new operation.
    pub fn create_new(
        filters: Vec<PacketFilter>,
        parameters: Vec<TftParameter>,
    ) -> Result<Self, TftError> {
        Self::new(
            TftOperation::CreateNew,
            PacketFilterList::Filters(filters),
            parameters,
        )
    }

    /// Construct a delete-existing operation.
    pub fn delete_existing() -> Self {
        Self {
            operation: TftOperation::DeleteExisting,
            packet_filters: PacketFilterList::None,
            parameters: Vec::new(),
            ignored_contents: Vec::new(),
        }
    }

    /// Construct a delete-existing operation with an independent parameter list.
    ///
    /// TS 24.008 requires the packet-filter count and list to be empty for this
    /// operation, but does not prohibit the E-bit parameter list. Use
    /// [`Self::delete_existing`] for the common form without parameters.
    pub fn delete_existing_with_parameters(
        parameters: Vec<TftParameter>,
    ) -> Result<Self, TftError> {
        Self::new(
            TftOperation::DeleteExisting,
            PacketFilterList::None,
            parameters,
        )
    }

    /// Construct an add-packet-filters operation.
    pub fn add_packet_filters(
        filters: Vec<PacketFilter>,
        parameters: Vec<TftParameter>,
    ) -> Result<Self, TftError> {
        Self::new(
            TftOperation::AddPacketFilters,
            PacketFilterList::Filters(filters),
            parameters,
        )
    }

    /// Construct a replace-packet-filters operation.
    pub fn replace_packet_filters(
        filters: Vec<PacketFilter>,
        parameters: Vec<TftParameter>,
    ) -> Result<Self, TftError> {
        Self::new(
            TftOperation::ReplacePacketFilters,
            PacketFilterList::Filters(filters),
            parameters,
        )
    }

    /// Construct a delete-packet-filters operation.
    pub fn delete_packet_filters(
        identifiers: Vec<PacketFilterIdentifier>,
        parameters: Vec<TftParameter>,
    ) -> Result<Self, TftError> {
        Self::new(
            TftOperation::DeletePacketFilters,
            PacketFilterList::Identifiers(identifiers),
            parameters,
        )
    }

    /// Construct a parameter-only no-operation value.
    pub fn no_operation(parameters: Vec<TftParameter>) -> Result<Self, TftError> {
        Self::new(
            TftOperation::NoOperation,
            PacketFilterList::None,
            parameters,
        )
    }

    /// TFT operation.
    pub const fn operation(&self) -> TftOperation {
        self.operation
    }

    /// Operation-specific packet-filter list.
    pub const fn packet_filters(&self) -> &PacketFilterList {
        &self.packet_filters
    }

    /// Parameter list in preserved order.
    pub fn parameters(&self) -> &[TftParameter] {
        &self.parameters
    }

    /// Uninterpreted contents present only for `Ignore this IE`.
    pub fn ignored_contents(&self) -> &[u8] {
        &self.ignored_contents
    }

    pub(crate) fn validate(&self) -> Result<(), TftError> {
        if let Some(filters) = self.packet_filters.filters() {
            for filter in filters {
                filter.validate()?;
            }
        }
        validate_parameter_sequence(&self.parameters)?;

        match (self.operation, &self.packet_filters) {
            (TftOperation::Ignore, PacketFilterList::None) => {
                if !self.parameters.is_empty() {
                    return Err(TftErrorKind::InvalidOperationHeader {
                        operation: self.operation.code(),
                    }
                    .into());
                }
            }
            (TftOperation::DeleteExisting, PacketFilterList::None) => {
                if !self.ignored_contents.is_empty() {
                    return Err(TftErrorKind::InvalidOperationHeader {
                        operation: self.operation.code(),
                    }
                    .into());
                }
            }
            (TftOperation::NoOperation, PacketFilterList::None) => {
                if self.parameters.is_empty() || !self.ignored_contents.is_empty() {
                    return Err(TftErrorKind::EmptyParameterList.into());
                }
            }
            (
                TftOperation::CreateNew
                | TftOperation::AddPacketFilters
                | TftOperation::ReplacePacketFilters,
                PacketFilterList::Filters(filters),
            ) => {
                validate_filter_count(self.operation, filters.len())?;
                validate_unique_full_filters(filters)?;
                if !self.ignored_contents.is_empty() {
                    return Err(TftErrorKind::UnexpectedTrailingData.into());
                }
            }
            (TftOperation::DeletePacketFilters, PacketFilterList::Identifiers(identifiers)) => {
                validate_filter_count(self.operation, identifiers.len())?;
                validate_unique_identifiers(identifiers, false)?;
                if !self.ignored_contents.is_empty() {
                    return Err(TftErrorKind::UnexpectedTrailingData.into());
                }
            }
            _ => {
                return Err(TftErrorKind::InvalidPacketFilterList {
                    operation: self.operation.code(),
                }
                .into());
            }
        }

        let length = self.encoded_value_len_internal()?;
        if !(TFT_MIN_VALUE_LEN..=TFT_MAX_VALUE_LEN).contains(&length) {
            return Err(TftErrorKind::InvalidValueLength {
                actual: length,
                minimum: TFT_MIN_VALUE_LEN,
                maximum: TFT_MAX_VALUE_LEN,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn encoded_value_len_internal(&self) -> Result<usize, TftError> {
        let mut length = TFT_MIN_VALUE_LEN;
        match &self.packet_filters {
            PacketFilterList::None => {}
            PacketFilterList::Identifiers(identifiers) => {
                length = length
                    .checked_add(identifiers.len())
                    .ok_or(TftErrorKind::LengthOverflow)?;
            }
            PacketFilterList::Filters(filters) => {
                for filter in filters {
                    let contents_len = filter.contents_len()?;
                    length = length
                        .checked_add(3)
                        .and_then(|value| value.checked_add(contents_len))
                        .ok_or(TftErrorKind::LengthOverflow)?;
                }
            }
        }
        for parameter in &self.parameters {
            length = length
                .checked_add(2)
                .and_then(|value| value.checked_add(parameter.contents_len()))
                .ok_or(TftErrorKind::LengthOverflow)?;
        }
        length = length
            .checked_add(self.ignored_contents.len())
            .ok_or(TftErrorKind::LengthOverflow)?;
        Ok(length)
    }
}

impl fmt::Debug for TrafficFlowTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafficFlowTemplate")
            .field("operation", &self.operation)
            .field("packet_filter_count", &self.packet_filters.len())
            .field("parameter_count", &self.parameters.len())
            .field("ignored_contents_len", &self.ignored_contents.len())
            .finish()
    }
}

fn validate_filter_count(operation: TftOperation, count: usize) -> Result<(), TftError> {
    if !(1..=TFT_MAX_PACKET_FILTERS).contains(&count) {
        return Err(TftErrorKind::InvalidPacketFilterCount {
            operation: operation.code(),
            count,
        }
        .into());
    }
    Ok(())
}

fn validate_unique_full_filters(filters: &[PacketFilter]) -> Result<(), TftError> {
    let mut identifiers = [false; 16];
    let mut precedences = [false; 256];
    for filter in filters {
        let identifier = filter.identifier.value();
        let identifier_index = usize::from(identifier);
        if identifiers[identifier_index] {
            return Err(TftErrorKind::DuplicatePacketFilterIdentifier { identifier }.into());
        }
        identifiers[identifier_index] = true;

        let precedence = filter.evaluation_precedence;
        let precedence_index = usize::from(precedence);
        if precedences[precedence_index] {
            return Err(TftErrorKind::DuplicateEvaluationPrecedence { precedence }.into());
        }
        precedences[precedence_index] = true;
    }
    Ok(())
}

fn validate_unique_identifiers(
    identifiers: &[PacketFilterIdentifier],
    parameter: bool,
) -> Result<(), TftError> {
    let mut seen = [false; 16];
    for identifier in identifiers {
        let value = identifier.value();
        let index = usize::from(value);
        if seen[index] {
            return if parameter {
                Err(
                    TftErrorKind::DuplicateParameterPacketFilterIdentifier { identifier: value }
                        .into(),
                )
            } else {
                Err(TftErrorKind::DuplicatePacketFilterIdentifier { identifier: value }.into())
            };
        }
        seen[index] = true;
    }
    Ok(())
}

fn validate_parameter_sequence(parameters: &[TftParameter]) -> Result<(), TftError> {
    for (index, parameter) in parameters.iter().enumerate() {
        if matches!(parameter, TftParameter::AuthorizationToken(_))
            && !matches!(
                parameters.get(index.saturating_add(1)),
                Some(TftParameter::FlowIdentifier(_))
            )
        {
            return Err(TftErrorKind::AuthorizationTokenWithoutFlowIdentifier {
                parameter_index: index,
            }
            .into());
        }
    }
    Ok(())
}

fn validate_parameter_length(
    identifier: u8,
    actual: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), TftError> {
    if !(minimum..=maximum).contains(&actual) {
        return Err(TftErrorKind::InvalidParameterLength {
            identifier,
            actual,
            minimum,
            maximum,
        }
        .into());
    }
    Ok(())
}
