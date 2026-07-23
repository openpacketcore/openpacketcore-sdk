//! Family-tagged grouped-session ABI shared by the loader and tc programs.
//!
//! The legacy v5 maps remain byte-for-byte IPv4-only. These layouts are a
//! separate additive generation: every address is family tagged and stored in
//! a fixed sixteen-byte slot, and one group record is the sole activation
//! point for all of a logical session's family entries.

use crate::{
    GtpuEndpointAddress, GtpuSourcePortPolicy, GtpuSourcePortRange, GtpuUplinkSourcePortPolicy,
};

/// Fixed byte width of a caller-owned grouped-session identifier.
pub const GTPU_SESSION_GROUP_ID_LEN: usize = 16;
/// Fixed byte width of a family-tagged grouped uplink selector.
pub const GTPU_SESSION_UPLINK_KEY_LEN: usize = 24;
/// Fixed byte width of a family-tagged grouped downlink selector.
pub const GTPU_SESSION_DOWNLINK_KEY_LEN: usize = 8;
/// Fixed byte width of an index reference to one grouped session.
pub const GTPU_SESSION_GROUP_REF_LEN: usize = 48;
/// Fixed byte width of one grouped family entry.
pub const GTPU_SESSION_ENTRY_LEN: usize = 80;
/// Fixed byte width of the atomic grouped-session authority record.
pub const GTPU_SESSION_GROUP_VALUE_LEN: usize = 208;
/// Fixed byte width of one durable grouped-session transaction journal.
pub const GTPU_SESSION_TRANSACTION_VALUE_LEN: usize = 464;
/// Fixed byte width of managed grouped-session device configuration.
pub const GTPU_SESSION_CONFIG_VALUE_LEN: usize = 64;

/// Slot used by the canonical IPv4 inner-family entry.
pub const GTPU_SESSION_IPV4_SLOT: u8 = 0;
/// Slot used by the canonical IPv6 inner-family entry.
pub const GTPU_SESSION_IPV6_SLOT: u8 = 1;

const GROUP_HEADER_LEN: usize = 48;
const TRANSACTION_HEADER_LEN: usize = 48;
const ENTRY_FORMAT_VERSION: u8 = 1;
const GROUP_FORMAT_VERSION: u8 = 1;
const TRANSACTION_FORMAT_VERSION: u8 = 1;
const CONFIG_FORMAT_VERSION: u8 = 1;

/// Opaque, caller-owned identity of one logical session group.
///
/// The identifier is nonzero, redacted from diagnostics, and must be generated
/// independently of subscriber addresses, TEIDs, packet marks, and other
/// mutable selectors. Once used, it must never be reused during the lifetime
/// of the stable pin namespace. The caller's durable identity registry, not
/// an unbounded dataplane tombstone map, enforces permanent retirement.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct GtpuSessionGroupId([u8; GTPU_SESSION_GROUP_ID_LEN]);

impl core::fmt::Debug for GtpuSessionGroupId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GtpuSessionGroupId")
            .field(&"<redacted>")
            .finish()
    }
}

impl core::fmt::Display for GtpuSessionGroupId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted-session-group-id>")
    }
}

impl GtpuSessionGroupId {
    /// Construct a nonzero opaque identity.
    #[must_use]
    pub const fn new(value: [u8; GTPU_SESSION_GROUP_ID_LEN]) -> Option<Self> {
        let mut index = 0;
        while index < value.len() {
            if value[index] != 0 {
                return Some(Self(value));
            }
            index += 1;
        }
        None
    }

    /// Return the fixed map-key bytes.
    ///
    /// These bytes are routing identity and must not be logged.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; GTPU_SESSION_GROUP_ID_LEN] {
        self.0
    }
}

/// Stable opaque identity of one managed device/pin namespace.
///
/// This identity is not an ifindex. It survives restart and is rebound to a
/// replacement attachment only after the pin namespace and replacement
/// interface have each been independently proven.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct GtpuSessionDeviceId([u8; GTPU_SESSION_GROUP_ID_LEN]);

impl core::fmt::Debug for GtpuSessionDeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GtpuSessionDeviceId")
            .field(&"<redacted>")
            .finish()
    }
}

impl core::fmt::Display for GtpuSessionDeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted-session-device-id>")
    }
}

impl GtpuSessionDeviceId {
    /// Construct a nonzero stable device identity.
    #[must_use]
    pub const fn new(value: [u8; GTPU_SESSION_GROUP_ID_LEN]) -> Option<Self> {
        let mut index = 0;
        while index < value.len() {
            if value[index] != 0 {
                return Some(Self(value));
            }
            index += 1;
        }
        None
    }

    /// Return the fixed map-value bytes.
    ///
    /// These bytes are attachment authority and must not be logged.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; GTPU_SESSION_GROUP_ID_LEN] {
        self.0
    }
}

/// Opaque, nonzero token for one durable grouped-session transaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct GtpuSessionTransactionId([u8; GTPU_SESSION_GROUP_ID_LEN]);

impl core::fmt::Debug for GtpuSessionTransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GtpuSessionTransactionId")
            .field(&"<redacted>")
            .finish()
    }
}

impl core::fmt::Display for GtpuSessionTransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted-session-transaction-id>")
    }
}

impl GtpuSessionTransactionId {
    /// Construct a nonzero operation token.
    #[must_use]
    pub const fn new(value: [u8; GTPU_SESSION_GROUP_ID_LEN]) -> Option<Self> {
        let mut index = 0;
        while index < value.len() {
            if value[index] != 0 {
                return Some(Self(value));
            }
            index += 1;
        }
        None
    }

    /// Return the fixed journal bytes.
    ///
    /// These bytes must not be logged.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; GTPU_SESSION_GROUP_ID_LEN] {
        self.0
    }
}

/// Monotonic nonzero incarnation of one never-reused group identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct GtpuSessionGeneration(u64);

impl GtpuSessionGeneration {
    /// Initial generation for the first transaction of a new group.
    pub const INITIAL: Self = Self(1);

    /// Construct a nonzero generation.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Return the wire integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance monotonically, failing closed at overflow.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// IP family encoded in grouped-session map keys and values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum GtpuSessionIpFamily {
    /// IPv4.
    Ipv4 = 4,
    /// IPv6.
    Ipv6 = 6,
}

impl GtpuSessionIpFamily {
    /// Return the canonical inner-family slot.
    #[must_use]
    pub const fn slot(self) -> u8 {
        match self {
            Self::Ipv4 => GTPU_SESSION_IPV4_SLOT,
            Self::Ipv6 => GTPU_SESSION_IPV6_SLOT,
        }
    }

    /// Decode a canonical wire family.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            4 => Some(Self::Ipv4),
            6 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

/// Canonical 3GPP packet-data-network identity.
///
/// IPv4 PAA is an exact `/32`. IPv6 PAA is the TS 29.274 fixed `/64`
/// prefix, stored with no subscriber interface identifier. Uplink packet
/// addresses are normalized to the first 64 bits; downlink destinations are
/// authorized when their first 64 bits match.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum GtpuSessionPaa {
    /// Exact IPv4 PAA.
    Ipv4([u8; 4]),
    /// Canonical IPv6 `/64` prefix.
    Ipv6Prefix([u8; 8]),
}

impl core::fmt::Debug for GtpuSessionPaa {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple(match self {
            Self::Ipv4(_) => "Ipv4",
            Self::Ipv6Prefix(_) => "Ipv6Prefix64",
        })
        .field(&"<redacted>")
        .finish()
    }
}

impl GtpuSessionPaa {
    /// Construct a canonical configuration identity.
    ///
    /// IPv6 requires a nonzero prefix and an all-zero lower 64 bits. Packet
    /// addresses with an interface identifier use [`Self::from_packet_address`].
    #[must_use]
    pub fn new(address: GtpuEndpointAddress) -> Option<Self> {
        match address {
            GtpuEndpointAddress::Ipv4(value) if value != [0; 4] => Some(Self::Ipv4(value)),
            GtpuEndpointAddress::Ipv6(value)
                if value[..8].iter().any(|byte| *byte != 0)
                    && value[8..].iter().all(|byte| *byte == 0) =>
            {
                let mut prefix = [0_u8; 8];
                prefix.copy_from_slice(&value[..8]);
                Some(Self::Ipv6Prefix(prefix))
            }
            _ => None,
        }
    }

    /// Explicitly project a full 3GPP PAA address to its forwarding identity.
    ///
    /// For IPv6 this deliberately discards the lower 64-bit interface
    /// identifier and returns the fixed `/64` prefix carried by TS 29.274.
    #[must_use]
    pub fn from_full_paa(address: GtpuEndpointAddress) -> Option<Self> {
        Self::from_packet_address(address)
    }

    /// Normalize a packet source/destination address to its PAA selector.
    #[must_use]
    pub fn from_packet_address(address: GtpuEndpointAddress) -> Option<Self> {
        match address {
            GtpuEndpointAddress::Ipv4(value) if value != [0; 4] => Some(Self::Ipv4(value)),
            GtpuEndpointAddress::Ipv6(value) if value[..8].iter().any(|byte| *byte != 0) => {
                let mut prefix = [0_u8; 8];
                prefix.copy_from_slice(&value[..8]);
                Some(Self::Ipv6Prefix(prefix))
            }
            _ => None,
        }
    }

    /// PAA address family.
    #[must_use]
    pub const fn family(self) -> GtpuSessionIpFamily {
        match self {
            Self::Ipv4(_) => GtpuSessionIpFamily::Ipv4,
            Self::Ipv6Prefix(_) => GtpuSessionIpFamily::Ipv6,
        }
    }

    /// Return the canonical address represented by this forwarding identity.
    ///
    /// IPv4 is unchanged. IPv6 has an all-zero lower 64-bit interface
    /// identifier so userspace readback cannot invent information omitted by
    /// the fixed `/64` ABI.
    #[must_use]
    pub const fn canonical_address(self) -> GtpuEndpointAddress {
        match self {
            Self::Ipv4(value) => GtpuEndpointAddress::Ipv4(value),
            Self::Ipv6Prefix(prefix) => GtpuEndpointAddress::Ipv6([
                prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], prefix[6],
                prefix[7], 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
        }
    }

    /// Return whether a complete packet address belongs to this PAA.
    #[must_use]
    pub fn contains(self, address: GtpuEndpointAddress) -> bool {
        Self::from_packet_address(address) == Some(self)
    }

    fn encode_bytes(self) -> [u8; 16] {
        match self {
            Self::Ipv4(value) => [
                value[0], value[1], value[2], value[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            Self::Ipv6Prefix(prefix) => [
                prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], prefix[6],
                prefix[7], 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }

    fn decode(family: u8, bytes: [u8; 16]) -> Option<Self> {
        Self::new(decode_address(family, bytes)?)
    }
}

/// Durable phase of one grouped-session transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GtpuSessionGroupPhase {
    /// A fresh generation-1 create is fenced while indexes are staged.
    Pending = 1,
    /// The complete exact family graph is authorized to forward.
    Active = 2,
    /// Removal is fenced and no family entry may forward.
    Removing = 3,
}

impl GtpuSessionGroupPhase {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Pending),
            2 => Some(Self::Active),
            3 => Some(Self::Removing),
            _ => None,
        }
    }
}

/// Durable phase of the userspace-only transaction journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GtpuSessionTransactionPhase {
    /// Base and desired graphs are durably recorded before index staging.
    Prepared = 1,
    /// Exact dual-generation indexes await the single authority cutover.
    IndexesStaged = 2,
    /// Authority readback proved the desired generation or removal fence;
    /// exact old-candidate cleanup remains.
    AuthorityCommitted = 3,
}

impl GtpuSessionTransactionPhase {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Prepared),
            2 => Some(Self::IndexesStaged),
            3 => Some(Self::AuthorityCommitted),
            _ => None,
        }
    }
}

/// Versioned managed-device configuration consumed by both tc directions.
///
/// This is the loader↔tc proof source for stable device identity, exact
/// ingress attachment, and canonical local endpoint membership. IPv4 and IPv6
/// addresses occupy independent fixed slots; absence is explicit in the
/// family mask and every reserved byte must remain zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionDeviceConfig {
    device_id: GtpuSessionDeviceId,
    ingress_ifindex: u32,
    ipv4: Option<[u8; 4]>,
    ipv6: Option<[u8; 16]>,
}

impl core::fmt::Debug for GtpuSessionDeviceConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuSessionDeviceConfig")
            .field("device_id", &self.device_id)
            .field("ingress_ifindex", &"<redacted>")
            .field("ipv4", &self.ipv4.map(|_| "<redacted>"))
            .field("ipv6", &self.ipv6.map(|_| "<redacted>"))
            .finish()
    }
}

impl GtpuSessionDeviceConfig {
    /// Construct exact attachment authority with one or both local families.
    #[must_use]
    pub fn new(
        device_id: GtpuSessionDeviceId,
        ingress_ifindex: u32,
        ipv4: Option<[u8; 4]>,
        ipv6: Option<[u8; 16]>,
    ) -> Option<Self> {
        if ingress_ifindex == 0
            || ipv4.is_none() && ipv6.is_none()
            || ipv4.is_some_and(|address| address == [0; 4])
            || ipv6.is_some_and(|address| address == [0; 16])
        {
            return None;
        }
        Some(Self {
            device_id,
            ingress_ifindex,
            ipv4,
            ipv6,
        })
    }

    /// Stable device/pin-namespace identity.
    #[must_use]
    pub const fn device_id(self) -> GtpuSessionDeviceId {
        self.device_id
    }

    /// Exact ingress attachment index.
    #[must_use]
    pub const fn ingress_ifindex(self) -> u32 {
        self.ingress_ifindex
    }

    /// Exact managed local endpoint for one outer family.
    #[must_use]
    pub const fn local_endpoint(self, family: GtpuSessionIpFamily) -> Option<GtpuEndpointAddress> {
        match family {
            GtpuSessionIpFamily::Ipv4 => match self.ipv4 {
                Some(address) => Some(GtpuEndpointAddress::Ipv4(address)),
                None => None,
            },
            GtpuSessionIpFamily::Ipv6 => match self.ipv6 {
                Some(address) => Some(GtpuEndpointAddress::Ipv6(address)),
                None => None,
            },
        }
    }

    /// Return whether an exact local outer endpoint belongs to this attachment.
    #[must_use]
    pub const fn authorizes_local(self, address: GtpuEndpointAddress) -> bool {
        match address {
            GtpuEndpointAddress::Ipv4(address) => match self.ipv4 {
                Some(expected) => {
                    expected[0] == address[0]
                        && expected[1] == address[1]
                        && expected[2] == address[2]
                        && expected[3] == address[3]
                }
                None => false,
            },
            GtpuEndpointAddress::Ipv6(address) => match self.ipv6 {
                Some(expected) => {
                    let mut index = 0;
                    while index < 16 {
                        if expected[index] != address[index] {
                            return false;
                        }
                        index += 1;
                    }
                    true
                }
                None => false,
            },
        }
    }

    /// Encode the exact configuration ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_CONFIG_VALUE_LEN] {
        let mut out = [0_u8; GTPU_SESSION_CONFIG_VALUE_LEN];
        out[0] = CONFIG_FORMAT_VERSION;
        out[1] = (self.ipv4.is_some() as u8) | ((self.ipv6.is_some() as u8) << 1);
        out[4..8].copy_from_slice(&self.ingress_ifindex.to_be_bytes());
        out[8..24].copy_from_slice(&self.device_id.to_bytes());
        if let Some(ipv4) = self.ipv4 {
            out[24..28].copy_from_slice(&ipv4);
        }
        if let Some(ipv6) = self.ipv6 {
            out[40..56].copy_from_slice(&ipv6);
        }
        out
    }

    /// Decode canonical configuration and reject every inconsistent slot.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_CONFIG_VALUE_LEN]) -> Option<Self> {
        if value[0] != CONFIG_FORMAT_VERSION
            || !matches!(value[1], 1..=3)
            || value[2..4].iter().any(|byte| *byte != 0)
            || value[56..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let ingress_ifindex = u32::from_be_bytes(copy_4(value, 4)?);
        let device_id = GtpuSessionDeviceId::new(copy_16(value, 8)?)?;
        let ipv4 = if value[1] & 1 != 0 {
            if value[28..40].iter().any(|byte| *byte != 0) {
                return None;
            }
            Some(copy_4(value, 24)?)
        } else if value[24..40].iter().all(|byte| *byte == 0) {
            None
        } else {
            return None;
        };
        let ipv6 = if value[1] & 2 != 0 {
            Some(copy_16(value, 40)?)
        } else if value[40..56].iter().all(|byte| *byte == 0) {
            None
        } else {
            return None;
        };
        Self::new(device_id, ingress_ifindex, ipv4, ipv6)
    }
}

fn address_family(address: GtpuEndpointAddress) -> GtpuSessionIpFamily {
    match address {
        GtpuEndpointAddress::Ipv4(_) => GtpuSessionIpFamily::Ipv4,
        GtpuEndpointAddress::Ipv6(_) => GtpuSessionIpFamily::Ipv6,
    }
}

fn address_bytes(address: GtpuEndpointAddress) -> [u8; 16] {
    match address {
        GtpuEndpointAddress::Ipv4(value) => [
            value[0], value[1], value[2], value[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        GtpuEndpointAddress::Ipv6(value) => value,
    }
}

fn decode_address(family: u8, bytes: [u8; 16]) -> Option<GtpuEndpointAddress> {
    match GtpuSessionIpFamily::from_wire(family)? {
        GtpuSessionIpFamily::Ipv4 if bytes[4..] == [0; 12] => Some(GtpuEndpointAddress::Ipv4([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ])),
        GtpuSessionIpFamily::Ipv4 => None,
        GtpuSessionIpFamily::Ipv6 => Some(GtpuEndpointAddress::Ipv6(bytes)),
    }
}

fn copy_16(value: &[u8], offset: usize) -> Option<[u8; 16]> {
    let end = offset.checked_add(16)?;
    let source = value.get(offset..end)?;
    let mut out = [0_u8; 16];
    out.copy_from_slice(source);
    Some(out)
}

fn copy_4(value: &[u8], offset: usize) -> Option<[u8; 4]> {
    let end = offset.checked_add(4)?;
    let source = value.get(offset..end)?;
    let mut out = [0_u8; 4];
    out.copy_from_slice(source);
    Some(out)
}

fn copy_8(value: &[u8], offset: usize) -> Option<[u8; 8]> {
    let end = offset.checked_add(8)?;
    let source = value.get(offset..end)?;
    let mut out = [0_u8; 8];
    out.copy_from_slice(source);
    Some(out)
}

/// Complete forwarding state for one inner address family in a logical group.
///
/// Every routing/session value is redacted from `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionEntry {
    inner_paa: GtpuSessionPaa,
    peer_outer_address: GtpuEndpointAddress,
    local_outer_address: GtpuEndpointAddress,
    local_teid: [u8; 4],
    peer_teid: [u8; 4],
    bearer_mark: [u8; 4],
    egress_dscp_wire: u8,
    downlink_source_port_policy: GtpuSourcePortPolicy,
    uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
}

impl core::fmt::Debug for GtpuSessionEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuSessionEntry")
            .field("inner_family", &self.inner_family())
            .field("outer_family", &self.outer_family())
            .field("routing_identity", &"<redacted>")
            .field("egress_dscp", &self.egress_dscp())
            .field("source_port_policies", &"<redacted>")
            .finish()
    }
}

impl GtpuSessionEntry {
    /// Construct one canonical grouped family entry.
    ///
    /// Outer local and peer addresses must use the same family. Every address
    /// and TEID must be nonzero; DSCP must be at most 63; and the uplink
    /// source-port policy must have a canonical wire encoding.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        inner_paa: GtpuSessionPaa,
        peer_outer_address: GtpuEndpointAddress,
        local_outer_address: GtpuEndpointAddress,
        local_teid: [u8; 4],
        peer_teid: [u8; 4],
        bearer_mark: [u8; 4],
        egress_dscp: Option<u8>,
        downlink_source_port_policy: GtpuSourcePortPolicy,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
    ) -> Option<Self> {
        if peer_outer_address.is_unspecified()
            || local_outer_address.is_unspecified()
            || address_family(peer_outer_address) != address_family(local_outer_address)
            || inner_paa.contains(local_outer_address)
            || local_teid == [0; 4]
            || peer_teid == [0; 4]
            || egress_dscp.is_some_and(|value| value > 63)
            || uplink_source_port_policy.map_value().is_none()
        {
            return None;
        }
        Some(Self {
            inner_paa,
            peer_outer_address,
            local_outer_address,
            local_teid,
            peer_teid,
            bearer_mark,
            egress_dscp_wire: egress_dscp.unwrap_or(0xff),
            downlink_source_port_policy,
            uplink_source_port_policy,
        })
    }

    /// Canonical inner IPv4 `/32` or IPv6 `/64` PAA.
    #[must_use]
    pub const fn inner_paa(self) -> GtpuSessionPaa {
        self.inner_paa
    }

    /// Authorized peer outer address.
    #[must_use]
    pub const fn peer_outer_address(self) -> GtpuEndpointAddress {
        self.peer_outer_address
    }

    /// Exact managed local outer address.
    #[must_use]
    pub const fn local_outer_address(self) -> GtpuEndpointAddress {
        self.local_outer_address
    }

    /// Incoming/local TEID in network order.
    #[must_use]
    pub const fn local_teid(self) -> [u8; 4] {
        self.local_teid
    }

    /// Outgoing/peer TEID in network order.
    #[must_use]
    pub const fn peer_teid(self) -> [u8; 4] {
        self.peer_teid
    }

    /// Complete packet mark in network order; zero selects the default path.
    #[must_use]
    pub const fn bearer_mark(self) -> [u8; 4] {
        self.bearer_mark
    }

    /// Optional fixed outer DSCP.
    #[must_use]
    pub const fn egress_dscp(self) -> Option<u8> {
        if self.egress_dscp_wire == 0xff {
            None
        } else {
            Some(self.egress_dscp_wire)
        }
    }

    /// Explicit inbound source-port authorization.
    #[must_use]
    pub const fn downlink_source_port_policy(self) -> GtpuSourcePortPolicy {
        self.downlink_source_port_policy
    }

    /// Explicit uplink source-port selection.
    #[must_use]
    pub const fn uplink_source_port_policy(self) -> GtpuUplinkSourcePortPolicy {
        self.uplink_source_port_policy
    }

    /// Inner address family.
    #[must_use]
    pub fn inner_family(self) -> GtpuSessionIpFamily {
        self.inner_paa.family()
    }

    /// Outer transport family.
    #[must_use]
    pub fn outer_family(self) -> GtpuSessionIpFamily {
        address_family(self.peer_outer_address)
    }

    /// Encode the exact fixed-width entry ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_ENTRY_LEN] {
        let mut out = [0_u8; GTPU_SESSION_ENTRY_LEN];
        out[0] = ENTRY_FORMAT_VERSION;
        out[1] = self.inner_family() as u8;
        out[2] = self.outer_family() as u8;
        out[3] = 0;
        out[4..20].copy_from_slice(&self.inner_paa.encode_bytes());
        out[20..36].copy_from_slice(&address_bytes(self.peer_outer_address));
        out[36..52].copy_from_slice(&address_bytes(self.local_outer_address));
        out[52..56].copy_from_slice(&self.local_teid);
        out[56..60].copy_from_slice(&self.peer_teid);
        out[60..64].copy_from_slice(&self.bearer_mark);
        out[64] = self.egress_dscp_wire;
        let (policy, first, last) = self.downlink_source_port_policy.encode();
        out[65] = policy;
        out[66..68].copy_from_slice(&first.to_be_bytes());
        out[68..70].copy_from_slice(&last.to_be_bytes());
        if let Some(source_port) = self.uplink_source_port_policy.map_value() {
            out[70..72].copy_from_slice(&source_port);
        }
        out
    }

    /// Decode one canonical fixed-width entry.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_ENTRY_LEN]) -> Option<Self> {
        if value[0] != ENTRY_FORMAT_VERSION
            || value[3] != 0
            || value[72..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let inner = GtpuSessionPaa::decode(value[1], copy_16(value, 4)?)?;
        let peer = decode_address(value[2], copy_16(value, 20)?)?;
        let local = decode_address(value[2], copy_16(value, 36)?)?;
        let first = u16::from_be_bytes([value[66], value[67]]);
        let last = u16::from_be_bytes([value[68], value[69]]);
        let downlink_policy = match value[65] {
            0 if first == 0 && last == 0 => GtpuSourcePortPolicy::Any,
            1 if first == last => GtpuSourcePortPolicy::Exact(first),
            2 => GtpuSourcePortRange::new(first, last).map(GtpuSourcePortPolicy::InclusiveRange)?,
            _ => return None,
        };
        let uplink_policy = GtpuUplinkSourcePortPolicy::from_map_value([value[70], value[71]])?;
        let dscp = match value[64] {
            0..=63 => Some(value[64]),
            0xff => None,
            _ => return None,
        };
        Self::new(
            inner,
            peer,
            local,
            copy_4(value, 52)?,
            copy_4(value, 56)?,
            copy_4(value, 60)?,
            dscp,
            downlink_policy,
            uplink_policy,
        )
    }
}

fn wire_address_is_canonical(family: u8, value: &[u8]) -> bool {
    if value.len() != 16 {
        return false;
    }
    match GtpuSessionIpFamily::from_wire(family) {
        Some(GtpuSessionIpFamily::Ipv4) => {
            value[..4].iter().any(|byte| *byte != 0) && value[4..].iter().all(|byte| *byte == 0)
        }
        Some(GtpuSessionIpFamily::Ipv6) => value.iter().any(|byte| *byte != 0),
        None => false,
    }
}

fn entry_wire_is_canonical(value: &[u8], expected_family: GtpuSessionIpFamily) -> bool {
    if value.len() != GTPU_SESSION_ENTRY_LEN
        || value[0] != ENTRY_FORMAT_VERSION
        || value[1] != expected_family as u8
        || value[3] != 0
        || !wire_address_is_canonical(value[1], &value[4..20])
        || !wire_address_is_canonical(value[2], &value[20..36])
        || !wire_address_is_canonical(value[2], &value[36..52])
        || value[52..56].iter().all(|byte| *byte == 0)
        || value[56..60].iter().all(|byte| *byte == 0)
        || !matches!(value[64], 0..=63 | 0xff)
        || value[72..].iter().any(|byte| *byte != 0)
    {
        return false;
    }
    let aliases_inner = match (expected_family, GtpuSessionIpFamily::from_wire(value[2])) {
        (GtpuSessionIpFamily::Ipv4, Some(GtpuSessionIpFamily::Ipv4)) => {
            value[4..8] == value[36..40]
        }
        (GtpuSessionIpFamily::Ipv6, Some(GtpuSessionIpFamily::Ipv6)) => {
            value[4..12] == value[36..44]
        }
        _ => false,
    };
    if aliases_inner {
        return false;
    }
    let first = u16::from_be_bytes([value[66], value[67]]);
    let last = u16::from_be_bytes([value[68], value[69]]);
    let downlink_policy_is_canonical = match value[65] {
        0 => first == 0 && last == 0,
        1 => first == last,
        2 => first < last,
        _ => false,
    };
    downlink_policy_is_canonical
        && GtpuUplinkSourcePortPolicy::from_map_value([value[70], value[71]]).is_some()
}

/// Canonical grouped uplink lookup key `(inner family, PAA, complete mark)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionUplinkKey {
    inner_paa: GtpuSessionPaa,
    bearer_mark: [u8; 4],
}

impl core::fmt::Debug for GtpuSessionUplinkKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuSessionUplinkKey")
            .field("family", &self.inner_paa.family())
            .field("routing_identity", &"<redacted>")
            .finish()
    }
}

impl GtpuSessionUplinkKey {
    /// Construct an uplink selector from canonical PAA identity.
    #[must_use]
    pub const fn new(inner_paa: GtpuSessionPaa, bearer_mark: [u8; 4]) -> Self {
        Self {
            inner_paa,
            bearer_mark,
        }
    }

    /// Normalize a complete packet source address to a PAA selector.
    #[must_use]
    pub fn from_packet_address(
        inner_address: GtpuEndpointAddress,
        bearer_mark: [u8; 4],
    ) -> Option<Self> {
        let inner_paa = GtpuSessionPaa::from_packet_address(inner_address)?;
        Some(Self {
            inner_paa,
            bearer_mark,
        })
    }

    /// Build the selector projected by an entry.
    #[must_use]
    pub fn from_entry(entry: GtpuSessionEntry) -> Self {
        Self {
            inner_paa: entry.inner_paa,
            bearer_mark: entry.bearer_mark,
        }
    }

    /// Inner address family.
    #[must_use]
    pub fn family(self) -> GtpuSessionIpFamily {
        self.inner_paa.family()
    }

    /// Encode the exact key ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_UPLINK_KEY_LEN] {
        let mut out = [0_u8; GTPU_SESSION_UPLINK_KEY_LEN];
        out[0] = self.family() as u8;
        out[4..20].copy_from_slice(&self.inner_paa.encode_bytes());
        out[20..24].copy_from_slice(&self.bearer_mark);
        out
    }

    /// Decode a canonical key.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_UPLINK_KEY_LEN]) -> Option<Self> {
        if value[1..4].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(Self::new(
            GtpuSessionPaa::decode(value[0], copy_16(value, 4)?)?,
            copy_4(value, 20)?,
        ))
    }
}

/// Canonical grouped downlink lookup key
/// `(outer family, parsed inner family, local TEID)`.
///
/// The inner family is parsed from the bounded GTP-U payload before lookup.
/// It prevents a TEID owned by one family slot from authorizing the other
/// family and lets both slots intentionally share one outer-family/TEID pair.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionDownlinkKey {
    outer_family: GtpuSessionIpFamily,
    inner_family: GtpuSessionIpFamily,
    local_teid: [u8; 4],
}

impl core::fmt::Debug for GtpuSessionDownlinkKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuSessionDownlinkKey")
            .field("outer_family", &self.outer_family)
            .field("inner_family", &self.inner_family)
            .field("local_teid", &"<redacted>")
            .finish()
    }
}

impl GtpuSessionDownlinkKey {
    /// Construct a key with a nonzero local TEID.
    #[must_use]
    pub fn new(
        outer_family: GtpuSessionIpFamily,
        inner_family: GtpuSessionIpFamily,
        local_teid: [u8; 4],
    ) -> Option<Self> {
        if local_teid == [0; 4] {
            return None;
        }
        Some(Self {
            outer_family,
            inner_family,
            local_teid,
        })
    }

    /// Build the selector projected by an entry.
    #[must_use]
    pub fn from_entry(entry: GtpuSessionEntry) -> Self {
        Self {
            outer_family: entry.outer_family(),
            inner_family: entry.inner_family(),
            local_teid: entry.local_teid,
        }
    }

    /// Outer transport family.
    #[must_use]
    pub const fn outer_family(self) -> GtpuSessionIpFamily {
        self.outer_family
    }

    /// Parsed inner packet family.
    #[must_use]
    pub const fn inner_family(self) -> GtpuSessionIpFamily {
        self.inner_family
    }

    /// Local TEID in network order.
    #[must_use]
    pub const fn local_teid(self) -> [u8; 4] {
        self.local_teid
    }

    /// Encode the exact key ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_DOWNLINK_KEY_LEN] {
        let mut out = [0_u8; GTPU_SESSION_DOWNLINK_KEY_LEN];
        out[0] = self.outer_family as u8;
        out[1] = self.inner_family as u8;
        out[4..8].copy_from_slice(&self.local_teid);
        out
    }

    /// Decode a canonical key.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_DOWNLINK_KEY_LEN]) -> Option<Self> {
        if value[2..4].iter().any(|byte| *byte != 0) {
            return None;
        }
        Self::new(
            GtpuSessionIpFamily::from_wire(value[0])?,
            GtpuSessionIpFamily::from_wire(value[1])?,
            copy_4(value, 4)?,
        )
    }
}

/// One generation/inner-family candidate in a selector index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionIndexCandidate {
    generation: GtpuSessionGeneration,
    slot: u8,
}

impl GtpuSessionIndexCandidate {
    /// Construct an exact candidate for one canonical family slot.
    #[must_use]
    pub const fn new(generation: GtpuSessionGeneration, slot: u8) -> Option<Self> {
        if matches!(slot, GTPU_SESSION_IPV4_SLOT | GTPU_SESSION_IPV6_SLOT) {
            Some(Self { generation, slot })
        } else {
            None
        }
    }

    /// Referenced authority generation.
    #[must_use]
    pub const fn generation(self) -> GtpuSessionGeneration {
        self.generation
    }

    /// Exact canonical family slot.
    #[must_use]
    pub const fn slot(self) -> u8 {
        self.slot
    }
}

/// Dual-candidate selector value used for lossless authority cutover.
///
/// A shared selector is staged with candidates `N` and `N+1`, a new selector
/// with only `N+1`, and an old selector with only `N`. The tc path looks up
/// and retains this value first, then looks up the group authority exactly
/// once, and authorizes only the candidate matching that authority's exact
/// generation and canonical slot. It never re-looks-up the index.
///
/// One selector cannot transfer directly between group IDs. Such a transfer
/// must drain/remove the old group before creating the new group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionGroupRef {
    group_id: GtpuSessionGroupId,
    base: Option<GtpuSessionIndexCandidate>,
    desired: Option<GtpuSessionIndexCandidate>,
}

impl core::fmt::Debug for GtpuSessionGroupRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuSessionGroupRef")
            .field("group_id", &"<redacted>")
            .field("base", &self.base)
            .field("desired", &self.desired)
            .finish()
    }
}

impl GtpuSessionGroupRef {
    /// Construct a canonical one- or two-generation selector value.
    ///
    /// When both candidates are present, `desired` must be exactly the checked
    /// successor of `base`. Overflow therefore fails closed before staging.
    #[must_use]
    pub const fn new(
        group_id: GtpuSessionGroupId,
        base: Option<GtpuSessionIndexCandidate>,
        desired: Option<GtpuSessionIndexCandidate>,
    ) -> Option<Self> {
        match (base, desired) {
            (None, None) => None,
            (Some(base), Some(desired))
                if match base.generation.checked_next() {
                    Some(next) => next.get() == desired.generation.get(),
                    None => false,
                } && base.slot == desired.slot =>
            {
                Some(Self {
                    group_id,
                    base: Some(base),
                    desired: Some(desired),
                })
            }
            (Some(base), None) => Some(Self {
                group_id,
                base: Some(base),
                desired: None,
            }),
            (None, Some(desired)) => Some(Self {
                group_id,
                base: None,
                desired: Some(desired),
            }),
            _ => None,
        }
    }

    /// Construct a single currently authoritative candidate.
    #[must_use]
    pub const fn single(
        group_id: GtpuSessionGroupId,
        candidate: GtpuSessionIndexCandidate,
    ) -> Self {
        Self {
            group_id,
            base: Some(candidate),
            desired: None,
        }
    }

    /// Referenced group identifier.
    #[must_use]
    pub const fn group_id(self) -> GtpuSessionGroupId {
        self.group_id
    }

    /// Pre-cutover candidate, if retained.
    #[must_use]
    pub const fn base(self) -> Option<GtpuSessionIndexCandidate> {
        self.base
    }

    /// Staged post-cutover candidate, if present.
    #[must_use]
    pub const fn desired(self) -> Option<GtpuSessionIndexCandidate> {
        self.desired
    }

    /// Return the sole candidate for an exact authority generation.
    #[must_use]
    pub const fn for_generation(
        self,
        generation: GtpuSessionGeneration,
    ) -> Option<GtpuSessionIndexCandidate> {
        if let Some(base) = self.base {
            if base.generation.get() == generation.get() {
                return Some(base);
            }
        }
        if let Some(desired) = self.desired {
            if desired.generation.get() == generation.get() {
                return Some(desired);
            }
        }
        None
    }

    /// Encode the exact dual-candidate index-value ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_GROUP_REF_LEN] {
        let mut out = [0_u8; GTPU_SESSION_GROUP_REF_LEN];
        out[..16].copy_from_slice(&self.group_id.to_bytes());
        if let Some(base) = self.base {
            out[16..24].copy_from_slice(&base.generation.get().to_be_bytes());
            out[24] = base.slot;
        }
        if let Some(desired) = self.desired {
            out[32..40].copy_from_slice(&desired.generation.get().to_be_bytes());
            out[40] = desired.slot;
        }
        out
    }

    /// Decode a canonical dual-candidate index value.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_GROUP_REF_LEN]) -> Option<Self> {
        let group_id = GtpuSessionGroupId::new(copy_16(value, 0)?)?;
        let decode_candidate = |offset: usize| {
            let generation = u64::from_be_bytes(value.get(offset..offset + 8)?.try_into().ok()?);
            let slot = *value.get(offset + 8)?;
            let reserved = value.get(offset + 9..offset + 16)?;
            if generation == 0 {
                if slot == 0 && reserved.iter().all(|byte| *byte == 0) {
                    Some(None)
                } else {
                    None
                }
            } else if reserved.iter().all(|byte| *byte == 0) {
                Some(Some(GtpuSessionIndexCandidate::new(
                    GtpuSessionGeneration::new(generation)?,
                    slot,
                )?))
            } else {
                None
            }
        };
        Self::new(group_id, decode_candidate(16)?, decode_candidate(32)?)
    }
}

/// Verifier-oriented header view of one raw group authority value.
///
/// Decoding validates the fixed header and both slots in place without
/// copying either 80-byte entry. tc then selects exactly one slot from the
/// already-retained authority pointer and materializes only that entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionAuthorityHeader {
    group_id: GtpuSessionGroupId,
    device_id: GtpuSessionDeviceId,
    generation: GtpuSessionGeneration,
    phase: GtpuSessionGroupPhase,
    family_mask: u8,
}

impl GtpuSessionAuthorityHeader {
    /// Validate a raw authority header and both fixed slots without
    /// materializing a complete group record.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_GROUP_VALUE_LEN]) -> Option<Self> {
        if value[0] != GROUP_FORMAT_VERSION
            || value[3] != 0
            || value[12..16].iter().any(|byte| *byte != 0)
            || !matches!(value[2], 1..=3)
        {
            return None;
        }
        let generation = GtpuSessionGeneration::new(u64::from_be_bytes(copy_8(value, 4)?))?;
        let phase = GtpuSessionGroupPhase::from_wire(value[1])?;
        if phase == GtpuSessionGroupPhase::Pending && generation != GtpuSessionGeneration::INITIAL
            || phase == GtpuSessionGroupPhase::Removing && generation.get() < 2
        {
            return None;
        }
        let header = Self {
            device_id: GtpuSessionDeviceId::new(copy_16(value, 16)?)?,
            group_id: GtpuSessionGroupId::new(copy_16(value, 32)?)?,
            generation,
            phase,
            family_mask: value[2],
        };
        for (slot, family, mask) in [
            (0_usize, GtpuSessionIpFamily::Ipv4, 1_u8),
            (1, GtpuSessionIpFamily::Ipv6, 2),
        ] {
            let start = GROUP_HEADER_LEN + slot * GTPU_SESSION_ENTRY_LEN;
            let end = start + GTPU_SESSION_ENTRY_LEN;
            let encoded = value.get(start..end)?;
            if header.family_mask & mask != 0 {
                if !entry_wire_is_canonical(encoded, family) {
                    return None;
                }
            } else if encoded.iter().any(|byte| *byte != 0) {
                return None;
            }
        }
        Some(header)
    }

    /// Group map key duplicated in the authority.
    #[must_use]
    pub const fn group_id(self) -> GtpuSessionGroupId {
        self.group_id
    }

    /// Exact managed device identity.
    #[must_use]
    pub const fn device_id(self) -> GtpuSessionDeviceId {
        self.device_id
    }

    /// Exact active/staged generation.
    #[must_use]
    pub const fn generation(self) -> GtpuSessionGeneration {
        self.generation
    }

    /// Durable authority phase.
    #[must_use]
    pub const fn phase(self) -> GtpuSessionGroupPhase {
        self.phase
    }

    /// Canonical family-presence mask.
    #[must_use]
    pub const fn family_mask(self) -> u8 {
        self.family_mask
    }
}

fn decode_selected_authority_entry(
    value: &[u8; GTPU_SESSION_GROUP_VALUE_LEN],
    slot: u8,
) -> Option<GtpuSessionEntry> {
    let slot = usize::from(slot);
    if slot > 1 {
        return None;
    }
    let start = GROUP_HEADER_LEN + slot * GTPU_SESSION_ENTRY_LEN;
    let end = start + GTPU_SESSION_ENTRY_LEN;
    let mut encoded = [0_u8; GTPU_SESSION_ENTRY_LEN];
    encoded.copy_from_slice(value.get(start..end)?);
    GtpuSessionEntry::decode(&encoded)
}

/// Atomic authority for every family entry in one logical session.
///
/// The backing map must be an ordinary non-per-CPU HASH and this entire value
/// must be replaced with one `BPF_MAP_UPDATE_ELEM`. tc retains its selector
/// value, then retains this authority value, exact-matches generation, device,
/// key, and slot, and acts without another selector lookup. A packet already
/// holding an older RCU map-value pointer may complete after cutover. Selector
/// and TEID reuse therefore requires an explicit drain/grace proof; immediate
/// reuse is forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionGroupRecord {
    group_id: GtpuSessionGroupId,
    device_id: GtpuSessionDeviceId,
    generation: GtpuSessionGeneration,
    phase: GtpuSessionGroupPhase,
    ipv4: Option<GtpuSessionEntry>,
    ipv6: Option<GtpuSessionEntry>,
}

impl GtpuSessionGroupRecord {
    /// Construct canonical Active authority with one or both inner families.
    #[must_use]
    pub fn active(
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
        ipv4: Option<GtpuSessionEntry>,
        ipv6: Option<GtpuSessionEntry>,
    ) -> Option<Self> {
        Self::from_parts(
            group_id,
            device_id,
            generation,
            ipv4,
            ipv6,
            GtpuSessionGroupPhase::Active,
        )
    }

    fn from_parts(
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
        ipv4: Option<GtpuSessionEntry>,
        ipv6: Option<GtpuSessionEntry>,
        phase: GtpuSessionGroupPhase,
    ) -> Option<Self> {
        if ipv4.is_none() && ipv6.is_none()
            || ipv4.is_some_and(|entry| entry.inner_family() != GtpuSessionIpFamily::Ipv4)
            || ipv6.is_some_and(|entry| entry.inner_family() != GtpuSessionIpFamily::Ipv6)
            || phase == GtpuSessionGroupPhase::Pending
                && generation != GtpuSessionGeneration::INITIAL
            || phase == GtpuSessionGroupPhase::Removing && generation.get() < 2
        {
            return None;
        }
        Some(Self {
            group_id,
            device_id,
            generation,
            phase,
            ipv4,
            ipv6,
        })
    }

    /// Group map key duplicated for exact ref/key back-validation.
    #[must_use]
    pub const fn group_id(self) -> GtpuSessionGroupId {
        self.group_id
    }

    /// Exact managed device/pin-namespace identity.
    #[must_use]
    pub const fn device_id(self) -> GtpuSessionDeviceId {
        self.device_id
    }

    /// Monotonic nonzero group generation.
    #[must_use]
    pub const fn generation(self) -> GtpuSessionGeneration {
        self.generation
    }

    /// Durable transaction phase.
    #[must_use]
    pub const fn phase(self) -> GtpuSessionGroupPhase {
        self.phase
    }

    /// Return a family entry.
    #[must_use]
    pub const fn entry(self, family: GtpuSessionIpFamily) -> Option<GtpuSessionEntry> {
        match family {
            GtpuSessionIpFamily::Ipv4 => self.ipv4,
            GtpuSessionIpFamily::Ipv6 => self.ipv6,
        }
    }

    /// Return a canonical slot entry.
    #[must_use]
    pub const fn slot(self, slot: u8) -> Option<GtpuSessionEntry> {
        match slot {
            GTPU_SESSION_IPV4_SLOT => self.ipv4,
            GTPU_SESSION_IPV6_SLOT => self.ipv6,
            _ => None,
        }
    }

    /// Return the inner-family presence mask.
    #[must_use]
    pub const fn family_mask(self) -> u8 {
        (self.ipv4.is_some() as u8) | ((self.ipv6.is_some() as u8) << 1)
    }

    fn with_phase(self, phase: GtpuSessionGroupPhase) -> Option<Self> {
        Self::from_parts(
            self.group_id,
            self.device_id,
            self.generation,
            self.ipv4,
            self.ipv6,
            phase,
        )
    }

    fn with_generation_and_phase(
        self,
        generation: GtpuSessionGeneration,
        phase: GtpuSessionGroupPhase,
    ) -> Option<Self> {
        Self::from_parts(
            self.group_id,
            self.device_id,
            generation,
            self.ipv4,
            self.ipv6,
            phase,
        )
    }

    /// Encode the exact group-authority ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_GROUP_VALUE_LEN] {
        let mut out = [0_u8; GTPU_SESSION_GROUP_VALUE_LEN];
        out[0] = GROUP_FORMAT_VERSION;
        out[1] = self.phase as u8;
        out[2] = self.family_mask();
        out[4..12].copy_from_slice(&self.generation.get().to_be_bytes());
        out[16..32].copy_from_slice(&self.device_id.to_bytes());
        out[32..48].copy_from_slice(&self.group_id.to_bytes());
        if let Some(entry) = self.ipv4 {
            out[GROUP_HEADER_LEN..GROUP_HEADER_LEN + GTPU_SESSION_ENTRY_LEN]
                .copy_from_slice(&entry.encode());
        }
        if let Some(entry) = self.ipv6 {
            let start = GROUP_HEADER_LEN + GTPU_SESSION_ENTRY_LEN;
            out[start..start + GTPU_SESSION_ENTRY_LEN].copy_from_slice(&entry.encode());
        }
        out
    }

    /// Decode a canonical group-authority record.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_GROUP_VALUE_LEN]) -> Option<Self> {
        let header = GtpuSessionAuthorityHeader::decode(value)?;
        let ipv4 = if header.family_mask & 1 != 0 {
            Some(decode_selected_authority_entry(
                value,
                GTPU_SESSION_IPV4_SLOT,
            )?)
        } else {
            None
        };
        let ipv6 = if header.family_mask & 2 != 0 {
            Some(decode_selected_authority_entry(
                value,
                GTPU_SESSION_IPV6_SLOT,
            )?)
        } else {
            None
        };
        Self::from_parts(
            header.group_id,
            header.device_id,
            header.generation,
            ipv4,
            ipv6,
            header.phase,
        )
    }
}

/// Durable userspace-only base/desired transaction journal.
///
/// The journal is written before any selector mutation and remains until
/// authority cutover and exact candidate cleanup are both read back. It is
/// bounded to in-flight work: after exact removal, the authority is deleted
/// last and the caller permanently retires the cryptographically unique group
/// ID. Journals are not permanent dataplane tombstones.
///
/// Recovery may remove only byte-exact candidates owned by this record.
/// Missing, malformed, or conflicting journal/authority/index state remains
/// fenced or unchanged and is classified indeterminate; cleanup is never
/// guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionTransactionRecord {
    group_id: GtpuSessionGroupId,
    transaction_id: GtpuSessionTransactionId,
    target_generation: GtpuSessionGeneration,
    phase: GtpuSessionTransactionPhase,
    base: Option<GtpuSessionGroupRecord>,
    desired: Option<GtpuSessionGroupRecord>,
}

impl GtpuSessionTransactionRecord {
    /// Prepare an install, update, or removal journal before any mutation.
    ///
    /// `None → Some` is fresh creation at generation 1, `Some → Some` is an
    /// update to the exact checked successor, and `Some → None` is removal
    /// whose fence uses that successor. Both semantic graph records must be
    /// Active and must carry the same exact managed device identity. Later
    /// phases can be reached only through [`Self::advance`] or decoded from
    /// already-persisted canonical bytes.
    #[must_use]
    pub fn prepare(
        group_id: GtpuSessionGroupId,
        transaction_id: GtpuSessionTransactionId,
        base: Option<GtpuSessionGroupRecord>,
        desired: Option<GtpuSessionGroupRecord>,
    ) -> Option<Self> {
        Self::from_parts(
            group_id,
            transaction_id,
            GtpuSessionTransactionPhase::Prepared,
            base,
            desired,
        )
    }

    fn from_parts(
        group_id: GtpuSessionGroupId,
        transaction_id: GtpuSessionTransactionId,
        phase: GtpuSessionTransactionPhase,
        base: Option<GtpuSessionGroupRecord>,
        desired: Option<GtpuSessionGroupRecord>,
    ) -> Option<Self> {
        if base.is_none() && desired.is_none()
            || base.is_some_and(|record| record.phase != GtpuSessionGroupPhase::Active)
            || desired.is_some_and(|record| record.phase != GtpuSessionGroupPhase::Active)
            || base.is_some_and(|record| record.group_id != group_id)
            || desired.is_some_and(|record| record.group_id != group_id)
            || base.is_some()
                && desired.is_none()
                && phase == GtpuSessionTransactionPhase::IndexesStaged
            || matches!(
                (base, desired),
                (Some(base), Some(desired)) if base.device_id != desired.device_id
            )
        {
            return None;
        }
        let target_generation = match (base, desired) {
            (None, Some(desired)) if desired.generation == GtpuSessionGeneration::INITIAL => {
                desired.generation
            }
            (Some(base), Some(desired))
                if base.generation.checked_next() == Some(desired.generation) =>
            {
                desired.generation
            }
            (Some(base), None) => base.generation.checked_next()?,
            _ => return None,
        };
        Some(Self {
            group_id,
            transaction_id,
            target_generation,
            phase,
            base,
            desired,
        })
    }

    /// Group whose selector graph is being changed.
    #[must_use]
    pub const fn group_id(self) -> GtpuSessionGroupId {
        self.group_id
    }

    /// Unique operation token.
    #[must_use]
    pub const fn transaction_id(self) -> GtpuSessionTransactionId {
        self.transaction_id
    }

    /// Generation committed by the single authority cutover.
    #[must_use]
    pub const fn target_generation(self) -> GtpuSessionGeneration {
        self.target_generation
    }

    /// Durable transaction progress.
    #[must_use]
    pub const fn phase(self) -> GtpuSessionTransactionPhase {
        self.phase
    }

    /// Exact pre-transaction semantic graph, or absence for creation.
    #[must_use]
    pub const fn base(self) -> Option<GtpuSessionGroupRecord> {
        self.base
    }

    /// Exact desired semantic graph, or absence for removal.
    #[must_use]
    pub const fn desired(self) -> Option<GtpuSessionGroupRecord> {
        self.desired
    }

    /// Advance through the only canonical operation-specific journal phase.
    #[must_use]
    pub fn advance(self) -> Option<Self> {
        let phase = match (self.phase, self.base, self.desired) {
            (GtpuSessionTransactionPhase::Prepared, Some(_), None) => {
                GtpuSessionTransactionPhase::AuthorityCommitted
            }
            (GtpuSessionTransactionPhase::Prepared, _, Some(_)) => {
                GtpuSessionTransactionPhase::IndexesStaged
            }
            (GtpuSessionTransactionPhase::IndexesStaged, _, Some(_)) => {
                GtpuSessionTransactionPhase::AuthorityCommitted
            }
            _ => return None,
        };
        Self::from_parts(
            self.group_id,
            self.transaction_id,
            phase,
            self.base,
            self.desired,
        )
    }

    /// Authority value used to fence a prepared fresh create or removal.
    ///
    /// Updates deliberately keep the old Active generation until all
    /// dual-generation candidates are staged.
    #[must_use]
    pub fn fence_authority(self) -> Option<GtpuSessionGroupRecord> {
        match (self.phase, self.base, self.desired) {
            (GtpuSessionTransactionPhase::Prepared, None, Some(desired)) => {
                desired.with_phase(GtpuSessionGroupPhase::Pending)
            }
            (GtpuSessionTransactionPhase::Prepared, Some(base), None) => base
                .with_generation_and_phase(self.target_generation, GtpuSessionGroupPhase::Removing),
            _ => None,
        }
    }

    /// Authority value for an install/update cutover after indexes are staged.
    #[must_use]
    pub const fn desired_authority(self) -> Option<GtpuSessionGroupRecord> {
        match self.phase {
            GtpuSessionTransactionPhase::IndexesStaged => self.desired,
            GtpuSessionTransactionPhase::Prepared
            | GtpuSessionTransactionPhase::AuthorityCommitted => None,
        }
    }

    /// Encode the exact fixed-width journal ABI.
    #[must_use]
    pub fn encode(self) -> [u8; GTPU_SESSION_TRANSACTION_VALUE_LEN] {
        let mut out = [0_u8; GTPU_SESSION_TRANSACTION_VALUE_LEN];
        out[0] = TRANSACTION_FORMAT_VERSION;
        out[1] = self.phase as u8;
        out[2] = (self.base.is_some() as u8) | ((self.desired.is_some() as u8) << 1);
        out[8..24].copy_from_slice(&self.group_id.to_bytes());
        out[24..40].copy_from_slice(&self.transaction_id.to_bytes());
        out[40..48].copy_from_slice(&self.target_generation.get().to_be_bytes());
        if let Some(base) = self.base {
            out[TRANSACTION_HEADER_LEN..TRANSACTION_HEADER_LEN + GTPU_SESSION_GROUP_VALUE_LEN]
                .copy_from_slice(&base.encode());
        }
        if let Some(desired) = self.desired {
            let start = TRANSACTION_HEADER_LEN + GTPU_SESSION_GROUP_VALUE_LEN;
            out[start..start + GTPU_SESSION_GROUP_VALUE_LEN].copy_from_slice(&desired.encode());
        }
        out
    }

    /// Decode a canonical fixed-width journal.
    #[must_use]
    pub fn decode(value: &[u8; GTPU_SESSION_TRANSACTION_VALUE_LEN]) -> Option<Self> {
        if value[0] != TRANSACTION_FORMAT_VERSION
            || value[3..8].iter().any(|byte| *byte != 0)
            || !matches!(value[2], 1..=3)
        {
            return None;
        }
        let group_id = GtpuSessionGroupId::new(copy_16(value, 8)?)?;
        let transaction_id = GtpuSessionTransactionId::new(copy_16(value, 24)?)?;
        let encoded_target = GtpuSessionGeneration::new(u64::from_be_bytes(copy_8(value, 40)?))?;
        let phase = GtpuSessionTransactionPhase::from_wire(value[1])?;
        let decode_record = |offset: usize| {
            let mut encoded = [0_u8; GTPU_SESSION_GROUP_VALUE_LEN];
            encoded.copy_from_slice(value.get(offset..offset + GTPU_SESSION_GROUP_VALUE_LEN)?);
            GtpuSessionGroupRecord::decode(&encoded)
        };
        let slot_is_zero = |offset: usize| {
            value
                .get(offset..offset + GTPU_SESSION_GROUP_VALUE_LEN)
                .is_some_and(|slot| slot.iter().all(|byte| *byte == 0))
        };
        let base = if value[2] & 1 != 0 {
            Some(decode_record(TRANSACTION_HEADER_LEN)?)
        } else if slot_is_zero(TRANSACTION_HEADER_LEN) {
            None
        } else {
            return None;
        };
        let desired_offset = TRANSACTION_HEADER_LEN + GTPU_SESSION_GROUP_VALUE_LEN;
        let desired = if value[2] & 2 != 0 {
            Some(decode_record(desired_offset)?)
        } else if slot_is_zero(desired_offset) {
            None
        } else {
            return None;
        };
        let decoded = Self::from_parts(group_id, transaction_id, phase, base, desired)?;
        if decoded.target_generation == encoded_target {
            Some(decoded)
        } else {
            None
        }
    }
}

/// Select one exact uplink action from an already-retained index and authority.
///
/// Required tc order is: decode/retain the index value first, extract
/// [`GtpuSessionGroupRef::group_id`], perform exactly one authority lookup by
/// that key, then call this function without another index lookup. Only the
/// selected 80-byte slot is copied; the 208-byte authority is never
/// materialized on the verifier stack.
#[must_use]
pub fn gtpu_session_group_authorizes_uplink(
    record: &[u8; GTPU_SESSION_GROUP_VALUE_LEN],
    reference: GtpuSessionGroupRef,
    key: GtpuSessionUplinkKey,
    config: GtpuSessionDeviceConfig,
    observed_ifindex: u32,
) -> Option<GtpuSessionEntry> {
    let header = GtpuSessionAuthorityHeader::decode(record)?;
    if header.phase != GtpuSessionGroupPhase::Active
        || header.group_id != reference.group_id
        || header.device_id != config.device_id
        || observed_ifindex == 0
        || observed_ifindex != config.ingress_ifindex
    {
        return None;
    }
    let candidate = reference.for_generation(header.generation)?;
    if candidate.slot != key.family().slot() {
        return None;
    }
    let entry = decode_selected_authority_entry(record, candidate.slot)?;
    if GtpuSessionUplinkKey::from_entry(entry) == key
        && config.authorizes_local(entry.local_outer_address)
    {
        Some(entry)
    } else {
        None
    }
}

/// Return whether an Active group authorizes one exact downlink packet.
///
/// The bounded inner parser supplies `inner_destination` before lookup. The
/// selected slot, downlink key, peer/local outer addresses, source-port policy,
/// device identity, and inner destination must all match the same canonical
/// entry. A selector owned only by the other family can never authorize it.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn gtpu_session_group_authorizes_downlink(
    record: &[u8; GTPU_SESSION_GROUP_VALUE_LEN],
    reference: GtpuSessionGroupRef,
    key: GtpuSessionDownlinkKey,
    config: GtpuSessionDeviceConfig,
    observed_ifindex: u32,
    packet_peer_outer: GtpuEndpointAddress,
    packet_local_outer: GtpuEndpointAddress,
    packet_source_port: u16,
    inner_destination: GtpuEndpointAddress,
) -> Option<GtpuSessionEntry> {
    let header = GtpuSessionAuthorityHeader::decode(record)?;
    if header.phase != GtpuSessionGroupPhase::Active
        || header.group_id != reference.group_id
        || header.device_id != config.device_id
        || observed_ifindex == 0
        || observed_ifindex != config.ingress_ifindex
        || !config.authorizes_local(packet_local_outer)
    {
        return None;
    }
    if address_family(inner_destination) != key.inner_family {
        return None;
    }
    let candidate = reference.for_generation(header.generation)?;
    if candidate.slot != key.inner_family.slot() {
        return None;
    }
    let entry = decode_selected_authority_entry(record, candidate.slot)?;
    if GtpuSessionDownlinkKey::from_entry(entry) == key
        && entry.inner_paa.contains(inner_destination)
        && entry.peer_outer_address == packet_peer_outer
        && entry.local_outer_address == packet_local_outer
        && entry
            .downlink_source_port_policy
            .permits(packet_source_port)
    {
        Some(entry)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn group_id() -> GtpuSessionGroupId {
        GtpuSessionGroupId::new([0x44; GTPU_SESSION_GROUP_ID_LEN]).unwrap()
    }

    fn other_group_id() -> GtpuSessionGroupId {
        GtpuSessionGroupId::new([0x45; GTPU_SESSION_GROUP_ID_LEN]).unwrap()
    }

    fn device_id() -> GtpuSessionDeviceId {
        GtpuSessionDeviceId::new([0x55; GTPU_SESSION_GROUP_ID_LEN]).unwrap()
    }

    fn transaction_id() -> GtpuSessionTransactionId {
        GtpuSessionTransactionId::new([0x66; GTPU_SESSION_GROUP_ID_LEN]).unwrap()
    }

    fn device_config() -> GtpuSessionDeviceConfig {
        GtpuSessionDeviceConfig::new(
            device_id(),
            42,
            Some([192, 0, 2, 1]),
            Some([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        )
        .unwrap()
    }

    fn generation(value: u64) -> GtpuSessionGeneration {
        GtpuSessionGeneration::new(value).unwrap()
    }

    fn v4_entry() -> GtpuSessionEntry {
        GtpuSessionEntry::new(
            GtpuSessionPaa::new(GtpuEndpointAddress::Ipv4([10, 23, 0, 2])).unwrap(),
            GtpuEndpointAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            GtpuEndpointAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            0x1000_0001_u32.to_be_bytes(),
            0x2000_0001_u32.to_be_bytes(),
            [0; 4],
            Some(46),
            GtpuSourcePortPolicy::Exact(21_152),
            GtpuUplinkSourcePortPolicy::selected(40_000).unwrap(),
        )
        .unwrap()
    }

    fn v6_entry() -> GtpuSessionEntry {
        GtpuSessionEntry::new(
            GtpuSessionPaa::from_full_paa(GtpuEndpointAddress::Ipv6([
                0x20, 1, 0x0d, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ]))
            .unwrap(),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            0x1000_0002_u32.to_be_bytes(),
            0x2000_0002_u32.to_be_bytes(),
            0x0102_0304_u32.to_be_bytes(),
            None,
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
        )
        .unwrap()
    }

    fn inner_packet(entry: GtpuSessionEntry, iid: u8) -> GtpuEndpointAddress {
        match entry.inner_paa() {
            GtpuSessionPaa::Ipv4(address) => GtpuEndpointAddress::Ipv4(address),
            GtpuSessionPaa::Ipv6Prefix(prefix) => GtpuEndpointAddress::Ipv6([
                prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], prefix[6],
                prefix[7], 0, 0, 0, 0, 0, 0, 0, iid,
            ]),
        }
    }

    fn active(
        generation: u64,
        ipv4: Option<GtpuSessionEntry>,
        ipv6: Option<GtpuSessionEntry>,
    ) -> GtpuSessionGroupRecord {
        GtpuSessionGroupRecord::active(
            group_id(),
            device_id(),
            self::generation(generation),
            ipv4,
            ipv6,
        )
        .unwrap()
    }

    fn candidate(generation: u64, entry: GtpuSessionEntry) -> GtpuSessionIndexCandidate {
        GtpuSessionIndexCandidate::new(self::generation(generation), entry.inner_family().slot())
            .unwrap()
    }

    #[test]
    fn crossed_family_entries_round_trip_without_address_aliasing() {
        for entry in [v4_entry(), v6_entry()] {
            let encoded = entry.encode();
            assert_eq!(GtpuSessionEntry::decode(&encoded), Some(entry));
            assert_eq!(encoded.len(), GTPU_SESSION_ENTRY_LEN);
        }
        assert_eq!(v4_entry().inner_family(), GtpuSessionIpFamily::Ipv4);
        assert_eq!(v4_entry().outer_family(), GtpuSessionIpFamily::Ipv6);
        assert_eq!(v6_entry().inner_family(), GtpuSessionIpFamily::Ipv6);
        assert_eq!(v6_entry().outer_family(), GtpuSessionIpFamily::Ipv4);
    }

    #[test]
    fn local_outer_endpoint_cannot_alias_inner_paa_identity() {
        assert!(GtpuSessionEntry::new(
            GtpuSessionPaa::new(GtpuEndpointAddress::Ipv4([10, 23, 0, 2])).unwrap(),
            GtpuEndpointAddress::Ipv4([10, 23, 0, 3]),
            GtpuEndpointAddress::Ipv4([10, 23, 0, 2]),
            1_u32.to_be_bytes(),
            2_u32.to_be_bytes(),
            [0; 4],
            None,
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
        )
        .is_none());
        assert!(GtpuSessionEntry::new(
            GtpuSessionPaa::new(GtpuEndpointAddress::Ipv6([
                0x20, 1, 0x0d, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]))
            .unwrap(),
            GtpuEndpointAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,]),
            GtpuEndpointAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,]),
            1_u32.to_be_bytes(),
            2_u32.to_be_bytes(),
            [0; 4],
            None,
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
        )
        .is_none());
    }

    #[test]
    fn ipv6_paa_normalizes_full_addresses_to_fixed_64_bit_identity() {
        let entry = v6_entry();
        let first = inner_packet(entry, 2);
        let same_prefix = inner_packet(entry, 0xfe);
        let mut adjacent = match same_prefix {
            GtpuEndpointAddress::Ipv6(value) => value,
            GtpuEndpointAddress::Ipv4(_) => unreachable!(),
        };
        adjacent[7] ^= 1;
        let adjacent = GtpuEndpointAddress::Ipv6(adjacent);
        assert!(entry.inner_paa().contains(first));
        assert!(entry.inner_paa().contains(same_prefix));
        assert!(!entry.inner_paa().contains(adjacent));
        let canonical = match entry.inner_paa().canonical_address() {
            GtpuEndpointAddress::Ipv6(value) => value,
            GtpuEndpointAddress::Ipv4(_) => unreachable!(),
        };
        assert_eq!(&canonical[8..], &[0; 8]);
        assert_eq!(
            GtpuSessionPaa::from_full_paa(first)
                .unwrap()
                .canonical_address(),
            GtpuSessionPaa::from_full_paa(same_prefix)
                .unwrap()
                .canonical_address()
        );
        assert_eq!(
            GtpuSessionUplinkKey::from_packet_address(first, entry.bearer_mark()),
            GtpuSessionUplinkKey::from_packet_address(same_prefix, entry.bearer_mark())
        );
        assert_ne!(
            GtpuSessionUplinkKey::from_packet_address(first, entry.bearer_mark()),
            GtpuSessionUplinkKey::from_packet_address(adjacent, entry.bearer_mark())
        );
    }

    #[test]
    fn public_identities_are_checked_and_redacted() {
        assert_eq!(GtpuSessionGroupId::new([0; 16]), None);
        assert_eq!(GtpuSessionDeviceId::new([0; 16]), None);
        assert_eq!(GtpuSessionTransactionId::new([0; 16]), None);
        let rendered = std::format!(
            "{:?} {} {:?} {} {:?} {}",
            group_id(),
            group_id(),
            device_id(),
            device_id(),
            transaction_id(),
            transaction_id()
        );
        assert!(!rendered.contains("44"));
        assert!(!rendered.contains("55"));
        assert!(!rendered.contains("66"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn group_record_is_one_device_bound_atomic_authority_for_both_families() {
        let record = active(7, Some(v4_entry()), Some(v6_entry()));
        let encoded = record.encode();
        assert_eq!(GtpuSessionGroupRecord::decode(&encoded), Some(record));
        assert_eq!(record.family_mask(), 3);
        assert_eq!(record.device_id(), device_id());
        assert_eq!(record.generation(), generation(7));

        for entry in [v4_entry(), v6_entry()] {
            let reference = GtpuSessionGroupRef::single(group_id(), candidate(7, entry));
            let key = GtpuSessionUplinkKey::from_entry(entry);
            assert!(gtpu_session_group_authorizes_uplink(
                &encoded,
                reference,
                key,
                device_config(),
                42,
            )
            .is_some());
        }
        let pending = active(1, Some(v4_entry()), None)
            .with_phase(GtpuSessionGroupPhase::Pending)
            .unwrap()
            .encode();
        let reference = GtpuSessionGroupRef::single(group_id(), candidate(1, v4_entry()));
        let key = GtpuSessionUplinkKey::from_entry(v4_entry());
        assert!(gtpu_session_group_authorizes_uplink(
            &pending,
            reference,
            key,
            device_config(),
            42,
        )
        .is_none());
    }

    #[test]
    fn dual_candidate_index_round_trips_and_generation_overflow_fails_closed() {
        let base = candidate(7, v4_entry());
        let desired = candidate(8, v4_entry());
        let staged = GtpuSessionGroupRef::new(group_id(), Some(base), Some(desired)).unwrap();
        assert_eq!(GtpuSessionGroupRef::decode(&staged.encode()), Some(staged));
        assert_eq!(staged.for_generation(generation(7)), Some(base));
        assert_eq!(staged.for_generation(generation(8)), Some(desired));
        assert_eq!(staged.for_generation(generation(9)), None);
        assert!(
            GtpuSessionGroupRef::new(group_id(), Some(base), Some(candidate(9, v4_entry())))
                .is_none()
        );
        let maximum =
            GtpuSessionIndexCandidate::new(generation(u64::MAX), GTPU_SESSION_IPV4_SLOT).unwrap();
        assert!(GtpuSessionGroupRef::new(group_id(), Some(maximum), Some(desired)).is_none());
        let wrong_slot =
            GtpuSessionIndexCandidate::new(generation(8), GTPU_SESSION_IPV6_SLOT).unwrap();
        assert!(GtpuSessionGroupRef::new(group_id(), Some(base), Some(wrong_slot)).is_none());
        let mut malformed = staged.encode();
        malformed[40] = GTPU_SESSION_IPV6_SLOT;
        assert_eq!(GtpuSessionGroupRef::decode(&malformed), None);
    }

    #[test]
    fn same_selector_cutover_interleavings_never_cross_authority_generation() {
        let old_entry = v4_entry();
        let mut new_entry = old_entry;
        new_entry.peer_teid = 0x2000_00ff_u32.to_be_bytes();
        let old = active(7, Some(old_entry), None).encode();
        let new = active(8, Some(new_entry), None).encode();
        let key = GtpuSessionUplinkKey::from_entry(old_entry);
        assert_eq!(key, GtpuSessionUplinkKey::from_entry(new_entry));

        let old_candidate = candidate(7, old_entry);
        let new_candidate = candidate(8, new_entry);
        let indexes = [
            (
                GtpuSessionGroupRef::single(group_id(), old_candidate),
                [true, false],
            ),
            (
                GtpuSessionGroupRef::new(group_id(), Some(old_candidate), Some(new_candidate))
                    .unwrap(),
                [true, true],
            ),
            (
                GtpuSessionGroupRef::new(group_id(), None, Some(new_candidate)).unwrap(),
                [false, true],
            ),
        ];
        for (reference, expected) in indexes {
            for (index, authority) in [old, new].iter().enumerate() {
                assert_eq!(
                    gtpu_session_group_authorizes_uplink(
                        authority,
                        reference,
                        key,
                        device_config(),
                        42,
                    )
                    .is_some(),
                    expected[index],
                );
            }
        }

        let wrong_group = GtpuSessionGroupRef::single(other_group_id(), old_candidate);
        assert!(
            gtpu_session_group_authorizes_uplink(&old, wrong_group, key, device_config(), 42,)
                .is_none()
        );
        let wrong_device = GtpuSessionDeviceId::new([0x77; 16]).unwrap();
        let wrong_config = GtpuSessionDeviceConfig::new(
            wrong_device,
            42,
            Some([192, 0, 2, 1]),
            Some([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        )
        .unwrap();
        let old_reference = GtpuSessionGroupRef::single(group_id(), old_candidate);
        assert!(
            gtpu_session_group_authorizes_uplink(&old, old_reference, key, wrong_config, 42,)
                .is_none()
        );
    }

    #[test]
    fn rekey_staging_keeps_old_and_new_selectors_generation_exact() {
        let old_entry = v4_entry();
        let mut new_entry = old_entry;
        new_entry.inner_paa =
            GtpuSessionPaa::new(GtpuEndpointAddress::Ipv4([10, 23, 0, 3])).unwrap();
        let old = active(12, Some(old_entry), None).encode();
        let new = active(13, Some(new_entry), None).encode();
        let old_key = GtpuSessionUplinkKey::from_entry(old_entry);
        let new_key = GtpuSessionUplinkKey::from_entry(new_entry);
        let old_ref = GtpuSessionGroupRef::single(group_id(), candidate(12, old_entry));
        let new_ref =
            GtpuSessionGroupRef::new(group_id(), None, Some(candidate(13, new_entry))).unwrap();
        for (authority, old_allowed, new_allowed) in [(&old, true, false), (&new, false, true)] {
            assert_eq!(
                gtpu_session_group_authorizes_uplink(
                    authority,
                    old_ref,
                    old_key,
                    device_config(),
                    42,
                )
                .is_some(),
                old_allowed,
            );
            assert_eq!(
                gtpu_session_group_authorizes_uplink(
                    authority,
                    new_ref,
                    new_key,
                    device_config(),
                    42,
                )
                .is_some(),
                new_allowed,
            );
        }
    }

    #[test]
    fn downlink_shared_teid_selects_and_authorizes_the_exact_inner_slot() {
        let mut ipv4 = v4_entry();
        ipv4.peer_outer_address = GtpuEndpointAddress::Ipv4([192, 0, 2, 10]);
        ipv4.local_outer_address = GtpuEndpointAddress::Ipv4([192, 0, 2, 1]);
        let mut ipv6 = v6_entry();
        ipv6.local_teid = ipv4.local_teid;
        let record = active(1, Some(ipv4), Some(ipv6)).encode();
        for entry in [ipv4, ipv6] {
            let key = GtpuSessionDownlinkKey::from_entry(entry);
            let reference = GtpuSessionGroupRef::single(group_id(), candidate(1, entry));
            assert!(gtpu_session_group_authorizes_downlink(
                &record,
                reference,
                key,
                device_config(),
                42,
                entry.peer_outer_address(),
                entry.local_outer_address(),
                21_152,
                inner_packet(entry, 2),
            )
            .is_some());
        }

        let v4_key = GtpuSessionDownlinkKey::from_entry(ipv4);
        let v4_reference = GtpuSessionGroupRef::single(group_id(), candidate(1, ipv4));
        assert!(gtpu_session_group_authorizes_downlink(
            &record,
            v4_reference,
            v4_key,
            device_config(),
            42,
            ipv4.peer_outer_address(),
            ipv4.local_outer_address(),
            21_152,
            inner_packet(ipv6, 2),
        )
        .is_none());
    }

    #[test]
    fn transaction_journal_preserves_exact_base_and_desired_graphs() {
        let base = active(7, Some(v4_entry()), None);
        let desired = active(8, Some(v4_entry()), Some(v6_entry()));
        let update = GtpuSessionTransactionRecord::prepare(
            group_id(),
            transaction_id(),
            Some(base),
            Some(desired),
        )
        .unwrap();
        assert_eq!(
            GtpuSessionTransactionRecord::decode(&update.encode()),
            Some(update)
        );
        assert_eq!(update.target_generation(), generation(8));
        assert_eq!(update.fence_authority(), None);
        assert_eq!(update.desired_authority(), None);
        let staged = update.advance().unwrap();
        assert_eq!(staged.phase(), GtpuSessionTransactionPhase::IndexesStaged);
        assert_eq!(staged.desired_authority(), Some(desired));
        assert_eq!(staged.fence_authority(), None);
        assert_eq!(
            GtpuSessionTransactionRecord::decode(&staged.encode()),
            Some(staged)
        );
        let committed = staged.advance().unwrap();
        assert_eq!(
            committed.phase(),
            GtpuSessionTransactionPhase::AuthorityCommitted
        );
        assert_eq!(committed.advance(), None);
        assert_eq!(committed.desired_authority(), None);
        assert_eq!(committed.fence_authority(), None);
        assert_eq!(
            GtpuSessionTransactionRecord::decode(&committed.encode()),
            Some(committed)
        );

        let create = GtpuSessionTransactionRecord::prepare(
            group_id(),
            transaction_id(),
            None,
            Some(active(1, Some(v4_entry()), None)),
        )
        .unwrap();
        let create_fence = create.fence_authority().unwrap();
        assert_eq!(create_fence.phase(), GtpuSessionGroupPhase::Pending);
        assert_eq!(
            GtpuSessionGroupRecord::decode(&create_fence.encode()),
            Some(create_fence)
        );
        let create_staged = create.advance().unwrap();
        assert_eq!(create_staged.fence_authority(), None);
        assert_eq!(
            create_staged.desired_authority(),
            Some(active(1, Some(v4_entry()), None))
        );

        let remove =
            GtpuSessionTransactionRecord::prepare(group_id(), transaction_id(), Some(base), None)
                .unwrap();
        let fence = remove.fence_authority().unwrap();
        assert_eq!(fence.phase(), GtpuSessionGroupPhase::Removing);
        assert_eq!(fence.generation(), generation(8));
        assert_eq!(GtpuSessionGroupRecord::decode(&fence.encode()), Some(fence));
        assert_eq!(
            remove.advance().unwrap().phase(),
            GtpuSessionTransactionPhase::AuthorityCommitted
        );
        assert_eq!(remove.advance().unwrap().fence_authority(), None);
        assert_eq!(
            GtpuSessionTransactionRecord::decode(&remove.encode()),
            Some(remove)
        );
        assert!(GtpuSessionTransactionRecord::prepare(
            group_id(),
            transaction_id(),
            Some(active(u64::MAX, Some(v4_entry()), None)),
            None,
        )
        .is_none());
    }

    fn independent_v4_entry_bytes() -> [u8; GTPU_SESSION_ENTRY_LEN] {
        let mut raw = [0_u8; GTPU_SESSION_ENTRY_LEN];
        raw[0] = ENTRY_FORMAT_VERSION;
        raw[1] = 4;
        raw[2] = 6;
        raw[4..8].copy_from_slice(&[10, 23, 0, 2]);
        raw[20..36].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        raw[36..52].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        raw[52..56].copy_from_slice(&0x1000_0001_u32.to_be_bytes());
        raw[56..60].copy_from_slice(&0x2000_0001_u32.to_be_bytes());
        raw[64] = 46;
        raw[65] = 1;
        raw[66..68].copy_from_slice(&21_152_u16.to_be_bytes());
        raw[68..70].copy_from_slice(&21_152_u16.to_be_bytes());
        raw[70..72].copy_from_slice(&40_000_u16.to_be_bytes());
        raw
    }

    fn independent_v6_entry_bytes() -> [u8; GTPU_SESSION_ENTRY_LEN] {
        let mut raw = [0_u8; GTPU_SESSION_ENTRY_LEN];
        raw[0] = ENTRY_FORMAT_VERSION;
        raw[1] = 6;
        raw[2] = 4;
        raw[4..12].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x01, 0, 0, 0]);
        raw[20..24].copy_from_slice(&[192, 0, 2, 10]);
        raw[36..40].copy_from_slice(&[192, 0, 2, 1]);
        raw[52..56].copy_from_slice(&0x1000_0002_u32.to_be_bytes());
        raw[56..60].copy_from_slice(&0x2000_0002_u32.to_be_bytes());
        raw[60..64].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        raw[64] = 0xff;
        raw[70..72].copy_from_slice(&2_152_u16.to_be_bytes());
        raw
    }

    fn independent_authority_bytes(
        generation: u64,
        phase: GtpuSessionGroupPhase,
    ) -> [u8; GTPU_SESSION_GROUP_VALUE_LEN] {
        let mut raw = [0_u8; GTPU_SESSION_GROUP_VALUE_LEN];
        raw[0] = GROUP_FORMAT_VERSION;
        raw[1] = phase as u8;
        raw[2] = 1;
        raw[4..12].copy_from_slice(&generation.to_be_bytes());
        raw[16..32].fill(0x55);
        raw[32..48].fill(0x44);
        raw[48..48 + GTPU_SESSION_ENTRY_LEN].copy_from_slice(&independent_v4_entry_bytes());
        raw
    }

    fn independent_v6_authority_bytes(generation: u64) -> [u8; GTPU_SESSION_GROUP_VALUE_LEN] {
        let mut raw = [0_u8; GTPU_SESSION_GROUP_VALUE_LEN];
        raw[0] = GROUP_FORMAT_VERSION;
        raw[1] = GtpuSessionGroupPhase::Active as u8;
        raw[2] = 2;
        raw[4..12].copy_from_slice(&generation.to_be_bytes());
        raw[16..32].fill(0x55);
        raw[32..48].fill(0x44);
        let ipv6_slot = GROUP_HEADER_LEN + GTPU_SESSION_ENTRY_LEN;
        raw[ipv6_slot..ipv6_slot + GTPU_SESSION_ENTRY_LEN]
            .copy_from_slice(&independent_v6_entry_bytes());
        raw
    }

    #[test]
    fn independent_exact_bytes_pin_every_new_map_abi() {
        let entry_raw = independent_v4_entry_bytes();
        assert_eq!(v4_entry().encode(), entry_raw);
        assert_eq!(GtpuSessionEntry::decode(&entry_raw), Some(v4_entry()));

        let ipv6_entry_raw = independent_v6_entry_bytes();
        assert_eq!(v6_entry().encode(), ipv6_entry_raw);
        assert_eq!(GtpuSessionEntry::decode(&ipv6_entry_raw), Some(v6_entry()));

        let mut uplink_raw = [0_u8; GTPU_SESSION_UPLINK_KEY_LEN];
        uplink_raw[0] = 4;
        uplink_raw[4..8].copy_from_slice(&[10, 23, 0, 2]);
        assert_eq!(
            GtpuSessionUplinkKey::from_entry(v4_entry()).encode(),
            uplink_raw
        );
        assert_eq!(
            GtpuSessionUplinkKey::decode(&uplink_raw),
            Some(GtpuSessionUplinkKey::from_entry(v4_entry()))
        );

        let mut ipv6_uplink_raw = [0_u8; GTPU_SESSION_UPLINK_KEY_LEN];
        ipv6_uplink_raw[0] = 6;
        ipv6_uplink_raw[4..12].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x01, 0, 0, 0]);
        ipv6_uplink_raw[20..24].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        assert_eq!(
            GtpuSessionUplinkKey::from_entry(v6_entry()).encode(),
            ipv6_uplink_raw
        );
        assert_eq!(
            GtpuSessionUplinkKey::decode(&ipv6_uplink_raw),
            Some(GtpuSessionUplinkKey::from_entry(v6_entry()))
        );

        let mut downlink_raw = [0_u8; GTPU_SESSION_DOWNLINK_KEY_LEN];
        downlink_raw[0] = 6;
        downlink_raw[1] = 4;
        downlink_raw[4..8].copy_from_slice(&0x1000_0001_u32.to_be_bytes());
        assert_eq!(
            GtpuSessionDownlinkKey::from_entry(v4_entry()).encode(),
            downlink_raw
        );
        assert_eq!(
            GtpuSessionDownlinkKey::decode(&downlink_raw),
            Some(GtpuSessionDownlinkKey::from_entry(v4_entry()))
        );

        let mut ipv6_downlink_raw = [0_u8; GTPU_SESSION_DOWNLINK_KEY_LEN];
        ipv6_downlink_raw[0] = 4;
        ipv6_downlink_raw[1] = 6;
        ipv6_downlink_raw[4..8].copy_from_slice(&0x1000_0002_u32.to_be_bytes());
        assert_eq!(
            GtpuSessionDownlinkKey::from_entry(v6_entry()).encode(),
            ipv6_downlink_raw
        );
        assert_eq!(
            GtpuSessionDownlinkKey::decode(&ipv6_downlink_raw),
            Some(GtpuSessionDownlinkKey::from_entry(v6_entry()))
        );

        let mut reference_raw = [0_u8; GTPU_SESSION_GROUP_REF_LEN];
        reference_raw[..16].fill(0x44);
        reference_raw[16..24].copy_from_slice(&7_u64.to_be_bytes());
        reference_raw[24] = GTPU_SESSION_IPV4_SLOT;
        reference_raw[32..40].copy_from_slice(&8_u64.to_be_bytes());
        reference_raw[40] = GTPU_SESSION_IPV4_SLOT;
        let reference = GtpuSessionGroupRef::new(
            group_id(),
            Some(candidate(7, v4_entry())),
            Some(candidate(8, v4_entry())),
        )
        .unwrap();
        assert_eq!(reference.encode(), reference_raw);
        assert_eq!(GtpuSessionGroupRef::decode(&reference_raw), Some(reference));

        let mut ipv6_reference_raw = [0_u8; GTPU_SESSION_GROUP_REF_LEN];
        ipv6_reference_raw[..16].fill(0x44);
        ipv6_reference_raw[16..24].copy_from_slice(&9_u64.to_be_bytes());
        ipv6_reference_raw[24] = GTPU_SESSION_IPV6_SLOT;
        let ipv6_reference = GtpuSessionGroupRef::single(group_id(), candidate(9, v6_entry()));
        assert_eq!(ipv6_reference.encode(), ipv6_reference_raw);
        assert_eq!(
            GtpuSessionGroupRef::decode(&ipv6_reference_raw),
            Some(ipv6_reference)
        );

        let authority_raw = independent_authority_bytes(7, GtpuSessionGroupPhase::Active);
        let authority = active(7, Some(v4_entry()), None);
        assert_eq!(authority.encode(), authority_raw);
        assert_eq!(
            GtpuSessionGroupRecord::decode(&authority_raw),
            Some(authority)
        );

        let ipv6_authority_raw = independent_v6_authority_bytes(9);
        let ipv6_authority = active(9, None, Some(v6_entry()));
        assert_eq!(ipv6_authority.encode(), ipv6_authority_raw);
        assert_eq!(
            GtpuSessionGroupRecord::decode(&ipv6_authority_raw),
            Some(ipv6_authority)
        );
        assert!(
            ipv6_authority_raw[GROUP_HEADER_LEN..GROUP_HEADER_LEN + GTPU_SESSION_ENTRY_LEN]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            &ipv6_authority_raw
                [GROUP_HEADER_LEN + GTPU_SESSION_ENTRY_LEN..GTPU_SESSION_GROUP_VALUE_LEN],
            &ipv6_entry_raw
        );

        let mut config_raw = [0_u8; GTPU_SESSION_CONFIG_VALUE_LEN];
        config_raw[0] = CONFIG_FORMAT_VERSION;
        config_raw[1] = 3;
        config_raw[4..8].copy_from_slice(&42_u32.to_be_bytes());
        config_raw[8..24].fill(0x55);
        config_raw[24..28].copy_from_slice(&[192, 0, 2, 1]);
        config_raw[40..56]
            .copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(device_config().encode(), config_raw);
        assert_eq!(
            GtpuSessionDeviceConfig::decode(&config_raw),
            Some(device_config())
        );

        let desired = active(1, Some(v4_entry()), None);
        let create = GtpuSessionTransactionRecord::prepare(
            group_id(),
            transaction_id(),
            None,
            Some(desired),
        )
        .unwrap();
        let mut journal_raw = [0_u8; GTPU_SESSION_TRANSACTION_VALUE_LEN];
        journal_raw[0] = TRANSACTION_FORMAT_VERSION;
        journal_raw[1] = GtpuSessionTransactionPhase::Prepared as u8;
        journal_raw[2] = 2;
        journal_raw[8..24].fill(0x44);
        journal_raw[24..40].fill(0x66);
        journal_raw[40..48].copy_from_slice(&1_u64.to_be_bytes());
        let desired_offset = TRANSACTION_HEADER_LEN + GTPU_SESSION_GROUP_VALUE_LEN;
        journal_raw[desired_offset..desired_offset + GTPU_SESSION_GROUP_VALUE_LEN].copy_from_slice(
            &independent_authority_bytes(1, GtpuSessionGroupPhase::Active),
        );
        assert_eq!(create.encode(), journal_raw);
        assert_eq!(
            GtpuSessionTransactionRecord::decode(&journal_raw),
            Some(create)
        );
    }

    #[test]
    fn every_new_wire_type_rejects_noncanonical_control_bytes() {
        let entry = independent_v4_entry_bytes();
        for (offset, replacement) in [(0, 2), (1, 5), (3, 1), (72, 1)] {
            let mut malformed = entry;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionEntry::decode(&malformed), None);
        }

        let uplink = GtpuSessionUplinkKey::from_entry(v4_entry()).encode();
        for (offset, replacement) in [(0, 5), (1, 1)] {
            let mut malformed = uplink;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionUplinkKey::decode(&malformed), None);
        }
        let downlink = GtpuSessionDownlinkKey::from_entry(v4_entry()).encode();
        for (offset, replacement) in [(0, 5), (1, 5), (2, 1)] {
            let mut malformed = downlink;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionDownlinkKey::decode(&malformed), None);
        }

        let reference = GtpuSessionGroupRef::single(group_id(), candidate(1, v4_entry())).encode();
        for offset in [25_usize, 41] {
            let mut malformed = reference;
            malformed[offset] = 1;
            assert_eq!(GtpuSessionGroupRef::decode(&malformed), None);
        }

        let authority = independent_authority_bytes(1, GtpuSessionGroupPhase::Active);
        for (offset, replacement) in [(0, 2), (1, 0), (2, 0), (3, 1), (12, 1), (49, 5)] {
            let mut malformed = authority;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionGroupRecord::decode(&malformed), None);
        }
        let mut impossible_pending = independent_authority_bytes(2, GtpuSessionGroupPhase::Pending);
        assert_eq!(GtpuSessionGroupRecord::decode(&impossible_pending), None);
        impossible_pending = independent_authority_bytes(1, GtpuSessionGroupPhase::Removing);
        assert_eq!(GtpuSessionGroupRecord::decode(&impossible_pending), None);

        let config = device_config().encode();
        for (offset, replacement) in [(0, 2), (1, 0), (2, 1), (56, 1)] {
            let mut malformed = config;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionDeviceConfig::decode(&malformed), None);
        }

        let journal = GtpuSessionTransactionRecord::prepare(
            group_id(),
            transaction_id(),
            None,
            Some(active(1, Some(v4_entry()), None)),
        )
        .unwrap()
        .encode();
        for (offset, replacement) in [(0, 2), (1, 0), (2, 0), (3, 1)] {
            let mut malformed = journal;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionTransactionRecord::decode(&malformed), None);
        }
    }

    #[test]
    fn malformed_reserved_family_and_phase_bytes_fail_closed() {
        let canonical = active(1, Some(v4_entry()), None).encode();
        for (offset, replacement) in [(0, 2), (1, 0), (2, 0), (3, 1), (12, 1)] {
            let mut malformed = canonical;
            malformed[offset] = replacement;
            assert_eq!(GtpuSessionGroupRecord::decode(&malformed), None);
        }
        let mut malformed_entry = canonical;
        malformed_entry[GROUP_HEADER_LEN + 2] = 5;
        assert_eq!(GtpuSessionGroupRecord::decode(&malformed_entry), None);
    }

    #[test]
    fn every_grouped_debug_surface_redacts_routing_values() {
        let entry = v4_entry();
        let key = GtpuSessionUplinkKey::from_entry(entry);
        let downlink = GtpuSessionDownlinkKey::from_entry(entry);
        let reference = GtpuSessionGroupRef::single(group_id(), candidate(1, entry));
        let journal = GtpuSessionTransactionRecord::prepare(
            group_id(),
            transaction_id(),
            None,
            Some(active(1, Some(entry), None)),
        )
        .unwrap();
        let rendered = std::format!("{entry:?} {key:?} {downlink:?} {reference:?} {journal:?}");
        for forbidden in ["10, 23", "192", "40000", "16909060", "1145324612"] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
