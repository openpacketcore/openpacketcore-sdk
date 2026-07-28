//! Shared map ABI and packet-decision rules for the lease-bound egress fence.
//!
//! This dependency-free `no_std` crate is the single source of truth for map
//! byte layouts used by the userspace loader and tc/eBPF classifier. Values
//! use explicit little-endian integer encoding because the committed object
//! targets `bpfel-unknown-none`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

mod packet;

pub use packet::{classify_ethernet_udp_source, PacketEndpointDisposition};

/// ABI version encoded into every configuration and control command.
pub const EGRESS_FENCE_ABI_VERSION: u16 = 2;
/// Maximum cookie entries in the non-LRU kernel hash map.
pub const EGRESS_FENCE_MAX_COOKIE_ENTRIES: u32 = 4_096;
/// Frozen tc classifier program name.
pub const EGRESS_FENCE_PROGRAM_NAME: &str = "opc_egress_fence";
/// Frozen cookie map name.
pub const EGRESS_FENCE_COOKIE_MAP_NAME: &str = "OPC_EGRESS_COOKIES";
/// Frozen configuration map name.
pub const EGRESS_FENCE_CONFIG_MAP_NAME: &str = "OPC_EGRESS_CONFIG";
/// Frozen per-CPU counter map name.
pub const EGRESS_FENCE_COUNTER_MAP_NAME: &str = "OPC_EGRESS_COUNTERS";
/// Frozen monotonic-current-fence map name.
pub const EGRESS_FENCE_CURRENT_MAP_NAME: &str = "OPC_EGRESS_CURRENT";
/// Frozen control-program name used through `BPF_PROG_TEST_RUN`.
pub const EGRESS_FENCE_CONTROL_PROGRAM_NAME: &str = "opc_egress_control";
/// Encoded configuration value width.
pub const EGRESS_FENCE_CONFIG_VALUE_LEN: usize = 56;
/// Encoded cookie entry width.
pub const EGRESS_FENCE_COOKIE_VALUE_LEN: usize = 32;
/// Encoded monotonic-current-token value width.
pub const EGRESS_FENCE_CURRENT_VALUE_LEN: usize = 16;
/// Encoded control command width.
pub const EGRESS_FENCE_CONTROL_COMMAND_LEN: usize = 64;

/// Counter slot for packets admitted by a live cookie deadline.
pub const COUNTER_ALLOWED: u32 = 0;
/// Counter slot for protected-endpoint packets missing the dedicated mark.
pub const COUNTER_UNMARKED: u32 = 1;
/// Counter slot for marked packets whose socket cookie is zero.
pub const COUNTER_COOKIE_ZERO: u32 = 2;
/// Counter slot for protected packets without a registered cookie.
pub const COUNTER_COOKIE_MISSING: u32 = 3;
/// Counter slot for a canonical closed cookie.
pub const COUNTER_CLOSED: u32 = 4;
/// Counter slot for an expired cookie.
pub const COUNTER_EXPIRED: u32 = 5;
/// Counter slot for malformed configuration or cookie state.
pub const COUNTER_MALFORMED: u32 = 6;
/// Counter slot for a cookie carrying a superseded durable fence token.
pub const COUNTER_STALE_TOKEN: u32 = 7;
/// Number of per-CPU counter slots.
pub const EGRESS_FENCE_COUNTER_SLOTS: u32 = 8;

const CONFIG_MAGIC: [u8; 4] = *b"OEF1";
const FAMILY_IPV4: u8 = 4;
const FAMILY_IPV6: u8 = 6;
/// Cookie-map control word for a newly registered fail-closed entry.
pub const COOKIE_CONTROL_INITIAL_CLOSED: u32 = 0x4f45_0101;
/// Cookie-map control word for an active entry.
pub const COOKIE_CONTROL_ACTIVE: u32 = 0x4f45_0102;
/// Cookie-map control word for a non-reopenable terminal tombstone.
pub const COOKIE_CONTROL_TERMINAL_CLOSED: u32 = 0x4f45_0103;
/// Internal cookie-map control word used while atomically reclaiming an entry.
pub const COOKIE_CONTROL_RECLAIMING: u32 = 0x4f45_01ff;
/// Current-token map control word.
pub const CURRENT_TOKEN_CONTROL: u32 = 0x4f45_0201;
/// Initial per-cookie control epoch.
pub const EGRESS_FENCE_INITIAL_COOKIE_EPOCH: u64 = 1;
const CONTROL_MAGIC: [u8; 4] = *b"OEC1";

/// Successful control-program result.
pub const CONTROL_RESULT_APPLIED: u32 = 0;
/// Control command or map state was malformed.
pub const CONTROL_RESULT_INVALID: u32 = 1;
/// Command carried a token older than the kernel's current token.
pub const CONTROL_RESULT_STALE_TOKEN: u32 = 2;
/// Registered cookie was missing.
pub const CONTROL_RESULT_COOKIE_MISSING: u32 = 3;
/// Per-cookie operation epoch did not match.
pub const CONTROL_RESULT_EPOCH_MISMATCH: u32 = 4;
/// Terminal state forbids the requested transition.
pub const CONTROL_RESULT_TERMINAL: u32 = 5;
/// Requested deadline was already elapsed.
pub const CONTROL_RESULT_DEADLINE_ELAPSED: u32 = 6;
/// Requested transition was not valid for the entry's lifecycle state.
pub const CONTROL_RESULT_STATE_MISMATCH: u32 = 7;
/// Kernel map mutation failed.
pub const CONTROL_RESULT_MAP_ERROR: u32 = 8;
/// Entry was not safely reclaimable.
pub const CONTROL_RESULT_NOT_RECLAIMABLE: u32 = 9;

/// One centrally allocated packet-mark bit owned by a fence attachment.
///
/// There is deliberately no SDK-global bit choice: products can have XFRM,
/// routing, or dataplane mark domains at any position. Product admission must
/// select one bit disjoint from every other owner and persist that choice in
/// [`FenceConfig`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceMark {
    bit: u32,
}

impl FenceMark {
    /// Construct an exact single-bit mark domain.
    #[must_use]
    pub const fn new(bit: u32) -> Option<Self> {
        if bit.count_ones() == 1 {
            Some(Self { bit })
        } else {
            None
        }
    }

    /// Owned mark mask and required value.
    #[must_use]
    pub const fn bit(self) -> u32 {
        self.bit
    }

    /// Whether this mark is present on a packet.
    #[must_use]
    pub const fn is_present(self, packet_mark: u32) -> bool {
        packet_mark & self.bit == self.bit
    }

    /// Clear only this fence-owned bit.
    #[must_use]
    pub const fn clear(self, packet_mark: u32) -> u32 {
        packet_mark & !self.bit
    }

    /// Whether another mark mask overlaps this owned bit.
    #[must_use]
    pub const fn overlaps(self, other_mask: u32) -> bool {
        self.bit & other_mask != 0
    }
}

impl fmt::Debug for FenceMark {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FenceMark(<redacted>)")
    }
}

/// Exact local UDP source endpoint protected by one fence attachment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProtectedEndpoint {
    /// IPv4 address and nonzero UDP source port.
    Ipv4 {
        /// Network-order address octets.
        address: [u8; 4],
        /// UDP source port.
        port: u16,
    },
    /// IPv6 address and nonzero UDP source port.
    Ipv6 {
        /// Network-order address octets.
        address: [u8; 16],
        /// UDP source port.
        port: u16,
    },
}

impl ProtectedEndpoint {
    /// Construct an IPv4 endpoint when the address and port are usable.
    #[must_use]
    pub const fn ipv4(address: [u8; 4], port: u16) -> Option<Self> {
        if port == 0
            || address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0
            || address[0] >= 224
        {
            None
        } else {
            Some(Self::Ipv4 { address, port })
        }
    }

    /// Construct an IPv6 endpoint when the address and port are usable.
    #[must_use]
    pub const fn ipv6(address: [u8; 16], port: u16) -> Option<Self> {
        let mut nonzero = false;
        let mut index = 0;
        while index < address.len() {
            nonzero |= address[index] != 0;
            index += 1;
        }
        if port == 0 || !nonzero || address[0] == 0xff {
            None
        } else {
            Some(Self::Ipv6 { address, port })
        }
    }

    /// Return the UDP source port without exposing the address through
    /// formatting implementations.
    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::Ipv4 { port, .. } | Self::Ipv6 { port, .. } => port,
        }
    }

    /// Return whether this endpoint exactly matches the supplied IPv4 source.
    #[must_use]
    pub const fn matches_ipv4(self, address: [u8; 4], port: u16) -> bool {
        match self {
            Self::Ipv4 {
                address: expected,
                port: expected_port,
            } => {
                expected[0] == address[0]
                    && expected[1] == address[1]
                    && expected[2] == address[2]
                    && expected[3] == address[3]
                    && expected_port == port
            }
            Self::Ipv6 { .. } => false,
        }
    }

    /// Return whether this endpoint exactly matches the supplied IPv6 source.
    #[must_use]
    pub const fn matches_ipv6(self, address: [u8; 16], port: u16) -> bool {
        match self {
            Self::Ipv6 {
                address: expected,
                port: expected_port,
            } => {
                let mut matches = expected_port == port;
                let mut index = 0;
                while index < address.len() {
                    matches &= expected[index] == address[index];
                    index += 1;
                }
                matches
            }
            Self::Ipv4 { .. } => false,
        }
    }
}

impl fmt::Debug for ProtectedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedEndpoint")
            .field("address", &"<redacted>")
            .field("port_present", &true)
            .finish()
    }
}

/// Canonical attachment configuration shared with the tc classifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceConfig {
    endpoint: ProtectedEndpoint,
    mark: FenceMark,
    ifindex: u32,
    netns_cookie: u64,
    capacity: u32,
}

impl FenceConfig {
    /// Construct a canonical configuration.
    #[must_use]
    pub const fn new(
        endpoint: ProtectedEndpoint,
        mark: FenceMark,
        ifindex: u32,
        netns_cookie: u64,
        capacity: u32,
    ) -> Option<Self> {
        if ifindex == 0
            || netns_cookie == 0
            || capacity == 0
            || capacity > EGRESS_FENCE_MAX_COOKIE_ENTRIES
        {
            None
        } else {
            Some(Self {
                endpoint,
                mark,
                ifindex,
                netns_cookie,
                capacity,
            })
        }
    }

    /// Protected local endpoint.
    #[must_use]
    pub const fn endpoint(self) -> ProtectedEndpoint {
        self.endpoint
    }

    /// Centrally allocated single-bit mark domain.
    #[must_use]
    pub const fn mark(self) -> FenceMark {
        self.mark
    }

    /// Exact attach-interface index.
    #[must_use]
    pub const fn ifindex(self) -> u32 {
        self.ifindex
    }

    /// Kernel network-namespace cookie owning this attachment.
    #[must_use]
    pub const fn netns_cookie(self) -> u64 {
        self.netns_cookie
    }

    /// Product admission bound within the fixed kernel-map capacity.
    #[must_use]
    pub const fn capacity(self) -> u32 {
        self.capacity
    }

    /// Encode this configuration for the pinned array map.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_CONFIG_VALUE_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_CONFIG_VALUE_LEN];
        encoded[0] = CONFIG_MAGIC[0];
        encoded[1] = CONFIG_MAGIC[1];
        encoded[2] = CONFIG_MAGIC[2];
        encoded[3] = CONFIG_MAGIC[3];
        let version = EGRESS_FENCE_ABI_VERSION.to_le_bytes();
        encoded[4] = version[0];
        encoded[5] = version[1];
        let mark_value = self.mark.bit().to_le_bytes();
        let mark_mask = self.mark.bit().to_le_bytes();
        encoded[8] = mark_value[0];
        encoded[9] = mark_value[1];
        encoded[10] = mark_value[2];
        encoded[11] = mark_value[3];
        encoded[12] = mark_mask[0];
        encoded[13] = mark_mask[1];
        encoded[14] = mark_mask[2];
        encoded[15] = mark_mask[3];
        let port = self.endpoint.port().to_be_bytes();
        encoded[16] = port[0];
        encoded[17] = port[1];
        let ifindex = self.ifindex.to_le_bytes();
        encoded[20] = ifindex[0];
        encoded[21] = ifindex[1];
        encoded[22] = ifindex[2];
        encoded[23] = ifindex[3];
        let netns_cookie = self.netns_cookie.to_le_bytes();
        let mut identity_index = 0;
        while identity_index < netns_cookie.len() {
            encoded[24 + identity_index] = netns_cookie[identity_index];
            identity_index += 1;
        }
        let capacity = self.capacity.to_le_bytes();
        encoded[48] = capacity[0];
        encoded[49] = capacity[1];
        encoded[50] = capacity[2];
        encoded[51] = capacity[3];
        match self.endpoint {
            ProtectedEndpoint::Ipv4 { address, .. } => {
                encoded[6] = FAMILY_IPV4;
                encoded[32] = address[0];
                encoded[33] = address[1];
                encoded[34] = address[2];
                encoded[35] = address[3];
            }
            ProtectedEndpoint::Ipv6 { address, .. } => {
                encoded[6] = FAMILY_IPV6;
                let mut index = 0;
                while index < address.len() {
                    encoded[32 + index] = address[index];
                    index += 1;
                }
            }
        }
        encoded
    }

    /// Decode an exact canonical map value.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_CONFIG_VALUE_LEN]) -> Option<Self> {
        if encoded[0] != CONFIG_MAGIC[0]
            || encoded[1] != CONFIG_MAGIC[1]
            || encoded[2] != CONFIG_MAGIC[2]
            || encoded[3] != CONFIG_MAGIC[3]
            || u16::from_le_bytes([encoded[4], encoded[5]]) != EGRESS_FENCE_ABI_VERSION
            || encoded[7] != 0
            || encoded[18] != 0
            || encoded[19] != 0
            || encoded[52] != 0
            || encoded[53] != 0
            || encoded[54] != 0
            || encoded[55] != 0
        {
            return None;
        }
        let port = u16::from_be_bytes([encoded[16], encoded[17]]);
        let mark_value = u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
        let mark_mask = u32::from_le_bytes([encoded[12], encoded[13], encoded[14], encoded[15]]);
        if mark_value != mark_mask {
            return None;
        }
        let mark = match FenceMark::new(mark_mask) {
            Some(mark) => mark,
            None => return None,
        };
        let ifindex = u32::from_le_bytes([encoded[20], encoded[21], encoded[22], encoded[23]]);
        let netns_cookie = u64::from_le_bytes([
            encoded[24],
            encoded[25],
            encoded[26],
            encoded[27],
            encoded[28],
            encoded[29],
            encoded[30],
            encoded[31],
        ]);
        let capacity = u32::from_le_bytes([encoded[48], encoded[49], encoded[50], encoded[51]]);
        let endpoint = if encoded[6] == FAMILY_IPV4 {
            let mut reserved = 36;
            while reserved < 48 {
                if encoded[reserved] != 0 {
                    return None;
                }
                reserved += 1;
            }
            match ProtectedEndpoint::ipv4(
                [encoded[32], encoded[33], encoded[34], encoded[35]],
                port,
            ) {
                Some(endpoint) => endpoint,
                None => return None,
            }
        } else if encoded[6] == FAMILY_IPV6 {
            let mut address = [0_u8; 16];
            let mut index = 0;
            while index < address.len() {
                address[index] = encoded[32 + index];
                index += 1;
            }
            match ProtectedEndpoint::ipv6(address, port) {
                Some(endpoint) => endpoint,
                None => return None,
            }
        } else {
            return None;
        };
        Self::new(endpoint, mark, ifindex, netns_cookie, capacity)
    }
}

impl fmt::Debug for FenceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceConfig")
            .field("endpoint", &self.endpoint)
            .field("mark", &self.mark)
            .field("attachment_identity", &"<redacted>")
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// Canonical value for the attachment's kernel-monotonic durable token.
///
/// The first four encoded bytes are reserved for `bpf_spin_lock` and read as
/// zero through `BPF_F_LOCK`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CurrentFenceToken {
    durable_fence_token: u64,
}

impl CurrentFenceToken {
    /// Construct the initial closed token state.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            durable_fence_token: 0,
        }
    }

    /// Construct a published nonzero token.
    #[must_use]
    pub const fn published(durable_fence_token: u64) -> Option<Self> {
        if durable_fence_token == 0 {
            None
        } else {
            Some(Self {
                durable_fence_token,
            })
        }
    }

    /// Current durable token, or zero before the first publication.
    #[must_use]
    pub const fn durable_fence_token(self) -> u64 {
        self.durable_fence_token
    }

    /// Encode for the single-slot pinned array map.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_CURRENT_VALUE_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_CURRENT_VALUE_LEN];
        let control = CURRENT_TOKEN_CONTROL.to_le_bytes();
        encoded[4] = control[0];
        encoded[5] = control[1];
        encoded[6] = control[2];
        encoded[7] = control[3];
        let token = self.durable_fence_token.to_le_bytes();
        let mut index = 0;
        while index < token.len() {
            encoded[8 + index] = token[index];
            index += 1;
        }
        encoded
    }

    /// Decode an exact value read with `BPF_F_LOCK`.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_CURRENT_VALUE_LEN]) -> Option<Self> {
        if encoded[0] != 0
            || encoded[1] != 0
            || encoded[2] != 0
            || encoded[3] != 0
            || u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]])
                != CURRENT_TOKEN_CONTROL
        {
            return None;
        }
        Some(Self {
            durable_fence_token: u64::from_le_bytes([
                encoded[8],
                encoded[9],
                encoded[10],
                encoded[11],
                encoded[12],
                encoded[13],
                encoded[14],
                encoded[15],
            ]),
        })
    }
}

impl fmt::Debug for CurrentFenceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentFenceToken")
            .field(
                "durable_fence_token_present",
                &(self.durable_fence_token != 0),
            )
            .finish()
    }
}

/// Atomic transition requested from the frozen kernel control program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlOperation {
    /// Advance the attachment's current durable token monotonically.
    PublishToken = 1,
    /// Open a newly registered cookie.
    Activate = 2,
    /// Extend an already active cookie under the same durable token.
    Refresh = 3,
    /// Irreversibly close a cookie.
    Close = 4,
    /// Reclaim a proven closed, expired, or superseded cookie entry.
    Reclaim = 5,
}

impl ControlOperation {
    const fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PublishToken),
            2 => Some(Self::Activate),
            3 => Some(Self::Refresh),
            4 => Some(Self::Close),
            5 => Some(Self::Reclaim),
            _ => None,
        }
    }
}

/// Value-free command sent to the unattached tc control program.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ControlCommand {
    operation: ControlOperation,
    ifindex: u32,
    netns_cookie: u64,
    socket_cookie: u64,
    durable_fence_token: u64,
    deadline_boot_ns: u64,
    expected_epoch: u64,
}

impl ControlCommand {
    /// Construct a command bound to one exact attachment identity.
    #[must_use]
    pub const fn new(
        operation: ControlOperation,
        ifindex: u32,
        netns_cookie: u64,
        socket_cookie: u64,
        durable_fence_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Option<Self> {
        let fields_are_canonical = match operation {
            ControlOperation::PublishToken => {
                socket_cookie == 0
                    && durable_fence_token != 0
                    && deadline_boot_ns == 0
                    && expected_epoch == 0
            }
            ControlOperation::Activate | ControlOperation::Refresh => {
                socket_cookie != 0
                    && durable_fence_token != 0
                    && deadline_boot_ns != 0
                    && expected_epoch != 0
            }
            ControlOperation::Close => {
                socket_cookie != 0 && deadline_boot_ns == 0 && expected_epoch != 0
            }
            ControlOperation::Reclaim => {
                socket_cookie != 0 && deadline_boot_ns == 0 && expected_epoch != 0
            }
        };
        if ifindex == 0 || netns_cookie == 0 || !fields_are_canonical {
            None
        } else {
            Some(Self {
                operation,
                ifindex,
                netns_cookie,
                socket_cookie,
                durable_fence_token,
                deadline_boot_ns,
                expected_epoch,
            })
        }
    }

    /// Requested transition.
    #[must_use]
    pub const fn operation(self) -> ControlOperation {
        self.operation
    }

    /// Expected attachment interface index.
    #[must_use]
    pub const fn ifindex(self) -> u32 {
        self.ifindex
    }

    /// Expected attachment network-namespace cookie.
    #[must_use]
    pub const fn netns_cookie(self) -> u64 {
        self.netns_cookie
    }

    /// Full-width socket cookie, zero only for token publication.
    #[must_use]
    pub const fn socket_cookie(self) -> u64 {
        self.socket_cookie
    }

    /// Durable per-resource fencing token.
    ///
    /// A Close command may carry zero only when the kernel entry is exactly
    /// InitialClosed with token zero. The kernel independently rejects a zero
    /// token for Active or TerminalClosed entries.
    #[must_use]
    pub const fn durable_fence_token(self) -> u64 {
        self.durable_fence_token
    }

    /// Absolute suspend-aware activation deadline.
    #[must_use]
    pub const fn deadline_boot_ns(self) -> u64 {
        self.deadline_boot_ns
    }

    /// Exact per-cookie transition epoch.
    #[must_use]
    pub const fn expected_epoch(self) -> u64 {
        self.expected_epoch
    }

    /// Encode into the control program's fixed input packet.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_CONTROL_COMMAND_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_CONTROL_COMMAND_LEN];
        encoded[0] = CONTROL_MAGIC[0];
        encoded[1] = CONTROL_MAGIC[1];
        encoded[2] = CONTROL_MAGIC[2];
        encoded[3] = CONTROL_MAGIC[3];
        let version = EGRESS_FENCE_ABI_VERSION.to_le_bytes();
        encoded[4] = version[0];
        encoded[5] = version[1];
        encoded[6] = self.operation as u8;
        put_u32(&mut encoded, 8, self.ifindex);
        put_u64(&mut encoded, 16, self.netns_cookie);
        put_u64(&mut encoded, 24, self.socket_cookie);
        put_u64(&mut encoded, 32, self.durable_fence_token);
        put_u64(&mut encoded, 40, self.deadline_boot_ns);
        put_u64(&mut encoded, 48, self.expected_epoch);
        encoded
    }

    /// Decode an exact canonical control command.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_CONTROL_COMMAND_LEN]) -> Option<Self> {
        if encoded[0] != CONTROL_MAGIC[0]
            || encoded[1] != CONTROL_MAGIC[1]
            || encoded[2] != CONTROL_MAGIC[2]
            || encoded[3] != CONTROL_MAGIC[3]
            || u16::from_le_bytes([encoded[4], encoded[5]]) != EGRESS_FENCE_ABI_VERSION
            || encoded[7] != 0
            || get_u32(encoded, 12) != 0
            || get_u64(encoded, 56) != 0
        {
            return None;
        }
        let operation = match ControlOperation::decode(encoded[6]) {
            Some(operation) => operation,
            None => return None,
        };
        Self::new(
            operation,
            get_u32(encoded, 8),
            get_u64(encoded, 16),
            get_u64(encoded, 24),
            get_u64(encoded, 32),
            get_u64(encoded, 40),
            get_u64(encoded, 48),
        )
    }
}

impl fmt::Debug for ControlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlCommand")
            .field("operation", &self.operation)
            .field("attachment_identity", &"<redacted>")
            .field("socket_cookie_present", &(self.socket_cookie != 0))
            .field(
                "durable_fence_token_present",
                &(self.durable_fence_token != 0),
            )
            .field("deadline_present", &(self.deadline_boot_ns != 0))
            .field("expected_epoch_present", &(self.expected_epoch != 0))
            .finish()
    }
}

/// Lifecycle state for one registered socket cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceEntryState {
    /// Registered fail-closed and eligible for its first activation.
    InitialClosed,
    /// Active or refreshable under the exact durable token.
    Active,
    /// Terminal tombstone that can never transition back to active.
    TerminalClosed,
}

/// Canonical state for one registered socket cookie.
///
/// The first four encoded bytes are reserved and must remain zero. The cookie
/// map deliberately has no per-entry spinlock: the classifier and control
/// program look up all required map pointers first, then serialize every
/// cookie read or transition with the single lock in the current-token map.
/// That global lock makes token publication and cookie inspection one ordered
/// domain without unsupported nested BPF locks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceEntry {
    state: FenceEntryState,
    durable_fence_token: u64,
    deadline_boot_ns: u64,
    control_epoch: u64,
}

impl FenceEntry {
    /// Initial closed registration state.
    #[must_use]
    pub const fn initial_closed() -> Self {
        Self {
            state: FenceEntryState::InitialClosed,
            durable_fence_token: 0,
            deadline_boot_ns: 0,
            control_epoch: EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
        }
    }

    /// Construct active state. Zero token, deadline, or epoch is rejected.
    #[must_use]
    pub const fn active(
        durable_fence_token: u64,
        deadline_boot_ns: u64,
        control_epoch: u64,
    ) -> Option<Self> {
        if durable_fence_token == 0 || deadline_boot_ns == 0 || control_epoch == 0 {
            None
        } else {
            Some(Self {
                state: FenceEntryState::Active,
                durable_fence_token,
                deadline_boot_ns,
                control_epoch,
            })
        }
    }

    /// Construct a terminal tombstone retaining its last token for audit.
    #[must_use]
    pub const fn terminal_closed(durable_fence_token: u64, control_epoch: u64) -> Option<Self> {
        if control_epoch == 0 {
            None
        } else {
            Some(Self {
                state: FenceEntryState::TerminalClosed,
                durable_fence_token,
                deadline_boot_ns: 0,
                control_epoch,
            })
        }
    }

    /// Lifecycle state.
    #[must_use]
    pub const fn state(self) -> FenceEntryState {
        self.state
    }

    /// Durable store fencing token retained for exact readback.
    #[must_use]
    pub const fn durable_fence_token(self) -> u64 {
        self.durable_fence_token
    }

    /// Absolute suspend-aware kernel boot-time deadline.
    #[must_use]
    pub const fn deadline_boot_ns(self) -> u64 {
        self.deadline_boot_ns
    }

    /// Monotonic per-cookie control epoch.
    #[must_use]
    pub const fn control_epoch(self) -> u64 {
        self.control_epoch
    }

    /// Whether this entry is closed.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        !matches!(self.state, FenceEntryState::Active)
    }

    /// Whether this entry is a terminal, non-reopenable tombstone.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self.state, FenceEntryState::TerminalClosed)
    }

    /// Encode this entry for the pinned hash map.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_COOKIE_VALUE_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_COOKIE_VALUE_LEN];
        let control = match self.state {
            FenceEntryState::InitialClosed => COOKIE_CONTROL_INITIAL_CLOSED,
            FenceEntryState::Active => COOKIE_CONTROL_ACTIVE,
            FenceEntryState::TerminalClosed => COOKIE_CONTROL_TERMINAL_CLOSED,
        };
        let control = control.to_le_bytes();
        encoded[4] = control[0];
        encoded[5] = control[1];
        encoded[6] = control[2];
        encoded[7] = control[3];
        let token = self.durable_fence_token.to_le_bytes();
        let deadline = self.deadline_boot_ns.to_le_bytes();
        let epoch = self.control_epoch.to_le_bytes();
        let mut index = 0;
        while index < 8 {
            encoded[8 + index] = token[index];
            encoded[16 + index] = deadline[index];
            encoded[24 + index] = epoch[index];
            index += 1;
        }
        encoded
    }

    /// Decode an exact canonical map value read while the global current-token
    /// lock is held.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_COOKIE_VALUE_LEN]) -> Option<Self> {
        if encoded[0] != 0 || encoded[1] != 0 || encoded[2] != 0 || encoded[3] != 0 {
            return None;
        }
        let control = u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        let token = u64::from_le_bytes([
            encoded[8],
            encoded[9],
            encoded[10],
            encoded[11],
            encoded[12],
            encoded[13],
            encoded[14],
            encoded[15],
        ]);
        let deadline = u64::from_le_bytes([
            encoded[16],
            encoded[17],
            encoded[18],
            encoded[19],
            encoded[20],
            encoded[21],
            encoded[22],
            encoded[23],
        ]);
        let epoch = u64::from_le_bytes([
            encoded[24],
            encoded[25],
            encoded[26],
            encoded[27],
            encoded[28],
            encoded[29],
            encoded[30],
            encoded[31],
        ]);
        match control {
            COOKIE_CONTROL_INITIAL_CLOSED if token == 0 && deadline == 0 => {
                if epoch == EGRESS_FENCE_INITIAL_COOKIE_EPOCH {
                    Some(Self::initial_closed())
                } else {
                    None
                }
            }
            COOKIE_CONTROL_ACTIVE => Self::active(token, deadline, epoch),
            COOKIE_CONTROL_TERMINAL_CLOSED if deadline == 0 => Self::terminal_closed(token, epoch),
            _ => None,
        }
    }
}

impl fmt::Debug for FenceEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceEntry")
            .field(
                "durable_fence_token_present",
                &(self.durable_fence_token != 0),
            )
            .field("state", &self.state)
            .field("control_epoch_present", &(self.control_epoch != 0))
            .finish()
    }
}

/// Redaction-safe tc decision for traffic in or outside the fence domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    /// Packet is unrelated to the protected endpoint and mark.
    PassUnrelated,
    /// Packet is admitted under an unexpired cookie deadline.
    Allow,
    /// Exact protected endpoint lacked the dedicated socket mark.
    DropUnmarked,
    /// Marked packet did not carry a usable socket cookie.
    DropCookieZero,
    /// Protected packet's cookie was not registered.
    DropMissing,
    /// Cookie is canonically closed.
    DropClosed,
    /// Cookie deadline has expired, including equality.
    DropExpired,
    /// Cookie carries a durable token superseded by a successor.
    DropStaleToken,
    /// Configuration or cookie value failed canonical decoding.
    DropMalformed,
}

impl FenceVerdict {
    /// Per-CPU counter slot for decisions that enter the fence domain.
    #[must_use]
    pub const fn counter_slot(self) -> Option<u32> {
        match self {
            Self::PassUnrelated => None,
            Self::Allow => Some(COUNTER_ALLOWED),
            Self::DropUnmarked => Some(COUNTER_UNMARKED),
            Self::DropCookieZero => Some(COUNTER_COOKIE_ZERO),
            Self::DropMissing => Some(COUNTER_COOKIE_MISSING),
            Self::DropClosed => Some(COUNTER_CLOSED),
            Self::DropExpired => Some(COUNTER_EXPIRED),
            Self::DropMalformed => Some(COUNTER_MALFORMED),
            Self::DropStaleToken => Some(COUNTER_STALE_TOKEN),
        }
    }

    /// Whether tc must return `TC_ACT_SHOT`.
    #[must_use]
    pub const fn must_drop(self) -> bool {
        !matches!(self, Self::PassUnrelated | Self::Allow)
    }
}

/// Packet-side inputs to one classifier decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketFenceContext {
    attachment_identity_valid: bool,
    endpoint_disposition: PacketEndpointDisposition,
    fence_mark: FenceMark,
    packet_mark: u32,
    socket_cookie: u64,
}

impl PacketFenceContext {
    /// Build packet-side decision context.
    #[must_use]
    pub const fn new(
        attachment_identity_valid: bool,
        endpoint_disposition: PacketEndpointDisposition,
        fence_mark: FenceMark,
        packet_mark: u32,
        socket_cookie: u64,
    ) -> Self {
        Self {
            attachment_identity_valid,
            endpoint_disposition,
            fence_mark,
            packet_mark,
            socket_cookie,
        }
    }
}

impl fmt::Debug for PacketFenceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketFenceContext")
            .field("attachment_identity_valid", &self.attachment_identity_valid)
            .field("endpoint_disposition", &self.endpoint_disposition)
            .field("fence_mark", &self.fence_mark)
            .field("socket_cookie_present", &(self.socket_cookie != 0))
            .finish()
    }
}

/// Globally serialized authority snapshot for one classifier decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceAuthoritySnapshot {
    entry: Option<FenceEntry>,
    current_durable_fence_token: u64,
    now_boot_ns: u64,
}

impl FenceAuthoritySnapshot {
    /// Build an authority snapshot copied while the global current-token lock
    /// is held.
    #[must_use]
    pub const fn new(
        entry: Option<FenceEntry>,
        current_durable_fence_token: u64,
        now_boot_ns: u64,
    ) -> Self {
        Self {
            entry,
            current_durable_fence_token,
            now_boot_ns,
        }
    }
}

impl fmt::Debug for FenceAuthoritySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceAuthoritySnapshot")
            .field("entry_present", &self.entry.is_some())
            .field(
                "current_durable_fence_token_present",
                &(self.current_durable_fence_token != 0),
            )
            .field("clock_present", &(self.now_boot_ns != 0))
            .finish()
    }
}

/// Apply the fail-closed fence decision after packet endpoint parsing.
///
/// `endpoint_matches` means the packet is UDP sourced from the configured
/// local endpoint. A matching packet without the dedicated mark is rejected;
/// a marked packet is always in-domain even if endpoint parsing failed.
#[must_use]
pub const fn decide_egress(
    packet: PacketFenceContext,
    authority: FenceAuthoritySnapshot,
) -> FenceVerdict {
    if !packet.attachment_identity_valid {
        return FenceVerdict::DropMalformed;
    }
    let marked = packet.fence_mark.is_present(packet.packet_mark);
    if !marked {
        return match packet.endpoint_disposition {
            PacketEndpointDisposition::Protected => FenceVerdict::DropUnmarked,
            PacketEndpointDisposition::Unrelated => FenceVerdict::PassUnrelated,
            PacketEndpointDisposition::Indeterminate => FenceVerdict::DropMalformed,
        };
    }
    if packet.socket_cookie == 0 {
        return FenceVerdict::DropCookieZero;
    }
    let Some(entry) = authority.entry else {
        return FenceVerdict::DropMissing;
    };
    if !matches!(entry.state(), FenceEntryState::Active) {
        return FenceVerdict::DropClosed;
    }
    if authority.current_durable_fence_token == 0
        || entry.durable_fence_token() != authority.current_durable_fence_token
    {
        return FenceVerdict::DropStaleToken;
    }
    if authority.now_boot_ns >= entry.deadline_boot_ns() {
        return FenceVerdict::DropExpired;
    }
    FenceVerdict::Allow
}

const fn put_u32<const N: usize>(encoded: &mut [u8; N], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    let mut index = 0;
    while index < bytes.len() {
        encoded[offset + index] = bytes[index];
        index += 1;
    }
}

const fn put_u64<const N: usize>(encoded: &mut [u8; N], offset: usize, value: u64) {
    let bytes = value.to_le_bytes();
    let mut index = 0;
    while index < bytes.len() {
        encoded[offset + index] = bytes[index];
        index += 1;
    }
}

const fn get_u32<const N: usize>(encoded: &[u8; N], offset: usize) -> u32 {
    u32::from_le_bytes([
        encoded[offset],
        encoded[offset + 1],
        encoded[offset + 2],
        encoded[offset + 3],
    ])
}

const fn get_u64<const N: usize>(encoded: &[u8; N], offset: usize) -> u64 {
    u64::from_le_bytes([
        encoded[offset],
        encoded[offset + 1],
        encoded[offset + 2],
        encoded[offset + 3],
        encoded[offset + 4],
        encoded[offset + 5],
        encoded[offset + 6],
        encoded[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn config_and_cookie_encodings_are_canonical() {
        let endpoint = ProtectedEndpoint::ipv4([192, 0, 2, 10], 2123)
            .expect("documentation address is a usable fixture");
        let mark = FenceMark::new(1 << 17).expect("single-bit fixture");
        let config = FenceConfig::new(endpoint, mark, 7, 11, 64).expect("canonical fixture");
        assert_eq!(FenceConfig::decode(&config.encode()), Some(config));

        let closed = FenceEntry::terminal_closed(9, 3).expect("nonzero terminal epoch");
        assert_eq!(FenceEntry::decode(&closed.encode()), Some(closed));
        let initial = FenceEntry::initial_closed();
        assert_eq!(FenceEntry::decode(&initial.encode()), Some(initial));
        let active = FenceEntry::active(9, 10, 2).expect("nonzero active fixture");
        assert_eq!(FenceEntry::decode(&active.encode()), Some(active));

        let current = CurrentFenceToken::published(9).expect("nonzero token");
        assert_eq!(CurrentFenceToken::decode(&current.encode()), Some(current));

        let command = ControlCommand::new(ControlOperation::Activate, 7, 11, 13, 9, 10, 1)
            .expect("canonical command");
        assert_eq!(ControlCommand::decode(&command.encode()), Some(command));
    }

    #[test]
    fn equality_at_deadline_is_expired() {
        let active = FenceEntry::active(9, 10, 2).expect("nonzero active fixture");
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(
                    true,
                    PacketEndpointDisposition::Protected,
                    FenceMark::new(1 << 17).expect("single-bit fixture"),
                    1 << 17,
                    11,
                ),
                FenceAuthoritySnapshot::new(Some(active), 9, 10),
            ),
            FenceVerdict::DropExpired
        );
    }

    #[test]
    fn fence_mark_is_single_bit_and_reports_overlap_without_exposing_value() {
        let mark = FenceMark::new(1 << 17).expect("single-bit fixture");
        assert!(mark.is_present((1 << 17) | 7));
        assert_eq!(mark.clear((1 << 17) | 7), 7);
        assert!(mark.overlaps(0x0003_f000));
        assert!(!mark.overlaps(0xfe00_0000));
        assert!(FenceMark::new(0).is_none());
        assert!(FenceMark::new(3).is_none());
        assert_eq!(std::format!("{mark:?}"), "FenceMark(<redacted>)");
    }

    #[test]
    fn control_command_operations_reject_every_noncanonical_field_shape() {
        let publish = ControlCommand::new(ControlOperation::PublishToken, 7, 11, 0, 9, 0, 0)
            .expect("canonical publication");
        let activate = ControlCommand::new(ControlOperation::Activate, 7, 11, 13, 9, 10, 1)
            .expect("canonical activation");
        let refresh = ControlCommand::new(ControlOperation::Refresh, 7, 11, 13, 9, 10, 1)
            .expect("canonical refresh");
        let close = ControlCommand::new(ControlOperation::Close, 7, 11, 13, 9, 0, 1)
            .expect("canonical close");
        let close_initial = ControlCommand::new(ControlOperation::Close, 7, 11, 13, 0, 0, 1)
            .expect("canonical initial-state close");
        let reclaim = ControlCommand::new(ControlOperation::Reclaim, 7, 11, 13, 0, 0, 1)
            .expect("canonical initial-state reclaim");
        for command in [publish, activate, refresh, close, close_initial, reclaim] {
            assert_eq!(ControlCommand::decode(&command.encode()), Some(command));
        }

        assert!(ControlCommand::new(ControlOperation::PublishToken, 0, 11, 0, 9, 0, 0).is_none());
        assert!(ControlCommand::new(ControlOperation::PublishToken, 7, 0, 0, 9, 0, 0).is_none());
        assert!(ControlCommand::new(ControlOperation::PublishToken, 7, 11, 13, 9, 0, 0).is_none());
        assert!(ControlCommand::new(ControlOperation::PublishToken, 7, 11, 0, 0, 0, 0).is_none());
        assert!(ControlCommand::new(ControlOperation::PublishToken, 7, 11, 0, 9, 10, 0).is_none());
        assert!(ControlCommand::new(ControlOperation::PublishToken, 7, 11, 0, 9, 0, 1).is_none());

        for operation in [ControlOperation::Activate, ControlOperation::Refresh] {
            assert!(ControlCommand::new(operation, 7, 11, 0, 9, 10, 1).is_none());
            assert!(ControlCommand::new(operation, 7, 11, 13, 0, 10, 1).is_none());
            assert!(ControlCommand::new(operation, 7, 11, 13, 9, 0, 1).is_none());
            assert!(ControlCommand::new(operation, 7, 11, 13, 9, 10, 0).is_none());
        }

        assert!(ControlCommand::new(ControlOperation::Close, 7, 11, 0, 9, 0, 1).is_none());
        assert!(ControlCommand::new(ControlOperation::Close, 7, 11, 13, 9, 10, 1).is_none());
        assert!(ControlCommand::new(ControlOperation::Close, 7, 11, 13, 9, 0, 0).is_none());

        assert!(ControlCommand::new(ControlOperation::Reclaim, 7, 11, 0, 0, 0, 1).is_none());
        assert!(ControlCommand::new(ControlOperation::Reclaim, 7, 11, 13, 0, 10, 1).is_none());
        assert!(ControlCommand::new(ControlOperation::Reclaim, 7, 11, 13, 0, 0, 0).is_none());
    }

    #[test]
    fn encoded_control_field_mutations_fail_canonical_decode() {
        let activate = ControlCommand::new(ControlOperation::Activate, 7, 11, 13, 9, 10, 1)
            .expect("canonical activation")
            .encode();
        for offset in [0, 4, 6, 8, 16, 24, 32, 40, 48] {
            let mut mutated = activate;
            mutated[offset] = 0;
            assert!(
                ControlCommand::decode(&mutated).is_none(),
                "offset {offset} must be canonical"
            );
        }
        for offset in [7, 12, 56] {
            let mut mutated = activate;
            mutated[offset] = 1;
            assert!(
                ControlCommand::decode(&mutated).is_none(),
                "reserved offset {offset} must be zero"
            );
        }

        let publish = ControlCommand::new(ControlOperation::PublishToken, 7, 11, 0, 9, 0, 0)
            .expect("canonical publication")
            .encode();
        for offset in [24, 40, 48] {
            let mut mutated = publish;
            mutated[offset] = 1;
            assert!(
                ControlCommand::decode(&mutated).is_none(),
                "publication offset {offset} must remain zero"
            );
        }

        let close = ControlCommand::new(ControlOperation::Close, 7, 11, 13, 9, 0, 1)
            .expect("canonical close")
            .encode();
        let mut close_with_deadline = close;
        close_with_deadline[40] = 1;
        assert!(ControlCommand::decode(&close_with_deadline).is_none());
    }
}
