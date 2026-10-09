//! Shared map ABI and packet-decision rules for the lease-bound egress fence.
//!
//! This dependency-free `no_std` crate is the single source of truth for map
//! byte layouts used by the userspace loader and eBPF programs. Values
//! use explicit little-endian integer encoding because the committed object
//! targets `bpfel-unknown-none`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

mod packet;

pub use packet::{classify_l3_udp_source, PacketEndpointDisposition};

/// ABI version encoded into every configuration and control command.
pub const EGRESS_FENCE_ABI_VERSION: u16 = 5;
/// Maximum cookie entries in the non-LRU kernel hash map.
pub const EGRESS_FENCE_MAX_COOKIE_ENTRIES: u32 = 4_096;
/// Hard upper bound for one kernel gate deadline, in suspend-aware nanoseconds.
///
/// This is a safety ceiling rather than a recommended lease TTL. Products
/// should normally configure a substantially shorter lifetime.
pub const EGRESS_FENCE_MAX_GATE_LIFETIME_NS: u64 = 300_000_000_000;
/// Stable cgroup-skb egress program ABI name.
pub const EGRESS_FENCE_PROGRAM_NAME: &str = "opc_egress_gate";
/// Stable syscall-frozen cookie map ABI name.
pub const EGRESS_FENCE_COOKIE_MAP_NAME: &str = "OPC_FENCE_CKS";
/// Stable syscall-frozen configuration map ABI name.
pub const EGRESS_FENCE_CONFIG_MAP_NAME: &str = "OPC_FENCE_CFG";
/// Stable syscall-frozen per-CPU counter map ABI name.
pub const EGRESS_FENCE_COUNTER_MAP_NAME: &str = "OPC_FENCE_CTR";
/// Stable syscall-frozen monotonic-current-fence map ABI name.
pub const EGRESS_FENCE_CURRENT_MAP_NAME: &str = "OPC_FENCE_CUR";
/// Stable shared BTF spin-lock map ABI name.
///
/// Linux rejects `BPF_MAP_FREEZE` for maps containing special BTF fields such
/// as `bpf_spin_lock`, so installers must not claim this map is syscall-frozen.
/// Its exact schema and initial zero value remain part of admission.
pub const EGRESS_FENCE_LOCK_MAP_NAME: &str = "OPC_FENCE_LOCK";
/// Stable syscall-frozen structural-mutation authority map ABI name.
pub const EGRESS_FENCE_MUTATION_MAP_NAME: &str = "OPC_FENCE_MUT";
/// Stable control-program ABI name used through `BPF_PROG_TEST_RUN`.
pub const EGRESS_FENCE_CONTROL_PROGRAM_NAME: &str = "opc_fence_ctl";
/// Stable synchronized read-only inspect-program ABI name.
pub const EGRESS_FENCE_INSPECT_PROGRAM_NAME: &str = "opc_fence_view";
/// Encoded configuration value width.
pub const EGRESS_FENCE_CONFIG_VALUE_LEN: usize = 40;
/// Encoded cookie entry width.
pub const EGRESS_FENCE_COOKIE_VALUE_LEN: usize = 40;
/// Encoded cookie-map key width.
pub const EGRESS_FENCE_COOKIE_KEY_LEN: usize = 16;
/// Encoded lifecycle-state width without its redundant map identity.
pub const EGRESS_FENCE_ENTRY_STATE_LEN: usize = 32;
/// Encoded monotonic-current-token and registered-cookie value width.
pub const EGRESS_FENCE_CURRENT_VALUE_LEN: usize = 24;
/// Encoded control command width.
pub const EGRESS_FENCE_CONTROL_COMMAND_LEN: usize = 48;
/// Inspect request/response skb width.
pub const EGRESS_FENCE_INSPECT_BUFFER_LEN: usize = 128;

/// Counter slot for packets admitted by a live cookie deadline.
pub const COUNTER_ALLOWED: u32 = 0;
/// Reserved counter slot retained in the frozen eight-slot map ABI.
pub const COUNTER_RESERVED: u32 = 1;
/// Counter slot for protected packets whose socket cookie is zero.
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
/// CURRENT control word for an odd, socket-lifecycle token.
pub const CURRENT_LIFECYCLE_OPEN_CONTROL: u32 = 0x4f45_0201;
/// CURRENT control word for an even, registration-closed retirement token.
pub const CURRENT_RETIREMENT_CLOSED_CONTROL: u32 = 0x4f45_0202;
/// Initial per-cookie control epoch.
pub const EGRESS_FENCE_INITIAL_COOKIE_EPOCH: u64 = 1;
const CONTROL_MAGIC: [u8; 4] = *b"OEC1";
const INSPECTION_MAGIC: [u8; 4] = *b"OEI1";

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

/// Fail-closed outcome of the post-contention refresh clock observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshDeadlineDecision {
    /// The prior deadline remains live and the requested deadline is canonical.
    Apply,
    /// The prior deadline elapsed before the refresh won mutation authority.
    PriorExpired,
    /// The requested deadline is elapsed or exceeds the frozen lifetime bound.
    RequestedDeadlineInvalid,
    /// The requested deadline would shorten the live authorization.
    DeadlineRegressed,
}

/// Evaluate refresh deadlines at the BOOTTIME observation taken only after the
/// kernel entry has been made fail-closed under mutation authority.
#[must_use]
pub const fn evaluate_refresh_deadlines(
    observed_at_boot_ns: u64,
    prior_deadline_boot_ns: u64,
    requested_deadline_boot_ns: u64,
) -> RefreshDeadlineDecision {
    if observed_at_boot_ns >= prior_deadline_boot_ns {
        RefreshDeadlineDecision::PriorExpired
    } else if requested_deadline_boot_ns <= observed_at_boot_ns
        || requested_deadline_boot_ns - observed_at_boot_ns > EGRESS_FENCE_MAX_GATE_LIFETIME_NS
    {
        RefreshDeadlineDecision::RequestedDeadlineInvalid
    } else if requested_deadline_boot_ns < prior_deadline_boot_ns {
        RefreshDeadlineDecision::DeadlineRegressed
    } else {
        RefreshDeadlineDecision::Apply
    }
}

/// Exact local UDP source endpoint protected by one fence attachment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProtectedEndpoint {
    /// ABI-level IPv4 address candidate and nonzero UDP source port.
    ///
    /// The Linux installer separately proves the local prefix and canonical
    /// interface-broadcast metadata needed to establish exact unicast use.
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
    /// Construct an ABI-level IPv4 candidate when address and port are usable.
    ///
    /// This dependency-free type has no interface prefix information. The
    /// Linux installer must complete subnet-number and directed-broadcast
    /// rejection before admitting the endpoint.
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
        let ipv4_mapped = address[0] == 0
            && address[1] == 0
            && address[2] == 0
            && address[3] == 0
            && address[4] == 0
            && address[5] == 0
            && address[6] == 0
            && address[7] == 0
            && address[8] == 0
            && address[9] == 0
            && address[10] == 0xff
            && address[11] == 0xff;
        let link_local = address[0] == 0xfe && address[1] & 0xc0 == 0x80;
        if port == 0 || !nonzero || address[0] == 0xff || ipv4_mapped || link_local {
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

/// Canonical immutable configuration shared with the root cgroup classifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceConfig {
    endpoint: ProtectedEndpoint,
    root_cgroup_id: u64,
    capacity: u32,
}

impl FenceConfig {
    /// Construct a canonical configuration.
    #[must_use]
    pub const fn new(
        endpoint: ProtectedEndpoint,
        root_cgroup_id: u64,
        capacity: u32,
    ) -> Option<Self> {
        if root_cgroup_id == 0 || capacity != EGRESS_FENCE_MAX_COOKIE_ENTRIES {
            None
        } else {
            Some(Self {
                endpoint,
                root_cgroup_id,
                capacity,
            })
        }
    }

    /// Protected local endpoint.
    #[must_use]
    pub const fn endpoint(self) -> ProtectedEndpoint {
        self.endpoint
    }

    /// Inode ID of the unified default-hierarchy root cgroup.
    #[must_use]
    pub const fn root_cgroup_id(self) -> u64 {
        self.root_cgroup_id
    }

    /// Frozen production kernel-map capacity.
    ///
    /// A different value identifies an incompatible configuration rather than
    /// a tunable runtime limit.
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
        let port = self.endpoint.port().to_be_bytes();
        encoded[8] = port[0];
        encoded[9] = port[1];
        let capacity = self.capacity.to_le_bytes();
        encoded[12] = capacity[0];
        encoded[13] = capacity[1];
        encoded[14] = capacity[2];
        encoded[15] = capacity[3];
        let root_cgroup_id = self.root_cgroup_id.to_le_bytes();
        let mut cgroup_index = 0;
        while cgroup_index < root_cgroup_id.len() {
            encoded[16 + cgroup_index] = root_cgroup_id[cgroup_index];
            cgroup_index += 1;
        }
        match self.endpoint {
            ProtectedEndpoint::Ipv4 { address, .. } => {
                encoded[6] = FAMILY_IPV4;
                encoded[24] = address[0];
                encoded[25] = address[1];
                encoded[26] = address[2];
                encoded[27] = address[3];
            }
            ProtectedEndpoint::Ipv6 { address, .. } => {
                encoded[6] = FAMILY_IPV6;
                let mut index = 0;
                while index < address.len() {
                    encoded[24 + index] = address[index];
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
            || encoded[10] != 0
            || encoded[11] != 0
        {
            return None;
        }
        let port = u16::from_be_bytes([encoded[8], encoded[9]]);
        let capacity = u32::from_le_bytes([encoded[12], encoded[13], encoded[14], encoded[15]]);
        let root_cgroup_id = u64::from_le_bytes([
            encoded[16],
            encoded[17],
            encoded[18],
            encoded[19],
            encoded[20],
            encoded[21],
            encoded[22],
            encoded[23],
        ]);
        let endpoint = if encoded[6] == FAMILY_IPV4 {
            let mut reserved = 28;
            while reserved < 40 {
                if encoded[reserved] != 0 {
                    return None;
                }
                reserved += 1;
            }
            match ProtectedEndpoint::ipv4(
                [encoded[24], encoded[25], encoded[26], encoded[27]],
                port,
            ) {
                Some(endpoint) => endpoint,
                None => return None,
            }
        } else if encoded[6] == FAMILY_IPV6 {
            let mut address = [0_u8; 16];
            let mut index = 0;
            while index < address.len() {
                address[index] = encoded[24 + index];
                index += 1;
            }
            match ProtectedEndpoint::ipv6(address, port) {
                Some(endpoint) => endpoint,
                None => return None,
            }
        } else {
            return None;
        };
        Self::new(endpoint, root_cgroup_id, capacity)
    }
}

impl fmt::Debug for FenceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceConfig")
            .field("endpoint", &self.endpoint)
            .field("root_attachment", &"<redacted>")
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// Canonical value for the attachment's kernel-monotonic durable token.
///
/// The first four encoded bytes are reserved zero. Synchronization lives in a
/// separate lock-only map so this authorization map can be kernel-frozen
/// against every syscall-side mutation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CurrentFenceToken {
    durable_fence_token: u64,
    registered_socket_cookie: u64,
    retirement_closed: bool,
}

impl CurrentFenceToken {
    /// Construct the initial closed token state.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            durable_fence_token: 0,
            registered_socket_cookie: 0,
            retirement_closed: false,
        }
    }

    /// Construct a published nonzero token.
    #[must_use]
    pub const fn lifecycle_open(durable_fence_token: u64) -> Option<Self> {
        if durable_fence_token == 0 || durable_fence_token & 1 == 0 {
            None
        } else {
            Some(Self {
                durable_fence_token,
                registered_socket_cookie: 0,
                retirement_closed: false,
            })
        }
    }

    /// Construct a closed even retirement token.
    #[must_use]
    pub const fn retirement_closed(durable_fence_token: u64) -> Option<Self> {
        if durable_fence_token == 0 || durable_fence_token & 1 != 0 {
            None
        } else {
            Some(Self {
                durable_fence_token,
                registered_socket_cookie: 0,
                retirement_closed: true,
            })
        }
    }

    /// Construct a published token with its one registered socket cookie.
    #[must_use]
    pub const fn registered(
        durable_fence_token: u64,
        registered_socket_cookie: u64,
    ) -> Option<Self> {
        if durable_fence_token == 0 || durable_fence_token & 1 == 0 || registered_socket_cookie == 0
        {
            None
        } else {
            Some(Self {
                durable_fence_token,
                registered_socket_cookie,
                retirement_closed: false,
            })
        }
    }

    /// Current durable token, or zero before the first publication.
    #[must_use]
    pub const fn durable_fence_token(self) -> u64 {
        self.durable_fence_token
    }

    /// Full-width cookie claimed for this token, or zero before registration.
    ///
    /// Close and Reclaim deliberately retain this value. Only publication of
    /// a strictly higher token resets it, preventing same-token cookie reuse.
    #[must_use]
    pub const fn registered_socket_cookie(self) -> u64 {
        self.registered_socket_cookie
    }

    /// Whether this odd lifecycle token can own one socket registration.
    #[must_use]
    pub const fn is_lifecycle_open(self) -> bool {
        self.durable_fence_token != 0 && !self.retirement_closed
    }

    /// Whether this even retirement token permanently closes registration.
    #[must_use]
    pub const fn is_retirement_closed(self) -> bool {
        self.durable_fence_token != 0 && self.retirement_closed
    }

    /// Encode for the single-slot pinned array map.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_CURRENT_VALUE_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_CURRENT_VALUE_LEN];
        if self.durable_fence_token == 0 {
            return encoded;
        }
        let control = if self.retirement_closed {
            CURRENT_RETIREMENT_CLOSED_CONTROL
        } else {
            CURRENT_LIFECYCLE_OPEN_CONTROL
        }
        .to_le_bytes();
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
        let cookie = self.registered_socket_cookie.to_le_bytes();
        let mut index = 0;
        while index < cookie.len() {
            encoded[16 + index] = cookie[index];
            index += 1;
        }
        encoded
    }

    /// Decode an exact synchronized Inspect snapshot.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_CURRENT_VALUE_LEN]) -> Option<Self> {
        let all_zero = {
            let mut index = 0;
            let mut zero = true;
            while index < encoded.len() {
                zero &= encoded[index] == 0;
                index += 1;
            }
            zero
        };
        if all_zero {
            return Some(Self::initial());
        }
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
        let cookie = u64::from_le_bytes([
            encoded[16],
            encoded[17],
            encoded[18],
            encoded[19],
            encoded[20],
            encoded[21],
            encoded[22],
            encoded[23],
        ]);
        match control {
            CURRENT_LIFECYCLE_OPEN_CONTROL if cookie == 0 => Self::lifecycle_open(token),
            CURRENT_LIFECYCLE_OPEN_CONTROL => Self::registered(token, cookie),
            CURRENT_RETIREMENT_CLOSED_CONTROL if cookie == 0 => Self::retirement_closed(token),
            _ => None,
        }
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
            .field(
                "registered_socket_cookie_present",
                &(self.registered_socket_cookie != 0),
            )
            .field("retirement_closed", &self.retirement_closed)
            .finish()
    }
}

/// Synchronized state of the global structural-mutation barrier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceMutationAuthority {
    generation: u64,
    in_flight_claim: u64,
}

impl FenceMutationAuthority {
    /// Initial structural-mutation authority.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            generation: 0,
            in_flight_claim: 0,
        }
    }

    /// Construct canonical structural-mutation authority.
    ///
    /// A live claim is uniquely the next nonwrapping generation.
    #[must_use]
    pub const fn new(generation: u64, in_flight_claim: u64) -> Option<Self> {
        if in_flight_claim == 0 || generation != u64::MAX && in_flight_claim == generation + 1 {
            Some(Self {
                generation,
                in_flight_claim,
            })
        } else {
            None
        }
    }

    /// Last completed structural-mutation generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Unique in-flight claim, or zero while idle.
    #[must_use]
    pub const fn in_flight_claim(self) -> u64 {
        self.in_flight_claim
    }

    /// Encode the frozen 16-byte structural-mutation authority.
    #[must_use]
    pub const fn encode(self) -> [u8; 16] {
        let mut encoded = [0_u8; 16];
        put_u64(&mut encoded, 0, self.generation);
        put_u64(&mut encoded, 8, self.in_flight_claim);
        encoded
    }

    /// Decode a canonical synchronized value.
    #[must_use]
    pub const fn decode(encoded: &[u8; 16]) -> Option<Self> {
        Self::new(get_u64(encoded, 0), get_u64(encoded, 8))
    }
}

impl fmt::Debug for FenceMutationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceMutationAuthority")
            .field("generation_present", &(self.generation != 0))
            .field("mutation_in_flight", &(self.in_flight_claim != 0))
            .finish()
    }
}

/// Atomic transition requested from the frozen kernel control program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlOperation {
    /// Publish an odd lifecycle-open token monotonically.
    PublishLifecycle = 1,
    /// Insert and claim one fail-closed socket cookie under the current token.
    Register = 2,
    /// Open a newly registered cookie.
    Activate = 3,
    /// Extend an already active cookie under the same durable token.
    Refresh = 4,
    /// Irreversibly close a cookie.
    Close = 5,
    /// Delete an exact entry after durable publication of any strictly higher
    /// canonical CURRENT token makes the predecessor non-authoritative.
    Reclaim = 6,
    /// Return one synchronized CURRENT/mutation/optional-entry snapshot.
    Inspect = 7,
    /// Close an odd lifecycle with its exact consecutive even retirement token.
    PublishRetirement = 8,
}

impl ControlOperation {
    const fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PublishLifecycle),
            2 => Some(Self::Register),
            3 => Some(Self::Activate),
            4 => Some(Self::Refresh),
            5 => Some(Self::Close),
            6 => Some(Self::Reclaim),
            7 => Some(Self::Inspect),
            8 => Some(Self::PublishRetirement),
            _ => None,
        }
    }
}

/// Value-free command sent to the unattached sched-cls control program.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ControlCommand {
    operation: ControlOperation,
    root_cgroup_id: u64,
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
        root_cgroup_id: u64,
        socket_cookie: u64,
        durable_fence_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Option<Self> {
        let fields_are_canonical = match operation {
            ControlOperation::PublishLifecycle => {
                socket_cookie == 0
                    && durable_fence_token != 0
                    && durable_fence_token & 1 == 1
                    && deadline_boot_ns == 0
                    && expected_epoch == 0
            }
            ControlOperation::PublishRetirement => {
                socket_cookie == 0
                    && durable_fence_token != 0
                    && durable_fence_token & 1 == 0
                    && deadline_boot_ns == 0
                    && expected_epoch == 0
            }
            ControlOperation::Register => {
                socket_cookie != 0
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
                socket_cookie != 0
                    && durable_fence_token != 0
                    && deadline_boot_ns == 0
                    && expected_epoch != 0
            }
            ControlOperation::Reclaim => {
                socket_cookie != 0
                    && durable_fence_token != 0
                    && deadline_boot_ns == 0
                    && expected_epoch != 0
            }
            ControlOperation::Inspect => {
                ((socket_cookie == 0 && durable_fence_token == 0)
                    || (socket_cookie != 0 && durable_fence_token != 0))
                    && deadline_boot_ns == 0
                    && expected_epoch == 0
            }
        };
        if root_cgroup_id == 0 || !fields_are_canonical {
            None
        } else {
            Some(Self {
                operation,
                root_cgroup_id,
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

    /// Expected unified default-hierarchy root cgroup inode ID.
    #[must_use]
    pub const fn root_cgroup_id(self) -> u64 {
        self.root_cgroup_id
    }

    /// Full-width socket cookie, zero only for token publication.
    #[must_use]
    pub const fn socket_cookie(self) -> u64 {
        self.socket_cookie
    }

    /// Durable per-resource fencing token.
    ///
    /// Every per-cookie operation carries the nonzero durable token allocated
    /// before that cookie was registered.
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
        put_u64(&mut encoded, 8, self.root_cgroup_id);
        put_u64(&mut encoded, 16, self.socket_cookie);
        put_u64(&mut encoded, 24, self.durable_fence_token);
        put_u64(&mut encoded, 32, self.deadline_boot_ns);
        put_u64(&mut encoded, 40, self.expected_epoch);
        encoded
    }

    /// Encode an Inspect command into the zero-padded request/response skb.
    #[must_use]
    pub const fn encode_inspect_request(self) -> Option<[u8; EGRESS_FENCE_INSPECT_BUFFER_LEN]> {
        if !matches!(self.operation, ControlOperation::Inspect) {
            return None;
        }
        let command = self.encode();
        let mut encoded = [0_u8; EGRESS_FENCE_INSPECT_BUFFER_LEN];
        let mut index = 0;
        while index < command.len() {
            encoded[index] = command[index];
            index += 1;
        }
        Some(encoded)
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
        {
            return None;
        }
        let operation = match ControlOperation::decode(encoded[6]) {
            Some(operation) => operation,
            None => return None,
        };
        Self::new(
            operation,
            get_u64(encoded, 8),
            get_u64(encoded, 16),
            get_u64(encoded, 24),
            get_u64(encoded, 32),
            get_u64(encoded, 40),
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

/// Exact identity of one registered socket lifecycle.
///
/// Linux socket cookies can be reused after the last reference to a socket is
/// closed. Pairing the full-width cookie with the durable, nonwrapping
/// lifecycle token prevents a delayed deletion for an earlier lifecycle from
/// removing a successor that received the same numeric cookie.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceCookieKey {
    socket_cookie: u64,
    durable_fence_token: u64,
}

impl FenceCookieKey {
    /// Construct an exact nonzero socket-lifecycle identity.
    #[must_use]
    pub const fn new(socket_cookie: u64, durable_fence_token: u64) -> Option<Self> {
        if socket_cookie == 0 || durable_fence_token == 0 {
            None
        } else {
            Some(Self {
                socket_cookie,
                durable_fence_token,
            })
        }
    }

    /// Full-width kernel socket cookie.
    #[must_use]
    pub const fn socket_cookie(self) -> u64 {
        self.socket_cookie
    }

    /// Durable, nonwrapping lifecycle token.
    #[must_use]
    pub const fn durable_fence_token(self) -> u64 {
        self.durable_fence_token
    }

    /// Encode the exact little-endian hash-map key.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_COOKIE_KEY_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_COOKIE_KEY_LEN];
        put_u64(&mut encoded, 0, self.socket_cookie);
        put_u64(&mut encoded, 8, self.durable_fence_token);
        encoded
    }

    /// Decode an exact canonical hash-map key.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_COOKIE_KEY_LEN]) -> Option<Self> {
        Self::new(get_u64(encoded, 0), get_u64(encoded, 8))
    }
}

impl fmt::Debug for FenceCookieKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceCookieKey")
            .field("socket_cookie_present", &(self.socket_cookie != 0))
            .field(
                "durable_fence_token_present",
                &(self.durable_fence_token != 0),
            )
            .finish()
    }
}

/// Canonical cookie-map value with redundant lifecycle identity.
///
/// Hash-map value storage can be recycled after deletion while an earlier BPF
/// invocation still retains a verifier-approved pointer. The redundant cookie
/// and token make such reuse observable: callers must compare [`Self::key`]
/// with the key used for lookup before trusting [`Self::entry`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceCookieValue {
    key: FenceCookieKey,
    entry: FenceEntry,
}

impl FenceCookieValue {
    /// Pair an entry with the exact map key it redundantly encodes.
    #[must_use]
    pub const fn new(key: FenceCookieKey, entry: FenceEntry) -> Option<Self> {
        if key.durable_fence_token() == entry.durable_fence_token() {
            Some(Self { key, entry })
        } else {
            None
        }
    }

    /// Redundant socket-lifecycle identity.
    #[must_use]
    pub const fn key(self) -> FenceCookieKey {
        self.key
    }

    /// Canonical lifecycle state.
    #[must_use]
    pub const fn entry(self) -> FenceEntry {
        self.entry
    }

    /// Encode the frozen 40-byte hash-map value.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_COOKIE_VALUE_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_COOKIE_VALUE_LEN];
        let state = self.entry.encode();
        put_u32(&mut encoded, 4, get_u32(&state, 4));
        put_u64(&mut encoded, 8, self.key.socket_cookie());
        put_u64(&mut encoded, 16, self.key.durable_fence_token());
        put_u64(&mut encoded, 24, self.entry.deadline_boot_ns());
        put_u64(&mut encoded, 32, self.entry.control_epoch());
        encoded
    }

    /// Decode a canonical value and its nonzero redundant identity.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_COOKIE_VALUE_LEN]) -> Option<Self> {
        if get_u32(encoded, 0) != 0 {
            return None;
        }
        let key = match FenceCookieKey::new(get_u64(encoded, 8), get_u64(encoded, 16)) {
            Some(key) => key,
            None => return None,
        };
        let mut state = [0_u8; EGRESS_FENCE_ENTRY_STATE_LEN];
        put_u32(&mut state, 4, get_u32(encoded, 4));
        put_u64(&mut state, 8, get_u64(encoded, 16));
        put_u64(&mut state, 16, get_u64(encoded, 24));
        put_u64(&mut state, 24, get_u64(encoded, 32));
        let entry = match FenceEntry::decode(&state) {
            Some(entry) => entry,
            None => return None,
        };
        Self::new(key, entry)
    }
}

impl fmt::Debug for FenceCookieValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceCookieValue")
            .field("key", &self.key)
            .field("entry", &self.entry)
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
    /// Fail-closed deletion state retained when a map delete must be retried.
    Reclaiming,
}

/// Canonical state for one registered socket cookie.
///
/// The first four encoded bytes are reserved and must remain zero. The cookie
/// map deliberately has no per-entry spinlock. Registration inserts a
/// fail-closed value with `BPF_NOEXIST` before claiming it under the single
/// current-authority lock; the classifier admits an entry only while CURRENT
/// names the exact cookie and token. All entry transitions and packet-side
/// snapshots are serialized by that same lock.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceEntry {
    state: FenceEntryState,
    durable_fence_token: u64,
    deadline_boot_ns: u64,
    control_epoch: u64,
}

impl FenceEntry {
    /// Initial closed registration state under a fresh durable token.
    #[must_use]
    pub const fn initial_closed(durable_fence_token: u64) -> Option<Self> {
        if durable_fence_token == 0 || durable_fence_token & 1 == 0 {
            None
        } else {
            Some(Self {
                state: FenceEntryState::InitialClosed,
                durable_fence_token,
                deadline_boot_ns: 0,
                control_epoch: EGRESS_FENCE_INITIAL_COOKIE_EPOCH,
            })
        }
    }

    /// Construct active state. Zero token, deadline, or epoch is rejected.
    #[must_use]
    pub const fn active(
        durable_fence_token: u64,
        deadline_boot_ns: u64,
        control_epoch: u64,
    ) -> Option<Self> {
        if durable_fence_token == 0
            || durable_fence_token & 1 == 0
            || deadline_boot_ns == 0
            || control_epoch == 0
        {
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
        if durable_fence_token == 0 || durable_fence_token & 1 == 0 || control_epoch == 0 {
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

    /// Construct an exact fail-closed deletion-retry state.
    #[must_use]
    pub const fn reclaiming(durable_fence_token: u64, control_epoch: u64) -> Option<Self> {
        if durable_fence_token == 0 || durable_fence_token & 1 == 0 || control_epoch == 0 {
            None
        } else {
            Some(Self {
                state: FenceEntryState::Reclaiming,
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

    /// Whether deletion was linearized and must be retried exactly.
    #[must_use]
    pub const fn is_reclaiming(self) -> bool {
        matches!(self.state, FenceEntryState::Reclaiming)
    }

    /// Encode this entry for the pinned hash map.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_ENTRY_STATE_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_ENTRY_STATE_LEN];
        let control = match self.state {
            FenceEntryState::InitialClosed => COOKIE_CONTROL_INITIAL_CLOSED,
            FenceEntryState::Active => COOKIE_CONTROL_ACTIVE,
            FenceEntryState::TerminalClosed => COOKIE_CONTROL_TERMINAL_CLOSED,
            FenceEntryState::Reclaiming => COOKIE_CONTROL_RECLAIMING,
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
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_ENTRY_STATE_LEN]) -> Option<Self> {
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
            COOKIE_CONTROL_INITIAL_CLOSED if token != 0 && deadline == 0 => {
                if epoch == EGRESS_FENCE_INITIAL_COOKIE_EPOCH {
                    Self::initial_closed(token)
                } else {
                    None
                }
            }
            COOKIE_CONTROL_ACTIVE => Self::active(token, deadline, epoch),
            COOKIE_CONTROL_TERMINAL_CLOSED if deadline == 0 => Self::terminal_closed(token, epoch),
            COOKIE_CONTROL_RECLAIMING if deadline == 0 => Self::reclaiming(token, epoch),
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

/// One atomically coherent kernel-authority inspection.
///
/// Products must use this control-program result for lifecycle decisions.
/// Direct map lookups are suitable only for metadata/enumeration because
/// multiword array reads and hash-entry storage can race logical transitions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceInspection {
    current: CurrentFenceToken,
    mutation: FenceMutationAuthority,
    entry: Option<FenceCookieValue>,
}

impl FenceInspection {
    /// Construct one coherent snapshot.
    #[must_use]
    pub const fn new(
        current: CurrentFenceToken,
        mutation: FenceMutationAuthority,
        entry: Option<FenceCookieValue>,
    ) -> Self {
        Self {
            current,
            mutation,
            entry,
        }
    }

    /// Current published lifecycle authority.
    #[must_use]
    pub const fn current(self) -> CurrentFenceToken {
        self.current
    }

    /// Structural-mutation authority from the same critical section.
    #[must_use]
    pub const fn mutation(self) -> FenceMutationAuthority {
        self.mutation
    }

    /// Exact requested entry, when present.
    #[must_use]
    pub const fn entry(self) -> Option<FenceCookieValue> {
        self.entry
    }

    /// Encode the fixed Inspect response.
    #[must_use]
    pub const fn encode(self) -> [u8; EGRESS_FENCE_INSPECT_BUFFER_LEN] {
        let mut encoded = [0_u8; EGRESS_FENCE_INSPECT_BUFFER_LEN];
        encoded[0] = INSPECTION_MAGIC[0];
        encoded[1] = INSPECTION_MAGIC[1];
        encoded[2] = INSPECTION_MAGIC[2];
        encoded[3] = INSPECTION_MAGIC[3];
        let version = EGRESS_FENCE_ABI_VERSION.to_le_bytes();
        encoded[4] = version[0];
        encoded[5] = version[1];
        encoded[6] = if self.entry.is_some() { 1 } else { 0 };
        let current = self.current.encode();
        let mutation = self.mutation.encode();
        let mut index = 0;
        while index < current.len() {
            encoded[8 + index] = current[index];
            index += 1;
        }
        let mut index = 0;
        while index < mutation.len() {
            encoded[32 + index] = mutation[index];
            index += 1;
        }
        if let Some(entry) = self.entry {
            let entry = entry.encode();
            let mut index = 0;
            while index < entry.len() {
                encoded[48 + index] = entry[index];
                index += 1;
            }
        }
        encoded
    }

    /// Decode an exact canonical Inspect response.
    #[must_use]
    pub const fn decode(encoded: &[u8; EGRESS_FENCE_INSPECT_BUFFER_LEN]) -> Option<Self> {
        if encoded[0] != INSPECTION_MAGIC[0]
            || encoded[1] != INSPECTION_MAGIC[1]
            || encoded[2] != INSPECTION_MAGIC[2]
            || encoded[3] != INSPECTION_MAGIC[3]
            || u16::from_le_bytes([encoded[4], encoded[5]]) != EGRESS_FENCE_ABI_VERSION
            || encoded[6] > 1
            || encoded[7] != 0
        {
            return None;
        }
        let mut current = [0_u8; EGRESS_FENCE_CURRENT_VALUE_LEN];
        let mut index = 0;
        while index < current.len() {
            current[index] = encoded[8 + index];
            index += 1;
        }
        let current = match CurrentFenceToken::decode(&current) {
            Some(current) => current,
            None => return None,
        };
        let mut mutation = [0_u8; 16];
        let mut index = 0;
        while index < mutation.len() {
            mutation[index] = encoded[32 + index];
            index += 1;
        }
        let mutation = match FenceMutationAuthority::decode(&mutation) {
            Some(mutation) => mutation,
            None => return None,
        };
        let mut entry = [0_u8; EGRESS_FENCE_COOKIE_VALUE_LEN];
        let mut index = 0;
        while index < entry.len() {
            entry[index] = encoded[48 + index];
            index += 1;
        }
        let entry = if encoded[6] == 0 {
            let mut index = 0;
            while index < entry.len() {
                if entry[index] != 0 {
                    return None;
                }
                index += 1;
            }
            None
        } else {
            match FenceCookieValue::decode(&entry) {
                Some(entry) => Some(entry),
                None => return None,
            }
        };
        let mut index = 88;
        while index < encoded.len() {
            if encoded[index] != 0 {
                return None;
            }
            index += 1;
        }
        Some(Self::new(current, mutation, entry))
    }
}

impl fmt::Debug for FenceInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FenceInspection")
            .field("current", &self.current)
            .field("mutation", &self.mutation)
            .field("entry_present", &self.entry.is_some())
            .finish()
    }
}

/// Redaction-safe root-cgroup decision for traffic in or outside the fence domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    /// Packet is provably unrelated to the protected endpoint.
    PassUnrelated,
    /// Packet is admitted under an unexpired cookie deadline.
    Allow,
    /// Protected packet did not carry a usable socket cookie.
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
            Self::DropCookieZero => Some(COUNTER_COOKIE_ZERO),
            Self::DropMissing => Some(COUNTER_COOKIE_MISSING),
            Self::DropClosed => Some(COUNTER_CLOSED),
            Self::DropExpired => Some(COUNTER_EXPIRED),
            Self::DropMalformed => Some(COUNTER_MALFORMED),
            Self::DropStaleToken => Some(COUNTER_STALE_TOKEN),
        }
    }

    /// Whether the cgroup-skb program must deny the send.
    #[must_use]
    pub const fn must_drop(self) -> bool {
        !matches!(self, Self::PassUnrelated | Self::Allow)
    }
}

/// Packet-side inputs to one classifier decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketFenceContext {
    attachment_identity_valid: bool,
    socket_endpoint_matches: bool,
    endpoint_disposition: PacketEndpointDisposition,
    socket_cookie: u64,
}

impl PacketFenceContext {
    /// Build packet-side decision context.
    #[must_use]
    pub const fn new(
        attachment_identity_valid: bool,
        socket_endpoint_matches: bool,
        endpoint_disposition: PacketEndpointDisposition,
        socket_cookie: u64,
    ) -> Self {
        Self {
            attachment_identity_valid,
            socket_endpoint_matches,
            endpoint_disposition,
            socket_cookie,
        }
    }
}

impl fmt::Debug for PacketFenceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketFenceContext")
            .field("attachment_identity_valid", &self.attachment_identity_valid)
            .field("socket_endpoint_matches", &self.socket_endpoint_matches)
            .field("endpoint_disposition", &self.endpoint_disposition)
            .field("socket_cookie_present", &(self.socket_cookie != 0))
            .finish()
    }
}

/// Globally serialized authority snapshot for one classifier decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FenceAuthoritySnapshot {
    entry: Option<FenceEntry>,
    current_durable_fence_token: u64,
    current_registered_socket_cookie: u64,
    now_boot_ns: u64,
}

impl FenceAuthoritySnapshot {
    /// Build an authority snapshot copied while the global current-token lock
    /// is held.
    #[must_use]
    pub const fn new(
        entry: Option<FenceEntry>,
        current_durable_fence_token: u64,
        current_registered_socket_cookie: u64,
        now_boot_ns: u64,
    ) -> Self {
        Self {
            entry,
            current_durable_fence_token,
            current_registered_socket_cookie,
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
            .field(
                "current_registered_socket_cookie_present",
                &(self.current_registered_socket_cookie != 0),
            )
            .field("clock_present", &(self.now_boot_ns != 0))
            .finish()
    }
}

/// Apply the fail-closed fence decision after packet endpoint parsing.
///
/// A protected packet is UDP sourced from the configured exact local
/// endpoint. Provably unrelated traffic passes. Any packet whose relationship
/// to that endpoint cannot be proven is conservatively denied.
#[must_use]
pub const fn decide_egress(
    packet: PacketFenceContext,
    authority: FenceAuthoritySnapshot,
) -> FenceVerdict {
    if !packet.attachment_identity_valid {
        return FenceVerdict::DropMalformed;
    }
    if !packet.socket_endpoint_matches {
        match packet.endpoint_disposition {
            PacketEndpointDisposition::Unrelated => return FenceVerdict::PassUnrelated,
            PacketEndpointDisposition::Indeterminate => return FenceVerdict::DropMalformed,
            PacketEndpointDisposition::Protected => {}
        }
    }
    if packet.socket_cookie == 0 {
        return FenceVerdict::DropCookieZero;
    }
    let Some(entry) = authority.entry else {
        return FenceVerdict::DropMissing;
    };
    if authority.current_durable_fence_token == 0
        || authority.current_registered_socket_cookie == 0
        || packet.socket_cookie != authority.current_registered_socket_cookie
        || entry.durable_fence_token() != authority.current_durable_fence_token
    {
        return FenceVerdict::DropStaleToken;
    }
    if !matches!(entry.state(), FenceEntryState::Active) {
        return FenceVerdict::DropClosed;
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

    const ROOT_CGROUP_ID: u64 = 1;
    const CAPACITY: u32 = EGRESS_FENCE_MAX_COOKIE_ENTRIES;
    const COOKIE: u64 = 13;
    const TOKEN: u64 = 9;

    fn ipv4_endpoint() -> ProtectedEndpoint {
        ProtectedEndpoint::ipv4([192, 0, 2, 10], 2_123)
            .expect("documentation address is a usable fixture")
    }

    #[test]
    fn config_and_cookie_encodings_are_canonical() {
        let config =
            FenceConfig::new(ipv4_endpoint(), ROOT_CGROUP_ID, CAPACITY).expect("canonical fixture");
        let encoded = config.encode();
        assert_eq!(&encoded[8..10], &[0x08, 0x4b], "port is network order");
        assert_eq!(&encoded[24..28], &[192, 0, 2, 10]);
        assert_eq!(&encoded[28..40], &[0; 12]);
        assert_eq!(FenceConfig::decode(&encoded), Some(config));

        let closed = FenceEntry::terminal_closed(TOKEN, 3).expect("nonzero terminal epoch");
        assert_eq!(FenceEntry::decode(&closed.encode()), Some(closed));
        let initial = FenceEntry::initial_closed(TOKEN).expect("nonzero initial token");
        assert_eq!(FenceEntry::decode(&initial.encode()), Some(initial));
        let active = FenceEntry::active(TOKEN, 10, 2).expect("nonzero active fixture");
        assert_eq!(FenceEntry::decode(&active.encode()), Some(active));
        let reclaiming = FenceEntry::reclaiming(TOKEN, 3).expect("nonzero reclaiming fixture");
        assert_eq!(FenceEntry::decode(&reclaiming.encode()), Some(reclaiming));
        let cookie_key = FenceCookieKey::new(COOKIE, TOKEN).expect("nonzero lifecycle key");
        assert_eq!(
            FenceCookieKey::decode(&cookie_key.encode()),
            Some(cookie_key)
        );
        let cookie_value =
            FenceCookieValue::new(cookie_key, active).expect("matching redundant token");
        assert_eq!(
            FenceCookieValue::decode(&cookie_value.encode()),
            Some(cookie_value)
        );
        assert!(FenceCookieValue::new(
            FenceCookieKey::new(COOKIE, TOKEN + 1).expect("nonzero mismatched key"),
            active,
        )
        .is_none());
        let mut reused_identity = cookie_value.encode();
        reused_identity[8] ^= 1;
        let decoded_reuse =
            FenceCookieValue::decode(&reused_identity).expect("other identity remains canonical");
        assert_ne!(decoded_reuse.key(), cookie_key);
        assert!(FenceCookieKey::new(0, TOKEN).is_none());
        assert!(FenceCookieKey::new(COOKIE, 0).is_none());
        assert_eq!(
            std::format!("{cookie_key:?}"),
            "FenceCookieKey { socket_cookie_present: true, durable_fence_token_present: true }"
        );

        let current = CurrentFenceToken::lifecycle_open(TOKEN).expect("odd lifecycle token");
        assert_eq!(CurrentFenceToken::decode(&current.encode()), Some(current));
        let registered =
            CurrentFenceToken::registered(TOKEN, COOKIE).expect("nonzero registration");
        assert_eq!(
            CurrentFenceToken::decode(&registered.encode()),
            Some(registered)
        );
        assert_eq!(
            CurrentFenceToken::decode(&[0; EGRESS_FENCE_CURRENT_VALUE_LEN]),
            Some(CurrentFenceToken::initial())
        );

        let command = ControlCommand::new(
            ControlOperation::Activate,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            10,
            1,
        )
        .expect("canonical command");
        assert_eq!(ControlCommand::decode(&command.encode()), Some(command));
    }

    #[test]
    fn config_rejects_every_noncanonical_field_and_address_shape() {
        let config =
            FenceConfig::new(ipv4_endpoint(), ROOT_CGROUP_ID, CAPACITY).expect("canonical fixture");
        let encoded = config.encode();
        for offset in [0, 4, 6, 13, 16] {
            let mut mutated = encoded;
            mutated[offset] = 0;
            assert!(
                FenceConfig::decode(&mutated).is_none(),
                "required field at offset {offset} must be canonical"
            );
        }
        for offset in [7, 10, 11, 28, 39] {
            let mut mutated = encoded;
            mutated[offset] = 1;
            assert!(
                FenceConfig::decode(&mutated).is_none(),
                "reserved/IPv4-tail byte {offset} must be zero"
            );
        }
        assert!(
            FenceConfig::new(ipv4_endpoint(), ROOT_CGROUP_ID, CAPACITY - 1).is_none(),
            "production capacity is frozen"
        );
        let mut wrong_capacity = encoded;
        wrong_capacity[12..16].copy_from_slice(&(CAPACITY - 1).to_le_bytes());
        assert!(
            FenceConfig::decode(&wrong_capacity).is_none(),
            "encoded capacity must equal the production map capacity"
        );
        let mut wrong_family = encoded;
        wrong_family[6] = 5;
        assert!(FenceConfig::decode(&wrong_family).is_none());
        let mut zero_port = encoded;
        zero_port[8] = 0;
        zero_port[9] = 0;
        assert!(FenceConfig::decode(&zero_port).is_none());

        let mut swapped_port = encoded;
        swapped_port.swap(8, 9);
        let decoded = FenceConfig::decode(&swapped_port)
            .expect("byte-swapped bytes are a different canonical nonzero UDP port");
        assert_ne!(
            decoded, config,
            "network-order mutation cannot preserve identity"
        );

        assert!(ProtectedEndpoint::ipv4([0, 0, 0, 0], 2_123).is_none());
        assert!(ProtectedEndpoint::ipv4([224, 0, 0, 1], 2_123).is_none());
        assert!(ProtectedEndpoint::ipv4([255, 255, 255, 255], 2_123).is_none());
        assert!(ProtectedEndpoint::ipv4([192, 0, 2, 10], 0).is_none());
        assert!(ProtectedEndpoint::ipv6([0; 16], 2_123).is_none());
        let mut multicast_v6 = [0_u8; 16];
        multicast_v6[0] = 0xff;
        assert!(ProtectedEndpoint::ipv6(multicast_v6, 2_123).is_none());
        let mut mapped_v6 = [0_u8; 16];
        mapped_v6[10] = 0xff;
        mapped_v6[11] = 0xff;
        mapped_v6[12..16].copy_from_slice(&[192, 0, 2, 10]);
        assert!(ProtectedEndpoint::ipv6(mapped_v6, 2_123).is_none());
        let mut link_local_v6 = [0_u8; 16];
        link_local_v6[0] = 0xfe;
        link_local_v6[1] = 0x80;
        link_local_v6[15] = 1;
        assert!(
            ProtectedEndpoint::ipv6(link_local_v6, 2_123).is_none(),
            "link-local endpoints require scope identity absent from this ABI"
        );
        link_local_v6[1] = 0xbf;
        assert!(ProtectedEndpoint::ipv6(link_local_v6, 2_123).is_none());
        link_local_v6[1] = 0xc0;
        assert!(
            ProtectedEndpoint::ipv6(link_local_v6, 2_123).is_some(),
            "the rejection is exactly fe80::/10"
        );

        let global_v6 = ProtectedEndpoint::ipv6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            2_123,
        )
        .expect("global documentation endpoint");
        let mut encoded_v6 = FenceConfig::new(global_v6, ROOT_CGROUP_ID, CAPACITY)
            .expect("canonical IPv6 configuration")
            .encode();
        encoded_v6[24..40].fill(0);
        encoded_v6[24] = 0xfe;
        encoded_v6[25] = 0x80;
        encoded_v6[39] = 1;
        assert!(
            FenceConfig::decode(&encoded_v6).is_none(),
            "decoding rejects scoped IPv6 endpoints"
        );
        encoded_v6[25] = 0xbf;
        assert!(
            FenceConfig::decode(&encoded_v6).is_none(),
            "decoding rejects the upper edge of the scoped range"
        );
        encoded_v6[25] = 0xc0;
        assert!(
            FenceConfig::decode(&encoded_v6).is_some(),
            "decoding accepts the adjacent unscoped range"
        );
    }

    #[test]
    fn endpoint_match_requires_cookie_without_any_mark_selector() {
        let active = FenceEntry::active(TOKEN, 10, 2).expect("nonzero active fixture");
        let authority = FenceAuthoritySnapshot::new(Some(active), TOKEN, COOKIE, 9);
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(true, false, PacketEndpointDisposition::Protected, COOKIE,),
                authority,
            ),
            FenceVerdict::Allow
        );
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(true, false, PacketEndpointDisposition::Unrelated, 0),
                authority,
            ),
            FenceVerdict::PassUnrelated
        );
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(true, true, PacketEndpointDisposition::Unrelated, COOKIE,),
                authority,
            ),
            FenceVerdict::Allow,
            "a protected bound socket remains gated after SNAT rewrites its tuple"
        );
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(
                    true,
                    false,
                    PacketEndpointDisposition::Indeterminate,
                    COOKIE,
                ),
                authority,
            ),
            FenceVerdict::DropMalformed
        );
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(true, false, PacketEndpointDisposition::Protected, 0),
                authority,
            ),
            FenceVerdict::DropCookieZero
        );
    }

    #[test]
    fn equality_at_deadline_is_expired() {
        let active = FenceEntry::active(TOKEN, 10, 2).expect("nonzero active fixture");
        assert_eq!(
            decide_egress(
                PacketFenceContext::new(true, false, PacketEndpointDisposition::Protected, COOKIE,),
                FenceAuthoritySnapshot::new(Some(active), TOKEN, COOKIE, 10),
            ),
            FenceVerdict::DropExpired
        );
    }

    #[test]
    fn refresh_clock_observations_cannot_resurrect_an_expired_entry() {
        assert_eq!(
            evaluate_refresh_deadlines(99, 100, 200),
            RefreshDeadlineDecision::Apply,
            "phase-two observation still precedes the old deadline"
        );
        assert_eq!(
            evaluate_refresh_deadlines(100, 100, 200),
            RefreshDeadlineDecision::PriorExpired,
            "old-only crossing at final completion is terminal"
        );
        assert_eq!(
            evaluate_refresh_deadlines(99, 100, 99),
            RefreshDeadlineDecision::RequestedDeadlineInvalid
        );
        assert_eq!(
            evaluate_refresh_deadlines(99, 100, 99 + EGRESS_FENCE_MAX_GATE_LIFETIME_NS + 1),
            RefreshDeadlineDecision::RequestedDeadlineInvalid
        );
        assert_eq!(
            evaluate_refresh_deadlines(50, 100, 99),
            RefreshDeadlineDecision::DeadlineRegressed
        );
    }

    #[test]
    fn control_command_operations_reject_every_noncanonical_field_shape() {
        let publish = ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            0,
            9,
            0,
            0,
        )
        .expect("canonical publication");
        let retirement = ControlCommand::new(
            ControlOperation::PublishRetirement,
            ROOT_CGROUP_ID,
            0,
            10,
            0,
            0,
        )
        .expect("canonical retirement");
        let register = ControlCommand::new(
            ControlOperation::Register,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            0,
            0,
        )
        .expect("canonical registration");
        let activate = ControlCommand::new(
            ControlOperation::Activate,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            10,
            1,
        )
        .expect("canonical activation");
        let refresh = ControlCommand::new(
            ControlOperation::Refresh,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            10,
            1,
        )
        .expect("canonical refresh");
        let close =
            ControlCommand::new(ControlOperation::Close, ROOT_CGROUP_ID, COOKIE, TOKEN, 0, 1)
                .expect("canonical close");
        let reclaim = ControlCommand::new(
            ControlOperation::Reclaim,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            0,
            1,
        )
        .expect("canonical reclaim");
        let inspect = ControlCommand::new(
            ControlOperation::Inspect,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            0,
            0,
        )
        .expect("canonical inspection");
        for command in [
            publish, retirement, register, activate, refresh, close, reclaim, inspect,
        ] {
            assert_eq!(ControlCommand::decode(&command.encode()), Some(command));
        }
        assert!(inspect.encode_inspect_request().is_some());

        assert!(ControlCommand::new(ControlOperation::PublishLifecycle, 0, 0, 9, 0, 0).is_none());
        assert!(ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            0,
            0,
        )
        .is_none());
        assert!(ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            0,
            0,
            0,
            0
        )
        .is_none());
        assert!(ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            0,
            10,
            0,
            0
        )
        .is_none());
        assert!(ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            0,
            9,
            10,
            0
        )
        .is_none());
        assert!(ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            0,
            9,
            0,
            1
        )
        .is_none());
        assert!(ControlCommand::new(
            ControlOperation::PublishRetirement,
            ROOT_CGROUP_ID,
            0,
            9,
            0,
            0
        )
        .is_none());

        assert!(
            ControlCommand::new(ControlOperation::Register, ROOT_CGROUP_ID, 0, TOKEN, 0, 0)
                .is_none()
        );
        assert!(
            ControlCommand::new(ControlOperation::Register, ROOT_CGROUP_ID, COOKIE, 0, 0, 0)
                .is_none()
        );
        assert!(ControlCommand::new(
            ControlOperation::Register,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            1,
            0
        )
        .is_none());
        assert!(ControlCommand::new(
            ControlOperation::Register,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            0,
            1
        )
        .is_none());

        for operation in [ControlOperation::Activate, ControlOperation::Refresh] {
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, 0, TOKEN, 10, 1).is_none());
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, COOKIE, 0, 10, 1).is_none());
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, COOKIE, TOKEN, 0, 1).is_none());
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, COOKIE, TOKEN, 10, 0).is_none());
        }

        for operation in [ControlOperation::Close, ControlOperation::Reclaim] {
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, 0, TOKEN, 0, 1).is_none());
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, COOKIE, 0, 0, 1).is_none());
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, COOKIE, TOKEN, 10, 1).is_none());
            assert!(ControlCommand::new(operation, ROOT_CGROUP_ID, COOKIE, TOKEN, 0, 0).is_none());
        }
    }

    #[test]
    fn encoded_control_field_mutations_fail_canonical_decode() {
        let activate = ControlCommand::new(
            ControlOperation::Activate,
            ROOT_CGROUP_ID,
            COOKIE,
            TOKEN,
            10,
            1,
        )
        .expect("canonical activation")
        .encode();
        for offset in [0, 4, 6, 8, 16, 24, 32, 40] {
            let mut mutated = activate;
            mutated[offset] = 0;
            assert!(
                ControlCommand::decode(&mutated).is_none(),
                "offset {offset} must be canonical"
            );
        }
        let mut mutated = activate;
        mutated[7] = 1;
        assert!(ControlCommand::decode(&mutated).is_none());

        let publish = ControlCommand::new(
            ControlOperation::PublishLifecycle,
            ROOT_CGROUP_ID,
            0,
            TOKEN,
            0,
            0,
        )
        .expect("canonical publication")
        .encode();
        for offset in [16, 32, 40] {
            let mut mutated = publish;
            mutated[offset] = 1;
            assert!(
                ControlCommand::decode(&mutated).is_none(),
                "publication offset {offset} must remain zero"
            );
        }

        let close =
            ControlCommand::new(ControlOperation::Close, ROOT_CGROUP_ID, COOKIE, TOKEN, 0, 1)
                .expect("canonical close")
                .encode();
        let mut close_with_deadline = close;
        close_with_deadline[32] = 1;
        assert!(ControlCommand::decode(&close_with_deadline).is_none());
    }
}
