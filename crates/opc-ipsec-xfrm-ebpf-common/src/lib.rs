//! Shared layouts for the XFRM eBPF companions.
//!
//! Linux XFRM can set masked output `skb->mark` bits on an SA but has no UAPI
//! attribute for a fixed outer DSCP. The host backend encodes a presence bit
//! plus a six-bit DSCP into a caller-reserved seven-bit mark window. The tc
//! program validates that token, stamps the outer IPv4/IPv6 DS field while
//! preserving ECN, then clears only its reserved bits.
//!
//! The observation layouts are a private host/kernel ABI for the authenticated
//! ESP peer source. Address-bearing structures intentionally do not implement
//! `Debug`: callers must project them into the redacted public observation
//! types instead of accidentally logging kernel routing facts.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Number of contiguous skb-mark bits reserved by the companion.
pub const MARK_TOKEN_BITS: u8 = 7;
/// Largest valid starting bit for a seven-bit window in a `u32` mark.
pub const MAX_MARK_SHIFT: u8 = 32 - MARK_TOKEN_BITS;
/// Encoded companion configuration map value length.
pub const MARK_CONFIG_VALUE_LEN: usize = 8;

/// BPF single-slot configuration map name.
pub const MAP_MARK_CONFIG: &str = "XFRM_DSCP_CFG";
/// tc egress classifier program name.
pub const PROG_EGRESS_DSCP: &str = "opc_xfrm_dscp";

/// fentry program that detects configurations the observation source cannot
/// authoritatively cover.
pub const PROG_ESP_PEER_GUARD: &str = "opc_xfrm_guard";
/// fexit program that emits observations only after the final replay recheck.
pub const PROG_ESP_PEER_OBSERVATION: &str = "opc_xfrm_obs";
/// fentry program that poisons authority before an XFRM state insertion.
pub const PROG_ESP_PEER_INSERT: &str = "opc_xfrm_insert";
/// fentry program that poisons authority before an XFRM state deletion.
pub const PROG_ESP_PEER_DELETE: &str = "opc_xfrm_delete";
/// fentry program that poisons authority before an XFRM state update.
pub const PROG_ESP_PEER_UPDATE: &str = "opc_xfrm_update";

/// Exact-SA registration map name.
pub const MAP_ESP_PEER_REGISTRATIONS: &str = "XFRM_OBS_REGS";
/// Mutable per-SA cursor, loss, and authority state map name.
pub const MAP_ESP_PEER_STATES: &str = "XFRM_OBS_STATE";
/// Authenticated peer-observation ring-buffer map name.
pub const MAP_ESP_PEER_EVENTS: &str = "XFRM_OBS_EVENTS";
/// Per-CPU diagnostic counters map name.
pub const MAP_ESP_PEER_STATS: &str = "XFRM_OBS_STATS";
/// Source-wide terminal state map name.
pub const MAP_ESP_PEER_SOURCE: &str = "XFRM_OBS_SOURCE";
/// Per-SA kernel-lifecycle generation map name.
pub const MAP_ESP_PEER_LIFECYCLES: &str = "XFRM_OBS_LIFE";

/// Maximum exact inbound SAs tracked by one observation source.
pub const ESP_PEER_OBSERVATION_MAX_SAS: u32 = 1024;
/// Ring-buffer capacity in bytes.
pub const ESP_PEER_OBSERVATION_RING_BYTES: u32 = 256 * 1024;
/// Canonical encoded exact-SA key length.
pub const ESP_PEER_OBSERVATION_SA_KEY_LEN: usize = 48;
/// Canonical encoded registration value length.
pub const ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN: usize = 32;
/// Canonical encoded kernel-lifecycle value length.
pub const ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN: usize = 8;
/// Canonical encoded per-lifecycle state key length.
pub const ESP_PEER_OBSERVATION_STATE_KEY_LEN: usize = 56;
/// Canonical encoded per-lifecycle state value length.
pub const ESP_PEER_OBSERVATION_STATE_LEN: usize = 56;
/// Canonical encoded ring-buffer record length.
pub const ESP_PEER_OBSERVATION_RECORD_LEN: usize = 112;
/// Canonical encoded source state length.
pub const ESP_PEER_OBSERVATION_SOURCE_STATE_LEN: usize = 16;
/// Map direction value for an inbound XFRM SA.
pub const ESP_PEER_DIRECTION_INBOUND: u8 = 1;

/// No terminal authority-loss condition has been observed.
pub const ESP_PEER_AUTHORITY_OK: u32 = 0;
/// Hardware or packet XFRM offload bypasses the qualified replay hook.
pub const ESP_PEER_AUTHORITY_OFFLOAD: u32 = 1;
/// The registered SA has no enabled anti-replay window.
pub const ESP_PEER_AUTHORITY_REPLAY_DISABLED: u32 = 2;
/// The registered SA has neither integrity authentication nor AEAD.
pub const ESP_PEER_AUTHORITY_UNAUTHENTICATED: u32 = 3;
/// The registered SA is not UDP-encapsulated ESP.
pub const ESP_PEER_AUTHORITY_UNSUPPORTED_ENCAP: u32 = 4;
/// The registered kernel object is not an inbound ESP SA.
pub const ESP_PEER_AUTHORITY_UNSUPPORTED_SA: u32 = 5;
/// The outer packet or source tuple could not be parsed exactly.
pub const ESP_PEER_AUTHORITY_MALFORMED_PACKET: u32 = 6;
/// Required per-SA mutable state was absent while a registration was live.
pub const ESP_PEER_AUTHORITY_STATE_MISSING: u32 = 7;
/// The SA's network-namespace identity could not be obtained.
pub const ESP_PEER_AUTHORITY_NAMESPACE_UNKNOWN: u32 = 8;
/// A lifecycle cursor, loss counter, or active-hook count exhausted its range.
pub const ESP_PEER_AUTHORITY_COUNTER_EXHAUSTED: u32 = 9;
/// The exact kernel XFRM state was inserted, deleted, or updated.
pub const ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED: u32 = 10;

/// Number of diagnostic counter slots exported by the observation object.
pub const ESP_PEER_STAT_COUNT: u32 = 12;
/// Number of final-replay-recheck calls that returned success.
pub const ESP_PEER_STAT_RECHECK_ACCEPTED: u32 = 0;
/// Number of accepted packets that matched no exact registration.
pub const ESP_PEER_STAT_UNREGISTERED: u32 = 1;
/// Number of accepted packets that matched the kernel's current peer tuple.
pub const ESP_PEER_STAT_CURRENT_SOURCE: u32 = 2;
/// Number of repeated observations suppressed for the same changed tuple.
pub const ESP_PEER_STAT_DUPLICATE_SOURCE: u32 = 3;
/// Number of changed-source records submitted to the ring buffer.
pub const ESP_PEER_STAT_EVENTS: u32 = 4;
/// Number of changed-source records lost because the ring buffer was full.
pub const ESP_PEER_STAT_RING_DROPPED: u32 = 5;
/// Number of packets rejected because their outer tuple was malformed.
pub const ESP_PEER_STAT_PARSE_FAILED: u32 = 6;
/// Number of registered SAs observed using XFRM offload.
pub const ESP_PEER_STAT_OFFLOAD: u32 = 7;
/// Number of registered SAs observed without anti-replay protection.
pub const ESP_PEER_STAT_REPLAY_DISABLED: u32 = 8;
/// Number of registered SAs observed without integrity or AEAD protection.
pub const ESP_PEER_STAT_UNAUTHENTICATED: u32 = 9;
/// Number of registered SAs with an unsupported protocol or encapsulation.
pub const ESP_PEER_STAT_UNSUPPORTED_SA: u32 = 10;
/// Number of internal state/namespace failures that terminated authority.
pub const ESP_PEER_STAT_INTERNAL_FAILURE: u32 = 11;

/// Ethernet header length at the tc attach point.
pub const ETH_HDR_LEN: usize = 14;
/// IPv4 EtherType.
pub const ETH_P_IPV4: u16 = 0x0800;
/// IPv6 EtherType.
pub const ETH_P_IPV6: u16 = 0x86dd;
/// Minimum IPv4 header length.
pub const IPV4_HEADER_LEN: usize = 20;
/// Fixed IPv6 base-header length.
pub const IPV6_HEADER_LEN: usize = 40;
/// IP protocol number for ESP.
pub const IPPROTO_ESP: u8 = 50;
/// IP protocol number for UDP (ESP-in-UDP/NAT-T).
pub const IPPROTO_UDP: u8 = 17;
/// UDP header length.
pub const UDP_HEADER_LEN: usize = 8;
/// ESP SPI length used to reject the NAT-T non-ESP marker.
pub const ESP_SPI_LEN: usize = 4;

/// Exact kernel identity used to register one inbound ESP SA.
///
/// The byte codec uses little endian for scalar storage because the committed
/// object targets `bpfel`; `spi_be` retains the kernel's raw `__be32` memory
/// representation. IPv4 destinations occupy the first four address bytes and
/// require the remaining twelve bytes to be zero.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationSaKey {
    /// Stable network-namespace cookie containing the SA.
    ///
    /// The host obtains the same value with `SO_NETNS_COOKIE`; a task's
    /// current namespace or namespace inode is not an equivalent identity.
    pub net_cookie: u64,
    /// XFRM lookup-mark value.
    pub mark_value: u32,
    /// XFRM lookup-mark mask.
    pub mark_mask: u32,
    /// XFRM interface identifier, or zero when unbound.
    pub if_id: u32,
    /// ESP SPI in kernel/network byte order.
    pub spi_be: u32,
    /// Outer address family (`AF_INET` or `AF_INET6`).
    pub family: u16,
    /// XFRM protocol number; authoritative registrations require ESP.
    pub protocol: u8,
    /// Direction; authoritative registrations require inbound.
    pub direction: u8,
    /// Reserved bytes; writers must set them to zero.
    pub reserved: [u8; 4],
    /// Canonical outer destination address.
    pub destination: [u8; 16],
}

/// Immutable authority minted by the host for one exact registration.
///
/// Publication is deliberately staged: establish a nonzero lifecycle
/// generation, insert zeroed state under `(SA, epoch)`, publish this value
/// unarmed, perform a second exact GETSA plus stable-generation check, and only
/// then replace the value with `armed = 1`. Teardown deletes this registration
/// first, polls the old state's opaque atomic `active` word with a bounded wait
/// until zero, drains records and final loss/terminal values, and only then
/// removes old state and lifecycle generation. A timeout or read failure is
/// terminal authority loss.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationRegistrationValue {
    /// Opaque process-local source scope.
    pub source_scope: u64,
    /// Opaque nonzero registration-lifecycle epoch.
    pub epoch: u64,
    /// Nonzero generation from the kernel-lifecycle poison map.
    pub lifecycle_generation: u64,
    /// Zero while the host performs its second exact GETSA; one only after
    /// that readback and a stable generation check succeed.
    pub armed: u64,
}

/// Monotonic generation invalidated before a same-key kernel SA mutation.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationLifecycleValue {
    /// Opaque, nonzero, non-wrapping generation.
    pub generation: u64,
}

/// Key for mutable state belonging to one exact registration lifecycle.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationStateKey {
    /// Exact SA identity.
    pub sa: EspPeerObservationSaKey,
    /// Opaque nonzero registration-lifecycle epoch.
    pub epoch: u64,
}

/// Mutable kernel-side state for one exact lifecycle.
///
/// The host inserts a zeroed value before publishing the matching
/// registration and removes the registration before removing this value.
/// The leading scalar fields are independently atomic, not one compound
/// snapshot. While a registration is live, consumers must not infer a
/// cross-field point in time. After unpublishing and observing `active == 0`,
/// cursor, loss, and authority are stable for the final read.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationState {
    /// Opaque atomic admission word for this exact registration lifecycle.
    ///
    /// The low bits count admitted hooks and the kernel-private high bit
    /// serializes duplicate suppression. Userspace must only distinguish zero
    /// from nonzero. Teardown unpublishes the immutable registration, then
    /// performs bounded polling until the complete word reaches zero.
    pub active: u64,
    /// Monotonic cursor allocated before each ring-buffer submission.
    ///
    /// This field is updated atomically and interpreted independently.
    pub cursor: u64,
    /// Monotonic producer-side ring-buffer loss count.
    ///
    /// This field is updated atomically and interpreted independently.
    pub dropped: u64,
    /// Sticky `ESP_PEER_AUTHORITY_*` terminal reason.
    ///
    /// The eBPF writer sets this once with an atomic compare-and-swap.
    pub authority_lost: u64,
    /// Address family of `last_source_address`.
    last_source_family: u16,
    /// Network-byte-order port of the last changed source.
    last_source_port_be: u16,
    /// One when the last-source tuple is populated.
    last_source_valid: u8,
    /// Reserved bytes; writers must set them to zero.
    reserved: [u8; 3],
    /// Last changed source successfully submitted to the ring buffer.
    ///
    /// A failed submission must not update this field, so a later
    /// authenticated packet from the same tuple retries after capacity
    /// recovers.
    last_source_address: [u8; 16],
}

impl EspPeerObservationState {
    /// Construct the only valid host-side initial state.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            active: 0,
            cursor: 0,
            dropped: 0,
            authority_lost: ESP_PEER_AUTHORITY_OK as u64,
            last_source_family: 0,
            last_source_port_be: 0,
            last_source_valid: 0,
            reserved: [0; 3],
            last_source_address: [0; 16],
        }
    }

    /// Clear only the eBPF-private duplicate-suppression tuple.
    ///
    /// This preserves all independently atomic public state. A host that
    /// writes the returned whole value back to the map must first unpublish
    /// the registration and observe the complete `active` word at zero so it
    /// cannot overwrite a concurrent eBPF update.
    #[must_use]
    pub const fn clear_last_source(mut self) -> Self {
        self.last_source_family = 0;
        self.last_source_port_be = 0;
        self.last_source_valid = 0;
        self.reserved = [0; 3];
        self.last_source_address = [0; 16];
        self
    }
}

/// One ring-buffer record tied to a source scope and registration epoch.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationRecord {
    /// Exact SA identity observed by the kernel.
    pub key: EspPeerObservationSaKey,
    /// Opaque process-local source scope copied from registration.
    pub source_scope: u64,
    /// Opaque registration-lifecycle epoch copied from registration.
    pub epoch: u64,
    /// Per-SA monotonic event cursor.
    pub cursor: u64,
    /// Producer-side cumulative loss snapshot for this record.
    ///
    /// This may exceed this record's cursor when contending producers allocate
    /// and account later cursor losses outside the source-tuple gate. Only a
    /// quiescent global state snapshot can reconcile cursor, loss, and
    /// successfully delivered record counts.
    pub dropped_total: u64,
    /// ESP sequence low word in host byte order.
    pub sequence_low: u32,
    /// ESP ESN high word in host byte order, or zero for non-ESN SAs.
    pub sequence_high: u32,
    /// Kernel ingress interface index from `skb_iif`.
    pub ingress_ifindex: u32,
    /// Address family of `outer_source_address`.
    pub outer_source_family: u16,
    /// Observed UDP source port in host byte order.
    pub outer_source_port: u16,
    /// Observed outer source address.
    pub outer_source_address: [u8; 16],
}

/// Source-wide fail-closed state for failures that cannot be attributed to a
/// per-SA state map entry.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EspPeerObservationSourceState {
    /// Sticky `ESP_PEER_AUTHORITY_*` terminal reason.
    ///
    /// The eBPF writer sets this once with an atomic compare-and-swap.
    pub authority_lost: u64,
    /// Monotonic count of source-wide terminal detections.
    pub failures: u64,
}

impl EspPeerObservationSourceState {
    /// Construct the only valid host-side initial source state.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            authority_lost: ESP_PEER_AUTHORITY_OK as u64,
            failures: 0,
        }
    }
}

impl EspPeerObservationSaKey {
    /// Encode the exact key into its canonical map-key bytes.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_SA_KEY_LEN] {
        let mut encoded = [0; ESP_PEER_OBSERVATION_SA_KEY_LEN];
        put_u64(&mut encoded, 0, self.net_cookie);
        put_u32(&mut encoded, 8, self.mark_value);
        put_u32(&mut encoded, 12, self.mark_mask);
        put_u32(&mut encoded, 16, self.if_id);
        put_u32(&mut encoded, 20, self.spi_be);
        put_u16(&mut encoded, 24, self.family);
        encoded[26] = self.protocol;
        encoded[27] = self.direction;
        encoded[28..32].copy_from_slice(&self.reserved);
        encoded[32..48].copy_from_slice(&self.destination);
        encoded
    }

    /// Decode and validate one canonical map key.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_SA_KEY_LEN]) -> Option<Self> {
        let mut reserved = [0; 4];
        reserved.copy_from_slice(&encoded[28..32]);
        let mut destination = [0; 16];
        destination.copy_from_slice(&encoded[32..48]);
        let key = Self {
            net_cookie: get_u64(encoded, 0),
            mark_value: get_u32(encoded, 8),
            mark_mask: get_u32(encoded, 12),
            if_id: get_u32(encoded, 16),
            spi_be: get_u32(encoded, 20),
            family: get_u16(encoded, 24),
            protocol: encoded[26],
            direction: encoded[27],
            reserved,
            destination,
        };
        key.is_valid().then_some(key)
    }

    fn is_valid(&self) -> bool {
        self.net_cookie != 0
            && self.spi_be != 0
            && self.protocol == IPPROTO_ESP
            && self.direction == ESP_PEER_DIRECTION_INBOUND
            && self.reserved == [0; 4]
            && (self.mark_value & self.mark_mask) == self.mark_value
            && valid_address(self.family, &self.destination, false)
    }
}

impl EspPeerObservationRegistrationValue {
    /// Encode the immutable registration value.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN] {
        let mut encoded = [0; ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN];
        put_u64(&mut encoded, 0, self.source_scope);
        put_u64(&mut encoded, 8, self.epoch);
        put_u64(&mut encoded, 16, self.lifecycle_generation);
        put_u64(&mut encoded, 24, self.armed);
        encoded
    }

    /// Decode a registration value, rejecting zero authority identifiers.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN]) -> Option<Self> {
        let value = Self {
            source_scope: get_u64(encoded, 0),
            epoch: get_u64(encoded, 8),
            lifecycle_generation: get_u64(encoded, 16),
            armed: get_u64(encoded, 24),
        };
        (value.source_scope != 0
            && value.epoch != 0
            && value.lifecycle_generation != 0
            && value.armed <= 1)
            .then_some(value)
    }
}

impl EspPeerObservationLifecycleValue {
    /// Encode one kernel-lifecycle generation.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN] {
        self.generation.to_le_bytes()
    }

    /// Decode a nonzero kernel-lifecycle generation.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN]) -> Option<Self> {
        let value = Self {
            generation: u64::from_le_bytes(*encoded),
        };
        (value.generation != 0).then_some(value)
    }
}

impl EspPeerObservationStateKey {
    /// Encode an exact SA-plus-epoch state key.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_STATE_KEY_LEN] {
        let mut encoded = [0; ESP_PEER_OBSERVATION_STATE_KEY_LEN];
        encoded[..ESP_PEER_OBSERVATION_SA_KEY_LEN].copy_from_slice(&self.sa.encode());
        put_u64(&mut encoded, ESP_PEER_OBSERVATION_SA_KEY_LEN, self.epoch);
        encoded
    }

    /// Decode an exact SA-plus-epoch state key.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_STATE_KEY_LEN]) -> Option<Self> {
        let mut sa = [0; ESP_PEER_OBSERVATION_SA_KEY_LEN];
        sa.copy_from_slice(&encoded[..ESP_PEER_OBSERVATION_SA_KEY_LEN]);
        let key = Self {
            sa: EspPeerObservationSaKey::decode(&sa)?,
            epoch: get_u64(encoded, ESP_PEER_OBSERVATION_SA_KEY_LEN),
        };
        (key.epoch != 0).then_some(key)
    }
}

impl EspPeerObservationState {
    /// Encode a state value suitable for map insertion or independent-field
    /// readback.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_STATE_LEN] {
        let mut encoded = [0; ESP_PEER_OBSERVATION_STATE_LEN];
        put_u64(&mut encoded, 0, self.active);
        put_u64(&mut encoded, 8, self.cursor);
        put_u64(&mut encoded, 16, self.dropped);
        put_u64(&mut encoded, 24, self.authority_lost);
        put_u16(&mut encoded, 32, self.last_source_family);
        put_u16(&mut encoded, 34, self.last_source_port_be);
        encoded[36] = self.last_source_valid;
        encoded[37..40].copy_from_slice(&self.reserved);
        encoded[40..56].copy_from_slice(&self.last_source_address);
        encoded
    }

    /// Decode one state-map read.
    ///
    /// `active`, `cursor`, `dropped`, and `authority_lost` are each atomic but
    /// are not a compound snapshot while `active` is nonzero.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_STATE_LEN]) -> Option<Self> {
        let mut reserved = [0; 3];
        reserved.copy_from_slice(&encoded[37..40]);
        let mut last_source_address = [0; 16];
        last_source_address.copy_from_slice(&encoded[40..56]);
        let value = Self {
            active: get_u64(encoded, 0),
            cursor: get_u64(encoded, 8),
            dropped: get_u64(encoded, 16),
            authority_lost: get_u64(encoded, 24),
            last_source_family: get_u16(encoded, 32),
            last_source_port_be: get_u16(encoded, 34),
            last_source_valid: encoded[36],
            reserved,
            last_source_address,
        };
        value.is_valid().then_some(value)
    }

    fn is_valid(&self) -> bool {
        // The last-source tuple is eBPF-private duplicate-suppression state.
        // Its independently updated fields can tear during a live map read,
        // so userspace deliberately does not interpret or validate it.
        self.reserved == [0; 3] && valid_authority_reason(self.authority_lost)
    }
}

impl EspPeerObservationRecord {
    /// Encode one immutable ring-buffer record.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_RECORD_LEN] {
        let mut encoded = [0; ESP_PEER_OBSERVATION_RECORD_LEN];
        encoded[..ESP_PEER_OBSERVATION_SA_KEY_LEN].copy_from_slice(&self.key.encode());
        put_u64(&mut encoded, 48, self.source_scope);
        put_u64(&mut encoded, 56, self.epoch);
        put_u64(&mut encoded, 64, self.cursor);
        put_u64(&mut encoded, 72, self.dropped_total);
        put_u32(&mut encoded, 80, self.sequence_low);
        put_u32(&mut encoded, 84, self.sequence_high);
        put_u32(&mut encoded, 88, self.ingress_ifindex);
        put_u16(&mut encoded, 92, self.outer_source_family);
        put_u16(&mut encoded, 94, self.outer_source_port);
        encoded[96..112].copy_from_slice(&self.outer_source_address);
        encoded
    }

    /// Decode and validate one immutable ring-buffer record.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_RECORD_LEN]) -> Option<Self> {
        let mut key = [0; ESP_PEER_OBSERVATION_SA_KEY_LEN];
        key.copy_from_slice(&encoded[..ESP_PEER_OBSERVATION_SA_KEY_LEN]);
        let mut outer_source_address = [0; 16];
        outer_source_address.copy_from_slice(&encoded[96..112]);
        let value = Self {
            key: EspPeerObservationSaKey::decode(&key)?,
            source_scope: get_u64(encoded, 48),
            epoch: get_u64(encoded, 56),
            cursor: get_u64(encoded, 64),
            dropped_total: get_u64(encoded, 72),
            sequence_low: get_u32(encoded, 80),
            sequence_high: get_u32(encoded, 84),
            ingress_ifindex: get_u32(encoded, 88),
            outer_source_family: get_u16(encoded, 92),
            outer_source_port: get_u16(encoded, 94),
            outer_source_address,
        };
        (value.source_scope != 0
            && value.epoch != 0
            && value.cursor != 0
            && value.ingress_ifindex != 0
            && value.outer_source_port != 0
            && value.outer_source_family == value.key.family
            && valid_address(
                value.outer_source_family,
                &value.outer_source_address,
                false,
            ))
        .then_some(value)
    }
}

impl EspPeerObservationSourceState {
    /// Encode source-wide independently atomic terminal state.
    #[must_use]
    pub fn encode(self) -> [u8; ESP_PEER_OBSERVATION_SOURCE_STATE_LEN] {
        let mut encoded = [0; ESP_PEER_OBSERVATION_SOURCE_STATE_LEN];
        put_u64(&mut encoded, 0, self.authority_lost);
        put_u64(&mut encoded, 8, self.failures);
        encoded
    }

    /// Decode independently atomic source-state fields.
    #[must_use]
    pub fn decode(encoded: &[u8; ESP_PEER_OBSERVATION_SOURCE_STATE_LEN]) -> Option<Self> {
        let value = Self {
            authority_lost: get_u64(encoded, 0),
            failures: get_u64(encoded, 8),
        };
        valid_authority_reason(value.authority_lost).then_some(value)
    }
}

fn valid_authority_reason(reason: u64) -> bool {
    reason <= u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED)
}

fn valid_address(family: u16, address: &[u8; 16], allow_unspecified: bool) -> bool {
    let family_valid = match family {
        2 => address[4..] == [0; 12],
        10 => true,
        _ => false,
    };
    family_valid && (allow_unspecified || *address != [0; 16])
}

fn put_u16<const N: usize>(target: &mut [u8; N], offset: usize, value: u16) {
    target[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32<const N: usize>(target: &mut [u8; N], offset: usize, value: u32) {
    target[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64<const N: usize>(target: &mut [u8; N], offset: usize, value: u64) {
    target[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16<const N: usize>(source: &[u8; N], offset: usize) -> u16 {
    u16::from_le_bytes([source[offset], source[offset + 1]])
}

fn get_u32<const N: usize>(source: &[u8; N], offset: usize) -> u32 {
    u32::from_le_bytes([
        source[offset],
        source[offset + 1],
        source[offset + 2],
        source[offset + 3],
    ])
}

fn get_u64<const N: usize>(source: &[u8; N], offset: usize) -> u64 {
    u64::from_le_bytes([
        source[offset],
        source[offset + 1],
        source[offset + 2],
        source[offset + 3],
        source[offset + 4],
        source[offset + 5],
        source[offset + 6],
        source[offset + 7],
    ])
}

/// Validated reserved skb-mark profile shared by host and datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkProfile {
    /// Starting bit of the seven-bit token window.
    pub shift: u8,
    /// Exact mask for the seven contiguous reserved bits.
    pub mask: u32,
}

impl MarkProfile {
    /// Derive the exact seven-bit mask for `shift`.
    #[must_use]
    pub const fn mask_for_shift(shift: u8) -> Option<u32> {
        if shift > MAX_MARK_SHIFT {
            return None;
        }
        Some(0x7f_u32 << shift)
    }

    /// Validate an explicit shift and mask pair.
    #[must_use]
    pub const fn new(shift: u8, mask: u32) -> Option<Self> {
        match Self::mask_for_shift(shift) {
            Some(expected) if expected == mask => Some(Self { shift, mask }),
            _ => None,
        }
    }

    /// Return the presence bit within the reserved token window.
    #[must_use]
    pub const fn presence_bit(self) -> u32 {
        0x40_u32 << self.shift
    }

    /// Encode one validated DSCP as a masked XFRM output-mark token.
    #[must_use]
    pub const fn encode_token(self, dscp: u8) -> Option<u32> {
        if dscp > 63 {
            return None;
        }
        Some(((dscp as u32) | 0x40) << self.shift)
    }

    /// Decode the token from a packet mark.
    #[must_use]
    pub const fn decode_token(self, mark: u32) -> MarkToken {
        let reserved = mark & self.mask;
        if reserved == 0 {
            return MarkToken::Absent;
        }
        if reserved & self.presence_bit() == 0 {
            return MarkToken::Malformed;
        }
        MarkToken::Dscp(((reserved >> self.shift) & 0x3f) as u8)
    }

    /// Clear exactly the seven reserved bits and preserve every unrelated bit.
    #[must_use]
    pub const fn clear_token(self, mark: u32) -> u32 {
        mark & !self.mask
    }

    /// Encode this profile into the pinned config-map wire layout.
    #[must_use]
    pub const fn encode(self) -> [u8; MARK_CONFIG_VALUE_LEN] {
        let mask = self.mask.to_le_bytes();
        [self.shift, 0, 0, 0, mask[0], mask[1], mask[2], mask[3]]
    }

    /// Decode and validate the pinned config-map wire layout.
    #[must_use]
    pub const fn decode(value: &[u8; MARK_CONFIG_VALUE_LEN]) -> Option<Self> {
        if value[1] != 0 || value[2] != 0 || value[3] != 0 {
            return None;
        }
        let mask = u32::from_le_bytes([value[4], value[5], value[6], value[7]]);
        Self::new(value[0], mask)
    }
}

/// Classification of this companion's reserved mark bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkToken {
    /// All reserved bits are clear; the packet is unrelated and passes.
    Absent,
    /// Reserved bits are set without the required presence bit.
    Malformed,
    /// A valid six-bit DSCP token.
    Dscp(u8),
}

/// Valid ESP carrier selected from an outer IP protocol and UDP ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspCarrier {
    /// ESP begins immediately after the outer IP header.
    Direct,
    /// ESP follows one UDP header (RFC 3948 NAT traversal).
    UdpEncapsulated,
}

/// Classify the only outer carriers eligible for DSCP stamping.
///
/// Direct ESP ignores `udp_ports`. UDP requires non-zero source and
/// destination ports so malformed/non-socket traffic cannot consume a token.
#[must_use]
pub const fn classify_esp_carrier(protocol: u8, udp_ports: [u8; 4]) -> Option<EspCarrier> {
    match protocol {
        IPPROTO_ESP => Some(EspCarrier::Direct),
        IPPROTO_UDP
            if (udp_ports[0] != 0 || udp_ports[1] != 0)
                && (udp_ports[2] != 0 || udp_ports[3] != 0) =>
        {
            Some(EspCarrier::UdpEncapsulated)
        }
        _ => None,
    }
}

/// Return whether four bytes represent a non-zero ESP SPI.
///
/// A zero word after UDP is the RFC 3948 non-ESP marker used by IKE and must
/// never be treated as transformed data traffic.
#[must_use]
pub const fn valid_esp_spi(spi: [u8; ESP_SPI_LEN]) -> bool {
    spi[0] != 0 || spi[1] != 0 || spi[2] != 0 || spi[3] != 0
}

/// Rewrite an outer IPv4 header's DSCP while preserving ECN and checksum.
///
/// The function accepts the fixed 20-byte header produced by Linux XFRM
/// tunnel mode. It fails closed for a non-IPv4/IHL-5 header or invalid DSCP.
#[must_use]
pub fn rewrite_ipv4_dscp(header: &mut [u8; IPV4_HEADER_LEN], dscp: u8) -> bool {
    if header[0] != 0x45 || dscp > 63 {
        return false;
    }
    let ecn = header[1] & 0x03;
    header[1] = (dscp << 2) | ecn;
    header[10] = 0;
    header[11] = 0;
    let checksum = ipv4_checksum(header).to_be_bytes();
    header[10] = checksum[0];
    header[11] = checksum[1];
    true
}

/// Rewrite an outer IPv6 base header's DSCP while preserving ECN/flow label.
#[must_use]
pub fn rewrite_ipv6_dscp(header: &mut [u8; IPV6_HEADER_LEN], dscp: u8) -> bool {
    if header[0] >> 4 != 6 || dscp > 63 {
        return false;
    }
    let traffic_class = ((header[0] & 0x0f) << 4) | (header[1] >> 4);
    let updated = (dscp << 2) | (traffic_class & 0x03);
    header[0] = (header[0] & 0xf0) | (updated >> 4);
    header[1] = (updated << 4) | (header[1] & 0x0f);
    true
}

fn ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut sum = 0_u32;
    let mut offset = 0;
    while offset < IPV4_HEADER_LEN {
        sum += u32::from(u16::from_be_bytes([header[offset], header[offset + 1]]));
        offset += 2;
    }
    // A fixed 20-byte header has ten words. Two carry folds are sufficient
    // for their maximum sum and keep the eBPF control-flow graph bounded.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation_key() -> EspPeerObservationSaKey {
        EspPeerObservationSaKey {
            net_cookie: 0x0102_0304_0506_0708,
            mark_value: 0x1234,
            mark_mask: 0xffff,
            if_id: 7,
            spi_be: u32::from_ne_bytes([0x01, 0x02, 0x03, 0x04]),
            family: 2,
            protocol: IPPROTO_ESP,
            direction: ESP_PEER_DIRECTION_INBOUND,
            reserved: [0; 4],
            destination: [192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn observation_abi_sizes_match_wire_lengths() {
        assert_eq!(
            core::mem::size_of::<EspPeerObservationSaKey>(),
            ESP_PEER_OBSERVATION_SA_KEY_LEN
        );
        assert_eq!(
            core::mem::size_of::<EspPeerObservationRegistrationValue>(),
            ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN
        );
        assert_eq!(
            core::mem::size_of::<EspPeerObservationLifecycleValue>(),
            ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN
        );
        assert_eq!(
            core::mem::size_of::<EspPeerObservationStateKey>(),
            ESP_PEER_OBSERVATION_STATE_KEY_LEN
        );
        assert_eq!(
            core::mem::size_of::<EspPeerObservationState>(),
            ESP_PEER_OBSERVATION_STATE_LEN
        );
        assert_eq!(
            core::mem::size_of::<EspPeerObservationRecord>(),
            ESP_PEER_OBSERVATION_RECORD_LEN
        );
        assert_eq!(
            core::mem::size_of::<EspPeerObservationSourceState>(),
            ESP_PEER_OBSERVATION_SOURCE_STATE_LEN
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationSaKey, destination),
            32
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationRegistrationValue, lifecycle_generation),
            16
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationRegistrationValue, armed),
            24
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationState, authority_lost),
            24
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationState, last_source_address),
            40
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationRecord, source_scope),
            48
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationRecord, sequence_low),
            80
        );
        assert_eq!(
            core::mem::offset_of!(EspPeerObservationRecord, outer_source_address),
            96
        );
    }

    #[test]
    fn observation_map_values_and_record_round_trip() {
        let key = observation_key();
        assert!(EspPeerObservationSaKey::decode(&key.encode()) == Some(key));

        let registration = EspPeerObservationRegistrationValue {
            source_scope: 42,
            epoch: 9,
            lifecycle_generation: 17,
            armed: 1,
        };
        assert!(
            EspPeerObservationRegistrationValue::decode(&registration.encode())
                == Some(registration)
        );

        let lifecycle = EspPeerObservationLifecycleValue { generation: 17 };
        assert!(EspPeerObservationLifecycleValue::decode(&lifecycle.encode()) == Some(lifecycle));

        let state_key = EspPeerObservationStateKey { sa: key, epoch: 9 };
        assert!(EspPeerObservationStateKey::decode(&state_key.encode()) == Some(state_key));

        let state = EspPeerObservationState {
            active: 2,
            cursor: 8,
            dropped: 1,
            authority_lost: u64::from(ESP_PEER_AUTHORITY_MALFORMED_PACKET),
            last_source_family: 2,
            last_source_port_be: u16::from_ne_bytes([0x11, 0x94]),
            last_source_valid: 1,
            reserved: [0; 3],
            last_source_address: [198, 51, 100, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert!(EspPeerObservationState::decode(&state.encode()) == Some(state));
        let cleared = state.clear_last_source();
        assert_eq!(cleared.active, state.active);
        assert_eq!(cleared.cursor, state.cursor);
        assert_eq!(cleared.dropped, state.dropped);
        assert_eq!(cleared.authority_lost, state.authority_lost);
        assert_eq!(cleared.last_source_family, 0);
        assert_eq!(cleared.last_source_port_be, 0);
        assert_eq!(cleared.last_source_valid, 0);
        assert_eq!(cleared.reserved, [0; 3]);
        assert_eq!(cleared.last_source_address, [0; 16]);

        let record = EspPeerObservationRecord {
            key,
            source_scope: 42,
            epoch: 9,
            cursor: 8,
            dropped_total: 1,
            sequence_low: 0xfefe_dcba,
            sequence_high: 3,
            ingress_ifindex: 11,
            outer_source_family: 2,
            outer_source_port: 4500,
            outer_source_address: [198, 51, 100, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert!(EspPeerObservationRecord::decode(&record.encode()) == Some(record));

        let source = EspPeerObservationSourceState {
            authority_lost: u64::from(ESP_PEER_AUTHORITY_NAMESPACE_UNKNOWN),
            failures: 1,
        };
        assert!(EspPeerObservationSourceState::decode(&source.encode()) == Some(source));
    }

    #[test]
    fn observation_record_accepts_concurrent_loss_snapshot_ahead_of_cursor() {
        let record = EspPeerObservationRecord {
            key: observation_key(),
            source_scope: 42,
            epoch: 9,
            cursor: 1,
            dropped_total: 2,
            sequence_low: 1,
            sequence_high: 0,
            ingress_ifindex: 11,
            outer_source_family: 2,
            outer_source_port: 4500,
            outer_source_address: [198, 51, 100, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };

        assert!(EspPeerObservationRecord::decode(&record.encode()) == Some(record));
    }

    #[test]
    fn observation_codecs_reject_invalid_authority_and_reserved_bytes() {
        let mut key = observation_key().encode();
        key[28] = 1;
        assert!(EspPeerObservationSaKey::decode(&key).is_none());
        let mut noncanonical_mark = observation_key().encode();
        noncanonical_mark[8..12].copy_from_slice(&0x1_0000_u32.to_le_bytes());
        assert!(EspPeerObservationSaKey::decode(&noncanonical_mark).is_none());

        let mut registration = EspPeerObservationRegistrationValue {
            source_scope: 1,
            epoch: 1,
            lifecycle_generation: 1,
            armed: 0,
        }
        .encode();
        registration[24..32].copy_from_slice(&2_u64.to_le_bytes());
        assert!(EspPeerObservationRegistrationValue::decode(&registration).is_none());
        assert!(EspPeerObservationLifecycleValue::decode(
            &[0; ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN]
        )
        .is_none());

        let mut state = EspPeerObservationState::empty().encode();
        state[37] = 1;
        assert!(EspPeerObservationState::decode(&state).is_none());

        let mut source = EspPeerObservationSourceState::empty().encode();
        source[0..8]
            .copy_from_slice(&u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED + 1).to_le_bytes());
        assert!(EspPeerObservationSourceState::decode(&source).is_none());

        let mut transient = EspPeerObservationSourceState::empty().encode();
        transient[8..16].copy_from_slice(&1_u64.to_le_bytes());
        assert!(EspPeerObservationSourceState::decode(&transient).is_some());
    }

    #[test]
    fn mark_profile_validates_shift_and_exact_mask() {
        assert_eq!(MarkProfile::mask_for_shift(0), Some(0x7f));
        assert_eq!(MarkProfile::mask_for_shift(25), Some(0xfe00_0000));
        assert_eq!(MarkProfile::mask_for_shift(26), None);
        assert!(MarkProfile::new(25, 0xfe00_0000).is_some());
        assert!(MarkProfile::new(25, 0xfc00_0000).is_none());
    }

    #[test]
    fn token_round_trip_and_clear_preserve_unrelated_bits() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let unrelated = 0x0101_2345;
        let marked = unrelated | profile.encode_token(46).unwrap();
        assert_eq!(profile.decode_token(marked), MarkToken::Dscp(46));
        assert_eq!(profile.clear_token(marked), unrelated & !profile.mask);
        assert_eq!(
            profile.decode_token(unrelated & !profile.mask),
            MarkToken::Absent
        );
        assert_eq!(
            profile.decode_token(1_u32 << profile.shift),
            MarkToken::Malformed
        );
        assert!(profile.encode_token(64).is_none());
    }

    #[test]
    fn config_wire_round_trips_and_rejects_reserved_bytes() {
        let profile = MarkProfile::new(7, 0x0000_3f80).unwrap();
        let encoded = profile.encode();
        assert_eq!(MarkProfile::decode(&encoded), Some(profile));
        let mut malformed = encoded;
        malformed[1] = 1;
        assert_eq!(MarkProfile::decode(&malformed), None);
    }

    #[test]
    fn esp_carrier_rejects_non_esp_malformed_udp_and_non_esp_markers() {
        assert_eq!(
            classify_esp_carrier(IPPROTO_ESP, [0; 4]),
            Some(EspCarrier::Direct)
        );
        assert_eq!(
            classify_esp_carrier(IPPROTO_UDP, [0x11, 0x94, 0x11, 0x94]),
            Some(EspCarrier::UdpEncapsulated)
        );
        assert_eq!(classify_esp_carrier(IPPROTO_UDP, [0, 0, 0x11, 0x94]), None);
        assert_eq!(classify_esp_carrier(IPPROTO_UDP, [0x11, 0x94, 0, 0]), None);
        assert_eq!(classify_esp_carrier(6, [0; 4]), None);
        assert!(!valid_esp_spi([0; ESP_SPI_LEN]));
        assert!(valid_esp_spi([0, 0, 0, 1]));
    }

    #[test]
    fn ipv4_rewrite_preserves_ecn_and_updates_checksum() {
        let mut header = [0_u8; IPV4_HEADER_LEN];
        header[0] = 0x45;
        header[1] = 0x03;
        header[2..4].copy_from_slice(&100_u16.to_be_bytes());
        header[8] = 64;
        header[9] = IPPROTO_ESP;
        header[12..16].copy_from_slice(&[192, 0, 2, 1]);
        header[16..20].copy_from_slice(&[192, 0, 2, 2]);
        assert!(rewrite_ipv4_dscp(&mut header, 46));
        assert_eq!(header[1], (46 << 2) | 3);
        assert_eq!(ipv4_checksum(&header), 0);
        assert!(!rewrite_ipv4_dscp(&mut header, 64));
    }

    #[test]
    fn ipv6_rewrite_preserves_ecn_and_flow_label() {
        let mut header = [0_u8; IPV6_HEADER_LEN];
        header[0] = 0x60;
        header[1] = 0x31;
        header[2] = 0x23;
        header[3] = 0x45;
        assert!(rewrite_ipv6_dscp(&mut header, 46));
        let traffic_class = ((header[0] & 0x0f) << 4) | (header[1] >> 4);
        assert_eq!(traffic_class, (46 << 2) | 3);
        assert_eq!(header[1] & 0x0f, 1);
        assert_eq!(header[2..4], [0x23, 0x45]);
    }
}
