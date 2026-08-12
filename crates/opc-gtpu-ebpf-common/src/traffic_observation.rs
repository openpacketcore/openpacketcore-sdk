//! Fixed-layout, non-identifying traffic-observation ABI for the GTP-U tc backend.
//!
//! These records describe trusted *local forwarding-boundary* observations.
//! They deliberately contain no subscriber addresses, TEIDs, SPI values,
//! packet bytes, lengths, hashes, or peer-delivery claims. A consumer must
//! compose both directions with explicit source-loss evidence and a real
//! bidirectional round-trip/continuity evaluator; one record is not proof
//! that a peer received a packet on the wire.

use crate::{
    GtpuSessionAuthorityWireView, GtpuSessionDeviceId, GtpuSessionGeneration, GtpuSessionGroupId,
};

/// Width of an opaque reconcile-fence token.
pub const GTPU_TRAFFIC_OBSERVATION_FENCE_LEN: usize = 16;
/// Fixed byte width of one observation registration map value.
pub const GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN: usize = 96;
/// Fixed byte width of one packet observation event.
pub const GTPU_TRAFFIC_OBSERVATION_EVENT_LEN: usize = 96;
/// Fixed byte width of one authenticated ICMP Echo challenge payload.
///
/// The payload contains no subscriber, address, port, or flow material. Its
/// only public identity is the finite registration publication ID and a
/// caller-selected nonzero sample ID.
pub const GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN: usize = 32;
/// Exact magic prefix for an ICMP Echo challenge payload.
pub const GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_MAGIC: [u8; 4] = *b"OPCQ";
/// Exact supported ICMP Echo challenge payload format version.
///
/// Version two introduces domain-separated public request and private return
/// tags. Version-one payloads fail closed even if every other public header
/// field is copied into a current packet.
pub const GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_VERSION: u8 = 2;
/// Fixed challenge-profile discriminator stored in registration byte 92.
///
/// This value is deliberately distinct from both historical initiator wire
/// values. It prevents a registration written by the bidirectional ABI from
/// being interpreted as an authority for this core-initiated profile.
pub const GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE: u8 = 3;
/// Concise public name for the ICMP Echo challenge magic.
pub const GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_MAGIC: [u8; 4] =
    GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_MAGIC;
/// Concise public name for the ICMP Echo challenge version.
pub const GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_VERSION: u8 =
    GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_VERSION;
/// Maximum number of exact group registrations held by the eBPF backend.
pub const GTPU_TRAFFIC_OBSERVATION_REGISTRATION_MAX_ENTRIES: u32 = 65_536;
/// Fixed byte width of one redirect-authority nonce and group-map key/value.
pub const GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN: usize = 16;
/// Byte capacity of the bounded packet-event ring buffer.
pub const GTPU_TRAFFIC_OBSERVATION_RING_BYTES: u32 = 65_536;
/// Largest finite publication identity accepted by the observation ABI.
///
/// Identities are allocated monotonically from the retained gate map and are
/// never reused within that map graph; exhausting this range fails observation
/// registration closed. Uplink redirect re-entry is additionally fenced by a
/// full-width per-attempt nonce, including across fresh graph recreation.
pub const GTPU_TRAFFIC_OBSERVATION_PUBLICATION_ID_MAX: u32 = 0x0fff_ffff;
/// Gate-map slot containing the reset/quiescence generation.
pub const GTPU_TRAFFIC_OBSERVATION_GATE_INDEX: u32 = 0;
/// Gate-map slot containing the durable publication-identity high-water mark.
pub const GTPU_TRAFFIC_OBSERVATION_PUBLICATION_SEQUENCE_INDEX: u32 = 1;
/// Exact retained gate-map cardinality.
pub const GTPU_TRAFFIC_OBSERVATION_GATE_MAX_ENTRIES: u32 = 2;

/// Pinned eBPF map name for exact group observation registrations.
pub const GTPU_TRAFFIC_OBSERVATION_REGISTRATION_MAP_NAME: &str = "GTPU_OBS_REG";
/// Pinned eBPF map name binding a per-attempt redirect nonce to its group.
///
/// The nonce is the registration's CSPRNG-filled correlation secret. Its dual
/// use is domain-safe: it is never emitted or logged, while the event-side
/// challenge-stream identifier is a domain-separated one-way keyed derivation.
/// The redirect map instead uses the full secret solely as an unforgeable,
/// one-shot tc scratch capability across neighbour redirect re-entry.
pub const GTPU_TRAFFIC_OBSERVATION_REDIRECT_MAP_NAME: &str = "GTPU_OBS_REDIR";
/// Pinned eBPF map name for packet observation events.
pub const GTPU_TRAFFIC_OBSERVATION_EVENT_MAP_NAME: &str = "GTPU_OBS_EVT";
/// Pinned eBPF map name for per-CPU event-loss evidence.
pub const GTPU_TRAFFIC_OBSERVATION_LOSS_MAP_NAME: &str = "GTPU_OBS_LOSS";
/// Pinned eBPF map name for the global producer sequence.
pub const GTPU_TRAFFIC_OBSERVATION_SEQUENCE_MAP_NAME: &str = "GTPU_OBS_SEQ";
/// Pinned eBPF map name for source-publication control state.
///
/// Slot zero is the reset gate. Odd values authorize publication. A loader
/// publishes a distinct even value before resetting retained state, waits for
/// per-CPU flow scratch to become empty, and enables a new odd value only after
/// the replacement graph is verified. An old in-flight program can therefore
/// never observe an ABA gate. Slot one is a monotonic publication-identity
/// high-water mark and is deliberately never reset with source state.
pub const GTPU_TRAFFIC_OBSERVATION_GATE_MAP_NAME: &str = "GTPU_OBS_GATE";
/// Pinned BTF map name for the producer-sequence spin lock.
///
/// Linux treats values containing `bpf_spin_lock` as special BTF state, so
/// loaders bind this map's identity but never freeze or update its contents
/// through ordinary map syscalls.
pub const GTPU_TRAFFIC_OBSERVATION_SEQUENCE_LOCK_MAP_NAME: &str = "GTPU_OBS_LCK";
/// Pinned per-CPU verifier scratch map for the publication-active marker.
///
/// The historical map identity and fixed value width remain stable. The
/// producer now uses only a nonzero in-flight marker and clears the complete
/// value on every success and failure path; consumers must never treat this
/// map as diagnostics or proof evidence.
pub const GTPU_TRAFFIC_OBSERVATION_FLOW_SCRATCH_MAP_NAME: &str = "GTPU_OBS_FLOW";

const GROUP_ID_OFFSET: usize = 0;
const DEVICE_ID_OFFSET: usize = 16;
const GENERATION_OFFSET: usize = 32;
const BACKEND_INCARNATION_OFFSET: usize = 40;
const SOURCE_EPOCH_OFFSET: usize = 48;
const FENCE_OFFSET: usize = 56;
const CORRELATION_SECRET_OFFSET: usize = 72;
const PUBLICATION_ID_OFFSET: usize = 88;
const REGISTRATION_RESERVED_OFFSET: usize = 92;
const EVENT_GENERATION_OFFSET: usize = 16;
const EVENT_BACKEND_INCARNATION_OFFSET: usize = 24;
const EVENT_SOURCE_EPOCH_OFFSET: usize = 32;
const EVENT_FENCE_OFFSET: usize = 40;
const EVENT_CORRELATION_ID_OFFSET: usize = 56;
const EVENT_BOOT_TIME_OFFSET: usize = EVENT_CORRELATION_ID_OFFSET + 16;
const EVENT_SEQUENCE_OFFSET: usize = EVENT_BOOT_TIME_OFFSET + 8;
const EVENT_DIRECTION_OFFSET: usize = EVENT_SEQUENCE_OFFSET + 8;
const EVENT_RESERVED_OFFSET: usize = EVENT_DIRECTION_OFFSET + 1;
const ICMP_ECHO_CHALLENGE_SAMPLE_ID_OFFSET: usize = 12;
const ICMP_ECHO_CHALLENGE_TAG_OFFSET: usize = 16;

const ICMP_ECHO_CHALLENGE_TAG_FIRST_DOMAIN: u64 = 0x4f50_4351_5441_4731;
const ICMP_ECHO_CHALLENGE_TAG_SECOND_DOMAIN: u64 = 0x4f50_4351_5441_4732;
const ICMP_ECHO_RESPONSE_TAG_FIRST_DOMAIN: u64 = 0x4f50_4351_5253_5031;
const ICMP_ECHO_RESPONSE_TAG_SECOND_DOMAIN: u64 = 0x4f50_4351_5253_5032;
const ICMP_ECHO_CHALLENGE_CORRELATION_FIRST_DOMAIN: u64 = 0x4f50_4351_434f_5231;
const ICMP_ECHO_CHALLENGE_CORRELATION_SECOND_DOMAIN: u64 = 0x4f50_4351_434f_5232;

/// Direction of a successful local GTP-U forwarding-boundary submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GtpuTrafficObservationDirection {
    /// A grouped inner packet was locally submitted after GTP-U encapsulation.
    AccessToCore = 1,
    /// A grouped GTP-U packet was locally submitted after decapsulation/redirect.
    CoreToAccess = 2,
}

impl GtpuTrafficObservationDirection {
    /// Decode one exact wire discriminant.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AccessToCore),
            2 => Some(Self::CoreToAccess),
            _ => None,
        }
    }
}

/// Exact session and dataplane-generation binding for one observation registration.
///
/// Grouping these inseparable identity dimensions prevents a registration
/// caller from presenting them as unrelated positional values. Diagnostics
/// deliberately reveal none of the bound identities.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuTrafficObservationBinding {
    group_id: GtpuSessionGroupId,
    device_id: GtpuSessionDeviceId,
    generation: GtpuSessionGeneration,
}

impl GtpuTrafficObservationBinding {
    /// Bind one exact group and device to its current dataplane generation.
    #[must_use]
    pub const fn new(
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
    ) -> Self {
        Self {
            group_id,
            device_id,
            generation,
        }
    }
}

impl core::fmt::Debug for GtpuTrafficObservationBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GtpuTrafficObservationBinding(<redacted>)")
    }
}

/// Exact-current authority needed before a backend may emit observations.
///
/// The all-byte-array `repr(C)` layout is alignment-one and contains no
/// invalid bit patterns, so it is safe to copy between eBPF maps and ordinary
/// host buffers without pointer casts. Call [`Self::decode`] on all external
/// bytes before trusting the record.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GtpuTrafficObservationRegistration {
    group_id: [u8; 16],
    device_id: [u8; 16],
    generation_be: [u8; 8],
    backend_incarnation_be: [u8; 8],
    source_epoch_be: [u8; 8],
    reconcile_fence: [u8; GTPU_TRAFFIC_OBSERVATION_FENCE_LEN],
    correlation_secret: [u8; 16],
    publication_id_be: [u8; 4],
    challenge_profile: u8,
    reserved: [u8; 3],
}

impl core::fmt::Debug for GtpuTrafficObservationRegistration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuTrafficObservationRegistration")
            .field("authority", &"<redacted>")
            .finish()
    }
}

impl GtpuTrafficObservationRegistration {
    /// Construct one exact-current, nonzero observation registration.
    #[must_use]
    pub const fn new(
        binding: GtpuTrafficObservationBinding,
        backend_incarnation: u64,
        source_epoch: u64,
        reconcile_fence: [u8; GTPU_TRAFFIC_OBSERVATION_FENCE_LEN],
        publication_id: u32,
        correlation_secret: [u8; 16],
    ) -> Option<Self> {
        if backend_incarnation == 0
            || source_epoch == 0
            || publication_id == 0
            || publication_id > GTPU_TRAFFIC_OBSERVATION_PUBLICATION_ID_MAX
            || !nonzero(&reconcile_fence)
            || !nonzero(&correlation_secret)
        {
            return None;
        }
        Some(Self {
            group_id: binding.group_id.to_bytes(),
            device_id: binding.device_id.to_bytes(),
            generation_be: binding.generation.get().to_be_bytes(),
            backend_incarnation_be: backend_incarnation.to_be_bytes(),
            source_epoch_be: source_epoch.to_be_bytes(),
            reconcile_fence,
            correlation_secret,
            publication_id_be: publication_id.to_be_bytes(),
            challenge_profile: GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE,
            reserved: [0; 3],
        })
    }

    /// Decode and validate a registration received from an external map.
    #[must_use]
    pub const fn decode(value: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN]) -> Option<Self> {
        let registration = Self {
            group_id: slice_16(value, GROUP_ID_OFFSET),
            device_id: slice_16(value, DEVICE_ID_OFFSET),
            generation_be: slice_8(value, GENERATION_OFFSET),
            backend_incarnation_be: slice_8(value, BACKEND_INCARNATION_OFFSET),
            source_epoch_be: slice_8(value, SOURCE_EPOCH_OFFSET),
            reconcile_fence: slice_16(value, FENCE_OFFSET),
            correlation_secret: slice_16(value, CORRELATION_SECRET_OFFSET),
            publication_id_be: slice_4(value, PUBLICATION_ID_OFFSET),
            challenge_profile: value[REGISTRATION_RESERVED_OFFSET],
            reserved: [
                value[REGISTRATION_RESERVED_OFFSET + 1],
                value[REGISTRATION_RESERVED_OFFSET + 2],
                value[REGISTRATION_RESERVED_OFFSET + 3],
            ],
        };
        if registration.is_valid() {
            Some(registration)
        } else {
            None
        }
    }

    /// Encode this registration for its eBPF map value.
    #[must_use]
    pub const fn encode(self) -> [u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN] {
        [
            self.group_id[0],
            self.group_id[1],
            self.group_id[2],
            self.group_id[3],
            self.group_id[4],
            self.group_id[5],
            self.group_id[6],
            self.group_id[7],
            self.group_id[8],
            self.group_id[9],
            self.group_id[10],
            self.group_id[11],
            self.group_id[12],
            self.group_id[13],
            self.group_id[14],
            self.group_id[15],
            self.device_id[0],
            self.device_id[1],
            self.device_id[2],
            self.device_id[3],
            self.device_id[4],
            self.device_id[5],
            self.device_id[6],
            self.device_id[7],
            self.device_id[8],
            self.device_id[9],
            self.device_id[10],
            self.device_id[11],
            self.device_id[12],
            self.device_id[13],
            self.device_id[14],
            self.device_id[15],
            self.generation_be[0],
            self.generation_be[1],
            self.generation_be[2],
            self.generation_be[3],
            self.generation_be[4],
            self.generation_be[5],
            self.generation_be[6],
            self.generation_be[7],
            self.backend_incarnation_be[0],
            self.backend_incarnation_be[1],
            self.backend_incarnation_be[2],
            self.backend_incarnation_be[3],
            self.backend_incarnation_be[4],
            self.backend_incarnation_be[5],
            self.backend_incarnation_be[6],
            self.backend_incarnation_be[7],
            self.source_epoch_be[0],
            self.source_epoch_be[1],
            self.source_epoch_be[2],
            self.source_epoch_be[3],
            self.source_epoch_be[4],
            self.source_epoch_be[5],
            self.source_epoch_be[6],
            self.source_epoch_be[7],
            self.reconcile_fence[0],
            self.reconcile_fence[1],
            self.reconcile_fence[2],
            self.reconcile_fence[3],
            self.reconcile_fence[4],
            self.reconcile_fence[5],
            self.reconcile_fence[6],
            self.reconcile_fence[7],
            self.reconcile_fence[8],
            self.reconcile_fence[9],
            self.reconcile_fence[10],
            self.reconcile_fence[11],
            self.reconcile_fence[12],
            self.reconcile_fence[13],
            self.reconcile_fence[14],
            self.reconcile_fence[15],
            self.correlation_secret[0],
            self.correlation_secret[1],
            self.correlation_secret[2],
            self.correlation_secret[3],
            self.correlation_secret[4],
            self.correlation_secret[5],
            self.correlation_secret[6],
            self.correlation_secret[7],
            self.correlation_secret[8],
            self.correlation_secret[9],
            self.correlation_secret[10],
            self.correlation_secret[11],
            self.correlation_secret[12],
            self.correlation_secret[13],
            self.correlation_secret[14],
            self.correlation_secret[15],
            self.publication_id_be[0],
            self.publication_id_be[1],
            self.publication_id_be[2],
            self.publication_id_be[3],
            self.challenge_profile,
            self.reserved[0],
            self.reserved[1],
            self.reserved[2],
        ]
    }

    /// Return the opaque group map key. Do not log this value.
    #[must_use]
    pub const fn group_key(self) -> [u8; 16] {
        self.group_id
    }

    /// Return the opaque per-attempt redirect nonce. Do not log this value.
    ///
    /// This is deliberately the same secret used as the correlation-key
    /// material: correlation output is derived and public only as an opaque
    /// identifier, whereas this exact value remains kernel-private.
    #[must_use]
    pub const fn redirect_nonce(self) -> [u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN] {
        self.correlation_secret
    }

    /// Return whether this registration exactly matches current authority.
    #[must_use]
    pub fn matches_current(
        self,
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
    ) -> bool {
        self.group_id == group_id.to_bytes()
            && self.device_id == device_id.to_bytes()
            && self.generation_be == generation.get().to_be_bytes()
    }

    /// Validate one encoded registration against exact current kernel
    /// authority without copying the map value onto the eBPF stack.
    #[must_use]
    #[inline(always)]
    pub fn encoded_matches_current(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
        publication_id: u32,
    ) -> bool {
        encoded_is_valid(encoded)
            && encoded[GROUP_ID_OFFSET..DEVICE_ID_OFFSET] == group_id.to_bytes()
            && encoded[DEVICE_ID_OFFSET..GENERATION_OFFSET] == device_id.to_bytes()
            && encoded[GENERATION_OFFSET..BACKEND_INCARNATION_OFFSET]
                == generation.get().to_be_bytes()
            && encoded[PUBLICATION_ID_OFFSET..REGISTRATION_RESERVED_OFFSET]
                == publication_id.to_be_bytes()
    }

    /// Validate one encoded registration against a borrowed canonical
    /// authority without materializing its opaque identities on the BPF stack.
    #[must_use]
    #[inline(always)]
    pub fn encoded_matches_current_authority(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        authority: GtpuSessionAuthorityWireView<'_>,
        publication_id: u32,
    ) -> bool {
        let authority = authority.as_wire();
        encoded_is_valid(encoded)
            && encoded[GROUP_ID_OFFSET..DEVICE_ID_OFFSET] == authority[32..48]
            && encoded[DEVICE_ID_OFFSET..GENERATION_OFFSET] == authority[16..32]
            && encoded[GENERATION_OFFSET..BACKEND_INCARNATION_OFFSET] == authority[4..12]
            && encoded[PUBLICATION_ID_OFFSET..REGISTRATION_RESERVED_OFFSET]
                == publication_id.to_be_bytes()
    }

    /// Return the exact redirect nonce and finite publication identity when
    /// the encoded registration matches the live forwarding authority.
    #[must_use]
    #[inline(always)]
    pub fn encoded_redirect_identity_if_current(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
    ) -> Option<([u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN], u32)> {
        let publication_id =
            Self::encoded_publication_id_if_current(encoded, group_id, device_id, generation)?;
        Some((slice_16(encoded, CORRELATION_SECRET_OFFSET), publication_id))
    }

    /// Return the redirect nonce and publication identity bound to one
    /// canonical authority, without an owned authority header.
    #[must_use]
    #[inline(always)]
    pub fn encoded_redirect_identity_if_current_authority(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        authority: GtpuSessionAuthorityWireView<'_>,
    ) -> Option<([u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN], u32)> {
        let authority = authority.as_wire();
        if !encoded_is_valid(encoded)
            || encoded[GROUP_ID_OFFSET..DEVICE_ID_OFFSET] != authority[32..48]
            || encoded[DEVICE_ID_OFFSET..GENERATION_OFFSET] != authority[16..32]
            || encoded[GENERATION_OFFSET..BACKEND_INCARNATION_OFFSET] != authority[4..12]
        {
            return None;
        }
        Some((
            slice_16(encoded, CORRELATION_SECRET_OFFSET),
            u32::from_be_bytes(slice_4(encoded, PUBLICATION_ID_OFFSET)),
        ))
    }

    /// Return the exact finite publication identity when an encoded
    /// registration is valid and bound to the supplied forwarding authority.
    ///
    /// The eBPF producer captures this identity at each local forwarding
    /// boundary. Downlink publication rechecks it after decapsulation, while
    /// uplink redirect re-entry carries and rechecks the registration's exact
    /// nonce as well. Stale packets therefore cannot bind a replacement proof
    /// attempt.
    #[must_use]
    #[inline(always)]
    pub fn encoded_publication_id_if_current(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        group_id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        generation: GtpuSessionGeneration,
    ) -> Option<u32> {
        if !encoded_is_valid(encoded)
            || encoded[GROUP_ID_OFFSET..DEVICE_ID_OFFSET] != group_id.to_bytes()
            || encoded[DEVICE_ID_OFFSET..GENERATION_OFFSET] != device_id.to_bytes()
            || encoded[GENERATION_OFFSET..BACKEND_INCARNATION_OFFSET]
                != generation.get().to_be_bytes()
        {
            return None;
        }
        Some(u32::from_be_bytes(slice_4(encoded, PUBLICATION_ID_OFFSET)))
    }

    /// Return this registration's nonzero backend-incarnation token.
    #[must_use]
    pub const fn backend_incarnation(self) -> u64 {
        u64::from_be_bytes(self.backend_incarnation_be)
    }

    /// Return this registration's nonzero source epoch.
    #[must_use]
    pub const fn source_epoch(self) -> u64 {
        u64::from_be_bytes(self.source_epoch_be)
    }

    /// Return the exact finite publication identity for this registration.
    #[must_use]
    pub const fn publication_id(self) -> u32 {
        u32::from_be_bytes(self.publication_id_be)
    }

    /// Return the public ICMP Echo *request* payload for one nonzero sample.
    ///
    /// This host-facing method intentionally returns only public fixed-format
    /// bytes; it never reveals this registration's authentication secret.
    #[must_use]
    pub fn icmp_echo_challenge_payload(
        self,
        sample_id: u32,
    ) -> Option<[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN]> {
        if sample_id == 0 {
            return None;
        }
        let header = icmp_echo_challenge_header(self.publication_id(), sample_id);
        let tag = icmp_echo_request_tag(&self.correlation_secret, &header);
        let mut payload = [0; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN];
        payload[..ICMP_ECHO_CHALLENGE_TAG_OFFSET].copy_from_slice(&header);
        payload[ICMP_ECHO_CHALLENGE_TAG_OFFSET..].copy_from_slice(&tag);
        Some(payload)
    }

    /// Validate a core-to-access ICMP Echo request and derive its private
    /// access-to-core reply payload.
    ///
    /// The identifier and sequence must be the exact high and low 16-bit
    /// halves of the nonzero sample ID. The returned payload has a distinct,
    /// secret-derived response tag and is available only to a caller holding
    /// the encoded registration.
    #[must_use]
    #[inline(always)]
    pub fn encoded_icmp_echo_response_payload_if_request_valid(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        identifier: u16,
        sequence: u16,
        payload: &[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN],
    ) -> Option<[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN]> {
        let sample_id = Self::encoded_icmp_echo_request_sample_if_valid(
            encoded, identifier, sequence, payload,
        )?;
        let header = icmp_echo_challenge_header(
            u32::from_be_bytes(slice_4(encoded, PUBLICATION_ID_OFFSET)),
            sample_id,
        );
        let tag = icmp_echo_response_tag(&slice_16(encoded, CORRELATION_SECRET_OFFSET), &header);
        let mut response = [0; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN];
        response[..ICMP_ECHO_CHALLENGE_TAG_OFFSET].copy_from_slice(&header);
        response[ICMP_ECHO_CHALLENGE_TAG_OFFSET..].copy_from_slice(&tag);
        Some(response)
    }

    /// Validate a core-to-access ICMP Echo request and return its sample ID.
    ///
    /// Response-tagged payloads never validate here, including when their
    /// public header, identifier, and sequence are otherwise exact.
    #[must_use]
    #[inline(always)]
    pub fn encoded_icmp_echo_request_sample_if_valid(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        identifier: u16,
        sequence: u16,
        payload: &[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN],
    ) -> Option<u32> {
        let sample_id =
            encoded_icmp_echo_sample_if_valid(encoded, identifier, sequence, payload, true);
        (sample_id != 0).then_some(sample_id)
    }

    /// Validate an access-to-core ICMP Echo reply and return its sample ID.
    ///
    /// Request-tagged payloads never validate here, including when their
    /// public header, identifier, and sequence are otherwise exact.
    #[must_use]
    #[inline(always)]
    pub fn encoded_icmp_echo_reply_sample_if_valid(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        identifier: u16,
        sequence: u16,
        payload: &[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN],
    ) -> Option<u32> {
        let sample_id =
            encoded_icmp_echo_sample_if_valid(encoded, identifier, sequence, payload, false);
        (sample_id != 0).then_some(sample_id)
    }

    /// Derive the opaque correlation shared by every accepted challenge sample
    /// under this exact registration. It contains no packet-flow material.
    #[must_use]
    pub fn challenge_stream_correlation_id(self) -> [u8; 16] {
        challenge_stream_correlation_id_from_secret(&self.correlation_secret, self.publication_id())
    }

    /// Derive the challenge-stream correlation from an already validated
    /// encoded registration without copying its secret onto the BPF stack.
    #[must_use]
    #[inline(always)]
    pub fn encoded_challenge_stream_correlation_id(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
    ) -> Option<[u8; 16]> {
        if !encoded_is_valid(encoded) {
            return None;
        }
        Some(challenge_stream_correlation_id_from_secret(
            &slice_16(encoded, CORRELATION_SECRET_OFFSET),
            u32::from_be_bytes(slice_4(encoded, PUBLICATION_ID_OFFSET)),
        ))
    }

    /// Return the exact dataplane generation bound to this registration.
    #[must_use]
    pub const fn generation(self) -> Option<GtpuSessionGeneration> {
        GtpuSessionGeneration::new(u64::from_be_bytes(self.generation_be))
    }

    /// Validate an encoded registration, bind it to current authority, and
    /// write an event directly into a caller-owned fixed-size output buffer.
    ///
    /// This is intended for the verifier-constrained eBPF path, which must
    /// avoid copying the registration or event onto the BPF stack. The output
    /// is populated only when the registration is valid and exact-current.
    #[must_use]
    #[inline(always)]
    pub fn write_current_event(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        authority: &[u8; crate::GTPU_SESSION_GROUP_VALUE_LEN],
        publication_id: u32,
        sample_id: u32,
        output: &mut [u8; GTPU_TRAFFIC_OBSERVATION_EVENT_LEN],
    ) -> bool {
        if !encoded_is_valid(encoded)
            || sample_id == 0
            // The retained authority was decoded by tc before this helper.
            // Its device, group, and generation header fields are at fixed
            // offsets 16, 32, and 4 respectively.
            || encoded[GROUP_ID_OFFSET..DEVICE_ID_OFFSET] != authority[32..48]
            || encoded[DEVICE_ID_OFFSET..GENERATION_OFFSET] != authority[16..32]
            || encoded[GENERATION_OFFSET..BACKEND_INCARNATION_OFFSET]
                != authority[4..12]
            || encoded[PUBLICATION_ID_OFFSET..REGISTRATION_RESERVED_OFFSET]
                != publication_id.to_be_bytes()
        {
            return false;
        }
        let boot_time_ns = u64::from_be_bytes([
            output[EVENT_BOOT_TIME_OFFSET],
            output[EVENT_BOOT_TIME_OFFSET + 1],
            output[EVENT_BOOT_TIME_OFFSET + 2],
            output[EVENT_BOOT_TIME_OFFSET + 3],
            output[EVENT_BOOT_TIME_OFFSET + 4],
            output[EVENT_BOOT_TIME_OFFSET + 5],
            output[EVENT_BOOT_TIME_OFFSET + 6],
            output[EVENT_BOOT_TIME_OFFSET + 7],
        ]);
        let producer_sequence = u64::from_be_bytes([
            output[EVENT_SEQUENCE_OFFSET],
            output[EVENT_SEQUENCE_OFFSET + 1],
            output[EVENT_SEQUENCE_OFFSET + 2],
            output[EVENT_SEQUENCE_OFFSET + 3],
            output[EVENT_SEQUENCE_OFFSET + 4],
            output[EVENT_SEQUENCE_OFFSET + 5],
            output[EVENT_SEQUENCE_OFFSET + 6],
            output[EVENT_SEQUENCE_OFFSET + 7],
        ]);
        if boot_time_ns == 0
            || producer_sequence == 0
            || GtpuTrafficObservationDirection::from_wire(output[EVENT_DIRECTION_OFFSET]).is_none()
        {
            return false;
        }
        // The producer comparison above binds the full device identity. The
        // ring record retains the exact group while omitting that redundant
        // device field, reducing verifier stack pressure and identifier
        // retention without weakening the current-authority check.
        output[..EVENT_GENERATION_OFFSET].copy_from_slice(&encoded[..DEVICE_ID_OFFSET]);
        output[EVENT_GENERATION_OFFSET..EVENT_BACKEND_INCARNATION_OFFSET]
            .copy_from_slice(&encoded[GENERATION_OFFSET..BACKEND_INCARNATION_OFFSET]);
        output[EVENT_BACKEND_INCARNATION_OFFSET..EVENT_SOURCE_EPOCH_OFFSET]
            .copy_from_slice(&encoded[BACKEND_INCARNATION_OFFSET..SOURCE_EPOCH_OFFSET]);
        output[EVENT_SOURCE_EPOCH_OFFSET..EVENT_FENCE_OFFSET]
            .copy_from_slice(&encoded[SOURCE_EPOCH_OFFSET..FENCE_OFFSET]);
        output[EVENT_FENCE_OFFSET..EVENT_CORRELATION_ID_OFFSET]
            .copy_from_slice(&encoded[FENCE_OFFSET..CORRELATION_SECRET_OFFSET]);
        let correlation_id = challenge_stream_correlation_id_from_secret(
            &slice_16(encoded, CORRELATION_SECRET_OFFSET),
            u32::from_be_bytes(slice_4(encoded, PUBLICATION_ID_OFFSET)),
        );
        output[EVENT_CORRELATION_ID_OFFSET..EVENT_BOOT_TIME_OFFSET]
            .copy_from_slice(&correlation_id);
        output[EVENT_RESERVED_OFFSET..EVENT_RESERVED_OFFSET + 4]
            .copy_from_slice(&sample_id.to_be_bytes());
        output[EVENT_RESERVED_OFFSET + 4..].fill(0);
        true
    }

    const fn is_valid(self) -> bool {
        GtpuSessionGroupId::new(self.group_id).is_some()
            && GtpuSessionDeviceId::new(self.device_id).is_some()
            && GtpuSessionGeneration::new(u64::from_be_bytes(self.generation_be)).is_some()
            && u64::from_be_bytes(self.backend_incarnation_be) != 0
            && u64::from_be_bytes(self.source_epoch_be) != 0
            && u32::from_be_bytes(self.publication_id_be) != 0
            && u32::from_be_bytes(self.publication_id_be)
                <= GTPU_TRAFFIC_OBSERVATION_PUBLICATION_ID_MAX
            && nonzero(&self.reconcile_fence)
            && nonzero(&self.correlation_secret)
            && self.challenge_profile == GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE
            && self.reserved[0] == 0
            && self.reserved[1] == 0
            && self.reserved[2] == 0
    }
}

fn encoded_is_valid(value: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN]) -> bool {
    GtpuSessionGroupId::new(slice_16(value, GROUP_ID_OFFSET)).is_some()
        && GtpuSessionDeviceId::new(slice_16(value, DEVICE_ID_OFFSET)).is_some()
        && GtpuSessionGeneration::new(u64::from_be_bytes(slice_8(value, GENERATION_OFFSET)))
            .is_some()
        && u64::from_be_bytes(slice_8(value, BACKEND_INCARNATION_OFFSET)) != 0
        && u64::from_be_bytes(slice_8(value, SOURCE_EPOCH_OFFSET)) != 0
        && nonzero(&value[FENCE_OFFSET..CORRELATION_SECRET_OFFSET])
        && nonzero(&value[CORRELATION_SECRET_OFFSET..PUBLICATION_ID_OFFSET])
        && u32::from_be_bytes(slice_4(value, PUBLICATION_ID_OFFSET)) != 0
        && u32::from_be_bytes(slice_4(value, PUBLICATION_ID_OFFSET))
            <= GTPU_TRAFFIC_OBSERVATION_PUBLICATION_ID_MAX
        && value[REGISTRATION_RESERVED_OFFSET]
            == GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE
        && value[REGISTRATION_RESERVED_OFFSET + 1] == 0
        && value[REGISTRATION_RESERVED_OFFSET + 2] == 0
        && value[REGISTRATION_RESERVED_OFFSET + 3] == 0
}

fn encoded_icmp_echo_sample_if_valid(
    encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
    identifier: u16,
    sequence: u16,
    payload: &[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN],
    request: bool,
) -> u32 {
    if !encoded_is_valid(encoded) {
        return 0;
    }
    let sample_id = u32::from_be_bytes(slice_4(payload, ICMP_ECHO_CHALLENGE_SAMPLE_ID_OFFSET));
    if sample_id == 0 || !icmp_echo_identifier_sequence_matches(sample_id, identifier, sequence) {
        return 0;
    }
    let header = icmp_echo_challenge_header(
        u32::from_be_bytes(slice_4(encoded, PUBLICATION_ID_OFFSET)),
        sample_id,
    );
    if slice_16(payload, 0) != header {
        return 0;
    }
    let secret = slice_16(encoded, CORRELATION_SECRET_OFFSET);
    let expected_tag = if request {
        icmp_echo_request_tag(&secret, &header)
    } else {
        icmp_echo_response_tag(&secret, &header)
    };
    if !constant_time_eq_16(
        &slice_16(payload, ICMP_ECHO_CHALLENGE_TAG_OFFSET),
        &expected_tag,
    ) {
        return 0;
    }
    sample_id
}

#[inline(always)]
const fn icmp_echo_identifier_sequence_matches(
    sample_id: u32,
    identifier: u16,
    sequence: u16,
) -> bool {
    identifier == (sample_id >> 16) as u16 && sequence == sample_id as u16
}

fn icmp_echo_challenge_header(
    publication_id: u32,
    sample_id: u32,
) -> [u8; ICMP_ECHO_CHALLENGE_TAG_OFFSET] {
    let publication_id_be = publication_id.to_be_bytes();
    let sample_id_be = sample_id.to_be_bytes();
    [
        GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_MAGIC[0],
        GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_MAGIC[1],
        GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_MAGIC[2],
        GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_MAGIC[3],
        GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_VERSION,
        GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE,
        0,
        0,
        publication_id_be[0],
        publication_id_be[1],
        publication_id_be[2],
        publication_id_be[3],
        sample_id_be[0],
        sample_id_be[1],
        sample_id_be[2],
        sample_id_be[3],
    ]
}

fn icmp_echo_request_tag(
    secret: &[u8; 16],
    header: &[u8; ICMP_ECHO_CHALLENGE_TAG_OFFSET],
) -> [u8; 16] {
    siphash128(
        secret,
        ICMP_ECHO_CHALLENGE_TAG_FIRST_DOMAIN,
        ICMP_ECHO_CHALLENGE_TAG_SECOND_DOMAIN,
        header,
    )
}

fn icmp_echo_response_tag(
    secret: &[u8; 16],
    header: &[u8; ICMP_ECHO_CHALLENGE_TAG_OFFSET],
) -> [u8; 16] {
    siphash128(
        secret,
        ICMP_ECHO_RESPONSE_TAG_FIRST_DOMAIN,
        ICMP_ECHO_RESPONSE_TAG_SECOND_DOMAIN,
        header,
    )
}

fn challenge_stream_correlation_id_from_secret(secret: &[u8; 16], publication_id: u32) -> [u8; 16] {
    let header = icmp_echo_challenge_header(publication_id, 0);
    siphash128(
        secret,
        ICMP_ECHO_CHALLENGE_CORRELATION_FIRST_DOMAIN,
        ICMP_ECHO_CHALLENGE_CORRELATION_SECOND_DOMAIN,
        &header,
    )
}

fn siphash128(
    key: &[u8; 16],
    first_domain: u64,
    second_domain: u64,
    header: &[u8; ICMP_ECHO_CHALLENGE_TAG_OFFSET],
) -> [u8; 16] {
    let first = siphash24_fixed_header(key, first_domain, header).to_be_bytes();
    let second = siphash24_fixed_header(key, second_domain, header).to_be_bytes();
    [
        first[0], first[1], first[2], first[3], first[4], first[5], first[6], first[7], second[0],
        second[1], second[2], second[3], second[4], second[5], second[6], second[7],
    ]
}

/// SipHash-2-4 over one domain block and the fixed 16-byte public header.
///
/// The message is exactly 24 bytes (`domain || header`), so the three absorbs
/// and all rounds are statically bounded. The domain is part of the message,
/// rather than merely a changed key, which keeps the two tag halves separated
/// even if callers accidentally reuse a registration secret elsewhere.
#[inline(always)]
fn siphash24_fixed_header(
    key: &[u8; 16],
    domain: u64,
    header: &[u8; ICMP_ECHO_CHALLENGE_TAG_OFFSET],
) -> u64 {
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;
    siphash_compress(&mut v0, &mut v1, &mut v2, &mut v3, domain);
    siphash_compress(
        &mut v0,
        &mut v1,
        &mut v2,
        &mut v3,
        u64::from_le_bytes(slice_8(header, 0)),
    );
    siphash_compress(
        &mut v0,
        &mut v1,
        &mut v2,
        &mut v3,
        u64::from_le_bytes(slice_8(header, 8)),
    );
    // The final SipHash block carries the exact 24-byte message length.
    siphash_compress(&mut v0, &mut v1, &mut v2, &mut v3, 24_u64 << 56);
    v2 ^= 0xff;
    let mut round = 0;
    while round < 4 {
        siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
        round += 1;
    }
    v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
fn siphash_compress(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64, block: u64) {
    *v3 ^= block;
    let mut round = 0;
    while round < 2 {
        siphash_round(v0, v1, v2, v3);
        round += 1;
    }
    *v0 ^= block;
}

#[inline(always)]
fn siphash_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[inline(always)]
fn constant_time_eq_16(left: &[u8; 16], right: &[u8; 16]) -> bool {
    let mut difference = 0_u8;
    let mut index = 0;
    while index < 16 {
        difference |= left[index] ^ right[index];
        index += 1;
    }
    difference == 0
}

/// One successful local GTP-U forwarding-boundary observation.
///
/// This record identifies an exact source incarnation and epoch. Consumers
/// must reject queued records after either changes and must bracket drains
/// with the backend's explicit loss counter. It carries both a nonzero kernel
/// boot-monotonic timestamp and a distinct global producer sequence. Consumers
/// order by `(boot_time, producer_sequence)` and reject reused sequence values;
/// the sequence breaks valid cross-CPU timestamp ties without pretending that
/// a timestamp alone is globally unique.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct GtpuTrafficObservationEvent {
    group_id: [u8; 16],
    generation_be: [u8; 8],
    backend_incarnation_be: [u8; 8],
    source_epoch_be: [u8; 8],
    reconcile_fence: [u8; GTPU_TRAFFIC_OBSERVATION_FENCE_LEN],
    correlation_id: [u8; 16],
    boot_time_ns_be: [u8; 8],
    producer_sequence_be: [u8; 8],
    direction: u8,
    sample_id_be: [u8; 4],
    reserved: [u8; 3],
}

impl core::fmt::Debug for GtpuTrafficObservationEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuTrafficObservationEvent")
            .field("direction", &self.direction())
            .field("boot_time", &"<monotonic>")
            .field("authority", &"<redacted>")
            .finish()
    }
}

impl GtpuTrafficObservationEvent {
    /// Construct one event after a successful local forwarding submission.
    #[must_use]
    pub const fn new(
        registration: GtpuTrafficObservationRegistration,
        correlation_id: [u8; 16],
        sample_id: u32,
        direction: GtpuTrafficObservationDirection,
        boot_time_ns: u64,
        producer_sequence: u64,
    ) -> Option<Self> {
        if sample_id == 0
            || boot_time_ns == 0
            || producer_sequence == 0
            || !nonzero(&correlation_id)
        {
            return None;
        }
        Some(Self {
            group_id: registration.group_id,
            generation_be: registration.generation_be,
            backend_incarnation_be: registration.backend_incarnation_be,
            source_epoch_be: registration.source_epoch_be,
            reconcile_fence: registration.reconcile_fence,
            correlation_id,
            boot_time_ns_be: boot_time_ns.to_be_bytes(),
            producer_sequence_be: producer_sequence.to_be_bytes(),
            direction: direction as u8,
            sample_id_be: sample_id.to_be_bytes(),
            reserved: [0; 3],
        })
    }

    /// Decode and validate an event received from the bounded ring buffer.
    #[must_use]
    pub const fn decode(value: &[u8; GTPU_TRAFFIC_OBSERVATION_EVENT_LEN]) -> Option<Self> {
        let event = Self {
            group_id: slice_16(value, GROUP_ID_OFFSET),
            generation_be: slice_8(value, EVENT_GENERATION_OFFSET),
            backend_incarnation_be: slice_8(value, EVENT_BACKEND_INCARNATION_OFFSET),
            source_epoch_be: slice_8(value, EVENT_SOURCE_EPOCH_OFFSET),
            reconcile_fence: slice_16(value, EVENT_FENCE_OFFSET),
            correlation_id: slice_16(value, EVENT_CORRELATION_ID_OFFSET),
            boot_time_ns_be: slice_8(value, EVENT_BOOT_TIME_OFFSET),
            producer_sequence_be: slice_8(value, EVENT_SEQUENCE_OFFSET),
            direction: value[EVENT_DIRECTION_OFFSET],
            sample_id_be: slice_4(value, EVENT_RESERVED_OFFSET),
            reserved: [
                value[EVENT_RESERVED_OFFSET + 4],
                value[EVENT_RESERVED_OFFSET + 5],
                value[EVENT_RESERVED_OFFSET + 6],
            ],
        };
        if event.is_valid() {
            Some(event)
        } else {
            None
        }
    }

    /// Encode this event for the eBPF ring buffer.
    #[must_use]
    pub const fn encode(self) -> [u8; GTPU_TRAFFIC_OBSERVATION_EVENT_LEN] {
        let registration = [
            self.group_id[0],
            self.group_id[1],
            self.group_id[2],
            self.group_id[3],
            self.group_id[4],
            self.group_id[5],
            self.group_id[6],
            self.group_id[7],
            self.group_id[8],
            self.group_id[9],
            self.group_id[10],
            self.group_id[11],
            self.group_id[12],
            self.group_id[13],
            self.group_id[14],
            self.group_id[15],
            self.generation_be[0],
            self.generation_be[1],
            self.generation_be[2],
            self.generation_be[3],
            self.generation_be[4],
            self.generation_be[5],
            self.generation_be[6],
            self.generation_be[7],
            self.backend_incarnation_be[0],
            self.backend_incarnation_be[1],
            self.backend_incarnation_be[2],
            self.backend_incarnation_be[3],
            self.backend_incarnation_be[4],
            self.backend_incarnation_be[5],
            self.backend_incarnation_be[6],
            self.backend_incarnation_be[7],
            self.source_epoch_be[0],
            self.source_epoch_be[1],
            self.source_epoch_be[2],
            self.source_epoch_be[3],
            self.source_epoch_be[4],
            self.source_epoch_be[5],
            self.source_epoch_be[6],
            self.source_epoch_be[7],
            self.reconcile_fence[0],
            self.reconcile_fence[1],
            self.reconcile_fence[2],
            self.reconcile_fence[3],
            self.reconcile_fence[4],
            self.reconcile_fence[5],
            self.reconcile_fence[6],
            self.reconcile_fence[7],
            self.reconcile_fence[8],
            self.reconcile_fence[9],
            self.reconcile_fence[10],
            self.reconcile_fence[11],
            self.reconcile_fence[12],
            self.reconcile_fence[13],
            self.reconcile_fence[14],
            self.reconcile_fence[15],
        ];
        [
            registration[0],
            registration[1],
            registration[2],
            registration[3],
            registration[4],
            registration[5],
            registration[6],
            registration[7],
            registration[8],
            registration[9],
            registration[10],
            registration[11],
            registration[12],
            registration[13],
            registration[14],
            registration[15],
            registration[16],
            registration[17],
            registration[18],
            registration[19],
            registration[20],
            registration[21],
            registration[22],
            registration[23],
            registration[24],
            registration[25],
            registration[26],
            registration[27],
            registration[28],
            registration[29],
            registration[30],
            registration[31],
            registration[32],
            registration[33],
            registration[34],
            registration[35],
            registration[36],
            registration[37],
            registration[38],
            registration[39],
            registration[40],
            registration[41],
            registration[42],
            registration[43],
            registration[44],
            registration[45],
            registration[46],
            registration[47],
            registration[48],
            registration[49],
            registration[50],
            registration[51],
            registration[52],
            registration[53],
            registration[54],
            registration[55],
            self.correlation_id[0],
            self.correlation_id[1],
            self.correlation_id[2],
            self.correlation_id[3],
            self.correlation_id[4],
            self.correlation_id[5],
            self.correlation_id[6],
            self.correlation_id[7],
            self.correlation_id[8],
            self.correlation_id[9],
            self.correlation_id[10],
            self.correlation_id[11],
            self.correlation_id[12],
            self.correlation_id[13],
            self.correlation_id[14],
            self.correlation_id[15],
            self.boot_time_ns_be[0],
            self.boot_time_ns_be[1],
            self.boot_time_ns_be[2],
            self.boot_time_ns_be[3],
            self.boot_time_ns_be[4],
            self.boot_time_ns_be[5],
            self.boot_time_ns_be[6],
            self.boot_time_ns_be[7],
            self.producer_sequence_be[0],
            self.producer_sequence_be[1],
            self.producer_sequence_be[2],
            self.producer_sequence_be[3],
            self.producer_sequence_be[4],
            self.producer_sequence_be[5],
            self.producer_sequence_be[6],
            self.producer_sequence_be[7],
            self.direction,
            self.sample_id_be[0],
            self.sample_id_be[1],
            self.sample_id_be[2],
            self.sample_id_be[3],
            self.reserved[0],
            self.reserved[1],
            self.reserved[2],
        ]
    }

    /// Return whether this event matches every registration field retained in
    /// the bounded ring record.
    ///
    /// [`GtpuTrafficObservationRegistration::write_current_event`] separately compares the registration's
    /// full device identity with current kernel authority before publication;
    /// consumers must also check their live group/device attachment before
    /// treating a matching event as evidence.
    #[must_use]
    pub fn matches_registration(self, registration: GtpuTrafficObservationRegistration) -> bool {
        self.group_id == registration.group_id
            && self.generation_be == registration.generation_be
            && self.backend_incarnation_be == registration.backend_incarnation_be
            && self.source_epoch_be == registration.source_epoch_be
            && self.reconcile_fence == registration.reconcile_fence
    }

    /// Return the opaque group map key. Do not log this value.
    #[must_use]
    pub const fn group_key(self) -> [u8; 16] {
        self.group_id
    }

    /// Return this event's opaque authenticated challenge-stream correlation.
    #[must_use]
    pub const fn correlation_id(self) -> [u8; 16] {
        self.correlation_id
    }

    /// Return the validated local forwarding direction.
    #[must_use]
    pub const fn direction(self) -> GtpuTrafficObservationDirection {
        match self.direction {
            1 => GtpuTrafficObservationDirection::AccessToCore,
            _ => GtpuTrafficObservationDirection::CoreToAccess,
        }
    }

    /// Return the nonzero boot-monotonic timestamp.
    #[must_use]
    pub const fn boot_time_ns(self) -> u64 {
        u64::from_be_bytes(self.boot_time_ns_be)
    }

    /// Return the nonzero source-scoped producer sequence.
    #[must_use]
    pub const fn producer_sequence(self) -> u64 {
        u64::from_be_bytes(self.producer_sequence_be)
    }

    /// Return the nonzero authenticated ICMP Echo challenge sample ID.
    #[must_use]
    pub const fn sample_id(self) -> u32 {
        u32::from_be_bytes(self.sample_id_be)
    }

    const fn is_valid(self) -> bool {
        GtpuSessionGroupId::new(self.group_id).is_some()
            && GtpuSessionGeneration::new(u64::from_be_bytes(self.generation_be)).is_some()
            && u64::from_be_bytes(self.backend_incarnation_be) != 0
            && u64::from_be_bytes(self.source_epoch_be) != 0
            && nonzero(&self.reconcile_fence)
            && nonzero(&self.correlation_id)
            && self.boot_time_ns() != 0
            && self.producer_sequence() != 0
            && GtpuTrafficObservationDirection::from_wire(self.direction).is_some()
            && self.sample_id() != 0
            && self.reserved[0] == 0
            && self.reserved[1] == 0
            && self.reserved[2] == 0
    }
}

const fn nonzero(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

const fn slice_8(value: &[u8], offset: usize) -> [u8; 8] {
    [
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
    ]
}

const fn slice_4(value: &[u8], offset: usize) -> [u8; 4] {
    [
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ]
}

const fn slice_16(value: &[u8], offset: usize) -> [u8; 16] {
    [
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
        value[offset + 8],
        value[offset + 9],
        value[offset + 10],
        value[offset + 11],
        value[offset + 12],
        value[offset + 13],
        value[offset + 14],
        value[offset + 15],
    ]
}

const _: [(); GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN] =
    [(); core::mem::size_of::<GtpuTrafficObservationRegistration>()];
const _: [(); 1] = [(); core::mem::align_of::<GtpuTrafficObservationRegistration>()];
const _: [(); GTPU_TRAFFIC_OBSERVATION_EVENT_LEN] =
    [(); core::mem::size_of::<GtpuTrafficObservationEvent>()];
const _: [(); 1] = [(); core::mem::align_of::<GtpuTrafficObservationEvent>()];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{
        GtpuEndpointAddress, GtpuSessionEntry, GtpuSessionGroupRecord, GtpuSessionPaa,
        GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy,
    };

    fn group_id() -> GtpuSessionGroupId {
        GtpuSessionGroupId::new([0x11; 16]).unwrap()
    }

    fn device_id() -> GtpuSessionDeviceId {
        GtpuSessionDeviceId::new([0x22; 16]).unwrap()
    }

    fn generation() -> GtpuSessionGeneration {
        GtpuSessionGeneration::new(7).unwrap()
    }

    fn registration() -> GtpuTrafficObservationRegistration {
        registration_with(11, [0x44; 16])
    }

    fn registration_with(
        publication_id: u32,
        secret: [u8; 16],
    ) -> GtpuTrafficObservationRegistration {
        GtpuTrafficObservationRegistration::new(
            GtpuTrafficObservationBinding::new(group_id(), device_id(), generation()),
            9,
            10,
            [0x33; 16],
            publication_id,
            secret,
        )
        .unwrap()
    }

    fn authority() -> [u8; crate::GTPU_SESSION_GROUP_VALUE_LEN] {
        let entry = GtpuSessionEntry::new(
            GtpuSessionPaa::new(GtpuEndpointAddress::Ipv4([10, 23, 0, 2])).unwrap(),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 2]),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            0x1000_0001_u32.to_be_bytes(),
            0x2000_0001_u32.to_be_bytes(),
            [0; 4],
            None,
            GtpuSourcePortPolicy::Any,
            GtpuUplinkSourcePortPolicy::LegacyServicePort,
        )
        .unwrap();
        GtpuSessionGroupRecord::active(group_id(), device_id(), generation(), Some(entry), None)
            .unwrap()
            .encode()
    }

    fn valid_request_sample(
        encoded: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
        candidate: &[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN],
    ) -> Option<u32> {
        GtpuTrafficObservationRegistration::encoded_icmp_echo_request_sample_if_valid(
            encoded, 0x1234, 0x5678, candidate,
        )
    }

    #[test]
    fn fixed_layout_is_alignment_one_and_exact() {
        assert_eq!(
            core::mem::size_of::<GtpuTrafficObservationRegistration>(),
            96
        );
        assert_eq!(
            core::mem::align_of::<GtpuTrafficObservationRegistration>(),
            1
        );
        assert_eq!(core::mem::size_of::<GtpuTrafficObservationEvent>(), 96);
        assert_eq!(core::mem::align_of::<GtpuTrafficObservationEvent>(), 1);
    }

    #[test]
    fn registration_round_trip_uses_the_fixed_challenge_profile() {
        let registration = registration();
        let encoded = registration.encode();
        assert_eq!(
            encoded[REGISTRATION_RESERVED_OFFSET],
            GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE
        );
        assert_eq!(&encoded[REGISTRATION_RESERVED_OFFSET + 1..], &[0; 3]);
        assert_eq!(
            GtpuTrafficObservationRegistration::decode(&encoded),
            Some(registration)
        );
    }

    #[test]
    fn icmp_echo_uses_private_domain_separated_reply_tags() {
        let registration = registration();
        let encoded = registration.encode();
        let sample_id = 0x1234_5678;
        let request = registration.icmp_echo_challenge_payload(sample_id).unwrap();
        assert_eq!(&request[..4], b"OPCQ");
        assert_eq!(
            request[4],
            GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_VERSION
        );
        assert_eq!(
            request[5],
            GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE
        );
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_icmp_echo_request_sample_if_valid(
                &encoded, 0x1234, 0x5678, &request,
            ),
            Some(sample_id),
        );
        let reply = GtpuTrafficObservationRegistration::encoded_icmp_echo_response_payload_if_request_valid(
            &encoded, 0x1234, 0x5678, &request,
        )
        .unwrap();
        assert_eq!(
            &reply[..ICMP_ECHO_CHALLENGE_TAG_OFFSET],
            &request[..ICMP_ECHO_CHALLENGE_TAG_OFFSET]
        );
        assert_ne!(
            &reply[ICMP_ECHO_CHALLENGE_TAG_OFFSET..],
            &request[ICMP_ECHO_CHALLENGE_TAG_OFFSET..]
        );
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_icmp_echo_reply_sample_if_valid(
                &encoded, 0x1234, 0x5678, &reply,
            ),
            Some(sample_id),
        );
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_icmp_echo_reply_sample_if_valid(
                &encoded, 0x1234, 0x5678, &request,
            ),
            None,
        );
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_icmp_echo_request_sample_if_valid(
                &encoded, 0x1234, 0x5678, &reply,
            ),
            None,
        );
        assert!(GtpuTrafficObservationRegistration::encoded_icmp_echo_response_payload_if_request_valid(
            &encoded, 0x1234, 0x5678, &reply,
        )
        .is_none());
    }

    #[test]
    fn icmp_echo_rejects_identifier_sequence_mutation_and_stale_authority() {
        let registration_a = registration_with(11, [0x44; 16]);
        let encoded_a = registration_a.encode();
        let sample_id = 0x1234_5678;
        let request = registration_a
            .icmp_echo_challenge_payload(sample_id)
            .unwrap();
        let reply = GtpuTrafficObservationRegistration::encoded_icmp_echo_response_payload_if_request_valid(
            &encoded_a, 0x1234, 0x5678, &request,
        )
        .unwrap();
        assert_eq!(valid_request_sample(&encoded_a, &request), Some(sample_id));
        assert!(registration_a.icmp_echo_challenge_payload(0).is_none());
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_icmp_echo_request_sample_if_valid(
                &encoded_a, 0x1235, 0x5678, &request,
            ),
            None,
        );
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_icmp_echo_reply_sample_if_valid(
                &encoded_a, 0x1234, 0x5679, &reply,
            ),
            None,
        );

        let wrong_secret = registration_with(11, [0x45; 16]).encode();
        assert_eq!(valid_request_sample(&wrong_secret, &request), None);
        let registration_b = registration_with(12, [0x44; 16]);
        let encoded_b = registration_b.encode();
        assert_eq!(valid_request_sample(&encoded_b, &request), None);
        assert_ne!(
            registration_a.challenge_stream_correlation_id(),
            registration_b.challenge_stream_correlation_id()
        );

        let mut malformed_profile = encoded_a;
        malformed_profile[REGISTRATION_RESERVED_OFFSET] = 2;
        assert!(GtpuTrafficObservationRegistration::decode(&malformed_profile).is_none());
        assert_eq!(valid_request_sample(&malformed_profile, &request), None);

        for offset in [0, 4, 5, 6, 8, 12, ICMP_ECHO_CHALLENGE_TAG_OFFSET] {
            let mut mutated = request;
            mutated[offset] ^= 1;
            assert_eq!(valid_request_sample(&encoded_a, &mutated), None);
        }
    }

    #[test]
    fn request_and_reply_tags_are_distinct_deterministic_and_redacted() {
        let registration = registration();
        let encoded = registration.encode();
        let first = registration.icmp_echo_challenge_payload(1).unwrap();
        let repeated = registration.icmp_echo_challenge_payload(1).unwrap();
        let second = registration.icmp_echo_challenge_payload(2).unwrap();
        assert_eq!(first, repeated);
        assert_ne!(first, second);
        let reply = GtpuTrafficObservationRegistration::encoded_icmp_echo_response_payload_if_request_valid(
            &encoded, 0, 1, &first,
        )
        .unwrap();
        let header = slice_16(&first, 0);
        assert_eq!(
            icmp_echo_request_tag(&[0x44; 16], &header),
            slice_16(&first, ICMP_ECHO_CHALLENGE_TAG_OFFSET)
        );
        assert_eq!(
            icmp_echo_response_tag(&[0x44; 16], &header),
            slice_16(&reply, ICMP_ECHO_CHALLENGE_TAG_OFFSET)
        );
        assert_ne!(
            slice_16(&first, ICMP_ECHO_CHALLENGE_TAG_OFFSET),
            slice_16(&reply, ICMP_ECHO_CHALLENGE_TAG_OFFSET)
        );
        let rendered = std::format!("{registration:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("44"));
    }

    #[test]
    fn event_round_trip_preserves_only_non_identifying_boundary_data() {
        let event = GtpuTrafficObservationEvent::new(
            registration(),
            registration().challenge_stream_correlation_id(),
            1,
            GtpuTrafficObservationDirection::AccessToCore,
            123,
            7,
        )
        .unwrap();
        let decoded = GtpuTrafficObservationEvent::decode(&event.encode()).unwrap();
        assert_eq!(decoded, event);
        assert_eq!(
            decoded.direction(),
            GtpuTrafficObservationDirection::AccessToCore
        );
        assert_eq!(decoded.group_key(), group_id().to_bytes());
        assert_eq!(decoded.boot_time_ns(), 123);
        assert_eq!(decoded.producer_sequence(), 7);
        assert_eq!(decoded.sample_id(), 1);
    }

    #[test]
    fn event_debug_redacts_authority_and_monotonic_time() {
        let event = GtpuTrafficObservationEvent::new(
            registration(),
            registration().challenge_stream_correlation_id(),
            1,
            GtpuTrafficObservationDirection::AccessToCore,
            123,
            7,
        )
        .unwrap();
        let rendered = std::format!("{event:?}");
        assert!(rendered.contains("AccessToCore"));
        assert!(rendered.contains("<monotonic>"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("123"));
    }

    #[test]
    fn decoding_rejects_zero_reserved_and_malformed_discriminants() {
        let mut malformed_registration = registration().encode();
        malformed_registration[BACKEND_INCARNATION_OFFSET..BACKEND_INCARNATION_OFFSET + 8].fill(0);
        assert!(GtpuTrafficObservationRegistration::decode(&malformed_registration).is_none());

        let mut zero_publication = registration().encode();
        zero_publication[PUBLICATION_ID_OFFSET..REGISTRATION_RESERVED_OFFSET].fill(0);
        assert!(GtpuTrafficObservationRegistration::decode(&zero_publication).is_none());

        let mut excessive_publication = registration().encode();
        excessive_publication[PUBLICATION_ID_OFFSET..REGISTRATION_RESERVED_OFFSET]
            .copy_from_slice(&(GTPU_TRAFFIC_OBSERVATION_PUBLICATION_ID_MAX + 1).to_be_bytes());
        assert!(GtpuTrafficObservationRegistration::decode(&excessive_publication).is_none());

        let mut malformed_profile = registration().encode();
        malformed_profile[REGISTRATION_RESERVED_OFFSET] = 4;
        assert!(GtpuTrafficObservationRegistration::decode(&malformed_profile).is_none());

        let mut registration_reserved = registration().encode();
        registration_reserved[REGISTRATION_RESERVED_OFFSET + 1] = 1;
        assert!(GtpuTrafficObservationRegistration::decode(&registration_reserved).is_none());

        let event = GtpuTrafficObservationEvent::new(
            registration(),
            registration().challenge_stream_correlation_id(),
            2,
            GtpuTrafficObservationDirection::CoreToAccess,
            456,
            8,
        )
        .unwrap();
        let mut malformed_direction = event.encode();
        malformed_direction[EVENT_DIRECTION_OFFSET] = 3;
        assert!(GtpuTrafficObservationEvent::decode(&malformed_direction).is_none());

        let mut reserved = event.encode();
        reserved[EVENT_RESERVED_OFFSET + 4] = 1;
        assert!(GtpuTrafficObservationEvent::decode(&reserved).is_none());

        let mut zero_sample = event.encode();
        zero_sample[EVENT_RESERVED_OFFSET..EVENT_RESERVED_OFFSET + 4].fill(0);
        assert!(GtpuTrafficObservationEvent::decode(&zero_sample).is_none());

        let mut zero_timestamp = event.encode();
        zero_timestamp[EVENT_BOOT_TIME_OFFSET..EVENT_BOOT_TIME_OFFSET + 8].fill(0);
        assert!(GtpuTrafficObservationEvent::decode(&zero_timestamp).is_none());

        let mut zero_sequence = event.encode();
        zero_sequence[EVENT_SEQUENCE_OFFSET..EVENT_SEQUENCE_OFFSET + 8].fill(0);
        assert!(GtpuTrafficObservationEvent::decode(&zero_sequence).is_none());
    }

    #[test]
    fn exact_current_authority_mismatch_suppresses_observation() {
        let registration = registration();
        assert!(registration.matches_current(group_id(), device_id(), generation()));
        assert!(!registration.matches_current(
            GtpuSessionGroupId::new([0x12; 16]).unwrap(),
            device_id(),
            generation(),
        ));
        assert!(!registration.matches_current(
            group_id(),
            GtpuSessionDeviceId::new([0x23; 16]).unwrap(),
            generation(),
        ));
        assert!(!registration.matches_current(
            group_id(),
            device_id(),
            GtpuSessionGeneration::new(8).unwrap(),
        ));
    }

    #[test]
    fn encoded_current_match_is_fenced_by_exact_publication_identity() {
        let registration = registration();
        let encoded = registration.encode();
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_publication_id_if_current(
                &encoded,
                group_id(),
                device_id(),
                generation(),
            ),
            Some(registration.publication_id())
        );
        assert!(GtpuTrafficObservationRegistration::encoded_matches_current(
            &encoded,
            group_id(),
            device_id(),
            generation(),
            registration.publication_id(),
        ));
        assert!(
            !GtpuTrafficObservationRegistration::encoded_matches_current(
                &encoded,
                group_id(),
                device_id(),
                generation(),
                registration.publication_id() + 1,
            )
        );
    }

    #[test]
    fn borrowed_authority_helpers_match_owned_binding_and_reject_mutation() {
        let registration = registration();
        let encoded = registration.encode();
        let authority = authority();
        let view = GtpuSessionAuthorityWireView::decode(&authority).unwrap();

        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_matches_current_authority(
                &encoded,
                view,
                registration.publication_id(),
            ),
            GtpuTrafficObservationRegistration::encoded_matches_current(
                &encoded,
                group_id(),
                device_id(),
                generation(),
                registration.publication_id(),
            ),
        );
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current_authority(
                &encoded, view,
            ),
            GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current(
                &encoded,
                group_id(),
                device_id(),
                generation(),
            ),
        );

        for offset in [4_usize, 16, 32] {
            let mut stale = authority;
            stale[offset] ^= 1;
            let stale = GtpuSessionAuthorityWireView::decode(&stale).unwrap();
            assert!(
                !GtpuTrafficObservationRegistration::encoded_matches_current_authority(
                    &encoded,
                    stale,
                    registration.publication_id(),
                )
            );
            assert_eq!(
                GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current_authority(
                    &encoded, stale,
                ),
                None,
            );
        }
        assert!(
            !GtpuTrafficObservationRegistration::encoded_matches_current_authority(
                &encoded,
                view,
                registration.publication_id() + 1,
            )
        );
    }

    #[test]
    fn exact_current_redirect_nonce_rejects_a_single_byte_mutation() {
        let registration = registration();
        let encoded = registration.encode();
        let nonce = registration.redirect_nonce();
        assert_eq!(
            GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current(
                &encoded,
                group_id(),
                device_id(),
                generation(),
            ),
            Some((nonce, registration.publication_id())),
        );
        let mut mutated = nonce;
        mutated[7] ^= 1;
        assert_ne!(
            GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current(
                &encoded,
                group_id(),
                device_id(),
                generation(),
            ),
            Some((mutated, registration.publication_id())),
        );
    }
}
