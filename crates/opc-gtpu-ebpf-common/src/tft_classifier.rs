//! Versioned map ABI and pure IPv4 matching for shared-SA uplink TFTs.
//!
//! The current GTP-U tc forwarding ABI is IPv4-only. This module therefore
//! exposes only the canonical IPv4 subset of the backend-neutral TFT model.
//! Callers must reject IPv6 filters before publishing them: encoding an IPv6
//! filter into this ABI is deliberately impossible.
//!
//! A classifier has one metadata entry and bounded filter entries in each of
//! two banks. Userspace writes and verifies every entry in the inactive bank,
//! then replaces the metadata value in one map operation to publish the new
//! bank. Every filter redundantly carries the opaque owner identity plus both
//! generations. The tc program validates those fields on every lookup, so a
//! stale, incomplete, or cross-owner record can only drop a packet. Exact
//! removal first converts active metadata into a fingerprint-bound tombstone;
//! tc rejects that canonical-but-inactive state while userspace removes the
//! records and, last, the tombstone. This makes cleanup retryable without ever
//! inferring a complete classifier from a surviving subset of filter rows.

use core::fmt;

/// Current shared-SA TFT map ABI version.
pub const TFT_CLASSIFIER_ABI_VERSION: u8 = 3;
/// The only inner family executable by the current GTP-U tc forwarding path.
pub const TFT_CLASSIFIER_FAMILY_IPV4: u8 = 4;
/// Number of immutable filter banks per classifier.
pub const TFT_CLASSIFIER_BANKS: u8 = 2;
/// Maximum canonical packet filters in one complete classifier snapshot.
///
/// This whole-classifier implementation bound follows the global `u8`
/// evaluation-precedence namespace: every filter associated with one PAA must
/// have a unique precedence, so at most 256 filters can be represented. It is
/// distinct from the maximum 15 filters in each individual TFT; packet-filter
/// identifiers use their separate four-bit `0..=15` namespace.
pub const TFT_CLASSIFIER_MAX_FILTERS: usize = 256;
/// Maximum representable components in one IPv4 filter.
///
/// One record has one slot for each supported canonical component category:
/// protocol, local/remote IPv4 address, local/remote port range, ToS, and ESP
/// SPI. The ABI has no component array and therefore no unbounded component
/// walk in tc.
pub const TFT_CLASSIFIER_MAX_COMPONENTS_PER_FILTER: usize = 7;
/// Maximum representable components in one complete classifier snapshot.
pub const TFT_CLASSIFIER_MAX_COMPONENTS: usize =
    TFT_CLASSIFIER_MAX_FILTERS * TFT_CLASSIFIER_MAX_COMPONENTS_PER_FILTER;
/// Pinned metadata-map capacity.
pub const TFT_CLASSIFIER_META_MAP_MAX_ENTRIES: u32 = 65_536;
/// Pinned filter-map capacity across both banks.
///
/// A publisher must preflight that all retained inactive-bank records and its
/// replacement records fit this fixed capacity before it touches metadata.
pub const TFT_CLASSIFIER_FILTER_MAP_MAX_ENTRIES: u32 = 65_536;
/// Number of bounded classifier-drop counters.
pub const TFT_CLASSIFIER_COUNTER_SLOTS: u32 = 3;

/// Shared-SA TFT schema marker map name.
pub const MAP_TFT_CLASSIFIER_SCHEMA: &str = "GTPU_TFT_SCHEMA";
/// Shared-SA TFT metadata map name.
pub const MAP_TFT_CLASSIFIER_META: &str = "GTPU_TFT_META";
/// Shared-SA TFT double-bank filter map name.
pub const MAP_TFT_CLASSIFIER_FILTERS: &str = "GTPU_TFT_FILT";
/// Shared-SA TFT bounded drop-counter map name.
pub const MAP_TFT_CLASSIFIER_COUNTERS: &str = "GTPU_TFT_DROP";

/// Schema-marker value width.
pub const TFT_CLASSIFIER_SCHEMA_VALUE_LEN: usize = 16;
/// Current schema marker for the additive IPv4-only classifier map graph.
pub const TFT_CLASSIFIER_SCHEMA_MARKER_VALUE: [u8; TFT_CLASSIFIER_SCHEMA_VALUE_LEN] =
    *b"OPC-TFT-IPv4-v3\0";
/// Classifier metadata-map key width.
pub const TFT_CLASSIFIER_KEY_LEN: usize = 8;
/// Exact classifier fingerprint width.
pub const TFT_CLASSIFIER_FINGERPRINT_LEN: usize = 32;
/// Classifier metadata-map value width.
pub const TFT_CLASSIFIER_META_VALUE_LEN: usize = 72;
/// Classifier filter-map key width.
pub const TFT_CLASSIFIER_FILTER_KEY_LEN: usize = 12;
/// Classifier filter-map value width.
pub const TFT_CLASSIFIER_FILTER_VALUE_LEN: usize = 72;

/// Counter index: an owned classifier received a malformed, truncated, or
/// fragmented IPv4 packet. Such packets never use the default bearer.
pub const COUNTER_TFT_CLASSIFIER_MALFORMED: u32 = 0;
/// Counter index: no filter matched and the exact snapshot has no default.
pub const COUNTER_TFT_CLASSIFIER_NO_MATCH: u32 = 1;
/// Counter index: a retained classifier map graph was stale, partial, or
/// internally inconsistent. The packet was dropped fail closed.
pub const COUNTER_TFT_CLASSIFIER_INVALID_STATE: u32 = 2;

const META_FLAG_HAS_DEFAULT: u8 = 1;
const META_FLAG_REMOVING: u8 = 1 << 1;
const META_VALID_FLAGS: u8 = META_FLAG_HAS_DEFAULT | META_FLAG_REMOVING;
const FILTER_MATCH_PROTOCOL: u8 = 1 << 0;
const FILTER_MATCH_LOCAL_ADDRESS: u8 = 1 << 1;
const FILTER_MATCH_REMOTE_ADDRESS: u8 = 1 << 2;
const FILTER_MATCH_LOCAL_PORT: u8 = 1 << 3;
const FILTER_MATCH_REMOTE_PORT: u8 = 1 << 4;
const FILTER_MATCH_TOS: u8 = 1 << 5;
const FILTER_MATCH_ESP_SPI: u8 = 1 << 6;
const FILTER_VALID_FLAGS: u8 = FILTER_MATCH_PROTOCOL
    | FILTER_MATCH_LOCAL_ADDRESS
    | FILTER_MATCH_REMOTE_ADDRESS
    | FILTER_MATCH_LOCAL_PORT
    | FILTER_MATCH_REMOTE_PORT
    | FILTER_MATCH_TOS
    | FILTER_MATCH_ESP_SPI;
const FILTER_IDENTIFIER_MASK: u8 = 0x0f;
const FILTER_DIRECTION_MASK: u8 = 0x30;
const FILTER_DIRECTION_UPLINK_ONLY: u8 = 0x20;
const FILTER_DIRECTION_BIDIRECTIONAL: u8 = 0x30;
const FILTER_LOCAL_PORT_RANGE: u8 = 0x40;
const FILTER_REMOTE_PORT_RANGE: u8 = 0x80;

/// Direction retained in a classifier record for exact userspace readback.
///
/// The tc matcher is uplink-only and therefore does not branch on this value;
/// it is nevertheless validated so map bytes cannot silently lose the public
/// TFT direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TftClassifierFilterDirection {
    /// The TFT applies only to uplink packets.
    UplinkOnly,
    /// The TFT applies in both directions.
    Bidirectional,
}

impl TftClassifierFilterDirection {
    const fn code(self) -> u8 {
        match self {
            Self::UplinkOnly => FILTER_DIRECTION_UPLINK_ONLY,
            Self::Bidirectional => FILTER_DIRECTION_BIDIRECTIONAL,
        }
    }

    const fn from_semantics(value: u8) -> Option<Self> {
        match value & FILTER_DIRECTION_MASK {
            FILTER_DIRECTION_UPLINK_ONLY => Some(Self::UplinkOnly),
            FILTER_DIRECTION_BIDIRECTIONAL => Some(Self::Bidirectional),
            _ => None,
        }
    }
}

/// Original TFT port component form retained for exact userspace readback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TftClassifierPortForm {
    /// A `SingleLocalPort` or `SingleRemotePort` component.
    SinglePort,
    /// A `LocalPortRange` or `RemotePortRange` component.
    PortRange,
}

/// Opaque stable identity of one classifier owner.
///
/// The value is supplied by the userspace ownership boundary. It is neither a
/// subscriber identity nor a value permitted in diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TftClassifierOwnerId([u8; 16]);

impl TftClassifierOwnerId {
    /// Construct a nonzero opaque owner identity.
    #[must_use]
    pub const fn new(value: [u8; 16]) -> Option<Self> {
        if bytes_are_zero(&value) {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Return the fixed-width value needed by a map publisher.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for TftClassifierOwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TftClassifierOwnerId(<redacted>)")
    }
}

/// Map key for one shared-SA classifier: attachment ifindex and IPv4 PAA.
///
/// Both fields are network-byte-order octets. The type is all-byte,
/// `repr(C)`, `Copy`, and alignment-one, so it is safe to use as a BPF map
/// key without native-endian or padding ambiguity.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TftClassifierKey {
    attachment_ifindex: [u8; 4],
    paa: [u8; 4],
}

impl TftClassifierKey {
    /// Construct the exact IPv4 classifier key.
    #[must_use]
    pub const fn new(attachment_ifindex: u32, paa: [u8; 4]) -> Option<Self> {
        if attachment_ifindex == 0 || bytes_are_zero(&paa) {
            None
        } else {
            Some(Self {
                attachment_ifindex: attachment_ifindex.to_be_bytes(),
                paa,
            })
        }
    }

    /// Return the attachment ifindex.
    #[must_use]
    pub const fn attachment_ifindex(self) -> u32 {
        u32::from_be_bytes(self.attachment_ifindex)
    }

    /// Return the IPv4 PAA in network byte order.
    #[must_use]
    pub const fn paa(self) -> [u8; 4] {
        self.paa
    }

    /// Return whether every field is canonical.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.attachment_ifindex() != 0 && !bytes_are_zero(&self.paa)
    }

    /// Encode this canonical key for byte-array BPF map I/O.
    #[must_use]
    pub const fn encode(self) -> [u8; TFT_CLASSIFIER_KEY_LEN] {
        [
            self.attachment_ifindex[0],
            self.attachment_ifindex[1],
            self.attachment_ifindex[2],
            self.attachment_ifindex[3],
            self.paa[0],
            self.paa[1],
            self.paa[2],
            self.paa[3],
        ]
    }

    /// Decode one canonical key from byte-array BPF map I/O.
    #[must_use]
    pub const fn decode(value: [u8; TFT_CLASSIFIER_KEY_LEN]) -> Option<Self> {
        let decoded = Self {
            attachment_ifindex: [value[0], value[1], value[2], value[3]],
            paa: [value[4], value[5], value[6], value[7]],
        };
        if decoded.is_valid() {
            Some(decoded)
        } else {
            None
        }
    }
}

impl fmt::Debug for TftClassifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftClassifierKey")
            .field("attachment", &"<redacted>")
            .field("paa", &"<redacted>")
            .finish()
    }
}

/// Metadata atomically selecting one complete filter bank or fencing its
/// exact removal.
///
/// All multi-octet values are stored as explicit big-endian byte arrays. The
/// last two bytes are explicit zero reservation rather than compiler padding.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TftClassifierMeta {
    abi_version: u8,
    family: u8,
    active_bank: u8,
    flags: u8,
    owner: [u8; 16],
    owner_generation: [u8; 8],
    snapshot_generation: [u8; 8],
    filter_count: [u8; 2],
    classifier_fingerprint: [u8; TFT_CLASSIFIER_FINGERPRINT_LEN],
    reserved: [u8; 2],
}

impl TftClassifierMeta {
    /// Construct one complete active-bank selector.
    #[must_use]
    pub const fn new(
        active_bank: u8,
        has_default: bool,
        owner: TftClassifierOwnerId,
        owner_generation: u64,
        snapshot_generation: u64,
        filter_count: u16,
        classifier_fingerprint: [u8; TFT_CLASSIFIER_FINGERPRINT_LEN],
    ) -> Option<Self> {
        if active_bank >= TFT_CLASSIFIER_BANKS
            || owner_generation == 0
            || snapshot_generation == 0
            || filter_count as usize > TFT_CLASSIFIER_MAX_FILTERS
            || (!has_default && filter_count == 0)
            || bytes_are_zero(&classifier_fingerprint)
        {
            return None;
        }
        Some(Self {
            abi_version: TFT_CLASSIFIER_ABI_VERSION,
            family: TFT_CLASSIFIER_FAMILY_IPV4,
            active_bank,
            flags: if has_default {
                META_FLAG_HAS_DEFAULT
            } else {
                0
            },
            owner: owner.into_bytes(),
            owner_generation: owner_generation.to_be_bytes(),
            snapshot_generation: snapshot_generation.to_be_bytes(),
            filter_count: filter_count.to_be_bytes(),
            classifier_fingerprint,
            reserved: [0; 2],
        })
    }

    /// Convert an active selector into its durable exact-removal fence.
    ///
    /// The fingerprint and all publication identity remain unchanged. The tc
    /// datapath rejects this state, while userspace can prove and finish the
    /// exact cleanup after acknowledgement loss or process restart.
    #[must_use]
    pub const fn removing(mut self) -> Option<Self> {
        if !self.is_valid() {
            return None;
        }
        self.flags |= META_FLAG_REMOVING;
        Some(self)
    }

    /// Return the selected filter bank.
    #[must_use]
    pub const fn active_bank(&self) -> u8 {
        self.active_bank
    }

    /// Return whether unmatched packets select mark zero.
    #[must_use]
    pub const fn has_default(&self) -> bool {
        self.flags & META_FLAG_HAS_DEFAULT != 0
    }

    /// Return whether this metadata is a durable exact-removal fence.
    #[must_use]
    pub const fn is_removing(&self) -> bool {
        self.flags & META_FLAG_REMOVING != 0
    }

    /// Return the opaque owner identity.
    #[must_use]
    pub const fn owner(&self) -> Option<TftClassifierOwnerId> {
        TftClassifierOwnerId::new(self.owner)
    }

    /// Return the nonzero fenced owner generation.
    #[must_use]
    pub const fn owner_generation(&self) -> u64 {
        u64::from_be_bytes(self.owner_generation)
    }

    /// Return the nonzero exact-snapshot generation.
    #[must_use]
    pub const fn snapshot_generation(&self) -> u64 {
        u64::from_be_bytes(self.snapshot_generation)
    }

    /// Return the exact active-bank filter count.
    #[must_use]
    pub const fn filter_count(&self) -> u16 {
        u16::from_be_bytes(self.filter_count)
    }

    /// Return the SHA-256 fingerprint of the exact encoded classifier.
    #[must_use]
    pub const fn classifier_fingerprint(&self) -> [u8; TFT_CLASSIFIER_FINGERPRINT_LEN] {
        self.classifier_fingerprint
    }

    /// Return whether this is a canonical active selector.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.is_canonical() && !self.is_removing()
    }

    /// Return whether this is a canonical removal fence.
    #[must_use]
    pub const fn is_valid_removal_fence(&self) -> bool {
        self.is_canonical() && self.is_removing()
    }

    const fn is_canonical(&self) -> bool {
        self.abi_version == TFT_CLASSIFIER_ABI_VERSION
            && self.family == TFT_CLASSIFIER_FAMILY_IPV4
            && self.active_bank < TFT_CLASSIFIER_BANKS
            && self.flags & !META_VALID_FLAGS == 0
            && !bytes_are_zero(&self.owner)
            && self.owner_generation() != 0
            && self.snapshot_generation() != 0
            && self.filter_count() as usize <= TFT_CLASSIFIER_MAX_FILTERS
            && (self.has_default() || self.filter_count() != 0)
            && !bytes_are_zero(&self.classifier_fingerprint)
            && bytes_are_zero(&self.reserved)
    }

    /// Encode this canonical metadata record for byte-array BPF map I/O.
    #[must_use]
    pub const fn encode(self) -> [u8; TFT_CLASSIFIER_META_VALUE_LEN] {
        [
            self.abi_version,
            self.family,
            self.active_bank,
            self.flags,
            self.owner[0],
            self.owner[1],
            self.owner[2],
            self.owner[3],
            self.owner[4],
            self.owner[5],
            self.owner[6],
            self.owner[7],
            self.owner[8],
            self.owner[9],
            self.owner[10],
            self.owner[11],
            self.owner[12],
            self.owner[13],
            self.owner[14],
            self.owner[15],
            self.owner_generation[0],
            self.owner_generation[1],
            self.owner_generation[2],
            self.owner_generation[3],
            self.owner_generation[4],
            self.owner_generation[5],
            self.owner_generation[6],
            self.owner_generation[7],
            self.snapshot_generation[0],
            self.snapshot_generation[1],
            self.snapshot_generation[2],
            self.snapshot_generation[3],
            self.snapshot_generation[4],
            self.snapshot_generation[5],
            self.snapshot_generation[6],
            self.snapshot_generation[7],
            self.filter_count[0],
            self.filter_count[1],
            self.classifier_fingerprint[0],
            self.classifier_fingerprint[1],
            self.classifier_fingerprint[2],
            self.classifier_fingerprint[3],
            self.classifier_fingerprint[4],
            self.classifier_fingerprint[5],
            self.classifier_fingerprint[6],
            self.classifier_fingerprint[7],
            self.classifier_fingerprint[8],
            self.classifier_fingerprint[9],
            self.classifier_fingerprint[10],
            self.classifier_fingerprint[11],
            self.classifier_fingerprint[12],
            self.classifier_fingerprint[13],
            self.classifier_fingerprint[14],
            self.classifier_fingerprint[15],
            self.classifier_fingerprint[16],
            self.classifier_fingerprint[17],
            self.classifier_fingerprint[18],
            self.classifier_fingerprint[19],
            self.classifier_fingerprint[20],
            self.classifier_fingerprint[21],
            self.classifier_fingerprint[22],
            self.classifier_fingerprint[23],
            self.classifier_fingerprint[24],
            self.classifier_fingerprint[25],
            self.classifier_fingerprint[26],
            self.classifier_fingerprint[27],
            self.classifier_fingerprint[28],
            self.classifier_fingerprint[29],
            self.classifier_fingerprint[30],
            self.classifier_fingerprint[31],
            self.reserved[0],
            self.reserved[1],
        ]
    }

    /// Decode one canonical metadata record from byte-array BPF map I/O.
    #[must_use]
    pub const fn decode(value: [u8; TFT_CLASSIFIER_META_VALUE_LEN]) -> Option<Self> {
        let decoded = Self {
            abi_version: value[0],
            family: value[1],
            active_bank: value[2],
            flags: value[3],
            owner: [
                value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11],
                value[12], value[13], value[14], value[15], value[16], value[17], value[18],
                value[19],
            ],
            owner_generation: [
                value[20], value[21], value[22], value[23], value[24], value[25], value[26],
                value[27],
            ],
            snapshot_generation: [
                value[28], value[29], value[30], value[31], value[32], value[33], value[34],
                value[35],
            ],
            filter_count: [value[36], value[37]],
            classifier_fingerprint: [
                value[38], value[39], value[40], value[41], value[42], value[43], value[44],
                value[45], value[46], value[47], value[48], value[49], value[50], value[51],
                value[52], value[53], value[54], value[55], value[56], value[57], value[58],
                value[59], value[60], value[61], value[62], value[63], value[64], value[65],
                value[66], value[67], value[68], value[69],
            ],
            reserved: [value[70], value[71]],
        };
        if decoded.is_canonical() {
            Some(decoded)
        } else {
            None
        }
    }
}

impl fmt::Debug for TftClassifierMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftClassifierMeta")
            .field("abi_version", &self.abi_version)
            .field("family", &self.family)
            .field("active_bank", &self.active_bank)
            .field("has_default", &self.has_default())
            .field("owner", &"<redacted>")
            .field("owner_generation", &"<redacted>")
            .field("snapshot_generation", &"<redacted>")
            .field("filter_count", &self.filter_count())
            .field("removing", &self.is_removing())
            .field("classifier_fingerprint", &"<redacted>")
            .finish()
    }
}

/// Map key for one exact indexed filter in a classifier bank.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TftClassifierFilterKey {
    classifier: TftClassifierKey,
    bank: u8,
    reserved: u8,
    filter_index: [u8; 2],
}

impl TftClassifierFilterKey {
    /// Construct an exact filter-map key.
    #[must_use]
    pub const fn new(classifier: TftClassifierKey, bank: u8, filter_index: u16) -> Option<Self> {
        if !classifier.is_valid()
            || bank >= TFT_CLASSIFIER_BANKS
            || filter_index as usize >= TFT_CLASSIFIER_MAX_FILTERS
        {
            None
        } else {
            Some(Self {
                classifier,
                bank,
                reserved: 0,
                filter_index: filter_index.to_be_bytes(),
            })
        }
    }

    /// Return the owning classifier key.
    #[must_use]
    pub const fn classifier(self) -> TftClassifierKey {
        self.classifier
    }

    /// Return the bank.
    #[must_use]
    pub const fn bank(self) -> u8 {
        self.bank
    }

    /// Return the fixed index in the selected bank.
    #[must_use]
    pub const fn filter_index(self) -> u16 {
        u16::from_be_bytes(self.filter_index)
    }

    /// Return whether every field is canonical.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.classifier.is_valid()
            && self.bank < TFT_CLASSIFIER_BANKS
            && self.reserved == 0
            && (self.filter_index() as usize) < TFT_CLASSIFIER_MAX_FILTERS
    }

    /// Encode this canonical filter key for byte-array BPF map I/O.
    #[must_use]
    pub const fn encode(self) -> [u8; TFT_CLASSIFIER_FILTER_KEY_LEN] {
        let classifier = self.classifier.encode();
        [
            classifier[0],
            classifier[1],
            classifier[2],
            classifier[3],
            classifier[4],
            classifier[5],
            classifier[6],
            classifier[7],
            self.bank,
            self.reserved,
            self.filter_index[0],
            self.filter_index[1],
        ]
    }

    /// Decode one canonical filter key from byte-array BPF map I/O.
    #[must_use]
    pub const fn decode(value: [u8; TFT_CLASSIFIER_FILTER_KEY_LEN]) -> Option<Self> {
        let classifier = match TftClassifierKey::decode([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]) {
            Some(value) => value,
            None => return None,
        };
        let decoded = Self {
            classifier,
            bank: value[8],
            reserved: value[9],
            filter_index: [value[10], value[11]],
        };
        if decoded.is_valid() {
            Some(decoded)
        } else {
            None
        }
    }
}

impl fmt::Debug for TftClassifierFilterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftClassifierFilterKey")
            .field("classifier", &self.classifier)
            .field("bank", &self.bank)
            .field("filter_index", &self.filter_index())
            .finish()
    }
}

/// Exact IPv4 masked-address component.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TftClassifierIpv4Address {
    address: [u8; 4],
    mask: [u8; 4],
}

impl TftClassifierIpv4Address {
    /// Construct an IPv4 address/mask component in network byte order.
    #[must_use]
    pub const fn new(address: [u8; 4], mask: [u8; 4]) -> Self {
        Self { address, mask }
    }

    /// Return the address in network byte order.
    #[must_use]
    pub const fn address(self) -> [u8; 4] {
        self.address
    }

    /// Return the mask in network byte order.
    #[must_use]
    pub const fn mask(self) -> [u8; 4] {
        self.mask
    }
}

impl fmt::Debug for TftClassifierIpv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TftClassifierIpv4Address(<redacted>)")
    }
}

/// Inclusive local or remote port component.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TftClassifierPortRange {
    first: u16,
    last: u16,
}

impl TftClassifierPortRange {
    /// Construct an inclusive canonical port range. Equal endpoints encode a
    /// canonical single-port filter.
    #[must_use]
    pub const fn new(first: u16, last: u16) -> Option<Self> {
        if first <= last {
            Some(Self { first, last })
        } else {
            None
        }
    }

    /// Inclusive first port.
    #[must_use]
    pub const fn first(self) -> u16 {
        self.first
    }

    /// Inclusive last port.
    #[must_use]
    pub const fn last(self) -> u16 {
        self.last
    }
}

impl fmt::Debug for TftClassifierPortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TftClassifierPortRange(<redacted>)")
    }
}

/// Type-of-service component for an IPv4 filter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TftClassifierTos {
    value: u8,
    mask: u8,
}

impl TftClassifierTos {
    /// Construct an exact ToS value/mask component.
    ///
    /// Bits outside `mask` do not participate in matching, but their original
    /// wire values are retained for exact classifier readback.
    #[must_use]
    pub const fn new(value: u8, mask: u8) -> Self {
        Self { value, mask }
    }

    /// ToS value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.value
    }

    /// ToS mask.
    #[must_use]
    pub const fn mask(self) -> u8 {
        self.mask
    }
}

impl fmt::Debug for TftClassifierTos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TftClassifierTos(<redacted>)")
    }
}

/// Complete supported component set of one canonical IPv4 TFT filter.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct TftClassifierIpv4FilterSpec {
    /// Exact IPv4 protocol identifier, if present.
    pub protocol: Option<u8>,
    /// Source (local/PAA-side) IPv4 address component, if present.
    pub local_address: Option<TftClassifierIpv4Address>,
    /// Destination (remote) IPv4 address component, if present.
    pub remote_address: Option<TftClassifierIpv4Address>,
    /// Source (local) port component, if present.
    pub local_port: Option<TftClassifierPortRange>,
    /// Destination (remote) port component, if present.
    pub remote_port: Option<TftClassifierPortRange>,
    /// IPv4 ToS value/mask component, if present.
    pub tos: Option<TftClassifierTos>,
    /// ESP SPI component, if present.
    pub esp_spi: Option<u32>,
}

impl TftClassifierIpv4FilterSpec {
    /// Return the number of explicitly present supported components.
    #[must_use]
    pub const fn component_count(self) -> usize {
        self.protocol.is_some() as usize
            + self.local_address.is_some() as usize
            + self.remote_address.is_some() as usize
            + self.local_port.is_some() as usize
            + self.remote_port.is_some() as usize
            + self.tos.is_some() as usize
            + self.esp_spi.is_some() as usize
    }

    const fn is_valid(self) -> bool {
        self.component_count() != 0
            && self.component_count() <= TFT_CLASSIFIER_MAX_COMPONENTS_PER_FILTER
            && !(self.esp_spi.is_some()
                && (self.local_port.is_some() || self.remote_port.is_some()))
    }
}

impl fmt::Debug for TftClassifierIpv4FilterSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftClassifierIpv4FilterSpec")
            .field("component_count", &self.component_count())
            .finish()
    }
}

/// One fixed-width, all-byte filter-map value.
///
/// The record has no compiler padding. Its formerly reserved semantic octet
/// retains the packet-filter identifier, direction, and port component forms;
/// the other explicit reservation bytes must be zero. It contains all
/// supported IPv4 component categories, plus the complete owner/snapshot
/// identity required to reject stale bank entries.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TftClassifierFilter {
    owner: [u8; 16],
    owner_generation: [u8; 8],
    snapshot_generation: [u8; 8],
    evaluation_precedence: u8,
    flags: u8,
    semantics: u8,
    reserved0: u8,
    bearer_mark: [u8; 4],
    local_address: [u8; 4],
    local_mask: [u8; 4],
    remote_address: [u8; 4],
    remote_mask: [u8; 4],
    local_port_first: [u8; 2],
    local_port_last: [u8; 2],
    remote_port_first: [u8; 2],
    remote_port_last: [u8; 2],
    protocol: u8,
    tos_value: u8,
    tos_mask: u8,
    reserved1: u8,
    esp_spi: [u8; 4],
}

impl TftClassifierFilter {
    /// Construct one fully canonical IPv4 classifier filter.
    #[must_use]
    pub const fn new(
        owner: TftClassifierOwnerId,
        owner_generation: u64,
        snapshot_generation: u64,
        evaluation_precedence: u8,
        bearer_mark: u32,
        spec: TftClassifierIpv4FilterSpec,
    ) -> Option<Self> {
        let local_port_form = match spec.local_port {
            Some(value) if value.first() == value.last() => Some(TftClassifierPortForm::SinglePort),
            Some(_) => Some(TftClassifierPortForm::PortRange),
            None => None,
        };
        let remote_port_form = match spec.remote_port {
            Some(value) if value.first() == value.last() => Some(TftClassifierPortForm::SinglePort),
            Some(_) => Some(TftClassifierPortForm::PortRange),
            None => None,
        };
        Self::new_with_semantics(
            owner,
            owner_generation,
            snapshot_generation,
            evaluation_precedence,
            bearer_mark,
            0,
            TftClassifierFilterDirection::UplinkOnly,
            local_port_form,
            remote_port_form,
            spec,
        )
    }

    /// Construct one fully canonical IPv4 classifier filter while retaining
    /// exact public-TFT semantics that do not affect tc matching.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new_with_semantics(
        owner: TftClassifierOwnerId,
        owner_generation: u64,
        snapshot_generation: u64,
        evaluation_precedence: u8,
        bearer_mark: u32,
        packet_filter_identifier: u8,
        direction: TftClassifierFilterDirection,
        local_port_form: Option<TftClassifierPortForm>,
        remote_port_form: Option<TftClassifierPortForm>,
        spec: TftClassifierIpv4FilterSpec,
    ) -> Option<Self> {
        if owner_generation == 0
            || snapshot_generation == 0
            || bearer_mark == 0
            || !spec.is_valid()
            || packet_filter_identifier > FILTER_IDENTIFIER_MASK
            || !port_form_is_canonical(spec.local_port, local_port_form)
            || !port_form_is_canonical(spec.remote_port, remote_port_form)
        {
            return None;
        }
        let semantics = packet_filter_identifier
            | direction.code()
            | match local_port_form {
                Some(TftClassifierPortForm::PortRange) => FILTER_LOCAL_PORT_RANGE,
                Some(TftClassifierPortForm::SinglePort) | None => 0,
            }
            | match remote_port_form {
                Some(TftClassifierPortForm::PortRange) => FILTER_REMOTE_PORT_RANGE,
                Some(TftClassifierPortForm::SinglePort) | None => 0,
            };
        let flags = (if spec.protocol.is_some() {
            FILTER_MATCH_PROTOCOL
        } else {
            0
        }) | (if spec.local_address.is_some() {
            FILTER_MATCH_LOCAL_ADDRESS
        } else {
            0
        }) | (if spec.remote_address.is_some() {
            FILTER_MATCH_REMOTE_ADDRESS
        } else {
            0
        }) | (if spec.local_port.is_some() {
            FILTER_MATCH_LOCAL_PORT
        } else {
            0
        }) | (if spec.remote_port.is_some() {
            FILTER_MATCH_REMOTE_PORT
        } else {
            0
        }) | (if spec.tos.is_some() {
            FILTER_MATCH_TOS
        } else {
            0
        }) | (if spec.esp_spi.is_some() {
            FILTER_MATCH_ESP_SPI
        } else {
            0
        });
        let local_address = match spec.local_address {
            Some(value) => value.address(),
            None => [0; 4],
        };
        let local_mask = match spec.local_address {
            Some(value) => value.mask(),
            None => [0; 4],
        };
        let remote_address = match spec.remote_address {
            Some(value) => value.address(),
            None => [0; 4],
        };
        let remote_mask = match spec.remote_address {
            Some(value) => value.mask(),
            None => [0; 4],
        };
        let local_port_first = match spec.local_port {
            Some(value) => value.first().to_be_bytes(),
            None => [0; 2],
        };
        let local_port_last = match spec.local_port {
            Some(value) => value.last().to_be_bytes(),
            None => [0; 2],
        };
        let remote_port_first = match spec.remote_port {
            Some(value) => value.first().to_be_bytes(),
            None => [0; 2],
        };
        let remote_port_last = match spec.remote_port {
            Some(value) => value.last().to_be_bytes(),
            None => [0; 2],
        };
        let protocol = match spec.protocol {
            Some(value) => value,
            None => 0,
        };
        let tos_value = match spec.tos {
            Some(value) => value.value(),
            None => 0,
        };
        let tos_mask = match spec.tos {
            Some(value) => value.mask(),
            None => 0,
        };
        let esp_spi = match spec.esp_spi {
            Some(value) => value.to_be_bytes(),
            None => [0; 4],
        };
        Some(Self {
            owner: owner.into_bytes(),
            owner_generation: owner_generation.to_be_bytes(),
            snapshot_generation: snapshot_generation.to_be_bytes(),
            evaluation_precedence,
            flags,
            semantics,
            reserved0: 0,
            bearer_mark: bearer_mark.to_be_bytes(),
            local_address,
            local_mask,
            remote_address,
            remote_mask,
            local_port_first,
            local_port_last,
            remote_port_first,
            remote_port_last,
            protocol,
            tos_value,
            tos_mask,
            reserved1: 0,
            esp_spi,
        })
    }

    /// Return this filter's evaluation precedence.
    #[must_use]
    pub const fn evaluation_precedence(&self) -> u8 {
        self.evaluation_precedence
    }

    /// Return the original four-bit packet-filter identifier.
    #[must_use]
    pub const fn packet_filter_identifier(&self) -> u8 {
        self.semantics & FILTER_IDENTIFIER_MASK
    }

    /// Return the original allowed TFT direction.
    #[must_use]
    pub const fn direction(&self) -> TftClassifierFilterDirection {
        match TftClassifierFilterDirection::from_semantics(self.semantics) {
            Some(value) => value,
            None => TftClassifierFilterDirection::UplinkOnly,
        }
    }

    /// Return the original local-port component form, if one is present.
    #[must_use]
    pub const fn local_port_form(&self) -> Option<TftClassifierPortForm> {
        if !self.has_local_port() {
            None
        } else if self.semantics & FILTER_LOCAL_PORT_RANGE != 0 {
            Some(TftClassifierPortForm::PortRange)
        } else {
            Some(TftClassifierPortForm::SinglePort)
        }
    }

    /// Return the original remote-port component form, if one is present.
    #[must_use]
    pub const fn remote_port_form(&self) -> Option<TftClassifierPortForm> {
        if !self.has_remote_port() {
            None
        } else if self.semantics & FILTER_REMOTE_PORT_RANGE != 0 {
            Some(TftClassifierPortForm::PortRange)
        } else {
            Some(TftClassifierPortForm::SinglePort)
        }
    }

    /// Return the selected nonzero Linux packet mark.
    #[must_use]
    pub const fn bearer_mark(&self) -> u32 {
        u32::from_be_bytes(self.bearer_mark)
    }

    /// Return the opaque owner identity.
    #[must_use]
    pub const fn owner(&self) -> Option<TftClassifierOwnerId> {
        TftClassifierOwnerId::new(self.owner)
    }

    /// Return the nonzero owner generation.
    #[must_use]
    pub const fn owner_generation_value(&self) -> u64 {
        self.owner_generation()
    }

    /// Return the nonzero snapshot generation.
    #[must_use]
    pub const fn snapshot_generation_value(&self) -> u64 {
        self.snapshot_generation()
    }

    /// Return the complete supported IPv4 component set.
    #[must_use]
    pub const fn spec(&self) -> TftClassifierIpv4FilterSpec {
        TftClassifierIpv4FilterSpec {
            protocol: if self.has_protocol() {
                Some(self.protocol)
            } else {
                None
            },
            local_address: if self.has_local_address() {
                Some(TftClassifierIpv4Address::new(
                    self.local_address,
                    self.local_mask,
                ))
            } else {
                None
            },
            remote_address: if self.has_remote_address() {
                Some(TftClassifierIpv4Address::new(
                    self.remote_address,
                    self.remote_mask,
                ))
            } else {
                None
            },
            local_port: if self.has_local_port() {
                TftClassifierPortRange::new(
                    u16::from_be_bytes(self.local_port_first),
                    u16::from_be_bytes(self.local_port_last),
                )
            } else {
                None
            },
            remote_port: if self.has_remote_port() {
                TftClassifierPortRange::new(
                    u16::from_be_bytes(self.remote_port_first),
                    u16::from_be_bytes(self.remote_port_last),
                )
            } else {
                None
            },
            tos: if self.has_tos() {
                Some(TftClassifierTos::new(self.tos_value, self.tos_mask))
            } else {
                None
            },
            esp_spi: if self.has_esp_spi() {
                Some(u32::from_be_bytes(self.esp_spi))
            } else {
                None
            },
        }
    }

    /// Encode this canonical filter record for byte-array BPF map I/O.
    #[must_use]
    pub fn encode(self) -> [u8; TFT_CLASSIFIER_FILTER_VALUE_LEN] {
        let mut value = [0; TFT_CLASSIFIER_FILTER_VALUE_LEN];
        value[0..16].copy_from_slice(&self.owner);
        value[16..24].copy_from_slice(&self.owner_generation);
        value[24..32].copy_from_slice(&self.snapshot_generation);
        value[32] = self.evaluation_precedence;
        value[33] = self.flags;
        value[34] = self.semantics;
        value[35] = self.reserved0;
        value[36..40].copy_from_slice(&self.bearer_mark);
        value[40..44].copy_from_slice(&self.local_address);
        value[44..48].copy_from_slice(&self.local_mask);
        value[48..52].copy_from_slice(&self.remote_address);
        value[52..56].copy_from_slice(&self.remote_mask);
        value[56..58].copy_from_slice(&self.local_port_first);
        value[58..60].copy_from_slice(&self.local_port_last);
        value[60..62].copy_from_slice(&self.remote_port_first);
        value[62..64].copy_from_slice(&self.remote_port_last);
        value[64] = self.protocol;
        value[65] = self.tos_value;
        value[66] = self.tos_mask;
        value[67] = self.reserved1;
        value[68..72].copy_from_slice(&self.esp_spi);
        value
    }

    /// Decode one canonical filter record from byte-array BPF map I/O.
    #[must_use]
    pub fn decode(value: [u8; TFT_CLASSIFIER_FILTER_VALUE_LEN]) -> Option<Self> {
        let mut owner = [0; 16];
        owner.copy_from_slice(&value[0..16]);
        let mut owner_generation = [0; 8];
        owner_generation.copy_from_slice(&value[16..24]);
        let mut snapshot_generation = [0; 8];
        snapshot_generation.copy_from_slice(&value[24..32]);
        let mut bearer_mark = [0; 4];
        bearer_mark.copy_from_slice(&value[36..40]);
        let mut local_address = [0; 4];
        local_address.copy_from_slice(&value[40..44]);
        let mut local_mask = [0; 4];
        local_mask.copy_from_slice(&value[44..48]);
        let mut remote_address = [0; 4];
        remote_address.copy_from_slice(&value[48..52]);
        let mut remote_mask = [0; 4];
        remote_mask.copy_from_slice(&value[52..56]);
        let mut local_port_first = [0; 2];
        local_port_first.copy_from_slice(&value[56..58]);
        let mut local_port_last = [0; 2];
        local_port_last.copy_from_slice(&value[58..60]);
        let mut remote_port_first = [0; 2];
        remote_port_first.copy_from_slice(&value[60..62]);
        let mut remote_port_last = [0; 2];
        remote_port_last.copy_from_slice(&value[62..64]);
        let mut esp_spi = [0; 4];
        esp_spi.copy_from_slice(&value[68..72]);
        let decoded = Self {
            owner,
            owner_generation,
            snapshot_generation,
            evaluation_precedence: value[32],
            flags: value[33],
            semantics: value[34],
            reserved0: value[35],
            bearer_mark,
            local_address,
            local_mask,
            remote_address,
            remote_mask,
            local_port_first,
            local_port_last,
            remote_port_first,
            remote_port_last,
            protocol: value[64],
            tos_value: value[65],
            tos_mask: value[66],
            reserved1: value[67],
            esp_spi,
        };
        if decoded.is_valid() {
            Some(decoded)
        } else {
            None
        }
    }

    /// Return whether this record is structurally canonical.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.flags & !FILTER_VALID_FLAGS == 0
            && self.flags != 0
            && !bytes_are_zero(&self.owner)
            && self.owner_generation() != 0
            && self.snapshot_generation() != 0
            && self.bearer_mark() != 0
            && self.reserved0 == 0
            && self.reserved1 == 0
            && TftClassifierFilterDirection::from_semantics(self.semantics).is_some()
            && self.port_forms_are_canonical()
            && self.absent_fields_are_zero()
            && self.present_ranges_are_canonical()
            && !(self.has_esp_spi() && (self.has_local_port() || self.has_remote_port()))
    }

    /// Return whether this record belongs to exactly `meta`'s active snapshot.
    #[must_use]
    pub const fn belongs_to(&self, meta: &TftClassifierMeta) -> bool {
        self.is_valid()
            && meta.is_valid()
            && bytes_equal(&self.owner, &meta.owner)
            && bytes_equal(&self.owner_generation, &meta.owner_generation)
            && bytes_equal(&self.snapshot_generation, &meta.snapshot_generation)
    }

    const fn owner_generation(&self) -> u64 {
        u64::from_be_bytes(self.owner_generation)
    }

    const fn snapshot_generation(&self) -> u64 {
        u64::from_be_bytes(self.snapshot_generation)
    }

    const fn has_protocol(&self) -> bool {
        self.flags & FILTER_MATCH_PROTOCOL != 0
    }

    const fn has_local_address(&self) -> bool {
        self.flags & FILTER_MATCH_LOCAL_ADDRESS != 0
    }

    const fn has_remote_address(&self) -> bool {
        self.flags & FILTER_MATCH_REMOTE_ADDRESS != 0
    }

    const fn has_local_port(&self) -> bool {
        self.flags & FILTER_MATCH_LOCAL_PORT != 0
    }

    const fn has_remote_port(&self) -> bool {
        self.flags & FILTER_MATCH_REMOTE_PORT != 0
    }

    const fn has_tos(&self) -> bool {
        self.flags & FILTER_MATCH_TOS != 0
    }

    const fn has_esp_spi(&self) -> bool {
        self.flags & FILTER_MATCH_ESP_SPI != 0
    }

    const fn absent_fields_are_zero(&self) -> bool {
        (self.has_protocol() || self.protocol == 0)
            && (self.has_local_address()
                || (bytes_are_zero(&self.local_address) && bytes_are_zero(&self.local_mask)))
            && (self.has_remote_address()
                || (bytes_are_zero(&self.remote_address) && bytes_are_zero(&self.remote_mask)))
            && (self.has_local_port()
                || (bytes_are_zero(&self.local_port_first)
                    && bytes_are_zero(&self.local_port_last)))
            && (self.has_remote_port()
                || (bytes_are_zero(&self.remote_port_first)
                    && bytes_are_zero(&self.remote_port_last)))
            && (self.has_tos() || (self.tos_value == 0 && self.tos_mask == 0))
            && (self.has_esp_spi() || bytes_are_zero(&self.esp_spi))
    }

    const fn present_ranges_are_canonical(&self) -> bool {
        (!self.has_local_port()
            || u16::from_be_bytes(self.local_port_first)
                <= u16::from_be_bytes(self.local_port_last))
            && (!self.has_remote_port()
                || u16::from_be_bytes(self.remote_port_first)
                    <= u16::from_be_bytes(self.remote_port_last))
    }

    const fn port_forms_are_canonical(&self) -> bool {
        ((!self.has_local_port() && self.semantics & FILTER_LOCAL_PORT_RANGE == 0)
            || (self.has_local_port()
                && (self.semantics & FILTER_LOCAL_PORT_RANGE != 0
                    || bytes_equal(&self.local_port_first, &self.local_port_last))))
            && ((!self.has_remote_port() && self.semantics & FILTER_REMOTE_PORT_RANGE == 0)
                || (self.has_remote_port()
                    && (self.semantics & FILTER_REMOTE_PORT_RANGE != 0
                        || bytes_equal(&self.remote_port_first, &self.remote_port_last))))
    }
}

const fn port_form_is_canonical(
    port: Option<TftClassifierPortRange>,
    form: Option<TftClassifierPortForm>,
) -> bool {
    match (port, form) {
        (None, None) | (Some(_), Some(TftClassifierPortForm::PortRange)) => true,
        (Some(value), Some(TftClassifierPortForm::SinglePort)) => value.first() == value.last(),
        _ => false,
    }
}

impl fmt::Debug for TftClassifierFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftClassifierFilter")
            .field("evaluation_precedence", &self.evaluation_precedence)
            .field("component_count", &self.flags.count_ones())
            .field("owner", &"<redacted>")
            .field("owner_generation", &"<redacted>")
            .field("snapshot_generation", &"<redacted>")
            .field("bearer_mark", &"<redacted>")
            .finish()
    }
}

/// Parsed inner IPv4 fields used by the supported TFT component set.
///
/// It intentionally has no `Debug` implementation so raw packet values are
/// not accidentally emitted by diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TftClassifierIpv4Packet {
    local_address: [u8; 4],
    remote_address: [u8; 4],
    protocol: u8,
    tos: u8,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    esp_spi: Option<u32>,
}

impl TftClassifierIpv4Packet {
    /// Construct a packet view after a boundary has completed strict parsing.
    #[must_use]
    pub const fn new(
        local_address: [u8; 4],
        remote_address: [u8; 4],
        protocol: u8,
        tos: u8,
        local_port: Option<u16>,
        remote_port: Option<u16>,
        esp_spi: Option<u32>,
    ) -> Self {
        Self {
            local_address,
            remote_address,
            protocol,
            tos,
            local_port,
            remote_port,
            esp_spi,
        }
    }

    /// Strictly parse one exact inner IPv4 packet.
    ///
    /// IPv4 fragments, trailing bytes, truncated TCP/UDP/ESP payloads, and
    /// malformed TCP/UDP lengths return `None`. This is shared with host tests
    /// to define the same fail-closed boundary used by tc.
    #[must_use]
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(packet[0] & 0x0f).checked_mul(4)?;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if header_len < 20
            || header_len > packet.len()
            || total_len != packet.len()
            || total_len < header_len
            || fragment & 0xbfff != 0
        {
            return None;
        }
        let protocol = packet[9];
        let local_address = [packet[12], packet[13], packet[14], packet[15]];
        let remote_address = [packet[16], packet[17], packet[18], packet[19]];
        let payload = &packet[header_len..];
        let (local_port, remote_port) = match protocol {
            6 => {
                if payload.len() < 20 {
                    return None;
                }
                let tcp_header_len = usize::from(payload[12] >> 4).checked_mul(4)?;
                if tcp_header_len < 20 || tcp_header_len > payload.len() {
                    return None;
                }
                (
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                )
            }
            17 => {
                if payload.len() < 8
                    || usize::from(u16::from_be_bytes([payload[4], payload[5]])) != payload.len()
                {
                    return None;
                }
                (
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                )
            }
            _ => (None, None),
        };
        let esp_spi = if protocol == 50 {
            if payload.len() < 8 {
                return None;
            }
            Some(u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]))
        } else {
            None
        };
        Some(Self::new(
            local_address,
            remote_address,
            protocol,
            packet[1],
            local_port,
            remote_port,
            esp_spi,
        ))
    }
}

/// Match one canonical filter against an already strictly parsed IPv4 packet.
#[must_use]
pub const fn tft_classifier_filter_matches(
    filter: &TftClassifierFilter,
    packet: &TftClassifierIpv4Packet,
) -> bool {
    (!filter.has_protocol() || filter.protocol == packet.protocol)
        && (!filter.has_local_address()
            || masked_ipv4_matches(
                packet.local_address,
                filter.local_address,
                filter.local_mask,
            ))
        && (!filter.has_remote_address()
            || masked_ipv4_matches(
                packet.remote_address,
                filter.remote_address,
                filter.remote_mask,
            ))
        && (!filter.has_local_port()
            || match packet.local_port {
                Some(port) => {
                    port >= u16::from_be_bytes(filter.local_port_first)
                        && port <= u16::from_be_bytes(filter.local_port_last)
                }
                None => false,
            })
        && (!filter.has_remote_port()
            || match packet.remote_port {
                Some(port) => {
                    port >= u16::from_be_bytes(filter.remote_port_first)
                        && port <= u16::from_be_bytes(filter.remote_port_last)
                }
                None => false,
            })
        && (!filter.has_tos() || packet.tos & filter.tos_mask == filter.tos_value & filter.tos_mask)
        && (!filter.has_esp_spi()
            || match packet.esp_spi {
                Some(spi) => spi == u32::from_be_bytes(filter.esp_spi),
                None => false,
            })
}

/// Value-independent result of selecting a complete active snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TftClassifierSelection {
    /// A dedicated bearer mark was selected.
    Selected(u32),
    /// No filter matched, and the snapshot selected its explicit default.
    Default,
    /// No filter matched and the snapshot has no default.
    NoMatch,
    /// The packet source differs from the classifier PAA.
    PaaMismatch,
    /// Metadata, filters, ownership, or precedence was not exact.
    Invalid,
}

impl fmt::Debug for TftClassifierSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(_) => f.write_str("TftClassifierSelection::Selected(<redacted>)"),
            Self::Default => f.write_str("TftClassifierSelection::Default"),
            Self::NoMatch => f.write_str("TftClassifierSelection::NoMatch"),
            Self::PaaMismatch => f.write_str("TftClassifierSelection::PaaMismatch"),
            Self::Invalid => f.write_str("TftClassifierSelection::Invalid"),
        }
    }
}

/// Pure bounded selection of one complete active IPv4 snapshot.
///
/// The caller supplies records in their fixed active-bank index order. A
/// missing record, cross-owner record, or precedence that is not strictly
/// increasing in index order is an invalid snapshot, never a deterministic
/// but incorrect tie-break.
#[must_use]
pub fn select_tft_classifier_ipv4(
    key: TftClassifierKey,
    meta: TftClassifierMeta,
    filters: &[TftClassifierFilter],
    packet: TftClassifierIpv4Packet,
) -> TftClassifierSelection {
    if !key.is_valid()
        || !meta.is_valid()
        || filters.len() != usize::from(meta.filter_count())
        || filters.len() > TFT_CLASSIFIER_MAX_FILTERS
    {
        return TftClassifierSelection::Invalid;
    }
    if packet.local_address != key.paa {
        return TftClassifierSelection::PaaMismatch;
    }
    let mut previous_precedence = None;
    for filter in filters {
        if !filter.belongs_to(&meta) {
            return TftClassifierSelection::Invalid;
        }
        let precedence = filter.evaluation_precedence();
        if previous_precedence.is_some_and(|previous| precedence <= previous) {
            return TftClassifierSelection::Invalid;
        }
        previous_precedence = Some(precedence);
    }
    let mut selected: Option<(u8, u32)> = None;
    for filter in filters {
        if !tft_classifier_filter_matches(filter, &packet) {
            continue;
        }
        let candidate = (filter.evaluation_precedence(), filter.bearer_mark());
        match selected {
            None => selected = Some(candidate),
            Some((precedence, _)) if candidate.0 < precedence => selected = Some(candidate),
            Some((precedence, _)) if candidate.0 == precedence => {
                return TftClassifierSelection::Invalid;
            }
            Some(_) => {}
        }
    }
    match selected {
        Some((_, mark)) => TftClassifierSelection::Selected(mark),
        None if meta.has_default() => TftClassifierSelection::Default,
        None => TftClassifierSelection::NoMatch,
    }
}

/// Return whether a schema-map value is exactly this ABI's marker.
#[must_use]
pub const fn tft_classifier_schema_is_current(
    value: &[u8; TFT_CLASSIFIER_SCHEMA_VALUE_LEN],
) -> bool {
    bytes_equal(value, &TFT_CLASSIFIER_SCHEMA_MARKER_VALUE)
}

const fn bytes_are_zero<const N: usize>(value: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn bytes_equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn masked_ipv4_matches(value: [u8; 4], expected: [u8; 4], mask: [u8; 4]) -> bool {
    value[0] & mask[0] == expected[0] & mask[0]
        && value[1] & mask[1] == expected[1] & mask[1]
        && value[2] & mask[2] == expected[2] & mask[2]
        && value[3] & mask[3] == expected[3] & mask[3]
}

const _: [(); TFT_CLASSIFIER_KEY_LEN] = [(); core::mem::size_of::<TftClassifierKey>()];
const _: [(); 1] = [(); core::mem::align_of::<TftClassifierKey>()];
const _: [(); TFT_CLASSIFIER_META_VALUE_LEN] = [(); core::mem::size_of::<TftClassifierMeta>()];
const _: [(); 1] = [(); core::mem::align_of::<TftClassifierMeta>()];
const _: [(); TFT_CLASSIFIER_FILTER_KEY_LEN] = [(); core::mem::size_of::<TftClassifierFilterKey>()];
const _: [(); 1] = [(); core::mem::align_of::<TftClassifierFilterKey>()];
const _: [(); TFT_CLASSIFIER_FILTER_VALUE_LEN] = [(); core::mem::size_of::<TftClassifierFilter>()];
const _: [(); 1] = [(); core::mem::align_of::<TftClassifierFilter>()];

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const OWNER_BYTES: [u8; 16] = [7; 16];

    fn owner() -> TftClassifierOwnerId {
        TftClassifierOwnerId::new(OWNER_BYTES).expect("synthetic owner")
    }

    fn fingerprint() -> [u8; TFT_CLASSIFIER_FINGERPRINT_LEN] {
        [9; TFT_CLASSIFIER_FINGERPRINT_LEN]
    }

    fn key() -> TftClassifierKey {
        TftClassifierKey::new(7, [10, 45, 0, 2]).expect("synthetic key")
    }

    fn meta(default: bool, filters: u16) -> TftClassifierMeta {
        TftClassifierMeta::new(1, default, owner(), 8, 9, filters, fingerprint())
            .expect("synthetic meta")
    }

    fn filter(precedence: u8, mark: u32, spec: TftClassifierIpv4FilterSpec) -> TftClassifierFilter {
        TftClassifierFilter::new(owner(), 8, 9, precedence, mark, spec).expect("synthetic filter")
    }

    fn udp_packet(remote_port: u16) -> [u8; 28] {
        let mut packet = [0_u8; 28];
        packet[0] = 0x45;
        packet[1] = 0xb8;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 45, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet[20..22].copy_from_slice(&40_001_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&remote_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    #[test]
    fn layouts_are_explicit_padding_free_and_alignment_one() {
        assert_eq!(
            core::mem::size_of::<TftClassifierKey>(),
            TFT_CLASSIFIER_KEY_LEN
        );
        assert_eq!(core::mem::align_of::<TftClassifierKey>(), 1);
        assert_eq!(
            core::mem::size_of::<TftClassifierMeta>(),
            TFT_CLASSIFIER_META_VALUE_LEN
        );
        assert_eq!(core::mem::align_of::<TftClassifierMeta>(), 1);
        assert_eq!(
            core::mem::size_of::<TftClassifierFilterKey>(),
            TFT_CLASSIFIER_FILTER_KEY_LEN
        );
        assert_eq!(core::mem::align_of::<TftClassifierFilterKey>(), 1);
        assert_eq!(
            core::mem::size_of::<TftClassifierFilter>(),
            TFT_CLASSIFIER_FILTER_VALUE_LEN
        );
        assert_eq!(core::mem::align_of::<TftClassifierFilter>(), 1);
    }

    #[test]
    fn whole_classifier_capacity_and_filter_identifier_zero_are_distinct() {
        let full_count = TFT_CLASSIFIER_MAX_FILTERS as u16;
        assert_eq!(
            meta(false, full_count).filter_count(),
            full_count,
            "the metadata count accepts the complete classifier bound"
        );
        assert!(
            TftClassifierMeta::new(1, false, owner(), 8, 9, full_count + 1, fingerprint())
                .is_none()
        );

        let final_key = TftClassifierFilterKey::new(key(), 1, full_count - 1)
            .expect("the final complete-snapshot index is representable");
        assert_eq!(final_key.filter_index(), full_count - 1);
        assert!(TftClassifierFilterKey::new(key(), 1, full_count).is_none());

        let identifier_zero = TftClassifierFilter::new_with_semantics(
            owner(),
            8,
            9,
            0,
            11,
            0,
            TftClassifierFilterDirection::UplinkOnly,
            None,
            None,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        )
        .expect("identifier zero is a valid packet-filter identifier");
        assert_eq!(identifier_zero.packet_filter_identifier(), 0);
    }

    #[test]
    fn byte_array_map_encodings_round_trip_and_reject_noncanonical_bytes() {
        let key = key();
        let filter_key = TftClassifierFilterKey::new(key, 1, 0).expect("synthetic filter key");
        let metadata = meta(true, 1);
        let filter = filter(
            1,
            11,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                remote_port: TftClassifierPortRange::new(443, 443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert_eq!(TftClassifierKey::decode(key.encode()), Some(key));
        assert_eq!(
            TftClassifierFilterKey::decode(filter_key.encode()),
            Some(filter_key)
        );
        assert_eq!(TftClassifierMeta::decode(metadata.encode()), Some(metadata));
        assert_eq!(TftClassifierFilter::decode(filter.encode()), Some(filter));

        let mut malformed_key = key.encode();
        malformed_key[..4].fill(0);
        assert!(TftClassifierKey::decode(malformed_key).is_none());
        let mut malformed_filter_key = filter_key.encode();
        malformed_filter_key[9] = 1;
        assert!(TftClassifierFilterKey::decode(malformed_filter_key).is_none());
        let mut malformed_meta = metadata.encode();
        malformed_meta[70] = 1;
        assert!(TftClassifierMeta::decode(malformed_meta).is_none());
        let mut unknown_meta_flag = metadata.encode();
        unknown_meta_flag[3] |= 0x80;
        assert!(TftClassifierMeta::decode(unknown_meta_flag).is_none());
        let mut zero_fingerprint = metadata.encode();
        zero_fingerprint[38..70].fill(0);
        assert!(TftClassifierMeta::decode(zero_fingerprint).is_none());
        let mut empty_without_default =
            TftClassifierMeta::new(1, true, owner(), 8, 9, 0, fingerprint())
                .expect("default-only metadata is canonical")
                .encode();
        empty_without_default[3] = 0;
        assert!(TftClassifierMeta::decode(empty_without_default).is_none());
        let removal_fence = metadata.removing().expect("active metadata can be fenced");
        assert!(removal_fence.is_valid_removal_fence());
        assert!(!removal_fence.is_valid());
        assert_eq!(
            TftClassifierMeta::decode(removal_fence.encode()),
            Some(removal_fence)
        );
        let mut malformed_filter = filter.encode();
        malformed_filter[34] = 1;
        assert!(TftClassifierFilter::decode(malformed_filter).is_none());
    }

    #[test]
    fn filter_semantics_round_trip_exactly_and_reject_hostile_bytes() {
        let spec = TftClassifierIpv4FilterSpec {
            local_port: TftClassifierPortRange::new(40_000, 40_000),
            remote_port: TftClassifierPortRange::new(443, 443),
            tos: Some(TftClassifierTos::new(0x20, 0xf0)),
            ..TftClassifierIpv4FilterSpec::default()
        };
        for (identifier, direction, local_form, remote_form) in [
            (
                0,
                TftClassifierFilterDirection::UplinkOnly,
                TftClassifierPortForm::SinglePort,
                TftClassifierPortForm::PortRange,
            ),
            (
                15,
                TftClassifierFilterDirection::Bidirectional,
                TftClassifierPortForm::PortRange,
                TftClassifierPortForm::SinglePort,
            ),
        ] {
            let value = TftClassifierFilter::new_with_semantics(
                owner(),
                8,
                9,
                1,
                11,
                identifier,
                direction,
                Some(local_form),
                Some(remote_form),
                spec,
            )
            .expect("synthetic exact filter");
            let decoded = TftClassifierFilter::decode(value.encode()).expect("canonical decode");
            assert_eq!(decoded, value);
            assert_eq!(decoded.packet_filter_identifier(), identifier);
            assert_eq!(decoded.direction(), direction);
            assert_eq!(decoded.local_port_form(), Some(local_form));
            assert_eq!(decoded.remote_port_form(), Some(remote_form));
            assert_eq!(decoded.spec(), spec);
        }

        let single = TftClassifierFilter::new_with_semantics(
            owner(),
            8,
            9,
            1,
            11,
            0,
            TftClassifierFilterDirection::UplinkOnly,
            Some(TftClassifierPortForm::SinglePort),
            Some(TftClassifierPortForm::SinglePort),
            spec,
        )
        .expect("synthetic single-port filter");
        let range = TftClassifierFilter::new_with_semantics(
            owner(),
            8,
            9,
            1,
            11,
            0,
            TftClassifierFilterDirection::UplinkOnly,
            Some(TftClassifierPortForm::PortRange),
            Some(TftClassifierPortForm::SinglePort),
            spec,
        )
        .expect("synthetic range filter");
        assert_ne!(single, range);

        let mut hostile = single.encode();
        hostile[34] = 0x00;
        assert!(TftClassifierFilter::decode(hostile).is_none());
        let mut hostile = single.encode();
        hostile[34] = 0x10;
        assert!(TftClassifierFilter::decode(hostile).is_none());
        let mut hostile = single.encode();
        hostile[58..60].copy_from_slice(&40_001_u16.to_be_bytes());
        assert!(TftClassifierFilter::decode(hostile).is_none());
        let local_only = TftClassifierFilter::new_with_semantics(
            owner(),
            8,
            9,
            1,
            11,
            0,
            TftClassifierFilterDirection::UplinkOnly,
            Some(TftClassifierPortForm::SinglePort),
            None,
            TftClassifierIpv4FilterSpec {
                local_port: TftClassifierPortRange::new(40_000, 40_000),
                ..TftClassifierIpv4FilterSpec::default()
            },
        )
        .expect("synthetic local-only filter");
        let mut hostile = local_only.encode();
        hostile[34] |= FILTER_REMOTE_PORT_RANGE;
        assert!(TftClassifierFilter::decode(hostile).is_none());
        let mut hostile = single.encode();
        hostile[56..58].copy_from_slice(&40_000_u16.to_be_bytes());
        hostile[58..60].copy_from_slice(&40_001_u16.to_be_bytes());
        assert!(TftClassifierFilter::decode(hostile).is_none());
        let mut hostile = single.encode();
        hostile[35] = 1;
        assert!(TftClassifierFilter::decode(hostile).is_none());
    }

    #[test]
    fn drop_counter_indices_are_distinct_and_within_the_fixed_map() {
        let indices = [
            COUNTER_TFT_CLASSIFIER_MALFORMED,
            COUNTER_TFT_CLASSIFIER_NO_MATCH,
            COUNTER_TFT_CLASSIFIER_INVALID_STATE,
        ];
        for index in indices {
            assert!(index < TFT_CLASSIFIER_COUNTER_SLOTS);
        }
        assert_ne!(
            COUNTER_TFT_CLASSIFIER_MALFORMED,
            COUNTER_TFT_CLASSIFIER_NO_MATCH
        );
        assert_ne!(
            COUNTER_TFT_CLASSIFIER_MALFORMED,
            COUNTER_TFT_CLASSIFIER_INVALID_STATE
        );
        assert_ne!(
            COUNTER_TFT_CLASSIFIER_NO_MATCH,
            COUNTER_TFT_CLASSIFIER_INVALID_STATE
        );
    }

    #[test]
    fn selection_observes_lowest_precedence_default_and_no_match_drop() {
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(443)).expect("valid UDP");
        let broad = filter(
            50,
            11,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        let narrow = filter(
            10,
            12,
            TftClassifierIpv4FilterSpec {
                remote_port: TftClassifierPortRange::new(443, 443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(true, 2), &[narrow, broad], packet),
            TftClassifierSelection::Selected(12)
        );
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(80)).expect("valid UDP");
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(true, 2), &[narrow, broad], packet),
            TftClassifierSelection::Selected(11)
        );
        let only_narrow = [narrow];
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(true, 1), &only_narrow, packet),
            TftClassifierSelection::Default
        );
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(false, 1), &only_narrow, packet),
            TftClassifierSelection::NoMatch
        );
    }

    #[test]
    fn removal_fence_is_invalid_for_selection_even_with_a_default() {
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(80)).expect("valid UDP");
        let active = meta(true, 1);
        let removal_fence = active.removing().expect("active metadata can be fenced");
        let only_filter = [filter(
            10,
            12,
            TftClassifierIpv4FilterSpec {
                remote_port: TftClassifierPortRange::new(443, 443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        )];

        assert_eq!(
            select_tft_classifier_ipv4(key(), removal_fence, &only_filter, packet),
            TftClassifierSelection::Invalid
        );
    }

    #[test]
    fn matches_protocol_addresses_ports_tos_and_esp_spi_exactly() {
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(443)).expect("valid UDP");
        let composite_filter = filter(
            1,
            11,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                local_address: Some(TftClassifierIpv4Address::new(
                    [10, 45, 0, 0],
                    [255, 255, 255, 0],
                )),
                remote_address: Some(TftClassifierIpv4Address::new(
                    [192, 0, 2, 0],
                    [255, 255, 255, 0],
                )),
                local_port: TftClassifierPortRange::new(40_000, 40_100),
                remote_port: TftClassifierPortRange::new(443, 443),
                tos: Some(TftClassifierTos::new(0xb0, 0xf0)),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert!(tft_classifier_filter_matches(&composite_filter, &packet));

        let esp = TftClassifierIpv4Packet::new(
            [10, 45, 0, 2],
            [192, 0, 2, 1],
            50,
            0,
            None,
            None,
            Some(0x1020_3040),
        );
        let esp_filter = filter(
            2,
            12,
            TftClassifierIpv4FilterSpec {
                protocol: Some(50),
                esp_spi: Some(0x1020_3040),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert!(tft_classifier_filter_matches(&esp_filter, &esp));
    }

    #[test]
    fn masked_tos_and_address_components_preserve_ignored_value_bits() {
        let tos = TftClassifierTos::new(0xb1, 0xf0);
        let spec = TftClassifierIpv4FilterSpec {
            local_address: Some(TftClassifierIpv4Address::new(
                [10, 45, 0, 255],
                [255, 255, 255, 0],
            )),
            tos: Some(tos),
            ..TftClassifierIpv4FilterSpec::default()
        };
        let original = filter(1, 11, spec);
        let decoded = TftClassifierFilter::decode(original.encode()).expect("exact filter bytes");
        assert_eq!(decoded.spec(), spec);

        let packet = TftClassifierIpv4Packet::parse(&udp_packet(443)).expect("valid UDP");
        assert!(tft_classifier_filter_matches(&decoded, &packet));

        let mut different_masked_bits = udp_packet(443);
        different_masked_bits[1] = 0xa1;
        let different_masked_bits = TftClassifierIpv4Packet::parse(&different_masked_bits)
            .expect("valid UDP with different masked ToS bits");
        assert!(!tft_classifier_filter_matches(
            &decoded,
            &different_masked_bits
        ));
    }

    #[test]
    fn malformed_fragmented_and_cross_owner_state_are_never_defaulted() {
        let mut fragment = udp_packet(443);
        fragment[6] = 0x20;
        assert!(TftClassifierIpv4Packet::parse(&fragment).is_none());
        let mut truncated_udp = udp_packet(443);
        truncated_udp[24..26].copy_from_slice(&9_u16.to_be_bytes());
        assert!(TftClassifierIpv4Packet::parse(&truncated_udp).is_none());

        let packet = TftClassifierIpv4Packet::parse(&udp_packet(443)).expect("valid UDP");
        let valid = filter(
            1,
            11,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        let wrong_owner = TftClassifierFilter::new(
            TftClassifierOwnerId::new([8; 16]).expect("synthetic other owner"),
            8,
            9,
            2,
            12,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        )
        .expect("synthetic filter");
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(true, 2), &[valid, wrong_owner], packet),
            TftClassifierSelection::Invalid
        );
    }

    #[test]
    fn duplicate_matching_precedence_is_invalid_not_a_tie_break() {
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(443)).expect("valid UDP");
        let one = filter(
            3,
            11,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        let two = filter(
            3,
            12,
            TftClassifierIpv4FilterSpec {
                remote_port: TftClassifierPortRange::new(443, 443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(false, 2), &[one, two], packet),
            TftClassifierSelection::Invalid
        );
    }

    #[test]
    fn duplicate_nonmatching_precedence_is_invalid_not_defaulted() {
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(80)).expect("valid UDP");
        let one = filter(
            3,
            11,
            TftClassifierIpv4FilterSpec {
                remote_port: TftClassifierPortRange::new(443, 443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        let two = filter(
            3,
            12,
            TftClassifierIpv4FilterSpec {
                remote_port: TftClassifierPortRange::new(8443, 8443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(true, 2), &[one, two], packet),
            TftClassifierSelection::Invalid
        );
    }

    #[test]
    fn out_of_order_precedence_is_invalid_not_reinterpreted() {
        let packet = TftClassifierIpv4Packet::parse(&udp_packet(443)).expect("valid UDP");
        let later = filter(
            50,
            11,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        let earlier = filter(
            10,
            12,
            TftClassifierIpv4FilterSpec {
                remote_port: TftClassifierPortRange::new(443, 443),
                ..TftClassifierIpv4FilterSpec::default()
            },
        );
        assert_eq!(
            select_tft_classifier_ipv4(key(), meta(true, 2), &[later, earlier], packet),
            TftClassifierSelection::Invalid
        );
    }

    #[test]
    fn ipv4_reserved_fragment_flag_is_rejected_but_df_is_accepted() {
        let mut reserved = udp_packet(443);
        reserved[6] = 0x80;
        assert!(TftClassifierIpv4Packet::parse(&reserved).is_none());
        let mut df = udp_packet(443);
        df[6] = 0x40;
        assert!(TftClassifierIpv4Packet::parse(&df).is_some());
    }

    #[test]
    fn constructors_reject_noncanonical_and_ipv6_unrepresentable_state() {
        assert!(TftClassifierOwnerId::new([0; 16]).is_none());
        assert!(TftClassifierKey::new(0, [10, 45, 0, 2]).is_none());
        assert!(TftClassifierKey::new(7, [0; 4]).is_none());
        assert!(TftClassifierMeta::new(2, false, owner(), 1, 1, 0, fingerprint()).is_none());
        assert!(TftClassifierMeta::new(0, false, owner(), 1, 1, 0, fingerprint()).is_none());
        assert!(TftClassifierMeta::new(0, true, owner(), 1, 1, 0, fingerprint()).is_some());
        assert!(TftClassifierMeta::new(0, false, owner(), 1, 1, 257, fingerprint()).is_none());
        assert!(TftClassifierMeta::new(0, true, owner(), 1, 1, 0, [0; 32]).is_none());
        assert!(TftClassifierPortRange::new(9, 8).is_none());
        assert!(TftClassifierFilter::new(
            owner(),
            1,
            1,
            1,
            0,
            TftClassifierIpv4FilterSpec {
                protocol: Some(17),
                ..TftClassifierIpv4FilterSpec::default()
            },
        )
        .is_none());
        assert!(TftClassifierFilter::new(
            owner(),
            1,
            1,
            1,
            11,
            TftClassifierIpv4FilterSpec {
                local_port: TftClassifierPortRange::new(1, 2),
                esp_spi: Some(1),
                ..TftClassifierIpv4FilterSpec::default()
            },
        )
        .is_none());
    }

    #[test]
    fn debug_and_schema_marker_do_not_expose_runtime_values() {
        let debug = std::format!("{:?} {:?} {:?}", key(), meta(true, 0), owner());
        for forbidden in ["10, 45", "7", "8", "0909"] {
            assert!(!debug.contains(forbidden));
        }
        assert!(tft_classifier_schema_is_current(
            &TFT_CLASSIFIER_SCHEMA_MARKER_VALUE
        ));
        let mut wrong = TFT_CLASSIFIER_SCHEMA_MARKER_VALUE;
        wrong[0] ^= 1;
        assert!(!tft_classifier_schema_is_current(&wrong));
    }
}
