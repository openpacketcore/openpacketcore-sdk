//! Safe model types for Linux XFRM IPsec backend operations.
//!
//! These types deliberately keep SA/policy policy in caller hands. The SDK
//! backend model owns selector/identity/lifetime/algorithm/key structure and
//! leaves IKE negotiation, namespace choice, and deployment privileges to the
//! product.

use std::{fmt, num::NonZeroU32};

use opc_types::DscpCodepoint;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::XfrmError;

/// IP address used by XFRM selectors and identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum IpAddress {
    /// IPv4 address as four octets.
    Ipv4([u8; 4]),
    /// IPv6 address as sixteen octets.
    Ipv6([u8; 16]),
}

impl IpAddress {
    /// True when the address is IPv4.
    pub const fn is_ipv4(self) -> bool {
        matches!(self, Self::Ipv4(_))
    }

    /// True when the address is IPv6.
    pub const fn is_ipv6(self) -> bool {
        matches!(self, Self::Ipv6(_))
    }

    /// True when every address octet is zero.
    pub const fn is_unspecified(self) -> bool {
        match self {
            Self::Ipv4(octets) => {
                octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0
            }
            Self::Ipv6(octets) => {
                let mut index = 0;
                while index < octets.len() {
                    if octets[index] != 0 {
                        return false;
                    }
                    index += 1;
                }
                true
            }
        }
    }
}

/// XFRM packet selector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XfrmSelector {
    /// Source address.
    pub source: IpAddress,
    /// Destination address.
    pub destination: IpAddress,
    /// Source port in host byte order.
    pub source_port: u16,
    /// Destination port in host byte order.
    pub destination_port: u16,
    /// Upper-layer protocol number such as `IPPROTO_ESP` or `IPPROTO_UDP`.
    pub protocol: u8,
    /// Source prefix length.
    pub source_prefix_len: u8,
    /// Destination prefix length.
    pub destination_prefix_len: u8,
}

impl XfrmSelector {
    /// Build a selector with common defaults (any port, /32 or /128 prefixes).
    pub fn new(source: IpAddress, destination: IpAddress, protocol: u8) -> Self {
        Self {
            source,
            destination,
            source_port: 0,
            destination_port: 0,
            protocol,
            source_prefix_len: prefix_len_for(&source),
            destination_prefix_len: prefix_len_for(&destination),
        }
    }
}

fn prefix_len_for(addr: &IpAddress) -> u8 {
    match addr {
        IpAddress::Ipv4(_) => 32,
        IpAddress::Ipv6(_) => 128,
    }
}

/// XFRM destination/protocol/SPI identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmId {
    /// Destination address.
    pub destination: IpAddress,
    /// Security Parameter Index in host byte order.
    pub spi: u32,
    /// Transform protocol such as `IPPROTO_ESP`.
    pub protocol: u8,
}

/// Non-zero Linux XFRM request identifier (`reqid`).
///
/// A shared request ID binds multiple SA states to one policy template without
/// pinning that template to a particular SPI. Zero is represented by `None` on
/// models that do not use request-ID binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct XfrmRequestId(NonZeroU32);

impl XfrmRequestId {
    /// Construct a non-zero request identifier.
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the raw Linux request identifier.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// UDP encapsulation type for ESP-in-UDP NAT traversal.
pub const UDP_ENCAP_ESPINUDP: u16 = 2;

/// Optional UDP encapsulation template for ESP-in-UDP NAT traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpEncap {
    /// Encapsulation type, for example [`UDP_ENCAP_ESPINUDP`].
    pub encap_type: u16,
    /// UDP source port in host byte order.
    pub source_port: u16,
    /// UDP destination port in host byte order.
    pub destination_port: u16,
}

/// Validation failure for an ESP-in-UDP encapsulation template.
///
/// Variants intentionally carry no received type or port values, keeping
/// `Debug` and `Display` suitable for redaction-safe diagnostics.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpEncapError {
    /// The encapsulation type is not the supported RFC 3948 ESP-in-UDP type.
    UnsupportedType,
    /// At least one UDP port is zero.
    ZeroPort,
}

impl UdpEncapError {
    /// Return a stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedType => "xfrm_udp_encap_unsupported_type",
            Self::ZeroPort => "xfrm_udp_encap_zero_port",
        }
    }

    pub(crate) fn into_xfrm_error(
        self,
        type_field: &'static str,
        port_field: &'static str,
    ) -> XfrmError {
        match self {
            Self::UnsupportedType => {
                XfrmError::invalid_config(type_field, "encapsulation must be ESP-in-UDP")
            }
            Self::ZeroPort => {
                XfrmError::invalid_config(port_field, "UDP encapsulation ports must be nonzero")
            }
        }
    }
}

impl fmt::Display for UdpEncapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for UdpEncapError {}

impl UdpEncap {
    /// Build an RFC 3948 ESP-in-UDP encapsulation template.
    pub const fn esp_in_udp(source_port: u16, destination_port: u16) -> Self {
        Self {
            encap_type: UDP_ENCAP_ESPINUDP,
            source_port,
            destination_port,
        }
    }

    /// Validate this template against the SDK's RFC 3948 NAT-T contract.
    ///
    /// The supported type is [`UDP_ENCAP_ESPINUDP`], and both ports must be
    /// non-zero. NAT detection and translated-port selection remain
    /// caller-owned.
    ///
    /// # Errors
    ///
    /// Returns a stable, value-free [`UdpEncapError`] when the type is
    /// unsupported or either port is zero.
    pub const fn validate_esp_in_udp(self) -> Result<(), UdpEncapError> {
        if self.encap_type != UDP_ENCAP_ESPINUDP {
            return Err(UdpEncapError::UnsupportedType);
        }
        if self.source_port == 0 || self.destination_port == 0 {
            return Err(UdpEncapError::ZeroPort);
        }
        Ok(())
    }
}

/// Linux XFRM mark value and mask.
///
/// The same wire shape is used for an SA or policy lookup mark
/// (`XFRMA_MARK`) and for an SA output mark (`XFRMA_SET_MARK` plus
/// `XFRMA_SET_MARK_MASK`). The field carrying the value determines which
/// kernel attribute is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XfrmMark {
    /// Mark value.
    pub value: u32,
    /// Mark mask.
    pub mask: u32,
}

pub(crate) fn validate_sa_output_mark(output_mark: Option<XfrmMark>) -> Result<(), XfrmError> {
    if matches!(output_mark, Some(XfrmMark { value: 0, mask: 0 })) {
        return Err(XfrmError::invalid_config(
            "sa.output_mark",
            "output-mark value and mask must not both be zero; use None",
        ));
    }
    Ok(())
}

/// XFRM mode.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmMode {
    /// Transport mode.
    Transport,
    /// Tunnel mode.
    Tunnel,
    /// BEET mode.
    Beet,
}

/// XFRM policy direction.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmDirection {
    /// Inbound policy.
    In,
    /// Outbound policy.
    Out,
    /// Forwarded policy.
    Forward,
}

/// XFRM policy action.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmAction {
    /// Allow matching packets.
    Allow,
    /// Block matching packets.
    Block,
}

/// The exact Linux kernel XFRM name for AES-CBC encryption; do not hand-write
/// hyphenated forms.
pub const XFRM_ENCR_CBC_AES: &str = "cbc(aes)";

/// The exact Linux kernel XFRM name for the ESP NULL encryption transform.
///
/// Linux requires this zero-key transform to be present for authenticated-only
/// ESP SAs; omitting the encryption attribute causes `XFRM_MSG_NEWSA` to fail
/// with `EINVAL`.
pub const XFRM_ENCR_NULL: &str = "ecb(cipher_null)";

/// The exact Linux kernel XFRM name for AES-GCM RFC 4106 AEAD; do not
/// hand-write hyphenated forms.
pub const XFRM_AEAD_RFC4106_GCM_AES: &str = "rfc4106(gcm(aes))";

/// The exact Linux kernel XFRM name for HMAC-SHA-1 authentication; do not
/// hand-write hyphenated forms.
pub const XFRM_AUTH_HMAC_SHA1: &str = "hmac(sha1)";

/// The exact Linux kernel XFRM name for HMAC-SHA-256 authentication; do not
/// hand-write hyphenated forms.
pub const XFRM_AUTH_HMAC_SHA256: &str = "hmac(sha256)";

/// The exact Linux kernel XFRM name for HMAC-SHA-384 authentication; do not
/// hand-write hyphenated forms.
pub const XFRM_AUTH_HMAC_SHA384: &str = "hmac(sha384)";

/// The exact Linux kernel XFRM name for HMAC-SHA-512 authentication; do not
/// hand-write hyphenated forms.
pub const XFRM_AUTH_HMAC_SHA512: &str = "hmac(sha512)";

/// Algorithm name used for authentication or encryption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Algorithm {
    /// Kernel algorithm name such as [`XFRM_ENCR_CBC_AES`].
    pub name: String,
}

impl Algorithm {
    /// Create an algorithm from a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Create the Linux XFRM AES-CBC encryption algorithm.
    pub fn cbc_aes() -> Self {
        Self::new(XFRM_ENCR_CBC_AES)
    }

    /// Create the Linux XFRM NULL encryption algorithm.
    ///
    /// This algorithm must be paired with empty [`KeyMaterial`].
    pub fn null() -> Self {
        Self::new(XFRM_ENCR_NULL)
    }
}

/// Authentication algorithm with truncation length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthAlgorithm {
    /// Kernel algorithm name such as [`XFRM_AUTH_HMAC_SHA256`].
    pub name: String,
    /// Truncation length in bits, for example 96 for `auth-trunc`.
    pub truncation_len_bits: u32,
}

impl AuthAlgorithm {
    /// Create an authentication algorithm.
    pub fn new(name: impl Into<String>, truncation_len_bits: u32) -> Self {
        Self {
            name: name.into(),
            truncation_len_bits,
        }
    }

    /// Create the Linux XFRM HMAC-SHA-1 authentication algorithm.
    pub fn hmac_sha1(truncation_len_bits: u32) -> Self {
        Self::new(XFRM_AUTH_HMAC_SHA1, truncation_len_bits)
    }

    /// Create the Linux XFRM HMAC-SHA-256 authentication algorithm.
    pub fn hmac_sha256(truncation_len_bits: u32) -> Self {
        Self::new(XFRM_AUTH_HMAC_SHA256, truncation_len_bits)
    }

    /// Create the Linux XFRM HMAC-SHA-384 authentication algorithm.
    pub fn hmac_sha384(truncation_len_bits: u32) -> Self {
        Self::new(XFRM_AUTH_HMAC_SHA384, truncation_len_bits)
    }

    /// Create the Linux XFRM HMAC-SHA-512 authentication algorithm.
    pub fn hmac_sha512(truncation_len_bits: u32) -> Self {
        Self::new(XFRM_AUTH_HMAC_SHA512, truncation_len_bits)
    }
}

/// Combined-mode AEAD algorithm with Integrity Check Value length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AeadAlgorithm {
    /// Kernel algorithm name such as [`XFRM_AEAD_RFC4106_GCM_AES`].
    pub name: String,
    /// ICV length in bits, for example 128 for AES-GCM-16.
    pub icv_len_bits: u32,
}

impl AeadAlgorithm {
    /// Create a combined-mode AEAD algorithm.
    pub fn new(name: impl Into<String>, icv_len_bits: u32) -> Self {
        Self {
            name: name.into(),
            icv_len_bits,
        }
    }

    /// Create the Linux XFRM AES-GCM RFC 4106 AEAD algorithm.
    pub fn rfc4106_gcm_aes(icv_len_bits: u32) -> Self {
        Self::new(XFRM_AEAD_RFC4106_GCM_AES, icv_len_bits)
    }
}

/// Sensitive key material.
///
/// The bytes are zeroized on drop. `Debug` and `Display` never emit the raw
/// material; they show only the length and a redaction placeholder.
///
/// Equality uses a constant-time byte comparison to avoid exposing the key
/// through a timing side-channel.
#[derive(Clone)]
pub struct KeyMaterial {
    bytes: Zeroizing<Vec<u8>>,
}

impl KeyMaterial {
    /// Wrap key bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.into()),
        }
    }

    /// Borrow the raw bytes. Callers must not expose them through logs or
    /// diagnostics.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of bytes of key material.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when no key material is present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("len", &self.bytes.len())
            .field("material", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted:{} bytes>", self.bytes.len())
    }
}

impl PartialEq for KeyMaterial {
    // Constant-time comparison is intentionally not unit-tested: timing
    // properties cannot be verified deterministically in this test suite.
    // Preserving `ct_eq` here is enforced by review only.
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for KeyMaterial {}

/// Lifetime limits for an SA or policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LifetimeConfig {
    /// Soft byte limit; zero disables.
    pub soft_byte_limit: u64,
    /// Hard byte limit; zero disables.
    pub hard_byte_limit: u64,
    /// Soft packet limit; zero disables.
    pub soft_packet_limit: u64,
    /// Hard packet limit; zero disables.
    pub hard_packet_limit: u64,
    /// Soft add-time expiry in seconds; zero disables.
    pub soft_add_expires_seconds: u64,
    /// Hard add-time expiry in seconds; zero disables.
    pub hard_add_expires_seconds: u64,
}

/// Current lifetime counters reported by the kernel for an SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LifetimeCurrent {
    /// Current byte count.
    pub bytes: u64,
    /// Current packet count.
    pub packets: u64,
    /// Kernel add time in seconds.
    pub add_time_seconds: u64,
    /// Kernel first-use time in seconds.
    pub use_time_seconds: u64,
}

/// Current replay and integrity-failure counters reported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SaStatistics {
    /// Kernel replay-window counter.
    pub replay_window: u32,
    /// Replay failures.
    pub replay_failures: u32,
    /// Integrity failures.
    pub integrity_failures: u32,
}

/// Replay/sequence state used for SA restore and query.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SaReplayState {
    /// Whether the state uses Extended Sequence Numbers.
    pub esn: bool,
    /// Outbound sequence number low word.
    pub outbound_sequence: u32,
    /// Inbound sequence number low word.
    pub inbound_sequence: u32,
    /// Outbound sequence number high word for ESN.
    pub outbound_sequence_hi: u32,
    /// Inbound sequence number high word for ESN.
    pub inbound_sequence_hi: u32,
    /// Anti-replay window size.
    pub replay_window: u32,
    /// Anti-replay bitmap words in kernel order.
    pub bitmap: Vec<u32>,
}

impl SaReplayState {
    /// Build a fresh replay state for a newly installed SA.
    #[must_use]
    pub fn fresh(replay_window: u32) -> Self {
        let esn = replay_window > 32;
        let bitmap = if esn {
            vec![0; replay_bitmap_word_len(replay_window)]
        } else if replay_window == 0 {
            Vec::new()
        } else {
            vec![0]
        };
        Self {
            esn,
            outbound_sequence: 0,
            inbound_sequence: 0,
            outbound_sequence_hi: 0,
            inbound_sequence_hi: 0,
            replay_window,
            bitmap,
        }
    }

    /// Build a legacy non-ESN replay state.
    #[must_use]
    pub fn legacy(outbound_sequence: u32, inbound_sequence: u32, bitmap: u32) -> Self {
        Self {
            esn: false,
            outbound_sequence,
            inbound_sequence,
            outbound_sequence_hi: 0,
            inbound_sequence_hi: 0,
            replay_window: 32,
            bitmap: vec![bitmap],
        }
    }
}

impl fmt::Debug for SaReplayState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaReplayState")
            .field("esn", &self.esn)
            .field("outbound_sequence", &self.outbound_sequence)
            .field("inbound_sequence", &self.inbound_sequence)
            .field("outbound_sequence_hi", &self.outbound_sequence_hi)
            .field("inbound_sequence_hi", &self.inbound_sequence_hi)
            .field("replay_window", &self.replay_window)
            .field("bitmap_words", &self.bitmap.len())
            .finish()
    }
}

/// Canonical Linux ESN selection for one SA request.
//
// Linux requires ESN for replay windows above 32 even when a malformed
// caller-provided replay snapshot says otherwise. Validation rejects that
// contradictory snapshot later, but every binding/fingerprint/parser decision
// must still use exactly the same flag rule as the encoder.
pub(crate) fn sa_uses_esn(parameters: &SaParameters) -> bool {
    parameters.replay_window > 32
        || parameters
            .replay_state
            .as_ref()
            .is_some_and(|state| state.esn)
}

fn replay_bitmap_word_len(replay_window: u32) -> usize {
    replay_window.div_ceil(32).max(1) as usize
}

/// Parameters needed to install or update a Security Association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaParameters {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// SA identity (destination, SPI, protocol).
    pub id: XfrmId,
    /// Source tunnel endpoint.
    pub source_address: IpAddress,
    /// Optional request identifier shared with matching policy templates.
    pub request_id: Option<XfrmRequestId>,
    /// Authentication algorithm and key.
    pub auth: Option<(AuthAlgorithm, KeyMaterial)>,
    /// Encryption algorithm and key.
    pub crypt: Option<(Algorithm, KeyMaterial)>,
    /// Combined-mode AEAD algorithm and key material.
    ///
    /// This is mutually exclusive with [`Self::auth`] and [`Self::crypt`].
    pub aead: Option<(AeadAlgorithm, KeyMaterial)>,
    /// XFRM mode.
    pub mode: XfrmMode,
    /// Lifetime limits.
    pub lifetime: LifetimeConfig,
    /// Replay window size.
    pub replay_window: u32,
    /// Optional replay/sequence state for restore.
    pub replay_state: Option<SaReplayState>,
    /// Optional UDP encapsulation template for NAT-T.
    pub encap: Option<UdpEncap>,
    /// Optional packet lookup mark (`XFRMA_MARK`).
    pub mark: Option<XfrmMark>,
    /// Optional post-transform packet mark (`XFRMA_SET_MARK`).
    ///
    /// Linux applies the masked value to `skb->mark` after this SA transforms
    /// a packet. This applies to inbound/decrypt SAs as well as outbound SAs,
    /// so callers can carry the decrypting SA identity into later routing or
    /// dataplane classification. It is independent of [`Self::mark`], which
    /// selects an SA during lookup.
    ///
    /// The value and mask must not both be zero. Linux omits both output-mark
    /// attributes for that pair on kernel readback, so use `None` to request
    /// no post-transform mark mutation.
    ///
    /// A configured fixed-DSCP companion does not constrain this field unless
    /// [`Self::egress_dscp`] is also set on this SA. When both are set, the
    /// generic value and mask must be disjoint from the companion's token
    /// window. The Linux backend combines both values into one kernel pair.
    pub output_mark: Option<XfrmMark>,
    /// Optional XFRM interface identifier.
    pub if_id: Option<u32>,
    /// Optional fixed DSCP for the outer tunnel header.
    ///
    /// Linux has no fixed-DSCP XFRM SA attribute. The production backend
    /// implements this through its explicitly configured post-transform tc
    /// eBPF companion and rejects `Some` when that capability is unavailable.
    /// `None` emits exactly the pre-DSCP XFRM netlink bytes and does not
    /// require the companion.
    pub egress_dscp: Option<DscpCodepoint>,
}

/// Parameters needed to install or update a Security Policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyParameters {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// Policy direction.
    pub direction: XfrmDirection,
    /// Policy action.
    pub action: XfrmAction,
    /// Policy priority.
    pub priority: u32,
    /// Templates describing SAs that satisfy the policy.
    pub templates: Vec<XfrmTemplate>,
    /// Optional packet mark.
    pub mark: Option<XfrmMark>,
    /// Optional XFRM interface identifier.
    pub if_id: Option<u32>,
}

/// Template describing an SA that may satisfy a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmTemplate {
    /// SA identity.
    pub id: XfrmId,
    /// Source tunnel endpoint.
    pub source_address: IpAddress,
    /// Optional request identifier. A template with wildcard SPI (`0`) must
    /// carry a non-zero request ID so it cannot match unrelated SAs.
    pub request_id: Option<XfrmRequestId>,
    /// XFRM mode.
    pub mode: XfrmMode,
}

/// Request to allocate an SPI for a new inbound SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocateSpiRequest {
    /// Destination address for the SA.
    pub destination: IpAddress,
    /// Transform protocol such as `IPPROTO_ESP`.
    pub protocol: u8,
    /// Minimum SPI in host byte order.
    pub min_spi: u32,
    /// Maximum SPI in host byte order.
    pub max_spi: u32,
}

/// Result of an SPI allocation.
///
/// Linux creates a larval SA for `XFRM_MSG_ALLOCSPI`. If the negotiation that
/// requested this allocation aborts before installing the final SA, remove the
/// larval entry with [`SpiAllocation::cleanup_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpiAllocation {
    /// Destination address.
    pub destination: IpAddress,
    /// Transform protocol.
    pub protocol: u8,
    /// Allocated SPI in host byte order.
    pub spi: u32,
}

impl SpiAllocation {
    /// Build the deletion request for the larval SA created by SPI allocation.
    #[must_use]
    pub const fn cleanup_request(self) -> RemoveSaRequest {
        RemoveSaRequest {
            destination: self.destination,
            protocol: self.protocol,
            spi: self.spi,
            mark: None,
        }
    }
}

/// Request to install a new Security Association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSaRequest {
    /// SA parameters.
    pub parameters: SaParameters,
}

/// Request to query a Security Association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuerySaRequest {
    /// Destination address.
    pub destination: IpAddress,
    /// Transform protocol.
    pub protocol: u8,
    /// SPI in host byte order.
    pub spi: u32,
    /// Optional packet mark selecting a marked SA with this identity.
    pub mark: Option<XfrmMark>,
}

impl QuerySaRequest {
    /// Build an SA query for an unmarked SA.
    #[must_use]
    pub const fn new(destination: IpAddress, protocol: u8, spi: u32) -> Self {
        Self {
            destination,
            protocol,
            spi,
            mark: None,
        }
    }

    /// Select an SA carrying the supplied Linux XFRM lookup mark.
    #[must_use]
    pub const fn with_mark(mut self, mark: XfrmMark) -> Self {
        self.mark = Some(mark);
        self
    }
}

pub(crate) fn validate_sa_query(request: QuerySaRequest) -> Result<(), XfrmError> {
    if request.spi == 0 {
        return Err(XfrmError::invalid_config("spi", "spi must be nonzero"));
    }
    if request.protocol == 0 {
        return Err(XfrmError::invalid_config(
            "protocol",
            "protocol must be nonzero",
        ));
    }
    Ok(())
}

/// Redaction-safe kernel state for a queried SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaState {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// SA identity.
    pub id: XfrmId,
    /// Source tunnel endpoint.
    pub source_address: IpAddress,
    /// Request identifier returned by the kernel, when configured.
    pub request_id: Option<XfrmRequestId>,
    /// XFRM mode.
    pub mode: XfrmMode,
    /// Configured replay window.
    pub replay_window: u32,
    /// Replay and sequence-counter state.
    pub replay_state: SaReplayState,
    /// Configured lifetime limits.
    pub lifetime_config: LifetimeConfig,
    /// Current lifetime counters.
    pub lifetime_current: LifetimeCurrent,
    /// Current kernel failure counters.
    pub statistics: SaStatistics,
    /// Exact post-transform packet mark returned by the kernel.
    ///
    /// This is the raw combined `XFRMA_SET_MARK`/
    /// `XFRMA_SET_MARK_MASK` pair. When fixed outer DSCP is configured, it can
    /// contain both the DSCP token window and a generic output mark. The raw
    /// pair is authoritative even when token intent is ambiguous.
    pub output_mark: Option<XfrmMark>,
    /// Fixed outer DSCP decoded from an exclusive, complete mark token.
    ///
    /// An arbitrary generic mark can overlap the backend's configured token
    /// window, so this is a decoded observation rather than durable proof of
    /// the original SA request. [`Self::output_mark`] remains exact.
    pub egress_dscp: Option<DscpCodepoint>,
}

/// Exact Linux selector snapshot used by single-SA relocation.
///
/// Unlike [`XfrmSelector`], this type retains every non-reserved field from
/// the kernel's `struct xfrm_selector`. Linux installs the selector supplied
/// to `XFRM_MSG_MIGRATE_STATE`, so dropping a port mask, interface index, or
/// UID would silently change which packets the relocated SA selects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SaRelocationSelector {
    /// Source address.
    pub source: IpAddress,
    /// Destination address.
    pub destination: IpAddress,
    /// Source port in host byte order.
    pub source_port: u16,
    /// Exact source-port mask in host byte order.
    pub source_port_mask: u16,
    /// Destination port in host byte order.
    pub destination_port: u16,
    /// Exact destination-port mask in host byte order.
    pub destination_port_mask: u16,
    /// Upper-layer protocol number.
    pub protocol: u8,
    /// Source prefix length.
    pub source_prefix_len: u8,
    /// Destination prefix length.
    pub destination_prefix_len: u8,
    /// Exact Linux selector interface index (`ifindex`).
    pub ifindex: i32,
    /// Exact Linux selector UID value (`user`).
    pub user_id: u32,
}

impl SaRelocationSelector {
    /// Build the canonical exact form emitted for an ordinary SDK selector.
    #[must_use]
    pub const fn from_selector(selector: &XfrmSelector) -> Self {
        Self {
            source: selector.source,
            destination: selector.destination,
            source_port: selector.source_port,
            source_port_mask: if selector.source_port == 0 {
                0
            } else {
                u16::MAX
            },
            destination_port: selector.destination_port,
            destination_port_mask: if selector.destination_port == 0 {
                0
            } else {
                u16::MAX
            },
            protocol: selector.protocol,
            source_prefix_len: selector.source_prefix_len,
            destination_prefix_len: selector.destination_prefix_len,
            ifindex: 0,
            user_id: 0,
        }
    }

    /// Return the existing SDK selector projection.
    ///
    /// Port masks, interface index, and UID remain available only on this
    /// exact snapshot and are intentionally not discarded by relocation.
    #[must_use]
    pub const fn selector(&self) -> XfrmSelector {
        XfrmSelector {
            source: self.source,
            destination: self.destination,
            source_port: self.source_port,
            destination_port: self.destination_port,
            protocol: self.protocol,
            source_prefix_len: self.source_prefix_len,
            destination_prefix_len: self.destination_prefix_len,
        }
    }
}

/// Current, query-proven identity and stable attributes of an SA to relocate.
///
/// Linux's exact single-SA migration UAPI identifies the kernel object by
/// destination, SPI, protocol, family, and lookup mark. The remaining fields
/// are an optimistic-concurrency snapshot: the backend checks them before the
/// mutation and preserves them in the relocated state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaRelocationIdentity {
    /// Current exact packet selector.
    pub selector: SaRelocationSelector,
    /// Current destination/protocol/SPI identity.
    pub id: XfrmId,
    /// Current outer source address.
    pub source_address: IpAddress,
    /// Current request identifier.
    pub request_id: Option<XfrmRequestId>,
    /// Current XFRM mode.
    pub mode: XfrmMode,
    /// Current UDP encapsulation, when configured.
    pub encap: Option<UdpEncap>,
    /// Current packet lookup mark, when configured.
    pub mark: Option<XfrmMark>,
    /// Current XFRM interface identifier, when configured.
    pub if_id: Option<u32>,
    /// Current exact post-transform packet mark, when configured.
    pub output_mark: Option<XfrmMark>,
}

/// How one relocation changes the SA's ESP-in-UDP encapsulation.
///
/// This models the exact `XFRM_MSG_MIGRATE_STATE` attribute semantics: an
/// omitted `XFRMA_ENCAP` inherits the current template, a normal attribute
/// sets one, and an attribute whose type is zero removes it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaRelocationEncap {
    /// Preserve the current native-ESP or ESP-in-UDP form and ports.
    Preserve,
    /// Add or replace the ESP-in-UDP template and NAT-T ports.
    Set(UdpEncap),
    /// Remove the current ESP-in-UDP template and use native ESP.
    Remove,
}

/// Traffic direction and caller-proven safety state for one SA relocation.
///
/// The current-upstream Linux migration procedure requires an outbound block
/// policy before an outgoing SA is migrated. There is deliberately no plain
/// `Outbound` variant: selecting [`Self::OutboundBlockPolicyInstalled`] is the
/// caller's assertion that the block is already active and will remain active
/// until the replacement allow policy is installed. Incoming SAs do not have
/// a cleartext egress fallback and do not require that block.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaRelocationDirection {
    /// Incoming SA; replay state is transferred atomically by the kernel.
    Inbound,
    /// Outgoing SA after the mandatory temporary block policy is installed.
    OutboundBlockPolicyInstalled,
}

impl SaRelocationDirection {
    /// Whether the upstream migration sequence requires a temporary block.
    ///
    /// A `true` result means the caller must already have completed the first
    /// step (install the block policy) before submitting the relocation.
    #[must_use]
    pub const fn requires_outbound_block_policy(self) -> bool {
        match self {
            Self::Inbound => false,
            Self::OutboundBlockPolicyInstalled => true,
        }
    }
}

impl SaRelocationEncap {
    pub(crate) const fn resulting(self, current: Option<UdpEncap>) -> Option<UdpEncap> {
        match self {
            Self::Preserve => current,
            Self::Set(encap) => Some(encap),
            Self::Remove => None,
        }
    }
}

/// Request to relocate one installed tunnel-mode ESP SA's outer endpoints and
/// optionally change its NAT-T encapsulation.
///
/// This request is only an authenticated control-plane primitive. Callers must
/// derive the new endpoints from an authenticated/signalled procedure and must
/// coordinate policy-template changes separately. Outgoing SAs require the
/// upstream install-block/remove-old-policy/migrate/install-new-policy/
/// remove-block sequence represented by [`SaRelocationDirection`]. Keep that
/// block installed after an indeterminate result. Implementations never infer
/// relocation from an inbound packet.
///
/// # Cancel safety
///
/// Once [`crate::XfrmBackend::relocate_sa`] has been polled, the operation is
/// not cancellation-safe: blocking netlink work can continue after the Rust
/// future is dropped. Supervise and poll it to completion; do not put it behind
/// an aborting timeout. Cancellation, task disconnection, or process loss must
/// be treated as an indeterminate result. Keep the outbound block policy and
/// namespace-wide writer exclusion in place until the worker has completed and
/// exact old/new tuple readback has reconciled the state. After process loss,
/// reconcile before retrying because relocation is not blindly idempotent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocateSaRequest {
    /// Query-proven current SA identity and stable attributes.
    pub current: SaRelocationIdentity,
    /// New outer source address.
    pub new_source_address: IpAddress,
    /// New outer destination address.
    pub new_destination: IpAddress,
    /// Exact ESP-in-UDP preservation, set, or removal action.
    pub encap: SaRelocationEncap,
    /// Traffic direction and required outbound block-policy assertion.
    pub direction: SaRelocationDirection,
}

pub(crate) fn validate_relocate_sa_request(request: &RelocateSaRequest) -> Result<(), XfrmError> {
    match request.direction {
        SaRelocationDirection::Inbound | SaRelocationDirection::OutboundBlockPolicyInstalled => {}
    }
    validate_sa_relocation_selector(&request.current.selector)?;
    if request.current.id.spi == 0 {
        return Err(XfrmError::invalid_config(
            "relocation.current.spi",
            "spi must be nonzero",
        ));
    }
    if request.current.id.protocol != 50 {
        return Err(XfrmError::invalid_config(
            "relocation.current.protocol",
            "SA relocation supports ESP only",
        ));
    }
    if request.current.mode != XfrmMode::Tunnel {
        return Err(XfrmError::invalid_config(
            "relocation.current.mode",
            "SA relocation supports tunnel mode only",
        ));
    }
    validate_relocation_address_pair(
        request.current.source_address,
        request.current.id.destination,
        "relocation.current.family",
    )?;
    validate_relocation_address_pair(
        request.new_source_address,
        request.new_destination,
        "relocation.new.family",
    )?;
    if request.current.source_address.is_unspecified()
        || request.current.id.destination.is_unspecified()
        || request.new_source_address.is_unspecified()
        || request.new_destination.is_unspecified()
    {
        return Err(XfrmError::invalid_config(
            "relocation.address",
            "outer addresses must not be unspecified",
        ));
    }
    if matches!(request.current.mark, Some(XfrmMark { mask: 0, .. })) {
        return Err(XfrmError::invalid_config(
            "relocation.current.mark",
            "lookup-mark mask must be nonzero; use None for an unmarked SA",
        ));
    }
    if request.current.if_id == Some(0) {
        return Err(XfrmError::invalid_config(
            "relocation.current.if_id",
            "interface identifier must be nonzero; use None when absent",
        ));
    }
    if let Some(encap) = request.current.encap {
        validate_relocation_encap(encap, "relocation.current.encap")?;
    }
    match request.encap {
        SaRelocationEncap::Preserve => {}
        SaRelocationEncap::Set(encap) => {
            validate_relocation_encap(encap, "relocation.encap")?;
        }
        SaRelocationEncap::Remove if request.current.encap.is_none() => {
            return Err(XfrmError::invalid_config(
                "relocation.encap",
                "cannot remove UDP encapsulation when none is installed",
            ));
        }
        SaRelocationEncap::Remove => {}
    }
    let resulting_encap = request.encap.resulting(request.current.encap);
    if request.current.source_address == request.new_source_address
        && request.current.id.destination == request.new_destination
        && request.current.encap == resulting_encap
    {
        return Err(XfrmError::invalid_config(
            "relocation",
            "at least one outer endpoint or encapsulation value must change",
        ));
    }
    Ok(())
}

fn validate_sa_relocation_selector(selector: &SaRelocationSelector) -> Result<(), XfrmError> {
    validate_relocation_address_pair(
        selector.source,
        selector.destination,
        "relocation.current.selector.family",
    )?;
    let prefix_limit = if selector.source.is_ipv4() { 32 } else { 128 };
    if selector.source_prefix_len > prefix_limit {
        return Err(XfrmError::invalid_config(
            "relocation.current.selector.source_prefix_len",
            "prefix length exceeds address family",
        ));
    }
    if selector.destination_prefix_len > prefix_limit {
        return Err(XfrmError::invalid_config(
            "relocation.current.selector.destination_prefix_len",
            "prefix length exceeds address family",
        ));
    }
    Ok(())
}

fn validate_relocation_address_pair(
    source: IpAddress,
    destination: IpAddress,
    field: &'static str,
) -> Result<(), XfrmError> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(XfrmError::invalid_config(
            field,
            "addresses must use the same family",
        ));
    }
    Ok(())
}

fn validate_relocation_encap(encap: UdpEncap, field: &'static str) -> Result<(), XfrmError> {
    encap
        .validate_esp_in_udp()
        .map_err(|error| error.into_xfrm_error(field, field))
}

/// Request to rekey (update) an existing Security Association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeySaRequest {
    /// SA parameters.
    pub parameters: SaParameters,
}

/// Request to remove a Security Association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RemoveSaRequest {
    /// Destination address.
    pub destination: IpAddress,
    /// Transform protocol.
    pub protocol: u8,
    /// SPI in host byte order.
    pub spi: u32,
    /// Optional packet mark selecting a marked SA with this identity.
    pub mark: Option<XfrmMark>,
}

impl RemoveSaRequest {
    /// Build an SA removal request for an unmarked SA.
    #[must_use]
    pub const fn new(destination: IpAddress, protocol: u8, spi: u32) -> Self {
        Self {
            destination,
            protocol,
            spi,
            mark: None,
        }
    }

    /// Select an SA carrying the supplied Linux XFRM lookup mark.
    #[must_use]
    pub const fn with_mark(mut self, mark: XfrmMark) -> Self {
        self.mark = Some(mark);
        self
    }
}

/// Request to install a new Security Policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPolicyRequest {
    /// Policy parameters.
    pub parameters: PolicyParameters,
}

/// Request to rekey (update) an existing Security Policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyPolicyRequest {
    /// Policy parameters.
    pub parameters: PolicyParameters,
}

/// Request to remove a Security Policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemovePolicyRequest {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// Policy direction.
    pub direction: XfrmDirection,
    /// Optional packet mark selecting a marked policy with this identity.
    pub mark: Option<XfrmMark>,
}

impl RemovePolicyRequest {
    /// Build a removal request for an unmarked policy.
    #[must_use]
    pub const fn new(selector: XfrmSelector, direction: XfrmDirection) -> Self {
        Self {
            selector,
            direction,
            mark: None,
        }
    }

    /// Select a policy carrying the supplied Linux XFRM lookup mark.
    #[must_use]
    pub const fn with_mark(mut self, mark: XfrmMark) -> Self {
        self.mark = Some(mark);
        self
    }
}

/// Kind of XFRM backend implementation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum XfrmBackendKind {
    /// Backend is not implemented for the current platform.
    #[default]
    Unsupported,
    /// Backend talks to the Linux kernel XFRM netlink interface.
    LinuxKernel,
    /// In-memory mock/dry-run backend for tests and offline development.
    Mock,
}

/// Capability state reported by a probe.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum XfrmCapability {
    /// Capability state has not been determined.
    #[default]
    Unknown,
    /// Capability cannot be established without attempting the operation.
    UnknownUntilUse,
    /// The capability is available.
    Available,
    /// The capability is missing (e.g. kernel lacks an algorithm).
    Missing,
    /// The capability is denied by privileges (e.g. no `CAP_NET_ADMIN`).
    PermissionDenied,
}

/// Capability and health probe for an XFRM backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XfrmProbe {
    /// Kind of backend that produced the probe.
    pub kind: XfrmBackendKind,
    /// The platform supports XFRM operations (e.g. Linux).
    pub platform_supported: bool,
    /// The backend believes it can reach the kernel netlink endpoint.
    pub kernel_reachable: bool,
    /// The process has the privileges needed to mutate XFRM state.
    pub net_admin_capable: bool,
    /// Availability of required XFRM algorithms.
    pub algorithms: XfrmCapability,
    /// Availability of fixed outer-DSCP stamping for tunnel-mode SAs.
    pub egress_dscp_marking: XfrmCapability,
    /// Optional human-readable detail; static so the probe stays `Copy`.
    pub details: Option<&'static str>,
}

impl XfrmProbe {
    /// Probe result for the in-memory mock backend.
    pub const fn mock() -> Self {
        Self {
            kind: XfrmBackendKind::Mock,
            platform_supported: true,
            kernel_reachable: false,
            net_admin_capable: false,
            algorithms: XfrmCapability::Available,
            egress_dscp_marking: XfrmCapability::Missing,
            details: Some("dry-run/mock backend"),
        }
    }

    /// Probe result for an unsupported platform.
    pub const fn unsupported() -> Self {
        Self {
            kind: XfrmBackendKind::Unsupported,
            platform_supported: false,
            kernel_reachable: false,
            net_admin_capable: false,
            algorithms: XfrmCapability::Unknown,
            egress_dscp_marking: XfrmCapability::Missing,
            details: Some("XFRM operations are not supported on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_debug_redacts_content() {
        let key = KeyMaterial::new(vec![0xab; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("KeyMaterial"));
        assert!(debug.contains("len"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("ab"));
    }

    #[test]
    fn key_material_display_redacts_content() {
        let key = KeyMaterial::new(vec![0xcd; 16]);
        let display = key.to_string();
        assert!(display.contains("redacted"));
        assert!(!display.contains("cd"));
    }

    #[test]
    fn key_material_equality_semantics() {
        // Verifies equality semantics only; the constant-time property is
        // enforced by review, not by this test.
        let empty = KeyMaterial::new(vec![]);
        assert_eq!(empty, empty);

        let a = KeyMaterial::new(vec![1, 2, 3]);
        let b = KeyMaterial::new(vec![1, 2, 3]);
        assert_eq!(a, b);

        let c = KeyMaterial::new(vec![1, 2, 4]);
        assert_ne!(a, c);

        let d = KeyMaterial::new(vec![1, 2]);
        assert_ne!(a, d);
    }

    #[test]
    fn kernel_algorithm_constants_use_linux_template_names() {
        assert_eq!(XFRM_ENCR_CBC_AES, "cbc(aes)");
        assert_eq!(XFRM_ENCR_NULL, "ecb(cipher_null)");
        assert_eq!(XFRM_AEAD_RFC4106_GCM_AES, "rfc4106(gcm(aes))");
        assert_eq!(XFRM_AUTH_HMAC_SHA1, "hmac(sha1)");
        assert_eq!(XFRM_AUTH_HMAC_SHA256, "hmac(sha256)");
        assert_eq!(XFRM_AUTH_HMAC_SHA384, "hmac(sha384)");
        assert_eq!(XFRM_AUTH_HMAC_SHA512, "hmac(sha512)");

        assert_eq!(Algorithm::cbc_aes().name, XFRM_ENCR_CBC_AES);
        assert_eq!(Algorithm::null().name, XFRM_ENCR_NULL);
        assert_eq!(
            AuthAlgorithm::hmac_sha1(96),
            AuthAlgorithm::new(XFRM_AUTH_HMAC_SHA1, 96)
        );
        assert_eq!(
            AuthAlgorithm::hmac_sha256(128),
            AuthAlgorithm::new(XFRM_AUTH_HMAC_SHA256, 128)
        );
        assert_eq!(
            AuthAlgorithm::hmac_sha384(192),
            AuthAlgorithm::new(XFRM_AUTH_HMAC_SHA384, 192)
        );
        assert_eq!(
            AuthAlgorithm::hmac_sha512(256),
            AuthAlgorithm::new(XFRM_AUTH_HMAC_SHA512, 256)
        );
        assert_eq!(
            AeadAlgorithm::rfc4106_gcm_aes(128),
            AeadAlgorithm::new(XFRM_AEAD_RFC4106_GCM_AES, 128)
        );
    }

    #[test]
    fn udp_encapsulation_validation_is_typed_and_value_free() {
        assert_eq!(
            UdpEncap::esp_in_udp(4500, 62_000).validate_esp_in_udp(),
            Ok(())
        );

        let unsupported = UdpEncap {
            encap_type: 47,
            source_port: 4500,
            destination_port: 4500,
        }
        .validate_esp_in_udp()
        .expect_err("unsupported encapsulation type must fail");
        assert_eq!(unsupported, UdpEncapError::UnsupportedType);
        assert_eq!(unsupported.to_string(), "xfrm_udp_encap_unsupported_type");
        assert!(!format!("{unsupported:?}").contains("47"));

        let zero_port = UdpEncap::esp_in_udp(0, 4500)
            .validate_esp_in_udp()
            .expect_err("zero UDP port must fail");
        assert_eq!(zero_port, UdpEncapError::ZeroPort);
        assert_eq!(zero_port.to_string(), "xfrm_udp_encap_zero_port");
        assert!(!format!("{zero_port:?}").contains("4500"));
    }

    #[test]
    fn selector_defaults_full_prefix_length() {
        let sel = XfrmSelector::new(
            IpAddress::Ipv4([10, 0, 0, 1]),
            IpAddress::Ipv4([10, 0, 0, 2]),
            50,
        );
        assert_eq!(sel.source_prefix_len, 32);
        assert_eq!(sel.destination_prefix_len, 32);

        let sel = XfrmSelector::new(IpAddress::Ipv6([0; 16]), IpAddress::Ipv6([1; 16]), 50);
        assert_eq!(sel.source_prefix_len, 128);
        assert_eq!(sel.destination_prefix_len, 128);
    }

    #[test]
    fn unspecified_address_detection_covers_both_families() {
        assert!(IpAddress::Ipv4([0; 4]).is_unspecified());
        assert!(!IpAddress::Ipv4([0, 0, 0, 1]).is_unspecified());
        assert!(IpAddress::Ipv6([0; 16]).is_unspecified());
        let mut ipv6 = [0; 16];
        ipv6[15] = 1;
        assert!(!IpAddress::Ipv6(ipv6).is_unspecified());
    }

    #[test]
    fn relocation_direction_encodes_the_outbound_block_policy_contract() {
        assert!(!SaRelocationDirection::Inbound.requires_outbound_block_policy());
        assert!(
            SaRelocationDirection::OutboundBlockPolicyInstalled.requires_outbound_block_policy()
        );
    }

    #[test]
    fn replay_state_debug_hides_bitmap_contents() {
        let state = SaReplayState {
            esn: true,
            outbound_sequence: 10,
            inbound_sequence: 11,
            outbound_sequence_hi: 1,
            inbound_sequence_hi: 2,
            replay_window: 64,
            bitmap: vec![0xdead_beef, 0xfeed_face],
        };
        let debug = format!("{state:?}");
        assert!(debug.contains("bitmap_words"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("feed"));
    }

    #[test]
    fn fresh_replay_state_uses_esn_for_windows_above_32() {
        let legacy = SaReplayState::fresh(32);
        assert!(!legacy.esn);
        assert_eq!(legacy.bitmap, vec![0]);

        let esn = SaReplayState::fresh(65);
        assert!(esn.esn);
        assert_eq!(esn.bitmap.len(), 3);
    }

    #[test]
    fn spi_allocation_builds_larval_cleanup_request() {
        let allocation = SpiAllocation {
            destination: IpAddress::Ipv4([192, 0, 2, 10]),
            protocol: 50,
            spi: 0x1000_0001,
        };

        assert_eq!(
            allocation.cleanup_request(),
            RemoveSaRequest {
                destination: IpAddress::Ipv4([192, 0, 2, 10]),
                protocol: 50,
                spi: 0x1000_0001,
                mark: None,
            }
        );
    }
}
