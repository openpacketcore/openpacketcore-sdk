//! Safe model types for Linux XFRM IPsec backend operations.
//!
//! These types deliberately keep SA/policy policy in caller hands. The SDK
//! backend model owns selector/identity/lifetime/algorithm/key structure and
//! leaves IKE negotiation, namespace choice, and deployment privileges to the
//! product.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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

/// Algorithm name used for authentication or encryption.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Algorithm {
    /// Kernel algorithm name such as `aes-cbc` or `hmac-sha256`.
    pub name: String,
}

impl Algorithm {
    /// Create an algorithm from a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Authentication algorithm with truncation length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthAlgorithm {
    /// Kernel algorithm name such as `hmac-sha256`.
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
}

/// Combined-mode AEAD algorithm with Integrity Check Value length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AeadAlgorithm {
    /// Kernel algorithm name such as `rfc4106(gcm(aes))`.
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

/// Parameters needed to install or update a Security Association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaParameters {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// SA identity (destination, SPI, protocol).
    pub id: XfrmId,
    /// Source tunnel endpoint.
    pub source_address: IpAddress,
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
    pub replay_window: u8,
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
}

/// Template describing an SA that may satisfy a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmTemplate {
    /// SA identity.
    pub id: XfrmId,
    /// Source tunnel endpoint.
    pub source_address: IpAddress,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpiAllocation {
    /// Destination address.
    pub destination: IpAddress,
    /// Transform protocol.
    pub protocol: u8,
    /// Allocated SPI in host byte order.
    pub spi: u32,
}

/// Request to install a new Security Association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSaRequest {
    /// SA parameters.
    pub parameters: SaParameters,
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
}
