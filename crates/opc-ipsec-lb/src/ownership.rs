//! Destination-scoped ownership identities and deterministic owner selection.
//!
//! These types carry only public packet metadata and opaque routing context.
//! They never accept or retain IKE/ESP key material. The canonical encoding is
//! versioned, bounded, and independent of Serde formats so it can be shared by
//! stores, redirect transports, and future datapath ABIs.

use std::fmt;
use std::num::NonZeroU64;

use opc_ipsec_lb_ebpf_common::{
    canonical_esp_key, canonical_established_ike_key, canonical_initial_ike_key, XdpIpAddress,
    OWNERSHIP_ADDR_FAMILY_IPV4, OWNERSHIP_ADDR_FAMILY_IPV6, OWNERSHIP_ESP_NATIVE,
    OWNERSHIP_ESP_UDP_ENCAPSULATED, OWNERSHIP_KEY_MAGIC, OWNERSHIP_KIND_ESP,
    OWNERSHIP_KIND_ESTABLISHED_IKE, OWNERSHIP_KIND_INITIAL_IKE,
};
#[doc(no_inline)]
pub use opc_ipsec_lb_ebpf_common::{
    OWNERSHIP_KEY_ENCODING_VERSION, OWNERSHIP_KEY_MAX_ENCODED_BYTES,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{IpAddress, ShardId};

const MIN_ALLOCATABLE_ESP_SPI: u32 = 256;

/// Maximum number of members admitted to one deterministic ownership view.
pub const MAX_ELIGIBLE_OWNERS: usize = 1_024;

/// Redaction-safe validation or canonical-decoding failure for an ownership key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OwnershipKeyError {
    /// IKE initiator and responder SPIs are never zero in a constructed key.
    #[error("IKE ownership SPI must be non-zero")]
    ZeroIkeSpi,
    /// RFC 4303 reserves ESP SPI values 0 through 255.
    #[error("ESP ownership SPI is reserved")]
    ReservedEspSpi,
    /// The wire IKE exchange discriminator must be non-zero.
    #[error("initial IKE exchange discriminator must be non-zero")]
    ZeroInitialExchangeDiscriminator,
    /// The stable encoding did not carry the ownership-key magic.
    #[error("invalid ownership-key encoding magic")]
    InvalidEncodingMagic,
    /// The stable encoding version is not supported by this SDK.
    #[error("unsupported ownership-key encoding version")]
    UnsupportedEncodingVersion,
    /// The stable encoding carried an unknown key variant.
    #[error("unknown ownership-key kind")]
    UnknownKeyKind,
    /// The stable encoding carried an unknown IP address family.
    #[error("unknown ownership-key address family")]
    UnknownAddressFamily,
    /// The stable encoding carried an unknown ESP encapsulation kind.
    #[error("unknown ownership-key ESP encapsulation")]
    UnknownEspEncapsulation,
    /// The stable encoding ended before all fields were present.
    #[error("truncated ownership-key encoding")]
    TruncatedEncoding,
    /// The stable encoding carried bytes after the selected variant.
    #[error("trailing ownership-key encoding bytes")]
    TrailingEncoding,
    /// The stable encoding exceeded its fixed production bound.
    #[error("ownership-key encoding exceeds the production bound")]
    EncodingTooLong,
}

impl OwnershipKeyError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroIkeSpi => "ownership_key_zero_ike_spi",
            Self::ReservedEspSpi => "ownership_key_reserved_esp_spi",
            Self::ZeroInitialExchangeDiscriminator => {
                "ownership_key_zero_initial_exchange_discriminator"
            }
            Self::InvalidEncodingMagic => "ownership_key_invalid_encoding_magic",
            Self::UnsupportedEncodingVersion => "ownership_key_unsupported_encoding_version",
            Self::UnknownKeyKind => "ownership_key_unknown_kind",
            Self::UnknownAddressFamily => "ownership_key_unknown_address_family",
            Self::UnknownEspEncapsulation => "ownership_key_unknown_esp_encapsulation",
            Self::TruncatedEncoding => "ownership_key_truncated_encoding",
            Self::TrailingEncoding => "ownership_key_trailing_encoding",
            Self::EncodingTooLong => "ownership_key_encoding_too_long",
        }
    }
}

/// Redaction-safe membership or selection validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OwnershipSelectionError {
    /// Membership generations are strictly positive.
    #[error("ownership membership generation must be non-zero")]
    ZeroMembershipGeneration,
    /// A membership view must contain at least one eligible owner.
    #[error("ownership membership is empty")]
    EmptyMembership,
    /// The caller supplied more owners than the production profile admits.
    #[error("ownership membership exceeds the production bound")]
    TooManyMembers,
    /// A member identity appeared more than once.
    #[error("ownership membership contains a duplicate member")]
    DuplicateMember,
    /// A selection was consumed against a different membership generation.
    #[error("ownership selection membership generation mismatch")]
    MembershipGenerationMismatch,
    /// A continuity promotion did not start from the selected initial key.
    #[error("ownership selection key does not match the promotion source")]
    SelectionKeyMismatch,
}

impl OwnershipSelectionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroMembershipGeneration => "ownership_zero_membership_generation",
            Self::EmptyMembership => "ownership_empty_membership",
            Self::TooManyMembers => "ownership_too_many_members",
            Self::DuplicateMember => "ownership_duplicate_member",
            Self::MembershipGenerationMismatch => "ownership_membership_generation_mismatch",
            Self::SelectionKeyMismatch => "ownership_selection_key_mismatch",
        }
    }
}

/// Opaque product-defined routing-domain tag.
///
/// The fixed-width value can represent a VRF/table identifier or an index into
/// a product-owned routing-domain registry. The SDK never interprets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoutingDomainTag(u64);

impl RoutingDomainTag {
    /// Construct an opaque routing-domain tag.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the opaque numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A public destination address bound to its routing domain.
///
/// Both fields are structurally present in every ownership-key variant.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DestinationContext {
    address: IpAddress,
    routing_domain: RoutingDomainTag,
}

impl DestinationContext {
    /// Bind a public destination address to one routing domain.
    #[must_use]
    pub const fn new(address: IpAddress, routing_domain: RoutingDomainTag) -> Self {
        Self {
            address,
            routing_domain,
        }
    }

    /// Return the public destination address.
    #[must_use]
    pub const fn address(self) -> IpAddress {
        self.address
    }

    /// Return the opaque routing-domain tag.
    #[must_use]
    pub const fn routing_domain(self) -> RoutingDomainTag {
        self.routing_domain
    }
}

impl fmt::Debug for DestinationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationContext")
            .field("address", &"<redacted>")
            .field("routing_domain", &self.routing_domain)
            .finish()
    }
}

impl fmt::Display for DestinationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "destination=<redacted> routing_domain={}",
            self.routing_domain.get()
        )
    }
}

/// The observed outer source IP address and UDP source port.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OuterSourceTuple {
    address: IpAddress,
    port: u16,
}

impl OuterSourceTuple {
    /// Construct the exact source tuple observed on the outer packet.
    #[must_use]
    pub const fn new(address: IpAddress, port: u16) -> Self {
        Self { address, port }
    }

    /// Return the observed outer source address.
    #[must_use]
    pub const fn address(self) -> IpAddress {
        self.address
    }

    /// Return the observed outer UDP source port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }
}

impl fmt::Debug for OuterSourceTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OuterSourceTuple")
            .field("address", &"<redacted>")
            .field("port", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for OuterSourceTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("source=<redacted>")
    }
}

/// A validated non-zero IKE SPI.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IkeSpi(NonZeroU64);

impl IkeSpi {
    /// Validate an initiator or responder IKE SPI.
    pub const fn new(value: u64) -> Result<Self, OwnershipKeyError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(OwnershipKeyError::ZeroIkeSpi),
        }
    }

    /// Return the wire SPI value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for IkeSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IkeSpi(<redacted>)")
    }
}

impl fmt::Display for IkeSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A validated allocatable ESP SPI.
///
/// RFC 4303 reserves values 0 through 255. Ownership is therefore never
/// created for those values even if a malformed packet reaches a classifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EspSpi(u32);

impl EspSpi {
    /// Validate an inbound ESP SPI.
    pub const fn new(value: u32) -> Result<Self, OwnershipKeyError> {
        if value < MIN_ALLOCATABLE_ESP_SPI {
            return Err(OwnershipKeyError::ReservedEspSpi);
        }
        Ok(Self(value))
    }

    /// Return the wire SPI value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for EspSpi {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for EspSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EspSpi(<redacted>)")
    }
}

impl fmt::Display for EspSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Wire IKE Exchange Type used to distinguish an initial exchange.
///
/// For IKE_SA_INIT this is `34`. Keeping the discriminator typed makes future
/// initial exchanges distinct without embedding packet bytes in the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct InitialExchangeDiscriminator(u8);

impl InitialExchangeDiscriminator {
    /// IKE_SA_INIT exchange type from RFC 7296.
    pub const IKE_SA_INIT: Self = Self(34);

    /// Validate a wire IKE Exchange Type.
    pub const fn new(value: u8) -> Result<Self, OwnershipKeyError> {
        if value == 0 {
            Err(OwnershipKeyError::ZeroInitialExchangeDiscriminator)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the wire Exchange Type.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for InitialExchangeDiscriminator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// ESP packet representation on the public ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EspEncapsulationKind {
    /// Native IP protocol 50 ESP.
    Native,
    /// RFC 3948 UDP-encapsulated ESP.
    UdpEncapsulated,
}

/// Canonical initial-IKE ownership identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InitialIkeOwnershipKey {
    destination: DestinationContext,
    outer_source: OuterSourceTuple,
    initiator_spi: IkeSpi,
    exchange: InitialExchangeDiscriminator,
}

impl InitialIkeOwnershipKey {
    /// Construct an initial-IKE ownership identity.
    #[must_use]
    pub const fn new(
        destination: DestinationContext,
        outer_source: OuterSourceTuple,
        initiator_spi: IkeSpi,
        exchange: InitialExchangeDiscriminator,
    ) -> Self {
        Self {
            destination,
            outer_source,
            initiator_spi,
            exchange,
        }
    }

    /// Return the destination/routing-domain context.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        self.destination
    }

    /// Return the observed outer source tuple.
    #[must_use]
    pub const fn outer_source(self) -> OuterSourceTuple {
        self.outer_source
    }

    /// Return the initiator SPI.
    #[must_use]
    pub const fn initiator_spi(self) -> IkeSpi {
        self.initiator_spi
    }

    /// Return the initial-exchange discriminator.
    #[must_use]
    pub const fn exchange(self) -> InitialExchangeDiscriminator {
        self.exchange
    }

    /// Convert a valid initial key after allocating a responder SPI.
    ///
    /// This conversion is total because both SPIs are already validated. The
    /// returned promotion retains both keys; use
    /// [`OwnerSelection::carry_forward`] to preserve the selected owner rather
    /// than hashing the new key as a new allocation decision.
    #[must_use]
    pub const fn promote(self, responder_spi: IkeSpi) -> OwnershipKeyPromotion {
        OwnershipKeyPromotion {
            initial: self,
            established: EstablishedIkeOwnershipKey::new(
                self.destination,
                self.initiator_spi,
                responder_spi,
            ),
        }
    }
}

impl fmt::Debug for InitialIkeOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialIkeOwnershipKey")
            .field("destination", &self.destination)
            .field("outer_source", &self.outer_source)
            .field("initiator_spi", &"<redacted>")
            .field("exchange", &self.exchange.get())
            .finish()
    }
}

impl fmt::Display for InitialIkeOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "initial-ike({}; {}; exchange={})",
            self.destination,
            self.outer_source,
            self.exchange.get()
        )
    }
}

/// Canonical established-IKE ownership identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EstablishedIkeOwnershipKey {
    destination: DestinationContext,
    initiator_spi: IkeSpi,
    responder_spi: IkeSpi,
}

impl EstablishedIkeOwnershipKey {
    /// Construct an established-IKE ownership identity.
    #[must_use]
    pub const fn new(
        destination: DestinationContext,
        initiator_spi: IkeSpi,
        responder_spi: IkeSpi,
    ) -> Self {
        Self {
            destination,
            initiator_spi,
            responder_spi,
        }
    }

    /// Return the destination/routing-domain context.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        self.destination
    }

    /// Return the initiator SPI.
    #[must_use]
    pub const fn initiator_spi(self) -> IkeSpi {
        self.initiator_spi
    }

    /// Return the responder SPI.
    #[must_use]
    pub const fn responder_spi(self) -> IkeSpi {
        self.responder_spi
    }
}

impl fmt::Debug for EstablishedIkeOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedIkeOwnershipKey")
            .field("destination", &self.destination)
            .field("initiator_spi", &"<redacted>")
            .field("responder_spi", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for EstablishedIkeOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "established-ike({})", self.destination)
    }
}

/// Canonical inbound-ESP ownership identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EspOwnershipKey {
    destination: DestinationContext,
    encapsulation: EspEncapsulationKind,
    inbound_spi: EspSpi,
}

impl EspOwnershipKey {
    /// Construct an inbound-ESP ownership identity.
    #[must_use]
    pub const fn new(
        destination: DestinationContext,
        encapsulation: EspEncapsulationKind,
        inbound_spi: EspSpi,
    ) -> Self {
        Self {
            destination,
            encapsulation,
            inbound_spi,
        }
    }

    /// Return the destination/routing-domain context.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        self.destination
    }

    /// Return the public-ingress encapsulation kind.
    #[must_use]
    pub const fn encapsulation(self) -> EspEncapsulationKind {
        self.encapsulation
    }

    /// Return the inbound ESP SPI.
    #[must_use]
    pub const fn inbound_spi(self) -> EspSpi {
        self.inbound_spi
    }
}

impl fmt::Debug for EspOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspOwnershipKey")
            .field("destination", &self.destination)
            .field("encapsulation", &self.encapsulation)
            .field("inbound_spi", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for EspOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "esp({}; encapsulation={:?})",
            self.destination, self.encapsulation
        )
    }
}

/// Ownership-key protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OwnershipKeyKind {
    /// Initial IKE exchange before responder-SPI allocation.
    InitialIke,
    /// Established IKE SA.
    EstablishedIke,
    /// Inbound ESP Child SA.
    Esp,
}

/// Canonical destination-scoped session ownership key.
///
/// The enum is ordered, hashable, Serde-serializable, and has a separate
/// stable canonical byte encoding. Every variant contains a
/// [`DestinationContext`], so an address-less ownership lookup is
/// unrepresentable. Its `Debug` and `Display` implementations redact public
/// and peer addresses as well as SPI correlation values.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SessionOwnershipKey {
    /// Initial IKE exchange.
    InitialIke(InitialIkeOwnershipKey),
    /// Established IKE SA.
    EstablishedIke(EstablishedIkeOwnershipKey),
    /// Inbound ESP Child SA.
    Esp(EspOwnershipKey),
}

impl SessionOwnershipKey {
    /// Return the protocol family represented by this key.
    #[must_use]
    pub const fn kind(self) -> OwnershipKeyKind {
        match self {
            Self::InitialIke(_) => OwnershipKeyKind::InitialIke,
            Self::EstablishedIke(_) => OwnershipKeyKind::EstablishedIke,
            Self::Esp(_) => OwnershipKeyKind::Esp,
        }
    }

    /// Return the required destination/routing-domain context.
    #[must_use]
    pub const fn destination(self) -> DestinationContext {
        match self {
            Self::InitialIke(key) => key.destination(),
            Self::EstablishedIke(key) => key.destination(),
            Self::Esp(key) => key.destination(),
        }
    }

    /// Encode the versioned, bounded canonical ownership key.
    ///
    /// The byte layout is owned by `opc-ipsec-lb-ebpf-common` so the XDP
    /// datapath derives byte-identical keys from packet headers.
    #[must_use]
    pub fn to_canonical_bytes(self) -> Vec<u8> {
        let (encoded, len) = match self {
            Self::InitialIke(key) => canonical_initial_ike_key(
                xdp_address(key.destination.address),
                key.destination.routing_domain.get(),
                xdp_address(key.outer_source.address),
                key.outer_source.port,
                key.initiator_spi.get(),
                key.exchange.get(),
            ),
            Self::EstablishedIke(key) => canonical_established_ike_key(
                xdp_address(key.destination.address),
                key.destination.routing_domain.get(),
                key.initiator_spi.get(),
                key.responder_spi.get(),
            ),
            Self::Esp(key) => canonical_esp_key(
                xdp_address(key.destination.address),
                key.destination.routing_domain.get(),
                match key.encapsulation {
                    EspEncapsulationKind::Native => OWNERSHIP_ESP_NATIVE,
                    EspEncapsulationKind::UdpEncapsulated => OWNERSHIP_ESP_UDP_ENCAPSULATED,
                },
                key.inbound_spi.get(),
            ),
        };
        encoded[..len].to_vec()
    }

    /// Decode one exact canonical ownership key.
    ///
    /// Truncation, unknown fields, reserved SPIs, and trailing bytes fail
    /// closed. At most [`OWNERSHIP_KEY_MAX_ENCODED_BYTES`] are inspected.
    pub fn from_canonical_bytes(encoded: &[u8]) -> Result<Self, OwnershipKeyError> {
        if encoded.len() > OWNERSHIP_KEY_MAX_ENCODED_BYTES {
            return Err(OwnershipKeyError::EncodingTooLong);
        }

        let mut cursor = EncodingCursor::new(encoded);
        if cursor.take::<4>()? != OWNERSHIP_KEY_MAGIC {
            return Err(OwnershipKeyError::InvalidEncodingMagic);
        }
        if cursor.u8()? != OWNERSHIP_KEY_ENCODING_VERSION {
            return Err(OwnershipKeyError::UnsupportedEncodingVersion);
        }
        let kind = cursor.u8()?;
        let destination = decode_destination(&mut cursor)?;

        let key = match kind {
            OWNERSHIP_KIND_INITIAL_IKE => {
                let outer_source =
                    OuterSourceTuple::new(decode_address(&mut cursor)?, cursor.u16()?);
                let initiator_spi = IkeSpi::new(cursor.u64()?)?;
                let exchange = InitialExchangeDiscriminator::new(cursor.u8()?)?;
                Self::InitialIke(InitialIkeOwnershipKey::new(
                    destination,
                    outer_source,
                    initiator_spi,
                    exchange,
                ))
            }
            OWNERSHIP_KIND_ESTABLISHED_IKE => {
                let initiator_spi = IkeSpi::new(cursor.u64()?)?;
                let responder_spi = IkeSpi::new(cursor.u64()?)?;
                Self::EstablishedIke(EstablishedIkeOwnershipKey::new(
                    destination,
                    initiator_spi,
                    responder_spi,
                ))
            }
            OWNERSHIP_KIND_ESP => {
                let encapsulation = match cursor.u8()? {
                    OWNERSHIP_ESP_NATIVE => EspEncapsulationKind::Native,
                    OWNERSHIP_ESP_UDP_ENCAPSULATED => EspEncapsulationKind::UdpEncapsulated,
                    _ => return Err(OwnershipKeyError::UnknownEspEncapsulation),
                };
                let inbound_spi = EspSpi::new(cursor.u32()?)?;
                Self::Esp(EspOwnershipKey::new(
                    destination,
                    encapsulation,
                    inbound_spi,
                ))
            }
            _ => return Err(OwnershipKeyError::UnknownKeyKind),
        };

        cursor.finish()?;
        Ok(key)
    }

    /// Stable SHA-256 digest of the canonical key.
    ///
    /// The digest is used only for deterministic owner selection and
    /// continuity binding. It is not IPsec key material and is never used as a
    /// cryptographic secret.
    #[must_use]
    pub fn canonical_digest(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"opc-ipsec-lb/ownership-key-digest/v1");
        hasher.update(self.to_canonical_bytes());
        hasher.finalize().into()
    }

    /// Classify a possible SPI collision in one destination context.
    ///
    /// Exact-key matches are surfaced separately because the consumer may
    /// classify them as a retransmission or an already-installed record. A
    /// protocol-SPI match with different remaining fields is a collision. The
    /// SDK does not decide whether to reject, reallocate, or retire either SA.
    #[must_use]
    pub fn collision_with(self, other: Self) -> OwnershipCollision {
        if self == other {
            return OwnershipCollision::ExactKey;
        }
        match (self, other) {
            (Self::InitialIke(left), Self::InitialIke(right))
                if left.destination == right.destination
                    && left.initiator_spi == right.initiator_spi =>
            {
                OwnershipCollision::InitialIkeInitiatorSpi
            }
            (Self::EstablishedIke(left), Self::EstablishedIke(right))
                if left.destination == right.destination
                    && left.responder_spi == right.responder_spi =>
            {
                OwnershipCollision::EstablishedIkeResponderSpi
            }
            (Self::Esp(left), Self::Esp(right))
                if left.destination == right.destination
                    && left.inbound_spi == right.inbound_spi =>
            {
                OwnershipCollision::EspInboundSpi
            }
            _ => OwnershipCollision::None,
        }
    }
}

impl From<InitialIkeOwnershipKey> for SessionOwnershipKey {
    fn from(value: InitialIkeOwnershipKey) -> Self {
        Self::InitialIke(value)
    }
}

impl From<EstablishedIkeOwnershipKey> for SessionOwnershipKey {
    fn from(value: EstablishedIkeOwnershipKey) -> Self {
        Self::EstablishedIke(value)
    }
}

impl From<EspOwnershipKey> for SessionOwnershipKey {
    fn from(value: EspOwnershipKey) -> Self {
        Self::Esp(value)
    }
}

impl fmt::Debug for SessionOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialIke(key) => fmt::Debug::fmt(key, f),
            Self::EstablishedIke(key) => fmt::Debug::fmt(key, f),
            Self::Esp(key) => fmt::Debug::fmt(key, f),
        }
    }
}

impl fmt::Display for SessionOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialIke(key) => fmt::Display::fmt(key, f),
            Self::EstablishedIke(key) => fmt::Display::fmt(key, f),
            Self::Esp(key) => fmt::Display::fmt(key, f),
        }
    }
}

/// Typed collision result for two ownership keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OwnershipCollision {
    /// The keys do not collide in one destination/routing-domain context.
    None,
    /// Both values are the same complete lookup key.
    ExactKey,
    /// Two distinct initial identities reuse an initiator SPI.
    InitialIkeInitiatorSpi,
    /// Two distinct established identities reuse a responder SPI.
    EstablishedIkeResponderSpi,
    /// Two distinct ESP identities reuse an inbound SPI.
    EspInboundSpi,
}

/// A total initial-to-established key conversion retaining both identities.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnershipKeyPromotion {
    initial: InitialIkeOwnershipKey,
    established: EstablishedIkeOwnershipKey,
}

impl OwnershipKeyPromotion {
    /// Return the complete initial lookup key.
    #[must_use]
    pub const fn initial(self) -> InitialIkeOwnershipKey {
        self.initial
    }

    /// Return the complete established lookup key.
    #[must_use]
    pub const fn established(self) -> EstablishedIkeOwnershipKey {
        self.established
    }
}

impl fmt::Debug for OwnershipKeyPromotion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnershipKeyPromotion")
            .field("initial", &self.initial)
            .field("established", &self.established)
            .finish()
    }
}

/// Strictly positive generation of one eligible-owner membership view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MembershipGeneration(u64);

impl MembershipGeneration {
    /// Validate a membership generation.
    pub const fn new(value: u64) -> Result<Self, OwnershipSelectionError> {
        if value == 0 {
            return Err(OwnershipSelectionError::ZeroMembershipGeneration);
        }
        Ok(Self(value))
    }

    /// Return the monotonic generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for MembershipGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validated, sorted eligible-owner view bound to one membership generation.
#[derive(Clone, PartialEq, Eq)]
pub struct EligibleOwnershipMembers {
    generation: MembershipGeneration,
    members: Vec<ShardId>,
}

impl EligibleOwnershipMembers {
    /// Validate, sort, and bind the eligible member set.
    pub fn new(
        generation: MembershipGeneration,
        mut members: Vec<ShardId>,
    ) -> Result<Self, OwnershipSelectionError> {
        if members.is_empty() {
            return Err(OwnershipSelectionError::EmptyMembership);
        }
        if members.len() > MAX_ELIGIBLE_OWNERS {
            return Err(OwnershipSelectionError::TooManyMembers);
        }
        members.sort_unstable();
        if members.windows(2).any(|window| window[0] == window[1]) {
            return Err(OwnershipSelectionError::DuplicateMember);
        }
        Ok(Self {
            generation,
            members,
        })
    }

    /// Return the membership generation carried by this view.
    #[must_use]
    pub const fn generation(&self) -> MembershipGeneration {
        self.generation
    }

    /// Borrow the canonical sorted eligible member list.
    #[must_use]
    pub fn members(&self) -> &[ShardId] {
        &self.members
    }
}

impl fmt::Debug for EligibleOwnershipMembers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EligibleOwnershipMembers")
            .field("generation", &self.generation)
            .field("member_count", &self.members.len())
            .finish()
    }
}

/// Deterministic owner decision bound to its key and membership generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OwnerSelection {
    owner: ShardId,
    membership_generation: MembershipGeneration,
    key_digest: [u8; 32],
}

impl OwnerSelection {
    pub(crate) fn new(
        owner: ShardId,
        membership_generation: MembershipGeneration,
        key_digest: [u8; 32],
    ) -> Self {
        Self {
            owner,
            membership_generation,
            key_digest,
        }
    }

    /// Return the selected owner shard for planning or diagnostics.
    ///
    /// Before admitting an external effect, prefer [`Self::owner_for_generation`]
    /// with the caller's current view so a superseded selection fails closed.
    #[must_use]
    pub const fn owner(self) -> ShardId {
        self.owner
    }

    /// Return the membership generation used for this decision.
    #[must_use]
    pub const fn membership_generation(self) -> MembershipGeneration {
        self.membership_generation
    }

    /// Return whether this selection was calculated for the supplied key.
    #[must_use]
    pub fn is_for(self, key: &SessionOwnershipKey) -> bool {
        self.key_digest == key.canonical_digest()
    }

    /// Consume the owner only when the caller's current generation matches.
    pub fn owner_for_generation(
        self,
        current: MembershipGeneration,
    ) -> Result<ShardId, OwnershipSelectionError> {
        if self.membership_generation != current {
            return Err(OwnershipSelectionError::MembershipGenerationMismatch);
        }
        Ok(self.owner)
    }

    /// Carry an initial owner decision into its established key without moving.
    ///
    /// This is the ownership-continuity path. It verifies that the decision was
    /// calculated for the promotion's exact initial key, retains the owner and
    /// membership generation, and binds the result to the established key. It
    /// deliberately does not run rendezvous selection again.
    pub fn carry_forward(
        self,
        promotion: OwnershipKeyPromotion,
    ) -> Result<Self, OwnershipSelectionError> {
        let initial = SessionOwnershipKey::InitialIke(promotion.initial);
        if !self.is_for(&initial) {
            return Err(OwnershipSelectionError::SelectionKeyMismatch);
        }
        Ok(Self {
            owner: self.owner,
            membership_generation: self.membership_generation,
            key_digest: SessionOwnershipKey::EstablishedIke(promotion.established)
                .canonical_digest(),
        })
    }
}

impl fmt::Debug for OwnerSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerSelection")
            .field("owner", &self.owner)
            .field("membership_generation", &self.membership_generation)
            .field("key_digest", &"<redacted>")
            .finish()
    }
}

const fn xdp_address(address: IpAddress) -> XdpIpAddress {
    match address {
        IpAddress::V4(octets) => XdpIpAddress::V4(octets),
        IpAddress::V6(octets) => XdpIpAddress::V6(octets),
    }
}

fn decode_destination(
    cursor: &mut EncodingCursor<'_>,
) -> Result<DestinationContext, OwnershipKeyError> {
    let routing_domain = RoutingDomainTag::new(cursor.u64()?);
    let address = decode_address(cursor)?;
    Ok(DestinationContext::new(address, routing_domain))
}

fn decode_address(cursor: &mut EncodingCursor<'_>) -> Result<IpAddress, OwnershipKeyError> {
    match cursor.u8()? {
        OWNERSHIP_ADDR_FAMILY_IPV4 => Ok(IpAddress::V4(cursor.take::<4>()?)),
        OWNERSHIP_ADDR_FAMILY_IPV6 => Ok(IpAddress::V6(cursor.take::<16>()?)),
        _ => Err(OwnershipKeyError::UnknownAddressFamily),
    }
}

struct EncodingCursor<'a> {
    encoded: &'a [u8],
    position: usize,
}

impl<'a> EncodingCursor<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self {
            encoded,
            position: 0,
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], OwnershipKeyError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(OwnershipKeyError::TruncatedEncoding)?;
        let bytes = self
            .encoded
            .get(self.position..end)
            .ok_or(OwnershipKeyError::TruncatedEncoding)?;
        let mut value = [0u8; N];
        value.copy_from_slice(bytes);
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, OwnershipKeyError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, OwnershipKeyError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, OwnershipKeyError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, OwnershipKeyError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn finish(self) -> Result<(), OwnershipKeyError> {
        if self.position != self.encoded.len() {
            return Err(OwnershipKeyError::TrailingEncoding);
        }
        Ok(())
    }
}
