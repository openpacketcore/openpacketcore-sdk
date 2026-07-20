//! Shared eBPF map ABI for the SWu IPsec load-balancing datapath.
//!
//! This crate is the single source of truth for byte layouts exchanged between
//! the host-XDP steering backend and the XDP program. It is `no_std`,
//! dependency-free, and deliberately key-material-free: values contain only
//! packet-header routing keys and redirect metadata.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

pub mod xdp;

pub use xdp::*;

/// Magic prefix for the authenticated cross-node ingress redirect protocol.
pub const INGRESS_REDIRECT_MAGIC: [u8; 4] = *b"OPCR";
/// Current authenticated ingress redirect wire version.
pub const INGRESS_REDIRECT_VERSION: u8 = 1;
/// Fixed v1 redirect header length.
pub const INGRESS_REDIRECT_HEADER_LEN: usize = 88;
/// SHA-256 digest width used to bind a frame to its authenticated sender.
pub const INGRESS_REDIRECT_SENDER_DIGEST_LEN: usize = 32;
/// Maximum canonical ownership-key width carried by v1.
pub const INGRESS_REDIRECT_OWNERSHIP_KEY_MAX_LEN: usize = 59;
/// AES-256-GCM authentication tag width.
pub const INGRESS_REDIRECT_AES_GCM_TAG_LEN: usize = 16;
/// HMAC-SHA256 authentication tag width.
pub const INGRESS_REDIRECT_HMAC_SHA256_TAG_LEN: usize = 32;

const REDIRECT_KIND_DATA: u8 = 1;
const REDIRECT_KIND_RECEIPT: u8 = 2;
const REDIRECT_SECURITY_AES_256_GCM: u8 = 1;
const REDIRECT_SECURITY_HMAC_SHA256: u8 = 2;

/// Authenticated redirect frame kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IngressRedirectFrameKind {
    /// Carries one original ingress IP packet and its canonical ownership key.
    Data = REDIRECT_KIND_DATA,
    /// Authenticated delivery or typed-rejection receipt.
    Receipt = REDIRECT_KIND_RECEIPT,
}

/// Protection selected by the authenticated mTLS control bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IngressRedirectSecurityMode {
    /// Encrypt packet bytes and authenticate all frame bytes with AES-256-GCM.
    Aes256Gcm = REDIRECT_SECURITY_AES_256_GCM,
    /// Preserve packet bytes and authenticate all frame bytes with HMAC-SHA256.
    HmacSha256 = REDIRECT_SECURITY_HMAC_SHA256,
}

impl IngressRedirectSecurityMode {
    /// Authentication trailer width for this mode.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::Aes256Gcm => INGRESS_REDIRECT_AES_GCM_TAG_LEN,
            Self::HmacSha256 => INGRESS_REDIRECT_HMAC_SHA256_TAG_LEN,
        }
    }
}

/// Authenticated result returned for one data frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IngressRedirectReceiptCode {
    /// The original packet was admitted to the receiver's bounded delivery queue.
    Delivered = 1,
    /// The authenticated receiver is not the fresh fenced owner.
    NotOwner = 2,
    /// The sender stamped a superseded ownership generation.
    StaleOwnershipGeneration = 3,
    /// The receiver's committed ownership view was not fresh.
    OwnershipViewStale = 4,
    /// The receiver's bounded packet or byte queue was full.
    QueueFull = 5,
    /// The authenticated redirect reached its hop limit.
    HopLimitReached = 6,
    /// Receiver reclassification did not reproduce the carried ownership key.
    ClassificationMismatch = 7,
    /// The receiver has a fresh authoritative view with no record for the key.
    OwnershipMissing = 8,
    /// The sender generation is newer than the receiver's committed evidence.
    ReceiverViewBehind = 9,
    /// The authenticated peer is not authorized for the carried routing domain.
    RoutingDomainNotAuthorized = 10,
}

/// Stable, allocation-free redirect-header validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngressRedirectHeaderError {
    /// Fewer than [`INGRESS_REDIRECT_HEADER_LEN`] bytes were available.
    Truncated,
    /// The protocol magic did not match.
    InvalidMagic,
    /// The version is not supported.
    UnsupportedVersion,
    /// The frame kind is not defined by this version.
    UnknownKind,
    /// The protection mode is not defined by this version.
    UnknownSecurityMode,
    /// Reserved v1 bits or bytes were non-zero.
    NonZeroReserved,
    /// Hop metadata was structurally invalid.
    InvalidHop,
    /// Ownership-key or packet lengths were invalid for the frame kind.
    InvalidLengths,
    /// Receipt-only fields were invalid for the frame kind.
    InvalidReceipt,
    /// Epoch or sequence identity was zero.
    InvalidSequence,
}

impl IngressRedirectHeaderError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "redirect_header_truncated",
            Self::InvalidMagic => "redirect_header_invalid_magic",
            Self::UnsupportedVersion => "redirect_header_unsupported_version",
            Self::UnknownKind => "redirect_header_unknown_kind",
            Self::UnknownSecurityMode => "redirect_header_unknown_security_mode",
            Self::NonZeroReserved => "redirect_header_nonzero_reserved",
            Self::InvalidHop => "redirect_header_invalid_hop",
            Self::InvalidLengths => "redirect_header_invalid_lengths",
            Self::InvalidReceipt => "redirect_header_invalid_receipt",
            Self::InvalidSequence => "redirect_header_invalid_sequence",
        }
    }
}

impl fmt::Display for IngressRedirectHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fixed-width v1 authenticated ingress redirect header.
///
/// All integers use network byte order. Packet bytes and the canonical
/// ownership key immediately follow this header; an authentication trailer
/// selected by [`Self::security_mode`] terminates the datagram. The sender
/// digest is public identity metadata, not a key, and `Debug` redacts it.
///
/// Layout (88 bytes):
///
/// | offset | width | field |
/// | ---: | ---: | --- |
/// | 0 | 4 | `OPCR` magic |
/// | 4 | 1 | version |
/// | 5 | 1 | frame kind |
/// | 6 | 1 | security mode |
/// | 7 | 1 | reserved (zero) |
/// | 8 | 1 | hop count |
/// | 9 | 1 | hop limit |
/// | 10 | 1 | receipt code (zero for data) |
/// | 11 | 1 | reserved (zero) |
/// | 12 | 8 | sender protection epoch |
/// | 20 | 8 | sender sequence |
/// | 28 | 8 | observed ownership generation (data only) |
/// | 36 | 32 | authenticated sender SPIFFE-ID digest |
/// | 68 | 2 | canonical ownership-key length (data only) |
/// | 70 | 2 | original packet length (data only) |
/// | 72 | 8 | acknowledged epoch (receipt only) |
/// | 80 | 8 | acknowledged sequence (receipt only) |
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IngressRedirectFrameHeader {
    kind: IngressRedirectFrameKind,
    security_mode: IngressRedirectSecurityMode,
    hop_count: u8,
    hop_limit: u8,
    receipt_code: Option<IngressRedirectReceiptCode>,
    epoch: u64,
    sequence: u64,
    ownership_generation: u64,
    sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
    ownership_key_len: u16,
    packet_len: u16,
    acknowledged_epoch: u64,
    acknowledged_sequence: u64,
}

impl IngressRedirectFrameHeader {
    /// Construct a structurally valid data header.
    #[allow(clippy::too_many_arguments)]
    pub fn data(
        security_mode: IngressRedirectSecurityMode,
        hop_count: u8,
        hop_limit: u8,
        epoch: u64,
        sequence: u64,
        ownership_generation: u64,
        sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
        ownership_key_len: u16,
        packet_len: u16,
    ) -> Result<Self, IngressRedirectHeaderError> {
        let header = Self {
            kind: IngressRedirectFrameKind::Data,
            security_mode,
            hop_count,
            hop_limit,
            receipt_code: None,
            epoch,
            sequence,
            ownership_generation,
            sender_digest,
            ownership_key_len,
            packet_len,
            acknowledged_epoch: 0,
            acknowledged_sequence: 0,
        };
        header.validate()?;
        Ok(header)
    }

    /// Construct a structurally valid authenticated receipt header.
    pub fn receipt(
        security_mode: IngressRedirectSecurityMode,
        epoch: u64,
        sequence: u64,
        sender_digest: [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN],
        acknowledged_epoch: u64,
        acknowledged_sequence: u64,
        receipt_code: IngressRedirectReceiptCode,
    ) -> Result<Self, IngressRedirectHeaderError> {
        let header = Self {
            kind: IngressRedirectFrameKind::Receipt,
            security_mode,
            hop_count: 0,
            hop_limit: 0,
            receipt_code: Some(receipt_code),
            epoch,
            sequence,
            ownership_generation: 0,
            sender_digest,
            ownership_key_len: 0,
            packet_len: 0,
            acknowledged_epoch,
            acknowledged_sequence,
        };
        header.validate()?;
        Ok(header)
    }

    /// Parse and strictly validate a v1 header prefix.
    pub fn decode(encoded: &[u8]) -> Result<Self, IngressRedirectHeaderError> {
        let encoded = encoded
            .get(..INGRESS_REDIRECT_HEADER_LEN)
            .ok_or(IngressRedirectHeaderError::Truncated)?;
        if encoded[0..4] != INGRESS_REDIRECT_MAGIC {
            return Err(IngressRedirectHeaderError::InvalidMagic);
        }
        if encoded[4] != INGRESS_REDIRECT_VERSION {
            return Err(IngressRedirectHeaderError::UnsupportedVersion);
        }
        let kind = match encoded[5] {
            REDIRECT_KIND_DATA => IngressRedirectFrameKind::Data,
            REDIRECT_KIND_RECEIPT => IngressRedirectFrameKind::Receipt,
            _ => return Err(IngressRedirectHeaderError::UnknownKind),
        };
        let security_mode = match encoded[6] {
            REDIRECT_SECURITY_AES_256_GCM => IngressRedirectSecurityMode::Aes256Gcm,
            REDIRECT_SECURITY_HMAC_SHA256 => IngressRedirectSecurityMode::HmacSha256,
            _ => return Err(IngressRedirectHeaderError::UnknownSecurityMode),
        };
        if encoded[7] != 0 || encoded[11] != 0 {
            return Err(IngressRedirectHeaderError::NonZeroReserved);
        }
        let receipt_code = match encoded[10] {
            0 => None,
            1 => Some(IngressRedirectReceiptCode::Delivered),
            2 => Some(IngressRedirectReceiptCode::NotOwner),
            3 => Some(IngressRedirectReceiptCode::StaleOwnershipGeneration),
            4 => Some(IngressRedirectReceiptCode::OwnershipViewStale),
            5 => Some(IngressRedirectReceiptCode::QueueFull),
            6 => Some(IngressRedirectReceiptCode::HopLimitReached),
            7 => Some(IngressRedirectReceiptCode::ClassificationMismatch),
            8 => Some(IngressRedirectReceiptCode::OwnershipMissing),
            9 => Some(IngressRedirectReceiptCode::ReceiverViewBehind),
            10 => Some(IngressRedirectReceiptCode::RoutingDomainNotAuthorized),
            _ => return Err(IngressRedirectHeaderError::InvalidReceipt),
        };
        let mut sender_digest = [0_u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN];
        sender_digest.copy_from_slice(&encoded[36..68]);
        let header = Self {
            kind,
            security_mode,
            hop_count: encoded[8],
            hop_limit: encoded[9],
            receipt_code,
            epoch: u64::from_be_bytes(copy_array::<8>(&encoded[12..20])),
            sequence: u64::from_be_bytes(copy_array::<8>(&encoded[20..28])),
            ownership_generation: u64::from_be_bytes(copy_array::<8>(&encoded[28..36])),
            sender_digest,
            ownership_key_len: u16::from_be_bytes(copy_array::<2>(&encoded[68..70])),
            packet_len: u16::from_be_bytes(copy_array::<2>(&encoded[70..72])),
            acknowledged_epoch: u64::from_be_bytes(copy_array::<8>(&encoded[72..80])),
            acknowledged_sequence: u64::from_be_bytes(copy_array::<8>(&encoded[80..88])),
        };
        header.validate()?;
        Ok(header)
    }

    /// Encode the exact fixed-width v1 representation.
    #[must_use]
    pub fn encode(self) -> [u8; INGRESS_REDIRECT_HEADER_LEN] {
        let mut encoded = [0_u8; INGRESS_REDIRECT_HEADER_LEN];
        encoded[0..4].copy_from_slice(&INGRESS_REDIRECT_MAGIC);
        encoded[4] = INGRESS_REDIRECT_VERSION;
        encoded[5] = self.kind as u8;
        encoded[6] = self.security_mode as u8;
        encoded[8] = self.hop_count;
        encoded[9] = self.hop_limit;
        encoded[10] = self.receipt_code.map_or(0, |code| code as u8);
        encoded[12..20].copy_from_slice(&self.epoch.to_be_bytes());
        encoded[20..28].copy_from_slice(&self.sequence.to_be_bytes());
        encoded[28..36].copy_from_slice(&self.ownership_generation.to_be_bytes());
        encoded[36..68].copy_from_slice(&self.sender_digest);
        encoded[68..70].copy_from_slice(&self.ownership_key_len.to_be_bytes());
        encoded[70..72].copy_from_slice(&self.packet_len.to_be_bytes());
        encoded[72..80].copy_from_slice(&self.acknowledged_epoch.to_be_bytes());
        encoded[80..88].copy_from_slice(&self.acknowledged_sequence.to_be_bytes());
        encoded
    }

    /// Frame kind.
    #[must_use]
    pub const fn kind(self) -> IngressRedirectFrameKind {
        self.kind
    }

    /// Negotiated protection mode.
    #[must_use]
    pub const fn security_mode(self) -> IngressRedirectSecurityMode {
        self.security_mode
    }

    /// Redirect count stamped by the sender.
    #[must_use]
    pub const fn hop_count(self) -> u8 {
        self.hop_count
    }

    /// Maximum redirect count admitted by the sender's profile.
    #[must_use]
    pub const fn hop_limit(self) -> u8 {
        self.hop_limit
    }

    /// Typed receipt result, present only on receipt frames.
    #[must_use]
    pub const fn receipt_code(self) -> Option<IngressRedirectReceiptCode> {
        self.receipt_code
    }

    /// Protection epoch selected by the sender.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Monotonic sequence within the sender's epoch and direction.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Fenced ownership generation observed by the data sender.
    #[must_use]
    pub const fn ownership_generation(self) -> u64 {
        self.ownership_generation
    }

    /// Digest of the sender's authenticated SPIFFE ID.
    #[must_use]
    pub const fn sender_digest(self) -> [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN] {
        self.sender_digest
    }

    /// Canonical ownership-key byte length.
    #[must_use]
    pub const fn ownership_key_len(self) -> u16 {
        self.ownership_key_len
    }

    /// Original IP packet byte length.
    #[must_use]
    pub const fn packet_len(self) -> u16 {
        self.packet_len
    }

    /// Epoch acknowledged by a receipt.
    #[must_use]
    pub const fn acknowledged_epoch(self) -> u64 {
        self.acknowledged_epoch
    }

    /// Sequence acknowledged by a receipt.
    #[must_use]
    pub const fn acknowledged_sequence(self) -> u64 {
        self.acknowledged_sequence
    }

    fn validate(self) -> Result<(), IngressRedirectHeaderError> {
        if self.epoch == 0 || self.sequence == 0 {
            return Err(IngressRedirectHeaderError::InvalidSequence);
        }
        match self.kind {
            IngressRedirectFrameKind::Data => {
                if self.hop_count == 0 || self.hop_limit == 0 || self.hop_count > self.hop_limit {
                    return Err(IngressRedirectHeaderError::InvalidHop);
                }
                if self.receipt_code.is_some()
                    || self.ownership_generation == 0
                    || self.acknowledged_epoch != 0
                    || self.acknowledged_sequence != 0
                {
                    return Err(IngressRedirectHeaderError::InvalidReceipt);
                }
                if self.ownership_key_len == 0
                    || usize::from(self.ownership_key_len) > INGRESS_REDIRECT_OWNERSHIP_KEY_MAX_LEN
                    || self.packet_len == 0
                {
                    return Err(IngressRedirectHeaderError::InvalidLengths);
                }
            }
            IngressRedirectFrameKind::Receipt => {
                if self.hop_count != 0 || self.hop_limit != 0 {
                    return Err(IngressRedirectHeaderError::InvalidHop);
                }
                if self.receipt_code.is_none()
                    || self.ownership_generation != 0
                    || self.acknowledged_epoch == 0
                    || self.acknowledged_sequence == 0
                {
                    return Err(IngressRedirectHeaderError::InvalidReceipt);
                }
                if self.ownership_key_len != 0 || self.packet_len != 0 {
                    return Err(IngressRedirectHeaderError::InvalidLengths);
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for IngressRedirectFrameHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectFrameHeader")
            .field("kind", &self.kind)
            .field("security_mode", &self.security_mode)
            .field("hop_count", &self.hop_count)
            .field("hop_limit", &self.hop_limit)
            .field("receipt_code", &self.receipt_code)
            .field("epoch", &self.epoch)
            .field("sequence", &self.sequence)
            .field("ownership_generation", &self.ownership_generation)
            .field("sender_digest", &"[redacted]")
            .field("ownership_key_len", &self.ownership_key_len)
            .field("packet_len", &self.packet_len)
            .field("acknowledged_epoch", &self.acknowledged_epoch)
            .field("acknowledged_sequence", &self.acknowledged_sequence)
            .finish()
    }
}

fn copy_array<const N: usize>(value: &[u8]) -> [u8; N] {
    let mut output = [0_u8; N];
    output.copy_from_slice(value);
    output
}

/// Ethernet header length at XDP ingress.
pub const ETH_HDR_LEN: usize = 14;
/// EtherType for IPv4.
pub const ETH_P_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
pub const ETH_P_IPV6: u16 = 0x86DD;
/// Minimum option-free IPv4 header length.
pub const IPV4_MIN_HDR_LEN: usize = 20;
/// UDP header length.
pub const UDP_HDR_LEN: usize = 8;
/// IKEv2 fixed header length.
pub const IKEV2_HDR_LEN: usize = 28;
/// ESP-in-UDP header prefix length: SPI + sequence number.
pub const ESP_HEADER_PREFIX_LEN: usize = 8;
/// UDP port for IKE.
pub const UDP_PORT_IKE: u16 = 500;
/// UDP port for IKE/ESP NAT traversal.
pub const UDP_PORT_IKE_NATT: u16 = 4500;
/// RFC 3948 non-ESP marker preceding IKE on UDP/4500.
pub const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
/// RFC 3948 NAT-T keepalive byte.
pub const NAT_T_KEEPALIVE: u8 = 0xff;
/// IKEv2 major version.
pub const IKEV2_MAJOR_VERSION: u8 = 2;
/// IKE_SA_INIT exchange type.
pub const IKEV2_EXCHANGE_IKE_SA_INIT: u8 = 34;

/// FNV-1a offset basis for the stateless IKE_SA_INIT bootstrap tag.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime for the stateless IKE_SA_INIT bootstrap tag.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Compute the stateless bootstrap routing tag for an initial IKE_SA_INIT.
///
/// An initial IKE_SA_INIT has a zero responder SPI, so there is no allocated
/// tagged SPI to route on yet. This is the single source of truth shared by the
/// XDP datapath and the userspace classifier so both steer such a packet to the
/// same shard: FNV-1a over the big-endian initiator SPI followed by the source-IP
/// octets (4 for IPv4, 16 for IPv6), masked to `tag_bits` high-order tag slots.
/// Returns `None` for an out-of-range tag width.
#[must_use]
pub fn bootstrap_tag(initiator_spi: u64, source_ip_octets: &[u8], tag_bits: u8) -> Option<u16> {
    if tag_bits == 0 || tag_bits > 16 {
        return None;
    }
    let mut hash = FNV_OFFSET_BASIS;
    for byte in initiator_spi.to_be_bytes() {
        hash = fnv1a(hash, byte);
    }
    for &byte in source_ip_octets {
        hash = fnv1a(hash, byte);
    }
    Some((hash & ((1_u64 << tag_bits) - 1)) as u16)
}

const fn fnv1a(hash: u64, byte: u8) -> u64 {
    (hash ^ (byte as u64)).wrapping_mul(FNV_PRIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender_digest() -> [u8; INGRESS_REDIRECT_SENDER_DIGEST_LEN] {
        [0xa5; INGRESS_REDIRECT_SENDER_DIGEST_LEN]
    }

    #[test]
    fn redirect_data_header_has_stable_exact_encoding() {
        let header = IngressRedirectFrameHeader::data(
            IngressRedirectSecurityMode::Aes256Gcm,
            1,
            4,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            sender_digest(),
            59,
            1_337,
        )
        .expect("valid header");
        let encoded = header.encode();

        assert_eq!(&encoded[0..12], b"OPCR\x01\x01\x01\x00\x01\x04\x00\x00");
        assert_eq!(&encoded[12..20], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&encoded[20..28], &0x1112_1314_1516_1718_u64.to_be_bytes());
        assert_eq!(&encoded[28..36], &0x2122_2324_2526_2728_u64.to_be_bytes());
        assert_eq!(&encoded[36..68], &sender_digest());
        assert_eq!(&encoded[68..70], &59_u16.to_be_bytes());
        assert_eq!(&encoded[70..72], &1_337_u16.to_be_bytes());
        assert_eq!(&encoded[72..88], &[0; 16]);
        assert_eq!(IngressRedirectFrameHeader::decode(&encoded), Ok(header));
    }

    #[test]
    fn redirect_receipt_header_round_trips() {
        let header = IngressRedirectFrameHeader::receipt(
            IngressRedirectSecurityMode::HmacSha256,
            9,
            12,
            sender_digest(),
            7,
            11,
            IngressRedirectReceiptCode::NotOwner,
        )
        .expect("valid receipt");
        let encoded = header.encode();

        assert_eq!(header.kind(), IngressRedirectFrameKind::Receipt);
        assert_eq!(
            header.receipt_code(),
            Some(IngressRedirectReceiptCode::NotOwner)
        );
        assert_eq!(IngressRedirectFrameHeader::decode(&encoded), Ok(header));
    }

    #[test]
    fn redirect_header_rejects_every_reserved_or_cross_kind_field() {
        let data = IngressRedirectFrameHeader::data(
            IngressRedirectSecurityMode::Aes256Gcm,
            1,
            2,
            1,
            1,
            1,
            sender_digest(),
            1,
            1,
        )
        .expect("valid data")
        .encode();

        for offset in [7_usize, 11] {
            let mut malformed = data;
            malformed[offset] = 1;
            assert_eq!(
                IngressRedirectFrameHeader::decode(&malformed),
                Err(IngressRedirectHeaderError::NonZeroReserved)
            );
        }

        let mut receipt_on_data = data;
        receipt_on_data[10] = IngressRedirectReceiptCode::Delivered as u8;
        assert_eq!(
            IngressRedirectFrameHeader::decode(&receipt_on_data),
            Err(IngressRedirectHeaderError::InvalidReceipt)
        );

        let mut acknowledged_data = data;
        acknowledged_data[87] = 1;
        assert_eq!(
            IngressRedirectFrameHeader::decode(&acknowledged_data),
            Err(IngressRedirectHeaderError::InvalidReceipt)
        );

        let mut unknown_kind = data;
        unknown_kind[5] = 0xff;
        assert_eq!(
            IngressRedirectFrameHeader::decode(&unknown_kind),
            Err(IngressRedirectHeaderError::UnknownKind)
        );

        let mut unknown_mode = data;
        unknown_mode[6] = 0xff;
        assert_eq!(
            IngressRedirectFrameHeader::decode(&unknown_mode),
            Err(IngressRedirectHeaderError::UnknownSecurityMode)
        );
    }

    #[test]
    fn redirect_header_bounds_lengths_and_sequence_identity() {
        assert_eq!(
            IngressRedirectFrameHeader::data(
                IngressRedirectSecurityMode::Aes256Gcm,
                1,
                1,
                0,
                1,
                1,
                sender_digest(),
                1,
                1,
            ),
            Err(IngressRedirectHeaderError::InvalidSequence)
        );
        assert_eq!(
            IngressRedirectFrameHeader::data(
                IngressRedirectSecurityMode::Aes256Gcm,
                0,
                1,
                1,
                1,
                1,
                sender_digest(),
                1,
                1,
            ),
            Err(IngressRedirectHeaderError::InvalidHop)
        );
        assert_eq!(
            IngressRedirectFrameHeader::data(
                IngressRedirectSecurityMode::Aes256Gcm,
                2,
                1,
                1,
                1,
                1,
                sender_digest(),
                1,
                1,
            ),
            Err(IngressRedirectHeaderError::InvalidHop)
        );
        assert!(IngressRedirectFrameHeader::data(
            IngressRedirectSecurityMode::Aes256Gcm,
            1,
            1,
            1,
            1,
            1,
            sender_digest(),
            1,
            1,
        )
        .is_ok());
        assert_eq!(
            IngressRedirectFrameHeader::data(
                IngressRedirectSecurityMode::Aes256Gcm,
                1,
                1,
                1,
                1,
                1,
                sender_digest(),
                (INGRESS_REDIRECT_OWNERSHIP_KEY_MAX_LEN + 1) as u16,
                1,
            ),
            Err(IngressRedirectHeaderError::InvalidLengths)
        );
        assert_eq!(
            IngressRedirectFrameHeader::decode(&[0_u8; INGRESS_REDIRECT_HEADER_LEN - 1]),
            Err(IngressRedirectHeaderError::Truncated)
        );
    }

    #[test]
    fn bootstrap_tag_is_deterministic_masked_and_width_checked() {
        let a = bootstrap_tag(0x0102_0304_0506_0708, &[198, 51, 100, 7], 8);
        assert_eq!(
            a,
            bootstrap_tag(0x0102_0304_0506_0708, &[198, 51, 100, 7], 8)
        );
        assert!(a.unwrap() < 256);
        assert!(bootstrap_tag(0xdead_beef, &[203, 0, 113, 9], 4).unwrap() < 16);
        // IPv6 octets (16 bytes) are accepted too.
        assert!(bootstrap_tag(7, &[0x20; 16], 10).unwrap() < 1024);
        assert_eq!(bootstrap_tag(1, &[], 0), None);
        assert_eq!(bootstrap_tag(1, &[], 17), None);
    }
}
