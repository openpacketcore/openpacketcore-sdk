//! IKEv2 NAT detection Notify payload semantics.
//!
//! @spec IETF RFC7296 2.23
//! @req REQ-IETF-RFC7296-NATD-001

use std::{
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
};

use sha1::{Digest, Sha1};

use crate::notify::{
    Ikev2NotifyPayload, IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
    IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
};

/// Length in octets of an IKEv2 NAT-D SHA-1 digest.
pub const IKEV2_NAT_DETECTION_HASH_LEN: usize = 20;

/// Compute an RFC 7296 NAT-D SHA-1 digest for one UDP endpoint.
///
/// The input SPIs are encoded in network byte order before the endpoint IP
/// address and UDP port.
#[must_use]
pub fn ikev2_nat_detection_hash(
    initiator_spi: u64,
    responder_spi: u64,
    endpoint: SocketAddr,
) -> [u8; IKEV2_NAT_DETECTION_HASH_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(initiator_spi.to_be_bytes());
    hasher.update(responder_spi.to_be_bytes());
    match endpoint.ip() {
        IpAddr::V4(ip) => hasher.update(ip.octets()),
        IpAddr::V6(ip) => hasher.update(ip.octets()),
    }
    hasher.update(endpoint.port().to_be_bytes());

    let digest = hasher.finalize();
    let mut out = [0_u8; IKEV2_NAT_DETECTION_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Borrowed NAT-D Notify payload set.
///
/// `Debug` reports only counts and presence. It never prints raw NAT-D hashes
/// or Notify notification data.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2NatDetectionPayloads<'a> {
    source_hashes: Vec<&'a [u8]>,
    destination_hash: Option<&'a [u8]>,
}

impl<'a> Ikev2NatDetectionPayloads<'a> {
    /// Return an empty NAT-D payload collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            source_hashes: Vec::new(),
            destination_hash: None,
        }
    }

    /// Collect NAT-D Notify payloads from a decoded Notify iterator.
    ///
    /// Non-NAT-D Notify payloads are ignored. NAT-D Notify payloads must have
    /// empty Protocol ID and SPI fields and a 20-octet SHA-1 digest.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2NatDetectionPayloadError`] when a NAT-D Notify is
    /// structurally invalid or more than one destination NAT-D Notify is
    /// present.
    pub fn from_notifies(
        notifies: impl IntoIterator<Item = Ikev2NotifyPayload<'a>>,
    ) -> Result<Self, Ikev2NatDetectionPayloadError> {
        let mut payloads = Self::new();
        for notify in notifies {
            payloads.push_notify(notify)?;
        }
        Ok(payloads)
    }

    /// Push one Notify payload when it is a NAT-D Notify.
    ///
    /// Returns `Ok(true)` when the Notify was consumed as NAT-D and `Ok(false)`
    /// when it was an unrelated Notify payload.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2NatDetectionPayloadError`] when a NAT-D Notify is
    /// structurally invalid or duplicates the destination NAT-D Notify.
    pub fn push_notify(
        &mut self,
        notify: Ikev2NotifyPayload<'a>,
    ) -> Result<bool, Ikev2NatDetectionPayloadError> {
        let kind = match notify.notify_message_type {
            IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP => Ikev2NatDetectionNotifyKind::SourceIp,
            IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP => Ikev2NatDetectionNotifyKind::DestinationIp,
            _ => return Ok(false),
        };

        if !notify.has_empty_protocol_spi() {
            return Err(Ikev2NatDetectionPayloadError::InvalidNotifyShape {
                notify_message_type: notify.notify_message_type,
            });
        }
        if notify.notification_data.len() != IKEV2_NAT_DETECTION_HASH_LEN {
            return Err(Ikev2NatDetectionPayloadError::InvalidHashLength {
                notify_message_type: notify.notify_message_type,
                len: notify.notification_data.len(),
            });
        }

        match kind {
            Ikev2NatDetectionNotifyKind::SourceIp => {
                self.source_hashes.push(notify.notification_data);
            }
            Ikev2NatDetectionNotifyKind::DestinationIp => {
                if self.destination_hash.is_some() {
                    return Err(Ikev2NatDetectionPayloadError::DuplicateDestinationHash);
                }
                self.destination_hash = Some(notify.notification_data);
            }
        }

        Ok(true)
    }

    /// Return the borrowed NAT-D source hashes.
    #[must_use]
    pub fn source_hashes(&self) -> &[&'a [u8]] {
        &self.source_hashes
    }

    /// Return the borrowed NAT-D destination hash when present.
    #[must_use]
    pub const fn destination_hash(&self) -> Option<&'a [u8]> {
        self.destination_hash
    }

    /// Return the number of source NAT-D Notify payloads.
    #[must_use]
    pub fn source_hash_count(&self) -> usize {
        self.source_hashes.len()
    }

    /// Return true when a destination NAT-D Notify payload is present.
    #[must_use]
    pub const fn has_destination_hash(&self) -> bool {
        self.destination_hash.is_some()
    }

    /// Return true when no NAT-D Notify payloads were collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source_hashes.is_empty() && self.destination_hash.is_none()
    }
}

impl Default for Ikev2NatDetectionPayloads<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Ikev2NatDetectionPayloads<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NatDetectionPayloads")
            .field("source_hash_count", &self.source_hashes.len())
            .field("has_destination_hash", &self.destination_hash.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ikev2NatDetectionNotifyKind {
    SourceIp,
    DestinationIp,
}

/// Error returned while collecting typed NAT-D Notify payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2NatDetectionPayloadError {
    /// A NAT-D Notify used a non-empty Protocol ID or SPI field.
    InvalidNotifyShape {
        /// Notify Message Type that failed shape validation.
        notify_message_type: u16,
    },
    /// A NAT-D Notify did not carry a 20-octet SHA-1 digest.
    InvalidHashLength {
        /// Notify Message Type that failed length validation.
        notify_message_type: u16,
        /// Notification data length observed by the collector.
        len: usize,
    },
    /// More than one `NAT_DETECTION_DESTINATION_IP` Notify was present.
    DuplicateDestinationHash,
}

impl Ikev2NatDetectionPayloadError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidNotifyShape { .. } => "ike_nat_detection_invalid_notify_shape",
            Self::InvalidHashLength { .. } => "ike_nat_detection_invalid_hash_length",
            Self::DuplicateDestinationHash => "ike_nat_detection_duplicate_destination_hash",
        }
    }
}

impl fmt::Display for Ikev2NatDetectionPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2NatDetectionPayloadError {}

/// Observed UDP endpoint used for NAT-D semantic evaluation.
///
/// `Debug` reports only whether a concrete, non-wildcard address is available.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Ikev2NatDetectionObservedEndpoint {
    /// Concrete endpoint observed on the UDP packet.
    SocketAddr(SocketAddr),
    /// Endpoint was not available to the caller.
    Missing,
}

impl Ikev2NatDetectionObservedEndpoint {
    /// Build an observed endpoint from a socket address.
    #[must_use]
    pub const fn socket_addr(endpoint: SocketAddr) -> Self {
        Self::SocketAddr(endpoint)
    }

    /// Return the endpoint availability status.
    #[must_use]
    pub fn status(self) -> Ikev2NatDetectionEndpointStatus {
        match self {
            Self::SocketAddr(endpoint) if endpoint.ip().is_unspecified() => {
                Ikev2NatDetectionEndpointStatus::UnspecifiedAddress
            }
            Self::SocketAddr(_) => Ikev2NatDetectionEndpointStatus::Concrete,
            Self::Missing => Ikev2NatDetectionEndpointStatus::Missing,
        }
    }

    fn concrete_socket_addr(self) -> Option<SocketAddr> {
        match self {
            Self::SocketAddr(endpoint) if endpoint.ip().is_unspecified() => None,
            Self::SocketAddr(endpoint) => Some(endpoint),
            Self::Missing => None,
        }
    }
}

impl From<SocketAddr> for Ikev2NatDetectionObservedEndpoint {
    fn from(value: SocketAddr) -> Self {
        Self::socket_addr(value)
    }
}

impl fmt::Debug for Ikev2NatDetectionObservedEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NatDetectionObservedEndpoint")
            .field("status", &self.status())
            .finish()
    }
}

/// Endpoint availability status used by NAT-D evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2NatDetectionEndpointStatus {
    /// A concrete, non-wildcard UDP endpoint is available.
    Concrete,
    /// No endpoint was provided.
    Missing,
    /// The endpoint used an unspecified address such as `0.0.0.0` or `::`.
    UnspecifiedAddress,
}

/// NAT-D semantic outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2NatDetectionOutcome {
    /// Inputs were incomplete or non-concrete, so NAT presence is unknown.
    Unknown,
    /// Both source and destination NAT-D hashes matched observed endpoints.
    NoNat,
    /// Source NAT-D hashes did not match the observed source endpoint.
    SourceNat,
    /// Destination NAT-D hash did not match the observed destination endpoint.
    DestinationNat,
    /// Both source and destination NAT-D checks indicate NAT.
    Both,
}

impl Ikev2NatDetectionOutcome {
    /// Stable machine-readable outcome code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unknown => "ike_nat_detection_unknown",
            Self::NoNat => "ike_nat_detection_no_nat",
            Self::SourceNat => "ike_nat_detection_source_nat",
            Self::DestinationNat => "ike_nat_detection_destination_nat",
            Self::Both => "ike_nat_detection_both_nat",
        }
    }
}

/// Full NAT-D evaluation result.
///
/// `Debug` reports semantic evidence only. It never prints raw NAT-D hashes,
/// Notify data, or UDP endpoint addresses.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2NatDetectionEvaluation {
    outcome: Ikev2NatDetectionOutcome,
    source_hash_count: usize,
    has_destination_hash: bool,
    source_endpoint_status: Ikev2NatDetectionEndpointStatus,
    destination_endpoint_status: Ikev2NatDetectionEndpointStatus,
    source_hash_matched: Option<bool>,
    destination_hash_matched: Option<bool>,
}

impl Ikev2NatDetectionEvaluation {
    fn unknown(
        payloads: &Ikev2NatDetectionPayloads<'_>,
        source_endpoint_status: Ikev2NatDetectionEndpointStatus,
        destination_endpoint_status: Ikev2NatDetectionEndpointStatus,
        source_hash_matched: Option<bool>,
        destination_hash_matched: Option<bool>,
    ) -> Self {
        Self {
            outcome: Ikev2NatDetectionOutcome::Unknown,
            source_hash_count: payloads.source_hashes.len(),
            has_destination_hash: payloads.destination_hash.is_some(),
            source_endpoint_status,
            destination_endpoint_status,
            source_hash_matched,
            destination_hash_matched,
        }
    }

    /// Return the NAT-D semantic outcome.
    #[must_use]
    pub const fn outcome(&self) -> Ikev2NatDetectionOutcome {
        self.outcome
    }

    /// Stable machine-readable outcome code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.outcome.code()
    }

    /// Return the number of source NAT-D hashes evaluated.
    #[must_use]
    pub const fn source_hash_count(&self) -> usize {
        self.source_hash_count
    }

    /// Return true when a destination NAT-D hash was present.
    #[must_use]
    pub const fn has_destination_hash(&self) -> bool {
        self.has_destination_hash
    }

    /// Return the source endpoint availability status.
    #[must_use]
    pub const fn source_endpoint_status(&self) -> Ikev2NatDetectionEndpointStatus {
        self.source_endpoint_status
    }

    /// Return the destination endpoint availability status.
    #[must_use]
    pub const fn destination_endpoint_status(&self) -> Ikev2NatDetectionEndpointStatus {
        self.destination_endpoint_status
    }

    /// Return whether any source NAT-D hash matched, when evaluated.
    #[must_use]
    pub const fn source_hash_matched(&self) -> Option<bool> {
        self.source_hash_matched
    }

    /// Return whether the destination NAT-D hash matched, when evaluated.
    #[must_use]
    pub const fn destination_hash_matched(&self) -> Option<bool> {
        self.destination_hash_matched
    }
}

impl fmt::Debug for Ikev2NatDetectionEvaluation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NatDetectionEvaluation")
            .field("outcome", &self.outcome)
            .field("source_hash_count", &self.source_hash_count)
            .field("has_destination_hash", &self.has_destination_hash)
            .field("source_endpoint_status", &self.source_endpoint_status)
            .field(
                "destination_endpoint_status",
                &self.destination_endpoint_status,
            )
            .field("source_hash_matched", &self.source_hash_matched)
            .field("destination_hash_matched", &self.destination_hash_matched)
            .finish()
    }
}

/// Evaluate NAT-D Notify payloads against observed UDP endpoints.
///
/// Missing NAT-D pair members, missing endpoints, and wildcard endpoints produce
/// [`Ikev2NatDetectionOutcome::Unknown`]. Multiple source hashes are treated as
/// an OR set: any matching source hash means the observed source endpoint was
/// not NATed.
#[must_use]
pub fn evaluate_ikev2_nat_detection(
    payloads: &Ikev2NatDetectionPayloads<'_>,
    initiator_spi: u64,
    responder_spi: u64,
    source_endpoint: Ikev2NatDetectionObservedEndpoint,
    destination_endpoint: Ikev2NatDetectionObservedEndpoint,
) -> Ikev2NatDetectionEvaluation {
    let source_status = source_endpoint.status();
    let destination_status = destination_endpoint.status();

    let Some(source_hashes) =
        (!payloads.source_hashes.is_empty()).then_some(&payloads.source_hashes)
    else {
        return Ikev2NatDetectionEvaluation::unknown(
            payloads,
            source_status,
            destination_status,
            None,
            None,
        );
    };
    let Some(destination_hash) = payloads.destination_hash else {
        return Ikev2NatDetectionEvaluation::unknown(
            payloads,
            source_status,
            destination_status,
            None,
            None,
        );
    };

    let Some(source_endpoint) = source_endpoint.concrete_socket_addr() else {
        return Ikev2NatDetectionEvaluation::unknown(
            payloads,
            source_status,
            destination_status,
            None,
            None,
        );
    };
    let Some(destination_endpoint) = destination_endpoint.concrete_socket_addr() else {
        return Ikev2NatDetectionEvaluation::unknown(
            payloads,
            source_status,
            destination_status,
            None,
            None,
        );
    };

    let source_hash = ikev2_nat_detection_hash(initiator_spi, responder_spi, source_endpoint);
    let destination_hash_expected =
        ikev2_nat_detection_hash(initiator_spi, responder_spi, destination_endpoint);
    let source_hash_matched = source_hashes.contains(&source_hash.as_slice());
    let destination_hash_matched = destination_hash == destination_hash_expected.as_slice();
    let outcome = match (source_hash_matched, destination_hash_matched) {
        (true, true) => Ikev2NatDetectionOutcome::NoNat,
        (false, true) => Ikev2NatDetectionOutcome::SourceNat,
        (true, false) => Ikev2NatDetectionOutcome::DestinationNat,
        (false, false) => Ikev2NatDetectionOutcome::Both,
    };

    Ikev2NatDetectionEvaluation {
        outcome,
        source_hash_count: payloads.source_hashes.len(),
        has_destination_hash: payloads.destination_hash.is_some(),
        source_endpoint_status: source_status,
        destination_endpoint_status: destination_status,
        source_hash_matched: Some(source_hash_matched),
        destination_hash_matched: Some(destination_hash_matched),
    }
}
