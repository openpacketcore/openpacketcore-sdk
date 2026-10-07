//! RFC 6311 message-ID synchronization Notify wire primitives.
//!
//! These codecs do not authenticate a peer, negotiate support, admit a sync
//! exchange, generate randomness, update counters, or authorize persistence or
//! transmission. Use them only inside the appropriate protected exchange:
//! support in IKE_AUTH, synchronization in a Message-ID-zero INFORMATIONAL.
//! Both peers must advertise support before synchronization can be used; an
//! IKE responder must not advertise unless the initiator offered it. A caller
//! must implement the complete RFC 6311 section 5.1 exchange before advertising.
//!
//! Sync data is a four-octet nonce followed by two network-order counters,
//! always relative to the **sender of this notification**. A request carries
//! M1/P1; its response echoes the nonce and carries P2/M2. The nonce must be
//! randomly generated for a new request and checked against its response; it
//! is distinct from the encryption IV. This module preserves these values
//! without deciding their freshness or whether a counter may be used.
//!
//! IPsec replay-counter synchronization is intentionally not implemented.
//!
//! @spec IETF RFC6311 5.1, 6.1, 6.3; IETF RFC7296 3.10
//! @conformance boundary-only

use std::{error::Error, fmt};

use crate::{
    ike_auth::Ikev2IkeAuthCleartextPayloads,
    notify::{
        Ikev2NotifyPayload, IKEV2_NOTIFY_MESSAGE_ID_SYNC, IKEV2_NOTIFY_MESSAGE_ID_SYNC_SUPPORTED,
        IKEV2_NOTIFY_PROTOCOL_ID_NONE,
    },
    sa_init::Ikev2NotifyPayloadBuild,
};

/// Structurally valid IKEV2_MESSAGE_ID_SYNC_SUPPORTED notification.
///
/// This marker proves only the Notify shape, not peer authentication or that
/// both parties advertised support. Obtain it through
/// [`decode_ikev2_message_id_sync_supported_notify`] or
/// [`Ikev2IkeAuthCleartextPayloads::message_id_sync_supported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2MessageIdSyncSupported {
    _private: (),
}

/// The fixed data carried by an IKEV2_MESSAGE_ID_SYNC request or response.
///
/// Counters are relative to this notification's sender, independently of its
/// original IKE role. All `u32` values are representable on the wire; successful
/// decoding does not imply valid RFC 6311 counter transitions. `Debug` hides
/// the nonce and counter values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2MessageIdSync {
    nonce: [u8; 4],
    expected_send_req_message_id: u32,
    expected_recv_req_message_id: u32,
}

impl Ikev2MessageIdSync {
    /// Construct wire data without generating a nonce or validating counters.
    ///
    /// The requester supplies a random nonce; the responder echoes it. In a
    /// request, `expected_send_req_message_id` is M1 and
    /// `expected_recv_req_message_id` is P1. In a response they are P2 and M2,
    /// respectively, as defined in RFC 6311 section 5.1.
    #[must_use]
    pub const fn new(
        nonce: [u8; 4],
        expected_send_req_message_id: u32,
        expected_recv_req_message_id: u32,
    ) -> Self {
        Self {
            nonce,
            expected_send_req_message_id,
            expected_recv_req_message_id,
        }
    }

    /// Return the four-octet request nonce or response echo.
    #[must_use]
    pub const fn nonce(self) -> [u8; 4] {
        self.nonce
    }

    /// Return this notification sender's proposed next outbound request ID.
    #[must_use]
    pub const fn expected_send_req_message_id(self) -> u32 {
        self.expected_send_req_message_id
    }

    /// Return this notification sender's proposed next inbound request ID.
    #[must_use]
    pub const fn expected_recv_req_message_id(self) -> u32 {
        self.expected_recv_req_message_id
    }
}

impl fmt::Debug for Ikev2MessageIdSync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2MessageIdSync").finish_non_exhaustive()
    }
}

/// Structural errors in message-ID synchronization notifications.
///
/// Variants contain no packet bytes, nonces, counters or peer identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2MessageIdSyncError {
    /// SPI Size was nonzero; these notifications do not carry an SPI.
    SpiSizeNonzero,
    /// SPI bytes were supplied despite a zero SPI Size.
    SpiNonempty,
    /// Data was not empty for support or exactly twelve octets for sync.
    InvalidDataLength,
    /// An IKE_AUTH payload set contained more than one support notification.
    DuplicateSupport,
}

impl Ikev2MessageIdSyncError {
    /// Return a stable, redaction-safe error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpiSizeNonzero => "ike_message_id_sync_spi_size_nonzero",
            Self::SpiNonempty => "ike_message_id_sync_spi_nonempty",
            Self::InvalidDataLength => "ike_message_id_sync_invalid_data_length",
            Self::DuplicateSupport => "ike_message_id_sync_duplicate_support",
        }
    }
}

impl fmt::Display for Ikev2MessageIdSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2MessageIdSyncError {}

fn validate_empty_spi(notify: Ikev2NotifyPayload<'_>) -> Result<(), Ikev2MessageIdSyncError> {
    if notify.spi_size != 0 {
        return Err(Ikev2MessageIdSyncError::SpiSizeNonzero);
    }
    if !notify.spi.is_empty() {
        return Err(Ikev2MessageIdSyncError::SpiNonempty);
    }
    // RFC 7296 section 3.10: ignore Protocol ID when the SPI is empty.
    // Builders still emit the canonical zero required by RFC 6311.
    Ok(())
}

/// Classify and decode a message-ID sync support Notify body.
///
/// Unrelated types return `Ok(None)`. Type 16420 requires no SPI or data;
/// Protocol ID is ignored on receipt under RFC 7296 section 3.10. This does
/// not validate the enclosing exchange or authenticate the advertisement.
///
/// # Errors
///
/// Returns [`Ikev2MessageIdSyncError`] for malformed type-16420 bodies.
pub fn decode_ikev2_message_id_sync_supported_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2MessageIdSyncSupported>, Ikev2MessageIdSyncError> {
    if notify.notify_message_type != IKEV2_NOTIFY_MESSAGE_ID_SYNC_SUPPORTED {
        return Ok(None);
    }
    validate_empty_spi(notify)?;
    if !notify.notification_data.is_empty() {
        return Err(Ikev2MessageIdSyncError::InvalidDataLength);
    }
    Ok(Some(Ikev2MessageIdSyncSupported { _private: () }))
}

/// Classify and decode a message-ID sync request or response Notify body.
///
/// Unrelated types return `Ok(None)`. Type 16422 requires an empty SPI and
/// exactly twelve data octets. Protocol ID is ignored on receipt. The caller
/// must authenticate and admit the enclosing Message-ID-zero INFORMATIONAL,
/// check its payload set and negotiated capability, and apply RFC 6311's
/// nonce and counter rules separately. Parsing alone authorizes no effect.
///
/// # Errors
///
/// Returns [`Ikev2MessageIdSyncError`] for malformed type-16422 bodies.
pub fn decode_ikev2_message_id_sync_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2MessageIdSync>, Ikev2MessageIdSyncError> {
    if notify.notify_message_type != IKEV2_NOTIFY_MESSAGE_ID_SYNC {
        return Ok(None);
    }
    validate_empty_spi(notify)?;
    let data: &[u8; 12] = notify
        .notification_data
        .try_into()
        .map_err(|_| Ikev2MessageIdSyncError::InvalidDataLength)?;
    Ok(Some(Ikev2MessageIdSync::new(
        [data[0], data[1], data[2], data[3]],
        u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
    )))
}

impl Ikev2NotifyPayloadBuild {
    /// Construct the canonical RFC 6311 support Notify for IKE_AUTH.
    ///
    /// Pass the result to [`crate::build_ike_auth_notify_payload`] to encode
    /// the four-octet body. This is not enabled automatically. Advertise only
    /// with a complete sync implementation; an IKE responder may advertise
    /// only if the initiator offered support. Both peers' advertisements
    /// must be authenticated before synchronization is used.
    #[must_use]
    pub fn message_id_sync_supported() -> Self {
        Self {
            protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            spi: Vec::new(),
            notify_message_type: IKEV2_NOTIFY_MESSAGE_ID_SYNC_SUPPORTED,
            notification_data: Vec::new(),
        }
    }

    /// Construct a canonical RFC 6311 sync Notify with caller-supplied data.
    ///
    /// The result encodes as a sixteen-octet Notify body. Protect it inside a
    /// Message-ID-zero INFORMATIONAL exchange after negotiation and counter
    /// validation; this builder does not create a complete exchange.
    #[must_use]
    pub fn message_id_sync(value: Ikev2MessageIdSync) -> Self {
        let mut notification_data = Vec::with_capacity(12);
        notification_data.extend_from_slice(&value.nonce);
        notification_data.extend_from_slice(&value.expected_send_req_message_id.to_be_bytes());
        notification_data.extend_from_slice(&value.expected_recv_req_message_id.to_be_bytes());
        Self {
            protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            spi: Vec::new(),
            notify_message_type: IKEV2_NOTIFY_MESSAGE_ID_SYNC,
            notification_data,
        }
    }
}

impl Ikev2IkeAuthCleartextPayloads<'_> {
    /// Extract at most one structurally valid RFC 6311 support advertisement.
    ///
    /// Absence is `Ok(None)`. This validates the Notify shape only: the
    /// caller must authenticate IKE_AUTH and record both peers' offers before
    /// selecting synchronization. An absent peer offer requires ordinary
    /// base-IKE behavior. Other notifications remain in [`Self::notifies`].
    /// A malformed or duplicate offer is not a valid offer: do not select
    /// synchronization and, as responder, do not advertise it. The error is
    /// diagnostic and is not by itself a reason to fail IKE_AUTH.
    ///
    /// # Errors
    ///
    /// Any duplicate type-16420 occurrences fail closed with
    /// [`Ikev2MessageIdSyncError::DuplicateSupport`], irrespective of their
    /// validity or order. A single malformed occurrence returns its
    /// structural error, never absence.
    pub fn message_id_sync_supported(
        &self,
    ) -> Result<Option<Ikev2MessageIdSyncSupported>, Ikev2MessageIdSyncError> {
        let mut offers = self
            .notifies
            .iter()
            .filter(|notify| notify.notify_message_type == IKEV2_NOTIFY_MESSAGE_ID_SYNC_SUPPORTED);
        let first = offers.next();
        if offers.next().is_some() {
            return Err(Ikev2MessageIdSyncError::DuplicateSupport);
        }
        match first {
            Some(notify) => decode_ikev2_message_id_sync_supported_notify(*notify),
            None => Ok(None),
        }
    }
}
