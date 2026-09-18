//! Strict, explicitly unprotected N2 framing over the existing SCTP transport.
//!
//! The backend-neutral profile checks complete SCTP records before exposing
//! opaque NGAP bytes. The live adapter uses the same checks and the existing
//! socket-owned partial receive accumulator. NGAP procedures, stream allocation,
//! association generations and reconnect policy remain caller-owned.
//!
//! TS 38.412 V18.1.0 clause 7 retains RFC 4960 and big-endian PPIDs. IANA assigns
//! NGAP PPID 60 and service port 38412. Additional associations may use an
//! explicitly selected dynamic port. PPID 66 DATA requires a separate protected
//! adapter; this module establishes no encryption or authenticated peer identity.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use thiserror::Error;

use crate::{
    DeliveryOrder, InboundMessage, OutboundMessage, SctpAssociation, SctpAssociationAbortHandle,
    SctpConnectConfig, SctpError, SctpEvent, SctpPathHealth, NGAP_PPID,
};

/// IANA's `ng-control` SCTP service port; an additional TNLA may use another port.
pub const NGAP_DEFAULT_PORT: u16 = 38412;

/// Construct a destination using the default NGAP service port.
///
/// Address selection and authorization remain the caller's responsibility.
#[must_use]
pub const fn default_destination(address: IpAddr) -> SocketAddr {
    SocketAddr::new(address, NGAP_DEFAULT_PORT)
}

/// A bounded, explicitly unprotected N2 record admission policy.
///
/// The cap is caller-selected policy. Ordered DATA, complete ancillary metadata
/// and a parsed notification boundary are required by this profile. These
/// checks do not decode NGAP or establish association-generation authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnprotectedN2Profile {
    max_message_bytes: usize,
}

impl fmt::Debug for UnprotectedN2Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnprotectedN2Profile { .. }")
    }
}

impl UnprotectedN2Profile {
    /// Select a nonzero maximum DATA record size.
    ///
    /// # Errors
    ///
    /// Returns [`N2Error::InvalidLimit`] for a zero limit.
    pub const fn new(max_message_bytes: usize) -> Result<Self, N2Error> {
        if max_message_bytes == 0 {
            return Err(N2Error::InvalidLimit);
        }
        Ok(Self { max_message_bytes })
    }

    /// Return the caller-selected DATA record bound.
    #[must_use]
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes
    }

    fn check_payload(self, payload: &[u8]) -> Result<(), N2Error> {
        if payload.is_empty() {
            return Err(N2Error::EmptyPayload);
        }
        if payload.len() > self.max_message_bytes {
            return Err(N2Error::MessageTooLarge);
        }
        Ok(())
    }

    /// Frame one opaque NGAP PDU on a caller-selected ordered SCTP stream.
    ///
    /// This does not allocate a stream or validate UE/non-UE stream bindings.
    ///
    /// # Errors
    ///
    /// Returns [`N2Error::EmptyPayload`] or [`N2Error::MessageTooLarge`] when
    /// the DATA record does not fit the profile's bound.
    pub fn outbound_message(
        self,
        payload: Bytes,
        stream_id: u16,
    ) -> Result<N2OutboundMessage, N2Error> {
        self.check_payload(&payload)?;
        Ok(N2OutboundMessage { payload, stream_id })
    }

    /// Admit one complete backend-delivered SCTP item.
    ///
    /// Notification PPIDs have no DATA meaning. Complete notifications are
    /// returned as typed events, never as NGAP bytes. The underlying backend
    /// must establish message boundaries and supply faithful metadata.
    ///
    /// # Errors
    ///
    /// Rejects truncation, inconsistent notification metadata, non-60 DATA
    /// PPIDs, unordered DATA and payloads outside the selected bound.
    pub fn admit(self, message: InboundMessage) -> Result<N2Inbound, N2Error> {
        if message.truncated {
            return Err(N2Error::TruncatedPayload);
        }
        if message.control_truncated {
            return Err(N2Error::TruncatedMetadata);
        }
        if message.notification {
            return message
                .event
                .map(N2Inbound::Notification)
                .ok_or(N2Error::InvalidNotification);
        }
        if message.event.is_some() {
            return Err(N2Error::InvalidNotification);
        }
        self.check_payload(&message.payload)?;
        if message.ppid != NGAP_PPID {
            return Err(N2Error::WrongPpid);
        }
        if message.order != DeliveryOrder::Ordered {
            return Err(N2Error::UnorderedData);
        }
        Ok(N2Inbound::Payload(N2Payload {
            payload: message.payload,
            stream_id: message.stream_id,
            assoc_id: message.assoc_id,
        }))
    }
}

/// One bounded outbound NGAP record with redacted diagnostics.
pub struct N2OutboundMessage {
    payload: Bytes,
    stream_id: u16,
}

impl fmt::Debug for N2OutboundMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N2OutboundMessage { .. }")
    }
}

impl N2OutboundMessage {
    /// Transfer the record to a generic SCTP backend as ordered PPID 60 DATA.
    ///
    /// The generic message contains the original payload. Its subsequent
    /// mutation and diagnostic handling are the backend caller's responsibility.
    #[must_use]
    pub fn into_sctp_message(self) -> OutboundMessage {
        OutboundMessage::ordered(self.payload, self.stream_id, NGAP_PPID)
    }
}

/// One admitted opaque NGAP record and its original SCTP metadata.
///
/// The association identifier is backend metadata, not a generation token.
pub struct N2Payload {
    payload: Bytes,
    stream_id: u16,
    assoc_id: i32,
}

impl fmt::Debug for N2Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N2Payload { .. }")
    }
}

impl N2Payload {
    /// Borrow the admitted opaque NGAP bytes for the caller's codec.
    #[must_use]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Return the SCTP stream that delivered this record.
    #[must_use]
    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Return the backend association identifier without interpreting its lifetime.
    #[must_use]
    pub const fn association_id(&self) -> i32 {
        self.assoc_id
    }

    /// Transfer the admitted payload to the caller.
    #[must_use]
    pub fn into_payload(self) -> Bytes {
        self.payload
    }
}

/// An admitted DATA record or a distinct transport notification.
pub enum N2Inbound {
    /// Opaque NGAP bytes with their original record metadata.
    Payload(N2Payload),
    /// Existing parsed SCTP event, including explicitly unknown event types.
    Notification(SctpEvent),
}

impl fmt::Debug for N2Inbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Payload(_) => "N2Inbound::Payload { .. }",
            Self::Notification(_) => "N2Inbound::Notification { .. }",
        })
    }
}

/// Live unprotected N2 association with mandatory framing checks.
///
/// This consumes the existing SCTP association and retains its receive bound,
/// cancellation ownership and address/readback behavior. Any receive or inbound
/// framing error aborts the association. Dropping it also aborts even if a caller
/// retains an abort handle. No raw send or receive handle is exposed.
///
/// This type does not arbitrate competing associations, assign streams, perform
/// reconnects or attest transport protection.
pub struct UnprotectedN2Association {
    association: SctpAssociation,
    profile: UnprotectedN2Profile,
    receive_gate: tokio::sync::Mutex<()>,
}

impl fmt::Debug for UnprotectedN2Association {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnprotectedN2Association { .. }")
    }
}

impl UnprotectedN2Association {
    /// Connect with the caller's complete ordered SCTP address sets and options.
    ///
    /// A caller may use [`default_destination`] or explicitly select another
    /// permitted destination port. Configured addresses never prove identity.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration, availability or connection error.
    pub async fn connect(config: SctpConnectConfig) -> Result<Self, N2Error> {
        UnprotectedN2Profile::new(config.max_message_bytes)?;
        let association = SctpAssociation::connect(config)
            .await
            .map_err(|error| transport_error(error, N2Error::ConnectFailed))?;
        Self::from_association(association)
    }

    /// Consume an existing connected or accepted SCTP association.
    ///
    /// The profile inherits the actual transport's receive cap. SCTP-AUTH, if
    /// configured externally, does not change this type's unprotected claim.
    ///
    /// # Errors
    ///
    /// Returns [`N2Error::InvalidLimit`] if the transport reports a zero cap.
    pub fn from_association(association: SctpAssociation) -> Result<Self, N2Error> {
        let profile = match UnprotectedN2Profile::new(association.max_message_bytes()) {
            Ok(profile) => profile,
            Err(error) => {
                association.abort_handle().abort();
                return Err(error);
            }
        };
        Ok(Self {
            association,
            profile,
            receive_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Return this association's immutable framing profile.
    #[must_use]
    pub const fn profile(&self) -> UnprotectedN2Profile {
        self.profile
    }

    /// Send one bounded opaque PDU on the caller-selected ordered stream.
    ///
    /// # Errors
    ///
    /// Returns a framing or bounded transport error. Invalid local payloads
    /// fail before sending and do not abort an otherwise live association.
    pub async fn send(&self, payload: Bytes, stream_id: u16) -> Result<usize, N2Error> {
        let message = self.profile.outbound_message(payload, stream_id)?;
        self.association
            .send(message.into_sctp_message())
            .await
            .map_err(|error| transport_error(error, N2Error::SendFailed))
    }

    /// Receive and admit one complete DATA record or transport event.
    ///
    /// Cancelling the future preserves partial DATA in the existing socket
    /// owner. There is no second accumulator or await between receiving a
    /// complete record and checking its metadata. Concurrent callers are
    /// serialized through admission and terminal-close handling as well as I/O.
    ///
    /// # Errors
    ///
    /// Any receive or framing error aborts this association and returns only
    /// a bounded classification. A prior completed delivery cannot be retracted.
    pub async fn recv(&self) -> Result<N2Inbound, N2Error> {
        let _receive_guard = self.receive_gate.lock().await;
        let result = self
            .association
            .recv()
            .await
            .map_err(|error| transport_error(error, N2Error::ReceiveFailed))
            .and_then(|message| self.profile.admit(message));
        if result.is_err() {
            self.abort();
        }
        result
    }

    /// Abort both transport directions immediately and idempotently.
    pub fn abort(&self) {
        self.association.abort_handle().abort();
    }

    /// Obtain terminal-close authority without raw send or receive authority.
    #[must_use]
    pub fn abort_handle(&self) -> SctpAssociationAbortHandle {
        self.association.abort_handle()
    }

    /// Read the existing transport's exact active local address set.
    ///
    /// # Errors
    ///
    /// Returns a bounded readback or availability error.
    pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, N2Error> {
        self.association
            .local_addresses()
            .map_err(|error| transport_error(error, N2Error::ReadbackFailed))
    }

    /// Read the existing transport's exact active peer address set.
    ///
    /// # Errors
    ///
    /// Returns a bounded readback or availability error.
    pub fn peer_addresses(&self) -> Result<Vec<SocketAddr>, N2Error> {
        self.association
            .peer_addresses()
            .map_err(|error| transport_error(error, N2Error::ReadbackFailed))
    }

    /// Read the existing transport's path-health snapshot.
    ///
    /// This is health metadata, not authenticated path or generation authority.
    #[must_use]
    pub fn peer_path_health(&self) -> Vec<SctpPathHealth> {
        self.association.peer_path_health()
    }
}

impl Drop for UnprotectedN2Association {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Bounded N2 errors containing no peer, payload, identifier or OS error values.
#[non_exhaustive]
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum N2Error {
    /// The caller selected a zero DATA cap.
    #[error("n2_invalid_limit")]
    InvalidLimit,
    /// The SCTP configuration is invalid.
    #[error("n2_invalid_configuration")]
    InvalidConfiguration,
    /// SCTP is unsupported on this platform.
    #[error("n2_unsupported_platform")]
    UnsupportedPlatform,
    /// A required SCTP capability is unavailable.
    #[error("n2_transport_unavailable")]
    TransportUnavailable,
    /// Connection setup failed.
    #[error("n2_connect_failed")]
    ConnectFailed,
    /// Sending failed.
    #[error("n2_send_failed")]
    SendFailed,
    /// Receiving failed.
    #[error("n2_receive_failed")]
    ReceiveFailed,
    /// Address readback failed.
    #[error("n2_readback_failed")]
    ReadbackFailed,
    /// A DATA record is empty.
    #[error("n2_empty_payload")]
    EmptyPayload,
    /// A DATA record exceeds the selected cap.
    #[error("n2_message_too_large")]
    MessageTooLarge,
    /// The backend reported payload truncation.
    #[error("n2_truncated_payload")]
    TruncatedPayload,
    /// The backend reported incomplete ancillary metadata.
    #[error("n2_truncated_metadata")]
    TruncatedMetadata,
    /// Notification flag and parsed event do not agree.
    #[error("n2_invalid_notification")]
    InvalidNotification,
    /// DATA does not carry strict NGAP PPID 60, including protected PPID 66.
    #[error("n2_wrong_ppid")]
    WrongPpid,
    /// DATA does not request ordered delivery.
    #[error("n2_unordered_data")]
    UnorderedData,
}

fn transport_error(error: SctpError, fallback: N2Error) -> N2Error {
    match error {
        SctpError::UnsupportedPlatform => N2Error::UnsupportedPlatform,
        SctpError::UnsupportedFeature { .. } | SctpError::CapabilityUnavailable { .. } => {
            N2Error::TransportUnavailable
        }
        SctpError::InvalidConfig { .. } => N2Error::InvalidConfiguration,
        SctpError::MessageTooLarge { .. } => N2Error::MessageTooLarge,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests;
