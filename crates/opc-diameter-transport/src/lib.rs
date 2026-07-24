//! Mutually authenticated Diameter-over-TLS/TCP and DTLS/SCTP transports.
//!
//! A connection is exposed only after both peers have been authenticated, the
//! configured exact SPIFFE identity has matched, coherent credential material
//! has been admitted, and the exact `opc-proto-diameter` peer-protection
//! attempt has been attested. TLS/TCP uses `opc-tls` (rustls); DTLS/SCTP uses
//! the `dimpl` Sans-IO engine over an internal message seam with RFC 6083
//! single-record, ordered stream-0 carriage on PPID 47 (registered by RFC
//! 6733 section 11.5). Direct-mode connector/acceptor methods
//! own their respective canonical CER/CEA roles. A negotiated TLS/TCP or
//! DTLS/SCTP connection can then be consumed into a bounded full-duplex peer
//! runtime that owns watchdog and disconnect procedures while delivering only
//! admitted application messages.

#![forbid(unsafe_code)]

mod frame;
mod frame_transport;
mod inband;
mod runtime;
mod tls;

mod dtls;
mod election;

#[cfg(test)]
mod dtls_tests;

pub use dtls::{
    parse_dtls_record_bounds, DiameterDtlsSctpAcceptor, DiameterDtlsSctpConnection,
    DiameterDtlsSctpConnector, DiameterDtlsSctpEvidence, DiameterDtlsSctpTransport,
    DiameterInbandDtlsSctpInitiator, DiameterInbandDtlsSctpInitiatorAwaitingAnswer,
    DiameterInbandDtlsSctpResponder, DiameterInbandDtlsSctpResponderCerReceived, DtlsRecordBounds,
    DtlsSctpCipher, DtlsSctpPolicy, DtlsSctpVersion, KernelSctpMessageIo, DIAMETER_DTLS_SCTP_PPID,
    DIAMETER_DTLS_SCTP_STREAM, MAX_DTLS_PEER_CERTIFICATES, MAX_DTLS_PEER_CERTIFICATE_BYTES,
    MAX_DTLS_PEER_CERTIFICATE_CHAIN_BYTES, MAX_DTLS_SCTP_MESSAGE_BYTES,
    MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES, MAX_DTLS_SCTP_RECORD_BYTES,
    MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES,
};

#[cfg(test)]
pub(crate) use dtls::{
    in_memory_sctp_link, InMemorySctpEndpoint, SctpMessageIo, SctpWireLog, SctpWireRecord,
};

pub use election::{
    elect_simultaneous_open, DiameterElectionError, DiameterElectionInput, DiameterElectionOutcome,
};

pub use frame::{DiameterFrameLimits, DiameterFrameLimitsError};
pub use inband::{
    DiameterInbandTlsInitiator, DiameterInbandTlsInitiatorAwaitingAnswer,
    DiameterInbandTlsResponder, DiameterInbandTlsResponderCerReceived,
};
pub use runtime::{
    DiameterApplicationMessage, DiameterApplicationReceiver, DiameterPeerActivity,
    DiameterPeerHandle, DiameterPeerRuntime, DiameterPeerRuntimeConfig,
    DiameterPeerRuntimeConfigError, DiameterPeerRuntimeError, DiameterWatchdogTwinit,
    DiameterWatchdogTwinitError,
};
pub use tls::{
    DiameterCapabilitiesExchangeAnswer, DiameterCapabilitiesExchangeOutcome,
    DiameterConnectionRole, DiameterTlsAcceptor, DiameterTlsCipher, DiameterTlsConnection,
    DiameterTlsConnector, DiameterTlsError, DiameterTlsEvidence, DiameterTlsPolicy,
    DiameterTlsPolicyError, DiameterTlsVersion, ExpectedPeerIdentity, ExpectedPeerIdentityError,
};
