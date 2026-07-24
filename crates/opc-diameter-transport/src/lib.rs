//! Mutually authenticated Diameter-over-TLS/TCP and DTLS/SCTP transports.
//!
//! A connection is exposed only after both peers have been authenticated, the
//! configured exact SPIFFE identity has matched, coherent credential material
//! has been admitted, and the exact `opc-proto-diameter` peer-protection
//! attempt has been attested. TLS/TCP uses `opc-tls` (rustls); DTLS/SCTP uses
//! the `dimpl` Sans-IO engine over the [`SctpMessageIo`] message seam with
//! RFC 6083 PPID-47 record carriage. Direct-mode connector/acceptor methods
//! own their respective canonical CER/CEA roles. A negotiated TLS/TCP
//! connection can then be consumed into a bounded full-duplex peer runtime
//! that owns watchdog and disconnect procedures while delivering only
//! admitted application messages.

#![forbid(unsafe_code)]

mod frame;
mod frame_transport;
mod inband;
mod runtime;
mod tls;

mod dtls;
mod election;

pub use dtls::{
    in_memory_sctp_link, DiameterDtlsSctpAcceptor, DiameterDtlsSctpConnection,
    DiameterDtlsSctpConnector, DiameterDtlsSctpEvidence, DtlsSctpCipher, DtlsSctpPolicy,
    DtlsSctpVersion, InMemorySctpEndpoint, SctpMessageIo, SctpTransportClose, SctpUserMessage,
    SctpWireLog, SctpWireRecord, DIAMETER_DTLS_SCTP_PPID, DIAMETER_DTLS_SCTP_STREAM,
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
