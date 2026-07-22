//! Mutually authenticated Diameter-over-TLS/TCP transport.
//!
//! This crate deliberately does not provide DTLS/SCTP. A connection is exposed
//! only after `opc-tls` has authenticated both peers, the configured exact
//! SPIFFE identity has matched, coherent credential material has been admitted,
//! and the exact `opc-proto-diameter` peer-protection attempt has been attested.
//! Direct-mode connector/acceptor methods own their respective canonical
//! CER/CEA roles; generic sequential send/receive methods admit only
//! post-negotiation application messages. The connection exposes owned
//! retirement-aware readiness projections, but it does not yet expose a
//! concurrent read/write split, watchdog/disconnect facade, or actor for a
//! full-duplex Diameter runtime.

#![forbid(unsafe_code)]

mod frame;
mod inband;
mod tls;

pub use frame::{DiameterFrameLimits, DiameterFrameLimitsError};
pub use inband::{
    DiameterInbandTlsInitiator, DiameterInbandTlsInitiatorAwaitingAnswer,
    DiameterInbandTlsResponder, DiameterInbandTlsResponderCerReceived,
};
pub use tls::{
    DiameterCapabilitiesExchangeAnswer, DiameterCapabilitiesExchangeOutcome,
    DiameterConnectionRole, DiameterTlsAcceptor, DiameterTlsCipher, DiameterTlsConnection,
    DiameterTlsConnector, DiameterTlsError, DiameterTlsEvidence, DiameterTlsPolicy,
    DiameterTlsPolicyError, DiameterTlsVersion, ExpectedPeerIdentity, ExpectedPeerIdentityError,
};
