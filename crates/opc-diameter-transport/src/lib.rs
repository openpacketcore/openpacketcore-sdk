//! Mutually authenticated Diameter-over-TLS/TCP transport.
//!
//! This crate deliberately does not provide DTLS/SCTP. A connection is exposed
//! only after `opc-tls` has authenticated both peers, the configured exact
//! SPIFFE identity has matched, coherent credential material has been admitted,
//! and the exact `opc-proto-diameter` peer-protection attempt has been attested.
//! Direct-mode connector/acceptor methods own their respective canonical
//! CER/CEA roles. A negotiated connection can then be consumed into a bounded
//! full-duplex peer runtime that owns watchdog and disconnect procedures while
//! delivering only admitted application messages.

#![forbid(unsafe_code)]

mod frame;
mod frame_transport;
mod inband;
mod runtime;
mod tls;

mod election;

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
