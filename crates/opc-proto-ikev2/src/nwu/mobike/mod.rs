//! Authenticated RFC 4555 mobility for an established NWu IKE responder.
//!
//! Structural Notify decoding does not authorize migration. [`Responder`]
//! opens exact datagrams through the admitted concrete IKE crypto provider,
//! checks the established SA, caller address policy and shared replay window,
//! and requires a fresh COOKIE2 exchange before producing Child-SA intent.
//! Peer authentication and negotiated capability originate in the caller's
//! established IKE_AUTH state. Key custody and backend application are separate.

mod authority;
mod responder;
mod wire;

pub use authority::{MigrationAssociation, MigrationPermit};
pub use responder::{
    Migration, NatState, Outbound, ProbeOutcome, ReceivedRequest, RequestStatus, Responder,
};
pub use wire::{Notify, Path, Request};

use std::{error::Error as StdError, fmt};

/// Payload-free mobility rejection. No error contains addresses, SPIs,
/// cryptographic inputs, notification values or provider diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An opened payload violated the bounded NWu framing contract.
    Payload(super::Error),
    /// UDP/500 or UDP/4500 framing was incompatible with this SA.
    Transport,
    /// The exact encrypted datagram did not pass the concrete crypto provider.
    Authentication,
    /// SPI, original role, exchange, response flag or message ID did not match.
    Correlation,
    /// The authenticated request was stale or already admitted.
    Replay,
    /// Shared established-SA message-ID state was absent, busy or inconsistent.
    Window,
    /// A routability response arrived from a different bound path.
    Source,
    /// There is no candidate or challenge appropriate to this operation.
    State,
    /// The admitted crypto module could not generate entropy or a NAT hash.
    Crypto,
    /// This session was closed, dropped or exhausted its migration generation.
    Closed,
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Payload(value)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Payload(_) => "mobike_payload",
            Self::Transport => "mobike_transport",
            Self::Authentication => "mobike_authentication",
            Self::Correlation => "mobike_correlation",
            Self::Replay => "mobike_replay",
            Self::Window => "mobike_window",
            Self::Source => "mobike_source",
            Self::State => "mobike_state",
            Self::Crypto => "mobike_crypto",
            Self::Closed => "mobike_closed",
        })
    }
}
impl StdError for Error {}
