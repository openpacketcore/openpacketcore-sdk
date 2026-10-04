//! Bounded TS 24.502 V18.8.0 NWu payload profiles.
//!
//! These views describe opened IKE payloads; they do not authenticate a peer,
//! install an SA, decide subscriber policy, or select a cryptographic suite.
//! Caller limits and duplicate rejection are explicit local admission policy.
//! Generic IKE and the TS 24.302 dedicated-bearer profile remain separate.

mod configuration;
mod create;
mod lifecycle;
pub mod mobike;
mod notify;
mod policy;
mod qos;

pub use configuration::{
    encode_payloads, AddressFamilies, ConfigurationReply, ConfigurationRequest, NasEndpoint,
};
pub use create::{all_packet_selectors, CreateAccepted, CreateRequest, CreateRequestBuild};
pub use lifecycle::{
    empty_response, encode_modification, ChildDelete, DeleteCollision, DeleteOutcome, Modification,
    ModificationOutcome, Peer, PeerError, PendingChildDelete, PendingIkeDelete,
    PendingModification, RequestIdentity,
};
pub use notify::{Address, EspSpi, Notify};
pub use policy::{AeadPolicy, AeadSelection, AeadSuite};
pub use qos::{AdditionalQos, QosInfo, QosParameter};

use std::{error::Error as StdError, fmt};

/// Redacted profile rejection. No error retains packet or deployment values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Generic payload framing is invalid.
    Framing,
    /// A value has the wrong length or encoding.
    InvalidValue,
    /// The Notify SPI shape does not match its type.
    SpiShape,
    /// A singleton attribute, notification, QFI, or parameter is repeated.
    Duplicate,
    /// A required profile field is absent.
    Missing,
    /// A caller resource limit or a wire length limit is exceeded.
    Limit,
    /// A known field is incompatible with the selected profile.
    Incompatible,
    /// A known, unsupported profile field is present.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Framing => "nwu_framing",
            Self::InvalidValue => "nwu_invalid_value",
            Self::SpiShape => "nwu_spi_shape",
            Self::Duplicate => "nwu_duplicate",
            Self::Missing => "nwu_missing",
            Self::Limit => "nwu_limit",
            Self::Incompatible => "nwu_incompatible",
            Self::Unsupported => "nwu_unsupported",
        })
    }
}
impl StdError for Error {}

/// Inclusive caller bounds for opened payloads and configuration attributes.
/// These are resource policy, not limits imposed by TS 24.502.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum opened chain or individual body size in octets.
    pub bytes: usize,
    /// Maximum payloads or configuration attributes, including ignored fields.
    pub entries: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 65_535,
            entries: 128,
        }
    }
}
impl Limits {
    pub(super) fn check(self, bytes: usize, entries: usize) -> Result<(), Error> {
        if bytes > self.bytes || entries > self.entries {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
}

pub(super) fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::Duplicate);
    }
    *slot = Some(value);
    Ok(())
}
