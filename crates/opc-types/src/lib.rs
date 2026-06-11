//! Shared OpenPacketCore SDK types for identifiers, versions, timestamps, and
//! redaction-safe debug helpers.
//!
//! Network-sensitive values should be wrapped in [`Redacted`] (or formatted
//! through [`redact`]) before being emitted to logs, traces, or panic output.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod identity;
mod nf;
mod redaction;
mod validation;
mod versioning;

pub use crate::error::ParseError;
pub use crate::identity::{InstanceId, PlmnId, RegionId, Snssai, SpiffeId, TenantId};
pub use crate::nf::{NetworkFunctionKind, NfInstanceId, NfKind, NfType};
pub use crate::redaction::{redact, IntoRedacted, Redacted, RedactedDebug};
pub use crate::versioning::{ConfigVersion, SchemaDigest, Timestamp, TxId};
