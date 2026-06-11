//! Data classification taxonomy and identifier types for OpenPacketCore privacy
//! governance.
//!
//! Every sensitive field in generated models and hand-written domain types MUST
//! carry a [`DataClass`]. Raw subscriber identifiers (SUPI, GPSI, MSISDN, PEI)
//! MUST never appear in logs, metrics, traces, or debug output without
//! redaction.

#![forbid(unsafe_code)]

mod class;
mod retention;

pub use class::{DataClass, IdentifierType};
pub use retention::{DisposalAction, PolicyError, RetentionPolicy};
