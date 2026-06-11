//! Redaction levels, keyed digests, and safe rendering for OpenPacketCore
//! sensitive data.
//!
//! Raw subscriber identifiers (SUPI, GPSI, MSISDN, PEI) MUST never appear in
//! `Debug` or `Display` output when passed through this crate's helpers.

#![forbid(unsafe_code)]

mod digest;
mod level;
pub mod metrics;
pub mod support_bundle;

pub use digest::{compute_digest, DigestError, DigestKey};
pub use level::{redact, LengthBucket, RedactedValue, RedactionLevel};
pub use metrics::metrics_label_safe;
pub use support_bundle::{
    redact_support_bundle, redact_text, BundleMode, DiagnosticEntry, RedactedEntry,
    RedactedSupportBundle, RedactionError, RedactionSummary,
};
