//! Closed retained NETCONF target profiles. Selecting a profile is not admission.

use serde::{Deserialize, Serialize};

/// Independently selected configuration target and capacity contract.
///
/// The profile is admitted by the caller's storage authority, never inferred
/// from stored data. Selection alone does not enable an unsupported profile.
/// All variants use the existing configuration authority and native WAL.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetainedConfigProfile {
    /// Original running authority with its existing capacity and byte formats.
    Legacy,
    /// RFC 019 retained NETCONF targets with the landed legacy capacity bounds.
    /// Command/wire revision 9 and storage/snapshot revision 7 are required;
    /// this does not opt in to the separately reserved capacity profile.
    NetconfTargetsV1,
}

impl std::fmt::Debug for RetainedConfigProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedConfigProfile(<redacted>)")
    }
}
