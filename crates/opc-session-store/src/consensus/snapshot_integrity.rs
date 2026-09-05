//! Snapshot integrity is independent of the consensus membership authority.

/// The explicitly selected local protection for fixed-quorum snapshots.
///
/// Both policies authenticate snapshot contents, retain fixed membership and
/// fencing, and reject corrupt input. They differ in how a verified image is
/// kept stable for subsequent consumption. This is not a topology policy and
/// does not select a different consensus engine or wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotIntegrityPolicy {
    /// Verify every consumed block against an SDK-owned bounded digest index.
    ///
    /// This works on supported ordinary Linux filesystems without fs-verity.
    /// It includes SQLite reads and does not rely on chmod or advisory locks.
    PortableVerified,
    /// Require the kernel's fixed fs-verity profile and reject unsupported
    /// snapshot storage during admission. There is no portable fallback.
    FsVerity,
}

impl SnapshotIntegrityPolicy {
    // Old authenticated recovery plans omit the policy. Preserve their exact
    // canonical serialization and strict meaning; never default to portable.
    pub(crate) const fn legacy() -> Self {
        Self::FsVerity
    }

    pub(crate) fn is_legacy(&self) -> bool {
        *self == Self::FsVerity
    }
}
