//! Preflight capability reporting for the SQLite backend.
//!
//! Before accepting writes, the backend verifies storage safety properties
//! and reports them via [`PersistCapabilities`]. If preflight fails, the backend
//! fails closed — it will not accept writes unless `ephemeral_mode` is set.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Capabilities and safety status reported by the SQLite backend preflight.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistCapabilities {
    /// The backend is ephemeral (e.g. in-memory or tmpfs); durability is not
    /// guaranteed and preflight may skip some checks.
    pub ephemeral_mode: bool,
    /// The storage path passed safety checks.
    pub storage_path: String,
    /// True if fsync is available and not disabled.
    pub fsync_available: bool,
    /// True if the filesystem supports POSIX byte-range locking.
    pub locking_compatible: bool,
    /// True if WAL, SHM, and database files are on the same filesystem.
    pub same_filesystem: bool,
    /// True if the volume is not a known-unsafe network filesystem.
    pub safe_filesystem: bool,
    /// Free bytes available on the volume.
    pub free_bytes: u64,
    /// Minimum free bytes required (configured threshold).
    pub min_free_bytes: u64,
    /// True if the database directory is writable only by the service account.
    pub directory_permissions_safe: bool,
    /// WAL autocheckpoint size in pages (0 = disabled).
    pub wal_autocheckpoint_pages: u32,
    /// SQLite journal mode in use.
    pub journal_mode: String,
    /// SQLite synchronous setting.
    pub synchronous_setting: String,
    /// Whether foreign keys are enforced.
    pub foreign_keys_on: bool,
    /// Whether WAL mode is active.
    pub wal_mode: bool,
}

impl PersistCapabilities {
    /// Returns true if the storage is safe for durable configuration commits.
    ///
    /// In production profiles this requires all safety checks to pass.
    /// In ephemeral mode, only free space and basic path checks are required.
    pub fn is_safe_for_writes(&self) -> bool {
        if self.ephemeral_mode {
            // Ephemeral mode: only require free space
            return self.free_bytes >= self.min_free_bytes;
        }
        // Production: all checks must pass
        self.fsync_available
            && self.locking_compatible
            && self.same_filesystem
            && self.safe_filesystem
            && self.directory_permissions_safe
            && self.free_bytes >= self.min_free_bytes
    }
}

impl fmt::Display for PersistCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PersistCapabilities {{")?;
        writeln!(f, "  ephemeral_mode: {}", self.ephemeral_mode)?;
        writeln!(f, "  storage_path: {}", self.storage_path)?;
        writeln!(f, "  fsync_available: {}", self.fsync_available)?;
        writeln!(f, "  locking_compatible: {}", self.locking_compatible)?;
        writeln!(f, "  same_filesystem: {}", self.same_filesystem)?;
        writeln!(f, "  safe_filesystem: {}", self.safe_filesystem)?;
        writeln!(f, "  free_bytes: {}", self.free_bytes)?;
        writeln!(f, "  min_free_bytes: {}", self.min_free_bytes)?;
        writeln!(
            f,
            "  directory_permissions_safe: {}",
            self.directory_permissions_safe
        )?;
        writeln!(
            f,
            "  wal_autocheckpoint_pages: {}",
            self.wal_autocheckpoint_pages
        )?;
        writeln!(f, "  journal_mode: {}", self.journal_mode)?;
        writeln!(f, "  synchronous_setting: {}", self.synchronous_setting)?;
        writeln!(f, "  foreign_keys_on: {}", self.foreign_keys_on)?;
        writeln!(f, "  wal_mode: {}", self.wal_mode)?;
        write!(f, "}}")
    }
}
