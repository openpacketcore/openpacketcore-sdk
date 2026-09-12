//! Failure-only workspace observations from the descriptors still owned by
//! the snapshot worker. These are samples, not reservations or proof of which
//! VFS write failed. In particular SQLITE_FULL alone does not prove ENOSPC.

use crate::consensus::snapshot::PinnedSqliteFile;
use std::io;

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Serialize)]
struct Resources {
    device: u64,
    inode: u64,
    links: u64,
    length_bytes: u64,
    allocated_bytes: u128,
    filesystem_bytes: u128,
    free_bytes: u128,
    available_bytes: u128,
    available_inodes: u128,
}

#[cfg(target_os = "linux")]
fn observe(file: &std::fs::File) -> io::Result<Resources> {
    use std::os::linux::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    let filesystem = nix::sys::statvfs::fstatvfs(file)?;
    let fragment = u128::from(filesystem.fragment_size());
    Ok(Resources {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
        links: metadata.st_nlink(),
        length_bytes: metadata.st_size(),
        allocated_bytes: u128::from(metadata.st_blocks()) * 512,
        filesystem_bytes: u128::from(filesystem.blocks()) * fragment,
        free_bytes: u128::from(filesystem.blocks_free()) * fragment,
        available_bytes: u128::from(filesystem.blocks_available()) * fragment,
        available_inodes: u128::from(filesystem.files_available()),
    })
}

/// Observe before the caller drops the cleanup-bearing pins. Never reopen a
/// diagnostic path, allocate a replacement file, or replace the original error
/// if observation fails. Fixed roles and numeric identities disclose no paths,
/// SQL messages, snapshot contents or session values.
pub(super) fn record_failure(
    stage: &'static str,
    error: &io::Error,
    artifacts: &[(&'static str, &PinnedSqliteFile)],
) {
    #[cfg(target_os = "linux")]
    for &(role, pinned) in artifacts {
        let observation = observe(pinned.file());
        let resources = observation.as_ref().ok();
        let observation_error_kind = observation.as_ref().err().map(io::Error::kind);
        let observation_os_error = observation.as_ref().err().and_then(io::Error::raw_os_error);
        tracing::error!(
            stage,
            artifact = role,
            kind = ?error.kind(),
            os_error = error.raw_os_error(),
            sqlite_extended_code = super::sqlite_error_code(error),
            ?resources,
            ?observation_error_kind,
            observation_os_error,
            "session snapshot workspace failure"
        );
        #[cfg(feature = "test-control")]
        eprintln!(
            "session_snapshot_workspace_failure {}",
            serde_json::json!({
                "stage": stage,
                "artifact": role,
                "kind": format!("{:?}", error.kind()),
                "os_error": error.raw_os_error(),
                "sqlite_extended_code": super::sqlite_error_code(error),
                "resources": resources,
                "observation_error_kind": observation_error_kind.map(|kind| format!("{kind:?}")),
                "observation_os_error": observation_os_error,
            }),
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (stage, error, artifacts);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::linux::fs::MetadataExt as _;

    #[test]
    fn snapshot_resources_follow_the_held_inode_after_path_replacement_and_unlink() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private-path-sentinel");
        std::fs::write(&path, [7; 8192]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let original = file.metadata().unwrap();
        let before = observe(&file).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, [9; 16384]).unwrap();
        let after = observe(&file).unwrap();
        assert_eq!(
            (after.device, after.inode),
            (original.st_dev(), original.st_ino())
        );
        assert_eq!(after.length_bytes, 8192);
        assert_eq!(after.allocated_bytes, before.allocated_bytes);
        assert_eq!(after.links, 0);
        assert_ne!(after.inode, std::fs::metadata(&path).unwrap().st_ino());
        assert!(after.available_bytes <= after.free_bytes);
        assert!(after.free_bytes <= after.filesystem_bytes);
        assert!(!serde_json::to_string(&after).unwrap().contains("sentinel"));
    }
}
