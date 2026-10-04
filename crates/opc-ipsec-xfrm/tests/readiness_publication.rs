//! Deterministic filesystem checks for process-harness readiness publication.
#![cfg(target_os = "linux")]

#[path = "support/readiness.rs"]
mod readiness;

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use rand::{rngs::SysRng, TryRng};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let mut suffix = [0_u8; 8];
        SysRng.try_fill_bytes(&mut suffix).unwrap();
        let path = std::env::temp_dir().join(format!(
            "opc-xfrm-readiness-{:016x}",
            u64::from_be_bytes(suffix)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn reader_sees_absence_until_the_complete_record_is_published() {
    let directory = Directory::new();
    let path = directory.0.join("child.ready");
    readiness::publish_with_hook(&path, b"synthetic-ready", || {
        // This is the exact scheduling boundary that exposed the old helper's
        // empty final file. No timing assumption or relaxed reader is needed.
        assert_eq!(fs::read(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
        Ok(())
    })
    .unwrap();
    assert!(fs::read(&path).unwrap() == b"synthetic-ready");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn an_existing_record_is_never_overwritten_or_removed() {
    for existing in [&b""[..], &b"partial"[..], &b"first-synthetic-record"[..]] {
        let directory = Directory::new();
        let path = directory.0.join("child.ready");
        // Independent writer: even malformed evidence is never silently
        // replaced. The recovery harness's strict reader must still refuse it.
        fs::write(&path, existing).unwrap();
        let error = readiness::publish(&path, b"replacement").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(fs::read(&path).unwrap() == existing);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }
}

#[test]
fn a_prepublication_failure_leaves_no_readiness_and_allows_retry() {
    let directory = Directory::new();
    let path = directory.0.join("child.ready");
    let error = readiness::publish_with_hook(&path, b"synthetic-ready", || {
        Err(io::ErrorKind::Interrupted.into())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(fs::read(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    readiness::publish(&path, b"synthetic-ready").unwrap();
    assert!(fs::read(&path).unwrap() == b"synthetic-ready");
}

#[test]
fn a_competing_publisher_cannot_remove_the_first_staging_file() {
    let directory = Directory::new();
    let path = directory.0.join("child.ready");
    readiness::publish_with_hook(&path, b"first-synthetic-record", || {
        let error = readiness::publish(&path, b"competing-record").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        Ok(())
    })
    .unwrap();
    assert!(fs::read(&path).unwrap() == b"first-synthetic-record");
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}
