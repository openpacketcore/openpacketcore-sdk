//! Shared bounded accounting for every native, SQLite and snapshot artifact.

use super::*;

const QUALIFICATION_FILESYSTEM_MAX_DEPTH: usize = 16;
const QUALIFICATION_FILESYSTEM_MAX_ENTRIES: u64 = 32_768;

pub(super) fn bounded_directory_measure(path: &Path) -> (u64, u64) {
    use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};

    fn checked_identity(
        before: rustix::fs::Stat,
        descriptor: &File,
        label: &str,
    ) -> rustix::fs::Stat {
        let after = fstat(descriptor).expect("fstat bounded qualification filesystem descriptor");
        assert!(
            before.st_dev == after.st_dev && before.st_ino == after.st_ino,
            "qualification filesystem {label} changed while descriptor-pinned"
        );
        after
    }

    fn walk(directory: &File, depth: usize, entries: &mut u64) -> (u64, u64) {
        assert!(
            depth <= QUALIFICATION_FILESYSTEM_MAX_DEPTH,
            "qualification filesystem traversal depth is bounded"
        );
        let mut bytes = 0_u64;
        let mut artifacts = 0_u64;
        let directory_entries = Dir::read_from(directory)
            .expect("read descriptor-pinned qualification artifact directory");
        for entry in directory_entries {
            let entry = entry.expect("read qualification artifact directory entry");
            let name = entry.file_name();
            #[cfg(unix)]
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            *entries = entries
                .checked_add(1)
                .expect("qualification filesystem entry count overflow");
            assert!(
                *entries <= QUALIFICATION_FILESYSTEM_MAX_ENTRIES,
                "qualification filesystem traversal cardinality is bounded"
            );
            let metadata = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .expect("read qualification artifact metadata without following links");
            assert!(
                !FileType::from_raw_mode(metadata.st_mode).is_symlink(),
                "qualification filesystem evidence rejects symlink traversal"
            );
            if FileType::from_raw_mode(metadata.st_mode).is_dir() {
                let child = File::from(
                    openat(
                        directory,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .expect("open qualification child directory without following links"),
                );
                checked_identity(metadata, &child, "child directory");
                let (nested_bytes, nested_artifacts) = walk(&child, depth + 1, entries);
                bytes = bytes
                    .checked_add(nested_bytes)
                    .expect("qualification directory byte total overflow");
                artifacts = artifacts
                    .checked_add(nested_artifacts)
                    .expect("qualification directory artifact count overflow");
            } else {
                assert!(
                    FileType::from_raw_mode(metadata.st_mode).is_file(),
                    "qualification filesystem evidence accepts only regular files"
                );
                let file = File::from(
                    openat(
                        directory,
                        name,
                        qualification_nofollow_metadata_flags(),
                        Mode::empty(),
                    )
                    .expect("open qualification regular file without following links"),
                );
                let metadata = checked_identity(metadata, &file, "regular file");
                bytes = bytes
                    .checked_add(
                        u64::try_from(metadata.st_size)
                            .expect("qualification regular file size is nonnegative"),
                    )
                    .expect("qualification directory byte total overflow");
                artifacts = artifacts
                    .checked_add(1)
                    .expect("qualification directory artifact count overflow");
            }
        }
        (bytes, artifacts)
    }

    let root = File::from(
        openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open qualification root directory without following links"),
    );
    assert!(
        FileType::from_raw_mode(
            fstat(&root)
                .expect("fstat qualification root directory")
                .st_mode,
        )
        .is_dir(),
        "qualification directory root is a real descriptor-pinned directory"
    );
    let mut entries = 0;
    walk(&root, 0, &mut entries)
}

pub(super) fn directory_bytes(path: &Path) -> u64 {
    bounded_directory_measure(path).0
}

pub(super) fn qualification_nofollow_metadata_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;

    #[cfg(target_os = "linux")]
    {
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }
}

pub(super) fn native_database_family_measure(path: &Path) -> (u64, u64) {
    let mut candidate = path.as_os_str().to_os_string();
    candidate.push(".native-wal");
    let candidate = std::path::PathBuf::from(candidate);
    match std::fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            assert!(
                metadata.file_type().is_dir(),
                "native qualification artifacts require a real directory"
            );
            bounded_directory_measure(&candidate)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (0, 0),
        Err(error) => panic!("read native qualification artifact directory: {error}"),
    }
}

pub(super) fn sqlite_database_family_bytes(path: &Path) -> u64 {
    use rustix::fs::{fstat, openat, FileType, Mode, CWD};

    let sqlite_bytes = ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            let candidate = std::path::PathBuf::from(candidate);
            match openat(
                CWD,
                &candidate,
                qualification_nofollow_metadata_flags(),
                Mode::empty(),
            ) {
                Ok(descriptor) => {
                    let metadata = fstat(&descriptor).expect("fstat SQLite qualification artifact");
                    assert!(
                        FileType::from_raw_mode(metadata.st_mode).is_file(),
                        "SQLite qualification artifact must be a regular no-follow file"
                    );
                    u64::try_from(metadata.st_size)
                        .expect("SQLite qualification artifact size is nonnegative")
                }
                Err(error)
                    if !suffix.is_empty()
                        && std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
                {
                    0
                }
                Err(error) => panic!(
                    "read required SQLite qualification artifact {}: {error}",
                    candidate.display()
                ),
            }
        })
        .fold(0_u64, |total, bytes| {
            total
                .checked_add(bytes)
                .expect("SQLite qualification artifact byte total overflow")
        });
    // Native storage is part of the same per-voter backend ceiling. Count
    // every real file, including selected generations and pending cleanup,
    // with the existing bounded descriptor-pinned directory walker.
    sqlite_bytes
        .checked_add(native_database_family_measure(path).0)
        .expect("complete database qualification byte total overflow")
}

pub(super) fn sqlite_database_family_artifacts(path: &Path) -> u64 {
    use rustix::fs::{fstat, openat, FileType, Mode, CWD};

    let sqlite_artifacts = ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            let candidate = std::path::PathBuf::from(candidate);
            match openat(
                CWD,
                &candidate,
                qualification_nofollow_metadata_flags(),
                Mode::empty(),
            ) {
                Ok(descriptor) => {
                    let metadata = fstat(&descriptor).expect("fstat SQLite qualification artifact");
                    assert!(
                        FileType::from_raw_mode(metadata.st_mode).is_file(),
                        "SQLite qualification artifact must be a regular no-follow file"
                    );
                    1
                }
                Err(error)
                    if !suffix.is_empty()
                        && std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
                {
                    0
                }
                Err(error) => panic!(
                    "read required SQLite qualification artifact {}: {error}",
                    candidate.display()
                ),
            }
        })
        .fold(0_u64, |total, artifacts| {
            total
                .checked_add(artifacts)
                .expect("SQLite qualification artifact count overflow")
        });
    sqlite_artifacts
        .checked_add(native_database_family_measure(path).1)
        .expect("complete database qualification artifact count overflow")
}

pub(super) fn directory_artifacts(path: &Path) -> u64 {
    bounded_directory_measure(path).1
}

pub(super) fn assert_voter_resource_ceiling(label: &str, values: &[u64], ceiling: u64) {
    assert_eq!(values.len(), VOTERS, "{label} must cover every voter");
    assert!(
        values.iter().all(|value| *value > 0 && *value <= ceiling),
        "{label} must be nonzero and no greater than {ceiling} bytes per voter: {values:?}",
    );
}
