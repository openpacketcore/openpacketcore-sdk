//! Bounded, payload-free classification of a qualification child's stderr.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_STDERR_BYTES: u64 = 8 * 1024;

/// The append-only diagnostic file boundary observed before sending a command.
#[derive(Debug, Clone, Copy)]
pub(super) struct StderrBoundary {
    device: u64,
    inode: u64,
    bytes: u64,
}

pub(super) fn boundary(path: &Path) -> Option<StderrBoundary> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(StderrBoundary {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
    })
}

pub(super) fn classify_since(path: &Path, boundary: StderrBoundary) -> ChildStderrDiagnostic {
    let Ok(mut file) = File::open(path) else {
        return ChildStderrDiagnostic::Unavailable;
    };
    let Ok(metadata) = file.metadata() else {
        return ChildStderrDiagnostic::Unavailable;
    };
    if metadata.dev() != boundary.device || metadata.ino() != boundary.inode {
        return ChildStderrDiagnostic::Unavailable;
    }
    classify_range(&mut file, metadata.len(), boundary.bytes)
}

fn classify_range(
    reader: &mut (impl Read + Seek),
    total_bytes: u64,
    start: u64,
) -> ChildStderrDiagnostic {
    let Some(length) = total_bytes.checked_sub(start) else {
        return ChildStderrDiagnostic::Unavailable;
    };
    if length > MAX_STDERR_BYTES {
        return ChildStderrDiagnostic::Redacted;
    }
    if reader.seek(SeekFrom::Start(start)).is_err() {
        return ChildStderrDiagnostic::Unavailable;
    }
    let mut bytes = Vec::with_capacity(length as usize);
    if reader.take(length).read_to_end(&mut bytes).is_err() || bytes.len() as u64 != length {
        return ChildStderrDiagnostic::Unavailable;
    }
    classify(&bytes, false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChildStderrDiagnostic {
    Unavailable,
    Empty,
    QualificationNodeFailed,
    QualificationNodeTransportFailed,
    QualificationNodeSqliteFailed,
    QualificationNodeConsensusFailed,
    QualificationNodeListenerFailed,
    InitializationFailed {
        stage: &'static str,
        error_class: &'static str,
    },
    Redacted,
}

fn initialization_failure(line: &[u8]) -> Option<ChildStderrDiagnostic> {
    let suffix = line.strip_prefix(b"qualification node initialize failed: ")?;
    let split = suffix.iter().position(|byte| *byte == b' ')?;
    let (stage, classes): (&'static str, &[&'static str]) = match &suffix[..split] {
        b"cluster" => (
            "cluster",
            &[
                "PersistenceModeMismatch",
                "SnapshotIntegrityUnavailable",
                "DynamicConsensusUnsupportedPlatform",
                "InvalidTopology",
                "PeerSetMismatch",
                "RecoveryRequired",
                "DurableIdentityMismatch",
                "StorageUnavailable",
                "FixedQuorumUnsupportedPlatform",
                "InvalidRuntimeConfiguration",
                "EngineUnavailable",
                "ClusterFormationRejected",
                "CandidateTransitionCancelled",
            ],
        ),
        stage @ (b"fenced_transition" | b"protected_roster_v2") => (
            if stage == b"fenced_transition" {
                "fenced_transition"
            } else {
                "protected_roster_v2"
            },
            &[
                "BackendUnavailable",
                "CasIdempotencyOutcomeUnavailable",
                "BackendOperationOutcomeUnavailable",
                "LeaseLostOrInvalid",
                "Other",
            ],
        ),
        _ => return None,
    };
    let error_class = classes
        .iter()
        .copied()
        .find(|class| class.as_bytes() == &suffix[split + 1..])?;
    // Both fields come from literals above, never from child-supplied text.
    Some(ChildStderrDiagnostic::InitializationFailed { stage, error_class })
}

pub(super) fn classify(bytes: &[u8], truncated: bool) -> ChildStderrDiagnostic {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return ChildStderrDiagnostic::Empty;
    }
    if truncated {
        return ChildStderrDiagnostic::Redacted;
    }
    let mut initialization = None;
    let mut open_failures = [false; 4];
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match line {
            b"qualification node failed" => {}
            b"qualification node open failed: transport" => {
                initialization = None;
                open_failures[0] = true;
            }
            b"qualification node open failed: sqlite" => {
                initialization = None;
                open_failures[1] = true;
            }
            b"qualification node open failed: consensus" => {
                initialization = None;
                open_failures[2] = true;
            }
            b"qualification node open failed: listener" => {
                initialization = None;
                open_failures[3] = true;
            }
            _ => match initialization_failure(line) {
                Some(failure) => initialization = Some(failure),
                None => return ChildStderrDiagnostic::Redacted,
            },
        }
    }
    if let Some(failure) = initialization {
        return failure;
    }
    if open_failures[3] {
        ChildStderrDiagnostic::QualificationNodeListenerFailed
    } else if open_failures[2] {
        ChildStderrDiagnostic::QualificationNodeConsensusFailed
    } else if open_failures[1] {
        ChildStderrDiagnostic::QualificationNodeSqliteFailed
    } else if open_failures[0] {
        ChildStderrDiagnostic::QualificationNodeTransportFailed
    } else {
        ChildStderrDiagnostic::QualificationNodeFailed
    }
}

#[test]
fn initialization_stages_and_payload_free_classes_are_observable() {
    for (stage, class) in [
        ("cluster", "RecoveryRequired"),
        ("cluster", "EngineUnavailable"),
        ("cluster", "ClusterFormationRejected"),
        ("fenced_transition", "BackendUnavailable"),
        ("protected_roster_v2", "BackendOperationOutcomeUnavailable"),
    ] {
        let line = format!("qualification node initialize failed: {stage} {class}\n");
        assert_eq!(
            classify(line.as_bytes(), false),
            ChildStderrDiagnostic::InitializationFailed {
                stage,
                error_class: class,
            },
        );
    }
}

#[test]
fn initialization_diagnostics_reject_payloads_and_unknown_or_truncated_lines() {
    let valid = b"qualification node initialize failed: cluster RecoveryRequired\n";
    assert_eq!(classify(valid, true), ChildStderrDiagnostic::Redacted);
    for suffix in [
        "cluster RecoveryRequired extra",
        "cluster BackendUnavailable",
        "protected_roster_v2 RecoveryRequired",
        "unknown Other",
        "cluster RecoveryRequired\r",
        "cluster RecoveryRequired\nprivate text",
    ] {
        let line = format!("qualification node initialize failed: {suffix}\n");
        assert_eq!(
            classify(line.as_bytes(), false),
            ChildStderrDiagnostic::Redacted
        );
    }
    let mut invalid_utf8 = valid.to_vec();
    invalid_utf8.push(0xff);
    assert_eq!(
        classify(&invalid_utf8, false),
        ChildStderrDiagnostic::Redacted
    );
}

#[test]
fn most_recent_initialization_failure_is_reported() {
    let lines = b"qualification node initialize failed: cluster RecoveryRequired\nqualification node initialize failed: protected_roster_v2 BackendUnavailable\nqualification node failed\n";
    assert_eq!(
        classify(lines, false),
        ChildStderrDiagnostic::InitializationFailed {
            stage: "protected_roster_v2",
            error_class: "BackendUnavailable",
        },
    );
}

#[test]
fn newer_open_failure_supersedes_old_initialization_diagnostic() {
    let initialization = "qualification node initialize failed: cluster RecoveryRequired";
    for (kind, expected) in [
        (
            "transport",
            ChildStderrDiagnostic::QualificationNodeTransportFailed,
        ),
        (
            "sqlite",
            ChildStderrDiagnostic::QualificationNodeSqliteFailed,
        ),
        (
            "consensus",
            ChildStderrDiagnostic::QualificationNodeConsensusFailed,
        ),
        (
            "listener",
            ChildStderrDiagnostic::QualificationNodeListenerFailed,
        ),
    ] {
        let open = format!("qualification node open failed: {kind}");
        let newer_open = format!("{initialization}\n{open}\nqualification node failed\n");
        assert_eq!(classify(newer_open.as_bytes(), false), expected);
        let newer_initialize = format!("{open}\nqualification node failed\n{initialization}\n");
        assert_eq!(
            classify(newer_initialize.as_bytes(), false),
            ChildStderrDiagnostic::InitializationFailed {
                stage: "cluster",
                error_class: "RecoveryRequired",
            },
        );
    }
}

#[test]
fn existing_open_failure_priority_and_redaction_are_preserved() {
    assert_eq!(classify(b" \n\t", false), ChildStderrDiagnostic::Empty);
    for (line, expected) in [
        (
            "qualification node failed",
            ChildStderrDiagnostic::QualificationNodeFailed,
        ),
        (
            "qualification node open failed: transport",
            ChildStderrDiagnostic::QualificationNodeTransportFailed,
        ),
        (
            "qualification node open failed: sqlite",
            ChildStderrDiagnostic::QualificationNodeSqliteFailed,
        ),
        (
            "qualification node open failed: consensus",
            ChildStderrDiagnostic::QualificationNodeConsensusFailed,
        ),
        (
            "qualification node open failed: listener",
            ChildStderrDiagnostic::QualificationNodeListenerFailed,
        ),
    ] {
        assert_eq!(classify(line.as_bytes(), false), expected);
        let contaminated = format!("{line}\nprivate text");
        assert_eq!(
            classify(contaminated.as_bytes(), false),
            ChildStderrDiagnostic::Redacted
        );
    }
    assert_eq!(
        classify(b"qualification node open failed: listener\nqualification node open failed: transport\n", false),
        ChildStderrDiagnostic::QualificationNodeListenerFailed,
    );
}

#[test]
fn current_command_without_output_cannot_inherit_an_earlier_failure() {
    let old = b"qualification node initialize failed: cluster RecoveryRequired\n";
    assert_eq!(
        classify_range(
            &mut std::io::Cursor::new(old),
            old.len() as u64,
            old.len() as u64
        ),
        ChildStderrDiagnostic::Empty,
    );
}

#[test]
fn current_command_can_be_classified_after_large_private_history() {
    let mut bytes = vec![b'x'; MAX_STDERR_BYTES as usize + 1];
    bytes.push(b'\n');
    let start = bytes.len() as u64;
    bytes.extend_from_slice(b"qualification node initialize failed: cluster RecoveryRequired\n");
    let end = bytes.len() as u64;
    assert_eq!(
        classify_range(&mut std::io::Cursor::new(bytes), end, start),
        ChildStderrDiagnostic::InitializationFailed {
            stage: "cluster",
            error_class: "RecoveryRequired",
        },
    );
}

#[test]
fn current_command_window_rejects_truncation_and_excessive_output() {
    let bytes = b"qualification node failed\n";
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(
        classify_range(&mut reader, 0, 1),
        ChildStderrDiagnostic::Unavailable
    );
    assert_eq!(
        classify_range(&mut reader, bytes.len() as u64 + 1, 0),
        ChildStderrDiagnostic::Unavailable,
    );
    assert_eq!(
        classify_range(&mut reader, MAX_STDERR_BYTES + 1, 0),
        ChildStderrDiagnostic::Redacted,
    );
}

#[test]
fn append_file_boundary_is_checked_against_the_opened_file() {
    use std::io::Write;
    struct TestDirectory(std::path::PathBuf);
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory_path = std::env::temp_dir().join(format!(
        "qualification-stderr-boundary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&directory_path).unwrap();
    let directory = TestDirectory(directory_path);
    let path = directory.0.join("stderr");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(b"qualification node initialize failed: cluster RecoveryRequired\n")
        .unwrap();
    let before = boundary(&path).unwrap();
    assert_eq!(classify_since(&path, before), ChildStderrDiagnostic::Empty);
    file.write_all(b"qualification node initialize failed: cluster EngineUnavailable\n")
        .unwrap();
    assert_eq!(
        classify_since(&path, before),
        ChildStderrDiagnostic::InitializationFailed {
            stage: "cluster",
            error_class: "EngineUnavailable",
        },
    );
    // Preserve the original inode so replacement cannot recycle its identity.
    std::fs::rename(&path, directory.0.join("predecessor")).unwrap();
    std::fs::write(&path, b"qualification node failed\n").unwrap();
    assert_eq!(
        classify_since(&path, before),
        ChildStderrDiagnostic::Unavailable
    );
}
