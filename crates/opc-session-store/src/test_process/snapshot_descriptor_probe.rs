//! Failure-only evidence for a synthetic snapshot inode in the unit-test process.
//!
//! This observes an already-failed enable ioctl. It never retries, opens a writer,
//! changes the returned error, or treats an empty scan as proof of retirement.
//! Procfs is racy: a task, child, descriptor, or pending kernel reference may have
//! retired before observation. Limits and read failures mark the scan incomplete.
//! Only matching inode descriptors in this process and its immediate children
//! are recorded. No pathname, process command, environment, or unrelated file
//! descriptor appears in the report. This module is reached only under cfg(test).

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::Serialize;

const MAX_TASKS: usize = 1024;
const MAX_CHILDREN: usize = 64;
const MAX_DESCRIPTOR_ENTRIES: usize = 16_384;
const MAX_MATCHES: usize = 64;
const MAX_PROC_TEXT_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct DescriptorMatch {
    pid: u32,
    descriptor: u32,
    child: bool,
    writable: Option<bool>,
    close_on_exec: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
struct DescriptorReport {
    test_pid: u32,
    identity: Option<FileIdentity>,
    enable_errno: i32,
    tasks_examined: usize,
    children_examined: usize,
    descriptor_entries_examined: usize,
    incomplete: bool,
    matches: Vec<DescriptorMatch>,
}

thread_local! {
    // Tests consume this immediately on the same thread as their real ioctl.
    // At most one bounded report is retained per participating test thread.
    static LAST_REPORT: RefCell<Option<DescriptorReport>> = const { RefCell::new(None) };
}

/// Observe a real busy-enable failure without changing the returned kernel error.
pub(crate) fn record_snapshot_seal_failure(file: &File, error: &opc_fs_verity_sys::Error) {
    let opc_fs_verity_sys::Error::Enable(error) = error else {
        return;
    };
    if error.raw_os_error() != Some(libc::ETXTBSY) {
        return;
    }
    let report = collect_report(file);
    // Diagnostics must not replace the original ioctl result if stderr fails.
    if let Ok(encoded) = serde_json::to_string(&report) {
        let _ = writeln!(
            io::stderr().lock(),
            "snapshot_seal_descriptor_probe={encoded}"
        );
    }
    LAST_REPORT.with(|slot| *slot.borrow_mut() = Some(report));
}

fn read_bounded_text(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_PROC_TEXT_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    if text.len() > MAX_PROC_TEXT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "procfs size limit",
        ));
    }
    Ok(text)
}

fn proc_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(field).map(str::trim))
}

fn fd_flags(text: &str) -> Option<u32> {
    u32::from_str_radix(proc_field(text, "flags:")?, 8).ok()
}

fn collect_report(file: &File) -> DescriptorReport {
    let mut report = DescriptorReport {
        test_pid: std::process::id(),
        identity: None,
        enable_errno: libc::ETXTBSY,
        tasks_examined: 0,
        children_examined: 0,
        descriptor_entries_examined: 0,
        incomplete: false,
        matches: Vec::new(),
    };
    let Ok(metadata) = file.metadata() else {
        report.incomplete = true;
        return report;
    };
    report.identity = Some(FileIdentity::from_metadata(&metadata));
    scan_descriptors(report.test_pid, false, &mut report);

    // A child can belong to any launching test/runtime thread, not just the
    // process leader. This intentionally does not walk host-wide /proc PIDs.
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        report.incomplete = true;
        return report;
    };
    let mut children = BTreeSet::new();
    for task in tasks.take(MAX_TASKS + 1) {
        if report.tasks_examined == MAX_TASKS {
            report.incomplete = true;
            break;
        }
        report.tasks_examined += 1;
        let Ok(task) = task else {
            report.incomplete = true;
            continue;
        };
        let Ok(text) = read_bounded_text(&task.path().join("children")) else {
            report.incomplete = true;
            continue;
        };
        for value in text.split_ascii_whitespace() {
            let Ok(pid) = value.parse::<u32>() else {
                report.incomplete = true;
                continue;
            };
            if children.len() == MAX_CHILDREN && !children.contains(&pid) {
                report.incomplete = true;
                break;
            }
            children.insert(pid);
        }
    }
    for pid in children {
        if report.descriptor_entries_examined == MAX_DESCRIPTOR_ENTRIES {
            report.incomplete = true;
            break;
        }
        report.children_examined += 1;
        scan_descriptors(pid, true, &mut report);
    }
    report
}

fn scan_descriptors(pid: u32, child: bool, report: &mut DescriptorReport) {
    let Ok(process) = File::open(format!("/proc/{pid}")) else {
        report.incomplete = true;
        return;
    };
    // Anchor traversal to this procfs directory rather than following a reused
    // PID after it exits. Recheck direct parentage before inspecting child fds.
    let process_path = format!("/proc/self/fd/{}", process.as_raw_fd());
    let process_path = Path::new(&process_path);
    if child {
        let parent = read_bounded_text(&process_path.join("status"))
            .ok()
            .and_then(|text| proc_field(&text, "PPid:")?.parse::<u32>().ok());
        if parent != Some(report.test_pid) {
            report.incomplete = true;
            return;
        }
    }
    let Ok(descriptors) = std::fs::read_dir(process_path.join("fd")) else {
        report.incomplete = true;
        return;
    };
    for entry in descriptors {
        if report.descriptor_entries_examined == MAX_DESCRIPTOR_ENTRIES
            || report.matches.len() == MAX_MATCHES
        {
            report.incomplete = true;
            break;
        }
        report.descriptor_entries_examined += 1;
        let Ok(entry) = entry else {
            report.incomplete = true;
            continue;
        };
        let Some(descriptor) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            report.incomplete = true;
            continue;
        };
        let Ok(before) = std::fs::metadata(entry.path()) else {
            report.incomplete = true;
            continue;
        };
        if Some(FileIdentity::from_metadata(&before)) != report.identity {
            continue;
        }
        // Never read the fd contents or its symlink target. Read rights only for
        // a descriptor already matched to the supplied synthetic snapshot inode.
        let flags = read_bounded_text(&process_path.join("fdinfo").join(descriptor.to_string()))
            .ok()
            .and_then(|text| fd_flags(&text));
        let after = std::fs::metadata(entry.path());
        if !matches!(after, Ok(metadata) if Some(FileIdentity::from_metadata(&metadata)) == report.identity)
        {
            report.incomplete = true;
            continue;
        }
        if flags.is_none() {
            report.incomplete = true;
        }
        report.matches.push(DescriptorMatch {
            pid,
            descriptor,
            child,
            writable: flags.map(|flags| {
                let mode = flags & libc::O_ACCMODE as u32;
                mode == libc::O_WRONLY as u32 || mode == libc::O_RDWR as u32
            }),
            close_on_exec: flags.map(|flags| flags & libc::O_CLOEXEC as u32 != 0),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::consensus::snapshot::PinnedSqliteFile;
    use crate::test_process::CommandExt;

    const PAYLOAD: &[u8] = b"synthetic descriptor ownership snapshot";
    const CHILD_TIMEOUT: Duration = Duration::from_secs(5);

    fn snapshot_directory() -> tempfile::TempDir {
        let required = std::env::var_os("OPC_FS_VERITY_QUALIFICATION").as_deref()
            == Some(OsStr::new("required"));
        match std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT") {
            Some(root) => {
                let root = PathBuf::from(root);
                assert!(
                    root.is_absolute(),
                    "fs-verity snapshot root must be absolute"
                );
                tempfile::Builder::new()
                    .prefix("descriptor-probe-")
                    .tempdir_in(root)
                    .expect("create fs-verity snapshot fixture")
            }
            None => {
                assert!(!required, "required fs-verity snapshot root is missing");
                tempfile::Builder::new()
                    .prefix("descriptor-probe-")
                    .tempdir()
                    .expect("create local snapshot fixture")
            }
        }
    }

    fn fixture(path: &Path) -> (File, PinnedSqliteFile) {
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create snapshot writer");
        writer.write_all(PAYLOAD).unwrap();
        writer.sync_all().unwrap();
        let pinned = PinnedSqliteFile::from_file(File::open(path).unwrap(), path.to_path_buf())
            .expect("pin read-only snapshot descriptor");
        (writer, pinned)
    }

    fn take_report() -> Option<DescriptorReport> {
        LAST_REPORT.with(|slot| slot.borrow_mut().take())
    }

    fn assert_busy(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "fixed snapshot sealing is unavailable (enable errno=Some(26))",
            "diagnostics must preserve the original kernel refusal"
        );
    }

    struct ChildGuard(Child);

    impl ChildGuard {
        fn retaining(descriptor: File) -> Self {
            let (mut ready, child_ready) = UnixStream::pair().unwrap();
            ready.set_read_timeout(Some(CHILD_TIMEOUT)).unwrap();
            let child = Self(
                Command::new("/bin/sh")
                    .args(["-c", "printf 'ready\\n'; read -r release"])
                    .stdin(Stdio::piped())
                    // Readiness uses stdout without any shell redirection, so
                    // the retained stderr descriptor is stable before "ready".
                    // The child never writes stderr. This is not a pre-exec model.
                    .stdout(Stdio::from(OwnedFd::from(child_ready)))
                    .stderr(Stdio::from(descriptor))
                    .test_spawn()
                    .unwrap(),
            );
            let mut message = [0; 6];
            ready.read_exact(&mut message).unwrap();
            assert_eq!(&message, b"ready\n");
            child
        }

        fn release_and_wait(&mut self) {
            self.0
                .stdin
                .take()
                .unwrap()
                .write_all(b"release\n")
                .unwrap();
            let deadline = Instant::now() + CHILD_TIMEOUT;
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                assert!(Instant::now() < deadline, "fixture child failed to retire");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn snapshot_descriptor_probe_observes_actual_parent_writers_then_seals() {
        let directory = snapshot_directory();
        let path = directory.path().join("snapshot");
        let (writer, mut pinned) = fixture(&path);
        let alias = writer.try_clone().unwrap();
        let unrelated = File::create(directory.path().join("unrelated")).unwrap();
        let writers = BTreeSet::from([writer.as_raw_fd() as u32, alias.as_raw_fd() as u32]);
        let identity = FileIdentity::from_metadata(&writer.metadata().unwrap());
        take_report();
        assert_busy(pinned.seal_fixed().unwrap_err());
        let observed = take_report();

        // Complete the real kernel negative/positive lifecycle before checking
        // the observation; removing just the call-site hook must fail below.
        drop(alias);
        drop(writer);
        pinned
            .seal_fixed()
            .expect("seal after actual writers close");
        pinned.verify_immutable_generation().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), PAYLOAD);
        let report = observed.expect("failed enable ioctl must record its descriptor holders");
        assert_eq!(report.identity, Some(identity));
        assert_eq!(report.enable_errno, libc::ETXTBSY);
        let found: BTreeSet<_> = report
            .matches
            .iter()
            .filter(|entry| entry.pid == std::process::id() && entry.writable == Some(true))
            .map(|entry| entry.descriptor)
            .collect();
        assert_eq!(found, writers);
        assert!(report
            .matches
            .iter()
            .all(|entry| entry.pid != std::process::id()
                || entry.descriptor != unrelated.as_raw_fd() as u32));
        assert!(report
            .matches
            .iter()
            .any(|entry| entry.writable == Some(false)));
        assert!(report
            .matches
            .iter()
            .filter(|entry| entry.pid == std::process::id() && found.contains(&entry.descriptor))
            .all(|entry| entry.close_on_exec == Some(true)));
    }

    #[test]
    fn snapshot_descriptor_probe_observes_actual_child_writer_then_seals() {
        let directory = snapshot_directory();
        let path = directory.path().join("snapshot");
        let (writer, mut pinned) = fixture(&path);
        let identity = FileIdentity::from_metadata(&writer.metadata().unwrap());
        let mut child = ChildGuard::retaining(writer);
        let pid = child.0.id();
        assert!(child.0.try_wait().unwrap().is_none());
        take_report();
        assert_busy(pinned.seal_fixed().unwrap_err());
        let observed = take_report();
        child.release_and_wait();
        pinned
            .seal_fixed()
            .expect("seal after child writer retires");
        pinned.verify_immutable_generation().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), PAYLOAD);

        let report = observed.expect("failed enable ioctl must record its descriptor holders");
        assert_eq!(report.identity, Some(identity));
        assert_eq!(report.enable_errno, libc::ETXTBSY);
        let writers: Vec<_> = report
            .matches
            .iter()
            .filter(|entry| entry.writable == Some(true))
            .collect();
        assert_eq!(writers.len(), 1, "only the actual child retains a writer");
        assert_eq!(writers[0].pid, pid);
        assert_eq!(writers[0].descriptor, 2);
        assert!(writers[0].child);
        assert_eq!(writers[0].close_on_exec, Some(false));
    }

    #[test]
    fn snapshot_descriptor_probe_allows_live_read_only_child() {
        let directory = snapshot_directory();
        let path = directory.path().join("snapshot");
        let (writer, mut pinned) = fixture(&path);
        drop(writer);
        let reader = File::open(&path).unwrap();
        let mut child = ChildGuard::retaining(reader.try_clone().unwrap());
        let observed = collect_report(&reader);
        take_report();
        pinned
            .seal_fixed()
            .expect("read-only child must not block sealing");
        pinned.verify_immutable_generation().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), PAYLOAD);
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(
            take_report().is_none(),
            "successful seals must not produce failure reports"
        );
        assert!(observed
            .matches
            .iter()
            .any(|entry| entry.pid == child.0.id()
                && entry.descriptor == 2
                && entry.child
                && entry.writable == Some(false)));
        assert!(observed
            .matches
            .iter()
            .all(|entry| entry.writable == Some(false)));
        child.release_and_wait();
    }

    #[test]
    fn snapshot_descriptor_probe_ignores_non_busy_errors() {
        let directory = tempfile::tempdir().unwrap();
        let file = File::create(directory.path().join("unused")).unwrap();
        take_report();
        for error in [
            opc_fs_verity_sys::Error::Enable(io::Error::from_raw_os_error(libc::EIO)),
            opc_fs_verity_sys::Error::Measure(io::Error::from_raw_os_error(libc::ETXTBSY)),
        ] {
            crate::test_process::record_snapshot_seal_failure(&file, &error);
            assert!(take_report().is_none());
        }
        assert_eq!(
            fd_flags("pos:\t0\nflags:\t02000001\nmnt_id:\t1\n"),
            Some(0o2000001)
        );
        assert_eq!(fd_flags("flags:\tinvalid\n"), None);
        assert_eq!(fd_flags("pos:\t0\n"), None);
    }
}
