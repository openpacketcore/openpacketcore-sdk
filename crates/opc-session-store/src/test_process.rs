//! Coordinate child launches with fs-verity in the shared unit-test process.
//!
//! CLOEXEC descriptors still exist in a forked child until exec. A concurrent
//! fixture can therefore close its last writer and get ETXTBSY while that child
//! retains an inherited writer. The exec handshake can finish before the kernel
//! has retired those file references. Seals take a shared gate; child launches
//! hold the exclusive gate through completion, or through an explicit userspace
//! readiness signal for a child that stays running. Actual writers still cause
//! the unchanged kernel validation to fail. None of this is production code.

use std::io;
#[cfg(target_os = "linux")]
use std::process::ExitStatus;
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Child, Command, Output};
#[cfg(target_os = "linux")]
use std::sync::RwLock;

#[cfg(target_os = "linux")]
pub(crate) static SNAPSHOT_PROCESS_FD_GATE: RwLock<()> = RwLock::new(());

#[cfg(target_os = "linux")]
mod snapshot_descriptor_probe;

#[cfg(target_os = "linux")]
pub(crate) use snapshot_descriptor_probe::record_snapshot_seal_failure;

struct PendingChild(Option<Child>);

impl Drop for PendingChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Use for every child launch in this crate's shared unit-test process.
pub(crate) trait CommandExt {
    /// Wait for a signal from the executed child before allowing snapshot seals.
    /// The readiness callback must have its own hang guard.
    fn test_spawn(&mut self, ready: impl FnOnce(&mut Child) -> io::Result<()>)
        -> io::Result<Child>;
    /// Hold the gate until a short, silent tool (such as mkfifo) exits.
    /// Re-executed libtest fixtures must use test_output for early gate release.
    #[cfg(target_os = "linux")]
    fn test_status(&mut self) -> io::Result<ExitStatus>;
    /// Capture both output streams, with null stdin, for an isolated libtest
    /// fixture. Its initial harness output is the userspace readiness signal.
    fn test_output(&mut self) -> io::Result<Output>;
}

impl CommandExt for Command {
    fn test_spawn(
        &mut self,
        ready: impl FnOnce(&mut Child) -> io::Result<()>,
    ) -> io::Result<Child> {
        #[cfg(target_os = "linux")]
        let _launch = SNAPSHOT_PROCESS_FD_GATE
            .write()
            .expect("test child-launch gate remains available");
        let mut child = PendingChild(Some(self.spawn()?));
        ready(child.0.as_mut().expect("pending test child"))?;
        Ok(child.0.take().expect("ready test child"))
    }

    #[cfg(target_os = "linux")]
    fn test_status(&mut self) -> io::Result<ExitStatus> {
        #[cfg(target_os = "linux")]
        let _launch = SNAPSHOT_PROCESS_FD_GATE
            .write()
            .expect("test child-launch gate remains available");
        self.status()
    }

    fn test_output(&mut self) -> io::Result<Output> {
        #[cfg(not(unix))]
        return self.output();

        #[cfg(unix)]
        {
            let (child, prefix) = {
                #[cfg(target_os = "linux")]
                let _launch = SNAPSHOT_PROCESS_FD_GATE
                    .write()
                    .expect("test child-launch gate remains available");
                let mut child = PendingChild(Some(
                    self.stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()?,
                ));
                let prefix = captured_readiness(
                    child.0.as_mut().expect("pending captured test child"),
                    std::time::Duration::from_secs(5),
                )?;
                (child.0.take().expect("ready captured child"), prefix)
            };
            // A long isolated fixture must not block unrelated snapshot seals.
            let mut output = child.wait_with_output()?;
            if let Some(prefix) = prefix {
                output.stdout.insert(0, prefix);
            }
            Ok(output)
        }
    }
}

/// Wait for one byte from userspace, or a silent child's reaped exit. A child
/// blocked before harness output (including on a full stderr pipe) must not
/// keep the process-wide seal gate forever. Restore blocking mode before the
/// ordinary output collector drains both streams outside the gate.
#[cfg(unix)]
fn captured_readiness(child: &mut Child, timeout: std::time::Duration) -> io::Result<Option<u8>> {
    use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let flags = fcntl_getfl(child.stdout.as_ref().expect("captured test stdout"))?;
    fcntl_setfl(
        child.stdout.as_ref().expect("captured test stdout"),
        flags | OFlags::NONBLOCK,
    )?;
    let deadline = Instant::now() + timeout;
    let result = (|| {
        loop {
            let mut byte = [0; 1];
            match child
                .stdout
                .as_mut()
                .expect("captured test stdout")
                .read(&mut byte)
            {
                Ok(0) => {
                    // EOF alone is not a userspace signal: stdout can close
                    // before the child exits. Reap it while still gated.
                    if child.try_wait()?.is_some() {
                        return Ok(None);
                    }
                }
                Ok(_) => return Ok(Some(byte[0])),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test child produced no stdout readiness byte or reaped exit before its hang guard",
                ));
            }
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    })();
    fcntl_setfl(child.stdout.as_ref().expect("captured test stdout"), flags)?;
    result
}

#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn captured_readiness_timeout_reaps_child_and_releases_snapshot_gate() {
        for script in [
            "exec 1>&-; exec sleep 60",
            "while :; do printf 'fill captured stderr before stdout readiness\\n' >&2; done",
        ] {
            let mut child_id = None;
            let error = Command::new("/bin/sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .test_spawn(|child| {
                    child_id = Some(child.id());
                    captured_readiness(child, Duration::from_millis(100)).map(|_| ())
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(
                !std::path::Path::new(&format!("/proc/{}", child_id.unwrap())).exists(),
                "a child that never becomes ready is killed and reaped"
            );
            let _seal = SNAPSHOT_PROCESS_FD_GATE.read().unwrap();
        }
    }

    #[test]
    fn captured_output_accepts_a_silent_child_only_after_exit() {
        let output = Command::new("/bin/true").test_output().unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn captured_output_releases_snapshot_gate_before_child_exit() {
        struct ReleaseChild(std::path::PathBuf);
        impl Drop for ReleaseChild {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.0, b"release");
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let ready_path = directory.path().join("ready");
        let release_path = directory.path().join("release");
        std::thread::scope(|scope| {
            let release = ReleaseChild(release_path.clone());
            let output = scope.spawn(|| {
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        "printf ready; printf started > \"$1\"; while [ ! -e \"$2\" ]; do sleep 0.01; done; printf finished >&2",
                        "captured-output",
                    ])
                    .arg(&ready_path)
                    .arg(&release_path)
                    .test_output()
                    .unwrap()
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready_path.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(ready_path.exists(), "captured child entered userspace");
            let (available, observed) = std::sync::mpsc::channel();
            let seal = scope.spawn(move || {
                let _seal = SNAPSHOT_PROCESS_FD_GATE.read().unwrap();
                available.send(()).unwrap();
            });
            let before_exit = observed.recv_timeout(Duration::from_secs(5));
            drop(release);
            let output = output.join().unwrap();
            seal.join().unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, b"ready");
            assert_eq!(output.stderr, b"finished");
            before_exit.expect("snapshot sealing proceeds while captured child stays alive");
        });
    }
}
