//! Coordinate child launches with snapshot descriptors in unit tests.
//!
//! CLOEXEC descriptors still exist in a forked child until exec. A concurrent
//! fixture can therefore close its last writer and get ETXTBSY, or close its
//! namespace socket and get EADDRINUSE on reopen, while that child retains the
//! inherited descriptor. The exec handshake can finish before the kernel has
//! retired those file references. Seals and namespace binds take a shared gate;
//! child launches hold the exclusive gate through completion, or through an
//! explicit userspace readiness signal for a child that stays running. Actual
//! writers and namespace owners still fail the unchanged kernel checks. None
//! of this coordination is production code.

use std::io;
#[cfg(target_os = "linux")]
use std::process::ExitStatus;
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Child, Command, Output};
#[cfg(target_os = "linux")]
use std::sync::RwLock;

#[cfg(target_os = "linux")]
pub(crate) static SNAPSHOT_PROCESS_FD_GATE: SnapshotProcessFdGate =
    SnapshotProcessFdGate(RwLock::new(()));

/// The fixture descriptor gate cannot hide a stuck owner indefinitely.
#[cfg(target_os = "linux")]
pub(crate) struct SnapshotProcessFdGate(RwLock<()>);

#[cfg(target_os = "linux")]
impl SnapshotProcessFdGate {
    fn acquire<'a, T>(
        &'a self,
        mut attempt: impl FnMut(&'a RwLock<()>) -> std::sync::TryLockResult<T>,
        timeout: std::time::Duration,
        step: &str,
    ) -> io::Result<T> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match attempt(&self.0) {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("test snapshot descriptor gate poisoned"))
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("test snapshot descriptor gate: {step} still blocked by an owner"),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    pub(crate) fn read(&self) -> io::Result<std::sync::RwLockReadGuard<'_, ()>> {
        self.acquire(
            RwLock::try_read,
            std::time::Duration::from_secs(180),
            "read admission",
        )
    }

    pub(crate) fn write(&self) -> io::Result<std::sync::RwLockWriteGuard<'_, ()>> {
        self.acquire(
            RwLock::try_write,
            std::time::Duration::from_secs(180),
            "child launch",
        )
    }
}

#[cfg(target_os = "linux")]
mod snapshot_descriptor_probe;

#[cfg(target_os = "linux")]
pub(crate) mod sqlite_lock_probe;

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
    /// Wait for a signal from the executed child before allowing snapshot seals
    /// or namespace binds.
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
    /// Bound a fixture, including blocking teardown, without releasing its owners.
    #[cfg(target_os = "linux")]
    fn test_output_with_deadline(&mut self, timeout: std::time::Duration) -> io::Result<Output>;
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
    #[cfg(target_os = "linux")]
    fn test_output_with_deadline(&mut self, timeout: std::time::Duration) -> io::Result<Output> {
        use std::io::Read as _;
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};

        const OWNED_GROUP: &str = "OPC_TEST_FIXTURE_OWNED_GROUP";
        let nested = std::env::var(OWNED_GROUP).as_deref() == Ok("1");
        // Descendants stay in the outer fixture's group so a failed nested
        // witness cannot leave another process holding its output or owners.
        if !nested {
            self.process_group(0);
        }
        self.env(OWNED_GROUP, "1");
        let (mut child, prefix) = {
            let _launch = SNAPSHOT_PROCESS_FD_GATE.write()?;
            let mut child = self
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            match captured_readiness(&mut child, Duration::from_secs(5)) {
                Ok(prefix) => (child, prefix),
                Err(error) => {
                    terminate_fixture_group(&child, nested, "test fixture readiness stalled");
                    let _ = child.wait();
                    return Err(error);
                }
            }
        };
        let mut stdout = child.stdout.take().expect("test child stdout");
        let mut stderr = child.stderr.take().expect("test child stderr");
        let out = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let err = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = (|| -> io::Result<ExitStatus> {
            let mut status = None;
            loop {
                if status.is_none() {
                    status = child.try_wait()?;
                }
                if let Some(status) = status.filter(|_| out.is_finished() && err.is_finished()) {
                    break Ok(status);
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    // The child owns this group. Include descendants which
                    // may retain captured output after their parent exits.
                    terminate_fixture_group(&child, nested, "test fixture exceeded its completion deadline; stuck blocking teardown or wait");
                    break child.wait();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })();
        if status.is_err() {
            terminate_fixture_group(&child, nested, "test fixture completion observation failed");
            let _ = child.wait();
        }
        let mut stdout = out.join().expect("test stdout reader")?;
        if let Some(prefix) = prefix {
            stdout.insert(0, prefix);
        }
        let stderr = err.join().expect("test stderr reader")?;
        if timed_out {
            return Err(io::Error::new(io::ErrorKind::TimedOut, format!(
                "test fixture exceeded its {timeout:?} completion deadline; stuck blocking teardown or wait\n{}\n{}",
                String::from_utf8_lossy(&stdout), String::from_utf8_lossy(&stderr))));
        }
        Ok(Output {
            status: status?,
            stdout,
            stderr,
        })
    }
}

#[cfg(target_os = "linux")]
fn terminate_fixture_group(child: &Child, nested: bool, message: &str) {
    let group = if nested {
        // Write outside libtest capture before terminating this failed owned
        // group, which includes the nested observer itself.
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), "{message}");
        rustix::process::getpgrp()
    } else {
        rustix::process::Pid::from_child(child)
    };
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
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
        const NESTED_PROBE: &str = "OPC_TEST_NESTED_FIXTURE_DEADLINE";
        if std::env::var_os(NESTED_PROBE).is_some() {
            let _ = Command::new("/bin/sh")
                .args(["-c", "printf ready; sleep 60 & wait"])
                .test_output_with_deadline(Duration::from_millis(20));
            panic!("a nested deadline must terminate its owned fixture group");
        }
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
        let gate = SnapshotProcessFdGate(RwLock::new(()));
        let held = gate.write().unwrap();
        let error = gate
            .acquire(
                RwLock::try_read,
                Duration::from_millis(20),
                "read admission",
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("snapshot descriptor gate"));
        drop(held);
        let started = Instant::now();
        let error = Command::new("/bin/sh")
            .args(["-c", "printf ready; exec sleep 60"])
            .test_output_with_deadline(Duration::from_millis(20))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error
            .to_string()
            .contains("stuck blocking teardown or wait"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bounded child teardown did not finish promptly"
        );
        let name = std::thread::current().name().unwrap().to_owned();
        let started = Instant::now();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--test-threads=1", "--nocapture"])
            .env(NESTED_PROBE, "1")
            .test_output_with_deadline(Duration::from_secs(5))
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("stuck blocking teardown or wait"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "nested fixture deadline left an owned descendant running"
        );
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

/// Give a unit fixture a bounded private process, including blocking teardown.
#[cfg(target_os = "linux")]
#[track_caller]
pub(crate) fn with_completion_deadline(timeout: std::time::Duration, run: impl FnOnce()) {
    if !run_completion_parent(timeout) {
        run();
    }
}

/// Observe an async fixture in a private process before it creates any owners.
#[cfg(target_os = "linux")]
#[track_caller]
pub(crate) fn run_completion_parent(timeout: std::time::Duration) -> bool {
    const CHILD: &str = "OPC_TEST_COMPLETION_DEADLINE_CASE";
    let current = std::thread::current();
    let name = current.name().expect("libtest names its fixture thread");
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(CHILD, name)
        .test_output_with_deadline(timeout)
        .unwrap_or_else(|error| panic!("{name}: {error}"));
    assert!(
        output.status.success(),
        "{name}: fixture failed\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "{name}: isolated fixture did not run exactly one test"
    );
    true
}

/// Finite observation guards for test-only synchronization witnesses.
#[cfg(target_os = "linux")]
pub(crate) mod witness {
    use std::sync::{mpsc, Condvar, LockResult, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    const DEADLINE: Duration = Duration::from_secs(180);

    pub(crate) trait CondvarExt {
        #[track_caller]
        fn test_wait<'a, T>(&self, state: MutexGuard<'a, T>) -> LockResult<MutexGuard<'a, T>>;
        #[track_caller]
        fn test_wait_while<'a, T: std::fmt::Debug>(
            &self,
            state: MutexGuard<'a, T>,
            pending: impl FnMut(&mut T) -> bool,
        ) -> LockResult<MutexGuard<'a, T>>;
    }

    impl CondvarExt for Condvar {
        fn test_wait<'a, T>(&self, state: MutexGuard<'a, T>) -> LockResult<MutexGuard<'a, T>> {
            let (state, elapsed) = self
                .wait_timeout(state, DEADLINE)
                .map_err(|error| PoisonError::new(error.into_inner().0))?;
            assert!(
                !elapsed.timed_out(),
                "test condition-variable notification stalled at {}",
                std::panic::Location::caller()
            );
            Ok(state)
        }

        fn test_wait_while<'a, T: std::fmt::Debug>(
            &self,
            state: MutexGuard<'a, T>,
            mut pending: impl FnMut(&mut T) -> bool,
        ) -> LockResult<MutexGuard<'a, T>> {
            let (mut state, elapsed) = self
                .wait_timeout_while(state, DEADLINE, &mut pending)
                .map_err(|error| PoisonError::new(error.into_inner().0))?;
            assert!(
                !elapsed.timed_out() || !pending(&mut state),
                "test condition-variable predicate stalled at {}: state={state:?}",
                std::panic::Location::caller()
            );
            Ok(state)
        }
    }

    pub(crate) trait ReceiverExt<T> {
        #[track_caller]
        fn test_recv(&self) -> Result<T, mpsc::RecvError>;
    }

    impl<T> ReceiverExt<T> for mpsc::Receiver<T> {
        fn test_recv(&self) -> Result<T, mpsc::RecvError> {
            match self.recv_timeout(DEADLINE) {
                Ok(value) => Ok(value),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(mpsc::RecvError),
                Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                    "test channel completion stalled at {}",
                    std::panic::Location::caller()
                ),
            }
        }
    }

    pub(crate) trait JoinExt<T> {
        #[track_caller]
        fn test_join(self) -> std::thread::Result<T>;
    }

    impl<'scope, T> JoinExt<T> for std::thread::ScopedJoinHandle<'scope, T> {
        fn test_join(self) -> std::thread::Result<T> {
            let deadline = Instant::now() + DEADLINE;
            while !self.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "test scoped worker completion stalled at {}",
                    std::panic::Location::caller()
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            self.join()
        }
    }

    impl<T> JoinExt<T> for std::thread::JoinHandle<T> {
        fn test_join(self) -> std::thread::Result<T> {
            let deadline = Instant::now() + DEADLINE;
            while !self.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "test worker completion stalled at {}",
                    std::panic::Location::caller()
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            self.join()
        }
    }
}
