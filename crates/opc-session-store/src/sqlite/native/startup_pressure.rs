//! Real, process-isolated descriptor exhaustion at the timer allocation boundary.

use std::cell::Cell;

use crate::test_process::CommandExt;

const CHILD: &str = "OPC_AUTHORITY_STARTUP_RESOURCE_TEST";
thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn isolate(test: &str) -> bool {
    let test = test.strip_prefix("opc_session_store::").unwrap();
    if std::env::var(CHILD).as_deref() == Ok(test) {
        return false;
    }
    let output = std::process::Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=5", "120"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(CHILD, test)
        .test_output()
        .expect("isolated startup resource test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed; 0 failed; 0 ignored"),
        "{test}: {stdout}\n{stderr}"
    );
    eprint!("{stderr}");
    true
}

pub(crate) fn arm() {
    assert!(std::env::var_os(CHILD).is_some(), "isolated child required");
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread,
        "the next timer allocation must run on this thread"
    );
    assert!(!ARMED.with(|armed| armed.replace(true)));
}

pub(crate) struct Pressure {
    original: (nix::sys::resource::rlim_t, nix::sys::resource::rlim_t),
    descriptors: Vec<std::fs::File>,
}

pub(super) fn take() -> Option<Pressure> {
    if !ARMED.with(|armed| armed.replace(false)) {
        return None;
    }
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    let mut pressure = Pressure {
        original: getrlimit(Resource::RLIMIT_NOFILE).unwrap(),
        descriptors: Vec::new(),
    };
    setrlimit(
        Resource::RLIMIT_NOFILE,
        pressure.original.1.min(64),
        pressure.original.1,
    )
    .unwrap();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => pressure.descriptors.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                break;
            }
        }
    }
    assert_eq!(
        rustix::time::timerfd_create(
            rustix::time::TimerfdClockId::Monotonic,
            rustix::time::TimerfdFlags::NONBLOCK | rustix::time::TimerfdFlags::CLOEXEC,
        )
        .expect_err("real timer allocation must fail before the production call"),
        rustix::io::Errno::MFILE,
    );
    eprintln!("startup resource pressure: timerfd_create=EMFILE immediately before allocation");
    Some(pressure)
}

impl Drop for Pressure {
    fn drop(&mut self) {
        self.descriptors.clear();
        nix::sys::resource::setrlimit(
            nix::sys::resource::Resource::RLIMIT_NOFILE,
            self.original.0,
            self.original.1,
        )
        .expect("restore the child's descriptor limit before startup cleanup");
    }
}
