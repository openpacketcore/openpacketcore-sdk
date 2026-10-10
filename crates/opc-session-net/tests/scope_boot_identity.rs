//! Run process-wide key protection in a child, never in the Cargo test runner.

#[cfg(target_os = "linux")]
#[test]
fn protected_boot_keeps_proc_self_reads_available() {
    use opc_session_net::scope::BootIdentity;
    use std::{fs::File, os::fd::AsRawFd, os::unix::fs::MetadataExt};

    const CHILD: &str = "OPC_SCOPE_BOOT_PROTECTION_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let before = rustix::process::dumpable_behavior().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "protected_boot_keeps_proc_self_reads_available",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(rustix::process::dumpable_behavior().unwrap(), before);
        return;
    }
    let first = BootIdentity::generate().unwrap();
    let second = BootIdentity::generate().unwrap();
    assert_eq!(
        rustix::process::dumpable_behavior().unwrap(),
        rustix::process::DumpableBehavior::NotDumpable
    );
    assert_ne!(first.process_nonce(), &[0; 16]);
    assert_ne!(first.process_nonce(), second.process_nonce());
    assert_ne!(first.key_digest(), second.key_digest());
    assert_eq!(first.public_key().len(), 33);
    assert_eq!(format!("{first:?}"), "BootIdentity([redacted])");

    let image = File::open("/proc/self/exe").unwrap();
    let actual = image.metadata().unwrap();
    for path in [
        "/proc/self/exe".to_owned(),
        format!("/proc/{}/exe", std::process::id()),
        format!("/proc/self/fd/{}", image.as_raw_fd()),
    ] {
        let reopened = File::open(path).unwrap().metadata().unwrap();
        assert_eq!(
            (reopened.dev(), reopened.ino()),
            (actual.dev(), actual.ino())
        );
    }
    std::fs::read_link("/proc/self/exe").unwrap();
    std::fs::read_to_string(format!("/proc/self/fdinfo/{}", image.as_raw_fd())).unwrap();
    assert!(std::fs::read_dir("/proc/self/fd").unwrap().count() > 2);
    File::open("/proc/thread-self/ns/net").unwrap();
    let mapping = std::fs::read_dir("/proc/self/map_files")
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    std::fs::read_link(mapping.path()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("pin"), b"probe").unwrap();
    let fd = File::open(directory.path()).unwrap();
    assert_eq!(
        std::fs::read(format!("/proc/self/fd/{}/pin", fd.as_raw_fd())).unwrap(),
        b"probe"
    );
}

/// An abruptly lost predecessor cannot strand the next container on a lock file.
#[cfg(target_os = "linux")]
#[test]
fn process_exit_releases_scope_exclusion_without_removing_the_lock_file() {
    use opc_session_net::scope::{BootIdentity, ScopeBinding, ScopeProcess, StartupError};
    use opc_types::{NetworkFunctionKind, TenantId};
    use std::{
        fs::File,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    const MODE: &str = "OPC_SCOPE_EXCLUSION_MODE";
    const ROOT: &str = "OPC_SCOPE_EXCLUSION_ROOT";
    const TEST: &str = "process_exit_releases_scope_exclusion_without_removing_the_lock_file";
    if let Some(mode) = std::env::var_os(MODE) {
        let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
        let binding = ScopeBinding::new(
            [1; 32],
            TenantId::new("test").unwrap(),
            NetworkFunctionKind::new("scope").unwrap(),
            [2; 32],
        )
        .unwrap();
        let process = ScopeProcess::new(
            binding,
            [3; 16],
            BootIdentity::generate().unwrap(),
            File::open(&root).unwrap(),
        );
        if mode == "busy" {
            assert!(matches!(process, Err(StartupError::ExclusionBusy)));
            return;
        }
        let process = process.unwrap();
        let mut public = process.boot().process_nonce().to_vec();
        public.extend_from_slice(process.boot().public_key());
        std::fs::write(root.join(mode.to_string_lossy().as_ref()), public).unwrap();
        if mode == "hold" {
            loop {
                std::thread::park();
            }
        }
        return;
    }
    struct Reap(Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let root = tempfile::tempdir().unwrap();
    let command = |mode: &str| {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", TEST, "--nocapture"])
            .env(MODE, mode)
            .env(ROOT, root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        cmd
    };
    let mut first = Reap(command("hold").spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !root.path().join("hold").exists() {
        assert!(
            first.0.try_wait().unwrap().is_none(),
            "lock owner remains alive"
        );
        assert!(Instant::now() < deadline, "child publishes its ready boot");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        command("busy").status().unwrap().success(),
        "a second live boot is refused"
    );
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    assert!(
        command("after-exit").status().unwrap().success(),
        "OS process exit releases the existing lock"
    );
    assert_ne!(
        std::fs::read(root.path().join("hold")).unwrap(),
        std::fs::read(root.path().join("after-exit")).unwrap(),
        "a restart has a new nonce and key"
    );
    assert_eq!(
        std::fs::read_dir(root.path())
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".lock"))
            .count(),
        1,
        "no lock-file cleanup or replacement is required"
    );
}
