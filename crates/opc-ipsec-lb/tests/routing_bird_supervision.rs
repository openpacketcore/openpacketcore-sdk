#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use opc_ipsec_lb::{
    BirdAdapterConfig, BirdControlSocketAdapter, BirdDomainBinding, BirdProcessConfig,
    RoutingDomainTag, RoutingStackAdapter,
};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
const HELPER: &str = env!("CARGO_BIN_EXE_opc-bird-supervisor");

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    pid_file: PathBuf,
    ready_file: PathBuf,
    bird_wrapper: PathBuf,
    bird_config: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "opc-bird-supervision-{}-{id}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("fragments")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            root.join("fragments"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let socket = root.join("bird.ctl");
        let pid_file = root.join("bird.pid.observed");
        let ready_file = root.join("parent.ready");
        let bird_config = root.join("bird.conf");
        std::fs::write(&bird_config, "# synthetic BIRD config\n").unwrap();
        let bird_wrapper = root.join("fake-bird");
        let test_binary = std::env::current_exe().unwrap();
        let wrapper = format!(
            "#!/bin/sh\nexport OPC_FAKE_BIRD_SOCKET={}\nexport OPC_FAKE_BIRD_PID_FILE={}\nexport OPC_FAKE_BIRD_FRAGMENT_DIR={}\nexport OPC_FAKE_BIRD_KNOWN_ABSENCE_FAIL_FILE={}\nexec {} --ignored --exact fake_bird_child_entrypoint --nocapture\n",
            shell_quote(&socket),
            shell_quote(&pid_file),
            shell_quote(&root.join("fragments")),
            shell_quote(&root.join("known-absence.fail")),
            shell_quote(&test_binary),
        );
        std::fs::write(&bird_wrapper, wrapper).unwrap();
        let mut permissions = std::fs::metadata(&bird_wrapper).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&bird_wrapper, permissions).unwrap();
        Self {
            root,
            socket,
            pid_file,
            ready_file,
            bird_wrapper,
            bird_config,
        }
    }

    fn adapter_config(&self) -> BirdAdapterConfig {
        BirdAdapterConfig {
            socket_path: self.socket.clone(),
            fragment_dir: self.root.join("fragments"),
            domains: vec![BirdDomainBinding {
                domain: RoutingDomainTag::new(64_512),
                static_protocol: "opc_adv_64512".to_owned(),
                peer_protocols: Vec::new(),
            }],
            command_timeout: Duration::from_millis(500),
        }
    }

    fn process_config(&self) -> BirdProcessConfig {
        BirdProcessConfig {
            supervisor_helper_path: PathBuf::from(HELPER),
            bird_executable_path: self.bird_wrapper.clone(),
            bird_config_path: self.bird_config.clone(),
            startup_timeout: Duration::from_secs(3),
            shutdown_timeout: Duration::from_secs(2),
        }
    }

    fn child_pid(&self) -> rustix::process::Pid {
        let raw = std::fs::read_to_string(&self.pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        rustix::process::Pid::from_raw(raw).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn shell_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn process_exists(pid: rustix::process::Pid) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_pid()));
    if let Ok(stat) = stat {
        if stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().next())
            == Some("Z")
        {
            // A zombie has already closed every descriptor and BGP session;
            // only parent-side reaping remains.
            return false;
        }
    }
    rustix::process::test_kill_process(pid).is_ok()
}

async fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for test path");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_process_exit(pid: rustix::process::Pid) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while process_exists(pid) {
        assert!(
            Instant::now() < deadline,
            "supervised process remained alive past the test bound"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Ignored child entry point used by the synthetic foreground-BIRD wrapper.
#[test]
#[ignore]
fn fake_bird_child_entrypoint() {
    let socket = PathBuf::from(std::env::var_os("OPC_FAKE_BIRD_SOCKET").unwrap());
    let pid_file = PathBuf::from(std::env::var_os("OPC_FAKE_BIRD_PID_FILE").unwrap());
    let fragment_dir = PathBuf::from(std::env::var_os("OPC_FAKE_BIRD_FRAGMENT_DIR").unwrap());
    let known_absence_fail_file =
        PathBuf::from(std::env::var_os("OPC_FAKE_BIRD_KNOWN_ABSENCE_FAIL_FILE").unwrap());
    assert!(std::fs::read_dir(fragment_dir).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("opc-ipsec-lb-domain-")));
    let listener = UnixListener::bind(socket).unwrap();
    std::fs::write(pid_file, std::process::id().to_string()).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        stream.write_all(b"0001 BIRD 2 synthetic ready.\n").unwrap();
        let mut command = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut command)
            .unwrap();
        match command.trim_end() {
            "show status" => stream.write_all(b"1000 synthetic status\n").unwrap(),
            "configure soft" if known_absence_fail_file.exists() => stream
                .write_all(b"0004 Reconfiguration in progress\n")
                .unwrap(),
            "configure soft" => stream.write_all(b"0003 Reconfigured\n").unwrap(),
            "show protocols all" => stream.write_all(b"0000 \n").unwrap(),
            command if command.starts_with("show route protocol ") => {
                stream.write_all(b"0000 \n").unwrap();
            }
            _ => stream.write_all(b"9001 unsupported\n").unwrap(),
        }
    }
}

/// Ignored subprocess entry point that leaves behind a closed control socket.
#[test]
#[ignore]
fn create_stale_bird_socket_entrypoint() {
    let socket = PathBuf::from(std::env::var_os("OPC_STALE_BIRD_SOCKET").unwrap());
    let listener = UnixListener::bind(&socket).unwrap();
    drop(listener);
    assert!(socket.exists());
}

/// Ignored subprocess entry point that proves abrupt whole-process death.
#[test]
#[ignore]
fn supervised_parent_entrypoint() {
    let root = PathBuf::from(std::env::var_os("OPC_PARENT_ROOT").unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let fixture = Fixture {
            socket: root.join("bird.ctl"),
            pid_file: root.join("bird.pid.observed"),
            ready_file: root.join("parent.ready"),
            bird_wrapper: root.join("fake-bird"),
            bird_config: root.join("bird.conf"),
            root,
        };
        let adapter = BirdControlSocketAdapter::spawn_supervised(
            fixture.adapter_config(),
            fixture.process_config(),
        )
        .await
        .unwrap();
        wait_for_path(&fixture.pid_file).await;
        std::fs::write(
            &fixture.ready_file,
            fixture.child_pid().as_raw_pid().to_string(),
        )
        .unwrap();
        std::mem::forget(adapter);
        std::mem::forget(fixture);
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL)
            .unwrap();
    });
}

#[tokio::test]
async fn guard_drop_terminates_the_owned_bird_process() {
    let fixture = Fixture::new("guard-drop");
    let adapter = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    let pid = fixture.child_pid();
    assert!(process_exists(pid));

    drop(adapter);

    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn unexpected_bird_exit_invalidates_admission_and_probe() {
    let fixture = Fixture::new("unexpected-exit");
    let adapter = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    let pid = fixture.child_pid();
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
    wait_for_process_exit(pid).await;

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let probe = adapter.probe().await.unwrap();
        if !probe.process_supervision_ready {
            assert!(!probe.stack_reachable);
            assert!(!probe.mutation_ready);
            break;
        }
        assert!(Instant::now() < deadline, "admission was not invalidated");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn non_socket_control_path_fails_before_helper_spawn() {
    let fixture = Fixture::new("non-socket-path");
    std::fs::write(&fixture.socket, b"stale").unwrap();

    let result = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await;

    assert!(result.is_err());
    assert!(!fixture.pid_file.exists());
}

#[tokio::test]
async fn active_control_socket_is_never_unlinked_or_replaced() {
    let fixture = Fixture::new("active-socket");
    let listener = UnixListener::bind(&fixture.socket).unwrap();

    let result = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await;

    assert!(result.is_err());
    assert!(fixture.socket.exists());
    assert!(!fixture.pid_file.exists());
    drop(listener);
}

#[tokio::test]
async fn dead_owned_control_socket_is_reclaimed_before_spawn() {
    let fixture = Fixture::new("dead-socket");
    // The parent test process runs other spawn-heavy tests concurrently. If
    // it owns this listener, any child between fork and exec can transiently
    // inherit the descriptor and make the production liveness probe correctly
    // classify the socket as active. Create the stale inode in an exact child
    // that exits before the recovery path begins instead.
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "create_stale_bird_socket_entrypoint",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OPC_STALE_BIRD_SOCKET", &fixture.socket)
        .status()
        .unwrap();
    assert!(status.success(), "stale-socket child must exit cleanly");
    assert!(fixture.socket.exists());

    let adapter = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    let pid = fixture.child_pid();
    assert!(process_exists(pid));

    adapter.shutdown_supervised().await.unwrap();
    drop(adapter);
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn stale_owned_fragments_are_removed_before_the_child_can_start() {
    let fixture = Fixture::new("pre-spawn-fragment-cleanup");
    let stale = fixture
        .root
        .join("fragments/opc-ipsec-lb-domain-64512.conf");
    std::fs::write(
        &stale,
        b"# opc-ipsec-lb-routing-fragment-v1\n# routing-domain: 64512\n# static-protocol: opc_adv_64512\nprotocol static opc_adv_64512 {\n    ipv4;\n    route 203.0.113.10/32 blackhole;\n}\n",
    )
    .unwrap();

    let adapter = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    assert!(!stale.exists());

    let pid = fixture.child_pid();
    adapter.shutdown_supervised().await.unwrap();
    drop(adapter);
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn failed_startup_known_absence_fail_stops_the_owned_bird_process() {
    let fixture = Fixture::new("known-absence-fail-stop");
    let adapter = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    let pid = fixture.child_pid();
    std::fs::write(fixture.root.join("known-absence.fail"), b"fail closed").unwrap();

    assert!(adapter.establish_known_absence().await.is_err());
    let probe = adapter.probe().await.unwrap();
    assert!(!probe.process_supervision_ready);
    assert!(!probe.stack_reachable);
    assert!(!probe.mutation_ready);
    wait_for_process_exit(pid).await;

    // The invalidated admission cannot be reused for a later mutation.
    assert!(adapter.establish_known_absence().await.is_err());
}

#[tokio::test]
async fn malformed_owned_fragment_prevents_child_launch() {
    let fixture = Fixture::new("pre-spawn-malformed-fragment");
    let stale = fixture
        .root
        .join("fragments/opc-ipsec-lb-domain-64512.conf");
    std::fs::write(
        &stale,
        b"# opc-ipsec-lb-routing-fragment-v1\n# routing-domain: 64512\n# static-protocol: opc_adv_64512\nprotocol static opc_adv_64512 {\n    import all;\n}\n",
    )
    .unwrap();

    let result = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await;
    assert!(result.is_err());
    assert!(!fixture.pid_file.exists());
    assert!(stale.exists());
}

#[tokio::test]
async fn crashed_child_restarts_after_dead_socket_cleanup() {
    let fixture = Fixture::new("crash-restart");
    let adapter = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    let first_pid = fixture.child_pid();
    rustix::process::kill_process(first_pid, rustix::process::Signal::KILL).unwrap();
    wait_for_process_exit(first_pid).await;
    adapter.shutdown_supervised().await.unwrap();
    drop(adapter);

    std::fs::remove_file(&fixture.pid_file).unwrap();
    assert!(fixture.socket.exists());
    let restarted = BirdControlSocketAdapter::spawn_supervised(
        fixture.adapter_config(),
        fixture.process_config(),
    )
    .await
    .unwrap();
    wait_for_path(&fixture.pid_file).await;
    let restarted_pid = fixture.child_pid();
    assert!(process_exists(restarted_pid));

    restarted.shutdown_supervised().await.unwrap();
    drop(restarted);
    wait_for_process_exit(restarted_pid).await;
}

#[test]
fn process_config_rejects_unbounded_or_credential_changing_inputs() {
    let fixture = Fixture::new("invalid-process-config");
    let valid = fixture.process_config();
    valid.validate().unwrap();

    let mut relative = valid.clone();
    relative.bird_config_path = PathBuf::from("bird.conf");
    assert!(relative.validate().is_err());

    let mut missing = valid.clone();
    missing.bird_executable_path = fixture.root.join("missing-bird");
    assert!(missing.validate().is_err());

    let mut zero_startup = valid.clone();
    zero_startup.startup_timeout = Duration::ZERO;
    assert!(zero_startup.validate().is_err());

    let mut excessive_shutdown = valid.clone();
    excessive_shutdown.shutdown_timeout = Duration::from_secs(31);
    assert!(excessive_shutdown.validate().is_err());

    let mut permissions = std::fs::metadata(&fixture.bird_wrapper)
        .unwrap()
        .permissions();
    permissions.set_mode(0o4700);
    std::fs::set_permissions(&fixture.bird_wrapper, permissions).unwrap();
    assert!(valid.validate().is_err());
}

#[tokio::test]
async fn abrupt_service_process_death_kills_bird_without_drop() {
    let fixture = Fixture::new("process-death");
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--ignored")
        .arg("--exact")
        .arg("supervised_parent_entrypoint")
        .arg("--nocapture")
        .env("OPC_PARENT_ROOT", &fixture.root)
        .status()
        .unwrap();
    assert!(!status.success(), "parent harness must die by SIGKILL");
    wait_for_path(&fixture.ready_file).await;
    let raw = std::fs::read_to_string(&fixture.ready_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    let pid = rustix::process::Pid::from_raw(raw).unwrap();
    wait_for_process_exit(pid).await;
}

#[tokio::test]
async fn spawning_thread_death_triggers_helper_parent_death_signal() {
    let fixture = Fixture::new("thread-death");
    let helper = PathBuf::from(HELPER);
    let bird = fixture.bird_wrapper.clone();
    let config = fixture.bird_config.clone();
    let socket = fixture.socket.clone();
    let pid_file = fixture.pid_file.clone();
    let thread = std::thread::spawn(move || {
        let expected_parent = rustix::process::getpid().as_raw_pid().to_string();
        let mut child = Command::new(helper)
            .arg("--expected-parent-pid")
            .arg(expected_parent)
            .arg("--bird-executable")
            .arg(bird)
            .arg("--config")
            .arg(config)
            .arg("--control-socket")
            .arg(socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                b"OPC_BIRD_SUPERVISOR 1 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
            )
            .unwrap();
        let mut response = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut response)
            .unwrap();
        assert!(response.starts_with("OPC_BIRD_SUPERVISOR_READY 1 "));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !pid_file.exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let raw = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(raw).unwrap();
        // Returning the process handle ends this exact spawning thread before
        // the caller waits. That thread exit must deliver the helper's
        // PDEATHSIG to BIRD, while retaining the handle lets the test reap the
        // terminated child instead of leaving a zombie.
        (pid, child)
    });
    let (pid, mut child) = thread.join().unwrap();

    wait_for_process_exit(pid).await;
    child.wait().unwrap();
}

#[test]
fn helper_rejects_a_parent_pid_mismatch_before_handshake() {
    let fixture = Fixture::new("wrong-parent");
    let wrong_parent = rustix::process::getpid().as_raw_pid().saturating_add(1);
    let status = Command::new(HELPER)
        .arg("--expected-parent-pid")
        .arg(wrong_parent.to_string())
        .arg("--bird-executable")
        .arg(&fixture.bird_wrapper)
        .arg("--config")
        .arg(&fixture.bird_config)
        .arg("--control-socket")
        .arg(&fixture.socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!fixture.pid_file.exists());
}

#[test]
fn helper_rejects_an_unknown_handshake_version_before_exec() {
    let fixture = Fixture::new("wrong-handshake-version");
    let parent = rustix::process::getpid().as_raw_pid().to_string();
    let mut child = Command::new(HELPER)
        .arg("--expected-parent-pid")
        .arg(parent)
        .arg("--bird-executable")
        .arg(&fixture.bird_wrapper)
        .arg("--config")
        .arg(&fixture.bird_config)
        .arg("--control-socket")
        .arg(&fixture.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(
            b"OPC_BIRD_SUPERVISOR 2 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .unwrap();
    drop(stdin);

    assert!(!child.wait().unwrap().success());
    assert!(!fixture.pid_file.exists());
}
