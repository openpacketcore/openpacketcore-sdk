//! Hold real file calls in a child so the production sealing future is exercised.
//! The preload fixture never changes the syscall result or runs in other tests.

use super::*;
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use tokio::io::AsyncReadExt;

const CHILD_ROOT: &str = "OPC_SNAPSHOT_IO_CHILD_ROOT";

#[test]
fn timed_out_snapshot_directory_validation_retains_file_work_ownership() {
    run_file_io_probe(
        "timed_out_snapshot_directory_validation_retains_file_work_ownership",
        "directory",
    );
}

#[test]
fn timed_out_snapshot_publication_fence_retains_file_work_ownership() {
    run_file_io_probe(
        "timed_out_snapshot_publication_fence_retains_file_work_ownership",
        "publication",
    );
}

#[test]
fn cancelled_snapshot_return_retains_file_work_ownership() {
    run_file_io_probe(
        "cancelled_snapshot_return_retains_file_work_ownership",
        "return",
    );
}

#[test]
fn timed_out_snapshot_hash_retains_file_work_ownership() {
    run_file_io_probe(
        "timed_out_snapshot_hash_retains_file_work_ownership",
        "read",
    );
}

#[test]
fn timed_out_snapshot_fsync_retains_file_work_ownership() {
    run_file_io_probe(
        "timed_out_snapshot_fsync_retains_file_work_ownership",
        "fsync",
    );
}

#[test]
fn timed_out_snapshot_verification_retains_file_work_ownership() {
    run_file_io_probe(
        "timed_out_snapshot_verification_retains_file_work_ownership",
        "verify",
    );
}

fn run_file_io_probe(test: &str, operation: &str) {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("file I/O probe runtime")
            .block_on(held_file_work(Path::new(&root), operation));
        return;
    }
    let directory = tempfile::tempdir().expect("file I/O probe directory");
    let source = directory.path().join("hold.c");
    let library = directory.path().join("hold.so");
    std::fs::write(&source, include_str!("snapshot_file_io_hold.c"))
        .expect("write syscall fixture");
    let mut compiler = Command::new("cc");
    #[cfg(target_pointer_width = "32")]
    compiler.arg("-m32");
    assert!(compiler
        .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&library)
        .arg(&source)
        .test_status()
        .expect("compile syscall fixture")
        .success());
    let test = format!(
        "{}::{test}",
        module_path!().strip_prefix("opc_session_store::").unwrap()
    );
    let output = Command::new("timeout")
        .arg("30s")
        .arg(std::env::current_exe().expect("test executable"))
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env(CHILD_ROOT, directory.path())
        .env("OPC_SNAPSHOT_IO_TARGET", directory.path().join("target"))
        .env(
            "OPC_SNAPSHOT_IO_SOCKET",
            directory.path().file_name().unwrap(),
        )
        .env("LD_PRELOAD", library)
        .test_output()
        .expect("run isolated real I/O probe");
    assert!(
        output.status.success(),
        "{operation} ownership probe failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn held_file_work(root: &Path, phase: &str) {
    if phase == "return" {
        held_snapshot_return(root).await;
        return;
    }
    if phase == "directory" || phase == "publication" {
        held_directory_validation(root, phase == "publication").await;
        return;
    }
    let operation = if phase == "verify" { "read" } else { phase };
    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(root.file_name().unwrap().as_bytes())
            .expect("abstract I/O progress address");
    let listener =
        std::os::unix::net::UnixListener::bind_addr(&address).expect("I/O progress listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let listener = tokio::net::UnixListener::from_std(listener).expect("async I/O listener");
    let backend = SqliteSessionBackend::open(root.join("sessions.sqlite")).expect("probe backend");
    let profiles: &[bool] = if phase == "verify" {
        &[false]
    } else {
        &[false, true]
    };
    for (index, fixed_profile) in
        (0..4).flat_map(|index| profiles.iter().map(move |&fixed| (index, fixed)))
    {
        let directory = root.join(format!("snapshots-{index}-{fixed_profile}"));
        let lease = acquire_snapshot_directory_lease(&backend, &directory)
            .await
            .expect("snapshot namespace lease");
        let namespace_owner = Arc::downgrade(&lease);
        let raw_name = std::ffi::OsStr::new("vacuum.sqlite");
        let mut raw =
            PinnedSqliteFile::create_new_in_namespace(Arc::clone(&lease.namespace), raw_name)
                .expect("compacted snapshot inode");
        std::io::Write::write_all(
            &mut raw.file().try_clone().expect("payload descriptor"),
            &[0x35; 4096],
        )
        .expect("compacted payload");
        raw = raw.refresh_identity().expect("compacted identity");
        let raw_path = directory.join(raw_name);
        let (raw, sealed) = if phase == "verify" {
            let sealed = seal_snapshot_database_in_place_sync(
                raw,
                false,
                SnapshotIntegrityPolicy::FsVerity,
                None,
            )
            .expect("prepare verification envelope before arming the hold");
            (None, Some(sealed))
        } else {
            (Some(raw), None)
        };
        let held_descriptor = raw
            .as_ref()
            .map(|raw| raw.file().as_raw_fd())
            .unwrap_or_else(|| sealed.as_ref().unwrap().0.as_raw_fd());
        std::fs::write(
            root.join("target"),
            format!("{held_descriptor} {operation}\n"),
        )
        .expect("arm exact-descriptor syscall hold");
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let snapshot_guard = LiveTerminalRecoveryHandoffGate {
            snapshot_gate: Arc::clone(&gate),
            _guard: Arc::new(Arc::clone(&gate).lock_owned().await),
            serving_guard: None,
        };
        let owner = ConsensusStorageShutdownGuard::tracked();
        let shutdown = owner.observer().expect("shutdown observer");
        let attempt = SnapshotBuildAttempt::new(Duration::from_millis(100));
        attempt.start().expect("start attempt");
        let cancel = CancelSnapshotAttempt(Arc::clone(&attempt));
        let work = SnapshotIntegrityWork {
            _gate: SnapshotIntegrityGate::Mutation {
                _guard: snapshot_guard,
            },
            _lease: lease,
            attempt: Some(Arc::clone(&attempt)),
            _shutdown: Some(Arc::new(owner)),
        };
        let final_path = directory.join("snapshot.opc");
        let verify_path = raw_path.clone();
        let mut seal = tokio::spawn(async move {
            if let Some((file, pin, checksum, length, cleanup)) = sealed {
                verify_built_snapshot(file, pin, verify_path, checksum, length, cleanup, work)
                    .await
                    .map(|_| ())
            } else {
                seal_snapshot_database_in_place(
                    raw.expect("unsealed probe input"),
                    &final_path,
                    fixed_profile,
                    SnapshotIntegrityPolicy::FsVerity,
                    Some(work),
                )
                .await
                .map(|_| ())
            }
        });
        let (mut channel, _) = tokio::select! {
            biased;
            entered = listener.accept() => entered.expect("actual syscall entered"),
            result = &mut seal => panic!("sealing finished before held {operation}: {}", result.is_ok()),
        };
        let mut signal = [0];
        channel
            .read_exact(&mut signal)
            .await
            .expect("syscall start signal");
        assert_eq!(signal, [b'S']);
        if index < 3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            attempt.stalled().await;
            assert!(attempt.expired());
        } else {
            shutdown.stop_snapshot_builds();
            shutdown.0.snapshot_build.stopped().await;
        }
        // Both expiry and shutdown drop the unpublished attempt observer.
        drop(cancel);
        seal.abort();
        assert!(matches!(seal.await, Err(error) if error.is_cancelled()));
        let gate_retained = Arc::clone(&gate).try_lock_owned().is_err();
        let namespace_retained = namespace_owner.upgrade().is_some();
        let artifact_retained = raw_path.exists();
        let mut waiting = Box::pin(tokio::time::timeout(
            Duration::from_millis(20),
            shutdown.wait(),
        ));
        let shutdown_pending = futures_util::poll!(&mut waiting).is_pending();
        let shutdown_bounded = if shutdown_pending {
            tokio::time::advance(Duration::from_millis(20)).await;
            waiting.await.is_err()
        } else {
            false
        };
        // Disarm before release so later calls on the same descriptor proceed.
        std::fs::remove_file(root.join("target")).expect("disarm syscall hold");
        channel.write_all(b"R").await.expect("release real syscall");
        channel
            .read_exact(&mut signal)
            .await
            .expect("syscall completion signal");
        assert_eq!(signal, [b'F']);
        drop(channel);
        let released = tokio::time::timeout(Duration::from_secs(5), Arc::clone(&gate).lock_owned())
            .await
            .expect("physical worker releases gate");
        drop(released);
        tokio::time::timeout(Duration::from_secs(1), shutdown.wait())
            .await
            .expect("shutdown observes actual worker exit");
        assert!(
            gate_retained,
            "attempt {index}: {operation} released its worker gate before physical completion"
        );
        assert!(
            namespace_retained,
            "attempt {index}: {operation} retired its namespace owner while running"
        );
        assert!(
            artifact_retained,
            "attempt {index}: {operation} unlinked its exact artifact while still using it"
        );
        assert!(
            shutdown_pending && shutdown_bounded,
            "attempt {index}: shutdown completed while {operation} still ran"
        );
        assert!(
            !raw_path.exists(),
            "cancelled work must clean its exact unpublished artifact before releasing the gate"
        );
        assert!(
            namespace_owner.upgrade().is_none(),
            "completed work releases its namespace lease"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn snapshot_publication_wait_scales_with_current_snapshot() {
    let directory = tempfile::tempdir().expect("publication wait directory");
    let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
        .expect("publication wait backend");
    let (_log, mut state_machine) = open(
        &backend,
        directory.path().join("snapshots"),
        identity(1),
        expected_members(),
    )
    .await
    .expect("publication wait storage");
    drop(
        state_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap(),
    );
    let core = state_machine.core.clone();
    let length = {
        let conn = core.conn.lock().await;
        core.read_selected_snapshot(&conn).unwrap().unwrap().3
    };
    assert!(length > SNAPSHOT_FOOTER_BYTES);
    let serving = Arc::clone(&core.snapshot_serving_gate).lock_owned().await;
    let publication = Arc::new(SnapshotArtifactGate::new());
    publication.arm();
    state_machine
        .shutdown_guard
        .observer()
        .unwrap()
        .pause_next_snapshot_publication_for_test(Arc::clone(&publication));
    let grace = snapshot_build::SNAPSHOT_BUILD_STALL_TIMEOUT;
    let attempt = SnapshotBuildAttempt::new(grace);
    let mut builder = state_machine.get_snapshot_builder().await;
    let mut build = Box::pin(builder.build_snapshot_attempt(Arc::clone(&attempt)));
    tokio::select! {
        () = publication.wait_started() => {},
        result = &mut build => panic!("build finished before publication wait: {}", result.is_ok()),
    }
    publication.release();
    assert!(futures_util::poll!(&mut build).is_pending());
    // Charge the real selected image, whose admission owns the serving gate.
    // Half its existing 1 s/MiB allowance extends beyond the unchanged grace.
    let allowance = Duration::from_nanos(length * 1_000_000_000 / (1024 * 1024));
    tokio::time::advance(grace + allowance / 2).await;
    let survived = !attempt.cancelled();
    drop(serving);
    let result = build.await;
    assert!(survived, "publication wait discarded a verified candidate within the current snapshot's size allowance");
    result.expect("the same candidate publishes after current admission completes");
}

async fn held_snapshot_return(root: &Path) {
    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(root.file_name().unwrap().as_bytes())
            .expect("abstract return-read progress address");
    let listener = std::os::unix::net::UnixListener::bind_addr(&address).unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let backend = SqliteSessionBackend::open(root.join("sessions.sqlite")).unwrap();
    let (log, mut state_machine) = open(
        &backend,
        root.join("snapshots"),
        identity(1),
        expected_members(),
    )
    .await
    .unwrap();
    let core = state_machine.core.clone();
    let namespace_owner = Arc::downgrade(&state_machine._snapshot_directory_lease);
    let shutdown = state_machine.shutdown_guard.observer().unwrap();
    let returning = Arc::new(SnapshotArtifactGate::new());
    returning.arm();
    let hook_directory =
        snapshot_namespace_test_hook_directory(&state_machine._snapshot_directory_lease);
    let _hook = FixedSnapshotReturnGateGuard::install(hook_directory, Arc::clone(&returning));
    let mut builder = state_machine.get_snapshot_builder().await;
    drop(log);
    drop(state_machine);
    let mut build = tokio::spawn(async move { builder.build_snapshot().await });
    tokio::select! {
        () = returning.wait_started() => {},
        result = &mut build => panic!("build finished before return gate: {}", result.is_ok()),
    }
    let current = {
        let conn = core.conn.lock().await;
        core.read_selected_snapshot(&conn).unwrap().unwrap()
    };
    let path = core.snapshot_dir.join(&current.1);
    let held_file = std::fs::File::open(&path).unwrap();
    std::fs::write(
        root.join("target"),
        format!("{} inode-read\n", held_file.as_raw_fd()),
    )
    .unwrap();
    returning.release();
    let (mut channel, _) = tokio::select! {
        entered = listener.accept() => entered.expect("real post-publication read entered"),
        result = &mut build => panic!("build finished before return read: {}", result.is_ok()),
    };
    let mut signal = [0];
    channel.read_exact(&mut signal).await.unwrap();
    assert_eq!(signal, [b'S']);
    // The committed build cannot be retried. Even dropping its observer must
    // retain ownership through cleanup and every read needed to return it.
    shutdown.stop_snapshot_builds();
    build.abort();
    assert!(matches!(build.await, Err(error) if error.is_cancelled()));
    let gate_retained = core.snapshot_gate.try_lock().is_err();
    let namespace_retained = namespace_owner.upgrade().is_some();
    let mut waiting = Box::pin(tokio::time::timeout(
        Duration::from_millis(20),
        shutdown.wait(),
    ));
    let shutdown_pending = futures_util::poll!(&mut waiting).is_pending();
    let shutdown_bounded = if shutdown_pending {
        tokio::time::advance(Duration::from_millis(20)).await;
        waiting.await.is_err()
    } else {
        false
    };
    std::fs::remove_file(root.join("target")).unwrap();
    channel.write_all(b"R").await.unwrap();
    channel.read_exact(&mut signal).await.unwrap();
    assert_eq!(signal, [b'F']);
    drop(channel);
    drop(
        tokio::time::timeout(
            Duration::from_secs(5),
            Arc::clone(&core.snapshot_gate).lock_owned(),
        )
        .await
        .expect("physical return work releases gate"),
    );
    tokio::time::timeout(Duration::from_secs(1), shutdown.wait())
        .await
        .unwrap();
    assert!(
        gate_retained,
        "snapshot return released its worker gate before physical completion"
    );
    assert!(
        namespace_retained,
        "snapshot return retired its namespace owner while running"
    );
    assert!(
        shutdown_pending && shutdown_bounded,
        "shutdown completed while snapshot return read still ran"
    );
    assert!(
        path.exists(),
        "committed snapshot survives caller cancellation"
    );
    let conn = core.conn.lock().await;
    assert_eq!(core.read_selected_snapshot(&conn).unwrap(), Some(current));
    assert!(
        namespace_owner.upgrade().is_none(),
        "completed return releases its namespace lease"
    );
}

async fn held_directory_validation(root: &Path, publication: bool) {
    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(root.file_name().unwrap().as_bytes())
            .expect("abstract directory-read progress address");
    let listener =
        std::os::unix::net::UnixListener::bind_addr(&address).expect("I/O progress listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let listener = tokio::net::UnixListener::from_std(listener).expect("async I/O listener");
    for index in 0..4 {
        let backend = SqliteSessionBackend::open(root.join(format!("sessions-{index}.sqlite")))
            .expect("directory probe backend");
        let (log, mut state_machine) = open(
            &backend,
            root.join(format!("snapshots-{index}")),
            identity(1),
            expected_members(),
        )
        .await
        .expect("directory probe storage");
        let core = state_machine.core.clone();
        let lease = Arc::clone(&state_machine._snapshot_directory_lease);
        drop(
            state_machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("publish current snapshot before arming hold"),
        );
        drop(log);
        drop(state_machine);
        let current = {
            let conn = core.conn.lock().await;
            core.read_selected_snapshot(&conn)
                .expect("current metadata")
                .expect("published current")
        };
        let path = core.snapshot_dir.join(&current.1);
        let held_file = std::fs::File::open(&path).expect("hold current inode identity");
        let operation = if publication { "open" } else { "read" };
        std::fs::write(
            root.join("target"),
            format!("{} inode-{operation}\n", held_file.as_raw_fd()),
        )
        .expect("arm exact-inode directory read hold");
        let namespace_owner = Arc::downgrade(&lease);
        let gate = Arc::clone(&core.snapshot_gate);
        let snapshot_guard = LiveTerminalRecoveryHandoffGate {
            snapshot_gate: Arc::clone(&gate),
            _guard: Arc::new(Arc::clone(&gate).lock_owned().await),
            serving_guard: if publication {
                Some(Arc::new(
                    Arc::clone(&core.snapshot_serving_gate).lock_owned().await,
                ))
            } else {
                None
            },
        };
        let owner = ConsensusStorageShutdownGuard::tracked();
        let shutdown = owner.observer().expect("shutdown observer");
        let attempt = SnapshotBuildAttempt::new(Duration::from_millis(100));
        attempt.start().expect("start directory validation attempt");
        let cancel = CancelSnapshotAttempt(Arc::clone(&attempt));
        let work = SnapshotIntegrityWork {
            _gate: SnapshotIntegrityGate::Mutation {
                _guard: snapshot_guard,
            },
            _lease: Arc::clone(&lease),
            attempt: Some(Arc::clone(&attempt)),
            _shutdown: Some(Arc::new(owner)),
        };
        let validation_core = core.clone();
        let mut validation = tokio::spawn(async move {
            if publication {
                let consumer = LiveTerminalRecoveryHandoffConsumer::from_live_snapshot_owner(
                    &validation_core,
                    &lease,
                );
                let SnapshotIntegrityGate::Mutation { _guard: guard } = &work._gate else {
                    unreachable!("mutation ownership fixture")
                };
                let result = consumer
                    .acquire_publication_connection(guard)
                    .await
                    .map(|_| 0);
                drop(work);
                result
            } else {
                validate_and_clean_snapshot_directory_with_retention(
                    &validation_core,
                    Some(&lease),
                    Some(work),
                )
                .await
            }
        });
        let (mut channel, _) = tokio::select! {
            biased;
            entered = listener.accept() => entered.expect("actual directory read entered"),
            result = &mut validation => panic!("validation finished before held read: {result:?}"),
        };
        let mut signal = [0];
        channel
            .read_exact(&mut signal)
            .await
            .expect("read start signal");
        assert_eq!(signal, [b'S']);
        if index < 3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            attempt.stalled().await;
            assert!(attempt.expired());
        } else {
            shutdown.stop_snapshot_builds();
            shutdown.0.snapshot_build.stopped().await;
        }
        drop(cancel);
        validation.abort();
        assert!(matches!(validation.await, Err(error) if error.is_cancelled()));
        let gate_retained = Arc::clone(&gate).try_lock_owned().is_err();
        let serving_retained = core.snapshot_serving_gate.try_lock().is_err();
        let namespace_retained = namespace_owner.upgrade().is_some();
        let mut waiting = Box::pin(tokio::time::timeout(
            Duration::from_millis(20),
            shutdown.wait(),
        ));
        let shutdown_pending = futures_util::poll!(&mut waiting).is_pending();
        let shutdown_bounded = if shutdown_pending {
            tokio::time::advance(Duration::from_millis(20)).await;
            waiting.await.is_err()
        } else {
            false
        };
        // Release the physical call before asserting, including on the RED.
        std::fs::remove_file(root.join("target")).expect("disarm syscall hold");
        channel
            .write_all(b"R")
            .await
            .expect("release directory read");
        channel
            .read_exact(&mut signal)
            .await
            .expect("read completion signal");
        assert_eq!(signal, [b'F']);
        drop(channel);
        drop(
            tokio::time::timeout(Duration::from_secs(5), Arc::clone(&gate).lock_owned())
                .await
                .expect("physical scan releases gate"),
        );
        tokio::time::timeout(Duration::from_secs(1), shutdown.wait())
            .await
            .expect("shutdown observes physical scan exit");
        assert!(
            gate_retained,
            "attempt {index}: directory {operation} released its worker gate before physical completion"
        );
        if publication {
            assert!(
                serving_retained,
                "publication fence releases serving exclusion only after physical completion"
            );
        }
        assert!(
            namespace_retained,
            "attempt {index}: directory read retired its namespace owner while running"
        );
        assert!(
            shutdown_pending && shutdown_bounded,
            "attempt {index}: shutdown completed while directory read still ran"
        );
        assert!(
            path.exists(),
            "cancelled validation must retain the published snapshot"
        );
        let conn = core.conn.lock().await;
        assert_eq!(core.read_selected_snapshot(&conn).unwrap(), Some(current));
        assert!(
            namespace_owner.upgrade().is_none(),
            "completed scan releases its namespace lease"
        );
    }
}
