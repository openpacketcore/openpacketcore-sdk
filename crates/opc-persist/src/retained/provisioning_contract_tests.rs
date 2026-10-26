use super::*;
use std::collections::BTreeMap;

const STEPS: &[&str] = &[
    "intent_created",
    "lock_created",
    "intent_written",
    "intent_synced",
    "intent_published",
    "intent_directory_synced",
    "database_created",
    "base_initialized",
    "consensus_initialized",
    "binding_stored",
    "database_written",
    "database_synced",
    "database_published",
    "database_directory_synced",
    "completion_created",
    "completion_written",
    "completion_synced",
    "record_written",
    "record_synced",
];

fn snapshot(path: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(path)
        .expect("directory")
        .map(|entry| {
            let entry = entry.expect("entry");
            (
                entry.file_name(),
                std::fs::read(entry.path()).expect("bytes"),
            )
        })
        .collect()
}

fn approved() -> RetainedConfigProvisionRequest {
    RetainedConfigProvisionRequest::new_authority(REQUEST).expect("request")
}

fn assert_completed_artifacts(path: &Path) {
    let mut actual: Vec<_> = snapshot(path).into_keys().collect();
    let mut expected = [
        "retained.sqlite",
        "retained.sqlite.opc-retained",
        "retained.sqlite.opc-retained-complete",
    ]
    .map(std::ffi::OsString::from);
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "exactly the completed artifacts, no leaks"
    );
}

#[test]
fn resume_never_reinitializes_an_established_missing_database() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(request(&path, false, REQUEST, &Arc::new(work())).expect("established"));
    std::fs::remove_file(&path).expect("database loss");
    let before = snapshot(dir.path());
    let retry = request(&path, true, REQUEST, &Arc::new(work()));
    assert!(
        matches!(retry, Err(RetainedConfigError::RecoveryRequired)),
        "resume must not mint fresh authority after established storage loss: {retry:?}"
    );
    assert!(!path.exists());
    assert_eq!(before, snapshot(dir.path()));
}

#[tokio::test]
async fn surviving_completion_prevents_legacy_create_or_open_after_intent_loss() {
    for database_lost in [true, false] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        drop(request(&path, false, REQUEST, &Arc::new(work())).expect("established"));
        std::fs::remove_file(lock_path(&path)).expect("intent loss");
        if database_lost {
            std::fs::remove_file(&path).expect("database loss");
        }
        let before = snapshot(dir.path());
        let legacy = SqliteBackend::open_with_audit_key(&path, true, 0, key()).await;
        assert!(
            legacy.is_err(),
            "completion requires retained admission even after intent loss: {legacy:?}"
        );
        assert_eq!(before, snapshot(dir.path()));
    }
}

#[test]
fn main_descriptor_is_closed_before_writer_exclusion_is_released() {
    use std::os::fd::AsRawFd;
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let parent = std::fs::File::open(dir.path()).expect("parent");
    let database = std::fs::File::create(&path).expect("database");
    let descriptor_path = format!("/proc/self/fd/{}", database.as_raw_fd());
    let lock_file = std::fs::File::create(lock_path(&path)).expect("lock");
    let mut lock = AdmissionFileLock::acquire(lock_file).expect("exclusive");
    let closed = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&closed);
    lock.before_unlock(move || {
        observed.store(
            std::fs::symlink_metadata(&descriptor_path).is_err(),
            Ordering::Release,
        );
    });
    let identity = file_identity(&parent, &lock, &database).expect("identity");
    drop(FileAdmission {
        path,
        parent,
        lock,
        database,
        completion: None,
        identity,
    });
    assert!(closed.load(Ordering::Acquire),
        "closing the old main descriptor after unlock could release a successor's SQLite POSIX locks");
}

#[test]
fn every_io_error_prefix_resumes_without_cleanup_or_overwrite() {
    for &step in STEPS {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let mut fault = work();
        fault.provision_fault = Some(Arc::new(move |observed| observed == step));
        assert!(
            request(&path, false, REQUEST, &Arc::new(fault)).is_err(),
            "{step}"
        );
        let before = snapshot(dir.path());
        if lock_path(&path).exists() {
            assert!(
                request(&path, true, [0x54; 32], &Arc::new(work())).is_err(),
                "{step}"
            );
            assert_eq!(before, snapshot(dir.path()), "conflict at {step}");
        }
        drop(request(&path, true, REQUEST, &Arc::new(work())).expect(step));
        assert_completed_artifacts(dir.path());
        drop(request(&path, true, REQUEST, &Arc::new(work())).expect("idempotent retry"));
    }
}

#[test]
fn extra_publication_boundaries_survive_process_loss() {
    for stage in [
        "intent_created",
        "intent_written",
        "intent_synced",
        "intent_published",
        "intent_directory_synced",
        "database_written",
        "database_published",
        "database_directory_synced",
        "completion_created",
        "completion_written",
        "completion_synced",
    ] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let output = std::process::Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "retained::provisioning_tests::transaction_crash_child",
                "--nocapture",
            ])
            .env("OPC_TRANSACTION_TEST_DATABASE", &path)
            .env("OPC_TRANSACTION_TEST_CRASH_STAGE", stage)
            .output()
            .expect("crash child");
        assert_eq!(output.status.code(), Some(92), "{stage}");
        drop(request(&path, true, REQUEST, &Arc::new(work())).expect(stage));
        assert_completed_artifacts(dir.path());
    }
}

#[test]
fn ordinary_reopen_does_not_finish_intent_and_conflicts_preserve_it() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut fault = work();
    fault.provision_fault = Some(Arc::new(|step| step == "intent_directory_synced"));
    assert!(request(&path, false, REQUEST, &Arc::new(fault)).is_err());
    let before = snapshot(dir.path());
    let reopen = OpenIntent::Transaction(approved(), provisioning::OpenMode::Reopen);
    assert!(matches!(
        open_authority_sync(options(&path), key(), reopen, &Arc::new(work())),
        Err(RetainedConfigError::RecoveryRequired)
    ));
    assert_eq!(before, snapshot(dir.path()));
    let resume = OpenIntent::Transaction(approved(), provisioning::OpenMode::Resume);
    for mutation in 0..4 {
        let mut candidate = options(&path);
        let mut candidate_key = key();
        match mutation {
            0 => candidate.binding.backing_identity = [0x91; 32],
            1 => candidate.binding.key_scope = [0x92; 32],
            2 => candidate_key = AuditKey::new([0x93; 32]).expect("wrong key"),
            _ => {
                candidate.binding.topology = crate::ConfigConsensusTopology::try_new(
                    crate::ConfigConsensusIdentity::new(
                        crate::ConfigConsensusClusterId::from_bytes([0x94; 32]),
                        crate::ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
                        crate::ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
                    ),
                    crate::ConfigConsensusNodeId::new(1).expect("node"),
                    std::collections::BTreeSet::from([
                        crate::ConfigConsensusNodeId::new(1).expect("node")
                    ]),
                )
                .expect("topology")
            }
        }
        assert!(matches!(
            open_authority_sync(candidate, candidate_key, resume, &Arc::new(work())),
            Err(RetainedConfigError::Rejected)
        ));
        assert_eq!(before, snapshot(dir.path()));
    }
    drop(request(&path, true, REQUEST, &Arc::new(work())).expect("resume"));
}

#[test]
fn foreign_partial_and_other_requests_are_never_adopted() {
    for suffix in [
        "",
        ".opc-retained",
        ".opc-retained-complete",
        "-wal",
        "-shm",
        "-journal",
    ] {
        for bytes in [b"".as_slice(), b"foreign partial input".as_slice()] {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            let mut artifact = path.as_os_str().to_os_string();
            artifact.push(suffix);
            std::fs::write(PathBuf::from(artifact), bytes).expect("foreign artifact");
            let before = snapshot(dir.path());
            assert!(request(&path, true, REQUEST, &Arc::new(work())).is_err());
            assert_eq!(before, snapshot(dir.path()));
        }
    }
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("implicit request"),
    );
    let before = snapshot(dir.path());
    assert!(request(&path, true, REQUEST, &Arc::new(work())).is_err());
    assert_eq!(before, snapshot(dir.path()));
    drop(
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
            .expect("other request preserved"),
    );
}

#[test]
fn reopen_requires_completion_and_resume_validates_before_completing() {
    for corrupt_database in [false, true] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let mut fault = work();
        fault.provision_fault = Some(Arc::new(|step| step == "database_directory_synced"));
        assert!(request(&path, false, REQUEST, &Arc::new(fault)).is_err());
        assert!(path.exists());
        if corrupt_database {
            std::fs::write(&path, b"foreign database").expect("corrupt database");
        }
        let before = snapshot(dir.path());
        assert!(matches!(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::Transaction(approved(), provisioning::OpenMode::Reopen),
                &Arc::new(work()),
            ),
            Err(RetainedConfigError::RecoveryRequired)
        ));
        assert_eq!(before, snapshot(dir.path()));
        let resumed = request(&path, true, REQUEST, &Arc::new(work()));
        if corrupt_database {
            assert!(resumed.is_err());
            assert_eq!(before, snapshot(dir.path()));
        } else {
            drop(resumed.expect("finish validated database"));
            assert_completed_artifacts(dir.path());
        }
    }
}

#[test]
fn invalid_or_replaced_completion_is_preserved_and_refused() {
    for truncate in [false, true] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        drop(request(&path, false, REQUEST, &Arc::new(work())).expect("established"));
        let completion = dir.path().join("retained.sqlite.opc-retained-complete");
        let mut bytes = std::fs::read(&completion).expect("completion");
        if truncate {
            bytes.truncate(1);
        } else {
            bytes[40] ^= 1;
        }
        std::fs::write(&completion, bytes).expect("fault");
        let before = snapshot(dir.path());
        for mode in [
            provisioning::OpenMode::Reopen,
            provisioning::OpenMode::Resume,
        ] {
            assert!(open_authority_sync(
                options(&path),
                key(),
                OpenIntent::Transaction(approved(), mode),
                &Arc::new(work()),
            )
            .is_err());
            assert_eq!(before, snapshot(dir.path()));
        }
    }
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = request(&path, false, REQUEST, &Arc::new(work())).expect("established");
    let completion = dir.path().join("retained.sqlite.opc-retained-complete");
    std::fs::rename(&completion, dir.path().join("previous-completion")).expect("replace");
    std::fs::copy(dir.path().join("previous-completion"), completion).expect("same bytes");
    let before = snapshot(dir.path());
    assert!(backend
        .conn()
        .blocking_lock()
        .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
        .is_err());
    assert_eq!(before, snapshot(dir.path()));
}

#[test]
fn bound_failure_keeps_only_resumable_intent() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut candidate = options(&path);
    candidate.max_validation_bytes = 1;
    assert!(matches!(
        open_authority_sync(
            candidate,
            key(),
            OpenIntent::Transaction(approved(), provisioning::OpenMode::Provision),
            &Arc::new(work())
        ),
        Err(RetainedConfigError::AdmissionBound)
    ));
    assert!(!path.exists());
    drop(request(&path, true, REQUEST, &Arc::new(work())).expect("bounded retry"));
}

#[test]
fn request_disposition_is_authenticated_and_repair_cannot_become_genesis() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let repair = RetainedConfigProvisionRequest::member_repair(REQUEST).expect("repair");
    let backend = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::Transaction(repair, provisioning::OpenMode::Provision),
        &Arc::new(work()),
    )
    .expect("repair provision");
    assert!(backend.retained_repair_only);
    drop(backend);
    let before = snapshot(dir.path());
    assert!(request(&path, true, REQUEST, &Arc::new(work())).is_err());
    assert_eq!(before, snapshot(dir.path()));
    let reopened = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::Transaction(repair, provisioning::OpenMode::Reopen),
        &Arc::new(work()),
    )
    .expect("repair reopen");
    assert!(reopened.retained_repair_only);
}

#[test]
fn competing_process_is_excluded() {
    if let Some(path) = std::env::var_os("OPC_TRANSACTION_TEST_COMPETING") {
        assert!(matches!(
            request(Path::new(&path), true, REQUEST, &Arc::new(work())),
            Err(RetainedConfigError::InUse)
        ));
        return;
    }
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = request(&path, false, REQUEST, &Arc::new(work())).expect("owner");
    let clone = backend.clone();
    drop(backend);
    let output = std::process::Command::new(std::env::current_exe().expect("binary"))
        .args([
            "--exact",
            "retained::provisioning_tests::contracts::competing_process_is_excluded",
        ])
        .env("OPC_TRANSACTION_TEST_COMPETING", &path)
        .output()
        .expect("competing child");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(clone);
    drop(request(&path, true, REQUEST, &Arc::new(work())).expect("released"));
}

#[tokio::test]
async fn cancelled_public_operation_joins_before_retry_and_cannot_transfer_late() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut operation =
        SqliteBackend::begin_provision_config_transaction(options(&path), key(), approved())
            .expect("begin");
    operation.cancel();
    assert!(operation.wait().await.is_err());
    assert!(matches!(
        operation.cancel_and_join().await,
        RetainedConfigOpenRetirement::Released { .. }
    ));
    assert!(operation.wait().await.is_err());
    let mut retry = SqliteBackend::begin_resume_config_provision(options(&path), key(), approved())
        .expect("resume");
    let backend = retry.wait().await.expect("recovered");
    assert!(matches!(
        retry.cancel_and_join().await,
        RetainedConfigOpenRetirement::BackendReturned
    ));
    drop(backend);
    let mut reopen =
        SqliteBackend::begin_reopen_config_transaction(options(&path), key(), approved())
            .expect("reopen");
    drop(reopen.wait().await.expect("completed store"));
}

#[tokio::test]
async fn expired_observer_retains_join_and_resume_ownership() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut candidate = options(&path);
    candidate.operation_timeout = Duration::from_nanos(1);
    let mut operation =
        SqliteBackend::begin_provision_config_transaction(candidate, key(), approved())
            .expect("begin");
    assert!(operation.wait().await.is_err());
    assert!(matches!(
        operation.cancel_and_join().await,
        RetainedConfigOpenRetirement::Released { .. }
    ));
    let mut retry = SqliteBackend::begin_resume_config_provision(options(&path), key(), approved())
        .expect("resume");
    drop(retry.wait().await.expect("recovered"));
}
