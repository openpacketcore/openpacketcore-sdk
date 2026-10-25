use super::*;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusIdentity, ConfigConsensusNodeId,
};
use std::collections::{BTreeMap, BTreeSet};

fn options(path: &Path) -> RetainedConfigOptions {
    let node = ConfigConsensusNodeId::new(1).expect("node");
    let topology = ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x31; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("topology");
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology, [0x41; 32], [0x42; 32]).expect("binding"),
        RetainedConfigDurability::Ephemeral,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("options")
}

fn key() -> AuditKey {
    AuditKey::new([0x71; 32]).expect("key")
}
fn work() -> AdmissionWork {
    AdmissionWork {
        cancelled: AtomicBool::new(false),
        mutated: AtomicBool::new(false),
        deadline: Instant::now() + Duration::from_secs(30),
        hook: None,
        lock_hook: None,
        completion_hook: None,
        fault: None,
    }
}
/// The crash child is gone, so its exclusive admission lock must be free.
fn lock_is_free(path: &Path) -> bool {
    match open_file(&lock_path(path), true, false) {
        Ok(file) => match AdmissionFileLock::acquire(file) {
            Ok(lock) => {
                drop(lock);
                true
            }
            Err(RetainedConfigError::InUse) => false,
            Err(_) => false,
        },
        Err(RetainedConfigError::RecoveryRequired) => true,
        Err(_) => false,
    }
}

fn files(path: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(path)
        .expect("files")
        .map(|entry| {
            let entry = entry.expect("file");
            (
                entry.file_name(),
                std::fs::read(entry.path()).expect("bytes"),
            )
        })
        .collect()
}

// dup and fork retain the same open file description. Keep a safe duplicate
// alive to model a concurrent preflight child between fork and close-on-exec,
// without unsafe fork calls or scheduler-dependent sleeps in the detector.
fn capture_inherited_lock(work: &mut AdmissionWork) -> Arc<std::sync::Mutex<Option<File>>> {
    let inherited = Arc::new(std::sync::Mutex::new(None));
    let target = Arc::clone(&inherited);
    work.lock_hook = Some(Arc::new(move |lock| {
        *target.lock().expect("capture") = Some(lock.try_clone().expect("duplicate description"));
    }));
    inherited
}

#[test]
fn backend_release_does_not_wait_for_an_unrelated_inherited_descriptor() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut admission = work();
    let inherited = capture_inherited_lock(&mut admission);
    let backend = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::NewAuthority,
        &Arc::new(admission),
    )
    .expect("provision");
    let current_worker = backend.conn().try_lock_owned().expect("detached worker");
    drop(backend);
    assert!(
        matches!(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work())),
            Err(RetainedConfigError::InUse)
        ),
        "a live SDK owner must retain the lock"
    );
    drop(current_worker);
    let successor =
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
            .expect("released SDK owner must not await an unrelated inherited descriptor");
    drop(inherited.lock().expect("capture").take());
    assert!(
        matches!(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work())),
            Err(RetainedConfigError::InUse)
        ),
        "closing an old duplicate must not release the successor's lock"
    );
    drop(successor);
}

#[test]
fn rejected_admission_releases_its_lock_despite_an_inherited_descriptor() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("provision"),
    );
    let before = files(dir.path());
    let mut admission = work();
    let inherited = capture_inherited_lock(&mut admission);
    let mut wrong = options(&path);
    wrong.binding.backing_identity = [0x43; 32];
    assert!(matches!(
        open_authority_sync(
            wrong.clone(),
            key(),
            OpenIntent::Reopen,
            &Arc::new(admission)
        ),
        Err(RetainedConfigError::Rejected)
    ));
    assert!(
        matches!(
            open_authority_sync(wrong, key(), OpenIntent::Reopen, &Arc::new(work())),
            Err(RetainedConfigError::Rejected)
        ),
        "a completed rejection must not leave an inherited lock behind"
    );
    assert_eq!(before, files(dir.path()));
    drop(inherited);
}

#[test]
fn sqlite_close_keeps_admission_after_authorizer_removal() {
    struct CloseProbe {
        path: PathBuf,
        saw_lock: Arc<AtomicBool>,
    }
    impl Drop for CloseProbe {
        fn drop(&mut self) {
            let file = open_file(&self.path, true, false).expect("lock file");
            let result =
                rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive);
            self.saw_lock.store(
                result == Err(rustix::io::Errno::WOULDBLOCK),
                Ordering::Release,
            );
        }
    }
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::NewAuthority,
        &Arc::new(work()),
    )
    .expect("provision");
    let saw_lock = Arc::new(AtomicBool::new(false));
    let probe = CloseProbe {
        path: lock_path(&path),
        saw_lock: Arc::clone(&saw_lock),
    };
    // rusqlite removes the authorizer before sqlite3_close. Observe the lock
    // from that exact removal boundary; admission must outlive the callback.
    backend
        .conn()
        .blocking_lock()
        .authorizer(Some(move |_: rusqlite::hooks::AuthContext<'_>| {
            let _ = &probe;
            rusqlite::hooks::Authorization::Allow
        }))
        .expect("SQLite test hook registration");
    drop(backend);
    assert!(
        saw_lock.load(Ordering::Acquire),
        "SQLite close must retain admission after removing hooks"
    );
    assert!(
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()),).is_ok()
    );
}

#[test]
fn rewritten_schema_digest_cannot_authorize_extra_base_schema() {
    for name in [
        "retained_schema_probe",
        "consensus_schema_probe",
        "consensusXschema_probe",
    ] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        drop(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(work()),
            )
            .expect("provision"),
        );
        let conn = Connection::open(&path).expect("synthetic fault access");
        conn.execute_batch(&format!(
            "CREATE TRIGGER {name} BEFORE INSERT ON config_history BEGIN SELECT RAISE(IGNORE); END"
        ))
        .expect("inject a trigger that suppresses committed history");
        // The persisted compatibility digest is untrusted input. Recompute it
        // exactly as a storage substitution could; no admission HMAC changes.
        let digest = crate::schema::current_schema_digest(&conn).expect("substituted digest");
        conn.execute(
            "UPDATE schema_version SET schema_digest = ?1 WHERE id = 1",
            [digest],
        )
        .expect("rewrite untrusted schema metadata");
        drop(conn);
        let before = files(dir.path());
        let admission = Arc::new(work());
        assert!(
            matches!(
                open_authority_sync(options(&path), key(), OpenIntent::Reopen, &admission),
                Err(RetainedConfigError::Rejected)
            ),
            "a rewritten compatibility digest must not authorize a changed base schema"
        );
        assert!(!admission.mutated.load(Ordering::Acquire));
        assert_eq!(before, files(dir.path()));
    }
}

const CRASH_STAGES: [&str; 9] = [
    "intent_published",
    "lock_created",
    "database_created",
    "base_initialized",
    "consensus_initialized",
    "binding_stored",
    "database_synced",
    "record_written",
    "record_synced",
];

fn crash_provision(path: &Path, stage: &str) {
    crash_provision_with(path, stage, false);
}

fn crash_provision_with(path: &Path, stage: &str, repair: bool) {
    let mut command = std::process::Command::new(std::env::current_exe().expect("test binary"));
    command
        .args([
            "--exact",
            "retained::tests::provisioning_crash_child",
            "--nocapture",
        ])
        .env("OPC_RETAINED_TEST_DATABASE", path)
        .env("OPC_RETAINED_TEST_CRASH_STAGE", stage);
    if repair {
        command.env("OPC_RETAINED_TEST_DISPOSITION", "repair");
    }
    let output = command.output().expect("crash child");
    assert_eq!(output.status.code(), Some(91), "{stage}");
}

// Only this private unit-test executable can select a provisioning crash.
#[test]
fn provisioning_crash_child() {
    let Some(path) = std::env::var_os("OPC_RETAINED_TEST_DATABASE") else {
        return;
    };
    let stage = std::env::var("OPC_RETAINED_TEST_CRASH_STAGE").expect("stage");
    let intent = match std::env::var("OPC_RETAINED_TEST_DISPOSITION").as_deref() {
        Ok("repair") => OpenIntent::RepairMember,
        _ => OpenIntent::NewAuthority,
    };
    let mut work = work();
    work.hook = Some(Arc::new(move |_, observed| {
        if observed == stage {
            std::process::exit(91);
        }
    }));
    let _ = open_authority_sync(options(Path::new(&path)), key(), intent, &Arc::new(work));
    panic!("crash boundary not reached");
}

#[test]
fn process_loss_at_every_provisioning_boundary_resumes_the_same_request() {
    for stage in CRASH_STAGES {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, stage);
        let before = files(dir.path());
        assert!(lock_is_free(&path), "no admission lock leaked at {stage}");
        let reopened =
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()));
        if matches!(stage, "record_written" | "record_synced") {
            // A complete authenticated record is sufficient after actual
            // readback, even when the prior caller never received success.
            drop(reopened.expect("complete provisioning reconciles"));
        } else {
            assert!(reopened.is_err(), "partial {stage}");
            assert_eq!(before, files(dir.path()), "reopen must not mutate {stage}");
        }
        // The durable intent authorizes exactly this request to resume: a
        // partial prefix is aborted under the lock, a committed record is
        // reconciled. Either way the retry returns one usable authority and
        // retires the intent.
        let backend = open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .unwrap_or_else(|error| panic!("same request resumes at {stage}: {error:?}"));
        drop(backend);
        assert!(
            !provision_intent_path(&path).exists(),
            "intent retired after {stage}"
        );
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("resumed authority reopens"),
        );
        assert!(
            !files(dir.path()).contains_key(&std::ffi::OsString::from(
                "retained.sqlite.opc-retained.intent"
            )),
            "no intent residue after {stage}"
        );
    }
}

#[test]
fn committed_authority_for_another_binding_is_never_deleted_by_a_resume() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    crash_provision(&path, "record_synced");
    let before = files(dir.path());
    // Replace the admission record with a valid authenticated record for a
    // different backing identity, keeping the same database identity.
    let original = before
        .get(&std::ffi::OsString::from("retained.sqlite.opc-retained"))
        .expect("admission record")
        .clone();
    let mut original_bytes = [0u8; RECORD_BYTES];
    original_bytes.copy_from_slice(&original);
    let identity = record_identity(&original_bytes).expect("identity");
    let other_binding = RetainedConfigBinding::new(
        options(&path).binding.topology().clone(),
        [0x43; 32],
        [0x42; 32],
    )
    .expect("other binding");
    let other_record =
        make_record(&other_binding, &key(), identity, [0x55; 32], false).expect("other record");
    std::fs::write(lock_path(&path), other_record).expect("replace record");
    let before_resume = files(dir.path());
    let resumed = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::NewAuthority,
        &Arc::new(work()),
    );
    assert!(
        matches!(resumed, Err(RetainedConfigError::RecoveryRequired)),
        "foreign committed record: {resumed:?}"
    );
    assert_eq!(
        before_resume,
        files(dir.path()),
        "another binding's committed record must not be adopted or deleted"
    );
    // The original committed operation is still recoverable once its record is
    // restored (the database binding row was never touched).
    std::fs::write(lock_path(&path), original).expect("restore record");
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("original request reconciles"),
    );
}

#[test]
fn process_loss_after_intent_retirement_leaves_an_established_reopenable_store() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    // The intent is retired only after the complete admission record was
    // validated. A crash at that last boundary is a completed provisioning
    // operation whose caller lost the reply: ordinary reopen reconciles it and
    // no intent residue remains.
    crash_provision(&path, "intent_removed");
    assert!(!provision_intent_path(&path).exists());
    drop(
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
            .expect("completed provisioning reopens"),
    );
    assert!(
        matches!(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(work())
            ),
            Err(RetainedConfigError::AlreadyExists)
        ),
        "an established store is not adopted by a new provisioning request"
    );
    drop(
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
            .expect("established store unchanged"),
    );
}

#[test]
fn a_conflicting_provisioning_request_never_adopts_or_overwrites_authenticated_state() {
    for stage in CRASH_STAGES {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, stage);
        let before = files(dir.path());
        let established_before = matches!(stage, "record_written" | "record_synced")
            && open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .is_ok();
        let conflicting = RetainedConfigOptions::new(
            &path,
            RetainedConfigBinding::new(
                options(&path).binding.topology().clone(),
                [0x43; 32],
                [0x42; 32],
            )
            .expect("conflicting binding"),
            RetainedConfigDurability::Ephemeral,
            16 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .expect("conflicting options");
        assert!(
            matches!(
                open_authority_sync(
                    conflicting,
                    key(),
                    OpenIntent::NewAuthority,
                    &Arc::new(work())
                ),
                Err(RetainedConfigError::Rejected)
                    | Err(RetainedConfigError::RecoveryRequired)
                    | Err(RetainedConfigError::AlreadyExists)
            ),
            "a conflicting request must be refused at {stage}"
        );
        assert_eq!(
            before,
            files(dir.path()),
            "conflict must not mutate {stage}"
        );
        if established_before {
            // A conflicting request never loses the established store.
            drop(
                open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                    .expect("established store survives the conflicting request"),
            );
        }
        // The authenticated original request still resumes afterwards.
        drop(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(work()),
            )
            .expect("original request still resumes"),
        );
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("original authority intact"),
        );
    }
}

#[test]
fn injected_faults_at_every_persistent_step_leave_retryable_state() {
    let steps = [
        "intent_create",
        "intent_read",
        "lock_create",
        "database_create",
        "base_schema",
        "consensus_schema",
        "binding_write",
        "database_sync",
        "database_parent_sync",
        "record_write",
        "record_sync",
        "record_parent_sync",
        "intent_remove",
    ];
    for step in steps {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let mut failing = work();
        let target = step.to_string();
        failing.fault = Some(Arc::new(move |observed| {
            (observed == target).then_some(RetainedConfigError::Unavailable)
        }));
        let result = open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(failing),
        );
        assert!(result.is_err(), "fault {step} must fail");
        // Retry the same request after the transient I/O fault. It either
        // aborts the authenticated prefix or reconciles a committed record.
        drop(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(work()),
            )
            .unwrap_or_else(|error| panic!("retry after {step}: {error:?}")),
        );
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("retried authority reopens"),
        );
        assert!(
            !provision_intent_path(&path).exists(),
            "intent retired after {step}"
        );
    }
}

#[test]
fn provisioning_cancellation_is_retryable_and_distinct_from_completed_retirement() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut cancelled = work();
    cancelled.hook = Some(Arc::new(move |work, stage| {
        if stage == "binding_stored" {
            work.cancelled.store(true, Ordering::Release);
        }
    }));
    assert!(
        matches!(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(cancelled)
            ),
            Err(RetainedConfigError::Indeterminate) | Err(RetainedConfigError::AdmissionBound)
        ),
        "cancellation after a mutation is bounded, never success"
    );
    // Retry after cancellation finishes the same request and is not a
    // completed-retirement claim.
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("cancelled provisioning resumes"),
    );
    // A deadline before the first effect creates nothing and stays retryable.
    let other = tempfile::tempdir().expect("storage");
    let other_path = other.path().join("retained.sqlite");
    let mut expired = work();
    expired.deadline = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        open_authority_sync(
            options(&other_path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(expired)
        ),
        Err(RetainedConfigError::AdmissionBound)
    ));
    assert!(!provision_intent_path(&other_path).exists());
    drop(
        open_authority_sync(
            options(&other_path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("deadline rejection leaves a retryable request"),
    );
}

#[test]
fn replacement_between_validation_and_sqlite_open_is_rejected_without_recovery() {
    for replace_lock in [false, true] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        drop(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(work()),
            )
            .expect("provision"),
        );
        let target = if replace_lock {
            lock_path(&path)
        } else {
            path.clone()
        };
        let original = std::fs::read(&target).expect("original");
        let mut work = work();
        work.hook = Some(Arc::new(move |_, stage| {
            if stage == "before_original_open" {
                let moved = target.with_extension("moved");
                std::fs::rename(&target, moved).expect("replace");
                std::fs::write(&target, &original).expect("replacement");
            }
        }));
        let work = Arc::new(work);
        assert!(open_authority_sync(options(&path), key(), OpenIntent::Reopen, &work).is_err());
        assert!(!work.mutated.load(Ordering::Acquire));
        assert!(!dir.path().join("retained.sqlite-wal").exists());
        assert!(!dir.path().join("retained.sqlite-shm").exists());
    }
}

#[test]
fn cancellation_after_validation_returns_no_capability_or_recovery_effect() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("provision"),
    );
    let before = files(dir.path());
    let mut work = work();
    work.hook = Some(Arc::new(|work, stage| {
        if stage == "before_original_open" {
            work.cancelled.store(true, Ordering::Release);
        }
    }));
    let work = Arc::new(work);
    assert!(open_authority_sync(options(&path), key(), OpenIntent::Reopen, &work).is_err());
    assert!(!work.mutated.load(Ordering::Acquire));
    assert_eq!(before, files(dir.path()));
}

#[test]
fn exclusive_open_child() {
    let Some(path) = std::env::var_os("OPC_RETAINED_TEST_LOCK_DATABASE") else {
        return;
    };
    assert!(matches!(
        open_authority_sync(
            options(Path::new(&path)),
            key(),
            OpenIntent::Reopen,
            &Arc::new(work())
        ),
        Err(RetainedConfigError::InUse)
    ));
}

#[test]
fn an_independent_process_cannot_open_live_retained_authority() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::NewAuthority,
        &Arc::new(work()),
    )
    .expect("provision");
    let output = std::process::Command::new(std::env::current_exe().expect("binary"))
        .args([
            "--exact",
            "retained::tests::exclusive_open_child",
            "--nocapture",
        ])
        .env("OPC_RETAINED_TEST_LOCK_DATABASE", &path)
        .output()
        .expect("second process");
    assert!(
        output.status.success(),
        "second process must reject the held lifetime lock"
    );
    drop(backend);
    assert!(
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work())).is_ok()
    );
}

#[test]
fn durable_intent_publication_is_classified_as_a_mutation() {
    // After the intent is durable, any later failure is an indeterminate
    // mutation (the operation wrapper maps `mutated`), not a pre-effect
    // rejection. Before publication it stays a clean pre-effect failure.
    for step in [
        "lock_create",
        "database_create",
        "base_schema",
        "consensus_schema",
        "binding_write",
        "database_sync",
        "database_parent_sync",
        "record_write",
        "record_sync",
        "record_parent_sync",
    ] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let mut failing = work();
        let target = step.to_string();
        failing.fault = Some(Arc::new(move |observed| {
            (observed == target).then_some(RetainedConfigError::Unavailable)
        }));
        let admission = Arc::new(failing);
        assert!(
            open_authority_sync(options(&path), key(), OpenIntent::NewAuthority, &admission)
                .is_err(),
            "{step}"
        );
        assert!(
            admission.mutated.load(Ordering::Acquire),
            "durable intent/artifact effect at {step} must be classified as mutation"
        );
        assert!(provision_intent_path(&path).exists(), "{step}");
    }

    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let mut failing = work();
    failing.fault = Some(Arc::new(|observed| {
        (observed == "intent_create").then_some(RetainedConfigError::Unavailable)
    }));
    let admission = Arc::new(failing);
    assert!(
        open_authority_sync(options(&path), key(), OpenIntent::NewAuthority, &admission).is_err()
    );
    assert!(
        !admission.mutated.load(Ordering::Acquire),
        "a refused intent publication creates nothing"
    );
    assert!(!provision_intent_path(&path).exists());
}

#[test]
fn remove_intent_file_refuses_foreign_file_types() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let intent = provision_intent_path(&path);

    // Group/other-writable regular file: never unlinked by SDK cleanup.
    std::fs::write(&intent, [0u8; INTENT_BYTES]).expect("write");
    std::fs::set_permissions(&intent, std::fs::Permissions::from_mode(0o666)).expect("permissions");
    assert!(matches!(
        remove_intent_file(&intent, &Arc::new(work())),
        Err(RetainedConfigError::Rejected)
    ));
    assert!(intent.exists(), "foreign regular file preserved");
    std::fs::remove_file(&intent).expect("test cleanup");

    // Symlink at the intent path: never followed or unlinked.
    let foreign = dir.path().join("foreign");
    std::fs::write(&foreign, b"foreign").expect("foreign");
    std::os::unix::fs::symlink(&foreign, &intent).expect("symlink");
    assert!(matches!(
        remove_intent_file(&intent, &Arc::new(work())),
        Err(RetainedConfigError::Rejected)
    ));
    assert!(intent.symlink_metadata().is_ok(), "symlink preserved");
    assert!(foreign.exists());
}

#[test]
fn torn_first_intent_without_artifacts_is_replaced_and_completes() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    // A torn first publication is SDK-owned recovery metadata with no artifact
    // mutation behind it; it is replaced rather than requiring operator action.
    std::fs::write(provision_intent_path(&path), [0u8; INTENT_BYTES]).expect("torn intent");
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("torn intent is replaced"),
    );
    assert!(!provision_intent_path(&path).exists());
    drop(
        open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
            .expect("provisioned authority reopens"),
    );
}

#[test]
fn abort_does_not_remove_a_concurrent_owners_fresh_lock() {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    // Crash before lock creation, then model a concurrent same-path opener
    // that has just claimed the empty lock slot and is still live.
    crash_provision(&path, "intent_published");
    let owner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path(&path))
        .expect("concurrent owner claims lock");
    let held = AdmissionFileLock::acquire(owner).expect("owner lock");
    let before = files(dir.path());
    let resumed = open_authority_sync(
        options(&path),
        key(),
        OpenIntent::NewAuthority,
        &Arc::new(work()),
    );
    assert!(
        matches!(resumed, Err(RetainedConfigError::InUse)),
        "abort under a live owner must fail closed: {resumed:?}"
    );
    assert_eq!(
        before,
        files(dir.path()),
        "a live owner's lock and partial state are not removed"
    );
    drop(held);
    drop(
        open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        )
        .expect("retry after the concurrent owner retires"),
    );
}

#[test]
fn repair_member_provisioning_resumes_and_disposition_conflicts_fail_closed() {
    for stage in ["intent_published", "binding_stored", "record_synced"] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision_with(&path, stage, true);
        let before = files(dir.path());

        // Same binding, different operation class: never adopt/abort/overwrite.
        let conflict = open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        );
        assert!(
            matches!(
                conflict,
                Err(RetainedConfigError::RecoveryRequired) | Err(RetainedConfigError::Rejected)
            ),
            "disposition conflict at {stage}: {conflict:?}"
        );
        assert_eq!(
            before,
            files(dir.path()),
            "disposition conflict must not mutate {stage}"
        );

        // The authenticated repair request itself resumes.
        drop(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::RepairMember,
                &Arc::new(work()),
            )
            .unwrap_or_else(|error| panic!("repair resumes at {stage}: {error:?}")),
        );
        assert!(!provision_intent_path(&path).exists());
        // The established repair store refuses fresh authority provisioning and
        // reopens through the ordinary path.
        assert!(matches!(
            open_authority_sync(
                options(&path),
                key(),
                OpenIntent::NewAuthority,
                &Arc::new(work())
            ),
            Err(RetainedConfigError::AlreadyExists)
        ));
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("established repair store reopens"),
        );
    }
}

mod provisioning_regressions {
    use super::*;

    fn resume_intent() -> OpenIntent {
        OpenIntent::NewAuthority
    }

    fn intent_path(path: &Path) -> PathBuf {
        provision_intent_path(path)
    }

    #[test]
    fn different_audit_key_cannot_replace_interrupted_provisioning() {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, "intent_published");
        let before = files(dir.path());
        let foreign_key = AuditKey::new([0x72; 32]).expect("foreign key");
        let result = open_authority_sync(
            options(&path),
            foreign_key,
            resume_intent(),
            &Arc::new(work()),
        );
        assert!(
            result.is_err(),
            "another key must not take over: {result:?}"
        );
        assert_eq!(before, files(dir.path()), "conflicting state is preserved");
        drop(
            open_authority_sync(options(&path), key(), resume_intent(), &Arc::new(work()))
                .expect("the authorized original request still resumes"),
        );
    }

    #[test]
    fn unverifiable_interrupted_intent_is_preserved() {
        for bytes in [vec![], vec![0; 13], vec![0; 105]] {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            std::fs::write(intent_path(&path), bytes).expect("unverifiable intent");
            let before = files(dir.path());
            let result =
                open_authority_sync(options(&path), key(), resume_intent(), &Arc::new(work()));
            assert!(
                result.is_err(),
                "unverifiable state cannot authorize a retry"
            );
            assert_eq!(
                before,
                files(dir.path()),
                "partial bytes must not be replaced"
            );
            assert!(!path.exists(), "no database may be initialized");
        }
    }

    #[test]
    fn reopen_then_fresh_provision_does_not_adopt_established_store() {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, "record_synced");
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("established authority reopens"),
        );
        let before = files(dir.path());
        let result = open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work()),
        );
        assert!(
            matches!(result, Err(RetainedConfigError::AlreadyExists)),
            "fresh provision cannot adopt an established store: {result:?}"
        );
        assert_eq!(before, files(dir.path()));
    }

    #[test]
    fn damaged_record_after_reopen_never_reinitializes_established_database() {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, "record_synced");
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("established authority reopens"),
        );
        std::fs::write(lock_path(&path), b"damaged admission").expect("damage record");
        let before = files(dir.path());
        let result = open_authority_sync(options(&path), key(), resume_intent(), &Arc::new(work()));
        assert!(
            result.is_err(),
            "damage cannot authorize new genesis: {result:?}"
        );
        assert_eq!(
            before,
            files(dir.path()),
            "established database must survive"
        );
    }

    #[test]
    fn established_database_loss_never_authorizes_a_fresh_resume() {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, "record_synced");
        drop(
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()))
                .expect("established authority reopens"),
        );
        std::fs::remove_file(&path).expect("database loss");
        let before = files(dir.path());
        let result = open_authority_sync(options(&path), key(), resume_intent(), &Arc::new(work()));
        assert!(
            matches!(result, Err(RetainedConfigError::RecoveryRequired)),
            "resume must refuse established storage loss: {result:?}"
        );
        assert!(!path.exists());
        assert_eq!(before, files(dir.path()));
    }

    #[tokio::test]
    async fn legacy_open_during_interrupted_provision_is_rejected() {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        crash_provision(&path, "intent_published");
        let before = files(dir.path());
        let legacy = SqliteBackend::open_with_audit_key(&path, true, 0, key()).await;
        assert!(
            legacy.is_err(),
            "retained intent denies legacy initialization: {legacy:?}"
        );
        assert_eq!(before, files(dir.path()));
    }
}
