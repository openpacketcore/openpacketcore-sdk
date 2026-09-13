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

// Only this private unit-test executable can select a provisioning crash.
#[test]
fn provisioning_crash_child() {
    let Some(path) = std::env::var_os("OPC_RETAINED_TEST_DATABASE") else {
        return;
    };
    let stage = std::env::var("OPC_RETAINED_TEST_CRASH_STAGE").expect("stage");
    let mut work = work();
    work.hook = Some(Arc::new(move |_, observed| {
        if observed == stage {
            std::process::exit(91);
        }
    }));
    let _ = open_authority_sync(
        options(Path::new(&path)),
        key(),
        OpenIntent::NewAuthority,
        &Arc::new(work),
    );
    panic!("crash boundary not reached");
}

#[test]
fn process_loss_at_every_provisioning_boundary_never_authorizes_initialization() {
    for stage in [
        "lock_created",
        "database_created",
        "base_initialized",
        "consensus_initialized",
        "binding_stored",
        "database_synced",
        "record_written",
        "record_synced",
    ] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "retained::tests::provisioning_crash_child",
                "--nocapture",
            ])
            .env("OPC_RETAINED_TEST_DATABASE", &path)
            .env("OPC_RETAINED_TEST_CRASH_STAGE", stage)
            .output()
            .expect("crash child");
        assert_eq!(output.status.code(), Some(91), "{stage}");
        let before = files(dir.path());
        let reopened =
            open_authority_sync(options(&path), key(), OpenIntent::Reopen, &Arc::new(work()));
        if matches!(stage, "record_written" | "record_synced") {
            // A complete authenticated record is sufficient after actual
            // readback, even when the prior caller never received success.
            drop(reopened.expect("complete provisioning reconciles"));
        } else {
            assert!(reopened.is_err(), "partial {stage}");
            assert_eq!(before, files(dir.path()), "rejected {stage}");
        }
        assert!(open_authority_sync(
            options(&path),
            key(),
            OpenIntent::NewAuthority,
            &Arc::new(work())
        )
        .is_err());
    }
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
