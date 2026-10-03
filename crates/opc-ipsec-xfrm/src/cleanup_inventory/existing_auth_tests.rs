use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    XfrmObjectInstallRecoveryStore, XfrmObjectRecoveryProofKey, XfrmObjectRosterRecoveryProofKey,
    XfrmObjectRosterRecoveryStore, XfrmSaRelocationRecoveryProofKey, XfrmSaRelocationRecoveryStore,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "opc-inventory-auth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn store(&self) -> PathBuf {
        self.0.join("store")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn open(family: usize, path: &Path, existing: bool) -> bool {
    match family {
        0 => {
            let key = XfrmObjectRecoveryProofKey::new([1; 32]).unwrap();
            let result = if existing {
                XfrmObjectInstallRecoveryStore::authenticate_existing_bound(path, key, [2; 40])
            } else {
                XfrmObjectInstallRecoveryStore::open_bound(path, key, [2; 40])
            };
            result.is_ok()
        }
        1 => {
            let key = XfrmSaRelocationRecoveryProofKey::new([1; 32]).unwrap();
            let result = if existing {
                XfrmSaRelocationRecoveryStore::authenticate_existing_bound(path, key, [2; 40])
            } else {
                XfrmSaRelocationRecoveryStore::open_bound(path, key, [2; 40])
            };
            result.is_ok()
        }
        _ => {
            let key = XfrmObjectRosterRecoveryProofKey::new([1; 32]).unwrap();
            let result = if existing {
                XfrmObjectRosterRecoveryStore::authenticate_existing_bound(path, key, [2; 40])
            } else {
                XfrmObjectRosterRecoveryStore::open_bound(path, key, [2; 40])
            };
            result.is_ok()
        }
    }
}

fn snapshot(path: &Path) -> Vec<(String, Vec<u8>)> {
    if !path.exists() {
        return Vec::new();
    }
    let mut files = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[test]
fn existing_authentication_never_creates_missing_or_empty_store_incarnations() {
    let mut failures = Vec::new();
    for family in 0..3 {
        for empty in [false, true] {
            let root = Root::new();
            if empty {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(root.store())
                    .unwrap();
            }
            let accepted = open(family, &root.store(), true);
            if accepted || root.store().exists() != empty || !snapshot(&root.store()).is_empty() {
                failures.push((family, empty));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "authentication created missing/empty stores: {failures:?}"
    );
}

#[test]
fn existing_authentication_preserves_incomplete_controls_and_staging_for_every_family() {
    let mut failures = Vec::new();
    for family in 0..3 {
        for staging in [false, true] {
            let root = Root::new();
            assert!(open(family, &root.store(), false));
            if staging {
                let prefix = [
                    ".opc-xfrm-object-pending-",
                    ".opc-xfrm-relocation-pending-",
                    ".opc-xfrm-roster-pending-",
                ][family];
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(root.store().join(format!("{prefix}{}", "11".repeat(16))))
                    .unwrap();
                file.write_all(b"interrupted").unwrap();
            } else {
                for entry in std::fs::read_dir(root.store()).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_name() != "control" {
                        std::fs::remove_file(entry.path()).unwrap();
                    }
                }
            }
            let before = snapshot(&root.store());
            let accepted = open(family, &root.store(), true);
            if accepted || snapshot(&root.store()) != before {
                failures.push((family, staging));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "authentication repaired incomplete/staged stores: {failures:?}"
    );
}

#[test]
fn existing_roster_authentication_never_trims_an_incomplete_journal_tail() {
    let root = Root::new();
    assert!(open(2, &root.store(), false));
    let journal = std::fs::read_dir(root.store())
        .unwrap()
        .map(|entry| entry.unwrap())
        .find(|entry| entry.file_name().to_string_lossy().contains("journal"))
        .unwrap()
        .path();
    std::fs::OpenOptions::new()
        .append(true)
        .open(journal)
        .unwrap()
        .write_all(&[0x77])
        .unwrap();
    let before = snapshot(&root.store());
    assert!(!open(2, &root.store(), true));
    assert_eq!(snapshot(&root.store()), before);
}

macro_rules! each_family {
    ($check:ident) => {
        $check!(XfrmObjectInstallRecoveryStore, XfrmObjectRecoveryProofKey);
        $check!(
            XfrmSaRelocationRecoveryStore,
            XfrmSaRelocationRecoveryProofKey
        );
        $check!(
            XfrmObjectRosterRecoveryStore,
            XfrmObjectRosterRecoveryProofKey
        );
    };
}

#[test]
fn complete_existing_stores_and_clones_stay_authenticated_without_write_authority() {
    macro_rules! check {
        ($store:ty, $key:ty) => {{
            let root = Root::new();
            let key = || <$key>::new([1; 32]).unwrap();
            let store = <$store>::open_bound(&root.store(), key(), [2; 40]).unwrap();
            let incarnation = store.authenticated_incarnation().unwrap();
            drop(store);
            let before = snapshot(&root.store());
            let store =
                <$store>::authenticate_existing_bound(&root.store(), key(), [2; 40]).unwrap();
            assert_eq!(store.authenticated_incarnation().unwrap(), incarnation);
            assert!(<$store>::authenticate_existing_bound(&root.store(), key(), [2; 40]).is_err());
            let cloned = store.clone();
            drop(store);
            assert!(cloned.advance_writer_epoch().is_err());
            assert_eq!(cloned.authenticated_incarnation().unwrap(), incarnation);
            assert_eq!(snapshot(&root.store()), before);
            drop(cloned);
            assert!(<$store>::authenticate_existing_bound(
                &root.store(),
                <$key>::new([9; 32]).unwrap(),
                [2; 40],
            )
            .is_err());
            assert!(<$store>::authenticate_existing_bound(&root.store(), key(), [9; 40]).is_err());
            assert_eq!(snapshot(&root.store()), before);
        }};
    }
    each_family!(check);
}

#[test]
fn existing_authentication_preserves_adjacent_epoch_residue_instead_of_reconciling() {
    macro_rules! check {
        ($store:ty, $key:ty) => {{
            let root = Root::new();
            let key = || <$key>::new([1; 32]).unwrap();
            let store = <$store>::open_bound(&root.store(), key(), [2; 40]).unwrap();
            let (old_name, old_bytes) = snapshot(&root.store())
                .into_iter()
                .find(|(name, _)| name.starts_with("epoch-"))
                .unwrap();
            store.advance_writer_epoch().unwrap();
            drop(store);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.store().join(old_name))
                .unwrap();
            file.write_all(&old_bytes).unwrap();
            drop(file);
            let before = snapshot(&root.store());
            assert!(<$store>::authenticate_existing_bound(&root.store(), key(), [2; 40]).is_err());
            assert_eq!(snapshot(&root.store()), before);
        }};
    }
    each_family!(check);
}

#[test]
fn recognized_fifo_inputs_refuse_promptly_and_release_the_lease() {
    use rustix::fs::{flock, mkfifoat, open as open_directory, FlockOperation, Mode, OFlags, CWD};
    use std::{
        os::unix::fs::MetadataExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    // A dedicated, owned process makes a blocking-open regression bounded.
    // The parent kills and reaps every timed-out child before any assertion.
    if let Some(path) = std::env::var_os("OPC_INVENTORY_FIFO_STORE") {
        let path = PathBuf::from(path);
        let family = std::env::var("OPC_INVENTORY_FIFO_FAMILY")
            .unwrap()
            .parse()
            .unwrap();
        assert!(!open(family, &path, true));
        let directory =
            open_directory(&path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        flock(&directory, FlockOperation::NonBlockingLockExclusive).unwrap();
        return;
    }

    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.0.try_wait().unwrap().is_none() {
                self.0.kill().unwrap();
            }
            self.0.wait().unwrap();
        }
    }
    let mut failures = Vec::new();
    for family in 0..3 {
        for entry in 0..3 {
            let root = Root::new();
            assert!(open(family, &root.store(), false));
            let before = snapshot(&root.store());
            let name = match entry {
                0 => String::from("control"),
                1 => before
                    .iter()
                    .find(|(name, _)| name.starts_with("epoch-"))
                    .unwrap()
                    .0
                    .clone(),
                _ if family == 2 => format!("prepared-{}-0000000000000001-0001", "11".repeat(16)),
                _ => format!("prepared-{}-0000000000000001", "11".repeat(16)),
            };
            let fifo = root.store().join(&name);
            if fifo.exists() {
                std::fs::remove_file(&fifo).unwrap();
            }
            mkfifoat(CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();
            let metadata = std::fs::symlink_metadata(&fifo).unwrap();
            let mut child = OwnedChild(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cleanup_inventory::existing_auth_tests::recognized_fifo_inputs_refuse_promptly_and_release_the_lease"])
                .env("OPC_INVENTORY_FIFO_STORE", root.store())
                .env("OPC_INVENTORY_FIFO_FAMILY", family.to_string())
                .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            let deadline = Instant::now() + Duration::from_secs(2);
            let success = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status.success();
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            drop(child);
            let after = std::fs::symlink_metadata(&fifo).unwrap();
            assert_eq!(
                (after.dev(), after.ino(), after.mode()),
                (metadata.dev(), metadata.ino(), metadata.mode())
            );
            std::fs::remove_file(&fifo).unwrap();
            let unchanged = before
                .into_iter()
                .filter(|(existing, _)| existing != &name)
                .collect::<Vec<_>>();
            assert_eq!(snapshot(&root.store()), unchanged);
            if !success {
                failures.push((family, entry));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "recognized FIFO blocked or failed to release its lease: {failures:?}"
    );
}

#[test]
fn existing_named_histories_allow_inspection_but_refuse_transition_and_terminal_pruning() {
    use crate::{
        durable_object::DurableObjectFingerprints,
        durable_relocation::DurableRelocationFingerprints, XfrmInstallObject,
        XfrmObjectInstallDurablePhase, XfrmObjectInstallOperationGeneration,
        XfrmObjectInstallOperationId, XfrmSaRelocationDurablePhase,
        XfrmSaRelocationOperationGeneration, XfrmSaRelocationOperationId,
    };
    macro_rules! check {
        ($store:ty, $key:ty, $phase:ty, $prepare:expr) => {{
            for terminal in [false, true] {
                let root = Root::new();
                let key = || <$key>::new([1; 32]).unwrap();
                let store = <$store>::open_bound(&root.store(), key(), [2; 40]).unwrap();
                let mut handle = $prepare(&store).unwrap();
                if terminal {
                    handle = store
                        .transition(&handle, <$phase>::Prepared, <$phase>::Retired, None)
                        .unwrap()
                        .handle(&key())
                        .unwrap();
                }
                drop(store);
                let expected = if terminal {
                    <$phase>::Retired
                } else {
                    <$phase>::Prepared
                };
                let before = snapshot(&root.store());
                let store =
                    <$store>::authenticate_existing_bound(&root.store(), key(), [2; 40]).unwrap();
                let cloned = store.clone();
                drop(store);
                assert_eq!(cloned.inspect(&handle), Ok(expected));
                if terminal {
                    // A terminal record reaches removal during pruning before epoch publication.
                    assert!(cloned.advance_writer_epoch().is_err());
                } else {
                    // This is a legal successor; its new named-file publication must refuse.
                    assert!(cloned
                        .transition(&handle, <$phase>::Prepared, <$phase>::Retired, None)
                        .is_err());
                }
                assert_eq!(cloned.inspect(&handle), Ok(expected));
                assert_eq!(snapshot(&root.store()), before);
                drop(cloned);
                // The same call succeeds through the legacy writer, proving the
                // read-only failure did not merely use an illegal transition.
                let writer = <$store>::open_bound(&root.store(), key(), [2; 40]).unwrap();
                if terminal {
                    writer.advance_writer_epoch().unwrap();
                } else {
                    writer
                        .transition(&handle, <$phase>::Prepared, <$phase>::Retired, None)
                        .unwrap();
                }
                assert_ne!(snapshot(&root.store()), before);
            }
        }};
    }
    check!(
        XfrmObjectInstallRecoveryStore,
        XfrmObjectRecoveryProofKey,
        XfrmObjectInstallDurablePhase,
        |store: &XfrmObjectInstallRecoveryStore| store.prepare(
            XfrmObjectInstallOperationId::from_bytes([3; 16]).unwrap(),
            XfrmObjectInstallOperationGeneration::new(1).unwrap(),
            XfrmInstallObject::Sa,
            DurableObjectFingerprints::repeated(4),
        )
    );
    check!(
        XfrmSaRelocationRecoveryStore,
        XfrmSaRelocationRecoveryProofKey,
        XfrmSaRelocationDurablePhase,
        |store: &XfrmSaRelocationRecoveryStore| store.prepare(
            XfrmSaRelocationOperationId::from_bytes([3; 16]).unwrap(),
            XfrmSaRelocationOperationGeneration::new(1).unwrap(),
            DurableRelocationFingerprints {
                deletion_identity: [4; 32],
                relocation_request: [5; 32]
            },
        )
    );
}

#[test]
fn existing_roster_history_allows_inspection_but_refuses_append_and_compaction() {
    use crate::{
        durable_roster::{
            XfrmObjectRosterMemberFingerprints, XfrmObjectRosterMemberId,
            XfrmObjectRosterMemberMaterial, XfrmObjectRosterTransition,
        },
        XfrmInstallObject, XfrmObjectRosterDurablePhase as Phase, XfrmObjectRosterGroupId,
        XfrmObjectRosterOperationGeneration,
    };
    for terminal in [false, true] {
        let root = Root::new();
        let key = || XfrmObjectRosterRecoveryProofKey::new([1; 32]).unwrap();
        let store =
            XfrmObjectRosterRecoveryStore::open_bound(&root.store(), key(), [2; 40]).unwrap();
        let mut handle = store
            .prepare(
                XfrmObjectRosterGroupId::from_bytes([3; 16]).unwrap(),
                XfrmObjectRosterOperationGeneration::new(1).unwrap(),
                &[XfrmObjectRosterMemberMaterial {
                    object: XfrmInstallObject::Sa,
                    member_id: XfrmObjectRosterMemberId::from_bytes([4; 16]).unwrap(),
                    member_generation: std::num::NonZeroU64::new(1).unwrap(),
                    fingerprints: XfrmObjectRosterMemberFingerprints {
                        deletion_identity: [5; 32],
                        install_request: [6; 32],
                    },
                }],
            )
            .unwrap();
        let transition = XfrmObjectRosterTransition::new(Phase::Retired, 0);
        if terminal {
            handle = store
                .transition(&handle, Phase::Prepared, transition)
                .unwrap()
                .handle(&key())
                .unwrap();
        }
        drop(store);
        let expected = if terminal {
            Phase::Retired
        } else {
            Phase::Prepared
        };
        let before = snapshot(&root.store());
        assert!(before.iter().any(|(name, _)| name == "journal"));
        let store = XfrmObjectRosterRecoveryStore::authenticate_existing_bound(
            &root.store(),
            key(),
            [2; 40],
        )
        .unwrap();
        let cloned = store.clone();
        drop(store);
        assert_eq!(cloned.inspect(&handle), Ok(expected));
        if terminal {
            // Terminal history invokes compact_journal, not a named-file unlink.
            assert!(cloned.advance_writer_epoch().is_err());
        } else {
            // A valid Prepared→Retired transition invokes append_journal_record.
            assert!(cloned
                .transition(&handle, Phase::Prepared, transition)
                .is_err());
        }
        assert_eq!(cloned.inspect(&handle), Ok(expected));
        assert_eq!(snapshot(&root.store()), before);
        drop(cloned);
        let writer =
            XfrmObjectRosterRecoveryStore::open_bound(&root.store(), key(), [2; 40]).unwrap();
        if terminal {
            writer.advance_writer_epoch().unwrap();
        } else {
            writer
                .transition(&handle, Phase::Prepared, transition)
                .unwrap();
        }
        assert_ne!(snapshot(&root.store()), before);
    }
}

#[test]
fn converting_a_new_store_to_authentication_only_requires_sole_ownership() {
    macro_rules! check {
        ($store:ty, $key:ty) => {{
            let root = Root::new();
            let writer =
                <$store>::open_bound(&root.store(), <$key>::new([1; 32]).unwrap(), [2; 40])
                    .unwrap();
            let alias = writer.clone();
            assert!(writer.into_authentication_only().is_err());
            // A pre-existing alias is never silently relabelled as restricted.
            alias.advance_writer_epoch().unwrap();
            let restricted = alias.into_authentication_only().unwrap();
            let before = snapshot(&root.store());
            let clone = restricted.clone();
            assert!(restricted.advance_writer_epoch().is_err());
            assert!(clone.advance_writer_epoch().is_err());
            assert_eq!(snapshot(&root.store()), before);
        }};
    }
    each_family!(check);
}

fn prepare_one_roster(
    store: &XfrmObjectRosterRecoveryStore,
) -> crate::XfrmObjectRosterRecoveryHandle {
    use crate::{
        durable_roster::{
            XfrmObjectRosterMemberFingerprints, XfrmObjectRosterMemberId,
            XfrmObjectRosterMemberMaterial,
        },
        XfrmInstallObject, XfrmObjectRosterGroupId, XfrmObjectRosterOperationGeneration,
    };
    store
        .prepare(
            XfrmObjectRosterGroupId::from_bytes([3; 16]).unwrap(),
            XfrmObjectRosterOperationGeneration::new(1).unwrap(),
            &[XfrmObjectRosterMemberMaterial {
                object: XfrmInstallObject::Sa,
                member_id: XfrmObjectRosterMemberId::from_bytes([4; 16]).unwrap(),
                member_generation: std::num::NonZeroU64::new(1).unwrap(),
                fingerprints: XfrmObjectRosterMemberFingerprints {
                    deletion_identity: [5; 32],
                    install_request: [6; 32],
                },
            }],
        )
        .unwrap()
}

#[test]
fn existing_authentication_refuses_a_missing_nonempty_roster_journal() {
    let root = Root::new();
    let store = XfrmObjectRosterRecoveryStore::open_bound(
        &root.store(),
        XfrmObjectRosterRecoveryProofKey::new([1; 32]).unwrap(),
        [2; 40],
    )
    .unwrap();
    let handle = prepare_one_roster(&store);
    assert_eq!(
        store.inspect(&handle),
        Ok(crate::XfrmObjectRosterDurablePhase::Prepared)
    );
    drop(store);
    std::fs::remove_file(root.store().join("journal")).unwrap();
    let before = snapshot(&root.store());
    assert!(
        !open(2, &root.store(), true),
        "missing journal was reinterpreted as empty legacy history"
    );
    assert_eq!(snapshot(&root.store()), before);
}

#[test]
fn existing_authentication_refuses_legacy_roster_records_without_changing_ordinary_support() {
    let root = Root::new();
    let store = XfrmObjectRosterRecoveryStore::open_bound(
        &root.store(),
        XfrmObjectRosterRecoveryProofKey::new([1; 32]).unwrap(),
        [2; 40],
    )
    .unwrap();
    let handle = prepare_one_roster(&store);
    drop(store);
    // A recovery handle is the existing legacy record's exact authenticated
    // format. Materialize its canonical name to exercise that supported path.
    std::fs::remove_file(root.store().join("journal")).unwrap();
    let mut record = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.store().join(format!(
            "prepared-{}-0000000000000001-0001",
            "03".repeat(16)
        )))
        .unwrap();
    record.write_all(&handle.to_bytes()).unwrap();
    drop(record);
    let before = snapshot(&root.store());
    let authenticated = XfrmObjectRosterRecoveryStore::authenticate_existing_bound(
        &root.store(),
        XfrmObjectRosterRecoveryProofKey::new([1; 32]).unwrap(),
        [2; 40],
    );
    let authentication_refused = authenticated.is_err();
    drop(authenticated);
    let ordinary = XfrmObjectRosterRecoveryStore::open_bound(
        &root.store(),
        XfrmObjectRosterRecoveryProofKey::new([1; 32]).unwrap(),
        [2; 40],
    )
    .unwrap();
    assert_eq!(
        ordinary.inspect(&handle),
        Ok(crate::XfrmObjectRosterDurablePhase::Prepared)
    );
    let conversion_refused = ordinary.into_authentication_only().is_err();
    assert_eq!(snapshot(&root.store()), before);
    assert!(authentication_refused && conversion_refused,
        "legacy inventory accepted: authentication_refused={authentication_refused}, conversion_refused={conversion_refused}");
}
