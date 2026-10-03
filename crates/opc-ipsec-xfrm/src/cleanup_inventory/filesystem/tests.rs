use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;
use crate::cleanup_inventory::{
    node::{InventoryKey, NodeContext, NodeKind},
    store::{Change, SnapshotStore},
    tree::{ChildReference, RootPage},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "opc-cleanup-inventory-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn store(&self) -> PathBuf {
        self.0.join("inventory")
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn limits() -> InventoryLimits {
    InventoryLimits {
        objects: 4,
        images: 8,
        coverage: 2,
        batch_records: 3,
        storage_bytes: 1024 * 1024,
        index_bytes: 4096,
        working_bytes: 2 * 1024 * 1024,
    }
}

fn binding(io: &DirectoryIo) -> NodeContext {
    let (device, inode) = io.identity();
    NodeContext {
        namespace: [1; 40],
        incarnation: [2; 16],
        device,
        inode,
        generation: 1,
        revision: 1,
        kind: NodeKind::Root,
        position: 0,
        slot: 0,
    }
}

fn create(root: &TemporaryDirectory) -> SnapshotStore<DirectoryIo> {
    let io = DirectoryIo::open(
        &root.store(),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format(),
    )
    .unwrap();
    let context = binding(&io);
    SnapshotStore::create(
        io,
        InventoryKey::new([3; 32]),
        context,
        RootPage {
            completion: [0; 4096],
            next_serial: 1,
            limits: limits(),
            stores: [None; 3],
            children: [ChildReference::EMPTY; 256],
        },
        super::super::tests::proposed_format(),
    )
    .unwrap()
}

fn reopen(root: &TemporaryDirectory) -> Result<SnapshotStore<DirectoryIo>, InventoryError> {
    let io = DirectoryIo::open(
        &root.store(),
        OpenMode::Reopen,
        limits(),
        super::super::tests::proposed_format(),
    )?;
    let context = binding(&io);
    SnapshotStore::reopen(
        io,
        InventoryKey::new([3; 32]),
        context,
        limits(),
        [None; 3],
        super::super::tests::proposed_format(),
    )
}

#[test]
fn disk_snapshot_holds_its_directory_lease_and_reopens_committed_records() {
    let root = TemporaryDirectory::new();
    assert!(reopen(&root).is_err());
    assert!(!root.store().exists());
    let mut store = create(&root);
    assert!(matches!(reopen(&root), Err(InventoryError::StoreBusy)));
    let mut record = super::super::tests::object_record(super::super::CleanupImage::Policy(
        super::super::tests::maximum_policy(),
    ));
    if let super::super::InventoryRecord::Object(object) = &mut record {
        object.coverage = None;
    }
    store
        .apply(
            vec![Change {
                position: 0,
                expected_serial: None,
                record: Some(record.clone()),
                absence: None,
            }],
            false,
        )
        .unwrap();
    assert_eq!(
        std::fs::metadata(root.store())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    for entry in std::fs::read_dir(root.store()).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    drop(store);
    let store = reopen(&root).unwrap();
    assert_eq!(store.record(0).unwrap(), Some(record));
    drop(store);
    assert!(DirectoryIo::open(
        &root.store(),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format()
    )
    .is_err());
}

fn private_file(path: &std::path::Path, bytes: &[u8]) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn disk_reopen_refuses_unsafe_entries_without_removing_them() {
    for entry in 0..7 {
        let root = TemporaryDirectory::new();
        drop(create(&root));
        let root_file = root.store().join("root");
        let marker = match entry {
            0 => {
                let path = root.store().join("unknown");
                private_file(&path, b"unknown");
                path
            }
            1 => {
                std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
                root_file
            }
            2 => {
                let link = root.0.join("root-link");
                std::fs::hard_link(&root_file, &link).unwrap();
                link
            }
            3 => {
                let outside = root.0.join("outside");
                private_file(&outside, b"outside");
                std::fs::remove_file(&root_file).unwrap();
                std::os::unix::fs::symlink(&outside, &root_file).unwrap();
                outside
            }
            4 => {
                let path = root.store().join("leaf-0001-0");
                private_file(&path, b"");
                path
            }
            5 => {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&root_file)
                    .unwrap()
                    .set_len(
                        u64::try_from(super::super::tests::proposed_format().root_bytes + 1)
                            .unwrap(),
                    )
                    .unwrap();
                root_file
            }
            _ => {
                std::fs::remove_file(&root_file).unwrap();
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root_file)
                    .unwrap();
                root_file
            }
        };
        assert!(reopen(&root).is_err());
        assert!(marker.exists());
        if entry == 3 {
            assert_eq!(std::fs::read(marker).unwrap(), b"outside");
        }
    }
}

#[test]
fn disk_root_and_directory_replacement_cannot_rebind_held_authority() {
    let root = TemporaryDirectory::new();
    let store = create(&root);
    let old_directory = root.0.join("original");
    std::fs::rename(root.store(), &old_directory).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(root.store())
        .unwrap();
    assert!(store.record(0).is_err());
    drop(store);
    std::fs::remove_dir(root.store()).unwrap();
    std::fs::rename(old_directory, root.store()).unwrap();

    let mut io = DirectoryIo::open(
        &root.store(),
        OpenMode::Reopen,
        limits(),
        super::super::tests::proposed_format(),
    )
    .unwrap();
    let (accepted, bytes) = io
        .read(
            NodeName::Root,
            super::super::tests::proposed_format().root_bytes,
        )
        .unwrap();
    let replacement = root.store().join("replacement");
    private_file(&replacement, &bytes);
    std::fs::rename(&replacement, root.store().join("root")).unwrap();
    assert!(io
        .stabilize_root(&accepted, super::super::node::ciphertext_digest(&bytes))
        .is_err());
}

#[test]
fn copied_inventory_and_symlinked_directory_fail_the_directory_binding() {
    let original = TemporaryDirectory::new();
    drop(create(&original));
    let copied = TemporaryDirectory::new();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(copied.store())
        .unwrap();
    private_file(
        &copied.store().join("root"),
        &std::fs::read(original.store().join("root")).unwrap(),
    );
    assert!(reopen(&copied).is_err());
    let alias = TemporaryDirectory::new();
    std::os::unix::fs::symlink(original.store(), alias.store()).unwrap();
    assert!(reopen(&alias).is_err());
    assert!(DirectoryIo::open(
        &alias.store(),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format()
    )
    .is_err());
    drop(reopen(&original).unwrap());
}

#[test]
fn interrupted_staging_is_reclaimed_only_after_authenticating_the_current_root() {
    for corrupt_root in [false, true] {
        let root = TemporaryDirectory::new();
        drop(create(&root));
        let staging = root.store().join("pending");
        private_file(&staging, b"interrupted");
        if corrupt_root {
            let root_file = root.store().join("root");
            let mut bytes = std::fs::read(&root_file).unwrap();
            bytes[0] ^= 1;
            std::fs::write(root_file, bytes).unwrap();
            assert!(reopen(&root).is_err());
            assert_eq!(std::fs::read(&staging).unwrap(), b"interrupted");
        } else {
            drop(reopen(&root).unwrap());
            assert!(!staging.exists());
        }
    }
}

#[test]
fn a_replaced_staging_name_cannot_publish_an_unrelated_inode() {
    let root = TemporaryDirectory::new();
    drop(create(&root));
    let mut io = DirectoryIo::open(
        &root.store(),
        OpenMode::Reopen,
        limits(),
        super::super::tests::proposed_format(),
    )
    .unwrap();
    io.write_temporary(b"original").unwrap();
    std::fs::rename(root.store().join("pending"), root.store().join("moved")).unwrap();
    private_file(&root.store().join("pending"), b"substitute");
    assert!(io.sync_temporary().is_err());
    assert!(io.rename_temporary(NodeName::Root).is_err());
    assert_eq!(
        std::fs::read(root.store().join("pending")).unwrap(),
        b"substitute"
    );
}

#[test]
fn invalid_root_modes_and_untrusted_parent_are_refused_before_creation() {
    let root = TemporaryDirectory::new();
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(DirectoryIo::open(
        &root.store(),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format()
    )
    .is_err());
    assert!(!root.store().exists());
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(create(&root));
    std::fs::set_permissions(root.store(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(reopen(&root).is_err());
}

#[test]
fn ancestor_symlinks_are_refused_before_create_or_reopen() {
    let mut failures = Vec::new();
    for mode in [OpenMode::CreateNew, OpenMode::Reopen] {
        let root = TemporaryDirectory::new();
        let real = root.0.join("real");
        let parent = real.join("parent");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&real)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let inventory = parent.join("inventory");
        if mode == OpenMode::Reopen {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&inventory)
                .unwrap();
        }
        let alias = root.0.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let result = DirectoryIo::open(
            &alias.join("parent/inventory"),
            mode,
            limits(),
            super::super::tests::proposed_format(),
        );
        if result.is_ok() || inventory.exists() != (mode == OpenMode::Reopen) {
            failures.push(mode == OpenMode::Reopen);
        }
    }
    assert!(
        failures.is_empty(),
        "ancestor symlink accepted or written through: {failures:?}"
    );
}

#[test]
fn binding_revalidation_refuses_an_ancestor_replaced_by_a_symlink() {
    let root = TemporaryDirectory::new();
    let ancestor = root.0.join("ancestor");
    let parent = ancestor.join("parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&ancestor)
        .unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .unwrap();
    let io = DirectoryIo::open(
        &parent.join("inventory"),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format(),
    )
    .unwrap();
    let moved = root.0.join("moved");
    std::fs::rename(&ancestor, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &ancestor).unwrap();
    assert!(io.check_binding().is_err());
    assert!(moved.join("parent/inventory").exists());
}

#[test]
fn dropping_the_owner_releases_the_lease_despite_an_inherited_open_description() {
    let root = TemporaryDirectory::new();
    let io = DirectoryIo::open(
        &root.store(),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format(),
    )
    .unwrap();
    // dup shares the open-file description, exactly as an inherited descriptor
    // does during fork-before-exec. CLOEXEC alone cannot end that interval.
    let inherited = rustix::io::dup(&io.root).unwrap();
    assert!(matches!(
        DirectoryIo::open(
            &root.store(),
            OpenMode::Reopen,
            limits(),
            super::super::tests::proposed_format(),
        ),
        Err(InventoryError::StoreBusy)
    ));
    drop(io);
    let next = DirectoryIo::open(
        &root.store(),
        OpenMode::Reopen,
        limits(),
        super::super::tests::proposed_format(),
    );
    assert!(
        next.is_ok(),
        "dropped owner left its lease on an inherited descriptor"
    );
    drop(inherited);
}

#[test]
fn dropping_a_foreign_process_copy_never_unlocks_the_live_owner() {
    let root = TemporaryDirectory::new();
    let parent = DirectoryIo::open(
        &root.store(),
        OpenMode::CreateNew,
        limits(),
        super::super::tests::proposed_format(),
    )
    .unwrap();
    // Model a fork child's process mismatch while sharing the real open-file
    // description. No unsafe fork or test-only production bypass is needed.
    let child = DirectoryIo {
        root: rustix::io::dup(&parent.root).unwrap(),
        path: parent.path.clone(),
        device: parent.device,
        inode: parent.inode,
        owner: parent.owner,
        process: parent.process.checked_add(1).unwrap(),
        limits: parent.limits,
        format: parent.format,
        temporary: None,
    };
    assert!(matches!(
        child.check_binding(),
        Err(InventoryError::WrongBinding)
    ));
    drop(child);
    parent.check_binding().unwrap();
    assert!(matches!(
        DirectoryIo::open(
            &root.store(),
            OpenMode::Reopen,
            limits(),
            super::super::tests::proposed_format(),
        ),
        Err(InventoryError::StoreBusy)
    ));
}

#[cfg(target_os = "linux")]
mod descriptor_process_tests;
