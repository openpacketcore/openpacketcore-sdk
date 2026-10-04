//! Complete lease-path tests for explicit configured-name/descriptor custody.

use super::*;
use crate::test_process::CommandExt as _;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::process::{Child, Command, Stdio};
use tokio::net::{UnixListener, UnixStream};

const CHILD_TEST: &str = "consensus::storage::pinned_directory_tests::pinned_namespace_child";
const CHILD_ROOT: &str = "OPC_SNAPSHOT_PIN_TEST_ROOT";
const CHILD_ROLE: &str = "OPC_SNAPSHOT_PIN_TEST_ROLE";
const CHILD_MODE: &str = "OPC_SNAPSHOT_PIN_TEST_MODE";
const CHILD_FD: &str = "OPC_SNAPSHOT_PIN_TEST_FD";
const CHILD_NAMESPACE: &str = "OPC_SNAPSHOT_PIN_TEST_NAMESPACE";
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const ADMITTED: u8 = 1;
const ADDRESS_IN_USE: u8 = 2;
const OTHER_REJECTION: u8 = 3;
const RELEASE: u8 = 4;
const RETIRED: u8 = 5;

fn private_directory(path: &Path) {
    std::fs::create_dir(path).expect("create synthetic snapshot directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("make synthetic snapshot directory private");
}

async fn admit_pin(
    backend: &SqliteSessionBackend,
    configured: &Path,
    descriptor: File,
) -> io::Result<Arc<SnapshotDirectoryLease>> {
    acquire_snapshot_directory(
        backend,
        SnapshotDirectory::from_pinned(configured, descriptor)?,
    )
    .await
}

struct Actor {
    child: Child,
    channel: UnixStream,
    outcome: u8,
}

impl Actor {
    async fn start(root: &Path, role: &str, mode: &str, descriptor: i32) -> Self {
        Self::start_in_namespace(root, role, role, mode, descriptor).await
    }

    async fn start_in_namespace(
        root: &Path,
        role: &str,
        namespace: &str,
        mode: &str,
        descriptor: i32,
    ) -> Self {
        let socket_path = root.join("handshake.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind synthetic actor handshake");
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ROOT, root)
            .env(CHILD_ROLE, role)
            .env(CHILD_MODE, mode)
            .env(CHILD_FD, descriptor.to_string())
            .env(CHILD_NAMESPACE, namespace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .test_spawn()
            .expect("spawn synthetic lease actor");
        // Install the child guard before any fallible handshake wait.
        let mut child = ChildGuard(Some(child));
        let (mut channel, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .expect("lease actor handshake deadline")
            .expect("accept lease actor handshake");
        std::fs::remove_file(&socket_path).expect("unlink owned actor handshake name");
        let outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.read_u8())
            .await
            .expect("lease actor admission deadline")
            .expect("read lease actor admission");
        Self {
            child: child.0.take().expect("transfer guarded actor"),
            channel,
            outcome,
        }
    }

    async fn retire(mut self) {
        self.channel.write_u8(RELEASE).await.expect("release actor");
        assert_eq!(
            tokio::time::timeout(HANDSHAKE_TIMEOUT, self.channel.read_u8())
                .await
                .expect("lease actor retirement deadline")
                .expect("read actor retirement"),
            RETIRED,
            "actor acknowledges final lease retirement"
        );
        assert!(self.child.wait().expect("join lease actor").success());
    }
}

impl Drop for Actor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
#[ignore = "controlled subprocess for the complete pinned-directory lease tests"]
async fn pinned_namespace_child() {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("actor root"));
    let role = std::env::var(CHILD_ROLE).expect("actor role");
    let mode = std::env::var(CHILD_MODE).expect("actor mode");
    let number = std::env::var(CHILD_FD)
        .expect("actor descriptor")
        .parse::<i32>()
        .expect("synthetic descriptor number");
    let mut channel = UnixStream::connect(root.join("handshake.sock"))
        .await
        .expect("connect actor handshake");
    let namespace = std::env::var(CHILD_NAMESPACE).unwrap_or_else(|_| role.clone());
    let configured = root.join(namespace).join("snapshots");
    let descriptor = File::open(&configured).expect("open actor snapshot descriptor");
    let descriptor = File::from(
        rustix::io::fcntl_dupfd_cloexec(&descriptor, number)
            .expect("reserve equal synthetic procfd number"),
    );
    assert_eq!(
        descriptor.as_raw_fd(),
        number,
        "descriptor fixture is exact"
    );
    let backend = SqliteSessionBackend::open(root.join(format!("{role}.sqlite")))
        .expect("open actor database");
    let lease = match mode.as_str() {
        "pinned" => admit_pin(&backend, &configured, descriptor).await,
        "path" => acquire_snapshot_directory_lease(&backend, &configured).await,
        _ => panic!("unknown synthetic actor mode"),
    };
    let outcome = match &lease {
        Ok(_) => ADMITTED,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => ADDRESS_IN_USE,
        Err(_) => OTHER_REJECTION,
    };
    channel.write_u8(outcome).await.expect("report admission");
    assert_eq!(
        tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.read_u8())
            .await
            .expect("actor release deadline")
            .expect("read actor release"),
        RELEASE
    );
    drop(lease);
    drop(backend);
    channel.write_u8(RETIRED).await.expect("report retirement");
}

#[tokio::test]
async fn independent_pinned_namespaces_survive_equal_procfd_spelling() {
    let root = tempfile::tempdir().expect("private actor workspace");
    for role in ["first", "second"] {
        private_directory(&root.path().join(role));
        private_directory(&root.path().join(role).join("snapshots"));
    }
    let first_metadata =
        std::fs::metadata(root.path().join("first/snapshots")).expect("first directory identity");
    let second_metadata =
        std::fs::metadata(root.path().join("second/snapshots")).expect("second directory identity");
    assert_ne!(
        (first_metadata.dev(), first_metadata.ino()),
        (second_metadata.dev(), second_metadata.ino())
    );
    let first = Actor::start(root.path(), "first", "pinned", 200).await;
    assert_eq!(
        first.outcome, ADMITTED,
        "first real lease owns its namespace"
    );
    let second = Actor::start(root.path(), "second", "pinned", 200).await;
    let simultaneous_outcome = second.outcome;
    second.retire().await;
    let first_database =
        std::fs::metadata(root.path().join("first.sqlite")).expect("first database identity");
    let second_database =
        std::fs::metadata(root.path().join("second.sqlite")).expect("second database identity");
    assert_ne!(
        (first_database.dev(), first_database.ino()),
        (second_database.dev(), second_database.ino()),
        "the actors own distinct actual databases"
    );
    // This checks B's real directory/database while the actual A lease stays
    // held. A procfd-key conflict must not masquerade as ownership of B.
    let ordinary = Actor::start(root.path(), "second", "path", 200).await;
    assert_eq!(
        ordinary.outcome, ADMITTED,
        "distinct ordinary namespace control"
    );
    ordinary.retire().await;
    first.retire().await;
    let after_retirement = Actor::start(root.path(), "second", "pinned", 200).await;
    assert_eq!(
        after_retirement.outcome, ADMITTED,
        "procfd after holder retirement"
    );
    after_retirement.retire().await;
    assert_eq!(
        simultaneous_outcome, ADMITTED,
        "P808_INDEPENDENT_NAMESPACE_ADMISSION: equal descriptor spellings must not merge distinct configured namespaces"
    );
}

#[tokio::test]
async fn same_pinned_name_excludes_replacement_across_process_and_descriptor_changes() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("private replacement workspace");
    let original_parent = root.path().join("original");
    let replacement_parent = root.path().join("replacement");
    for parent in [&original_parent, &replacement_parent] {
        private_directory(parent);
        private_directory(&parent.join("snapshots"));
    }
    let parent = root.path().join("first");
    symlink(&original_parent, &parent).expect("configure original parent");
    let first = Actor::start(root.path(), "first", "pinned", 200).await;
    assert_eq!(first.outcome, ADMITTED, "original complete lease holds D1");
    std::fs::remove_file(&parent).expect("retarget configured parent");
    symlink(&replacement_parent, &parent).expect("same configured name now resolves to D2");
    let replacement =
        Actor::start_in_namespace(root.path(), "second", "first", "pinned", 201).await;
    let replacement_outcome = replacement.outcome;
    replacement.retire().await;
    first.retire().await;
    let retired = Actor::start_in_namespace(root.path(), "second", "first", "pinned", 202).await;
    assert_eq!(
        retired.outcome, ADMITTED,
        "D2 admits after the last D1 owner retires"
    );
    retired.retire().await;
    assert_eq!(
        replacement_outcome, ADDRESS_IN_USE,
        "P808_CONFIGURED_KEY_EXCLUSION: descriptor changes and canonical parent retargeting cannot change the configured namespace"
    );
}

#[test]
fn pinned_name_must_identify_the_exact_secure_directory() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("private correspondence workspace");
    let first = root.path().join("first");
    let second = root.path().join("second");
    private_directory(&first);
    private_directory(&second);
    assert!(
        SnapshotDirectory::from_pinned(&first, File::open(&second).expect("second capability"))
            .is_err(),
        "P808_KEY_CAPABILITY_CORRESPONDENCE: a valid but foreign directory is rejected"
    );
    let link = root.path().join("link");
    symlink(&first, &link).expect("synthetic final symlink");
    assert!(
        SnapshotDirectory::from_pinned(&link, File::open(&first).expect("first capability"))
            .is_err()
    );
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o722))
        .expect("make a deliberately inadmissible directory");
    assert!(SnapshotDirectory::from_pinned(
        &first,
        File::open(&first).expect("insecure capability")
    )
    .is_err());
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o700))
        .expect("restore private fixture permissions");
    SnapshotDirectory::from_pinned(&first, File::open(&first).expect("restored capability"))
        .expect("the matching private directory is admitted");
}

#[tokio::test]
async fn pinned_handoff_keeps_original_io_and_rechecks_descriptor_permissions() {
    let root = tempfile::tempdir().expect("private handoff workspace");
    let configured = root.path().join("snapshots");
    let detached = root.path().join("detached");
    private_directory(&configured);
    let handoff = SnapshotDirectory::from_pinned(
        &configured,
        File::open(&configured).expect("original capability"),
    )
    .expect("bind original name and capability");
    let backend =
        SqliteSessionBackend::open(root.path().join("sessions.sqlite")).expect("handoff database");
    std::fs::rename(&configured, &detached).expect("replace name after explicit handoff");
    private_directory(&configured);
    let lease = acquire_snapshot_directory(&backend, handoff)
        .await
        .expect("admit original capability after name replacement");
    let name = std::ffi::OsStr::new("synthetic-child");
    let child = lease
        .namespace
        .create_new(name, true)
        .expect("create through admitted capability");
    let actual = child.metadata().expect("created child identity");
    let expected = std::fs::metadata(detached.join(name)).expect("child in original directory");
    assert_eq!(
        (actual.dev(), actual.ino()),
        (expected.dev(), expected.ino())
    );
    assert!(
        !configured.join(name).exists(),
        "replacement never receives admitted I/O"
    );
    drop(child);
    lease
        .namespace
        .unlink(name)
        .expect("unlink through original capability");
    lease.namespace.sync().expect("sync original capability");
    drop(lease);

    let handoff = SnapshotDirectory::from_pinned(
        &configured,
        File::open(&configured).expect("replacement capability"),
    )
    .expect("bind private replacement");
    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o722))
        .expect("invalidate permission after handoff");
    assert!(matches!(
        acquire_snapshot_directory(&backend, handoff).await,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied
    ));
    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o700))
        .expect("restore fixture permissions");
}

#[tokio::test]
async fn pinned_directory_uses_an_independent_flock_description() {
    use nix::fcntl::{Flock, FlockArg};

    let root = tempfile::tempdir().expect("private flock workspace");
    let configured = root.path().join("snapshots");
    private_directory(&configured);
    let backend =
        SqliteSessionBackend::open(root.path().join("sessions.sqlite")).expect("flock database");
    let owner = Flock::lock(
        File::open(&configured).expect("external directory owner"),
        FlockArg::LockExclusiveNonblock,
    )
    .expect("hold caller's original flock");
    let result = admit_pin(
        &backend,
        &configured,
        owner
            .try_clone()
            .expect("a duplicate shares the caller's original OFD"),
    )
    .await;
    let rejected = matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock);
    drop(result);
    let probe = Flock::lock(
        File::open(&configured).expect("independent contender"),
        FlockArg::LockExclusiveNonblock,
    );
    assert!(
        probe.is_err(),
        "P808_INDEPENDENT_FLOCK: failed admission must not unlock the supplied description"
    );
    drop(probe);
    drop(owner);
    let admitted = admit_pin(
        &backend,
        &configured,
        File::open(&configured).expect("released directory"),
    )
    .await
    .expect("complete lease admits only after external owner retirement");
    drop(admitted);
    assert!(
        rejected,
        "a duplicate of an already locked descriptor must contend independently"
    );
}

#[tokio::test]
async fn pinned_directory_and_database_aliases_preserve_both_owners() {
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("private alias workspace");
    let parent = root.path().join("parent");
    let alias = root.path().join("alias");
    private_directory(&parent);
    let configured = parent.join("snapshots");
    private_directory(&configured);
    symlink(&parent, &alias).expect("distinct configured parent spelling");
    let database = root.path().join("sessions.sqlite");
    let backend = SqliteSessionBackend::open(&database).expect("original database");
    let other_backend =
        SqliteSessionBackend::open(root.path().join("other.sqlite")).expect("independent database");
    let owner = admit_pin(
        &backend,
        &configured,
        File::open(&configured).expect("original directory"),
    )
    .await
    .expect("hold complete original lease");
    assert!(
        matches!(
            admit_pin(&other_backend, &alias.join("snapshots"), File::open(&configured).expect("directory alias")).await,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ),
        "different namespace names cannot bypass directory inode ownership"
    );
    let other_directory = root.path().join("other-snapshots");
    private_directory(&other_directory);
    assert!(
        matches!(
            admit_pin(&backend, &other_directory, File::open(&other_directory).expect("other directory")).await,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ),
        "same-backend OFD cannot own a second namespace"
    );
    let database_alias = root.path().join("database-alias.sqlite");
    symlink(&database, &database_alias).expect("synthetic database alias");
    let alias_backend = SqliteSessionBackend::open(&database_alias)
        .expect("independent backend through the same database alias");
    assert!(
        matches!(
            admit_pin(&alias_backend, &other_directory, File::open(&other_directory).expect("alias destination")).await,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ),
        "an independently opened database alias cannot own a second namespace"
    );
    drop(alias_backend);
    let probe = Flock::lock(
        File::open(&database).expect("independent database lock probe"),
        FlockArg::LockExclusiveNonblock,
    );
    assert!(
        probe.is_err(),
        "rejected same-backend admission must not unlock its database"
    );
    drop(probe);
    let directory_probe = Flock::lock(
        File::open(&configured).expect("independent directory lock probe"),
        FlockArg::LockExclusiveNonblock,
    );
    assert!(
        directory_probe.is_err(),
        "directory alias rejection keeps the original flock"
    );
    drop(directory_probe);
    drop(owner);
    admit_pin(
        &backend,
        &other_directory,
        File::open(&other_directory).expect("released second namespace"),
    )
    .await
    .expect("database moves only after its complete owner retires");
}

#[tokio::test]
async fn pinned_cleanup_retains_configured_key_and_exact_directory_until_acknowledgement() {
    use super::super::snapshot::{
        fail_namespace_pinned_post_create_setup_for_test, fail_retained_namespace_sync_for_test,
    };

    let root = tempfile::tempdir().expect("private retained cleanup workspace");
    let parent = root.path().join("first");
    private_directory(&parent);
    let configured = parent.join("snapshots");
    private_directory(&configured);
    let backend = SqliteSessionBackend::open(root.path().join("first.sqlite"))
        .expect("retained cleanup database");
    let lease = admit_pin(
        &backend,
        &configured,
        File::open(&configured).expect("original cleanup directory"),
    )
    .await
    .expect("hold complete original cleanup lease");
    let original_identity = lease.namespace.directory_identity();
    // Exercise the real post-O_EXCL owner: setup fails, the exact child is
    // removed, and failed parent fsync retains the namespace's actual fences.
    fail_namespace_pinned_post_create_setup_for_test(&lease.namespace);
    fail_retained_namespace_sync_for_test(&lease.namespace);
    assert!(PinnedSqliteFile::create_new_in_namespace(
        Arc::clone(&lease.namespace),
        std::ffi::OsStr::new("build-00000000-0000-4000-8000-000000000001.sqlite"),
    )
    .is_err());
    assert!(has_unpublished_snapshot_cleanup_failure(&configured));
    drop(lease);
    std::fs::rename(&configured, parent.join("detached")).expect("detach pending cleanup D1");
    private_directory(&configured);
    let foreign = Actor::start_in_namespace(root.path(), "second", "first", "pinned", 201).await;
    let foreign_outcome = foreign.outcome;
    foreign.retire().await;
    assert_eq!(
        foreign_outcome, ADDRESS_IN_USE,
        "pending cleanup retains cross-process key exclusion after outer lease Drop"
    );
    let recovered = admit_pin(
        &backend,
        &configured,
        File::open(&configured).expect("replacement cleanup directory"),
    )
    .await
    .expect("only the same database may reenter pending cleanup custody");
    assert_ne!(recovered.namespace.directory_identity(), original_identity);
    let failures = pending_unpublished_snapshot_cleanup_failures(&configured)
        .expect("capture exact pending cleanup generations");
    assert_eq!(failures.len(), 1, "one real fsync failure is retained");
    assert_eq!(
        failures[0].namespace().directory_identity(),
        original_identity
    );
    failures[0]
        .namespace()
        .sync()
        .expect("fsync the retained original D1");
    assert!(acknowledge_unpublished_snapshot_cleanup_failure(
        &configured,
        &failures[0]
    ));
    assert!(!has_unpublished_snapshot_cleanup_failure(&configured));
    drop(recovered);
    // A completed acknowledgement is not early release of another real owner:
    // the captured generation still holds D1's socket and database flock.
    let captured = Actor::start_in_namespace(root.path(), "second", "first", "pinned", 202).await;
    let captured_outcome = captured.outcome;
    captured.retire().await;
    assert_eq!(
        captured_outcome, ADDRESS_IN_USE,
        "captured cleanup authority keeps its lease until final Drop"
    );
    drop(failures);
    let retired = Actor::start_in_namespace(root.path(), "second", "first", "pinned", 203).await;
    assert_eq!(
        retired.outcome, ADMITTED,
        "fresh owner admits after exact sync, acknowledgement and final retirement"
    );
    retired.retire().await;
}
