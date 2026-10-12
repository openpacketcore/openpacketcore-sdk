//! Native format rejection through the ordinary backend and storage opener.

use super::*;
use crate::consensus::SessionRaft;
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;

const DATABASE: &str = "retained-bound.sqlite";
const ROOT_SELECTION: &str = "user.opc.native-root-v1";

#[derive(Debug, PartialEq, Eq)]
struct FileObservation {
    mode: u32,
    inode: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    bytes: Option<[u8; 32]>,
}

fn namespace(path: &Path) -> BTreeMap<PathBuf, FileObservation> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, FileObservation>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(!metadata.is_symlink());
        entries.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            FileObservation {
                mode: metadata.mode(),
                inode: metadata.ino(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                bytes: metadata
                    .is_file()
                    .then(|| Sha256::digest(std::fs::read(path).unwrap()).into()),
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(path, path, &mut entries);
    entries
}

fn root_selection(directory: &FixedRawReadStoreFixture) -> Vec<u8> {
    let file = std::fs::File::open(directory.path().join(DATABASE)).unwrap();
    let mut bytes = vec![0; 168];
    let length = rustix::fs::fgetxattr(&file, ROOT_SELECTION, &mut bytes[..]).unwrap();
    assert_eq!(length, bytes.len());
    bytes
}

fn write_root(directory: &FixedRawReadStoreFixture, bytes: &[u8]) {
    let root = directory.path().join(format!("{DATABASE}.native-wal/ROOT"));
    std::fs::write(root, bytes).unwrap();
    let file = std::fs::File::open(directory.path().join(DATABASE)).unwrap();
    rustix::fs::fsetxattr(
        &file,
        ROOT_SELECTION,
        bytes,
        rustix::fs::XattrFlags::REPLACE,
    )
    .unwrap();
    file.sync_all().unwrap();
}

async fn refused_open(
    directory: &FixedRawReadStoreFixture,
    mode: SessionPersistenceMode,
    expected_identity: SessionConsensusIdentity,
) -> SessionConsensusStorageError {
    let backend = SqliteSessionBackend::open(directory.path().join(DATABASE)).unwrap();
    let members = fixed_raw_read_members();
    let local = SessionConsensusNodeId::new(8).unwrap();
    let peers = members
        .iter()
        .copied()
        .filter(|node| *node != local)
        .map(|node| {
            (
                node,
                Arc::new(MembershipObservationProbePeer { node_id: node })
                    as Arc<dyn SessionConsensusPeer>,
            )
        })
        .collect();
    let network =
        SessionRaftNetworkFactory::try_new(expected_identity, local, members.clone(), peers)
            .unwrap();
    match open_fixed_with_persistence_and_roster_attestation_root(
        &backend,
        SnapshotDirectory::from_path(directory.snapshot_path().join("retained-bound-snapshots")),
        expected_identity,
        members.clone(),
        fixed_raw_read_bindings(&members),
        network.peer_directory(),
        PlacementResiliencePolicy::AllowReducedResilience,
        None,
        SnapshotIntegrityPolicy::FsVerity,
        mode,
    )
    .await
    {
        Err(error) => error,
        Ok(_) => panic!("unknown selected native format was admitted"),
    }
}

async fn assert_refused_without_writes(
    directory: &FixedRawReadStoreFixture,
    mode: SessionPersistenceMode,
    expected_identity: SessionConsensusIdentity,
    expected: SessionConsensusStorageError,
) {
    let before = (
        namespace(directory.path()),
        namespace(directory.snapshot_path()),
        root_selection(directory),
    );
    #[cfg(feature = "test-vfs")]
    {
        // Selecting the SQL fault-injection VFS cannot discard an existing
        // native owner and bypass its deferred read-only format admission.
        assert!(matches!(
            SqliteSessionBackend::open_with_vfs_for_test(directory.path().join(DATABASE), "unix"),
            Err(crate::StoreError::BackendUnavailable(message))
                if message == "native session state is unavailable"
        ));
        assert_eq!(
            (
                namespace(directory.path()),
                namespace(directory.snapshot_path()),
                root_selection(directory)
            ),
            before
        );
    }
    for _ in 0..2 {
        assert_eq!(
            refused_open(directory, mode, expected_identity).await,
            expected
        );
        assert_eq!(
            (
                namespace(directory.path()),
                namespace(directory.snapshot_path()),
                root_selection(directory)
            ),
            before
        );
    }
}

async fn close_engine(
    backend: SqliteSessionBackend,
    raft: SessionRaft,
    wal: Arc<crate::sqlite::consensus::wal::Wal>,
) -> Arc<crate::sqlite::consensus::wal::Wal> {
    raft.shutdown().await.unwrap();
    drop(raft);
    wal.shutdown_after_consensus().unwrap();
    drop(backend);
    wal
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_old_root_public_reopen_refuses_before_backend_or_snapshot_writes() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let directory = FixedRawReadStoreFixture::new();
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        let wal = close_engine(backend, raft, wal).await;
        let current = root_selection(&directory);
        let variants: &[(&[u8; 8], &[u8])] = match mode {
            SessionPersistenceMode::Durable => &[(b"OPCNR001", b"opc-session-native-wal-v1")],
            SessionPersistenceMode::Async => &[
                (b"OPCNA001", b"opc-session-native-async-v1"),
                (b"OPCNA002", b"opc-session-native-async-v2"),
                (b"OPCNA003", b"opc-session-native-async-v3"),
            ],
        };
        for (magic, domain) in variants {
            let mut old = current.clone();
            old[..8].copy_from_slice(*magic);
            let mut hash = Sha256::new();
            hash.update(domain);
            hash.update(serde_json::to_vec(&identity(1)).unwrap());
            hash.update(&old[40..104]);
            old[104..136].copy_from_slice(&hash.finalize());
            let checksum = Sha256::digest(&old[..136]);
            old[136..].copy_from_slice(&checksum);
            write_root(&directory, &old);
            assert_refused_without_writes(
                &directory,
                mode,
                identity(1),
                SessionConsensusStorageError::PersistenceFormatMismatch,
            )
            .await;
        }
        write_root(&directory, &current);
        drop(wal);
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        drop(close_engine(backend, raft, wal).await);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_future_generation_public_reopen_refuses_before_backend_or_snapshot_writes() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let directory = FixedRawReadStoreFixture::new();
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        let wal = close_engine(backend, raft, wal).await;
        let mut original = None;
        wal.rewrite_closed_native_generation_for_test(|bytes| {
            original = Some(bytes.clone());
            assert_eq!(&bytes[..8], b"OPCNJ006");
            bytes[..8].copy_from_slice(b"OPCNJ008");
        })
        .unwrap();
        for expected_identity in [identity(1), identity(2)] {
            assert_refused_without_writes(
                &directory,
                mode,
                expected_identity,
                SessionConsensusStorageError::CorruptState,
            )
            .await;
        }
        wal.rewrite_closed_native_generation_for_test(|bytes| *bytes = original.take().unwrap())
            .unwrap();
        drop(wal);
        assert_eq!(
            refused_open(&directory, mode, identity(2)).await,
            SessionConsensusStorageError::IdentityMismatch
        );
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        drop(close_engine(backend, raft, wal).await);
    }
}
