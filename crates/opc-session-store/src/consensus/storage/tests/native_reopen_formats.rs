//! Native format rejection through the ordinary backend and storage opener.

use super::*;
use crate::consensus::SessionRaft;
use opc_consensus::engine::raft::{AppendEntriesRequest, AppendEntriesResponse};
use opc_consensus::engine::Vote;
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

async fn select_command_and_snapshot(raft: &SessionRaft) {
    let response = raft
        .append_entries(AppendEntriesRequest {
            vote: Vote::new_committed(1, node_id()),
            prev_log_id: None,
            leader_commit: Some(log_id(1)),
            entries: vec![
                fixed_initial_membership_entry(),
                normal_entry(1, advance_time_command(identity(1), 1, 1)),
            ],
        })
        .await
        .unwrap();
    assert!(matches!(response, AppendEntriesResponse::Success));
    raft.wait(Some(Duration::from_secs(300)))
        .metrics(
            |metrics| metrics.last_applied == Some(log_id(1)),
            "fixture command applied",
        )
        .await
        .unwrap();
    raft.trigger().snapshot().await.unwrap();
    raft.wait(Some(Duration::from_secs(300)))
        .metrics(
            |metrics| metrics.snapshot == Some(log_id(1)),
            "fixture snapshot selected",
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_unknown_frontier_public_reopen_refuses_before_backend_or_snapshot_writes() {
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
            assert_eq!(&bytes[..8], b"OPCNJB\x06\x00");
            let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
            let field = b"\"frontiers\":{";
            let offset = 12
                + bytes[12..12 + length]
                    .windows(field.len())
                    .position(|window| window == field)
                    .unwrap()
                + field.len();
            let extension = b"\"future_retirement_floor\":1,";
            let selected_length = bytes.len();
            assert!(bytes[selected_length - extension.len()..]
                .iter()
                .all(|byte| *byte == 0));
            bytes.splice(offset..offset, extension.iter().copied());
            bytes[8..12].copy_from_slice(&((length + extension.len()) as u32).to_le_bytes());
            bytes.truncate(selected_length);
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
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        drop(close_engine(backend, raft, wal).await);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_unknown_command_public_reopen_refuses_before_backend_or_snapshot_writes() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let directory = FixedRawReadStoreFixture::new();
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        select_command_and_snapshot(&raft).await;
        let wal = close_engine(backend, raft, wal).await;
        let mut original = None;
        wal.rewrite_closed_native_generation_for_test(|bytes| {
            original = Some(bytes.clone());
            let known = b"AdvanceLogicalTime";
            let unknown = b"UnknownLogicalTime";
            assert_eq!(known.len(), unknown.len());
            let offsets: Vec<_> = bytes
                .windows(known.len())
                .enumerate()
                .filter_map(|(offset, value)| (value == known).then_some(offset))
                .collect();
            assert!(
                !offsets.is_empty(),
                "selected generation carries the real command row"
            );
            for offset in offsets {
                bytes[offset..offset + known.len()].copy_from_slice(unknown);
            }
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
        let (backend, raft, wal, _) =
            native_log_retained_bound::open_engine(&directory, mode).await;
        raft.wait(Some(Duration::from_secs(300)))
            .metrics(
                |metrics| metrics.last_applied == Some(log_id(1)),
                "reopened fixture applied",
            )
            .await
            .unwrap();
        drop(close_engine(backend, raft, wal).await);
    }
}

/// Reseal an otherwise unchanged exported SQLite image and publish matching
/// metadata through the normal owner. The positive twin executes this same
/// fixture path with the supported schema value. Thus neither checksum,
/// fs-verity nor selected-generation corruption can explain the refusal.
async fn select_image_schema_fixture(
    directory: &FixedRawReadStoreFixture,
    wal: &Arc<crate::sqlite::consensus::wal::Wal>,
    unknown: bool,
) {
    let snapshots = wal.native_retained_snapshots().unwrap();
    assert_eq!(snapshots.len(), 1);
    let mut candidate = snapshots[0].clone();
    let snapshot_directory = directory.snapshot_path().join("retained-bound-snapshots");
    let bytes = std::fs::read(snapshot_directory.join(&candidate.1)).unwrap();
    let raw_path = snapshot_directory.join("schema-fixture.sqlite");
    std::fs::write(
        &raw_path,
        &bytes[..bytes.len() - SNAPSHOT_FOOTER_BYTES as usize],
    )
    .unwrap();
    let conn = rusqlite::Connection::open(&raw_path).unwrap();
    conn.execute_batch("PRAGMA journal_mode = OFF;").unwrap();
    let supported: i64 = conn
        .query_row(
            "SELECT schema_version FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        conn.execute(
            "UPDATE consensus_identity SET schema_version = ?1 WHERE singleton = 1",
            [if unknown {
                supported + 1_000
            } else {
                supported
            }],
        )
        .unwrap(),
        1
    );
    drop(conn);
    let mut image = std::fs::read(&raw_path).unwrap();
    let payload_length = image.len() as u64;
    candidate.2 = Sha256::digest(&image).into();
    image.extend_from_slice(SNAPSHOT_FOOTER_MAGIC);
    image.extend_from_slice(&payload_length.to_be_bytes());
    image.extend_from_slice(&candidate.2);
    candidate.3 = image.len() as u64;
    candidate.1 = format!("snapshot-{}.opc", uuid::Uuid::new_v4());
    let path = snapshot_directory.join(&candidate.1);
    std::fs::write(&raw_path, image).unwrap();
    std::fs::rename(&raw_path, &path).unwrap();
    let mut pin = PinnedSqliteFile::reopen_and_seal_fixed(&path).unwrap();
    pin.verify_snapshot_envelope_and_bind_immutable_generation(
        &path,
        SNAPSHOT_FOOTER_MAGIC,
        SNAPSHOT_FOOTER_BYTES,
        SNAPSHOT_MAX_BYTES,
        candidate.2,
        candidate.3,
    )
    .unwrap();
    let wal = Arc::clone(wal);
    tokio::task::spawn_blocking(move || wal.native_publish_snapshot(candidate))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_unknown_image_schema_public_reopen_refuses_before_backend_or_snapshot_writes() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for unknown in [false, true] {
            let directory = FixedRawReadStoreFixture::new();
            let (backend, raft, wal, _) =
                native_log_retained_bound::open_engine(&directory, mode).await;
            select_command_and_snapshot(&raft).await;
            select_image_schema_fixture(&directory, &wal, unknown).await;
            drop(close_engine(backend, raft, wal).await);
            if unknown {
                for expected_identity in [identity(1), identity(2)] {
                    assert_refused_without_writes(
                        &directory,
                        mode,
                        expected_identity,
                        SessionConsensusStorageError::SchemaVersionMismatch,
                    )
                    .await;
                }
            } else {
                let (backend, raft, wal, _) =
                    native_log_retained_bound::open_engine(&directory, mode).await;
                raft.wait(Some(Duration::from_secs(300)))
                    .metrics(
                        |metrics| metrics.last_applied == Some(log_id(1)),
                        "reopened fixture applied",
                    )
                    .await
                    .unwrap();
                drop(close_engine(backend, raft, wal).await);
            }
        }
    }
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
            assert_eq!(&bytes[..8], b"OPCNJB\x06\x00");
            bytes[..8].copy_from_slice(b"OPCNJB\x07\x00");
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
