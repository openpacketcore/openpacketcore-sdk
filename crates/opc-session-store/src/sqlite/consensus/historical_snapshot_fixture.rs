//! Test-only historical fixture using the complete original snapshot installer.

use super::*;
use crate::consensus::snapshot::{
    PinnedSqliteFile, SNAPSHOT_ENVELOPE_FOOTER_BYTES, SNAPSHOT_MAX_BYTES,
};
use crate::sqlite::ops::RestoreScanIncarnation;
use opc_consensus::engine::SnapshotMeta;
use std::io::{Read, Seek, SeekFrom};
use wal::snapshot::{InstallSource, NativeSnapshotAuthority};

pub(crate) struct Installed {
    pub(crate) connection: Arc<tokio::sync::Mutex<Connection>>,
    pub(crate) origin: Arc<NativeSnapshotAuthority>,
    pub(crate) binding: [u8; 32],
}

pub(crate) fn original_install(
    published_path: &Path,
    mut source: std::fs::File,
    raw_cache: &Path,
    backend_path: &Path,
    identity: SessionConsensusIdentity,
    bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
) -> Installed {
    let length = source.metadata().unwrap().len();
    source
        .seek(SeekFrom::End(-(SNAPSHOT_ENVELOPE_FOOTER_BYTES as i64)))
        .unwrap();
    let mut footer = [0_u8; SNAPSHOT_ENVELOPE_FOOTER_BYTES as usize];
    source.read_exact(&mut footer).unwrap();
    assert_eq!(&footer[..8], b"OPCSNP01");
    let payload_length = u64::from_be_bytes(footer[8..16].try_into().unwrap());
    assert_eq!(payload_length + SNAPSHOT_ENVELOPE_FOOTER_BYTES, length);
    let checksum: [u8; 32] = footer[16..].try_into().unwrap();
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut raw_writer = std::fs::File::create_new(raw_cache).unwrap();
    assert_eq!(
        std::io::copy(&mut (&mut source).take(payload_length), &mut raw_writer).unwrap(),
        payload_length
    );
    raw_writer.sync_all().unwrap();
    drop(raw_writer);
    let mut raw = PinnedSqliteFile::from_file(
        std::fs::File::open(raw_cache).unwrap(),
        raw_cache.to_path_buf(),
    )
    .unwrap();
    raw.seal_fixed().unwrap();
    let mut published = PinnedSqliteFile::from_file_and_verify(
        source,
        published_path.to_path_buf(),
        crate::SnapshotIntegrityPolicy::FsVerity,
    )
    .unwrap();
    published
        .verify_snapshot_envelope_and_bind_immutable_generation(
            published_path,
            b"OPCSNP01",
            SNAPSHOT_ENVELOPE_FOOTER_BYTES,
            SNAPSHOT_MAX_BYTES,
            checksum,
            length,
        )
        .unwrap();
    let incoming = Connection::open_with_flags(
        pinned_snapshot_uri(&raw, true),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap();
    let candidate = (
        SnapshotMeta {
            last_log_id: read_applied_sync(&incoming, identity).unwrap(),
            last_membership: read_membership_sync(&incoming, identity).unwrap(),
            // A diagnostic installation ID, not an assertion about the live
            // producer's original snapshot metadata or quorum authority.
            snapshot_id: format!(
                "isolated-memory-{}",
                published_path.file_stem().unwrap().to_str().unwrap()
            ),
        },
        published_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        checksum,
        length,
    );
    drop(incoming);
    let source =
        InstallSource::new(candidate, raw, published, published_path.to_path_buf()).unwrap();
    let backend = SqliteSessionBackend::open(backend_path).unwrap();
    let connection = Arc::clone(&backend.conn);
    let binding = wal::Binding {
        identity,
        generation: [0xE7; 32],
        basis: [0xE9; 32],
        native: true,
        persistence: crate::SessionPersistenceMode::Async,
    };
    let origin = {
        let conn = connection.blocking_lock();
        conn.pragma_update(None, "cache_size", -2048).unwrap();
        conn.pragma_update(None, "mmap_size", 0).unwrap();
        initialize_schema_with_storage_anchor_and_pending_and_bindings(
            &conn,
            None,
            identity,
            &bindings.keys().copied().collect(),
            bindings,
            None,
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::default()),
            None,
        )
        .unwrap();
        source
            .apply_native_original(
                &conn,
                binding,
                None,
                &RestoreScanIncarnation::new().unwrap(),
                &|| Ok(()),
            )
            .unwrap()
    };
    drop(source);
    drop(backend);
    // Only this freshly extracted input cache is removed. The original
    // sealed source and every diagnostic output/evidence file are retained.
    std::fs::remove_file(raw_cache).unwrap();
    Installed {
        connection,
        origin,
        binding: binding.digest().unwrap(),
    }
}
