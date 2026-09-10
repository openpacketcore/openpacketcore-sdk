//! Focused real-file tests of the private WAL using the existing V2 fixtures.

use std::collections::BTreeMap;
use std::sync::{mpsc, Condvar, Mutex};
use std::time::Instant;

use super::super::wal::adapter::WalLogStore;
use super::super::wal::application::ApplyControl;
use super::super::wal::{Binding, IoControl, Limits, Operation, Point, Wal};
use super::*;

struct Pause {
    point: Point,
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Pause {
    fn new(point: Point) -> Arc<Self> {
        Arc::new(Self {
            point,
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
        })
    }

    fn control(self: &Arc<Self>) -> IoControl {
        let pause = Arc::clone(self);
        IoControl {
            hook: Arc::new(move |point| {
                if point != pause.point {
                    return Ok(());
                }
                let mut state = pause.state.lock().unwrap();
                if state.0 {
                    return Ok(());
                }
                state.0 = true;
                pause.changed.notify_all();
                let (state, timeout) = pause
                    .changed
                    .wait_timeout_while(state, Duration::from_secs(5), |state| !state.1)
                    .unwrap();
                if timeout.timed_out() && !state.1 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "test WAL gate not released",
                    ));
                }
                Ok(())
            }),
            ..IoControl::default()
        }
    }

    fn entered(&self) {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.0)
            .unwrap();
        assert!(state.0, "writer reached declared boundary");
    }

    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

struct Fixture {
    wal: Wal,
    pause: Option<Arc<Pause>>,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new(limits: Limits, control: IoControl, pause: Option<Arc<Pause>>, activate: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source = SqliteSessionBackend::open(directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        if activate {
            sdk741_initialize(&conn, &source.caps);
        } else {
            initialize_schema(&conn, identity(), &expected_members()).unwrap();
            let membership = membership_entry();
            append_logs_sync(&conn, identity(), std::slice::from_ref(&membership)).unwrap();
            save_committed_sync(&conn, identity(), Some(membership.log_id)).unwrap();
            apply_entries_sync(&conn, identity(), &source.caps, vec![membership]).unwrap();
        }
        let wal = Wal::create(
            &directory.path().join("wal"),
            &conn,
            identity(),
            [0xA1; 32],
            limits,
            control,
        )
        .unwrap();
        drop(conn);
        Self {
            wal,
            pause,
            directory,
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("wal")
    }

    fn reopen(&self, limits: Limits, control: IoControl) -> io::Result<Wal> {
        Wal::open(&self.path(), self.wal.binding(), limits, control)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(pause) = &self.pause {
            pause.release();
        }
        let _ = self.wal.shutdown();
    }
}

fn fixture() -> Fixture {
    Fixture::new(Limits::default(), IoControl::default(), None, true)
}

fn batch(index: u64) -> Entry<SessionRaftTypeConfig> {
    fenced_transition_v2_batch_entry(
        index,
        (0..8)
            .map(|slot| sdk741_component_request(Sdk741Payload::Create, index, slot, None))
            .collect(),
        timestamp(u8::try_from(index).unwrap()),
    )
}

fn blank(index: u64) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Blank,
    }
}

fn append(entries: &[Entry<SessionRaftTypeConfig>]) -> Operation {
    Operation::Append(
        entries
            .iter()
            .map(|entry| encode_json(entry).unwrap().into())
            .collect(),
    )
}

fn files(path: &Path) -> BTreeMap<String, [u8; 32]> {
    use sha2::{Digest, Sha256};
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                Sha256::digest(std::fs::read(entry.path()).unwrap()).into(),
            )
        })
        .collect()
}

fn preserved_rejection(path: &Path, binding: Binding, limits: Limits) {
    let before = files(path);
    assert!(Wal::open(path, binding, limits, IoControl::default()).is_err());
    assert_eq!(
        files(path),
        before,
        "failed recovery preserves every byte and filename"
    );
}

fn preserved_rejection_containing(path: &Path, binding: Binding, limits: Limits, expected: &str) {
    let before = files(path);
    let error = Wal::open(path, binding, limits, IoControl::default())
        .err()
        .expect("the specific validation rejects recovery");
    assert!(
        error.to_string().contains(expected),
        "expected {expected:?}, got {error}"
    );
    assert_eq!(
        files(path),
        before,
        "validation failure preserves all evidence"
    );
}

fn reopen_repaired_prefix(
    fixture: &Fixture,
    limits: Limits,
    before: &BTreeMap<String, [u8; 32]>,
) -> Wal {
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert_eq!(
        files(&fixture.path()),
        *before,
        "repair retains the exact complete acknowledged file set and bytes"
    );
    reopened
}

fn fail_at(point: Point) -> IoControl {
    IoControl {
        hook: Arc::new(move |actual| {
            if actual == point {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        }),
        ..IoControl::default()
    }
}

fn basis_selector(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path.join("CURRENT")).unwrap();
    assert_eq!(&bytes[..8], b"OPCWBAS1");
    serde_json::from_slice(&bytes[8..bytes.len() - 32]).unwrap()
}

fn snapshot_metadata_candidate(conn: &rusqlite::Connection) -> CurrentSnapshot {
    let (last_log_id, last_membership) =
        snapshot_applied_membership_sync(conn, identity()).unwrap();
    (
        opc_consensus::engine::SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: format!("wal-test-{}", uuid::Uuid::new_v4()),
        },
        format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
        [0x61; 32],
        4096,
    )
}

fn open_snapshot_cache(
    fixture: &Fixture,
    source: &SqliteSessionBackend,
    conn: &rusqlite::Connection,
    control: IoControl,
) -> io::Result<Wal> {
    // Kernel fixtures deliberately use synthetic snapshot descriptors.
    // Actual builder/fs-verity/cleanup behavior is tested in storage.rs.
    super::super::wal::snapshot::Opening::new(
        &fixture.path(),
        fixture.wal.binding(),
        Limits::default(),
        control,
    )?
    .finish(conn, &source.caps, || Ok(()))
}

pub(super) struct IncomingSnapshot {
    directory: tempfile::TempDir,
    pub(super) candidate: CurrentSnapshot,
    pub(super) raw: PathBuf,
    pub(super) published: PathBuf,
}

impl IncomingSnapshot {
    pub(super) fn new(conn: &rusqlite::Connection) -> Self {
        Self::with_identity(conn, identity())
    }

    pub(super) fn with_identity(
        conn: &rusqlite::Connection,
        identity: SessionConsensusIdentity,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let raw = directory.path().join("incoming.sqlite");
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(conn, identity, &raw).unwrap();
        let candidate = (
            opc_consensus::engine::SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id: format!("wal-install-{}", uuid::Uuid::new_v4()),
            },
            format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
            [0; 32],
            0,
        );
        let published = directory.path().join(&candidate.1);
        let mut incoming = Self {
            directory,
            candidate,
            raw,
            published,
        };
        incoming.encode_envelope();
        incoming
    }

    fn encode_envelope(&mut self) {
        use sha2::{Digest, Sha256};
        let mut payload = std::fs::read(&self.raw).unwrap();
        let length = payload.len() as u64;
        self.candidate.2 = Sha256::digest(&payload).into();
        payload.extend_from_slice(b"OPCSNP01");
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(&self.candidate.2);
        self.candidate.3 = payload.len() as u64;
        std::fs::write(&self.published, payload).unwrap();
    }

    pub(super) fn source(&self) -> io::Result<super::super::wal::snapshot::InstallSource> {
        use crate::consensus::snapshot::{
            PinnedSqliteFile, SNAPSHOT_ENVELOPE_FOOTER_BYTES, SNAPSHOT_MAX_BYTES,
        };
        use crate::SnapshotIntegrityPolicy;
        let raw = PinnedSqliteFile::from_file_and_verify(
            std::fs::File::open(&self.raw)?,
            self.raw.clone(),
            SnapshotIntegrityPolicy::PortableVerified,
        )?;
        let mut published = PinnedSqliteFile::from_file_and_verify(
            std::fs::File::open(&self.published)?,
            self.published.clone(),
            SnapshotIntegrityPolicy::PortableVerified,
        )?;
        published.verify_snapshot_envelope_and_bind_immutable_generation(
            &self.published,
            b"OPCSNP01",
            SNAPSHOT_ENVELOPE_FOOTER_BYTES,
            SNAPSHOT_MAX_BYTES,
            self.candidate.2,
            self.candidate.3,
        )?;
        super::super::wal::snapshot::InstallSource::new(
            self.candidate.clone(),
            raw,
            published,
            self.published.clone(),
        )
    }
}

fn empty_install_fixture(control: IoControl) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let source = SqliteSessionBackend::open(directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    initialize_schema(&conn, identity(), &expected_members()).unwrap();
    let wal = Wal::create(
        &directory.path().join("wal"),
        &conn,
        identity(),
        [0xA1; 32],
        Limits::default(),
        control,
    )
    .unwrap();
    drop(conn);
    Fixture {
        wal,
        pause: None,
        directory,
    }
}

fn open_install_cache(
    fixture: &Fixture,
    backend: &SqliteSessionBackend,
    conn: &rusqlite::Connection,
    incoming: &IncomingSnapshot,
    control: IoControl,
) -> io::Result<Wal> {
    let opening = super::super::wal::snapshot::Opening::new(
        &fixture.path(),
        fixture.wal.binding(),
        Limits::default(),
        control,
    )?;
    let source = if let Some(candidate) = opening.install_candidate() {
        if candidate != incoming.candidate {
            return Err(invalid_data("test incoming source metadata differs"));
        }
        Some(incoming.source()?)
    } else {
        None
    };
    opening.finish_with_install_source(conn, &backend.caps, source.as_ref(), || {
        source.as_ref().map_or(Ok(()), |source| source.verify())
    })
}

fn install_source_at(index: u64) -> IncomingSnapshot {
    let producer = fixture();
    let source =
        SqliteSessionBackend::open(producer.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    if index > 0 {
        let entries: Vec<_> = (1..=index).map(batch).collect();
        producer
            .wal
            .submit(append(&entries))
            .unwrap()
            .wait()
            .unwrap();
        producer
            .wal
            .submit(Operation::Committed(Some(log_id(index))))
            .unwrap()
            .wait()
            .unwrap();
        producer
            .wal
            .apply_committed(&conn, &source.caps, entries, ApplyControl::Normal)
            .unwrap();
    }
    let incoming = IncomingSnapshot::new(&conn);
    producer.wal.shutdown().unwrap();
    incoming
}

fn receipt_count(conn: &rusqlite::Connection) -> u64 {
    conn.query_row(
        "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn installed_origin(selector: &serde_json::Value) -> &serde_json::Value {
    let sequence = selector["position"]["sequence"]
        .as_u64()
        .unwrap()
        .to_string();
    &selector["cuts"][&sequence]["installed"]
}

#[test]
fn snapshot_install_advances_beyond_local_wal_and_preserves_uncommitted_suffix() {
    let incoming = install_source_at(2);
    for empty in [true, false] {
        let target = if empty {
            empty_install_fixture(IoControl::default())
        } else {
            fixture()
        };
        let backend =
            SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
        let conn = backend.conn.blocking_lock();
        if empty {
            target
                .wal
                .restore_application(&conn, &backend.caps)
                .unwrap();
        } else {
            target
                .wal
                .submit(append(&[batch(1), batch(2), batch(3)]))
                .unwrap()
                .wait()
                .unwrap();
            target
                .wal
                .submit(Operation::Committed(Some(log_id(1))))
                .unwrap()
                .wait()
                .unwrap();
            target
                .wal
                .apply_committed(&conn, &backend.caps, vec![batch(1)], ApplyControl::Normal)
                .unwrap();
        }
        let root = target.wal.binding();
        target
            .wal
            .install_snapshot(&conn, incoming.source().unwrap())
            .unwrap();
        let selected = basis_selector(&target.path());
        assert_eq!(selected["position"]["sequence"], if empty { 0 } else { 2 });
        assert_eq!(selected["cuts"].as_object().unwrap().len(), 1);
        assert_eq!(installed_origin(&selected)["epoch"], selected["epoch"]);
        assert_eq!(target.wal.binding().identity, root.identity);
        assert_eq!(target.wal.binding().generation, root.generation);
        assert_eq!(target.wal.binding().basis, root.basis);
        assert_eq!(target.wal.committed().unwrap(), Some(log_id(2)));
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(2))
        );
        assert_eq!(
            read_purged_sync(&conn, identity()).unwrap(),
            Some(log_id(2))
        );
        assert_eq!(receipt_count(&conn), 16);
        assert!(snapshot_raw_logs(&conn).is_empty());
        let retained = if empty { Vec::new() } else { vec![batch(3)] };
        assert!(target.wal.read(0, 4).unwrap() == retained);
        assert_eq!(
            snapshot_raw_logs(&selected_snapshot_basis(&target.path())).len(),
            usize::from(!empty)
        );
        target.wal.validate_application_cache(&conn).unwrap();
        target.wal.shutdown().unwrap();
        let reopened =
            open_install_cache(&target, &backend, &conn, &incoming, IoControl::default()).unwrap();
        if empty {
            reopened
                .submit(append(&[batch(3)]))
                .unwrap()
                .wait()
                .unwrap();
        }
        reopened
            .submit(Operation::Committed(Some(log_id(3))))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .apply_committed(&conn, &backend.caps, vec![batch(3)], ApplyControl::Normal)
            .unwrap();
        assert_eq!(receipt_count(&conn), 24);
        reopened.checkpoint().unwrap();
        assert!(basis_selector(&target.path())["cuts"]
            .as_object()
            .unwrap()
            .values()
            .all(|cut| cut.get("installed").is_none()));
        reopened.shutdown().unwrap();
        let final_open =
            open_install_cache(&target, &backend, &conn, &incoming, IoControl::default()).unwrap();
        final_open.validate_application_cache(&conn).unwrap();
        assert_eq!(receipt_count(&conn), 24);
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_INSTALL_CASE {}",
            serde_json::json!({"case":"advance_beyond_local_wal", "initial_sequence_zero":empty, "incoming_applied":2, "explicit_installed_cut":true, "retained_uncommitted_suffix":!empty, "successor_receipts":24, "checkpoint_reopen":true})
        );
    }
}

#[test]
fn snapshot_install_same_sequence_retains_origin_through_checkpoints_and_new_snapshot() {
    let incoming = install_source_at(1);
    let target = fixture();
    let backend =
        SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
    let conn = backend.conn.blocking_lock();
    target
        .wal
        .restore_application(&conn, &backend.caps)
        .unwrap();
    target
        .wal
        .install_snapshot(&conn, incoming.source().unwrap())
        .unwrap();
    let first = ops::read_restore_scan_state_sync(&conn).unwrap();
    target
        .wal
        .install_snapshot(&conn, incoming.source().unwrap())
        .unwrap();
    let second = ops::read_restore_scan_state_sync(&conn).unwrap();
    assert_ne!(first.0, second.0);
    assert!(*first.2 != *second.2);
    let installed = basis_selector(&target.path());
    assert_eq!(installed["position"]["sequence"], 0);
    assert_eq!(receipt_count(&conn), 8);
    let origin = installed_origin(&installed).clone();
    let marker = snapshot_cache_marker(&conn);
    target.wal.checkpoint().unwrap();
    assert_eq!(installed_origin(&basis_selector(&target.path())), &origin);
    let later = snapshot_metadata_candidate(&conn);
    assert_ne!(later, incoming.candidate);
    target
        .wal
        .publish_compacting_snapshot(&conn, later.clone())
        .unwrap();
    assert_eq!(installed_origin(&basis_selector(&target.path())), &origin);
    assert_eq!(snapshot_cache_marker(&conn), marker);
    assert_eq!(
        read_current_snapshot_sync(&conn, identity()).unwrap(),
        Some(later)
    );
    target.wal.shutdown().unwrap();
    let reopened = open_snapshot_cache(&target, &backend, &conn, IoControl::default()).unwrap();
    reopened
        .submit(append(&[batch(2)]))
        .unwrap()
        .wait()
        .unwrap();
    reopened.checkpoint().unwrap();
    let selected = basis_selector(&target.path());
    assert_eq!(selected["cuts"]["0"]["installed"], origin);
    assert!(
        installed_origin(&selected).is_null(),
        "ordinary successor ACK is its own source"
    );
    reopened
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(&conn, &backend.caps, vec![batch(2)], ApplyControl::Normal)
        .unwrap();
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let final_open = open_snapshot_cache(&target, &backend, &conn, IoControl::default()).unwrap();
    final_open.validate_application_cache(&conn).unwrap();
    assert_eq!(receipt_count(&conn), 16);
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_INSTALL_CASE {}",
        serde_json::json!({"case":"same_sequence_same_applied", "repeated_install":true, "fresh_local_incarnation":true, "origin_survives_checkpoint_and_compacting_snapshot":true, "ordinary_ack_retains_old_marker_origin":true, "successor_apply_and_reopen":true})
    );
}

#[test]
fn snapshot_install_empty_source_at_zero_has_explicit_origin_without_application_marker() {
    let producer = empty_install_fixture(IoControl::default());
    let backend =
        SqliteSessionBackend::open(producer.directory.path().join("source.sqlite")).unwrap();
    let source_conn = backend.conn.blocking_lock();
    let incoming = IncomingSnapshot::new(&source_conn);
    assert!(incoming.candidate.0.last_log_id.is_none());
    producer.wal.shutdown().unwrap();
    let target = empty_install_fixture(IoControl::default());
    let target_backend =
        SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
    let conn = target_backend.conn.blocking_lock();
    target
        .wal
        .restore_application(&conn, &target_backend.caps)
        .unwrap();
    for _ in 0..2 {
        target
            .wal
            .install_snapshot(&conn, incoming.source().unwrap())
            .unwrap();
        let selected = basis_selector(&target.path());
        assert_eq!(selected["position"]["sequence"], 0);
        assert!(selected["applied"].is_null());
        assert!(selected["marker"].is_null());
        assert_eq!(installed_origin(&selected)["epoch"], selected["epoch"]);
    }
    target.wal.shutdown().unwrap();
    let reopened = open_install_cache(
        &target,
        &target_backend,
        &conn,
        &incoming,
        IoControl::default(),
    )
    .unwrap();
    assert!(reopened.committed().unwrap().is_none());
    reopened
        .submit(append(&[membership_entry()]))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .submit(Operation::Committed(Some(log_id(0))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(
            &conn,
            &target_backend.caps,
            vec![membership_entry()],
            ApplyControl::Normal,
        )
        .unwrap();
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let final_open = open_install_cache(
        &target,
        &target_backend,
        &conn,
        &incoming,
        IoControl::default(),
    )
    .unwrap();
    final_open.validate_application_cache(&conn).unwrap();
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_INSTALL_CASE {}",
        serde_json::json!({"case":"empty_source_at_zero", "repeated_install":true, "marker_absent":true, "original_first_membership_apply":true, "checkpoint_reopen":true})
    );
}

fn restore_cursor(conn: &rusqlite::Connection) -> RestoreScanCursor {
    let (epoch, revision, cursor_key) = ops::read_restore_scan_state_sync(conn).unwrap();
    RestoreScanCursor::durable(
        &cursor_key,
        epoch,
        revision,
        timestamp(0),
        &RestoreScanScope::all(),
        &key(),
        1,
    )
    .unwrap()
}

fn reject_restore_cursor(conn: &rusqlite::Connection, cursor: RestoreScanCursor) {
    let error = ops::scan_restore_records_sync(
        conn,
        RestoreScanRequest {
            scope: RestoreScanScope::all(),
            cursor: Some(cursor),
            limit: 1,
        },
        timestamp(1),
        Arc::new(AtomicBool::new(false)),
        std::time::Instant::now() + Duration::from_secs(5),
        RestoreScanValidationProfile::Consensus,
    )
    .unwrap_err();
    assert_eq!(error, StoreError::RestoreScanCursorStale);
}

#[test]
fn snapshot_install_preserves_original_revision_and_invalidates_source_and_target_cursors() {
    let incoming = install_source_at(0);
    let raw = rusqlite::Connection::open_with_flags(
        &incoming.raw,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let source_state = ops::read_restore_scan_state_sync(&raw).unwrap();
    let mut first_target = None;
    let mut first_cursor = None;
    for target_number in 0..2 {
        let target = fixture();
        let backend =
            SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
        let conn = backend.conn.blocking_lock();
        let old_cursor = restore_cursor(&conn);
        target
            .wal
            .restore_application(&conn, &backend.caps)
            .unwrap();
        target
            .wal
            .install_snapshot(&conn, incoming.source().unwrap())
            .unwrap();
        let installed = ops::read_restore_scan_state_sync(&conn).unwrap();
        assert_eq!(
            installed.1,
            source_state.1 + 1,
            "original copy-then-increment behavior"
        );
        assert_ne!(installed.0, source_state.0);
        assert!(*installed.2 != *source_state.2);
        reject_restore_cursor(&conn, restore_cursor(&raw));
        reject_restore_cursor(&conn, old_cursor);
        if let Some((epoch, key)) = first_target.take() {
            assert_ne!(installed.0, epoch);
            assert!(*installed.2 != key);
            reject_restore_cursor(&conn, first_cursor.take().unwrap());
        } else {
            first_target = Some((installed.0, *installed.2));
            first_cursor = Some(restore_cursor(&conn));
        }
        let page = ops::scan_restore_records_sync(
            &conn,
            RestoreScanRequest {
                scope: RestoreScanScope::all(),
                cursor: None,
                limit: 1,
            },
            timestamp(1),
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
            RestoreScanValidationProfile::Consensus,
        )
        .unwrap();
        assert!(page.complete && page.records.is_empty());
        target.wal.shutdown().unwrap();
        let reopened =
            open_install_cache(&target, &backend, &conn, &incoming, IoControl::default()).unwrap();
        let durable = ops::read_restore_scan_state_sync(&conn).unwrap();
        assert_eq!(durable.0, installed.0);
        assert_eq!(durable.1, installed.1);
        assert!(*durable.2 == *installed.2);
        reopened.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_INSTALL_CASE {}",
            serde_json::json!({"case":"restore_incarnation", "target":target_number, "incoming_revision_plus_one":true, "source_and_prior_target_cursors_invalidated":true, "cross_target_cursor_rejected":target_number == 1, "first_page_restarts":true, "reopen_does_not_rotate_again":true})
        );
    }
}

fn prepare_install_target(
    target: &Fixture,
    backend: &SqliteSessionBackend,
    conn: &rusqlite::Connection,
) {
    target
        .wal
        .submit(append(&[batch(1), batch(2), batch(3)]))
        .unwrap()
        .wait()
        .unwrap();
    target
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    target
        .wal
        .apply_committed(conn, &backend.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
}

#[test]
fn snapshot_install_fault_boundaries_recover_exact_old_or_new_state_and_continue() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let incoming = install_source_at(2);
    for (point, occurrence) in [
        (Point::AfterBasisDirectorySync, 2),
        (Point::BeforeSnapshotProofSync, 1),
        (Point::AfterSnapshotProofRename, 1),
        (Point::AfterSnapshotProofDirectorySync, 1),
        (Point::BeforeSnapshotCacheWrite, 1),
        (Point::BeforeSnapshotCacheCommit, 1),
        (Point::AfterSnapshotCacheCommit, 1),
        (Point::AfterBasisSelectorRename, 2),
        (Point::BeforeBasisPublicationSync, 2),
        (Point::AfterBasisPublicationSync, 2),
        (Point::AfterSnapshotProofUnlink, 1),
        (Point::AfterSnapshotProofRetireSync, 1),
        (Point::AfterBasisReclaimFile, 1),
    ] {
        let cache_committed = Arc::new(AtomicBool::new(false));
        let fault_seen = Arc::new(AtomicBool::new(false));
        let committed_hook = Arc::clone(&cache_committed);
        let fault_hook = Arc::clone(&fault_seen);
        let hits = AtomicUsize::new(0);
        let control = IoControl {
            hook: Arc::new(move |actual| {
                if actual == Point::AfterSnapshotCacheCommit {
                    committed_hook.store(true, Ordering::SeqCst);
                }
                let armed =
                    point != Point::AfterBasisReclaimFile || committed_hook.load(Ordering::SeqCst);
                if actual == point && armed && hits.fetch_add(1, Ordering::SeqCst) + 1 == occurrence
                {
                    fault_hook.store(true, Ordering::SeqCst);
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let target = Fixture::new(Limits::default(), control, None, true);
        let backend =
            SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
        let conn = backend.conn.blocking_lock();
        prepare_install_target(&target, &backend, &conn);
        let old_marker = snapshot_cache_marker(&conn);
        let old_restore = ops::read_restore_scan_state_sync(&conn).unwrap();
        let source_files = files(incoming.directory.path());
        assert!(
            target
                .wal
                .install_snapshot(&conn, incoming.source().unwrap())
                .is_err(),
            "{point:?}"
        );
        assert!(
            fault_seen.load(Ordering::SeqCst),
            "declared install boundary {point:?}/{occurrence}"
        );
        assert!(target.wal.validate_application_cache(&conn).is_err());
        assert!(target.wal.read(0, 4).is_err());
        assert!(target.wal.submit(Operation::Barrier).is_err());
        assert!(target.wal.shutdown().is_err());
        let committed = cache_committed.load(Ordering::SeqCst);
        assert_eq!(
            read_current_snapshot_sync(&conn, identity()).unwrap(),
            committed.then(|| incoming.candidate.clone())
        );
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(if committed { 2 } else { 1 }))
        );
        assert_eq!(receipt_count(&conn), if committed { 16 } else { 8 });
        assert_eq!(
            snapshot_raw_logs(&conn).len(),
            if committed { 0 } else { 2 }
        );
        if !committed {
            assert_eq!(snapshot_cache_marker(&conn), old_marker);
        }
        if point == Point::AfterBasisReclaimFile {
            assert!(committed);
            assert_eq!(basis_selector(&target.path())["epoch"], 2);
            assert!(!target.path().join("SNAPSHOT.pending").exists());
        }
        let before_restore = ops::read_restore_scan_state_sync(&conn).unwrap();
        let reopened =
            open_install_cache(&target, &backend, &conn, &incoming, IoControl::default())
                .unwrap_or_else(|error| panic!("{point:?}: {error}"));
        let after_restore = ops::read_restore_scan_state_sync(&conn).unwrap();
        assert_eq!(before_restore.0, after_restore.0);
        assert_eq!(before_restore.1, after_restore.1);
        assert!(*before_restore.2 == *after_restore.2);
        if !committed {
            assert_eq!(after_restore.0, old_restore.0);
            assert_eq!(snapshot_cache_marker(&conn), old_marker);
            reopened
                .install_snapshot(&conn, incoming.source().unwrap())
                .unwrap();
        }
        assert!(reopened.read(0, 4).unwrap() == vec![batch(3)]);
        reopened
            .submit(Operation::Committed(Some(log_id(3))))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .apply_committed(&conn, &backend.caps, vec![batch(3)], ApplyControl::Normal)
            .unwrap();
        assert_eq!(receipt_count(&conn), 24);
        reopened.checkpoint().unwrap();
        reopened.shutdown().unwrap();
        let final_open =
            open_install_cache(&target, &backend, &conn, &incoming, IoControl::default()).unwrap();
        final_open.validate_application_cache(&conn).unwrap();
        final_open.shutdown().unwrap();
        assert_eq!(files(incoming.directory.path()), source_files);
        eprintln!(
            "SEQUENTIAL_WAL_INSTALL_CASE {}",
            serde_json::json!({"case":"atomic_fault", "point":format!("{point:?}"), "occurrence":occurrence, "armed_after_cache_commit":point == Point::AfterBasisReclaimFile, "cache_committed":committed, "exact_chosen_marker":true, "restore_incarnation_preserved":true, "source_files_preserved":true, "successor_receipts":24, "checkpoint_reopen":true})
        );
    }
}

fn rebind_install_new_image(
    body: &mut String,
    proof: &serde_json::Value,
    path: &Path,
    application: bool,
) {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(std::fs::read(path).unwrap()).into();
    let (old, new) = body.split_once("\"new\":").unwrap();
    let new = new
        .replacen(
            &format!("\"basis\":{}", proof["new"]["basis"]),
            &format!("\"basis\":{}", serde_json::to_string(&digest).unwrap()),
            1,
        )
        .replacen(
            &format!("\"basis_bytes\":{}", proof["new"]["basis_bytes"]),
            &format!("\"basis_bytes\":{}", std::fs::metadata(path).unwrap().len()),
            1,
        );
    *body = format!("{old}\"new\":{new}");
    if application {
        let conn =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let digest = super::super::wal::application::application_digest(&conn).unwrap();
        *body = body.replacen(
            &format!("\"new_application\":{}", proof["new_application"]),
            &format!(
                "\"new_application\":{}",
                serde_json::to_string(&digest).unwrap()
            ),
            1,
        );
    }
}

fn write_snapshot_pending_body(path: &Path, body: &str) {
    use sha2::{Digest, Sha256};
    let mut bytes = b"OPCWSNP1".to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    std::fs::write(path.join("SNAPSHOT.pending"), bytes).unwrap();
}

#[test]
fn snapshot_install_pending_corruption_rejects_coherent_hashes_without_repair() {
    for damage in [
        "old_marker_new_cache",
        "new_marker_old_cache",
        "new_selector_old_cache",
        "new_metadata_old_raw",
        "missing_transform",
        "compact_transform",
        "missing_origin",
        "zero_origin_epoch",
        "future_origin_epoch",
        "wrong_origin_metadata",
        "changed_retained_row",
        "missing_retained_row",
        "changed_restore_revision",
        "zero_restore_epoch",
        "zero_restore_key",
        "missing_source",
        "missing_published",
        "changed_published",
        "changed_raw",
        "wrong_source",
    ] {
        let incoming = install_source_at(2);
        let target = Fixture::new(
            Limits::default(),
            fail_at(Point::AfterSnapshotCacheCommit),
            None,
            true,
        );
        let backend =
            SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
        let mut conn = backend.conn.blocking_lock();
        prepare_install_target(&target, &backend, &conn);
        let old_marker = snapshot_cache_marker(&conn);
        let mut old_cache = rusqlite::Connection::open_in_memory().unwrap();
        rusqlite::backup::Backup::new(&conn, &mut old_cache)
            .unwrap()
            .run_to_completion(128, Duration::ZERO, None)
            .unwrap();
        assert!(target
            .wal
            .install_snapshot(&conn, incoming.source().unwrap())
            .is_err());
        assert!(target.wal.shutdown().is_err());
        assert_eq!(receipt_count(&conn), 16);
        let new_marker = snapshot_cache_marker(&conn);
        let path = target.path();
        let proof = snapshot_pending_value(&path);
        assert_eq!(proof["transform"], "Install");
        let sequence = proof["new"]["position"]["sequence"]
            .as_u64()
            .unwrap()
            .to_string();
        let old_path = path.join(format!(
            "basis-{:020}.sqlite",
            proof["old"]["epoch"].as_u64().unwrap()
        ));
        let new_path = path.join(format!(
            "basis-{:020}.sqlite",
            proof["new"]["epoch"].as_u64().unwrap()
        ));
        let bytes = std::fs::read(path.join("SNAPSHOT.pending")).unwrap();
        let mut body = std::str::from_utf8(&bytes[8..bytes.len() - 32])
            .unwrap()
            .to_owned();
        let mut wrong_source = None;
        match damage {
            "old_marker_new_cache" => {
                conn.execute(
                    "UPDATE consensus_wal_application SET marker_json = ?1",
                    [old_marker],
                )
                .unwrap();
            }
            "new_marker_old_cache" | "new_selector_old_cache" => {
                rusqlite::backup::Backup::new(&old_cache, &mut conn)
                    .unwrap()
                    .run_to_completion(128, Duration::ZERO, None)
                    .unwrap();
                if damage == "new_marker_old_cache" {
                    conn.execute(
                        "UPDATE consensus_wal_application SET marker_json = ?1",
                        [new_marker],
                    )
                    .unwrap();
                } else {
                    select_snapshot_proof_anchor(&path, "new");
                }
            }
            "new_metadata_old_raw" => {
                conn.execute(
                    "ATTACH DATABASE ?1 AS install_old",
                    params![old_path.to_str().unwrap()],
                )
                .unwrap();
                assert_eq!(conn.execute("INSERT INTO main.consensus_log SELECT * FROM install_old.consensus_log WHERE log_index <= 1", []).unwrap(), 2);
                conn.execute_batch("DETACH DATABASE install_old").unwrap();
            }
            "missing_transform" => body = body.replacen(",\"transform\":\"Install\"", "", 1),
            "compact_transform" => {
                body = body.replacen("\"transform\":\"Install\"", "\"transform\":\"Compact\"", 1)
            }
            "missing_origin"
            | "zero_origin_epoch"
            | "future_origin_epoch"
            | "wrong_origin_metadata" => {
                let origin = &proof["new"]["cuts"][&sequence]["installed"];
                if damage == "missing_origin" {
                    let needle = format!(",\"installed\":{origin}");
                    assert!(body.contains(&needle));
                    body = body.replacen(&needle, "", 1);
                } else {
                    let mut changed = origin.clone();
                    match damage {
                        "zero_origin_epoch" => changed["epoch"] = 0.into(),
                        "future_origin_epoch" => {
                            changed["epoch"] = (proof["new"]["epoch"].as_u64().unwrap() + 1).into()
                        }
                        "wrong_origin_metadata" => {
                            changed["snapshot_metadata_sha256"][0] =
                                (changed["snapshot_metadata_sha256"][0].as_u64().unwrap() ^ 1)
                                    .into()
                        }
                        _ => unreachable!(),
                    }
                    let needle = format!("\"installed\":{origin}");
                    assert!(body.contains(&needle));
                    body = body.replacen(&needle, &format!("\"installed\":{changed}"), 1);
                }
            }
            "changed_retained_row" | "missing_retained_row" => {
                let changed = rusqlite::Connection::open(&new_path).unwrap();
                if damage == "changed_retained_row" {
                    assert_eq!(
                        changed
                            .execute(
                                "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 3",
                                params![encode_json(&blank(3)).unwrap()]
                            )
                            .unwrap(),
                        1
                    );
                } else {
                    assert_eq!(
                        changed
                            .execute("DELETE FROM consensus_log WHERE log_index = 3", [])
                            .unwrap(),
                        1
                    );
                }
                drop(changed);
                rebind_install_new_image(&mut body, &proof, &new_path, false);
            }
            "changed_restore_revision" | "zero_restore_epoch" | "zero_restore_key" => {
                let changed = rusqlite::Connection::open(&new_path).unwrap();
                let sql = match damage {
                    "changed_restore_revision" => {
                        "UPDATE restore_scan_state SET revision = revision + 7"
                    }
                    "zero_restore_epoch" => "UPDATE restore_scan_state SET epoch = zeroblob(16)",
                    "zero_restore_key" => "UPDATE restore_scan_state SET cursor_key = zeroblob(32)",
                    _ => unreachable!(),
                };
                assert_eq!(changed.execute(sql, []).unwrap(), 1);
                assert_eq!(conn.execute(sql, []).unwrap(), 1);
                drop(changed);
                // Both cache and NEW are changed coherently, and both basis
                // and application hashes are rebound. The nonce validator or
                // exact original revision replay must reject this state.
                rebind_install_new_image(&mut body, &proof, &new_path, true);
            }
            "missing_source" => {}
            "missing_published" => std::fs::remove_file(&incoming.published).unwrap(),
            "changed_published" | "changed_raw" => {
                let file = if damage == "changed_raw" {
                    &incoming.raw
                } else {
                    &incoming.published
                };
                let mut changed = std::fs::read(file).unwrap();
                changed[100] ^= 1;
                std::fs::write(file, changed).unwrap();
            }
            "wrong_source" => wrong_source = Some(install_source_at(3)),
            _ => unreachable!(),
        }
        write_snapshot_pending_body(&path, &body);
        let wal_before = files(&path);
        let source_before = files(incoming.directory.path());
        let cache_before = super::super::wal::application::full_image_digest(&conn).unwrap();
        let error = (|| {
            let opening = super::super::wal::snapshot::Opening::new(
                &path,
                target.wal.binding(),
                Limits::default(),
                IoControl::default(),
            )?;
            let source = if damage == "missing_source" {
                None
            } else {
                Some(wrong_source.as_ref().unwrap_or(&incoming).source()?)
            };
            opening.finish_with_install_source(&conn, &backend.caps, source.as_ref(), || {
                source.as_ref().map_or(Ok(()), |source| source.verify())
            })
        })()
        .err()
        .unwrap_or_else(|| panic!("{damage} must reject"));
        if matches!(
            damage,
            "changed_retained_row" | "missing_retained_row" | "changed_restore_revision"
        ) {
            assert!(
                error.to_string().contains("declared original transaction"),
                "{damage}: {error}"
            );
        }
        if matches!(damage, "zero_restore_epoch" | "zero_restore_key") {
            assert!(
                error
                    .to_string()
                    .contains("installed restore metadata is invalid"),
                "{damage}: {error}"
            );
        }
        assert_eq!(files(&path), wal_before, "{damage}");
        assert_eq!(files(incoming.directory.path()), source_before, "{damage}");
        assert_eq!(
            super::super::wal::application::full_image_digest(&conn).unwrap(),
            cache_before,
            "{damage}"
        );
        eprintln!(
            "SEQUENTIAL_WAL_INSTALL_CASE {}",
            serde_json::json!({"case":"pending_corruption", "damage":damage, "coherent_new_basis_and_application_hashes":matches!(damage, "changed_restore_revision" | "zero_restore_epoch" | "zero_restore_key"), "all_authority_source_and_cache_bytes_preserved":true})
        );
    }
}

#[test]
fn snapshot_install_keeps_original_floor_raw_cut_receipt_and_clock_validation() {
    for damage in [
        "lower_index",
        "lower_term_higher_index",
        "same_index_different_full_id",
        "raw_metadata_cut_mismatch",
        "missing_receipts",
        "logical_clock_regression",
    ] {
        let mut incoming = install_source_at(2);
        let target = fixture();
        let backend =
            SqliteSessionBackend::open(target.directory.path().join("source.sqlite")).unwrap();
        let conn = backend.conn.blocking_lock();
        prepare_install_target(&target, &backend, &conn);
        match damage {
            "lower_index" => incoming.candidate.0.last_log_id = Some(log_id(0)),
            "lower_term_higher_index" => {
                incoming.candidate.0.last_log_id =
                    Some(LogId::new(CommittedLeaderId::new(0, node_id()), 9))
            }
            "same_index_different_full_id" => {
                incoming.candidate.0.last_log_id =
                    Some(LogId::new(CommittedLeaderId::new(2, node_id()), 1))
            }
            "raw_metadata_cut_mismatch" => incoming.candidate.0.last_log_id = Some(log_id(3)),
            "missing_receipts" | "logical_clock_regression" => {
                let changed = rusqlite::Connection::open(&incoming.raw).unwrap();
                let count = if damage == "missing_receipts" {
                    changed
                        .execute("DELETE FROM consensus_fenced_transition_v2_receipts", [])
                        .unwrap()
                } else {
                    changed
                        .execute(
                            "UPDATE consensus_machine SET logical_time = '2026-07-12T00:00:00Z'",
                            [],
                        )
                        .unwrap()
                };
                assert!(count > 0);
                drop(changed);
                incoming.encode_envelope();
            }
            _ => unreachable!(),
        }
        let input = incoming.source().unwrap();
        let cache_before = super::super::wal::application::full_image_digest(&conn).unwrap();
        let source_before = files(incoming.directory.path());
        assert!(
            target.wal.install_snapshot(&conn, input).is_err(),
            "{damage}"
        );
        assert!(target.wal.shutdown().is_err());
        assert!(!target.path().join("SNAPSHOT.pending").exists());
        assert_eq!(
            super::super::wal::application::full_image_digest(&conn).unwrap(),
            cache_before,
            "{damage}"
        );
        assert_eq!(files(incoming.directory.path()), source_before);
        let reopened = open_snapshot_cache(&target, &backend, &conn, IoControl::default()).unwrap();
        assert_eq!(reopened.committed().unwrap(), Some(log_id(1)));
        assert!(
            reopened.read(0, 4).unwrap() == vec![membership_entry(), batch(1), batch(2), batch(3)]
        );
        reopened.validate_application_cache(&conn).unwrap();
        reopened.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_INSTALL_CASE {}",
            serde_json::json!({"case":"original_validator_rejection", "damage":damage, "coherent_immutable_input":true, "cache_and_source_unchanged":true, "no_install_proof_published":true, "old_acknowledged_history_reopened":true})
        );
    }
}

#[test]
fn snapshot_metadata_handoff_keeps_unapplied_history_and_exact_cache_lineage() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    fixture
        .wal
        .submit(append(&[batch(1), batch(2), batch(3)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    let first = snapshot_metadata_candidate(&conn);
    fixture.wal.publish_snapshot(&conn, first.clone()).unwrap();
    assert_eq!(
        read_current_snapshot_sync(&conn, identity()).unwrap(),
        Some(first)
    );
    assert_eq!(basis_selector(&fixture.path())["epoch"], 2);
    assert!(!fixture.path().join("SNAPSHOT.pending").exists());
    assert!(fixture.wal.read(1, 4).unwrap() == vec![batch(1), batch(2), batch(3)]);
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .unwrap();
    let second = snapshot_metadata_candidate(&conn);
    fixture.wal.publish_snapshot(&conn, second.clone()).unwrap();
    assert_eq!(basis_selector(&fixture.path())["epoch"], 4);
    fixture
        .wal
        .submit(Operation::Purge(log_id(1)))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
    assert_eq!(
        read_current_snapshot_sync(&conn, identity()).unwrap(),
        Some(second)
    );
    assert!(reopened.read(0, 4).unwrap() == vec![batch(2), batch(3)]);
    reopened
        .submit(Operation::Committed(Some(log_id(3))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(&conn, &source.caps, vec![batch(3)], ApplyControl::Normal)
        .unwrap();
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 3);
    assert_eq!(
        conn.query_row::<u64, _, _>(
            "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
            [],
            |row| row.get(0)
        )
        .unwrap(),
        24
    );
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let final_open = open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
    final_open.validate_application_cache(&conn).unwrap();
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_SNAPSHOT_CASE {}",
        serde_json::json!({"case":"metadata_successors", "metadata_only_kernel":true, "publications":2, "unapplied_logs_retained":true, "later_application_receipts":24})
    );
}

fn snapshot_raw_logs(conn: &rusqlite::Connection) -> Vec<Vec<u8>> {
    conn.prepare("SELECT entry_json FROM consensus_log ORDER BY log_index")
        .unwrap()
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn snapshot_cache_marker(conn: &rusqlite::Connection) -> Vec<u8> {
    conn.query_row(
        "SELECT marker_json FROM consensus_wal_application",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn selected_snapshot_basis(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path.join(format!(
            "basis-{:020}.sqlite",
            basis_selector(path)["epoch"].as_u64().unwrap()
        )),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

#[test]
fn snapshot_compaction_preserves_unapplied_suffix_and_exact_successor_cache() {
    for damage in [
        "intact",
        "changed_retained_applied",
        "missing_retained_applied",
    ] {
        let fixture = fixture();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2), batch(3)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        let marker = snapshot_cache_marker(&conn);
        assert_eq!(snapshot_raw_logs(&conn).len(), 2);
        let candidate = snapshot_metadata_candidate(&conn);
        fixture
            .wal
            .publish_compacting_snapshot(&conn, candidate.clone())
            .unwrap();
        assert!(snapshot_raw_logs(&conn).is_empty());
        assert_eq!(snapshot_cache_marker(&conn), marker);
        assert_eq!(
            read_current_snapshot_sync(&conn, identity()).unwrap(),
            Some(candidate.clone())
        );
        assert_eq!(
            read_purged_sync(&conn, identity()).unwrap(),
            Some(log_id(1))
        );
        let basis = selected_snapshot_basis(&fixture.path());
        assert_eq!(
            snapshot_raw_logs(&basis),
            vec![
                encode_json(&batch(2)).unwrap(),
                encode_json(&batch(3)).unwrap()
            ]
        );
        assert_eq!(
            read_applied_sync(&basis, identity()).unwrap(),
            Some(log_id(1))
        );
        assert_eq!(
            read_committed_sync(&basis, identity()).unwrap(),
            Some(log_id(2))
        );
        assert_eq!(
            conn.query_row::<u64, _, _>(
                "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            8
        );
        drop(basis);
        assert!(fixture.wal.read(0, 4).unwrap() == vec![batch(2), batch(3)]);
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
            .unwrap();
        assert_eq!(
            snapshot_raw_logs(&conn),
            vec![encode_json(&batch(2)).unwrap()]
        );
        fixture.wal.checkpoint().unwrap();
        fixture.wal.shutdown().unwrap();
        match damage {
            "changed_retained_applied" => {
                assert_eq!(
                    conn.execute(
                        "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 2",
                        params![encode_json(&blank(2)).unwrap()]
                    )
                    .unwrap(),
                    1
                );
            }
            "missing_retained_applied" => {
                assert_eq!(
                    conn.execute("DELETE FROM consensus_log WHERE log_index = 2", [])
                        .unwrap(),
                    1
                );
            }
            _ => {}
        }
        let files_before = files(&fixture.path());
        let cache_before = super::super::wal::application::full_image_digest(&conn).unwrap();
        let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default());
        if damage == "intact" {
            let reopened = reopened.unwrap();
            reopened.validate_application_cache(&conn).unwrap();
            reopened
                .submit(Operation::Committed(Some(log_id(3))))
                .unwrap()
                .wait()
                .unwrap();
            reopened
                .apply_committed(&conn, &source.caps, vec![batch(3)], ApplyControl::Normal)
                .unwrap();
            assert_eq!(
                snapshot_raw_logs(&conn),
                vec![
                    encode_json(&batch(2)).unwrap(),
                    encode_json(&batch(3)).unwrap()
                ]
            );
            assert_eq!(
                conn.query_row::<u64, _, _>(
                    "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                24
            );
            reopened.checkpoint().unwrap();
            reopened.shutdown().unwrap();
            let final_open =
                open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
            final_open.validate_application_cache(&conn).unwrap();
            final_open.shutdown().unwrap();
        } else {
            assert!(reopened.is_err(), "{damage}");
            assert_eq!(files(&fixture.path()), files_before);
            assert_eq!(
                super::super::wal::application::full_image_digest(&conn).unwrap(),
                cache_before
            );
        }
        eprintln!(
            "SEQUENTIAL_WAL_COMPACTION_CASE {}",
            serde_json::json!({"case":"exact_successor_cache", "damage":damage, "synthetic_snapshot_descriptor":true, "compacted_rows":2, "unapplied_entries_retained":2, "committed_unapplied_index":2, "uncommitted_index":3, "marker_unchanged":true, "exact_reopen_or_preserved_rejection":true})
        );
    }
}

#[test]
fn snapshot_compaction_of_older_capture_keeps_stronger_logical_floor_and_later_rows() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    fixture
        .wal
        .submit(append(&[batch(1), batch(2), batch(3)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    let candidate = snapshot_metadata_candidate(&conn);
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .unwrap();
    fixture.wal.checkpoint().unwrap();
    fixture
        .wal
        .submit(Operation::Purge(log_id(2)))
        .unwrap()
        .wait()
        .unwrap();
    let marker = snapshot_cache_marker(&conn);
    fixture
        .wal
        .publish_compacting_snapshot(&conn, candidate.clone())
        .unwrap();
    assert_eq!(
        snapshot_raw_logs(&conn),
        vec![encode_json(&batch(2)).unwrap()]
    );
    assert_eq!(snapshot_cache_marker(&conn), marker);
    assert_eq!(
        read_purged_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
    let basis = selected_snapshot_basis(&fixture.path());
    assert_eq!(
        read_purged_sync(&basis, identity()).unwrap(),
        Some(log_id(2))
    );
    assert_eq!(
        snapshot_raw_logs(&basis),
        vec![
            encode_json(&batch(2)).unwrap(),
            encode_json(&batch(3)).unwrap()
        ]
    );
    drop(basis);
    assert!(fixture.wal.read(0, 4).unwrap() == vec![batch(3)]);
    fixture.wal.shutdown().unwrap();
    let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
    assert_eq!(
        read_current_snapshot_sync(&conn, identity()).unwrap(),
        Some(candidate)
    );
    reopened
        .submit(Operation::Committed(Some(log_id(3))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(&conn, &source.caps, vec![batch(3)], ApplyControl::Normal)
        .unwrap();
    assert_eq!(
        snapshot_raw_logs(&conn),
        vec![
            encode_json(&batch(2)).unwrap(),
            encode_json(&batch(3)).unwrap()
        ]
    );
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let final_open = open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
    final_open.validate_application_cache(&conn).unwrap();
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_COMPACTION_CASE {}",
        serde_json::json!({"case":"delayed_capture_stronger_floor", "snapshot_index":1, "basis_purged_index":2, "cache_purged_index":1, "later_rows_preserved":true, "marker_unchanged":true, "reopen_and_successor":true})
    );
}

#[test]
fn snapshot_compaction_faults_recover_atomic_metadata_and_physical_rows() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    for (point, occurrence) in [
        (Point::AfterBasisDirectorySync, 2),
        (Point::AfterSnapshotProofDirectorySync, 1),
        (Point::BeforeSnapshotCacheCommit, 1),
        (Point::AfterSnapshotCacheCommit, 1),
        (Point::AfterBasisSelectorRename, 2),
        (Point::BeforeBasisPublicationSync, 2),
        (Point::AfterBasisPublicationSync, 2),
        (Point::AfterSnapshotProofUnlink, 1),
        (Point::AfterSnapshotProofRetireSync, 1),
        (Point::AfterBasisReclaimFile, 1),
    ] {
        let cache_commit = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let commit_seen = Arc::clone(&cache_commit);
        let failure_seen = Arc::clone(&failed);
        let hits = AtomicUsize::new(0);
        let control = IoControl {
            hook: Arc::new(move |actual| {
                if actual == Point::AfterSnapshotCacheCommit {
                    commit_seen.store(true, Ordering::SeqCst);
                }
                let armed =
                    point != Point::AfterBasisReclaimFile || commit_seen.load(Ordering::SeqCst);
                if actual == point && armed && hits.fetch_add(1, Ordering::SeqCst) + 1 == occurrence
                {
                    failure_seen.store(true, Ordering::SeqCst);
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let fixture = Fixture::new(Limits::default(), control, None, true);
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        let old_rows = snapshot_raw_logs(&conn);
        let marker = snapshot_cache_marker(&conn);
        let candidate = snapshot_metadata_candidate(&conn);
        assert!(
            fixture
                .wal
                .publish_compacting_snapshot(&conn, candidate.clone())
                .is_err(),
            "{point:?}"
        );
        assert!(
            failed.load(Ordering::SeqCst),
            "declared compaction boundary {point:?}/{occurrence} executed"
        );
        assert!(fixture.wal.read(0, 3).is_err());
        assert!(fixture.wal.submit(Operation::Barrier).is_err());
        assert!(fixture.wal.shutdown().is_err());
        let committed = read_current_snapshot_sync(&conn, identity())
            .unwrap()
            .is_some();
        assert_eq!(committed, cache_commit.load(Ordering::SeqCst));
        assert_eq!(
            snapshot_raw_logs(&conn),
            if committed {
                Vec::<Vec<u8>>::new()
            } else {
                old_rows.clone()
            }
        );
        assert_eq!(snapshot_cache_marker(&conn), marker);
        if point == Point::AfterBasisReclaimFile {
            assert!(committed);
            assert_eq!(basis_selector(&fixture.path())["epoch"], 2);
            assert!(!fixture.path().join("SNAPSHOT.pending").exists());
        }
        let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default())
            .unwrap_or_else(|error| panic!("{point:?}: {error}"));
        assert_eq!(
            read_current_snapshot_sync(&conn, identity()).unwrap(),
            committed.then_some(candidate)
        );
        assert_eq!(
            snapshot_raw_logs(&conn),
            if committed {
                Vec::<Vec<u8>>::new()
            } else {
                old_rows
            }
        );
        assert_eq!(snapshot_cache_marker(&conn), marker);
        assert!(
            reopened.read(0, 3).unwrap()
                == if committed {
                    vec![batch(2)]
                } else {
                    vec![membership_entry(), batch(1), batch(2)]
                }
        );
        reopened
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
            .unwrap();
        assert_eq!(
            conn.query_row::<u64, _, _>(
                "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            16
        );
        reopened
            .publish_compacting_snapshot(&conn, snapshot_metadata_candidate(&conn))
            .unwrap();
        assert!(snapshot_raw_logs(&conn).is_empty());
        assert!(snapshot_raw_logs(&selected_snapshot_basis(&fixture.path())).is_empty());
        reopened.shutdown().unwrap();
        let final_open =
            open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
        final_open.validate_application_cache(&conn).unwrap();
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_COMPACTION_CASE {}",
            serde_json::json!({"case":"atomic_fault", "point":format!("{point:?}"), "occurrence":occurrence, "armed_after_cache_commit":point == Point::AfterBasisReclaimFile, "cache_committed":committed, "exact_old_or_new_raw_rows":true, "marker_unchanged":true, "successor_compaction_and_reopen":true})
        );
    }
}

#[test]
fn snapshot_compaction_pending_damage_rejects_mixed_images_and_changed_suffix() {
    use sha2::{Digest, Sha256};
    for damage in [
        "old_metadata_new_raw",
        "new_metadata_old_raw",
        "missing_transform",
        "unknown_transform",
        "changed_unapplied_basis_row",
        "missing_unapplied_basis_row",
    ] {
        let fixture = Fixture::new(
            Limits::default(),
            fail_at(Point::AfterSnapshotCacheCommit),
            None,
            true,
        );
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        assert!(fixture
            .wal
            .publish_compacting_snapshot(&conn, snapshot_metadata_candidate(&conn))
            .is_err());
        assert!(fixture.wal.shutdown().is_err());
        assert!(snapshot_raw_logs(&conn).is_empty());
        let path = fixture.path();
        let proof = snapshot_pending_value(&path);
        assert_eq!(proof["transform"], "Compact");
        let old_path = path.join(format!(
            "basis-{:020}.sqlite",
            proof["old"]["epoch"].as_u64().unwrap()
        ));
        let new_path = path.join(format!(
            "basis-{:020}.sqlite",
            proof["new"]["epoch"].as_u64().unwrap()
        ));
        let bytes = std::fs::read(path.join("SNAPSHOT.pending")).unwrap();
        let mut body = std::str::from_utf8(&bytes[8..bytes.len() - 32])
            .unwrap()
            .to_owned();
        match damage {
            "old_metadata_new_raw" => {
                assert_eq!(
                    conn.execute("DELETE FROM consensus_snapshot", []).unwrap(),
                    1
                );
            }
            "new_metadata_old_raw" => {
                conn.execute(
                    "ATTACH DATABASE ?1 AS compact_old",
                    params![old_path.to_str().unwrap()],
                )
                .unwrap();
                assert_eq!(conn.execute("INSERT INTO main.consensus_log SELECT * FROM compact_old.consensus_log WHERE log_index <= 1", []).unwrap(), 2);
                conn.execute_batch("DETACH DATABASE compact_old").unwrap();
            }
            "missing_transform" => {
                assert!(body.contains(",\"transform\":\"Compact\""));
                body = body.replacen(",\"transform\":\"Compact\"", "", 1);
            }
            "unknown_transform" => {
                body = body.replacen("\"transform\":\"Compact\"", "\"transform\":\"Unknown\"", 1);
            }
            "changed_unapplied_basis_row" | "missing_unapplied_basis_row" => {
                let changed = rusqlite::Connection::open(&new_path).unwrap();
                if damage == "changed_unapplied_basis_row" {
                    assert_eq!(
                        changed
                            .execute(
                                "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 2",
                                params![encode_json(&blank(2)).unwrap()]
                            )
                            .unwrap(),
                        1
                    );
                } else {
                    assert_eq!(
                        changed
                            .execute("DELETE FROM consensus_log WHERE log_index = 2", [])
                            .unwrap(),
                        1
                    );
                }
                drop(changed);
                let (old, new) = body.split_once("\"new\":").unwrap();
                let new = new
                    .replacen(
                        &format!("\"basis\":{}", proof["new"]["basis"]),
                        &format!(
                            "\"basis\":{}",
                            serde_json::to_string(&<[u8; 32]>::from(Sha256::digest(
                                std::fs::read(&new_path).unwrap()
                            )))
                            .unwrap()
                        ),
                        1,
                    )
                    .replacen(
                        &format!("\"basis_bytes\":{}", proof["new"]["basis_bytes"]),
                        &format!(
                            "\"basis_bytes\":{}",
                            std::fs::metadata(&new_path).unwrap().len()
                        ),
                        1,
                    );
                body = format!("{old}\"new\":{new}");
            }
            _ => unreachable!(),
        }
        if !matches!(damage, "old_metadata_new_raw" | "new_metadata_old_raw") {
            let mut changed = b"OPCWSNP1".to_vec();
            changed.extend_from_slice(body.as_bytes());
            changed.extend_from_slice(&Sha256::digest(&changed));
            std::fs::write(path.join("SNAPSHOT.pending"), changed).unwrap();
        }
        let wal_before = files(&path);
        let cache_before = super::super::wal::application::full_image_digest(&conn).unwrap();
        let error = open_snapshot_cache(&fixture, &source, &conn, IoControl::default())
            .err()
            .expect("damaged compaction must reject");
        if matches!(
            damage,
            "missing_transform" | "changed_unapplied_basis_row" | "missing_unapplied_basis_row"
        ) {
            assert!(
                error.to_string().contains("declared original transaction"),
                "{damage}: {error}"
            );
        }
        assert_eq!(files(&path), wal_before, "{damage}");
        assert_eq!(
            super::super::wal::application::full_image_digest(&conn).unwrap(),
            cache_before,
            "{damage}"
        );
        eprintln!(
            "SEQUENTIAL_WAL_COMPACTION_CASE {}",
            serde_json::json!({"case":"pending_damage", "damage":damage, "all_files_and_cache_preserved":true, "rehash_does_not_authorize_changed_transformation":true})
        );
    }
}

#[test]
fn snapshot_metadata_fault_boundaries_recover_only_the_complete_old_or_new_image() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let mut points = vec![
        (Point::BeforeSnapshotProof, 1),
        (Point::AfterSnapshotProofCreate, 1),
        (Point::BeforeSnapshotProofSync, 1),
        (Point::AfterSnapshotProofSync, 1),
        (Point::AfterSnapshotProofRename, 1),
        (Point::AfterSnapshotProofDirectorySync, 1),
        (Point::BeforeSnapshotCacheWrite, 1),
        (Point::BeforeSnapshotCacheCommit, 1),
        (Point::AfterSnapshotCacheCommit, 1),
        (Point::BeforeSnapshotProofRetire, 1),
        (Point::AfterSnapshotProofUnlink, 1),
        (Point::BeforeSnapshotProofRetireSync, 1),
        (Point::AfterSnapshotProofRetireSync, 1),
    ];
    points.extend(
        [
            Point::BeforeBasisCreate,
            Point::AfterBasisCreate,
            Point::BeforeBasisSync,
            Point::AfterBasisSync,
            Point::AfterBasisRename,
            Point::AfterBasisDirectorySync,
            Point::BeforeBasisSelector,
            Point::BeforeBasisSelectorSync,
            Point::AfterBasisSelectorSync,
            Point::AfterBasisSelectorRename,
            Point::BeforeBasisPublicationSync,
            Point::AfterBasisPublicationSync,
            Point::BeforeBasisReclaim,
            Point::AfterBasisReclaimFile,
            Point::BeforeBasisReclaimSync,
            Point::AfterBasisReclaimSync,
        ]
        .map(|point| (point, 2)),
    );
    for (point, occurrence) in points {
        let cache_commit_seen = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&cache_commit_seen);
        let hits = AtomicUsize::new(0);
        let control = IoControl {
            hook: Arc::new(move |actual| {
                if actual == Point::AfterSnapshotCacheCommit {
                    observed.store(true, Ordering::SeqCst);
                }
                // OLD checkpoint cleanup removes multiple covered cut files.
                // Arm this file-level fault only after the snapshot cache commit.
                let armed =
                    point != Point::AfterBasisReclaimFile || observed.load(Ordering::SeqCst);
                let target = if point == Point::AfterBasisReclaimFile {
                    1
                } else {
                    occurrence
                };
                if actual == point && armed && hits.fetch_add(1, Ordering::SeqCst) + 1 == target {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let fixture = Fixture::new(Limits::default(), control, None, true);
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        let candidate = snapshot_metadata_candidate(&conn);
        assert!(
            fixture
                .wal
                .publish_snapshot(&conn, candidate.clone())
                .is_err(),
            "{point:?}/{occurrence}"
        );
        assert!(fixture.wal.read(1, 3).is_err());
        assert!(fixture.wal.submit(Operation::Barrier).is_err());
        assert!(fixture.wal.shutdown().is_err());
        let committed = read_current_snapshot_sync(&conn, identity())
            .unwrap()
            .is_some();
        if fixture.path().join("SNAPSHOT.pending").exists() {
            assert!(
                snapshot_pending_value(&fixture.path())
                    .get("transform")
                    .is_none(),
                "metadata-only encoding remains unchanged"
            );
        }
        if point == Point::AfterBasisReclaimFile {
            assert!(cache_commit_seen.load(Ordering::SeqCst) && committed);
            assert_eq!(basis_selector(&fixture.path())["epoch"], 2);
            assert!(
                !fixture.path().join("SNAPSHOT.pending").exists(),
                "new selection retired proof before reclaim"
            );
        }
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
        let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default())
            .unwrap_or_else(|error| panic!("{point:?}/{occurrence}: {error}"));
        assert_eq!(
            read_current_snapshot_sync(&conn, identity()).unwrap(),
            committed.then_some(candidate)
        );
        assert!(!fixture.path().join("SNAPSHOT.pending").exists());
        assert!(!fixture.path().join("SNAPSHOT.preparing").exists());
        assert!(reopened.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
        reopened
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
            .unwrap();
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 2);
        reopened.checkpoint().unwrap();
        reopened.shutdown().unwrap();
        let final_open =
            open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_SNAPSHOT_CASE {}",
            serde_json::json!({"case":"publication_fault", "point":format!("{point:?}"), "occurrence":if point == Point::AfterBasisReclaimFile { 1 } else { occurrence }, "armed_after_cache_commit":point == Point::AfterBasisReclaimFile, "metadata_only_kernel":true, "cache_committed":committed, "exact_reopen_and_successor":true})
        );
    }
}

#[test]
fn snapshot_install_drains_actual_callback_and_excludes_admission_until_retirement() {
    use opc_consensus::engine::storage::RaftLogStorageExt;
    let before_cut = Pause::new(Point::BeforeCutPublish);
    let after_proof = Pause::new(Point::AfterSnapshotProofDirectorySync);
    let after_retire = Pause::new(Point::AfterSnapshotProofRetireSync);
    let controls = [
        before_cut.control(),
        after_proof.control(),
        after_retire.control(),
    ];
    let control = IoControl {
        hook: Arc::new(move |point| {
            for control in &controls {
                (control.hook)(point)?;
            }
            Ok(())
        }),
        ..IoControl::default()
    };
    let incoming = install_source_at(2);
    let fixture = fixture();
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(fixture.reopen(Limits::default(), control).unwrap());
    let source_path = fixture.directory.path().join("source.sqlite");
    let source = SqliteSessionBackend::open(&source_path).unwrap();
    {
        let conn = source.conn.blocking_lock();
        wal.restore_application(&conn, &source.caps).unwrap();
    }
    let installation = incoming.source().unwrap();
    let initial_vote = wal.vote().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        let appending =
            tokio::spawn(async move { log.blocking_append([batch(1), batch(2), batch(3)]).await });
        before_cut.entered();
        assert!(
            !appending.is_finished(),
            "writer still owns the real LogFlushed callback"
        );
        let publishing_wal = Arc::clone(&wal);
        let publishing = std::thread::spawn(move || {
            let conn = source.conn.blocking_lock();
            publishing_wal.install_snapshot(&conn, installation)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !wal.snapshot_pending_for_test().unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let later_wal = Arc::clone(&wal);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let later = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx
                .send(
                    later_wal
                        .submit(Operation::Vote(Vote::new(2, node_id())))
                        .and_then(|ticket| ticket.wait()),
                )
                .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        before_cut.release();
        after_proof.entered();
        tokio::time::timeout(Duration::from_secs(5), appending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(fixture.path().join("SNAPSHOT.pending").exists());
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        after_proof.release();
        after_retire.entered();
        assert_eq!(basis_selector(&fixture.path())["epoch"], 2);
        assert!(!fixture.path().join("SNAPSHOT.pending").exists());
        assert!(
            matches!(result_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "admission still waits for handoff completion"
        );
        after_retire.release();
        publishing.join().unwrap().unwrap();
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            2
        );
        later.join().unwrap();
    });
    let selector = basis_selector(&fixture.path());
    assert_eq!(selector["position"]["sequence"], 1);
    let selected = Connection::open_with_flags(
        fixture.path().join("basis-00000000000000000002.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(read_vote_sync(&selected, identity()).unwrap(), initial_vote);
    drop(selected);
    wal.shutdown().unwrap();
    let source = SqliteSessionBackend::open(&source_path).unwrap();
    let conn = source.conn.blocking_lock();
    let reopened =
        open_install_cache(&fixture, &source, &conn, &incoming, IoControl::default()).unwrap();
    assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
    reopened
        .submit(Operation::Committed(Some(log_id(3))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(&conn, &source.caps, vec![batch(3)], ApplyControl::Normal)
        .unwrap();
    assert_eq!(receipt_count(&conn), 24);
    reopened.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_INSTALL_CASE {}",
        serde_json::json!({"case":"actual_install_callback_handoff_drain", "real_log_flushed":true, "callback_completed_before_proof":true, "later_vote_excluded_through_retirement":true, "basis_sequence":1, "later_sequence":2, "reopen_and_later_apply":true})
    );
}

#[test]
fn snapshot_handoff_drains_actual_callback_and_excludes_admission_until_retirement() {
    use opc_consensus::engine::storage::RaftLogStorageExt;
    let before_cut = Pause::new(Point::BeforeCutPublish);
    let after_proof = Pause::new(Point::AfterSnapshotProofDirectorySync);
    let after_retire = Pause::new(Point::AfterSnapshotProofRetireSync);
    let controls = [
        before_cut.control(),
        after_proof.control(),
        after_retire.control(),
    ];
    let control = IoControl {
        hook: Arc::new(move |point| {
            for control in &controls {
                (control.hook)(point)?;
            }
            Ok(())
        }),
        ..IoControl::default()
    };
    let fixture = fixture();
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(fixture.reopen(Limits::default(), control).unwrap());
    let source_path = fixture.directory.path().join("source.sqlite");
    let source = SqliteSessionBackend::open(&source_path).unwrap();
    let candidate = {
        let conn = source.conn.blocking_lock();
        wal.restore_application(&conn, &source.caps).unwrap();
        snapshot_metadata_candidate(&conn)
    };
    let initial_vote = wal.vote().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        let appending = tokio::spawn(async move { log.blocking_append([batch(1)]).await });
        before_cut.entered();
        assert!(
            !appending.is_finished(),
            "writer still owns the real LogFlushed callback"
        );
        let publishing_wal = Arc::clone(&wal);
        let publishing = std::thread::spawn(move || {
            let conn = source.conn.blocking_lock();
            publishing_wal.publish_snapshot(&conn, candidate)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !wal.snapshot_pending_for_test().unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let later_wal = Arc::clone(&wal);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let later = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx
                .send(
                    later_wal
                        .submit(Operation::Vote(Vote::new(2, node_id())))
                        .and_then(|ticket| ticket.wait()),
                )
                .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        before_cut.release();
        after_proof.entered();
        tokio::time::timeout(Duration::from_secs(5), appending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(fixture.path().join("SNAPSHOT.pending").exists());
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        after_proof.release();
        after_retire.entered();
        assert_eq!(basis_selector(&fixture.path())["epoch"], 2);
        assert!(!fixture.path().join("SNAPSHOT.pending").exists());
        assert!(
            matches!(result_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "admission still waits for handoff completion"
        );
        after_retire.release();
        publishing.join().unwrap().unwrap();
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            2
        );
        later.join().unwrap();
    });
    let selector = basis_selector(&fixture.path());
    assert_eq!(selector["position"]["sequence"], 1);
    let selected = Connection::open_with_flags(
        fixture.path().join("basis-00000000000000000002.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(read_vote_sync(&selected, identity()).unwrap(), initial_vote);
    drop(selected);
    wal.shutdown().unwrap();
    let source = SqliteSessionBackend::open(&source_path).unwrap();
    let conn = source.conn.blocking_lock();
    let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
    assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
    reopened
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    reopened.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_SNAPSHOT_CASE {}",
        serde_json::json!({"case":"actual_callback_handoff_drain", "real_log_flushed":true, "callback_completed_before_proof":true, "later_vote_excluded_through_retirement":true, "basis_sequence":1, "later_sequence":2, "reopen_and_later_apply":true})
    );
}

fn snapshot_pending_value(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path.join("SNAPSHOT.pending")).unwrap();
    assert_eq!(&bytes[..8], b"OPCWSNP1");
    serde_json::from_slice(&bytes[8..bytes.len() - 32]).unwrap()
}

fn select_snapshot_proof_anchor(path: &Path, field: &str) {
    use sha2::{Digest, Sha256};
    let proof = std::fs::read(path.join("SNAPSHOT.pending")).unwrap();
    let body = std::str::from_utf8(&proof[8..proof.len() - 32]).unwrap();
    let start = body.find(&format!("\"{field}\":")).unwrap() + field.len() + 3;
    let mut depth = 0;
    let end = body[start..]
        .char_indices()
        .find_map(|(offset, ch)| {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(start + offset + 1)
        })
        .unwrap();
    let mut selected = b"OPCWBAS1".to_vec();
    selected.extend_from_slice(body[start..end].as_bytes());
    selected.extend_from_slice(&Sha256::digest(&selected));
    std::fs::write(path.join("CURRENT"), selected).unwrap();
}

#[test]
fn snapshot_pending_damage_rejects_before_any_file_or_cache_mutation() {
    use sha2::{Digest, Sha256};
    for damage in [
        "proof_checksum",
        "old_basis",
        "new_basis",
        "missing_old",
        "missing_new",
        "acknowledged_prefix",
        "cache_receipts",
        "cache_raw_log",
        "cache_marker",
        "new_selector_old_cache",
        "changed_new_image",
        "later_acknowledged_cut",
    ] {
        let fixture = Fixture::new(
            Limits::default(),
            fail_at(Point::AfterSnapshotCacheCommit),
            None,
            true,
        );
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        assert!(fixture
            .wal
            .publish_snapshot(&conn, snapshot_metadata_candidate(&conn))
            .is_err());
        assert!(fixture.wal.shutdown().is_err());
        let path = fixture.path();
        let proof = snapshot_pending_value(&path);
        let old_path = path.join(format!(
            "basis-{:020}.sqlite",
            proof["old"]["epoch"].as_u64().unwrap()
        ));
        let new_path = path.join(format!(
            "basis-{:020}.sqlite",
            proof["new"]["epoch"].as_u64().unwrap()
        ));
        match damage {
            "proof_checksum" | "old_basis" | "new_basis" | "acknowledged_prefix" => {
                let target = match damage {
                    "proof_checksum" => path.join("SNAPSHOT.pending"),
                    "old_basis" => old_path,
                    "new_basis" => new_path,
                    _ => path.join(format!(
                        "segment-{:020}.wal",
                        proof["old"]["position"]["segment"].as_u64().unwrap()
                    )),
                };
                let mut bytes = std::fs::read(&target).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                std::fs::write(target, bytes).unwrap();
            }
            "missing_old" => std::fs::remove_file(old_path).unwrap(),
            "missing_new" => std::fs::remove_file(new_path).unwrap(),
            "cache_receipts" => {
                conn.execute("DELETE FROM consensus_fenced_transition_v2_receipts", [])
                    .unwrap();
            }
            "cache_raw_log" => {
                conn.execute(
                    "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                    params![encode_json(&blank(1)).unwrap()],
                )
                .unwrap();
            }
            "cache_marker" => {
                conn.execute_batch("DROP TABLE consensus_wal_application")
                    .unwrap();
            }
            "new_selector_old_cache" => {
                select_snapshot_proof_anchor(&path, "new");
                conn.execute("DELETE FROM consensus_snapshot", []).unwrap();
            }
            "changed_new_image" => {
                let changed = rusqlite::Connection::open(&new_path).unwrap();
                changed.execute_batch("CREATE TABLE unexplained_snapshot_business (value INTEGER NOT NULL); INSERT INTO unexplained_snapshot_business VALUES (7)").unwrap();
                let application =
                    super::super::wal::application::application_digest(&changed).unwrap();
                drop(changed);
                let bytes = std::fs::read(path.join("SNAPSHOT.pending")).unwrap();
                let body = std::str::from_utf8(&bytes[8..bytes.len() - 32]).unwrap();
                let (old, new) = body.split_once("\"new\":").unwrap();
                let new = new
                    .replacen(
                        &format!("\"basis\":{}", proof["new"]["basis"]),
                        &format!(
                            "\"basis\":{}",
                            serde_json::to_string(&<[u8; 32]>::from(Sha256::digest(
                                std::fs::read(&new_path).unwrap()
                            )))
                            .unwrap()
                        ),
                        1,
                    )
                    .replacen(
                        &format!("\"basis_bytes\":{}", proof["new"]["basis_bytes"]),
                        &format!(
                            "\"basis_bytes\":{}",
                            std::fs::metadata(&new_path).unwrap().len()
                        ),
                        1,
                    )
                    .replacen(
                        &format!("\"new_application\":{}", proof["new_application"]),
                        &format!(
                            "\"new_application\":{}",
                            serde_json::to_string(&application).unwrap()
                        ),
                        1,
                    );
                let mut bytes = format!("OPCWSNP1{old}\"new\":{new}").into_bytes();
                bytes.extend_from_slice(&Sha256::digest(&bytes));
                std::fs::write(path.join("SNAPSHOT.pending"), bytes).unwrap();
            }
            "later_acknowledged_cut" => {
                let saved = std::fs::read(path.join("SNAPSHOT.pending")).unwrap();
                let next = std::fs::read(&new_path).unwrap();
                std::fs::remove_file(path.join("SNAPSHOT.pending")).unwrap();
                let illicit = fixture
                    .reopen(Limits::default(), IoControl::default())
                    .unwrap();
                illicit.submit(Operation::Barrier).unwrap().wait().unwrap();
                illicit.shutdown().unwrap();
                std::fs::write(new_path, next).unwrap();
                std::fs::write(path.join("SNAPSHOT.pending"), saved).unwrap();
            }
            _ => unreachable!(),
        }
        let wal_before = files(&path);
        let cache_before = super::super::wal::application::full_image_digest(&conn).unwrap();
        assert!(
            open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).is_err(),
            "{damage}"
        );
        assert_eq!(
            files(&path),
            wal_before,
            "{damage}: preserve files before rejection"
        );
        assert_eq!(
            super::super::wal::application::full_image_digest(&conn).unwrap(),
            cache_before,
            "{damage}: preserve every cache row"
        );
        eprintln!(
            "SEQUENTIAL_WAL_SNAPSHOT_CASE {}",
            serde_json::json!({"case":"pending_damage", "damage":damage, "all_files_and_cache_preserved":true})
        );
    }
}

#[test]
fn snapshot_recovery_repeats_proof_retirement_and_stabilizes_reordered_selection() {
    for scenario in [
        "proof_rename_reverted",
        "selector_rename_reverted",
        "proof_unlink_visible",
        "recovery_unlink_interrupted",
    ] {
        let point = if scenario == "proof_rename_reverted" {
            Point::AfterSnapshotProofRename
        } else {
            Point::AfterSnapshotCacheCommit
        };
        let fixture = Fixture::new(Limits::default(), fail_at(point), None, true);
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        let candidate = snapshot_metadata_candidate(&conn);
        assert!(fixture
            .wal
            .publish_snapshot(&conn, candidate.clone())
            .is_err());
        assert!(fixture.wal.shutdown().is_err());
        let path = fixture.path();
        match scenario {
            "proof_rename_reverted" => std::fs::rename(
                path.join("SNAPSHOT.pending"),
                path.join("SNAPSHOT.preparing"),
            )
            .unwrap(),
            "selector_rename_reverted" => {
                select_snapshot_proof_anchor(&path, "new");
                select_snapshot_proof_anchor(&path, "old");
            }
            "proof_unlink_visible" => {
                select_snapshot_proof_anchor(&path, "new");
                std::fs::remove_file(path.join("SNAPSHOT.pending")).unwrap();
                let before = files(&path);
                assert!(open_snapshot_cache(
                    &fixture,
                    &source,
                    &conn,
                    fail_at(Point::BeforeRecoveryPublicationSync)
                )
                .is_err());
                assert_eq!(
                    files(&path),
                    before,
                    "already absent proof still requires sync before reclamation"
                );
            }
            "recovery_unlink_interrupted" => {
                assert!(open_snapshot_cache(
                    &fixture,
                    &source,
                    &conn,
                    fail_at(Point::AfterSnapshotProofUnlink)
                )
                .is_err());
                assert!(!path.join("SNAPSHOT.pending").exists());
                assert!(
                    path.join("basis-00000000000000000001.sqlite").exists(),
                    "old image retained until proof retirement sync"
                );
            }
            _ => unreachable!(),
        }
        let reopened = open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
        assert_eq!(
            read_current_snapshot_sync(&conn, identity()).unwrap(),
            (scenario != "proof_rename_reverted").then_some(candidate)
        );
        reopened
            .publish_snapshot(&conn, snapshot_metadata_candidate(&conn))
            .unwrap();
        reopened
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
            .unwrap();
        reopened.shutdown().unwrap();
        let final_open =
            open_snapshot_cache(&fixture, &source, &conn, IoControl::default()).unwrap();
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_SNAPSHOT_CASE {}",
            serde_json::json!({"case":"directory_persistence", "scenario":scenario, "successor_reopened":true})
        );
    }
}

fn rewrite_basis_scalar(
    path: &Path,
    field: &str,
    before: serde_json::Value,
    after: serde_json::Value,
) {
    use sha2::{Digest, Sha256};
    let original = std::fs::read(path.join("CURRENT")).unwrap();
    let body = std::str::from_utf8(&original[8..original.len() - 32]).unwrap();
    let needle = format!("\"{field}\":{before}");
    assert!(
        body.contains(&needle),
        "fixture field {field} is present in canonical encoding"
    );
    let changed = body.replacen(&needle, &format!("\"{field}\":{after}"), 1);
    let mut bytes = original[..8].to_vec();
    bytes.extend_from_slice(changed.as_bytes());
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    std::fs::write(path.join("CURRENT"), bytes).unwrap();
}

#[test]
fn moving_basis_retains_unapplied_history_and_older_application_marker() {
    let limits = Limits {
        history_count: 4,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, IoControl::default(), None, true);
    fixture
        .wal
        .submit(append(&[batch(1), batch(2), batch(3)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    for term in [2, 3] {
        fixture
            .wal
            .submit(Operation::Vote(Vote::new(term, node_id())))
            .unwrap()
            .wait()
            .unwrap();
    }
    let marker: Vec<u8> = conn
        .query_row(
            "SELECT marker_json FROM consensus_wal_application",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fixture.wal.checkpoint().unwrap(), 1);
    let selector = basis_selector(&fixture.path());
    assert_eq!(selector["position"]["sequence"], 4);
    assert_eq!(selector["marker"]["cut_sequence"], 2);
    assert_eq!(selector["cuts"].as_object().unwrap().len(), 2);
    assert!(files(&fixture.path())
        .keys()
        .all(|name| !name.starts_with("cut-")));
    fixture.wal.shutdown().unwrap();

    // The selected marker expectation must survive a second checkpoint made
    // before attaching the external application cache to this incarnation.
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert_eq!(
        reopened
            .submit(Operation::Vote(Vote::new(4, node_id())))
            .unwrap()
            .wait()
            .unwrap(),
        5
    );
    assert_eq!(reopened.checkpoint().unwrap(), 2);
    assert_eq!(basis_selector(&fixture.path())["marker"]["cut_sequence"], 2);
    reopened.restore_application(&conn, &source.caps).unwrap();
    assert_eq!(
        conn.query_row::<Vec<u8>, _, _>(
            "SELECT marker_json FROM consensus_wal_application",
            [],
            |row| row.get(0)
        )
        .unwrap(),
        marker
    );
    assert!(reopened.read(1, 4).unwrap() == vec![batch(1), batch(2), batch(3)]);
    assert_eq!(reopened.committed().unwrap(), Some(log_id(1)));
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
    reopened
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .unwrap();
    reopened
        .submit(append(&[batch(4)]))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(reopened.checkpoint().unwrap(), 3);
    assert_eq!(basis_selector(&fixture.path())["marker"]["cut_sequence"], 6);
    assert!(!fixture
        .path()
        .join("basis-00000000000000000001.sqlite")
        .exists());
    assert!(!fixture
        .path()
        .join("basis-00000000000000000002.sqlite")
        .exists());
    reopened.shutdown().unwrap();
    let final_open = fixture.reopen(limits, IoControl::default()).unwrap();
    final_open.restore_application(&conn, &source.caps).unwrap();
    assert!(final_open.read(1, 5).unwrap() == vec![batch(1), batch(2), batch(3), batch(4)]);
    assert_eq!(final_open.committed().unwrap(), Some(log_id(2)));
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 2);
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_BASIS_CASE {}",
        serde_json::json!({"case":"older_marker_and_unapplied_suffix", "checkpoints":3, "unattached_checkpoint_preserved_marker":true, "uncommitted_entries_retained":2, "exact_application_reopened":true})
    );
}

#[test]
fn moving_basis_logical_purge_preserves_exact_application_cache_audit() {
    let raw_log = |conn: &rusqlite::Connection| {
        conn.prepare("SELECT entry_json FROM consensus_log ORDER BY log_index")
            .unwrap()
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    for damage in ["intact", "changed-covered-payload", "missing-covered-row"] {
        let fixture = fixture();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(
                &conn,
                &source.caps,
                vec![batch(1), batch(2)],
                ApplyControl::Normal,
            )
            .unwrap();
        let original_rows = raw_log(&conn);
        let original_marker: Vec<u8> = conn
            .query_row(
                "SELECT marker_json FROM consensus_wal_application",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fixture.wal.checkpoint().unwrap(), 1);
        fixture
            .wal
            .submit(Operation::Purge(log_id(1)))
            .unwrap()
            .wait()
            .unwrap();
        assert!(
            fixture.wal.read(0, 3).unwrap() == vec![batch(2)],
            "Raft reads obey the logical floor"
        );
        assert_eq!(
            raw_log(&conn),
            original_rows,
            "Raft purge does not rewrite the attached cache"
        );
        fixture
            .wal
            .restore_application(&conn, &source.caps)
            .unwrap();
        assert_eq!(
            conn.query_row::<Vec<u8>, _, _>(
                "SELECT marker_json FROM consensus_wal_application",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            original_marker
        );
        assert_eq!(fixture.wal.checkpoint().unwrap(), 2);
        fixture.wal.shutdown().unwrap();

        match damage {
            "changed-covered-payload" => {
                // A well-formed entry with the same exact full LogId still
                // changes acknowledged content below the logical floor.
                conn.execute(
                    "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                    rusqlite::params![encode_json(&blank(1)).unwrap()],
                )
                .unwrap();
            }
            "missing-covered-row" => {
                conn.execute("DELETE FROM consensus_log WHERE log_index = 1", [])
                    .unwrap();
            }
            _ => {}
        }
        let before_files = files(&fixture.path());
        let before_rows = raw_log(&conn);
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        if damage != "intact" {
            assert!(reopened.restore_application(&conn, &source.caps).is_err());
            assert!(reopened.read(0, 3).is_err());
            assert!(reopened
                .submit(Operation::Vote(Vote::new(2, node_id())))
                .is_err());
            assert!(reopened.shutdown().is_err());
            assert_eq!(files(&fixture.path()), before_files);
            assert_eq!(raw_log(&conn), before_rows);
            assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 2);
        } else {
            reopened.restore_application(&conn, &source.caps).unwrap();
            assert_eq!(raw_log(&conn), original_rows);
            assert!(reopened.read(0, 3).unwrap() == vec![batch(2)]);
            reopened
                .submit(append(&[batch(3)]))
                .unwrap()
                .wait()
                .unwrap();
            reopened
                .submit(Operation::Committed(Some(log_id(3))))
                .unwrap()
                .wait()
                .unwrap();
            reopened
                .apply_committed(&conn, &source.caps, vec![batch(3)], ApplyControl::Normal)
                .unwrap();
            assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 3);
            assert!(
                reopened.submit(Operation::Purge(log_id(3))).is_err(),
                "a live application advance does not replace the selected recovery basis"
            );
            assert!(
                reopened
                    .submit(Operation::Purge(LogId::new(
                        CommittedLeaderId::new(2, node_id()),
                        2
                    )))
                    .is_err(),
                "the original full LogId validation remains exact"
            );
            assert_eq!(reopened.checkpoint().unwrap(), 3);
            reopened
                .submit(Operation::Purge(log_id(2)))
                .unwrap()
                .wait()
                .unwrap();
            reopened
                .submit(Operation::Purge(log_id(1)))
                .unwrap()
                .wait()
                .unwrap();
            assert!(
                reopened.read(0, 4).unwrap() == vec![batch(3)],
                "delayed purge cannot regress the floor"
            );
            assert_eq!(reopened.checkpoint().unwrap(), 4);
            reopened.shutdown().unwrap();
            let final_open = fixture
                .reopen(Limits::default(), IoControl::default())
                .unwrap();
            final_open.restore_application(&conn, &source.caps).unwrap();
            assert_eq!(raw_log(&conn).len(), 4);
            assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 3);
            assert_eq!(
                conn.query_row::<u64, _, _>(
                    "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                24
            );
            assert!(final_open.read(0, 4).unwrap() == vec![batch(3)]);
            final_open.shutdown().unwrap();
        }
        eprintln!(
            "SEQUENTIAL_WAL_BASIS_CASE {}",
            serde_json::json!({"case":"logical_purge_cache_audit", "damage":damage, "logical_floor_and_exact_coverage_preserved":true, "intact_cache_successor_reopened":damage == "intact", "covered_corruption_rejected_without_mutation":damage != "intact"})
        );
    }
}

#[test]
fn automatic_basis_actual_adapter_preserves_count_and_byte_bounded_history() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};

    for (history_count, history_bytes) in [(2, 8192), (1024, 1024)] {
        let limits = Limits {
            history_count,
            history_bytes,
            ..Limits::default()
        };
        let fixture = Fixture::new(limits, IoControl::default(), None, false);
        fixture.wal.shutdown().unwrap();
        let wal = Arc::new(fixture.reopen(limits, IoControl::default()).unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut log = WalLogStore::new(Arc::clone(&wal));
            for index in 1..=24 {
                log.blocking_append([blank(index)]).await.unwrap();
                log.save_committed(Some(log_id(index))).await.unwrap();
                log.save_vote(&Vote::new_committed(index + 2, node_id()))
                    .await
                    .unwrap();
                let costs = wal.integration_observations().unwrap();
                assert!(
                    costs["costs"]["live_retained_requests"].as_u64().unwrap()
                        <= history_count as u64
                );
                assert!(
                    costs["costs"]["live_retained_bytes"].as_u64().unwrap() <= history_bytes as u64
                );
            }
        });
        let costs = wal.integration_observations().unwrap();
        assert_eq!(costs["costs"]["requests"], 72);
        let automatic = costs["costs"]["checkpoint"]["automatic_requests"]
            .as_u64()
            .unwrap();
        assert!(automatic > 0);
        assert_eq!(costs["costs"]["checkpoint"]["completed"], automatic);
        assert_eq!(costs["costs"]["checkpoint"]["failures"], 0);
        wal.shutdown().unwrap();
        let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
        assert!(reopened.read(1, 25).unwrap() == (1..=24).map(blank).collect::<Vec<_>>());
        assert_eq!(reopened.committed().unwrap(), Some(log_id(24)));
        assert_eq!(
            reopened.vote().unwrap(),
            Some(Vote::new_committed(26, node_id()))
        );
        reopened.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_AUTOMATIC_BASIS_CASE {}",
            serde_json::json!({"case":"bounded_actual_adapter", "history_count":history_count, "history_bytes":history_bytes, "original_callbacks_and_metadata":72, "automatic_completed":automatic, "exact_reopen":true})
        );
    }
}

#[test]
fn automatic_basis_oversized_request_rejects_without_handoff_loop() {
    use opc_consensus::engine::storage::RaftLogStorageExt;

    let limits = Limits {
        history_bytes: 1024,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, IoControl::default(), None, false);
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(fixture.reopen(limits, IoControl::default()).unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        assert!(log
            .blocking_append((1..=64).map(blank).collect::<Vec<_>>())
            .await
            .is_err());
        log.blocking_append([blank(1)]).await.unwrap();
    });
    let costs = wal.integration_observations().unwrap();
    assert_eq!(costs["costs"]["checkpoint"]["automatic_requests"], 0);
    assert_eq!(costs["costs"]["requests"], 1);
    wal.shutdown().unwrap();
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(reopened.read(1, 65).unwrap() == vec![blank(1)]);
    reopened.shutdown().unwrap();
}

#[test]
fn automatic_basis_drains_actual_callback_before_later_vote_admission() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};

    let before_cut = Pause::new(Point::BeforeCutPublish);
    let before_basis = Pause::new(Point::BeforeBasisCreate);
    let cut_control = before_cut.control();
    let basis_control = before_basis.control();
    let control = IoControl {
        hook: Arc::new(move |point| {
            (cut_control.hook)(point)?;
            (basis_control.hook)(point)
        }),
        ..IoControl::default()
    };
    let limits = Limits {
        history_count: 1,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, IoControl::default(), None, false);
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(fixture.reopen(limits, control).unwrap());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        let mut later = log.clone();
        let appending = tokio::spawn(async move { log.blocking_append([blank(1)]).await });
        before_cut.entered();
        assert!(!appending.is_finished());
        let voting =
            tokio::spawn(async move { later.save_vote(&Vote::new_committed(2, node_id())).await });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !wal.checkpoint_pending_for_test().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        before_cut.release();
        before_basis.entered();
        appending.await.unwrap().unwrap();
        assert!(
            !voting.is_finished(),
            "later vote is not admitted in the captured basis"
        );
        before_basis.release();
        voting.await.unwrap().unwrap();
    });
    assert_eq!(basis_selector(&fixture.path())["position"]["sequence"], 1);
    wal.shutdown().unwrap();
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![blank(1)]);
    assert_eq!(
        reopened.vote().unwrap(),
        Some(Vote::new_committed(2, node_id()))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn automatic_basis_faults_fence_unadmitted_callback_and_recover_prior_acknowledgments() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};

    for point in [
        Point::BeforeBasisCreate,
        Point::BeforeBasisSelector,
        Point::AfterBasisPublicationSync,
        Point::AfterBasisReclaimFile,
    ] {
        let limits = Limits {
            history_count: 2,
            ..Limits::default()
        };
        let fixture = Fixture::new(limits, IoControl::default(), None, false);
        fixture.wal.shutdown().unwrap();
        let wal = Arc::new(fixture.reopen(limits, fail_at(point)).unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut log = WalLogStore::new(Arc::clone(&wal));
            log.blocking_append([blank(1)]).await.unwrap();
            log.save_committed(Some(log_id(1))).await.unwrap();
            assert!(
                log.blocking_append([blank(2)]).await.is_err(),
                "original actual callback fails at {point:?}"
            );
            assert!(
                log.save_vote(&Vote::new_committed(2, node_id()))
                    .await
                    .is_err(),
                "all later admission fenced"
            );
        });
        assert!(wal.shutdown().is_err());
        let reopened = Arc::new(fixture.reopen(limits, IoControl::default()).unwrap());
        assert!(reopened.read(1, 3).unwrap() == vec![blank(1)]);
        assert_eq!(reopened.committed().unwrap(), Some(log_id(1)));
        runtime.block_on(async {
            let mut log = WalLogStore::new(Arc::clone(&reopened));
            log.blocking_append([blank(2)]).await.unwrap();
        });
        reopened.shutdown().unwrap();
        let final_open = fixture.reopen(limits, IoControl::default()).unwrap();
        assert!(final_open.read(1, 3).unwrap() == vec![blank(1), blank(2)]);
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_AUTOMATIC_BASIS_CASE {}",
            serde_json::json!({"case":"actual_callback_fault", "point":format!("{point:?}"), "prior_acknowledgments_recovered":true, "original_failed_request_unadmitted":true, "new_incarnation_success_reopened":true})
        );
    }
}

#[test]
fn moving_basis_bounds_count_only_retained_suffix() {
    let limits = Limits {
        outstanding_bytes: 1024,
        group_count: 4,
        group_bytes: 512,
        segment_bytes: 1024,
        history_count: 4,
        history_bytes: 8192,
        segments: 4,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, IoControl::default(), None, false);
    assert_eq!(
        fixture.wal.checkpoint().unwrap(),
        1,
        "a zero-operation basis is valid"
    );
    let mut total_sync_calls = 0;
    let mut total_data_sync_us = 0;
    for index in 1..=24 {
        assert_eq!(
            fixture
                .wal
                .submit(append(&[blank(index)]))
                .unwrap()
                .wait()
                .unwrap(),
            index
        );
        let samples = fixture.wal.observations().unwrap();
        assert!(
            samples
                .iter()
                .map(|sample| sample.admission.len())
                .sum::<usize>()
                <= limits.history_count
        );
        let latest = samples.last().unwrap();
        assert_eq!(latest.last, index);
        total_sync_calls += latest.sync_calls;
        total_data_sync_us += latest.data_sync.as_micros();
        if index % 4 == 0 {
            assert_eq!(fixture.wal.checkpoint().unwrap(), index / 4 + 1);
        }
    }
    let observation = fixture.wal.integration_observations().unwrap();
    let costs = &observation["costs"];
    assert_eq!(costs["scope"], "current_writer_incarnation");
    assert_eq!(costs["groups"], 24);
    assert_eq!(costs["requests"], 24);
    assert_eq!(costs["appended_entries"], 24);
    assert_eq!(costs["retained_groups"], 4);
    assert_eq!(costs["retained_requests"], 4);
    assert_eq!(costs["retained_request_limit"], 4);
    assert_eq!(costs["discarded_groups"], 20);
    assert_eq!(costs["discarded_requests"], 20);
    assert_eq!(costs["sync_calls"], total_sync_calls);
    assert_eq!(costs["data_sync_us"], serde_json::json!(total_data_sync_us));
    assert_eq!(observation["groups"].as_array().unwrap().len(), 4);
    assert_eq!(observation["groups"][0]["first"], 21);
    assert_eq!(observation["groups"][3]["last"], 24);
    let selector = basis_selector(&fixture.path());
    assert_eq!(selector["position"]["sequence"], 24);
    assert!(selector["position"]["segment"].as_u64().unwrap() >= limits.segments as u64);
    let retained = files(&fixture.path());
    assert_eq!(
        retained
            .keys()
            .filter(|name| name.starts_with("segment-"))
            .count(),
        1
    );
    assert_eq!(
        retained
            .keys()
            .filter(|name| name.starts_with("basis-"))
            .count(),
        1
    );
    assert!(retained.keys().all(|name| !name.starts_with("cut-")));
    fixture.wal.shutdown().unwrap();
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(reopened.read(1, 25).unwrap() == (1..=24).map(blank).collect::<Vec<_>>());
    assert_eq!(
        reopened
            .submit(append(&[blank(25)]))
            .unwrap()
            .wait()
            .unwrap(),
        25
    );
    reopened.shutdown().unwrap();
    let final_open = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(final_open.read(1, 26).unwrap() == (1..=25).map(blank).collect::<Vec<_>>());
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_BASIS_CASE {}",
        serde_json::json!({"case":"retained_bounds", "checkpoints":7, "operation_sequence":25, "absolute_segment":selector["position"]["segment"], "retained_segments":1, "retained_observation_requests":4, "total_observation_requests":24, "discarded_observation_requests":20, "all_flush_sync_and_time_totals_exact":true, "successor_reopened":true})
    );
}

#[test]
fn moving_basis_drains_callbacks_and_excludes_later_admission() {
    let before_cut = Pause::new(Point::BeforeCutPublish);
    let before_basis = Pause::new(Point::BeforeBasisCreate);
    let cut_control = before_cut.control();
    let basis_control = before_basis.control();
    let control = IoControl {
        hook: Arc::new(move |point| {
            (cut_control.hook)(point)?;
            (basis_control.hook)(point)
        }),
        ..IoControl::default()
    };
    let fixture = fixture();
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(fixture.reopen(Limits::default(), control).unwrap());
    let initial_vote = wal.vote().unwrap();
    let first = wal.submit(append(&[batch(1)])).unwrap();
    before_cut.entered();
    let checkpoint_wal = Arc::clone(&wal);
    let checkpoint = std::thread::spawn(move || checkpoint_wal.checkpoint());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !wal.checkpoint_pending_for_test().unwrap() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    let later_wal = Arc::clone(&wal);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let later = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx
            .send(
                later_wal
                    .submit(Operation::Vote(Vote::new(2, node_id())))
                    .and_then(|ticket| ticket.wait()),
            )
            .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        result_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    before_cut.release();
    before_basis.entered();
    assert_eq!(
        first.wait().unwrap(),
        1,
        "accepted callback completes before basis capture"
    );
    assert!(matches!(
        result_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    before_basis.release();
    assert_eq!(checkpoint.join().unwrap().unwrap(), 1);
    assert_eq!(
        result_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        2
    );
    later.join().unwrap();
    assert_eq!(basis_selector(&fixture.path())["position"]["sequence"], 1);
    let selected = Connection::open_with_flags(
        fixture.path().join("basis-00000000000000000001.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(read_vote_sync(&selected, identity()).unwrap(), initial_vote);
    drop(selected);
    wal.shutdown().unwrap();
    let reopened = Wal::open(
        &fixture.path(),
        wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
    assert!(reopened.read(1, 2).unwrap() == vec![batch(1)]);
    reopened.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_BASIS_CASE {}",
        serde_json::json!({"case":"drained_ownership", "captured_sequence":1, "later_sequence":2, "callback_completed_before_capture":true, "later_vote_absent_from_basis":true})
    );
}

#[test]
fn moving_basis_faults_recover_selection_or_prior_complete_history() {
    for point in [
        Point::BeforeBasisCreate,
        Point::AfterBasisCreate,
        Point::BeforeBasisSync,
        Point::AfterBasisSync,
        Point::AfterBasisRename,
        Point::AfterBasisDirectorySync,
        Point::BeforeBasisSelector,
        Point::BeforeBasisSelectorSync,
        Point::AfterBasisSelectorSync,
        Point::AfterBasisSelectorRename,
        Point::BeforeBasisPublicationSync,
        Point::AfterBasisPublicationSync,
        Point::BeforeBasisReclaim,
        Point::AfterBasisReclaimFile,
        Point::BeforeBasisReclaimSync,
        Point::AfterBasisReclaimSync,
    ] {
        let fixture = Fixture::new(Limits::default(), fail_at(point), None, true);
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Vote(Vote::new(2, node_id())))
            .unwrap()
            .wait()
            .unwrap();
        let prior = files(&fixture.path());
        assert!(fixture.wal.checkpoint().is_err(), "fault at {point:?}");
        assert!(fixture.wal.read(1, 2).is_err());
        assert!(fixture.wal.shutdown().is_err());
        let selected = fixture.path().join("CURRENT").exists();
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        if !selected {
            assert_eq!(
                files(&fixture.path()),
                prior,
                "unselected basis at {point:?} changes no acknowledged file"
            );
        }
        assert!(reopened.read(1, 2).unwrap() == vec![batch(1)]);
        assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
        assert_eq!(
            reopened
                .submit(Operation::Vote(Vote::new(3, node_id())))
                .unwrap()
                .wait()
                .unwrap(),
            3
        );
        assert_eq!(reopened.checkpoint().unwrap(), if selected { 2 } else { 1 });
        reopened.shutdown().unwrap();
        let final_open = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert!(final_open.read(1, 2).unwrap() == vec![batch(1)]);
        assert_eq!(final_open.vote().unwrap(), Some(Vote::new(3, node_id())));
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_BASIS_CASE {}",
            serde_json::json!({"case":"checkpoint_fault", "point":format!("{point:?}"), "selected_basis_adopted":selected, "all_acknowledged_history_preserved":true, "successor_and_checkpoint_reopened":true})
        );
    }
}

#[test]
fn moving_basis_reopen_stabilizes_selector_before_reclamation_and_use() {
    for point in [
        Point::BeforeRecoveryPublicationSync,
        Point::AfterRecoveryPublicationSync,
    ] {
        let fixture = Fixture::new(
            Limits::default(),
            fail_at(Point::AfterBasisSelectorRename),
            None,
            true,
        );
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        assert!(fixture.wal.checkpoint().is_err());
        assert!(fixture.wal.shutdown().is_err());
        let before = files(&fixture.path());
        assert!(fixture.reopen(Limits::default(), fail_at(point)).is_err());
        assert_eq!(
            files(&fixture.path()),
            before,
            "selector stabilization failure cannot reclaim covered history"
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&events);
        let control = IoControl {
            hook: Arc::new(move |point| {
                if matches!(
                    point,
                    Point::BeforeRecoveryPublicationSync
                        | Point::AfterRecoveryPublicationSync
                        | Point::BeforeBasisReclaim
                ) {
                    observed.lock().unwrap().push(point);
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let reopened = fixture.reopen(Limits::default(), control).unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                Point::BeforeRecoveryPublicationSync,
                Point::AfterRecoveryPublicationSync,
                Point::BeforeBasisReclaim
            ]
        );
        assert!(reopened.read(1, 2).unwrap() == vec![batch(1)]);
        reopened
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        reopened.shutdown().unwrap();
        let final_open = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert!(final_open.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_BASIS_CASE {}",
            serde_json::json!({"case":"selector_recovery_sync", "point":format!("{point:?}"), "no_owner_or_reclamation_before_sync":true, "successor_reopened":true})
        );
    }
}

#[test]
fn moving_basis_keeps_cache_marker_expectation_across_unattached_checkpoint() {
    for unattached in [false, true] {
        for damage in ["intact", "drop-table", "delete-row", "relabel-current-cut"] {
            let fixture = fixture();
            fixture
                .wal
                .submit(append(&[batch(1)]))
                .unwrap()
                .wait()
                .unwrap();
            fixture
                .wal
                .submit(Operation::Committed(Some(log_id(1))))
                .unwrap()
                .wait()
                .unwrap();
            let source =
                SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
            let conn = source.conn.blocking_lock();
            fixture
                .wal
                .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
                .unwrap();
            fixture
                .wal
                .submit(Operation::Vote(Vote::new(2, node_id())))
                .unwrap()
                .wait()
                .unwrap();
            fixture.wal.checkpoint().unwrap();
            fixture.wal.shutdown().unwrap();
            if unattached {
                let opened = fixture
                    .reopen(Limits::default(), IoControl::default())
                    .unwrap();
                assert_eq!(opened.checkpoint().unwrap(), 2);
                opened.shutdown().unwrap();
            }
            match damage {
                "intact" => {}
                "drop-table" => conn
                    .execute_batch("DROP TABLE consensus_wal_application")
                    .unwrap(),
                "delete-row" => {
                    assert_eq!(
                        conn.execute("DELETE FROM consensus_wal_application", [])
                            .unwrap(),
                        1
                    );
                }
                "relabel-current-cut" => {
                    let selector = basis_selector(&fixture.path());
                    let marker = &selector["marker"];
                    // This is another genuine retained durable cut with the
                    // same committed frontier, so a cut lookup alone passes.
                    let changed = format!(
                        "{{\"binding\":{},\"cut_sequence\":3,\"cut_chain\":{},\"applied\":{}}}",
                        marker["binding"],
                        selector["cuts"]["3"]["chain"],
                        serde_json::to_string(&log_id(1)).unwrap()
                    );
                    conn.execute(
                        "UPDATE consensus_wal_application SET marker_json = ?1",
                        params![changed.as_bytes()],
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let before = proposal_state_sync(&conn, identity()).unwrap();
            let wal_files = files(&fixture.path());
            let reopened = fixture
                .reopen(Limits::default(), IoControl::default())
                .unwrap();
            let result = reopened.restore_application(&conn, &source.caps);
            if damage == "intact" {
                result.unwrap();
                assert_eq!(proposal_state_sync(&conn, identity()).unwrap(), before);
                reopened
                    .submit(append(&[batch(2)]))
                    .unwrap()
                    .wait()
                    .unwrap();
                reopened
                    .submit(Operation::Committed(Some(log_id(2))))
                    .unwrap()
                    .wait()
                    .unwrap();
                reopened
                    .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
                    .unwrap();
                reopened.shutdown().unwrap();
                let later = fixture
                    .reopen(Limits::default(), IoControl::default())
                    .unwrap();
                later.restore_application(&conn, &source.caps).unwrap();
                assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 2);
                later.shutdown().unwrap();
            } else {
                let error = result.expect_err("selected marker expectation rejects corruption");
                if damage == "relabel-current-cut" {
                    assert!(
                        error.to_string().contains("changed at selected frontier"),
                        "{error}"
                    );
                }
                assert!(reopened.read(1, 2).is_err());
                assert!(reopened.submit(append(&[blank(2)])).is_err());
                assert_eq!(proposal_state_sync(&conn, identity()).unwrap(), before);
                assert_eq!(files(&fixture.path()), wal_files);
                assert!(reopened.shutdown().is_err());
            }
            eprintln!(
                "SEQUENTIAL_WAL_BASIS_CASE {}",
                serde_json::json!({"case":"selected_marker_expectation", "unattached_checkpoint":unattached, "damage":damage, "intact_or_legitimate_extension_restored":damage == "intact", "corruption_fenced":damage != "intact"})
            );
        }
    }
}

#[test]
fn moving_basis_rejects_selected_authority_and_suffix_damage_before_any_cleanup() {
    for damage in [
        "selector-checksum",
        "selector-root",
        "selector-extent",
        "selector-position-chain",
        "selector-cut-chain",
        "selector-offset",
        "selected-basis",
        "missing-selected-basis",
        "retained-prefix",
        "missing-anchor-segment",
        "missing-suffix-cut",
        "suffix-body",
        "suffix-cut",
        "extra-future-basis",
        "wrong-stage-epoch",
        "noncanonical-name",
        "oversized-selector-stage",
        "nonregular-file",
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Vote(Vote::new(2, node_id())))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.checkpoint().unwrap();
        fixture
            .wal
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let path = fixture.path();
        let selector = basis_selector(&path);
        let anchor = path.join(format!(
            "segment-{:020}.wal",
            selector["position"]["segment"].as_u64().unwrap()
        ));
        let basis = path.join("basis-00000000000000000001.sqlite");
        let suffix = path.join("cut-00000000000000000003.cut");
        // These are legitimate unselected partial preparations. Any failure
        // below must preserve them too, rather than eagerly cleaning first.
        std::fs::write(
            path.join("basis-00000000000000000002.preparing"),
            b"partial SQLite image",
        )
        .unwrap();
        std::fs::write(path.join("CURRENT.preparing"), b"partial selector").unwrap();
        match damage {
            "selector-checksum" => {
                let target = path.join("CURRENT");
                let mut bytes = std::fs::read(&target).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                std::fs::write(target, bytes).unwrap();
            }
            "selector-root" | "selector-position-chain" | "selector-cut-chain" => {
                let (field, old) = match damage {
                    "selector-root" => ("root", selector["root"].clone()),
                    "selector-position-chain" => ("chain", selector["position"]["chain"].clone()),
                    _ => ("cut_chain", selector["cut_chain"].clone()),
                };
                let mut changed = old.clone();
                changed[0] = serde_json::json!(changed[0].as_u64().unwrap() ^ 1);
                rewrite_basis_scalar(&path, field, old, changed);
            }
            "selector-extent" => rewrite_basis_scalar(
                &path,
                "basis_bytes",
                selector["basis_bytes"].clone(),
                serde_json::json!(selector["basis_bytes"].as_u64().unwrap() + 1),
            ),
            "selector-offset" => rewrite_basis_scalar(
                &path,
                "offset",
                selector["position"]["offset"].clone(),
                serde_json::json!(selector["position"]["offset"].as_u64().unwrap() - 1),
            ),
            "selected-basis" | "retained-prefix" | "suffix-body" | "suffix-cut" => {
                let (target, offset) = match damage {
                    "selected-basis" => (basis.clone(), 20),
                    "retained-prefix" => (anchor.clone(), 80 + 100),
                    "suffix-body" => (
                        anchor.clone(),
                        selector["position"]["offset"].as_u64().unwrap() as usize + 100,
                    ),
                    _ => (suffix.clone(), 351),
                };
                let mut bytes = std::fs::read(&target).unwrap();
                bytes[offset] ^= 1;
                std::fs::write(target, bytes).unwrap();
            }
            "missing-selected-basis" => std::fs::remove_file(&basis).unwrap(),
            "missing-anchor-segment" => std::fs::remove_file(&anchor).unwrap(),
            "missing-suffix-cut" => std::fs::remove_file(&suffix).unwrap(),
            "extra-future-basis" => {
                std::fs::copy(&basis, path.join("basis-00000000000000000003.sqlite")).unwrap();
            }
            "wrong-stage-epoch" => std::fs::write(
                path.join("basis-00000000000000000001.preparing"),
                b"foreign epoch",
            )
            .unwrap(),
            "noncanonical-name" => {
                std::fs::write(path.join("segment-0.wal"), b"foreign name").unwrap()
            }
            "oversized-selector-stage" => {
                std::fs::write(path.join("CURRENT.preparing"), vec![0; 8193]).unwrap()
            }
            "nonregular-file" => {
                std::os::unix::fs::symlink(&basis, path.join("foreign-link")).unwrap()
            }
            _ => unreachable!(),
        }
        preserved_rejection(&path, fixture.wal.binding(), Limits::default());
        eprintln!(
            "SEQUENTIAL_WAL_BASIS_CASE {}",
            serde_json::json!({"case":"selected_authority_damage", "damage":damage, "rejected_without_cleanup_or_mutation":true})
        );
    }
}

#[test]
fn moving_basis_recovers_partial_staging_and_unordered_directory_persistence() {
    for length in [0, 1, 31] {
        let fixture = Fixture::new(
            Limits::default(),
            fail_at(Point::AfterBasisCreate),
            None,
            true,
        );
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        let prior = files(&fixture.path());
        assert!(fixture.wal.checkpoint().is_err());
        assert!(fixture.wal.shutdown().is_err());
        std::fs::write(
            fixture.path().join("basis-00000000000000000001.preparing"),
            vec![0x73; length],
        )
        .unwrap();
        std::fs::write(fixture.path().join("CURRENT.preparing"), vec![0x31; length]).unwrap();
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert_eq!(files(&fixture.path()), prior);
        assert!(reopened.read(1, 2).unwrap() == vec![batch(1)]);
        reopened
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        reopened.checkpoint().unwrap();
        reopened.shutdown().unwrap();
        let final_open = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert!(final_open.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
        final_open.shutdown().unwrap();
        eprintln!(
            "SEQUENTIAL_WAL_BASIS_CASE {}",
            serde_json::json!({"case":"partial_unselected_staging", "bytes":length, "prior_authority_exact":true, "successor_reopened":true})
        );
    }

    // A selector rename not followed by directory durability can recover as
    // its old name after power loss. Its old acknowledged suffix is intact.
    let fixture = fixture();
    fixture
        .wal
        .submit(append(&[batch(1)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.checkpoint().unwrap();
    fixture.wal.shutdown().unwrap();
    let writer = fixture
        .reopen(Limits::default(), fail_at(Point::AfterBasisSelectorRename))
        .unwrap();
    writer.submit(append(&[batch(2)])).unwrap().wait().unwrap();
    let prior = files(&fixture.path());
    let old_selector = std::fs::read(fixture.path().join("CURRENT")).unwrap();
    assert!(writer.checkpoint().is_err());
    assert!(writer.shutdown().is_err());
    std::fs::write(fixture.path().join("CURRENT"), old_selector).unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert_eq!(files(&fixture.path()), prior);
    assert!(reopened.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
    assert_eq!(reopened.checkpoint().unwrap(), 2);
    reopened.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_BASIS_CASE {}",
        serde_json::json!({"case":"selector_rename_not_persisted", "prior_basis_and_acknowledged_suffix_exact":true, "same_epoch_retry_selected":true})
    );

    // Reclamation can lose any subset of unlink operations across power loss.
    // Every restored old name remains strictly inside the selected coverage.
    let limits = Limits {
        outstanding_bytes: 1024,
        group_count: 4,
        group_bytes: 512,
        segment_bytes: 1024,
        history_count: 16,
        history_bytes: 16384,
        segments: 8,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, fail_at(Point::BeforeBasisReclaimSync), None, false);
    for index in 1..=12 {
        fixture
            .wal
            .submit(append(&[blank(index)]))
            .unwrap()
            .wait()
            .unwrap();
    }
    let prior: BTreeMap<String, Vec<u8>> = std::fs::read_dir(fixture.path())
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    assert!(fixture.wal.checkpoint().is_err());
    assert!(fixture.wal.shutdown().is_err());
    let selected = basis_selector(&fixture.path());
    let anchor_name = format!(
        "segment-{:020}.wal",
        selected["position"]["segment"].as_u64().unwrap()
    );
    let mut restored = 0;
    for (index, (name, bytes)) in prior
        .iter()
        .filter(|(name, _)| {
            (name.starts_with("segment-") && *name != &anchor_name) || name.starts_with("cut-")
        })
        .enumerate()
    {
        if index % 2 == 0 {
            std::fs::write(fixture.path().join(name), bytes).unwrap();
            restored += 1;
        }
    }
    assert!(restored >= 3);
    let before_retry = files(&fixture.path());
    assert!(fixture
        .reopen(limits, fail_at(Point::BeforeRecoveryPublicationSync))
        .is_err());
    assert_eq!(files(&fixture.path()), before_retry);
    // Repeat an interrupted cleanup after all remaining old names are gone.
    assert!(fixture
        .reopen(limits, fail_at(Point::BeforeBasisReclaimSync))
        .is_err());
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let control = IoControl {
        hook: Arc::new(move |point| {
            if matches!(
                point,
                Point::BeforeRecoveryPublicationSync | Point::AfterRecoveryPublicationSync
            ) {
                observed.lock().unwrap().push(point);
            }
            Ok(())
        }),
        ..IoControl::default()
    };
    let reopened = fixture.reopen(limits, control).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            Point::BeforeRecoveryPublicationSync,
            Point::AfterRecoveryPublicationSync
        ]
    );
    assert!(reopened.read(1, 13).unwrap() == (1..=12).map(blank).collect::<Vec<_>>());
    assert_eq!(
        files(&fixture.path())
            .keys()
            .filter(|name| name.starts_with("segment-"))
            .count(),
        1
    );
    assert!(files(&fixture.path())
        .keys()
        .all(|name| !name.starts_with("cut-")));
    assert_eq!(
        reopened
            .submit(append(&[blank(13)]))
            .unwrap()
            .wait()
            .unwrap(),
        13
    );
    reopened.checkpoint().unwrap();
    reopened.shutdown().unwrap();
    let final_open = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(final_open.read(1, 14).unwrap() == (1..=13).map(blank).collect::<Vec<_>>());
    final_open.shutdown().unwrap();
    eprintln!(
        "SEQUENTIAL_WAL_BASIS_CASE {}",
        serde_json::json!({"case":"unordered_retired_unlinks", "restored_retired_names":restored, "repeated_handoff_sync_before_use":true, "only_selected_coverage_reclaimed":true, "successor_reopened":true})
    );
}

#[test]
fn real_v2_singletons_votes_and_committed_reopen_exactly() {
    let fixture = fixture();
    let entry = batch(1);
    assert_eq!(
        fixture
            .wal
            .submit(append(std::slice::from_ref(&entry)))
            .unwrap()
            .wait()
            .unwrap(),
        1
    );
    let vote = Vote::new(2, node_id());
    assert_eq!(
        fixture
            .wal
            .submit(Operation::Vote(vote))
            .unwrap()
            .wait()
            .unwrap(),
        2
    );
    assert_eq!(
        fixture
            .wal
            .submit(Operation::Committed(Some(entry.log_id)))
            .unwrap()
            .wait()
            .unwrap(),
        3
    );
    fixture.wal.shutdown().unwrap();
    let observations = fixture.wal.observations().unwrap();
    assert_eq!(
        observations.len(),
        3,
        "idle singletons do not wait for a fill batch"
    );
    for (index, observation) in observations.iter().enumerate() {
        assert_eq!(observation.first, index as u64 + 1);
        assert_eq!(observation.last, observation.first);
        assert!(observation.bytes > 100);
        assert_eq!(observation.queue_wait.len(), 1);
        assert_eq!(observation.admission.len(), 1);
        assert_eq!(observation.submit_to_callback.len(), 1);
        let admission = &observation.admission[0];
        assert!(admission.total >= admission.encode + admission.lock_wait + admission.projection);
        assert!(observation.submit_to_callback[0] >= admission.total + observation.queue_wait[0]);
        assert_eq!(observation.rollover, Duration::ZERO);
        assert_eq!(
            observation.sync_calls, 5,
            "intent file/directory, data, cut file/directory are distinct syncs"
        );
        assert!(
            observation.write
                + observation.intent
                + observation.data_sync
                + observation.publication
                + observation.callback_delay
                > Duration::ZERO
        );
    }
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![entry.clone()]);
    assert_eq!(reopened.vote().unwrap(), Some(vote));
    assert_eq!(reopened.committed().unwrap(), Some(entry.log_id));
    assert!(reopened
        .submit(Operation::Vote(Vote::new(1, node_id())))
        .is_err());
    reopened.shutdown().unwrap();
}

#[test]
fn frozen_basis_retains_acknowledged_unapplied_and_uncommitted_suffixes() {
    let directory = tempfile::tempdir().unwrap();
    let source = SqliteSessionBackend::open(directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    initialize_schema(&conn, identity(), &expected_members()).unwrap();
    let membership = membership_entry();
    append_logs_sync(&conn, identity(), std::slice::from_ref(&membership)).unwrap();
    save_committed_sync(&conn, identity(), Some(membership.log_id)).unwrap();
    apply_entries_sync(&conn, identity(), &source.caps, vec![membership]).unwrap();
    let entries = vec![blank(1), blank(2)];
    append_logs_sync(&conn, identity(), &entries).unwrap();
    save_committed_sync(&conn, identity(), Some(entries[0].log_id)).unwrap();
    let path = directory.path().join("wal");
    let wal = Wal::create(
        &path,
        &conn,
        identity(),
        [0xC7; 32],
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    let binding = wal.binding();
    assert_eq!(
        encode_json(&wal.read(1, 3).unwrap()).unwrap(),
        encode_json(&entries).unwrap()
    );
    assert_eq!(wal.committed().unwrap(), Some(entries[0].log_id));
    wal.shutdown().unwrap();
    let reopened = Wal::open(&path, binding, Limits::default(), IoControl::default()).unwrap();
    assert_eq!(
        encode_json(&reopened.read(1, 3).unwrap()).unwrap(),
        encode_json(&entries).unwrap()
    );
    assert_eq!(reopened.committed().unwrap(), Some(entries[0].log_id));
    assert_eq!(
        read_applied_sync(&conn, identity()).unwrap().unwrap().index,
        0
    );
    reopened.shutdown().unwrap();
}

#[test]
fn concurrent_pending_reads_and_ordered_group_admission_are_bounded() {
    let pause = Pause::new(Point::BeforeGroup);
    let limits = Limits {
        outstanding: 4,
        group_count: 4,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, pause.control(), Some(Arc::clone(&pause)), true);
    pause.entered();
    let first = batch(1);
    let second = batch(2);
    let (read_now, reader) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let wal = &fixture.wal;
        let expected = vec![first.clone(), second.clone()];
        let read = scope.spawn(move || {
            reader.recv().unwrap();
            assert!(wal.read(1, 3).unwrap() == expected);
        });
        let tickets = [
            fixture
                .wal
                .submit(append(std::slice::from_ref(&first)))
                .unwrap(),
            fixture
                .wal
                .submit(Operation::Vote(Vote::new(2, node_id())))
                .unwrap(),
            fixture
                .wal
                .submit(Operation::Committed(Some(first.log_id)))
                .unwrap(),
            fixture
                .wal
                .submit(append(std::slice::from_ref(&second)))
                .unwrap(),
        ];
        for ticket in &tickets {
            assert!(matches!(ticket.try_recv(), Err(mpsc::TryRecvError::Empty)));
        }
        assert!(
            matches!(fixture.wal.submit(Operation::Vote(Vote::new(3, node_id()))), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        read_now.send(()).unwrap();
        read.join().unwrap();
        pause.release();
        for (index, ticket) in tickets.into_iter().enumerate() {
            assert_eq!(ticket.wait().unwrap(), index as u64 + 1);
        }
    });
    fixture.wal.shutdown().unwrap();
    let observations = fixture.wal.observations().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(
        (
            observations[0].first,
            observations[0].last,
            observations[0].queue_wait.len()
        ),
        (1, 4, 4)
    );
    assert_eq!(observations[0].sync_calls, 5);
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(reopened.read(1, 3).unwrap() == vec![first, second]);
    assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
    assert_eq!(reopened.committed().unwrap(), Some(log_id(1)));
    reopened.shutdown().unwrap();
}

#[test]
fn no_success_before_each_data_and_publication_boundary() {
    for point in [
        Point::BeforeIntent,
        Point::AfterIntentCreate,
        Point::BeforeIntentSync,
        Point::AfterIntentSync,
        Point::AfterIntentRename,
        Point::AfterIntentPublish,
        Point::BeforeWrite,
        Point::BeforeDataSync,
        Point::AfterDataSync,
        Point::BeforeCutPublish,
        Point::AfterCutRename,
        Point::AfterCutPublish,
    ] {
        let pause = Pause::new(point);
        let fixture = Fixture::new(
            Limits::default(),
            pause.control(),
            Some(Arc::clone(&pause)),
            true,
        );
        let entry = batch(1);
        let ticket = fixture
            .wal
            .submit(append(std::slice::from_ref(&entry)))
            .unwrap();
        pause.entered();
        assert!(fixture.wal.read(1, 2).unwrap() == vec![entry]);
        assert!(
            matches!(ticket.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "no callback at {point:?}"
        );
        pause.release();
        assert_eq!(ticket.wait().unwrap(), 1);
        fixture.wal.shutdown().unwrap();
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert_eq!(reopened.read(1, 2).unwrap().len(), 1);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn cancelled_reply_and_shutdown_retain_owned_durable_write() {
    let pause = Pause::new(Point::AfterCutPublish);
    let fixture = Fixture::new(
        Limits::default(),
        pause.control(),
        Some(Arc::clone(&pause)),
        true,
    );
    let entry = batch(1);
    let ticket = fixture
        .wal
        .submit(append(std::slice::from_ref(&entry)))
        .unwrap();
    pause.entered();
    drop(ticket);
    std::thread::scope(|scope| {
        let shutdown = scope.spawn(|| fixture.wal.shutdown());
        pause.release();
        shutdown.join().unwrap().unwrap();
    });
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![entry]);
    // Lost acknowledgement does not license a replacement at the same index.
    assert!(reopened.submit(append(&[batch(1)])).is_err());
    assert_eq!(
        reopened
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap(),
        2
    );
    reopened.shutdown().unwrap();
}

#[test]
fn real_short_writes_are_completed_before_acknowledgement() {
    let fixture = Fixture::new(
        Limits::default(),
        IoControl {
            write_chunk: 127,
            ..IoControl::default()
        },
        None,
        true,
    );
    let entry = batch(1);
    fixture
        .wal
        .submit(append(std::slice::from_ref(&entry)))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![entry]);
    reopened.shutdown().unwrap();
}

#[test]
fn partial_enospc_fences_inflight_and_queued_completions() {
    let fixture = fixture();
    fixture
        .wal
        .submit(append(&[batch(1)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let before = files(&fixture.path());
    let pause = Pause::new(Point::BeforeWrite);
    let control = IoControl {
        fail_after_bytes: Some(21),
        write_chunk: 7,
        ..pause.control()
    };
    let wal = fixture.reopen(Limits::default(), control).unwrap();
    let append_ticket = wal.submit(append(&[batch(2)])).unwrap();
    pause.entered();
    let vote = wal
        .submit(Operation::Vote(Vote::new(2, node_id())))
        .unwrap();
    pause.release();
    assert!(append_ticket.wait().is_err());
    assert!(vote.wait().is_err());
    assert!(
        wal.read(1, 3).is_err(),
        "pending visibility is fenced before failure replies"
    );
    assert!(wal.submit(Operation::Committed(Some(log_id(1)))).is_err());
    assert!(wal.shutdown().is_err());
    let reopened = reopen_repaired_prefix(&fixture, Limits::default(), &before);
    assert!(reopened.read(1, 3).unwrap() == vec![batch(1)]);
    assert_eq!(reopened.vote().unwrap(), None);
    assert_eq!(
        reopened
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap(),
        2
    );
    reopened.shutdown().unwrap();
}

#[test]
fn write_zero_preserves_the_previously_acknowledged_cut() {
    let fixture = fixture();
    fixture
        .wal
        .submit(append(&[batch(1)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let before = files(&fixture.path());
    let wal = fixture
        .reopen(
            Limits::default(),
            IoControl {
                write_chunk: 0,
                ..IoControl::default()
            },
        )
        .unwrap();
    assert!(wal.submit(append(&[batch(2)])).unwrap().wait().is_err());
    assert!(wal.shutdown().is_err());
    assert_eq!(
        std::fs::metadata(fixture.path().join("cut-00000000000000000002.preparing"))
            .unwrap()
            .len(),
        0
    );
    let reopened = reopen_repaired_prefix(&fixture, Limits::default(), &before);
    assert!(reopened.read(1, 3).unwrap() == vec![batch(1)]);
    reopened.shutdown().unwrap();
}

#[test]
fn interrupted_intent_sync_and_cut_publication_restore_exact_prefix_or_published_reply_loss() {
    for point in [
        Point::BeforeIntent,
        Point::AfterIntentCreate,
        Point::BeforeIntentSync,
        Point::AfterIntentSync,
        Point::AfterIntentRename,
        Point::AfterIntentPublish,
        Point::BeforeWrite,
        Point::BeforeDataSync,
        Point::AfterDataSync,
        Point::BeforeCutPublish,
        Point::AfterCutRename,
        Point::AfterCutPublish,
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let before = files(&fixture.path());
        let control = IoControl {
            hook: Arc::new(move |actual| {
                if actual == point {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let wal = fixture.reopen(Limits::default(), control).unwrap();
        assert!(wal.submit(append(&[batch(2)])).unwrap().wait().is_err());
        assert!(wal.shutdown().is_err());
        if matches!(point, Point::AfterCutRename | Point::AfterCutPublish) {
            let reopened = fixture
                .reopen(Limits::default(), IoControl::default())
                .unwrap();
            assert!(reopened.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
            reopened.shutdown().unwrap();
        } else {
            let reopened = reopen_repaired_prefix(&fixture, Limits::default(), &before);
            assert!(reopened.read(1, 3).unwrap() == vec![batch(1)]);
            assert_eq!(
                reopened
                    .submit(append(&[batch(2)]))
                    .unwrap()
                    .wait()
                    .unwrap(),
                2
            );
            reopened.shutdown().unwrap();
        }
        eprintln!(
            "SDK741_WAL_RECOVERY {}",
            serde_json::json!({
                "case":"writer_boundary", "point":format!("{point:?}"),
                "callback_failed":true,
                "published_reply_loss_adopted":matches!(point, Point::AfterCutRename | Point::AfterCutPublish),
                "acknowledged_prefix_preserved":true,
            })
        );
    }
}

#[test]
fn partial_intent_and_final_cut_writes_repair_before_accepting_a_successor() {
    for (intent_failure, written) in [
        (true, 0),
        (true, 1),
        (true, 191),
        (false, 0),
        (false, 1),
        (false, 159),
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let before = files(&fixture.path());
        let control = IoControl {
            write_chunk: 7,
            intent_fail_after_bytes: intent_failure.then_some(written),
            cut_fail_after_bytes: (!intent_failure).then_some(written),
            ..IoControl::default()
        };
        let wal = fixture.reopen(Limits::default(), control).unwrap();
        assert!(wal.submit(append(&[batch(2)])).unwrap().wait().is_err());
        assert!(wal.read(1, 3).is_err());
        assert!(wal.submit(Operation::Barrier).is_err());
        assert!(wal.shutdown().is_err());
        let suffix = if intent_failure {
            "preparing"
        } else {
            "pending"
        };
        let stage = fixture
            .path()
            .join(format!("cut-00000000000000000002.{suffix}"));
        assert_eq!(
            std::fs::metadata(stage).unwrap().len(),
            (written + if intent_failure { 0 } else { 192 }) as u64
        );
        assert!(!fixture.path().join("cut-00000000000000000002.cut").exists());
        let reopened = reopen_repaired_prefix(&fixture, Limits::default(), &before);
        assert!(reopened.read(1, 3).unwrap() == vec![batch(1)]);
        assert_eq!(
            reopened
                .submit(append(&[batch(2)]))
                .unwrap()
                .wait()
                .unwrap(),
            2
        );
        reopened.shutdown().unwrap();
        let final_open = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert!(final_open.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
        final_open.shutdown().unwrap();
        eprintln!(
            "SDK741_WAL_RECOVERY {}",
            serde_json::json!({
                "case":"partial_publication_write", "stage":suffix, "written":written,
                "callback_failed_and_owner_fenced":true, "exact_prefix_restored":true,
                "successor_acknowledged_and_reopened":true,
            })
        );
    }
}

#[test]
fn recovery_stabilizes_surviving_cut_rename_before_returning_a_usable_owner() {
    for fault in [
        Point::BeforeRecoveryPublicationSync,
        Point::AfterRecoveryPublicationSync,
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let wal = fixture
            .reopen(Limits::default(), fail_at(Point::AfterCutRename))
            .unwrap();
        assert!(wal.submit(append(&[batch(2)])).unwrap().wait().is_err());
        assert!(wal.shutdown().is_err());
        assert!(fixture.path().join("cut-00000000000000000002.cut").exists());
        assert!(!fixture
            .path()
            .join("cut-00000000000000000002.pending")
            .exists());
        let before = files(&fixture.path());
        assert!(
            fixture.reopen(Limits::default(), fail_at(fault)).is_err(),
            "a failed recovery publication sync cannot hand out a usable owner"
        );
        assert_eq!(files(&fixture.path()), before);
        let boundaries = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&boundaries);
        let reopened = fixture
            .reopen(
                Limits::default(),
                IoControl {
                    hook: Arc::new(move |point| {
                        if matches!(
                            point,
                            Point::BeforeRecoveryPublicationSync
                                | Point::AfterRecoveryPublicationSync
                        ) {
                            observed.lock().unwrap().push(point);
                        }
                        Ok(())
                    }),
                    ..IoControl::default()
                },
            )
            .unwrap();
        assert_eq!(
            *boundaries.lock().unwrap(),
            vec![
                Point::BeforeRecoveryPublicationSync,
                Point::AfterRecoveryPublicationSync,
            ],
            "namespace sync completes before recovery returns"
        );
        assert_eq!(files(&fixture.path()), before);
        assert!(reopened.read(1, 3).unwrap() == vec![batch(1), batch(2)]);
        assert!(reopened.submit(append(&[batch(2)])).is_err());
        assert_eq!(
            reopened
                .submit(append(&[batch(3)]))
                .unwrap()
                .wait()
                .unwrap(),
            3
        );
        reopened.shutdown().unwrap();
        let final_open = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert!(final_open.read(1, 4).unwrap() == vec![batch(1), batch(2), batch(3)]);
        final_open.shutdown().unwrap();
        eprintln!(
            "SDK741_WAL_RECOVERY {}",
            serde_json::json!({
                "case":"recovery_publication_sync", "point":format!("{fault:?}"),
                "failed_sync_returned_no_owner":true, "successful_retry_synced_before_return":true,
                "published_reply_loss_adopted":true, "successor_acknowledged_and_reopened":true,
            })
        );
    }
}

#[test]
fn interrupted_tail_repair_repeats_data_sync_before_retiring_intent() {
    for fault in [
        Point::BeforeTailRepair,
        Point::BeforeTailDataSync,
        Point::AfterTailTruncate,
        Point::AfterTailSegmentRemove,
        Point::BeforeTailDirectorySync,
        Point::BeforePendingRemove,
        Point::AfterPendingUnlink,
        Point::AfterPendingRemove,
    ] {
        let vote_bytes = 100
            + Operation::Vote(Vote::new(2, node_id()))
                .encode()
                .unwrap()
                .to_vec()
                .len();
        assert_eq!(
            vote_bytes,
            100 + Operation::Vote(Vote::new(3, node_id()))
                .encode()
                .unwrap()
                .to_vec()
                .len()
        );
        let limits = Limits {
            group_count: 2,
            group_bytes: 101 + 100 + append(&[blank(1)]).encode().unwrap().to_vec().len(),
            segment_bytes: 80 + 2 * vote_bytes + 101,
            ..Limits::default()
        };
        let fixture = Fixture::new(limits, IoControl::default(), None, true);
        for term in [2, 3] {
            fixture
                .wal
                .submit(Operation::Vote(Vote::new(term, node_id())))
                .unwrap()
                .wait()
                .unwrap();
        }
        fixture.wal.shutdown().unwrap();
        let before = files(&fixture.path());
        let acknowledged: BTreeMap<_, _> = before
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    std::fs::read(fixture.path().join(name)).unwrap(),
                )
            })
            .collect();
        let last_path = fixture.path().join("segment-00000000000000000000.wal");
        let acknowledged_len = std::fs::metadata(&last_path).unwrap().len();
        assert_eq!(acknowledged_len + 101, limits.segment_bytes as u64);
        let pause = Pause::new(Point::BeforeGroup);
        let paused = pause.control();
        let failure = fail_at(Point::BeforeCutPublish);
        let control = IoControl {
            hook: Arc::new(move |point| {
                (paused.hook)(point)?;
                (failure.hook)(point)
            }),
            ..IoControl::default()
        };
        let wal = fixture.reopen(limits, control).unwrap();
        pause.entered();
        let barrier = wal.submit(Operation::Barrier).unwrap();
        let append_ticket = wal.submit(append(&[blank(1)])).unwrap();
        pause.release();
        assert!(barrier.wait().is_err());
        assert!(append_ticket.wait().is_err());
        assert!(wal.shutdown().is_err());
        let pending = fixture.path().join("cut-00000000000000000003.pending");
        assert!(pending.exists());
        assert!(std::fs::metadata(&last_path).unwrap().len() > acknowledged_len);
        assert!(fixture
            .path()
            .join("segment-00000000000000000001.wal")
            .exists());

        assert!(fixture.reopen(limits, fail_at(fault)).is_err());
        for (name, bytes) in &acknowledged {
            let actual = std::fs::read(fixture.path().join(name)).unwrap();
            if name.starts_with("segment-") {
                assert!(
                    actual.starts_with(bytes),
                    "repair cannot change acknowledged bytes at {fault:?}"
                );
            } else {
                assert_eq!(
                    actual, *bytes,
                    "repair cannot change an acknowledged publication"
                );
            }
        }
        let intent_remains =
            !matches!(fault, Point::AfterPendingUnlink | Point::AfterPendingRemove);
        assert_eq!(pending.exists(), intent_remains);
        if fault != Point::BeforeTailRepair {
            assert_eq!(
                std::fs::metadata(&last_path).unwrap().len(),
                acknowledged_len
            );
        }
        let sync_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&sync_attempts);
        let reopened = fixture
            .reopen(
                limits,
                IoControl {
                    hook: Arc::new(move |point| {
                        if point == Point::BeforeTailDataSync {
                            observed.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(())
                    }),
                    ..IoControl::default()
                },
            )
            .unwrap();
        assert_eq!(
            sync_attempts.load(Ordering::SeqCst),
            usize::from(intent_remains),
            "a retained intent repeats data sync even when the prior set_len is already visible"
        );
        assert_eq!(files(&fixture.path()), before);
        assert_eq!(reopened.vote().unwrap(), Some(Vote::new(3, node_id())));
        assert!(reopened.read(1, 2).unwrap().is_empty());
        assert_eq!(
            reopened
                .submit(append(&[blank(1)]))
                .unwrap()
                .wait()
                .unwrap(),
            3
        );
        reopened.shutdown().unwrap();
        let final_open = fixture.reopen(limits, IoControl::default()).unwrap();
        assert!(final_open.read(1, 2).unwrap() == vec![blank(1)]);
        assert_eq!(final_open.vote().unwrap(), Some(Vote::new(3, node_id())));
        final_open.shutdown().unwrap();
        eprintln!(
            "SDK741_WAL_RECOVERY {}",
            serde_json::json!({
                "case":"interrupted_repair", "point":format!("{fault:?}"),
                "intent_retained_until_tail_syncs":intent_remains,
                "retry_data_syncs":sync_attempts.load(Ordering::SeqCst),
                "exact_prefix_restored":true, "successor_acknowledged_and_reopened":true,
            })
        );
    }
}

#[test]
fn unpublished_rename_and_unordered_tail_unlinks_recover_only_the_proven_suffix() {
    let fixture = fixture();
    fixture
        .wal
        .submit(append(&[batch(1)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let before = files(&fixture.path());
    let wal = fixture
        .reopen(Limits::default(), fail_at(Point::AfterCutRename))
        .unwrap();
    assert!(wal.submit(append(&[batch(2)])).unwrap().wait().is_err());
    assert!(wal.shutdown().is_err());
    // Model the rename's pre-sync crash outcome: the durable prior pending
    // name survives, with no success callback ever issued.
    std::fs::rename(
        fixture.path().join("cut-00000000000000000002.cut"),
        fixture.path().join("cut-00000000000000000002.pending"),
    )
    .unwrap();
    let reopened = reopen_repaired_prefix(&fixture, Limits::default(), &before);
    assert!(reopened.read(1, 3).unwrap() == vec![batch(1)]);
    assert_eq!(
        reopened
            .submit(append(&[batch(2)]))
            .unwrap()
            .wait()
            .unwrap(),
        2
    );
    reopened.shutdown().unwrap();

    let fixture = Fixture::new(small_limits(), IoControl::default(), None, true);
    fixture
        .wal
        .submit(Operation::Vote(Vote::new(2, node_id())))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let before = files(&fixture.path());
    let wal = fixture
        .reopen(small_limits(), fail_at(Point::BeforeCutPublish))
        .unwrap();
    assert!(wal
        .submit(append(&(1..=64).map(blank).collect::<Vec<_>>()))
        .unwrap()
        .wait()
        .is_err());
    assert!(wal.shutdown().is_err());
    let tail_names: Vec<_> = files(&fixture.path())
        .into_keys()
        .filter(|name| name.starts_with("segment-") && !before.contains_key(name))
        .collect();
    assert!(tail_names.len() > 2);
    let last = tail_names.last().unwrap();
    let last_bytes = std::fs::read(fixture.path().join(last)).unwrap();
    assert!(fixture
        .reopen(small_limits(), fail_at(Point::BeforeTailDirectorySync))
        .is_err());
    assert!(tail_names
        .iter()
        .all(|name| !fixture.path().join(name).exists()));
    assert!(fixture
        .path()
        .join("cut-00000000000000000002.pending")
        .exists());
    // Before directory fsync, only some descending unlinks may be durable.
    // Restore the highest file to model that outcome, leaving suffix holes.
    std::fs::write(fixture.path().join(last), last_bytes).unwrap();
    let reopened = reopen_repaired_prefix(&fixture, small_limits(), &before);
    assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
    assert!(reopened.read(1, 65).unwrap().is_empty());
    assert_eq!(
        reopened
            .submit(append(&(1..=64).map(blank).collect::<Vec<_>>()))
            .unwrap()
            .wait()
            .unwrap(),
        2
    );
    reopened.shutdown().unwrap();
    let final_open = fixture
        .reopen(small_limits(), IoControl::default())
        .unwrap();
    assert!(final_open.read(1, 65).unwrap() == (1..=64).map(blank).collect::<Vec<_>>());
    final_open.shutdown().unwrap();
    eprintln!(
        "SDK741_WAL_RECOVERY {}",
        serde_json::json!({
            "case":"directory_persistence_outcomes", "cut_rename_not_persisted_repaired":true,
            "unacknowledged_suffix_holes_repaired":true, "tail_segments":tail_names.len(),
            "acknowledged_prefix_preserved":true, "whole_successor_reopened":true,
        })
    );
}

#[test]
fn pending_intent_cannot_hide_acknowledged_damage_or_claim_another_extent() {
    use sha2::{Digest, Sha256};
    for mutation in [
        "acknowledged-body",
        "acknowledged-cut",
        "missing-highest-cut",
        "missing-earlier-cut",
        "missing-acknowledged-segment",
        "missing-intent",
        "intent-checksum",
        "intent-binding",
        "intent-start-sequence",
        "intent-start-offset",
        "intent-predecessor",
        "intent-ordinal",
        "truncated-intent",
        "oversized-pending",
        "undercharged-intent",
        "preparing-with-tail",
        "two-stages",
        "unplanned-empty-segment",
        "impossible-plan",
        "excess-tail-byte",
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Vote(Vote::new(2, node_id())))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let wal = fixture
            .reopen(Limits::default(), fail_at(Point::BeforeCutPublish))
            .unwrap();
        assert!(wal.submit(append(&[batch(2)])).unwrap().wait().is_err());
        assert!(wal.shutdown().is_err());
        let pending = fixture.path().join("cut-00000000000000000003.pending");
        let segment = fixture.path().join("segment-00000000000000000000.wal");
        let original_intent = std::fs::read(&pending).unwrap();
        assert_eq!(original_intent.len(), 192 + 160);
        let rewrite_intent = |offset: usize, replacement: &[u8]| {
            let mut bytes = std::fs::read(&pending).unwrap();
            bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
            let checksum = Sha256::digest(&bytes[..160]);
            bytes[160..192].copy_from_slice(&checksum);
            std::fs::write(&pending, bytes).unwrap();
        };
        match mutation {
            "acknowledged-body" => {
                let mut bytes = std::fs::read(&segment).unwrap();
                bytes[180] ^= 1;
                std::fs::write(&segment, bytes).unwrap();
            }
            "acknowledged-cut" => {
                let path = fixture.path().join("cut-00000000000000000002.cut");
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[192 + 128] ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
            "missing-highest-cut" => {
                std::fs::remove_file(fixture.path().join("cut-00000000000000000002.cut")).unwrap()
            }
            "missing-earlier-cut" => {
                std::fs::remove_file(fixture.path().join("cut-00000000000000000001.cut")).unwrap()
            }
            "missing-acknowledged-segment" => std::fs::remove_file(&segment).unwrap(),
            "missing-intent" => std::fs::remove_file(&pending).unwrap(),
            "intent-checksum" => {
                let mut bytes = original_intent.clone();
                bytes[160] ^= 1;
                std::fs::write(&pending, bytes).unwrap();
            }
            "intent-binding" => rewrite_intent(96, &[original_intent[96] ^ 1]),
            "intent-start-sequence" => rewrite_intent(24, &1_u64.to_le_bytes()),
            "intent-start-offset" => {
                let offset = u64::from_le_bytes(original_intent[16..24].try_into().unwrap());
                rewrite_intent(16, &(offset - 1).to_le_bytes());
            }
            "intent-predecessor" => rewrite_intent(64, &[original_intent[64] ^ 1]),
            "intent-ordinal" => std::fs::rename(
                &pending,
                fixture.path().join("cut-00000000000000000004.pending"),
            )
            .unwrap(),
            "truncated-intent" => std::fs::write(&pending, &original_intent[..191]).unwrap(),
            "oversized-pending" => {
                let mut bytes = original_intent.clone();
                bytes.push(0);
                std::fs::write(&pending, bytes).unwrap();
            }
            "undercharged-intent" => {
                let offset = u64::from_le_bytes(original_intent[16..24].try_into().unwrap());
                rewrite_intent(136, &101_u64.to_le_bytes());
                rewrite_intent(152, &(offset + 101).to_le_bytes());
            }
            "preparing-with-tail" => {
                std::fs::write(&pending, &original_intent[..192]).unwrap();
                std::fs::rename(
                    &pending,
                    fixture.path().join("cut-00000000000000000003.preparing"),
                )
                .unwrap();
            }
            "two-stages" => std::fs::write(
                fixture.path().join("cut-00000000000000000003.preparing"),
                &original_intent[..192],
            )
            .unwrap(),
            "unplanned-empty-segment" => {
                std::fs::write(fixture.path().join("segment-00000000000000000001.wal"), []).unwrap()
            }
            "impossible-plan" => {
                rewrite_intent(144, &1_u64.to_le_bytes());
                rewrite_intent(152, &181_u64.to_le_bytes());
            }
            "excess-tail-byte" => {
                let mut bytes = std::fs::read(&segment).unwrap();
                bytes.push(0);
                std::fs::write(&segment, bytes).unwrap();
            }
            _ => unreachable!(),
        }
        preserved_rejection(&fixture.path(), fixture.wal.binding(), Limits::default());
        eprintln!(
            "SDK741_WAL_RECOVERY {}",
            serde_json::json!({
                "case":"intent_cannot_authorize_damage", "mutation":mutation,
                "rejected_without_file_mutation":true,
            })
        );
    }
}

#[test]
fn valid_pending_intent_rejects_foreign_suffix_headers_and_acknowledged_segment_holes() {
    for mutation in [
        "foreign-header",
        "foreign-partial-header",
        "empty-middle-tail",
        "acknowledged-gap",
    ] {
        let fixture = Fixture::new(small_limits(), IoControl::default(), None, true);
        for index in 1..=8 {
            fixture
                .wal
                .submit(append(&[blank(index)]))
                .unwrap()
                .wait()
                .unwrap();
        }
        fixture.wal.shutdown().unwrap();
        let before = files(&fixture.path());
        let wal = fixture
            .reopen(small_limits(), fail_at(Point::BeforeCutPublish))
            .unwrap();
        assert!(wal
            .submit(append(&(9..=72).map(blank).collect::<Vec<_>>()))
            .unwrap()
            .wait()
            .is_err());
        assert!(wal.shutdown().is_err());
        let tail: Vec<_> = files(&fixture.path())
            .into_keys()
            .filter(|name| name.starts_with("segment-") && !before.contains_key(name))
            .collect();
        assert!(tail.len() > 2);
        match mutation {
            "foreign-header" => {
                let path = fixture.path().join(tail.last().unwrap());
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[16] ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
            "foreign-partial-header" => {
                std::fs::write(fixture.path().join(tail.last().unwrap()), b"FOREIGN").unwrap()
            }
            "empty-middle-tail" => std::fs::write(fixture.path().join(&tail[0]), []).unwrap(),
            "acknowledged-gap" => {
                std::fs::remove_file(fixture.path().join("segment-00000000000000000001.wal"))
                    .unwrap()
            }
            _ => unreachable!(),
        }
        preserved_rejection(&fixture.path(), fixture.wal.binding(), small_limits());
        eprintln!(
            "SDK741_WAL_RECOVERY {}",
            serde_json::json!({
                "case":"intent_namespace_and_acknowledged_contiguity", "mutation":mutation,
                "rejected_without_file_mutation":true,
            })
        );
    }
}

#[test]
fn writer_panic_fails_every_owned_completion_and_joins() {
    let pause = Pause::new(Point::BeforeWrite);
    let pause_control = pause.control();
    let control = IoControl {
        hook: Arc::new(move |point| {
            (pause_control.hook)(point)?;
            assert_ne!(
                point,
                Point::BeforeDataSync,
                "intentional private WAL writer panic"
            );
            Ok(())
        }),
        ..IoControl::default()
    };
    let fixture = Fixture::new(Limits::default(), control, Some(Arc::clone(&pause)), true);
    let before = files(&fixture.path());
    let first = fixture.wal.submit(append(&[batch(1)])).unwrap();
    pause.entered();
    let second = fixture
        .wal
        .submit(Operation::Vote(Vote::new(2, node_id())))
        .unwrap();
    pause.release();
    assert!(first.wait().is_err());
    assert!(second.wait().is_err());
    assert!(fixture.wal.read(1, 2).is_err());
    assert!(fixture.wal.shutdown().is_err());
    let reopened = reopen_repaired_prefix(&fixture, Limits::default(), &before);
    assert!(reopened.read(1, 2).unwrap().is_empty());
    assert_eq!(
        reopened
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap(),
        1
    );
    reopened.shutdown().unwrap();
}

fn small_limits() -> Limits {
    Limits {
        group_bytes: 512,
        segment_bytes: 592,
        group_count: 2,
        ..Limits::default()
    }
}

#[test]
fn segment_rollover_reopens_and_continues_the_exact_chain() {
    let fixture = Fixture::new(small_limits(), IoControl::default(), None, true);
    for index in 1..=8 {
        fixture
            .wal
            .submit(append(&[blank(index)]))
            .unwrap()
            .wait()
            .unwrap();
    }
    fixture.wal.shutdown().unwrap();
    let names = files(&fixture.path());
    assert!(
        names
            .keys()
            .filter(|name| name.starts_with("segment-"))
            .count()
            >= 2
    );
    assert!(fixture
        .wal
        .observations()
        .unwrap()
        .iter()
        .any(|observation| observation.sync_calls == 7));
    let reopened = fixture
        .reopen(small_limits(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 9).unwrap() == (1..=8).map(blank).collect::<Vec<_>>());
    assert_eq!(
        reopened
            .submit(append(&[blank(9)]))
            .unwrap()
            .wait()
            .unwrap(),
        9
    );
    reopened.shutdown().unwrap();
}

#[test]
fn maximum_64_entry_append_streams_one_operation_across_segments() {
    let pause = Pause::new(Point::AfterFragment);
    let fixture = Fixture::new(
        Limits::default(),
        pause.control(),
        Some(Arc::clone(&pause)),
        true,
    );
    let entries = (1..=64)
        .map(|index| {
            // Legacy entries retain their original JSON compatibility, including
            // whitespace. These are 64 distinct, fully decoded maximum-size rows.
            let mut bytes = encode_json(&blank(index)).unwrap();
            bytes.resize(SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES, b' ');
            bytes.into()
        })
        .collect();
    let ticket = fixture.wal.submit(Operation::Append(entries)).unwrap();
    pause.entered();
    assert!(matches!(ticket.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(matches!(fixture.wal.submit(Operation::Barrier),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(!fixture.path().join("cut-00000000000000000001.cut").exists());
    assert!(fixture.wal.read(1, 65).unwrap() == (1..=64).map(blank).collect::<Vec<_>>());
    pause.release();
    assert_eq!(ticket.wait().unwrap(), 1);
    fixture.wal.shutdown().unwrap();
    let observations = fixture.wal.observations().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!((observations[0].first, observations[0].last), (1, 1));
    let logical_bytes = 5 + 64 * (4 + SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES);
    let fragments = logical_bytes.div_ceil(1024 * 1024);
    assert_eq!(observations[0].bytes, logical_bytes + fragments * 100);
    let segments: Vec<_> = std::fs::read_dir(fixture.path())
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("segment-"))
        .collect();
    assert!(segments.len() > 1);
    assert!(segments
        .iter()
        .all(|entry| entry.metadata().unwrap().len() <= 32 * 1024 * 1024));
    assert_eq!(observations[0].sync_calls, 5 + (segments.len() - 1) * 3);
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 65).unwrap() == (1..=64).map(blank).collect::<Vec<_>>());
    assert_eq!(
        reopened
            .submit(Operation::Vote(Vote::new(2, node_id())))
            .unwrap()
            .wait()
            .unwrap(),
        2
    );
    reopened.shutdown().unwrap();
    eprintln!(
        "SDK741_WAL_CAPACITY {}",
        serde_json::json!({
            "case": "maximum_append", "entries":64, "entry_bytes":SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
            "logical_bytes":logical_bytes, "fragments":fragments, "segments":segments.len(),
            "operation_completions":1, "reopened_entries":64,
        })
    );
}

#[test]
fn actual_adapter_typed_v2_append_exceeds_old_aggregate_frame_cap() {
    use opc_consensus::engine::storage::RaftLogStorageExt;
    let fixture = fixture();
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(
        fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap(),
    );
    let entry = fenced_transition_v2_batch_entry(
        1,
        (0..256)
            .map(|slot| sdk741_component_request(Sdk741Payload::Create, 1, slot, None))
            .collect(),
        timestamp(1),
    );
    let entry_bytes = encode_json(&entry).unwrap().len();
    assert!(entry_bytes <= SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES);
    assert!(64 * entry_bytes > 16 * 1024 * 1024 + 1024);
    // Exact request replay at later LogIds is a legal original projection;
    // replay retains the ciphertext and consumes no additional receipt slots.
    let entries: Vec<_> = (1..=64)
        .map(|index| {
            let mut entry = entry.clone();
            entry.log_id = log_id(index);
            entry
        })
        .collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        WalLogStore::new(Arc::clone(&wal))
            .blocking_append(entries.clone())
            .await
            .unwrap();
    });
    wal.shutdown().unwrap();
    let observations = wal.observations().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].admission[0].entries, 64);
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 65).unwrap() == entries);
    reopened.shutdown().unwrap();
    eprintln!(
        "SDK741_WAL_CAPACITY {}",
        serde_json::json!({
            "case":"typed_v2_large_adapter_append", "entries":64, "serialized_entry_bytes":entry_bytes,
            "aggregate_entry_bytes":64 * entry_bytes, "whole_actual_callbacks":1, "exact_reopen":true,
        })
    );
}

#[test]
fn actual_adapter_64_entry_callback_is_whole_append_and_mid_fragment_cut_is_rejected() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};
    use opc_consensus::engine::RaftLogReader;
    use sha2::{Digest, Sha256};

    let pause = Pause::new(Point::AfterFragment);
    let fixture = Fixture::new(small_limits(), IoControl::default(), None, true);
    fixture.wal.shutdown().unwrap();
    let wal = Arc::new(fixture.reopen(small_limits(), pause.control()).unwrap());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        assert!(log.blocking_append((1..=65).map(blank)).await.is_err());
        assert_eq!(
            log.get_log_state().await.unwrap().last_log_id,
            Some(log_id(0))
        );
        let mut reader = log.clone();
        let appending = tokio::spawn(async move { log.blocking_append((1..=64).map(blank)).await });
        pause.entered();
        assert!(
            !appending.is_finished(),
            "one LogFlushed still owns the complete append"
        );
        assert!(
            reader.try_get_log_entries(1..65).await.unwrap()
                == (1..=64).map(blank).collect::<Vec<_>>()
        );
        assert!(!fixture.path().join("cut-00000000000000000001.cut").exists());
        pause.release();
        appending.await.unwrap().unwrap();
    });
    wal.shutdown().unwrap();
    let observations = wal.observations().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].admission[0].entries, 64);
    let reopened = fixture
        .reopen(small_limits(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 65).unwrap() == (1..=64).map(blank).collect::<Vec<_>>());
    reopened.shutdown().unwrap();

    // A checksummed cut at an intact first fragment must not acknowledge
    // part of an operation, even when its final fragment is also present.
    let segment = std::fs::read(fixture.path().join("segment-00000000000000000000.wal")).unwrap();
    let first_size = u32::from_le_bytes(segment[96..100].try_into().unwrap()) as u64;
    let cut_path = fixture.path().join("cut-00000000000000000001.cut");
    let mut publication = std::fs::read(&cut_path).unwrap();
    assert_eq!(publication.len(), 192 + 160);
    // Keep the intent's physical plan self-consistent, so the complete
    // original operation decoder, rather than an envelope mismatch, rejects.
    publication[136..144].copy_from_slice(&(100 + first_size).to_le_bytes());
    publication[144..152].copy_from_slice(&0_u64.to_le_bytes());
    publication[152..160].copy_from_slice(&(80 + 100 + first_size).to_le_bytes());
    let checksum = Sha256::digest(&publication[..160]);
    publication[160..192].copy_from_slice(&checksum);
    let cut = &mut publication[192..];
    cut[8..16].copy_from_slice(&0_u64.to_le_bytes());
    cut[16..24].copy_from_slice(&(80 + 100 + first_size).to_le_bytes());
    cut[32..64].copy_from_slice(&segment[148..180]);
    let checksum = Sha256::digest(&cut[..128]);
    cut[128..160].copy_from_slice(&checksum);
    std::fs::write(cut_path, publication).unwrap();
    preserved_rejection_containing(
        &fixture.path(),
        fixture.wal.binding(),
        small_limits(),
        "not a whole operation",
    );
    eprintln!(
        "SDK741_WAL_CAPACITY {}",
        serde_json::json!({
            "case":"actual_64_entry_callback", "callbacks":1, "early_callback":false,
            "count_65_rejected":true, "checksummed_mid_fragment_cut_rejected":true,
        })
    );
}

#[test]
fn fragment_and_rollover_faults_fail_whole_actual_callback_and_preserve_acknowledged_prefix() {
    use opc_consensus::engine::storage::RaftLogStorageExt;
    for fault in [
        Point::AfterFragment,
        Point::BeforeRollover,
        Point::AfterRollover,
    ] {
        let fixture = Fixture::new(small_limits(), IoControl::default(), None, true);
        fixture
            .wal
            .submit(Operation::Vote(Vote::new(2, node_id())))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let cut_path = fixture.path().join("cut-00000000000000000001.cut");
        let acknowledged = std::fs::read(&cut_path).unwrap();
        let before = files(&fixture.path());
        let progress = std::sync::atomic::AtomicBool::new(false);
        let control = IoControl {
            hook: Arc::new(move |actual| {
                if actual == Point::AfterFragment {
                    progress.store(true, Ordering::SeqCst);
                }
                if actual == fault && progress.load(Ordering::SeqCst) {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let wal = Arc::new(fixture.reopen(small_limits(), control).unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(WalLogStore::new(Arc::clone(&wal))
                .blocking_append((1..=64).map(blank))
                .await
                .is_err());
        });
        assert!(wal.read(1, 65).is_err());
        assert!(wal
            .submit(Operation::Vote(Vote::new(3, node_id())))
            .is_err());
        assert!(wal.shutdown().is_err());
        assert_eq!(std::fs::read(cut_path).unwrap(), acknowledged);
        assert!(!fixture.path().join("cut-00000000000000000002.cut").exists());
        let reopened = Arc::new(reopen_repaired_prefix(&fixture, small_limits(), &before));
        assert!(reopened.read(1, 65).unwrap().is_empty());
        assert_eq!(reopened.vote().unwrap(), Some(Vote::new(2, node_id())));
        runtime.block_on(async {
            WalLogStore::new(Arc::clone(&reopened))
                .blocking_append((1..=64).map(blank))
                .await
                .unwrap();
        });
        assert!(reopened.read(1, 65).unwrap() == (1..=64).map(blank).collect::<Vec<_>>());
        reopened.shutdown().unwrap();
        eprintln!(
            "SDK741_WAL_CAPACITY {}",
            serde_json::json!({
                "case":"fragment_fault", "point":format!("{fault:?}"), "callback_failed":true,
                "acknowledged_cut_unchanged":true, "proven_unacknowledged_tail_discarded":true,
                "whole_successor_callback_and_64_entries_verified":true,
            })
        );
    }
}

#[test]
fn exact_truncate_and_covered_purge_are_ordered_and_durable() {
    let fixture = fixture();
    fixture
        .wal
        .submit(append(&[blank(1), blank(2)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    assert!(fixture.wal.submit(Operation::Truncate(log_id(1))).is_err());
    let wrong = LogId::new(CommittedLeaderId::new(2, node_id()), 2);
    assert!(fixture.wal.submit(Operation::Truncate(wrong)).is_err());
    fixture
        .wal
        .submit(Operation::Truncate(log_id(2)))
        .unwrap()
        .wait()
        .unwrap();
    let replacement = Entry {
        log_id: wrong,
        payload: EntryPayload::Blank,
    };
    fixture
        .wal
        .submit(append(std::slice::from_ref(&replacement)))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(wrong)))
        .unwrap()
        .wait()
        .unwrap();
    assert!(
        fixture.wal.submit(Operation::Purge(log_id(1))).is_err(),
        "state machine has only applied the frozen base"
    );
    fixture
        .wal
        .submit(Operation::Purge(log_id(0)))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 3).unwrap() == vec![blank(1), replacement]);
    assert_eq!(reopened.committed().unwrap(), Some(wrong));
    reopened.shutdown().unwrap();
}

#[test]
fn full_v2_schema_activation_authority_and_hole_checks_reject_before_admission() {
    let fixture = fixture();
    let bytes = encode_json(&batch(1)).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for tampered in [
        text.replacen('{', "{\"ignored\":0,", 1),
        text.replacen("\"index\":1", "\"index\":1,\"index\":1", 1),
    ] {
        assert!(fixture
            .wal
            .submit(Operation::Append(vec![tampered.into_bytes().into()]))
            .is_err());
    }
    assert!(fixture.wal.submit(append(&[batch(2)])).is_err());
    let mut wrong_identity = batch(1);
    let EntryPayload::Normal(command) = &mut wrong_identity.payload else {
        panic!("normal fixture");
    };
    command.identity = SessionConsensusIdentity::new(
        identity().cluster_id(),
        crate::consensus::SessionConsensusConfigurationId::from_bytes([0x52; 32]),
        identity().configuration_epoch(),
    );
    assert!(fixture.wal.submit(append(&[wrong_identity])).is_err());
    assert!(fixture.wal.read(1, 2).unwrap().is_empty());
    assert_eq!(
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap(),
        1,
        "failed validation has no admission identity or side effect"
    );
    fixture.wal.shutdown().unwrap();
    let inactive = Fixture::new(Limits::default(), IoControl::default(), None, false);
    assert!(
        inactive.wal.submit(append(&[batch(1)])).is_err(),
        "syntactically valid V2 still requires complete projected activation"
    );
    inactive.wal.shutdown().unwrap();
}

#[test]
fn revoked_authority_body_conflict_and_exact_replay_match_committed_semantics() {
    let fixture = fixture();
    let request = sdk741_component_request(Sdk741Payload::Create, 3, 0, None);
    let revoked = fenced_transition_v2_authorized_entry(
        1,
        request.clone(),
        timestamp(1),
        SessionConsensusNodeId::new(9).unwrap(),
        identity(),
    );
    let altered = fenced_transition_v2_authorized_entry(
        2,
        altered_fenced_transition_v2_request(&request),
        timestamp(2),
        node_id(),
        identity(),
    );
    let fresh = fenced_transition_v2_authorized_entry(
        3,
        request.clone(),
        timestamp(3),
        node_id(),
        identity(),
    );
    let replay = fenced_transition_v2_authorized_entry(
        4,
        request.clone(),
        timestamp(4),
        node_id(),
        identity(),
    );
    let later_altered = fenced_transition_v2_authorized_entry(
        5,
        altered_fenced_transition_v2_request(&request),
        timestamp(5),
        node_id(),
        identity(),
    );
    let entries = vec![revoked, altered, fresh, replay, later_altered];
    fixture
        .wal
        .submit(append(&entries))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(5))))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    let recovered = reopened.read(1, 6).unwrap();
    assert!(recovered == entries);
    let reference =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = reference.conn.blocking_lock();
    // Compare the recovered rows with the existing real state-machine path.
    // Application authority is checked at apply; these well-formed no-effect
    // outcomes must remain legal Raft entries at admission and recovery.
    append_logs_sync(&conn, identity(), &recovered).unwrap();
    save_committed_sync(&conn, identity(), Some(log_id(5))).unwrap();
    let applied = apply_entries_sync(&conn, identity(), &reference.caps, recovered).unwrap();
    assert!(matches!(
        applied.responses[0].result,
        Err(StoreError::TopologyAuthorityRevoked)
    ));
    assert!(matches!(
        applied.responses[1].result,
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    assert!(applied.responses[2].result.is_ok());
    assert!(applied.responses[3].result.is_ok());
    assert!(matches!(
        applied.responses[4].result,
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    assert_eq!(applied.responses[2].sequence, applied.responses[3].sequence);
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
    let receipts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        receipts, 1,
        "revocation/conflicts/replay cannot bind a second effect"
    );
    reopened.shutdown().unwrap();
}

#[test]
fn actual_openraft_adapter_callback_waits_for_publication_with_pending_reads() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};
    use opc_consensus::engine::RaftLogReader;

    let mut fixture = fixture();
    fixture.wal.shutdown().unwrap();
    let pause = Pause::new(Point::BeforeCutPublish);
    fixture.pause = Some(Arc::clone(&pause));
    let wal = Arc::new(fixture.reopen(Limits::default(), pause.control()).unwrap());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        let mut reader = log.get_log_reader().await;
        let appending = tokio::spawn(async move { log.blocking_append([batch(1)]).await });
        pause.entered();
        assert!(
            !appending.is_finished(),
            "the actual LogFlushed callback is still owned by the writer"
        );
        assert!(reader.try_get_log_entries(1..=1).await.unwrap() == vec![batch(1)]);
        assert!(reader.limited_get_log_entries(1, 2).await.unwrap() == vec![batch(1)]);
        assert!(reader.limited_get_log_entries(2, 3).await.is_err());
        assert!(reader.try_get_log_entries(..=u64::MAX).await.is_err());
        pause.release();
        appending.await.unwrap().unwrap();
        reader.save_committed(Some(log_id(1))).await.unwrap();
        reader
            .save_vote(&Vote::new_committed(2, node_id()))
            .await
            .unwrap();
        assert_eq!(
            reader.get_log_state().await.unwrap().last_log_id,
            Some(log_id(1))
        );
        assert_eq!(reader.read_committed().await.unwrap(), Some(log_id(1)));
        assert_eq!(
            reader.read_vote().await.unwrap(),
            Some(Vote::new_committed(2, node_id()))
        );
    });
    wal.shutdown().unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![batch(1)]);
    assert_eq!(reopened.committed().unwrap(), Some(log_id(1)));
    assert_eq!(
        reopened.vote().unwrap(),
        Some(Vote::new_committed(2, node_id()))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn actual_openraft_cancelled_append_keeps_callback_and_ordered_vote_with_writer() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};

    let mut fixture = fixture();
    fixture.wal.shutdown().unwrap();
    let pause = Pause::new(Point::BeforeDataSync);
    fixture.pause = Some(Arc::clone(&pause));
    let wal = Arc::new(fixture.reopen(Limits::default(), pause.control()).unwrap());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        let mut later = log.clone();
        let appending = tokio::spawn(async move { log.blocking_append([batch(1)]).await });
        pause.entered();
        appending.abort();
        assert!(appending.await.unwrap_err().is_cancelled());
        let voting =
            tokio::spawn(async move { later.save_vote(&Vote::new_committed(2, node_id())).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while wal.vote().unwrap().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !voting.is_finished(),
            "a later metadata request cannot pass the unflushed append"
        );
        pause.release();
        voting.await.unwrap().unwrap();
    });
    wal.shutdown().unwrap();
    let observations = wal.observations().unwrap();
    assert_eq!(
        observations
            .iter()
            .map(|entry| entry.last - entry.first + 1)
            .sum::<u64>(),
        2
    );
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![batch(1)]);
    assert_eq!(
        reopened.vote().unwrap(),
        Some(Vote::new_committed(2, node_id()))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn application_cannot_use_pending_commit_or_fabricated_entry() {
    let mut fixture = fixture();
    fixture
        .wal
        .submit(append(&[batch(1)]))
        .unwrap()
        .wait()
        .unwrap();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    assert!(fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .is_err());
    assert_eq!(
        read_applied_sync(&conn, identity()).unwrap(),
        Some(log_id(0))
    );
    fixture.wal.shutdown().unwrap();
    let pause = Pause::new(Point::BeforeCutPublish);
    fixture.pause = Some(Arc::clone(&pause));
    let wal = fixture.reopen(Limits::default(), pause.control()).unwrap();
    let committing = wal.submit(Operation::Committed(Some(log_id(1)))).unwrap();
    pause.entered();
    assert_eq!(
        wal.committed().unwrap(),
        Some(log_id(1)),
        "pending reader sees accepted commit"
    );
    assert!(
        wal.apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .is_err(),
        "pending committed pointer cannot authorize business effects"
    );
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 0);
    assert_eq!(
        last_log_sync(&conn, identity()).unwrap(),
        Some(log_id(0)),
        "SQL cache did not receive a pre-quorum append"
    );
    pause.release();
    committing.wait().unwrap();
    assert!(
        wal.apply_committed(&conn, &source.caps, vec![blank(1)], ApplyControl::Normal)
            .is_err(),
        "same LogId with another payload cannot apply"
    );
    let applied = wal
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    assert!(applied.responses[0].result.is_ok());
    assert_eq!(
        read_applied_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
    wal.shutdown().unwrap();
}

#[test]
fn application_prefix_advances_with_pending_suffix_and_reopens_exactly() {
    let fixture = fixture();
    fixture
        .wal
        .submit(append(&[batch(1), batch(2)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    let first = fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    assert!(first.responses[0].result.is_ok());
    assert!(fixture.wal.read(2, 3).unwrap() == vec![batch(2)]);
    assert_eq!(last_log_sync(&conn, identity()).unwrap(), Some(log_id(1)));
    assert!(fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .is_err());
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    let second = fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .unwrap();
    assert!(second.responses[0].result.is_ok());
    let machine = proposal_state_sync(&conn, identity()).unwrap();
    assert_eq!(machine.0, 2);
    fixture.wal.shutdown().unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    reopened.restore_application(&conn, &source.caps).unwrap();
    reopened.restore_application(&conn, &source.caps).unwrap();
    assert_eq!(
        proposal_state_sync(&conn, identity()).unwrap(),
        machine,
        "recovery must not execute SQL effects twice"
    );
    assert!(
        reopened.submit(Operation::Purge(log_id(2))).is_err(),
        "moving checkpoint is required before purge crosses frozen basis"
    );
    reopened
        .submit(append(&[batch(3)]))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .submit(Operation::Committed(Some(log_id(3))))
        .unwrap()
        .wait()
        .unwrap();
    assert!(reopened
        .apply_committed(&conn, &source.caps, vec![batch(3)], ApplyControl::Normal)
        .unwrap()
        .responses[0]
        .result
        .is_ok());
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 3);
    reopened.shutdown().unwrap();
}

#[test]
fn application_prefix_audits_only_the_extension_and_reaudits_on_restore() {
    let mut audit_counts = Vec::new();
    for history in [8_u64, 128] {
        let fixture = fixture();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        let retained = (1..=history).map(blank).collect::<Vec<_>>();
        for entries in retained.chunks(64) {
            fixture.wal.submit(append(entries)).unwrap().wait().unwrap();
            fixture
                .wal
                .submit(Operation::Committed(Some(entries.last().unwrap().log_id)))
                .unwrap()
                .wait()
                .unwrap();
            fixture
                .wal
                .apply_committed(&conn, &source.caps, entries.to_vec(), ApplyControl::Normal)
                .unwrap();
        }
        // Log history is independent of the fixture's wall-clock seconds.
        let entry = fenced_transition_v2_batch_entry(
            history + 1,
            (0..8)
                .map(|slot| {
                    sdk741_component_request(Sdk741Payload::Create, history + 1, slot, None)
                })
                .collect(),
            timestamp(1),
        );
        fixture
            .wal
            .submit(append(std::slice::from_ref(&entry)))
            .unwrap()
            .wait()
            .unwrap();
        for operation in [
            Operation::Vote(Vote::new_committed(2, node_id())),
            Operation::Barrier,
            Operation::Committed(Some(entry.log_id)),
        ] {
            fixture.wal.submit(operation).unwrap().wait().unwrap();
        }
        reset_committed_log_validation_decoded_rows_for_test();
        let applied = fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![entry], ApplyControl::Normal)
            .unwrap();
        let incremental_rows = committed_log_validation_decoded_rows_for_test();
        assert!(applied.responses[0].result.is_ok());
        assert_eq!(
            incremental_rows, 2,
            "one new row in the WAL proof and one in the original SQL commit proof"
        );
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(history + 1))
        );
        reset_committed_log_validation_decoded_rows_for_test();
        fixture
            .wal
            .restore_application(&conn, &source.caps)
            .unwrap();
        let restored_rows = committed_log_validation_decoded_rows_for_test();
        assert_eq!(
            restored_rows,
            2 * (history as usize + 2),
            "even reattachment audits every retained row in both images"
        );
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
        println!("sequential_wal_prefix_cost retained_history={history} incremental_audit_rows={incremental_rows} restore_audit_rows={restored_rows}");
        audit_counts.push(incremental_rows);
        fixture.wal.shutdown().unwrap();
    }
    assert_eq!(audit_counts[0], audit_counts[1]);
}

#[test]
fn application_prefix_reaudits_after_truncate_and_rejected_projection() {
    for boundary in ["truncate", "purge_rejected", "append_rejected"] {
        let fixture = fixture();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        let retained = (1..=8).map(blank).collect::<Vec<_>>();
        fixture
            .wal
            .submit(append(&retained))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(8))))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, retained, ApplyControl::Normal)
            .unwrap();
        match boundary {
            "truncate" => {
                fixture
                    .wal
                    .submit(append(&[blank(9)]))
                    .unwrap()
                    .wait()
                    .unwrap();
                reset_committed_log_validation_decoded_rows_for_test();
                fixture
                    .wal
                    .submit(Operation::Truncate(log_id(9)))
                    .unwrap()
                    .wait()
                    .unwrap();
                assert_eq!(
                    committed_log_validation_decoded_rows_for_test(),
                    28,
                    "truncate keeps the full committed, applied and retained-boundary audits"
                );
            }
            "purge_rejected" => assert!(fixture.wal.submit(Operation::Purge(log_id(8))).is_err()),
            "append_rejected" => assert!(fixture.wal.submit(append(&[blank(8)])).is_err()),
            _ => unreachable!(),
        }
        for index in [9, 10] {
            fixture
                .wal
                .submit(append(&[blank(index)]))
                .unwrap()
                .wait()
                .unwrap();
            fixture
                .wal
                .submit(Operation::Committed(Some(log_id(index))))
                .unwrap()
                .wait()
                .unwrap();
            reset_committed_log_validation_decoded_rows_for_test();
            fixture
                .wal
                .apply_committed(
                    &conn,
                    &source.caps,
                    vec![blank(index)],
                    ApplyControl::Normal,
                )
                .unwrap();
            let audited = committed_log_validation_decoded_rows_for_test();
            assert_eq!(
                audited,
                if index == 9 { 11 } else { 2 },
                "the first apply after {boundary} establishes a full proof before reuse"
            );
            println!("sequential_wal_prefix_boundary boundary={boundary} applied={index} audit_rows={audited}");
        }
        fixture.wal.shutdown().unwrap();
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        reopened.restore_application(&conn, &source.caps).unwrap();
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(10))
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn application_prefix_lineage_corruption_fences_before_effects_and_callback() {
    for (damage, first_use) in [
        ("payload", "apply"),
        ("payload", "admit"),
        ("payload", "read"),
        ("applied", "apply"),
        ("purged_marker", "apply"),
        ("schema", "apply"),
        ("rolled_back_write", "apply"),
    ] {
        let mut fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1), batch(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        let before = proposal_state_sync(&conn, identity()).unwrap();
        fixture.wal.shutdown().unwrap();
        let pause = Pause::new(Point::BeforeCutPublish);
        fixture.pause = Some(Arc::clone(&pause));
        let wal = fixture.reopen(Limits::default(), pause.control()).unwrap();
        wal.restore_application(&conn, &source.caps).unwrap();
        let waiting = wal
            .submit(Operation::Vote(Vote::new_committed(3, node_id())))
            .unwrap();
        pause.entered();
        wal.corrupt_projection_for_test(|pending| match damage {
            "payload" => {
                assert_eq!(
                    pending
                        .execute(
                            "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                            params![encode_json(&blank(1)).unwrap()],
                        )
                        .unwrap(),
                    1
                );
            }
            "applied" => set_test_log_pointer(pending, "consensus_applied", &log_id(0)),
            "purged_marker" => set_test_purge_floor(pending, &log_id(1)),
            "schema" => pending
                .execute_batch("CREATE TABLE foreign_prefix_schema (value INTEGER)")
                .unwrap(),
            "rolled_back_write" => {
                let tx = pending.unchecked_transaction().unwrap();
                assert_eq!(
                    tx.execute("DELETE FROM consensus_log WHERE log_index = 1", [])
                        .unwrap(),
                    1
                );
                tx.rollback().unwrap();
            }
            _ => unreachable!(),
        });
        let rejected = match first_use {
            "apply" => wal
                .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
                .is_err(),
            "admit" => wal.submit(Operation::Barrier).is_err(),
            "read" => wal.with_application_read(&conn, || 42).is_err(),
            _ => unreachable!(),
        };
        assert!(
            rejected,
            "{first_use} cannot inherit a prefix audit after {damage}"
        );
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap(), before);
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(1))
        );
        assert!(wal.vote().is_err());
        assert!(wal.submit(Operation::Barrier).is_err());
        pause.release();
        assert!(
            waiting.wait().is_err(),
            "{damage} fences the waiting durability owner"
        );
        assert!(wal.shutdown().is_err());
        println!("sequential_wal_prefix_corruption damage={damage} first_use={first_use} rejected_and_fenced=true");
    }
}

#[test]
fn application_sqlite_commit_faults_preserve_atomic_effect_and_exact_restart() {
    for fault in [
        ApplyControl::BeforeSqliteCommit,
        ApplyControl::AfterSqliteCommit,
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        assert!(fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], fault)
            .is_err());
        assert!(
            fixture.wal.read(1, 2).is_err(),
            "ambiguous application fences pending reads"
        );
        assert!(
            fixture.wal.submit(append(&[blank(2)])).is_err(),
            "ambiguous application fences new writer ownership"
        );
        assert!(fixture.wal.shutdown().is_err());
        let expected = u64::from(fault == ApplyControl::AfterSqliteCommit);
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, expected);
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(expected))
        );
        assert_eq!(
            read_committed_sync(&conn, identity()).unwrap(),
            Some(log_id(expected))
        );
        assert_eq!(
            last_log_sync(&conn, identity()).unwrap(),
            Some(log_id(expected))
        );
        let markers: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'consensus_wal_application')", [], |row| row.get(0)).unwrap();
        assert_eq!(
            markers,
            fault == ApplyControl::AfterSqliteCommit,
            "marker and effects share one SQLite commit"
        );
        drop(conn);
        drop(source);
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        reopened.restore_application(&conn, &source.caps).unwrap();
        if fault == ApplyControl::BeforeSqliteCommit {
            reopened
                .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
                .unwrap();
        }
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
        let mut replay = batch(1);
        replay.log_id = log_id(2);
        reopened
            .submit(append(std::slice::from_ref(&replay)))
            .unwrap()
            .wait()
            .unwrap();
        reopened
            .submit(Operation::Committed(Some(log_id(2))))
            .unwrap()
            .wait()
            .unwrap();
        let replayed = reopened
            .apply_committed(&conn, &source.caps, vec![replay], ApplyControl::Normal)
            .unwrap();
        assert!(replayed.responses[0].result.is_ok());
        assert_eq!(
            proposal_state_sync(&conn, identity()).unwrap().0,
            1,
            "exact request replay cannot repeat the committed effect"
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn application_over_64_entries_keeps_one_atomic_transaction_and_response_boundary() {
    for fault in [
        ApplyControl::Normal,
        ApplyControl::BeforeSqliteCommit,
        ApplyControl::AfterSqliteCommit,
    ] {
        let fixture = fixture();
        let mut entries: Vec<_> = (1..=130).map(blank).collect();
        for index in [1, 129] {
            entries[index - 1] = fenced_transition_v2_batch_entry(
                index as u64,
                (0..8)
                    .map(|slot| {
                        sdk741_component_request(Sdk741Payload::Create, index as u64, slot, None)
                    })
                    .collect(),
                timestamp(1),
            );
        }
        for chunk in entries.chunks(64) {
            fixture.wal.submit(append(chunk)).unwrap().wait().unwrap();
        }
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(130))))
            .unwrap()
            .wait()
            .unwrap();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        let mut wrong = entries.clone();
        wrong[128] = blank(129);
        assert!(fixture
            .wal
            .apply_committed(&conn, &source.caps, wrong, ApplyControl::Normal)
            .is_err());
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(0))
        );
        assert_eq!(last_log_sync(&conn, identity()).unwrap(), Some(log_id(0)));
        let result = fixture
            .wal
            .apply_committed(&conn, &source.caps, entries.clone(), fault);
        if fault == ApplyControl::Normal {
            let applied = result.unwrap();
            assert_eq!(applied.responses.len(), entries.len());
            assert!(applied.responses[0].result.is_ok());
            assert!(applied.responses[128].result.is_ok());
            fixture.wal.shutdown().unwrap();
        } else {
            assert!(result.is_err());
            assert!(fixture.wal.shutdown().is_err());
        }
        let committed = fault != ApplyControl::BeforeSqliteCommit;
        let expected = if committed { 130 } else { 0 };
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(expected))
        );
        assert_eq!(
            read_committed_sync(&conn, identity()).unwrap(),
            Some(log_id(expected))
        );
        assert_eq!(
            last_log_sync(&conn, identity()).unwrap(),
            Some(log_id(expected))
        );
        assert_eq!(
            proposal_state_sync(&conn, identity()).unwrap().0,
            if committed { 2 } else { 0 }
        );
        let receipts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM consensus_fenced_transition_v2_receipts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipts, if committed { 16 } else { 0 });
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        reopened.restore_application(&conn, &source.caps).unwrap();
        if !committed {
            let applied = reopened
                .apply_committed(&conn, &source.caps, entries, ApplyControl::Normal)
                .unwrap();
            assert_eq!(applied.responses.len(), 130);
        }
        assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 2);
        assert_eq!(
            read_applied_sync(&conn, identity()).unwrap(),
            Some(log_id(130))
        );
        reopened.shutdown().unwrap();
        eprintln!(
            "SDK741_WAL_CAPACITY {}",
            serde_json::json!({
                "case":"whole_apply_130", "fault":format!("{fault:?}"), "effects_before_restart":if committed {2} else {0},
                "first_and_last_business_entries_atomic":true, "restored_effects":2,
            })
        );
    }
}

#[test]
fn basis_over_32_mib_uses_anonymous_projection_and_shared_extent_guard() {
    use std::os::unix::fs::{FileExt, MetadataExt};

    fn anonymous_projection_files(
        bytes: u64,
        page_size: u64,
        identity_page: u64,
        token: &[u8],
    ) -> BTreeSet<(u64, u64)> {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let target = std::fs::read_link(&path).ok()?;
                let target = target.to_string_lossy();
                if !target.contains("etilqs_") || !target.ends_with(" (deleted)") {
                    return None;
                }
                // Keep no duplicate descriptor alive across the owner's drop. Match
                // this basis's unique page content, even with other tests spilling.
                let file = std::fs::File::open(path).ok()?;
                let meta = file.metadata().ok()?;
                if meta.nlink() != 0 || meta.len() != bytes {
                    return None;
                }
                let mut header = [0; 18];
                file.read_exact_at(&mut header, 0).ok()?;
                if &header[..16] != b"SQLite format 3\0"
                    || u64::from(u16::from_be_bytes([header[16], header[17]])) != page_size
                {
                    return None;
                }
                let mut page = vec![0; usize::try_from(page_size).unwrap()];
                file.read_exact_at(&mut page, (identity_page - 1) * page_size)
                    .ok()?;
                page.windows(token.len())
                    .any(|bytes| bytes == token)
                    .then_some((meta.dev(), meta.ino()))
            })
            .collect()
    }

    fn open_file_identities() -> BTreeSet<(u64, u64)> {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| {
                let meta = std::fs::metadata(entry.ok()?.path()).ok()?;
                meta.is_file().then_some((meta.dev(), meta.ino()))
            })
            .collect()
    }

    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.sqlite");
    let seed = Connection::open(&source_path).unwrap();
    seed.execute_batch("PRAGMA page_size=8192; CREATE TABLE wal_capacity_basis_probe(id INTEGER PRIMARY KEY, body BLOB NOT NULL); CREATE TABLE wal_capacity_projection_identity(id INTEGER PRIMARY KEY, token BLOB NOT NULL); INSERT INTO wal_capacity_projection_identity VALUES (1, randomblob(32));").unwrap();
    seed.close().unwrap();
    let source = SqliteSessionBackend::open(&source_path).unwrap();
    let conn = source.conn.blocking_lock();
    sdk741_initialize(&conn, &source.caps);
    let token: Vec<u8> = conn
        .query_row(
            "SELECT token FROM wal_capacity_projection_identity WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(token.len(), 32);
    let identity_page: u64 = conn
        .query_row(
            "SELECT rootpage FROM sqlite_schema WHERE name='wal_capacity_projection_identity'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(identity_page > 0);
    let tx = conn.unchecked_transaction().unwrap();
    for id in 0..40 {
        tx.execute(
            "INSERT INTO wal_capacity_basis_probe VALUES (?1, zeroblob(1048576))",
            params![id],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let path = directory.path().join("wal");
    let wal = Wal::create(
        &path,
        &conn,
        identity(),
        [0xCA; 32],
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    let binding = wal.binding();
    let storage = wal.projection_storage_for_test().unwrap();
    assert!(storage.path.is_empty());
    assert_eq!(storage.cache, -8192);
    assert_eq!(storage.journal, "delete");
    assert_eq!(storage.synchronous, 0);
    assert!(storage.bytes > 32 * 1024 * 1024);
    assert_eq!(storage.page_size, 8192);
    assert_eq!(
        storage.maximum_pages,
        crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES / storage.page_size
    );
    let owned = anonymous_projection_files(storage.bytes, storage.page_size, identity_page, &token);
    assert_eq!(
        owned.len(),
        1,
        "this basis's large anonymous projection spilled to exactly one unlinked file"
    );
    wal.restore_application(&conn, &source.caps).unwrap();
    wal.submit(append(&[batch(1)])).unwrap().wait().unwrap();
    wal.submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    wal.apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    wal.shutdown().unwrap();
    drop(wal);
    assert!(
        open_file_identities().is_disjoint(&owned),
        "closing the owner releases its anonymous projection"
    );
    let reopened = Wal::open(&path, binding, Limits::default(), IoControl::default()).unwrap();
    reopened.restore_application(&conn, &source.caps).unwrap();
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
    assert!(reopened
        .projection_storage_for_test()
        .unwrap()
        .path
        .is_empty());
    reopened.shutdown().unwrap();
    eprintln!(
        "SDK741_WAL_CAPACITY {}",
        serde_json::json!({
            "case":"anonymous_large_basis", "basis_bytes":storage.bytes, "cache_target_kib":8192,
            "page_size":storage.page_size, "maximum_pages":storage.maximum_pages,
            "unlinked_spill_observed":true, "spill_bound_by_size_page_size_and_unique_page_token":true,
            "owned_file_identity_released":true, "whole_restore_and_apply_verified":true,
        })
    );
}

#[test]
fn application_recovery_rejects_marker_splice_and_business_state_loss() {
    for damage in 0..5 {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        let source =
            SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        fixture.wal.shutdown().unwrap();
        match damage {
            0 => {
                conn.execute_batch("DROP TABLE consensus_wal_application")
                    .unwrap();
            }
            1..=3 => {
                let bytes: Vec<u8> = conn
                    .query_row(
                        "SELECT marker_json FROM consensus_wal_application",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut marker: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let field = if damage == 1 { "binding" } else { "cut_chain" };
                if damage == 3 {
                    marker["cut_sequence"] = serde_json::json!(0);
                    marker["cut_chain"] = serde_json::to_value(vec![0_u8; 32]).unwrap();
                } else {
                    marker[field][0] = serde_json::json!(marker[field][0].as_u64().unwrap() ^ 1);
                }
                // Preserve the struct's canonical field order. Value's map
                // order would otherwise fail encoding before lineage checks.
                let changed = format!(
                    "{{\"binding\":{},\"cut_sequence\":{},\"cut_chain\":{},\"applied\":{}}}",
                    marker["binding"],
                    marker["cut_sequence"],
                    marker["cut_chain"],
                    serde_json::to_string(&log_id(1)).unwrap()
                )
                .into_bytes();
                conn.execute(
                    "UPDATE consensus_wal_application SET marker_json = ?1",
                    params![changed],
                )
                .unwrap();
            }
            _ => {
                assert!(
                    conn.execute("DELETE FROM consensus_fenced_transition_v2_receipts", [])
                        .unwrap()
                        > 0
                );
            }
        }
        let before = proposal_state_sync(&conn, identity()).unwrap();
        let reopened = fixture
            .reopen(Limits::default(), IoControl::default())
            .unwrap();
        assert!(
            reopened.restore_application(&conn, &source.caps).is_err(),
            "damaged application evidence {damage} must not be adopted"
        );
        assert!(reopened.read(1, 2).is_err());
        assert!(reopened.submit(append(&[blank(2)])).is_err());
        assert_eq!(
            proposal_state_sync(&conn, identity()).unwrap(),
            before,
            "failed audit cannot repair SQL by overwriting evidence"
        );
        assert!(reopened.shutdown().is_err());
    }
}

#[test]
fn application_cache_corruption_fences_empty_apply_and_inflight_callback() {
    for separate_connection in [false, true] {
        let mut fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        let source_path = fixture.directory.path().join("source.sqlite");
        let source = SqliteSessionBackend::open(&source_path).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let pause = Pause::new(Point::BeforeCutPublish);
        fixture.pause = Some(Arc::clone(&pause));
        let wal = fixture.reopen(Limits::default(), pause.control()).unwrap();
        wal.restore_application(&conn, &source.caps).unwrap();
        let vote = wal
            .submit(Operation::Vote(Vote::new_committed(3, node_id())))
            .unwrap();
        pause.entered();
        if separate_connection {
            let other = Connection::open(&source_path).unwrap();
            assert!(
                other
                    .execute("DELETE FROM consensus_fenced_transition_v2_receipts", [])
                    .unwrap()
                    > 0
            );
        } else {
            assert!(
                conn.execute("DELETE FROM consensus_fenced_transition_v2_receipts", [])
                    .unwrap()
                    > 0
            );
        }
        assert!(
            wal.apply_committed(&conn, &source.caps, vec![], ApplyControl::Normal)
                .is_err(),
            "even empty application detects an out-of-band cache writer"
        );
        assert!(wal.read(1, 2).is_err());
        assert!(wal.submit(append(&[blank(2)])).is_err());
        pause.release();
        assert!(
            vote.wait().is_err(),
            "inflight durability cannot acknowledge success after the cache fence"
        );
        assert!(wal.shutdown().is_err());
    }
}

#[test]
fn application_read_discards_racing_foreign_commit_before_durability_callback() {
    for mutate_before_read in [false, true] {
        let mut fixture = fixture();
        fixture
            .wal
            .submit(append(&[batch(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(1))))
            .unwrap()
            .wait()
            .unwrap();
        let source_path = fixture.directory.path().join("source.sqlite");
        let source = SqliteSessionBackend::open(&source_path).unwrap();
        let conn = source.conn.blocking_lock();
        fixture
            .wal
            .apply_committed(&conn, &source.caps, vec![batch(1)], ApplyControl::Normal)
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let pause = Pause::new(Point::BeforeCutPublish);
        fixture.pause = Some(Arc::clone(&pause));
        let wal = fixture.reopen(Limits::default(), pause.control()).unwrap();
        wal.restore_application(&conn, &source.caps).unwrap();
        assert_eq!(wal.with_application_read(&conn, || 7).unwrap(), 7);
        let vote = wal
            .submit(Operation::Vote(Vote::new_committed(3, node_id())))
            .unwrap();
        pause.entered();
        let foreign = Connection::open(&source_path).unwrap();
        let corrupt = || {
            assert!(
                foreign
                    .execute("DELETE FROM consensus_fenced_transition_v2_receipts", [])
                    .unwrap()
                    > 0
            );
        };
        if mutate_before_read {
            corrupt();
        }
        let entered = std::cell::Cell::new(false);
        let read = wal.with_application_read(&conn, || {
            entered.set(true);
            if !mutate_before_read {
                // The pre-read guard succeeded. A completed foreign SQL
                // transaction now races the value about to be returned.
                corrupt();
            }
            42
        });
        assert!(read.is_err(), "the stale physical result must not escape");
        assert_eq!(entered.get(), !mutate_before_read);
        assert!(wal.vote().is_err());
        pause.release();
        assert!(
            vote.wait().is_err(),
            "the read fence precedes the waiting callback"
        );
        assert!(wal.shutdown().is_err());
    }
}

#[test]
fn application_missing_frontier_fences_before_empty_apply() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    conn.execute("DELETE FROM consensus_applied", []).unwrap();
    assert!(fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![], ApplyControl::Normal)
        .is_err());
    assert!(fixture.wal.vote().is_err());
    assert!(fixture
        .wal
        .submit(Operation::Vote(Vote::new_committed(2, node_id())))
        .is_err());
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn fixed_authority_uses_complete_original_validation_in_wal_and_adapter() {
    use opc_consensus::engine::storage::{RaftLogStorage, RaftLogStorageExt};
    let directory = tempfile::tempdir().unwrap();
    let source = SqliteSessionBackend::open(directory.path().join("source.sqlite")).unwrap();
    let fixed_members = members(&[7, 8, 9]);
    let bindings = test_member_bindings(&fixed_members);
    let conn = source.conn.blocking_lock();
    initialize_schema_with_profile(
        &conn,
        identity(),
        &fixed_members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let membership = membership_entry_at(0, vec![fixed_members.clone()], fixed_members.clone());
    append_logs_with_authority_sync(
        &conn,
        identity(),
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members,
        &bindings,
        FIXED_TEST_PLACEMENT_POLICY,
        std::slice::from_ref(&membership),
    )
    .unwrap();
    save_committed_with_authority_sync(
        &conn,
        identity(),
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members,
        &bindings,
        FIXED_TEST_PLACEMENT_POLICY,
        Some(membership.log_id),
    )
    .unwrap();
    apply_entries_with_authority_sync(
        &conn,
        identity(),
        &source.caps,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members,
        &bindings,
        FIXED_TEST_PLACEMENT_POLICY,
        vec![membership],
    )
    .unwrap();
    let wal_path = directory.path().join("wal");
    let wal = Arc::new(
        Wal::create(
            &wal_path,
            &conn,
            identity(),
            [0xB5; 32],
            Limits::default(),
            IoControl::default(),
        )
        .unwrap(),
    );
    drop(conn);
    let desired = members(&[8, 9, 10]);
    let forbidden = topology_entry_at(
        1,
        0x87,
        SessionMutationIntent::Authorized {
            origin: member(7),
            authority_identity: identity(),
            mutation: Box::new(SessionMutationIntent::PrepareTopologyTransition {
                transition_id: [0x87; MEMBERSHIP_TRANSITION_ID_BYTES],
                request_digest: [0x88; 32],
                desired_identity: identity_at(2, 0x89),
                desired_bindings: test_member_bindings(&desired),
                desired_members: desired,
            }),
        },
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let request = fenced_transition_v2_request(0xB6, 1, "wal-fixed-application");
    let activation = activating_fenced_transition_v2_authorized_entry(
        1,
        request.clone(),
        timestamp(1),
        member(7),
        identity(),
        identity(),
        &fixed_members,
    );
    runtime.block_on(async {
        let mut log = WalLogStore::new(Arc::clone(&wal));
        assert!(log
            .save_vote(&Vote::new_committed(1, member(10)))
            .await
            .is_err());
        assert!(log.blocking_append([forbidden]).await.is_err());
        assert!(log.read_vote().await.unwrap().is_none());
        assert_eq!(
            log.get_log_state().await.unwrap().last_log_id,
            Some(log_id(0))
        );
        log.blocking_append([activation.clone()]).await.unwrap();
        log.save_committed(Some(log_id(1))).await.unwrap();
        log.save_vote(&Vote::new_committed(2, member(7)))
            .await
            .unwrap();
    });
    let conn = source.conn.blocking_lock();
    let applied = wal
        .apply_committed(
            &conn,
            &source.caps,
            vec![activation.clone()],
            ApplyControl::Normal,
        )
        .unwrap();
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &applied.responses[0].result else {
        panic!("fixed activation must commit a real business outcome");
    };
    assert!(outcome.matches_v2_request(&request));
    assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
    validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
    assert_eq!(proposal_state_sync(&conn, identity()).unwrap().0, 1);
    assert_eq!(
        read_applied_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
    wal.shutdown().unwrap();
    let reopened = Wal::open(
        &wal_path,
        wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    reopened.restore_application(&conn, &source.caps).unwrap();
    assert!(reopened.read(1, 2).unwrap() == vec![activation]);
    let FencedTransitionV2Status::Recorded(recorded) =
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &request).unwrap()
    else {
        panic!("fixed restart retains the exact V2 receipt");
    };
    assert!(recorded.unwrap().matches_v2_request(&request));
    assert_eq!(
        proposal_state_sync(&conn, identity()).unwrap().0,
        1,
        "fixed recovery cannot execute the business mutation twice"
    );
    assert_eq!(
        reopened.vote().unwrap(),
        Some(Vote::new_committed(2, member(7)))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn checksummed_replay_still_runs_the_full_authority_validator() {
    use sha2::{Digest, Sha256};
    let fixture = fixture();
    let entry = batch(1);
    fixture
        .wal
        .submit(append(std::slice::from_ref(&entry)))
        .unwrap()
        .wait()
        .unwrap();
    fixture.wal.shutdown().unwrap();
    let mut wrong = entry;
    let EntryPayload::Normal(command) = &mut wrong.payload else {
        panic!("normal fixture");
    };
    command.identity = SessionConsensusIdentity::new(
        identity().cluster_id(),
        crate::consensus::SessionConsensusConfigurationId::from_bytes([0x52; 32]),
        identity().configuration_epoch(),
    );
    let body = append(&[wrong]).encode().unwrap().to_vec();
    let segment_path = fixture.path().join("segment-00000000000000000000.wal");
    let mut segment = std::fs::read(&segment_path).unwrap();
    assert_eq!(segment.len(), 80 + 100 + body.len());
    segment[180..].copy_from_slice(&body);
    let mut hash = Sha256::new();
    hash.update(&segment[80..148]);
    hash.update(&body);
    let chain: [u8; 32] = hash.finalize().into();
    segment[148..180].copy_from_slice(&chain);
    std::fs::write(&segment_path, segment).unwrap();
    let cut_path = fixture.path().join("cut-00000000000000000001.cut");
    let mut publication = std::fs::read(&cut_path).unwrap();
    assert_eq!(publication.len(), 192 + 160);
    let cut = &mut publication[192..];
    cut[32..64].copy_from_slice(&chain);
    let checksum = Sha256::digest(&cut[..128]);
    cut[128..160].copy_from_slice(&checksum);
    std::fs::write(cut_path, publication).unwrap();
    preserved_rejection_containing(
        &fixture.path(),
        fixture.wal.binding(),
        Limits::default(),
        "command identity mismatch",
    );
}

#[test]
fn acknowledged_history_damage_and_unexplained_tails_are_never_silently_discarded() {
    for mutation in [
        "body",
        "partial-frame",
        "whole-frame",
        "length",
        "segment-binding",
        "missing-cut",
        "missing-highest-cut",
        "extra-tail",
        "pending-cut",
    ] {
        let fixture = fixture();
        fixture
            .wal
            .submit(append(&[blank(1)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(append(&[blank(2)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.shutdown().unwrap();
        let path = fixture.path().join("segment-00000000000000000000.wal");
        let mut bytes = std::fs::read(&path).unwrap();
        match mutation {
            "body" => bytes[180] ^= 1,
            "partial-frame" => {
                bytes.pop();
            }
            "whole-frame" => {
                let first_size = u32::from_le_bytes(bytes[96..100].try_into().unwrap()) as usize;
                bytes.truncate(80 + 100 + first_size);
            }
            "length" => bytes[96..100].copy_from_slice(&u32::MAX.to_le_bytes()),
            "segment-binding" => bytes[16] ^= 1,
            "missing-cut" => {
                std::fs::remove_file(fixture.path().join("cut-00000000000000000001.cut")).unwrap()
            }
            "missing-highest-cut" => {
                std::fs::remove_file(fixture.path().join("cut-00000000000000000002.cut")).unwrap()
            }
            "extra-tail" => bytes.extend_from_slice(b"torn-next-record"),
            "pending-cut" => std::fs::write(
                fixture.path().join("cut-00000000000000000003.pending"),
                b"partial",
            )
            .unwrap(),
            _ => unreachable!(),
        }
        std::fs::write(path, bytes).unwrap();
        preserved_rejection(&fixture.path(), fixture.wal.binding(), Limits::default());
    }
}

#[test]
fn missing_segment_wrong_generation_and_basis_damage_fail_closed() {
    let fixture = Fixture::new(small_limits(), IoControl::default(), None, true);
    for index in 1..=8 {
        fixture
            .wal
            .submit(append(&[blank(index)]))
            .unwrap()
            .wait()
            .unwrap();
    }
    fixture.wal.shutdown().unwrap();
    let mut binding = fixture.wal.binding();
    binding.generation[0] ^= 1;
    preserved_rejection(&fixture.path(), binding, small_limits());
    std::fs::remove_file(fixture.path().join("segment-00000000000000000001.wal")).unwrap();
    preserved_rejection(&fixture.path(), fixture.wal.binding(), small_limits());
    let fixture = self::fixture();
    fixture.wal.shutdown().unwrap();
    let basis = fixture.path().join("basis.sqlite");
    let mut bytes = std::fs::read(&basis).unwrap();
    bytes[100] ^= 1;
    std::fs::write(basis, bytes).unwrap();
    preserved_rejection(&fixture.path(), fixture.wal.binding(), Limits::default());
}

#[test]
fn exclusive_writer_and_retained_history_limits_survive_reopen() {
    let limits = Limits {
        history_count: 2,
        ..Limits::default()
    };
    let fixture = Fixture::new(limits, IoControl::default(), None, true);
    assert!(
        fixture.reopen(limits, IoControl::default()).is_err(),
        "second writer cannot acquire the generation"
    );
    fixture
        .wal
        .submit(append(&[blank(1)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Vote(Vote::new(2, node_id())))
        .unwrap()
        .wait()
        .unwrap();
    assert!(
        matches!(fixture.wal.submit(append(&[blank(2)])), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    fixture.wal.shutdown().unwrap();
    let reopened = fixture.reopen(limits, IoControl::default()).unwrap();
    assert!(
        matches!(reopened.submit(append(&[blank(2)])), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(reopened.read(1, 2).unwrap() == vec![blank(1)]);
    reopened.shutdown().unwrap();
}
