//! A copied descriptor cannot extend root ownership or release its successor.

use super::*;
use crate::sqlite::consensus::wal::{native::Opening, snapshot};
use crate::SessionPersistenceMode;

#[derive(Clone, Copy)]
enum Release {
    OpeningDropped,
    ValidationFailed,
    WriterStopped,
}

fn native_release(mode: SessionPersistenceMode, release: Release) {
    let fixture = Fixture::with_persistence(Limits::default(), IoControl::default(), mode);
    fixture.parity(&[formation()]);
    fixture.wal.shutdown().unwrap();
    let path = fixture.directory.path().join("wal");
    let binding = fixture.wal.binding();
    let open = || {
        Opening::new(
            &path,
            binding,
            None,
            Limits::default(),
            IoControl::default(),
        )
    };
    let opening = open().unwrap();
    let duplicate = opening.duplicate_root_lock_for_test().unwrap();
    let error = open()
        .err()
        .expect("the original owner excludes a successor");
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    match release {
        Release::OpeningDropped => drop(opening),
        Release::ValidationFailed => {
            let error = opening
                .finish(|| Err(io::Error::other("injected descriptor verification failure")))
                .err()
                .expect("verification must fail before owner exposure");
            assert_eq!(
                error.to_string(),
                "injected descriptor verification failure"
            );
        }
        Release::WriterStopped => {
            let wal = opening.finish(|| Ok(())).unwrap();
            assert_eq!(
                open().err().expect("the writer owns its root").kind(),
                io::ErrorKind::WouldBlock
            );
            wal.shutdown().unwrap();
            drop(wal);
        }
    }
    let started = std::time::Instant::now();
    let successor = open().expect("release unlocks the root while its duplicate remains open");
    assert!(started.elapsed() < Duration::from_secs(5));
    duplicate.metadata().unwrap(); // The copied descriptor still exists.
    drop(duplicate);
    assert_eq!(
        open()
            .err()
            .expect("closing an old copy cannot unlock a successor")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let second_duplicate = successor.duplicate_root_lock_for_test().unwrap();
    drop(successor);
    let reopened = open().unwrap().finish(|| Ok(())).unwrap();
    second_duplicate.metadata().unwrap();
    reopened.shutdown().unwrap();
}

#[test]
fn native_root_lock_duplicate_does_not_outlive_durable_opening() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        native_release(SessionPersistenceMode::Durable, Release::OpeningDropped);
    });
}

#[test]
fn native_root_lock_duplicate_does_not_outlive_async_opening() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        native_release(SessionPersistenceMode::Async, Release::OpeningDropped);
    });
}

#[test]
fn native_root_lock_duplicate_does_not_outlive_failed_durable_validation() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        native_release(SessionPersistenceMode::Durable, Release::ValidationFailed);
    });
}

#[test]
fn native_root_lock_duplicate_does_not_outlive_failed_async_validation() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        native_release(SessionPersistenceMode::Async, Release::ValidationFailed);
    });
}

#[test]
fn native_root_lock_duplicate_does_not_outlive_durable_writer() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        native_release(SessionPersistenceMode::Durable, Release::WriterStopped);
    });
}

#[test]
fn native_root_lock_duplicate_does_not_outlive_async_writer() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(300), || {
        native_release(SessionPersistenceMode::Async, Release::WriterStopped);
    });
}

#[test]
fn legacy_root_lock_duplicate_does_not_outlive_its_owner() {
    for release in [
        Release::OpeningDropped,
        Release::ValidationFailed,
        Release::WriterStopped,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let backend = SqliteSessionBackend::open(directory.path().join("source.sqlite")).unwrap();
        let conn = backend.conn.blocking_lock();
        initialize_schema(&conn, identity(), &expected_members()).unwrap();
        let membership = membership_entry();
        append_logs_sync(&conn, identity(), std::slice::from_ref(&membership)).unwrap();
        save_committed_sync(&conn, identity(), Some(membership.log_id)).unwrap();
        apply_entries_sync(&conn, identity(), &backend.caps, vec![membership]).unwrap();
        let path = directory.path().join("wal");
        let wal = Wal::create(
            &path,
            &conn,
            identity(),
            [0xD6; 32],
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        let binding = wal.binding();
        wal.shutdown().unwrap();
        drop(wal);
        let open =
            || snapshot::Opening::new(&path, binding, Limits::default(), IoControl::default());
        let opening = open().unwrap();
        let duplicate = opening.duplicate_root_lock_for_test().unwrap();
        assert_eq!(
            open().err().expect("original root remains locked").kind(),
            io::ErrorKind::WouldBlock
        );
        match release {
            Release::OpeningDropped => drop(opening),
            Release::ValidationFailed => {
                let error = opening
                    .finish(&conn, &backend.caps, || {
                        Err(io::Error::other("injected descriptor verification failure"))
                    })
                    .err()
                    .expect("validation fails before owner exposure");
                assert_eq!(
                    error.to_string(),
                    "injected descriptor verification failure"
                );
            }
            Release::WriterStopped => {
                let wal = opening.finish(&conn, &backend.caps, || Ok(())).unwrap();
                wal.shutdown().unwrap();
                drop(wal);
            }
        }
        let successor = open().expect("the copied descriptor cannot extend root ownership");
        duplicate.metadata().unwrap();
        drop(duplicate);
        assert_eq!(
            open().err().expect("successor remains locked").kind(),
            io::ErrorKind::WouldBlock
        );
        let second_duplicate = successor.duplicate_root_lock_for_test().unwrap();
        drop(successor);
        let reopened = Wal::open(&path, binding, Limits::default(), IoControl::default()).unwrap();
        second_duplicate.metadata().unwrap();
        reopened.shutdown().unwrap();
    }
}
