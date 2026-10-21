//! Process loss at native purge and selected-snapshot persistence boundaries.

use super::*;
use crate::consensus::snapshot::{
    PinnedSqliteFile, SNAPSHOT_ENVELOPE_FOOTER_BYTES, SNAPSHOT_MAX_BYTES,
};
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::{native::Opening, snapshot::InstallSource, Binding, Point};
use crate::{SessionPersistenceMode, SnapshotIntegrityPolicy};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Mutex,
};

const CHILD: &str = "OPC_NATIVE_PURGE_CRASH_CASE";
const REPORT: &str = "OPC_NATIVE_PURGE_CRASH_REPORT";
const TEST: &str = "sqlite::consensus::tests::native::purge_crash::native_purge_crash_boundaries_recover_complete_context_twice";

#[derive(Clone, Copy, Debug)]
enum Phase {
    PurgeCut,
    PurgeCheckpoint,
    Snapshot,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    mode: SessionPersistenceMode,
    phase: Phase,
    point: Point,
    hold_prior_capture: bool,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for point in [
        Point::BeforeCutPublish,
        Point::AfterCutRename,
        Point::AfterCutPublish,
    ] {
        cases.push(Case {
            mode: SessionPersistenceMode::Durable,
            phase: Phase::PurgeCut,
            point,
            hold_prior_capture: false,
        });
    }
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for phase in [Phase::PurgeCheckpoint, Phase::Snapshot] {
            for point in [
                Point::AfterNativeGenerationCapture,
                Point::BeforeNativeGenerationAppend,
                Point::AfterNativeGenerationAppend,
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
                if mode == SessionPersistenceMode::Async
                    && matches!(
                        point,
                        Point::AfterNativeGenerationCapture
                            | Point::BeforeBasisReclaim
                            | Point::AfterBasisReclaimFile
                            | Point::BeforeBasisReclaimSync
                            | Point::AfterBasisReclaimSync
                    )
                {
                    // Async has no WAL cut cleanup and prepares its generation
                    // inline in its single writer, before the append hook.
                    continue;
                }
                cases.push(Case {
                    mode,
                    phase,
                    point,
                    hold_prior_capture: false,
                });
            }
        }
    }
    cases.push(Case {
        mode: SessionPersistenceMode::Async,
        phase: Phase::Snapshot,
        point: Point::BeforeBasisPublicationSync,
        hold_prior_capture: true,
    });
    cases
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct SnapshotFile {
    pub(super) candidate: CurrentSnapshot,
    raw: PathBuf,
    published: PathBuf,
}

impl SnapshotFile {
    pub(super) fn capture(incoming: &IncomingSnapshot) -> Self {
        Self {
            candidate: incoming.candidate.clone(),
            raw: incoming.raw.clone(),
            published: incoming.published.clone(),
        }
    }

    pub(super) fn source(&self) -> io::Result<InstallSource> {
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
        InstallSource::new(
            self.candidate.clone(),
            raw,
            published,
            self.published.clone(),
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Report {
    wal: PathBuf,
    basis: [u8; 32],
    snapshots: Vec<SnapshotFile>,
    business: [u8; 32],
}

fn snapshot(wal: &Wal) -> IncomingSnapshot {
    let mut incoming = IncomingSnapshot::new(&wal.native_export_snapshot().unwrap());
    incoming.candidate.0.snapshot_id = wal.native_snapshot_id().unwrap();
    incoming.source().unwrap().verify().unwrap();
    incoming
}

fn drain_async_fixture(wal: &Wal, release_prior: Option<mpsc::SyncSender<()>>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut publication = wal.async_persistence_progress();
        let cut = wal.request_async_persistence().unwrap();
        if let Some(release) = release_prior {
            release.send(()).unwrap();
        }
        loop {
            drop(publication.borrow_and_update());
            let (state, failure, progress) = wal.storage_health();
            assert_eq!(state, crate::consensus::SessionStorageState::Running);
            assert!(failure.is_none());
            let progress = progress.unwrap();
            assert!(progress.background_failure.is_none());
            if progress.completed_generation >= cut.0 && progress.completed_sequence >= cut.1 {
                break;
            }
            publication.changed().await.unwrap();
        }
    });
}

fn wait_for_prior_capture(wal: &Wal, captured: &mut tokio::sync::watch::Receiver<bool>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut publication = wal.async_persistence_progress();
    let cut = wal.storage_health().2.unwrap().resident_generation;
    runtime.block_on(async {
        tokio::time::timeout(opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT, async {
            loop {
                drop(publication.borrow_and_update());
                let (state, failure, progress) = wal.storage_health();
                assert_eq!(state, crate::consensus::SessionStorageState::Running);
                assert!(failure.is_none());
                let progress = progress.unwrap();
                assert!(progress.background_failure.is_none());
                if *captured.borrow_and_update() {
                    break;
                }
                assert!(
                    progress.completed_generation < cut,
                    "primer generation finished without entering its capture hold"
                );
                // WriterExit publishes here too. A failed writer must fail
                // the fixture even while the capture sender remains alive.
                tokio::select! {
                    result = captured.changed() => result.unwrap(),
                    result = publication.changed() => result.unwrap(),
                }
            }
        })
        .await
        .expect("primer generation must enter its capture hold within the operation budget");
    });
}

fn crash(case: Case) -> ! {
    let armed = Arc::new(AtomicBool::new(false));
    let hook_armed = Arc::clone(&armed);
    let hold_prior_capture = Arc::new(AtomicBool::new(false));
    let hook_hold_prior_capture = Arc::clone(&hold_prior_capture);
    let (captured_tx, mut captured_rx) = tokio::sync::watch::channel(false);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let control = IoControl {
        hook: Arc::new(move |point| {
            if point == Point::BeforeNativeGenerationAppend
                && hook_hold_prior_capture.swap(false, Ordering::SeqCst)
            {
                captured_tx.send_replace(true);
                release_rx
                    .lock()
                    .unwrap()
                    .recv()
                    .map_err(io::Error::other)?;
            }
            if point == case.point && hook_armed.load(Ordering::SeqCst) {
                // Exit from the actual writer at the declared boundary. No
                // WAL shutdown, destructor, or test-only checkpoint can run.
                std::process::exit(73);
            }
            Ok(())
        }),
        ..IoControl::default()
    };
    let fixture = Fixture::with_persistence(Limits::default(), control, case.mode);
    // Drop the release sender before Fixture::drop joins the writer, including
    // when any setup assertion or report write panics while capture is held.
    let mut prior_capture = case.hold_prior_capture.then_some(release_tx);
    let request = fenced_transition_v2_request(0xBD, 1, "native-purge-crash");
    let mut entries = vec![formation(), activation(1, request, timestamp(1))];
    entries.extend((2..=6).map(|index| Entry {
        log_id: log_id(index),
        payload: EntryPayload::Blank,
    }));
    fixture.parity(&entries);
    let old = snapshot(&fixture.wal);
    fixture
        .wal
        .native_publish_snapshot(old.candidate.clone())
        .unwrap();
    fixture.wal.checkpoint().unwrap();
    let mut snapshots = vec![SnapshotFile::capture(&old)];
    let newer = if matches!(case.phase, Phase::Snapshot) {
        fixture
            .wal
            .submit(Operation::Purge(log_id(2)))
            .unwrap()
            .wait()
            .unwrap();
        fixture.wal.checkpoint().unwrap();
        let newer = snapshot(&fixture.wal);
        snapshots.push(SnapshotFile::capture(&newer));
        if case.hold_prior_capture {
            drain_async_fixture(&fixture.wal, None);
            hold_prior_capture.store(true, Ordering::SeqCst);
        }
        // A snapshot at the same applied cut still changes its selected
        // descriptor. This barrier gives Durable cleanup a covered WAL cut.
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
        if case.hold_prior_capture {
            wait_for_prior_capture(&fixture.wal, &mut captured_rx);
            assert!(!fixture.wal.checkpoint_pending_for_test().unwrap());
        }
        Some(newer)
    } else {
        None
    };
    let report = Report {
        wal: fixture.directory.path().join("wal"),
        basis: fixture.wal.binding().basis,
        snapshots,
        business: fixture
            .wal
            .with_native_read(|state| state.business_digest_for_test())
            .unwrap(),
    };
    std::fs::write(
        std::env::var(REPORT).unwrap(),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    if case.mode == SessionPersistenceMode::Async {
        // An admitted barrier can still have an earlier generation in
        // flight. Drain it before attributing a hook to this operation.
        drain_async_fixture(&fixture.wal, prior_capture.take());
    }
    armed.store(true, Ordering::SeqCst);
    if let Some(release) = prior_capture {
        release.send(()).unwrap();
    }
    match case.phase {
        Phase::PurgeCut | Phase::PurgeCheckpoint => {
            fixture
                .wal
                .submit(Operation::Purge(log_id(4)))
                .unwrap()
                .wait()
                .unwrap();
            fixture.wal.checkpoint().unwrap();
        }
        Phase::Snapshot => fixture
            .wal
            .native_publish_snapshot(newer.as_ref().unwrap().candidate.clone())
            .unwrap(),
    }
    panic!("crash hook did not run: {case:?}");
}

fn selector_was_renamed(point: Point) -> bool {
    matches!(
        point,
        Point::AfterBasisSelectorRename
            | Point::BeforeBasisPublicationSync
            | Point::AfterBasisPublicationSync
            | Point::BeforeBasisReclaim
            | Point::AfterBasisReclaimFile
            | Point::BeforeBasisReclaimSync
            | Point::AfterBasisReclaimSync
    )
}

fn assert_context(wal: &Wal, report: &Report, case: Case) {
    let purged = match case.phase {
        Phase::PurgeCut => (case.point != Point::BeforeCutPublish).then(|| log_id(4)),
        Phase::PurgeCheckpoint
            if case.mode == SessionPersistenceMode::Durable || selector_was_renamed(case.point) =>
        {
            Some(log_id(4))
        }
        Phase::PurgeCheckpoint => None,
        Phase::Snapshot => Some(log_id(2)),
    };
    let selected =
        usize::from(matches!(case.phase, Phase::Snapshot) && selector_was_renamed(case.point));
    let expected = &report.snapshots[selected].candidate;
    let state = wal.native_log_state().unwrap();
    assert_eq!(state.last_purged_log_id, purged, "{case:?}");
    assert_eq!(state.last_log_id, Some(log_id(6)), "{case:?}");
    assert_eq!(wal.committed().unwrap(), Some(log_id(6)), "{case:?}");
    let first = purged.map_or(0, |id| id.index + 1);
    let inventory = wal.native_log_inventory_for_test().unwrap();
    assert_eq!(
        (inventory.0, inventory.1, inventory.2),
        ((7 - first) as usize, Some(first), purged.map(|id| id.index)),
        "{case:?}"
    );
    let entries = wal.read(0, 7).unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.log_id).collect::<Vec<_>>(),
        (first..7).map(log_id).collect::<Vec<_>>(),
        "{case:?}"
    );
    wal.with_native_read(|state| {
        assert_eq!(state.applied(), Some(log_id(6)), "{case:?}");
        assert_eq!(state.membership(), expected.0.last_membership, "{case:?}");
        assert_eq!(
            state.current_snapshot().as_ref(),
            Some(expected),
            "{case:?}"
        );
        assert_eq!(
            state.business_digest_for_test()?,
            report.business,
            "{case:?}"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn native_purge_crash_boundaries_recover_complete_context_twice() {
    let cases = cases();
    if let Ok(case) = std::env::var(CHILD) {
        crash(cases[case.parse::<usize>().unwrap()]);
    }
    for (index, case) in cases.into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, index.to_string())
            .env(REPORT, &path)
            .env("TMPDIR", directory.path())
            .test_output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "{case:?}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Report = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let binding = Binding {
            identity: identity(),
            generation: [0xE1; 32],
            basis: report.basis,
            native: true,
            persistence: case.mode,
            async_closed_format: case.mode == SessionPersistenceMode::Async,
            async_recovery_format: case.mode == SessionPersistenceMode::Async,
        };
        for reopen in 0..2 {
            let opening = Opening::new(
                &report.wal,
                binding,
                None,
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            let sources = opening
                .snapshots()
                .iter()
                .map(|candidate| {
                    report
                        .snapshots
                        .iter()
                        .find(|snapshot| &snapshot.candidate == candidate)
                        .expect("every selected snapshot has its original complete file")
                        .source()
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(sources.len(), 1);
            let wal = opening
                .finish(|| sources.iter().try_for_each(InstallSource::verify))
                .unwrap();
            assert_context(&wal, &report, case);
            wal.checkpoint().unwrap();
            wal.shutdown().unwrap();
            eprintln!(
                "NATIVE_PURGE_CRASH mode={:?} phase={:?} point={:?} reopen={reopen}",
                case.mode, case.phase, case.point
            );
        }
    }
}
