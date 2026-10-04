//! Selected asynchronous generations, independent foreground and real reopen.

use super::*;
use crate::{SessionPersistenceMode, SessionStorageState};

struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn async_persistence_keeps_admission_and_apply_live_then_selects_and_reopens() {
    let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
    let fixture = Fixture::with_persistence(
        Limits::default(),
        gate.control(),
        SessionPersistenceMode::Async,
    );
    let release = Release(Arc::clone(&gate));
    let initial = fenced_transition_v2_request(0xEC, 1, "async-initial");
    fixture.parity(&[formation(), activation(1, initial, timestamp(1))]);
    gate.entered();
    let original = selected(&fixture);
    for _ in 0..1_200 {
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
    }
    let request = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
    fixture.parity(&[fenced_transition_v2_entry(2, request.clone(), timestamp(2))]);
    let exact = status(&fixture.wal, &request);
    assert!(matches!(exact, FencedTransitionV2Status::Recorded(_)));
    let (lifecycle, failure, progress) = fixture.wal.storage_health();
    let progress = progress.unwrap();
    assert_eq!(lifecycle, SessionStorageState::Running);
    assert!(failure.is_none());
    assert!(progress.resident_sequence > 1_200);
    assert!(progress.captured_generation.is_some());
    assert_eq!(progress.completed_generation, 0);
    assert!(progress.background_failure.is_none());
    assert_eq!(selected(&fixture), original);
    drop(release);
    fixture.wal.checkpoint().unwrap();
    until(|| {
        fixture
            .wal
            .native_cold_counts_for_test()
            .unwrap()
            .iter()
            .sum::<usize>()
            > 0
    });
    let persisted = selected(&fixture);
    assert_eq!(
        persisted["position"]["sequence"], 0,
        "no synthetic WAL acknowledgements"
    );
    assert!(persisted["async_cut"]["sequence"].as_u64().unwrap() > 1_200);
    assert_eq!(persisted["async_cut"]["applied"]["index"], 2);
    assert_eq!(
        std::fs::metadata(
            fixture
                .directory
                .path()
                .join("wal/segment-00000000000000000000.wal")
        )
        .unwrap()
        .len(),
        80
    );
    let reopened = fixture.reopened();
    assert_eq!(
        encode_json(&status(&reopened, &request)).unwrap(),
        encode_json(&exact).unwrap()
    );
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(2))
    );
    reopened.shutdown().unwrap();
}

#[test]
fn async_persistence_io_failure_preserves_resident_results_and_reopens_only_selected_prefix() {
    let control = IoControl {
        hook: Arc::new(|point| {
            if point == Point::AfterNativeGenerationAppend {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            } else {
                Ok(())
            }
        }),
        ..IoControl::default()
    };
    let fixture =
        Fixture::with_persistence(Limits::default(), control, SessionPersistenceMode::Async);
    until(|| {
        fixture
            .wal
            .storage_health()
            .2
            .unwrap()
            .background_failure
            .is_some()
    });
    let initial = fenced_transition_v2_request(0xED, 1, "async-failed-writer");
    fixture.parity(&[formation(), activation(1, initial.clone(), timestamp(1))]);
    assert!(matches!(
        status(&fixture.wal, &initial),
        FencedTransitionV2Status::Recorded(_)
    ));
    let progress = fixture.wal.storage_health().2.unwrap();
    assert!(progress.saturated);
    assert_eq!(progress.completed_generation, 0);
    assert!(progress.captured_generation.is_none());
    assert!(fixture.wal.checkpoint().is_err());
    assert!(fixture.wal.shutdown().is_err());
    let reopened = Wal::open(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        None
    );
    reopened.shutdown().unwrap();
}

#[test]
fn async_persistence_reopen_rejects_missing_selector_and_wrong_mode_without_repair() {
    let fixture = Fixture::with_persistence(
        Limits::default(),
        IoControl::default(),
        SessionPersistenceMode::Async,
    );
    fixture.parity(&[formation()]);
    fixture.wal.shutdown().unwrap();
    let directory = fixture.directory.path().join("wal");
    let selector = std::fs::read(directory.join("CURRENT")).unwrap();
    let mut wrong = fixture.wal.binding();
    wrong.persistence = SessionPersistenceMode::Durable;
    assert!(Wal::open(&directory, wrong, Limits::default(), IoControl::default()).is_err());
    assert_eq!(std::fs::read(directory.join("CURRENT")).unwrap(), selector);
    std::fs::rename(directory.join("CURRENT"), directory.join("saved-selector")).unwrap();
    assert!(Wal::open(
        &directory,
        fixture.wal.binding(),
        Limits::default(),
        IoControl::default()
    )
    .is_err());
    assert_eq!(
        std::fs::read(directory.join("saved-selector")).unwrap(),
        selector
    );
    assert!(!directory.join("CURRENT").exists());
}
