use super::*;

#[derive(Debug)]
struct ClockSample(std::sync::Mutex<Timestamp>);
impl Clock for ClockSample {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
enum Observation {
    Get,
    Batch,
    Restore,
    ExpiryReference,
    #[cfg(feature = "lab-memory")]
    Observe,
    #[cfg(feature = "lab-memory")]
    LabRestore,
    #[cfg(feature = "lab-memory")]
    Prepare,
    #[cfg(feature = "lab-memory")]
    Status,
}

#[cfg(feature = "lab-memory")]
fn request() -> crate::FencedTransitionRequest {
    let key = test_key("clock-isolation", b"receipt");
    crate::FencedTransitionRequest::new(
        crate::FencedTransitionRequestId::new(),
        crate::FencedTransitionLease::acquire(
            key.clone(),
            OwnerId::new("owner").unwrap(),
            FenceToken::new(0),
            Duration::from_secs(60),
        )
        .unwrap(),
        crate::FencedTransitionMutation::create(test_record(key, 1, 1, "owner")),
    )
    .unwrap()
}

async fn read_cannot_choose_commit_time(observation: Observation, count: usize) {
    let start = Timestamp::now_utc();
    let clock = Arc::new(ClockSample(std::sync::Mutex::new(start)));
    let make = || {
        #[cfg(feature = "lab-memory")]
        if matches!(
            observation,
            Observation::Observe
                | Observation::LabRestore
                | Observation::Prepare
                | Observation::Status
        ) {
            return FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
        }
        FakeSessionBackend::new().with_clock(clock.clone())
    };
    let source = make();
    let control = make();
    #[cfg(feature = "lab-memory")]
    let prepared = if matches!(observation, Observation::Status) {
        let request = request();
        let source_request = source
            .prepare_fenced_transition(request.clone())
            .await
            .unwrap();
        let control_request = control.prepare_fenced_transition(request).await.unwrap();
        source.fenced_transition(&source_request).await.unwrap();
        control.fenced_transition(&control_request).await.unwrap();
        Some(source_request)
    } else {
        None
    };
    // Seed complete record/fence rows, not retirement counters. The real
    // production finalizer decides whether these N rows retire and rotate.
    for backend in [&source, &control] {
        let mut state = backend.inner.lock().await;
        for index in 0..count {
            let key = test_key("clock-isolation", &(index as u64).to_be_bytes());
            let mut record = test_record(key.clone(), 1, 1, "owner");
            record.expires_at = Some(start.add_seconds(1).unwrap());
            let key = FakeSessionBackend::map_key(&key);
            state.records.insert(key.clone(), record);
            state.key_fences.insert(key, FenceToken::new(1));
        }
        state.next_fence = state.next_fence.max(2);
    }
    let key = test_key("clock-isolation", &0_u64.to_be_bytes());
    let before = backend_data_snapshot(&source).await;
    *clock.0.lock().unwrap() = start.add_seconds(2).unwrap();
    match observation {
        Observation::Get => {
            source.get(&key).await.unwrap();
        }
        Observation::Batch => {
            source.batch(vec![SessionOp::Get { key }]).await.unwrap();
        }
        Observation::Restore => {
            source
                .scan_restore_records(RestoreScanRequest::all(16))
                .await
                .unwrap();
        }
        Observation::ExpiryReference => {
            assert!(source.record_expiry_reference().is_some());
        }
        #[cfg(feature = "lab-memory")]
        Observation::Observe => {
            source.observe_fenced_transition(&key).await.unwrap();
        }
        #[cfg(feature = "lab-memory")]
        Observation::LabRestore => {
            source
                .scan_restore_records(RestoreScanRequest::all(16))
                .await
                .unwrap();
        }
        #[cfg(feature = "lab-memory")]
        Observation::Prepare => {
            source.prepare_fenced_transition(request()).await.unwrap();
        }
        #[cfg(feature = "lab-memory")]
        Observation::Status => {
            source
                .fenced_transition_status(prepared.as_ref().unwrap())
                .await
                .unwrap();
        }
    }
    assert_eq!(backend_data_snapshot(&source).await, before);
    *clock.0.lock().unwrap() = start;
    let fresh = test_key("clock-isolation", b"next-commit");
    let source_lease = source
        .acquire(
            &fresh,
            OwnerId::new("writer").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let control_lease = control
        .acquire(
            &fresh,
            OwnerId::new("writer").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let after = source.inner.lock().await;
    assert_eq!(
        after.key_retention.epoch, 0,
        "{observation:?}: reads cannot cause a threshold rotation"
    );
    assert_eq!(
        after.key_retention.retired_count, 0,
        "{observation:?}: reads cannot cause retirement"
    );
    assert_eq!(after.records.len(), before.records.len());
    drop(after);
    assert_eq!(
        source_lease, control_lease,
        "{observation:?}: write uses its own clock"
    );
    assert_eq!(source_lease.acquired_at(), start);
    assert_eq!(
        backend_data_snapshot(&source).await,
        backend_data_snapshot(&control).await
    );
}

#[tokio::test]
async fn get_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::Get, 1).await;
}
#[tokio::test]
async fn read_only_batch_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::Batch, 1).await;
}
#[tokio::test]
async fn restore_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::Restore, 1).await;
}
#[tokio::test]
async fn expiry_reference_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::ExpiryReference, 1).await;
}
#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn observation_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::Observe, 1).await;
}
#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn lab_restore_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::LabRestore, 1).await;
}
#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn preparation_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::Prepare, 1).await;
}
#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn status_cannot_move_a_later_commit() {
    read_cannot_choose_commit_time(Observation::Status, 1).await;
}

#[tokio::test]
async fn a_reader_spike_cannot_trigger_the_real_retirement_threshold() {
    read_cannot_choose_commit_time(
        Observation::Get,
        crate::key_retention::RETIRED_KEYS_PER_EPOCH as usize,
    )
    .await;
}

#[tokio::test]
async fn local_commits_never_stamp_replication_time_backwards() {
    let start = Timestamp::now_utc();
    let clock = Arc::new(ClockSample(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let key = test_key("clock-isolation", b"monotone-write");
    let owner = OwnerId::new("owner").unwrap();
    let first = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    *clock.0.lock().unwrap() = start.add_seconds(2).unwrap();
    backend
        .renew(&first, Duration::from_secs(60))
        .await
        .unwrap();
    *clock.0.lock().unwrap() = start;
    let second = backend
        .acquire(
            &test_key("clock-isolation", b"after-rewind"),
            owner,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let entries = backend.get_replication_log(1, 16).await.unwrap();
    assert!(entries
        .windows(2)
        .all(|pair| pair[0].timestamp <= pair[1].timestamp));
    assert_eq!(second.acquired_at(), start.add_seconds(2).unwrap());
}
