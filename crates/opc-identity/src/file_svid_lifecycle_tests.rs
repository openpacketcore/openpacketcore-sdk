use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::timeout;

const HANG_GUARD: Duration = Duration::from_secs(5);

struct Retired(tokio::sync::watch::Sender<bool>);

impl Drop for Retired {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

struct TaskProbe {
    started: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    retired: tokio::sync::watch::Receiver<bool>,
    ran_after_release: Arc<AtomicBool>,
    abort: AbortHandle,
}

impl TaskProbe {
    fn release(&mut self) {
        if let Some(tx) = self.release.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for TaskProbe {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

fn gated_task(panic_after_release: bool) -> (JoinHandle<()>, TaskProbe) {
    let (started_tx, started) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let (retired_tx, retired) = tokio::sync::watch::channel(false);
    let guard = Retired(retired_tx);
    let ran_after_release = Arc::new(AtomicBool::new(false));
    let ran = ran_after_release.clone();
    let handle = tokio::spawn(async move {
        let _guard = guard;
        let _ = started_tx.send(());
        if release_rx.await.is_ok() {
            ran.store(true, Ordering::SeqCst);
            assert!(!panic_after_release, "synthetic task panic payload");
        }
    });
    let abort = handle.abort_handle();
    (
        handle,
        TaskProbe {
            started,
            release: Some(release),
            retired,
            ran_after_release,
            abort,
        },
    )
}

async fn controlled_source(poller: JoinHandle<()>, expiry: JoinHandle<()>) -> FileSvidSource {
    // All tests use the current-thread runtime. Replace and abort the original
    // handles before yielding, so those constructor tasks never start file I/O.
    let mut source = FileSvidSource::new(
        "unused-synthetic-svid.crt",
        "unused-synthetic-svid.key",
        vec!["unused-synthetic-bundle.crt"],
        Some(Duration::from_secs(3_600)),
    );
    let original_poller = std::mem::replace(&mut source._task_handle, poller);
    let original_expiry = std::mem::replace(&mut source._expiry_task_handle, expiry);
    original_poller.abort();
    original_expiry.abort();
    let _ = original_poller.await;
    let _ = original_expiry.await;
    source
}

async fn started(poller: &mut TaskProbe, expiry: &mut TaskProbe) -> bool {
    matches!(
        timeout(HANG_GUARD, async {
            let (a, b) = tokio::join!(&mut poller.started, &mut expiry.started);
            a.is_ok() && b.is_ok()
        })
        .await,
        Ok(true)
    )
}

async fn retired(poller: &mut TaskProbe, expiry: &mut TaskProbe) -> bool {
    matches!(
        timeout(HANG_GUARD, async {
            let (a, b) = tokio::join!(
                poller.retired.wait_for(|retired| *retired),
                expiry.retired.wait_for(|retired| *retired)
            );
            a.is_ok() && b.is_ok()
        })
        .await,
        Ok(true)
    )
}

async fn finish_detached(poller: &TaskProbe, expiry: &TaskProbe) -> bool {
    poller.abort.abort();
    expiry.abort.abort();
    let mut poller_retired = poller.retired.clone();
    let mut expiry_retired = expiry.retired.clone();
    // On this current-thread runtime, a task finishes its final poll before
    // the retirement notification can resume the observer.
    matches!(
        timeout(HANG_GUARD, async {
            let (a, b) = tokio::join!(
                poller_retired.wait_for(|retired| *retired),
                expiry_retired.wait_for(|retired| *retired)
            );
            a.is_ok() && b.is_ok()
        })
        .await,
        Ok(true)
    ) && poller.abort.is_finished()
        && expiry.abort.is_finished()
}

#[tokio::test]
async fn file_source_drop_cancels_both_owned_tasks_before_they_resume() {
    let (poller_task, mut poller) = gated_task(false);
    let (expiry_task, mut expiry) = gated_task(false);
    let source = controlled_source(poller_task, expiry_task).await;
    let both_started = started(&mut poller, &mut expiry).await;

    drop(source);
    // Under the original implementation these releases resume detached tasks.
    // With Drop cancellation, neither async body may resume after its gate.
    poller.release();
    expiry.release();
    let both_retired = retired(&mut poller, &mut expiry).await;
    let resumed = poller.ran_after_release.load(Ordering::SeqCst)
        || expiry.ran_after_release.load(Ordering::SeqCst);
    let both_finished = finish_detached(&poller, &expiry).await;

    // Cleanup precedes the intended failure in the tests-first/removal control.
    assert!(
        both_started && both_retired && both_finished,
        "task fixture cleanup failed"
    );
    assert!(!resumed, "FILE_SOURCE_DROP_DETACHED_OWNED_TASK");
}

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll, Waker};

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

async fn cleanup_owned(source: &mut FileSvidSource) {
    source._task_handle.abort();
    source._expiry_task_handle.abort();
    if !source.task_joined[0] {
        let _ = (&mut source._task_handle).await;
        source.task_joined[0] = true;
    }
    if !source.task_joined[1] {
        let _ = (&mut source._expiry_task_handle).await;
        source.task_joined[1] = true;
    }
}

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "opc-identity-shutdown-{label}-{}-{n}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("failed to create synthetic fixture: {e}"),
            }
        }
    }

    fn source(&self) -> FileSvidSource {
        FileSvidSource::new(
            self.0.join("svid.crt"),
            self.0.join("svid.key"),
            vec![self.0.join("bundle.crt")],
            Some(Duration::from_secs(3_600)),
        )
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SYNTHETIC_SPIFFE: &str =
    "spiffe://example.test/tenant/test/ns/default/sa/svc/nf/test/instance/0";

fn write_valid_identity(dir: &FixtureDir) {
    use rcgen::{CertificateParams, KeyPair, SanType};

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names.push(SanType::URI(
        rcgen::string::Ia5String::try_from(SYNTHETIC_SPIFFE).unwrap(),
    ));
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::days(1);
    params.not_after = now + ::time::Duration::days(1);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca).unwrap();
    std::fs::write(dir.0.join("svid.crt"), cert.pem() + &ca.pem()).unwrap();
    std::fs::write(dir.0.join("svid.key"), key.serialize_pem()).unwrap();
    std::fs::write(dir.0.join("bundle.crt"), ca.pem()).unwrap();
}

fn drain_events(
    rx: &mut broadcast::Receiver<IdentityReloadEvent>,
) -> broadcast::error::TryRecvError {
    loop {
        match rx.try_recv() {
            Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(e) => return e,
        }
    }
}

#[tokio::test]
async fn file_source_shutdown_joins_real_missing_file_polling_with_subscribers() {
    let dir = FixtureDir::new("missing");
    let mut source = dir.source();
    let state_rx = source.subscribe();
    let mut events = source.subscribe_events();
    // This event is a real completed missing-file read, not a sleep heuristic.
    let observed = timeout(HANG_GUARD, events.recv()).await;
    let result = timeout(HANG_GUARD, source.shutdown()).await;
    let joined = source.task_joined == [true; 2];
    let finished = source._task_handle.is_finished() && source._expiry_task_handle.is_finished();
    let state_closed = state_rx.has_changed().is_err();
    let event_channel_open = matches!(
        drain_events(&mut events),
        broadcast::error::TryRecvError::Empty
    );
    let repeated = timeout(HANG_GUARD, source.shutdown()).await;
    cleanup_owned(&mut source).await;
    drop(source);
    let events_closed = matches!(
        drain_events(&mut events),
        broadcast::error::TryRecvError::Closed
    );

    assert!(
        matches!(observed, Ok(Ok(IdentityReloadEvent::Failure { error }))
            if error == "failed to read identity files"),
        "real missing-file polling was not observed"
    );
    assert!(
        matches!(result, Ok(Ok(()))),
        "FILE_SOURCE_MISSING_SHUTDOWN_RESULT"
    );
    assert!(
        joined && finished && state_closed,
        "FILE_SOURCE_MISSING_TASKS_NOT_JOINED"
    );
    assert!(
        matches!(repeated, Ok(Ok(()))),
        "FILE_SOURCE_SHUTDOWN_NOT_IDEMPOTENT"
    );
    assert!(
        event_channel_open && events_closed,
        "FILE_SOURCE_EVENT_OWNERSHIP"
    );
}

#[tokio::test]
async fn file_source_shutdown_joins_loaded_identity_and_preserves_snapshot() {
    let dir = FixtureDir::new("loaded");
    write_valid_identity(&dir);
    let mut source = dir.source();
    let loaded = source.wait_for_initial_identity(HANG_GUARD).await;
    let state_rx = source.subscribe();
    let result = timeout(HANG_GUARD, source.shutdown()).await;
    let joined = source.task_joined == [true; 2];
    let state_closed = state_rx.has_changed().is_err();
    let retained = state_rx
        .borrow()
        .as_ref()
        .map(|s| s.identity.spiffe_id.as_str().to_owned());
    cleanup_owned(&mut source).await;
    drop(source);

    assert_eq!(
        loaded.unwrap().identity.spiffe_id.as_str(),
        SYNTHETIC_SPIFFE
    );
    assert!(
        matches!(result, Ok(Ok(()))),
        "FILE_SOURCE_LOADED_SHUTDOWN_RESULT"
    );
    assert!(
        joined && state_closed,
        "FILE_SOURCE_LOADED_TASKS_NOT_JOINED"
    );
    assert_eq!(
        retained.as_deref(),
        Some(SYNTHETIC_SPIFFE),
        "FILE_SOURCE_RETAINED_SNAPSHOT"
    );
}

#[tokio::test]
async fn file_source_shutdown_cancellation_retains_both_joins_and_can_retry() {
    let (poller_task, mut poller) = gated_task(false);
    let (expiry_task, mut expiry) = gated_task(false);
    let mut source = controlled_source(poller_task, expiry_task).await;
    let both_started = started(&mut poller, &mut expiry).await;
    let task_ids = (source._task_handle.id(), source._expiry_task_handle.id());

    let mut shutdown = Box::pin(source.shutdown());
    let was_pending = poll_once(shutdown.as_mut()).is_pending();
    drop(shutdown);
    let signalled = *source.stop_tx.borrow();
    let retained = source.task_joined == [false; 2]
        && task_ids == (source._task_handle.id(), source._expiry_task_handle.id());
    poller.release();
    expiry.release();
    let result = timeout(HANG_GUARD, source.shutdown()).await;
    let joined = source.task_joined == [true; 2];
    let finished_before_cleanup = poller.abort.is_finished() && expiry.abort.is_finished();
    let repeated = timeout(HANG_GUARD, source.shutdown()).await;
    cleanup_owned(&mut source).await;
    let both_retired = retired(&mut poller, &mut expiry).await;
    let all_finished = finish_detached(&poller, &expiry).await;

    assert!(
        both_started && both_retired && all_finished,
        "controlled tasks did not retire"
    );
    assert!(
        was_pending,
        "FILE_SOURCE_SHUTDOWN_RETURNED_BEFORE_COMPLETION"
    );
    assert!(
        signalled && retained,
        "FILE_SOURCE_CANCELLED_SHUTDOWN_LOST_OWNERSHIP"
    );
    assert!(
        matches!(result, Ok(Ok(()))) && joined && finished_before_cleanup,
        "FILE_SOURCE_RETRY_DID_NOT_JOIN_BOTH_TASKS"
    );
    assert!(
        matches!(repeated, Ok(Ok(()))),
        "FILE_SOURCE_SHUTDOWN_NOT_IDEMPOTENT"
    );
}

#[tokio::test]
async fn file_source_shutdown_retry_preserves_first_failure_and_joins_second_task() {
    let (poller_task, mut poller) = gated_task(true);
    let (expiry_task, mut expiry) = gated_task(false);
    let mut source = controlled_source(poller_task, expiry_task).await;
    let both_started = started(&mut poller, &mut expiry).await;
    poller.release();
    let poller_retired = timeout(HANG_GUARD, poller.retired.wait_for(|retired| *retired))
        .await
        .is_ok_and(|result| result.is_ok());
    tokio::task::yield_now().await;

    let mut shutdown = Box::pin(source.shutdown());
    let was_pending = poll_once(shutdown.as_mut()).is_pending();
    drop(shutdown);
    let retained_failure =
        source.task_joined == [true, false] && source.task_failed == [true, false];
    expiry.release();
    let result = timeout(HANG_GUARD, source.shutdown()).await;
    let joined = source.task_joined == [true; 2];
    let second_finished_before_cleanup = expiry.abort.is_finished();
    let repeated = timeout(HANG_GUARD, source.shutdown()).await;
    cleanup_owned(&mut source).await;
    let expiry_retired = timeout(HANG_GUARD, expiry.retired.wait_for(|retired| *retired))
        .await
        .is_ok_and(|result| result.is_ok());

    assert!(
        both_started && poller_retired && expiry_retired,
        "controlled tasks did not retire"
    );
    assert!(
        retained_failure,
        "FILE_SOURCE_FIRST_JOIN_RESULT_NOT_RETAINED"
    );
    assert!(
        was_pending
            && matches!(result, Ok(Err(FileSvidShutdownError::PollerFailed)))
            && joined
            && second_finished_before_cleanup,
        "FILE_SOURCE_FAILURE_SKIPPED_SECOND_JOIN"
    );
    assert!(
        matches!(repeated, Ok(Err(FileSvidShutdownError::PollerFailed))),
        "FILE_SOURCE_FAILURE_NOT_IDEMPOTENT"
    );
}

#[tokio::test]
async fn file_source_shutdown_reports_either_or_both_task_failures_without_payloads() {
    for (fail_poller, fail_expiry, expected) in [
        (true, false, FileSvidShutdownError::PollerFailed),
        (false, true, FileSvidShutdownError::ExpiryMonitorFailed),
        (true, true, FileSvidShutdownError::BothFailed),
    ] {
        let (poller_task, mut poller) = gated_task(fail_poller);
        let (expiry_task, mut expiry) = gated_task(fail_expiry);
        let mut source = controlled_source(poller_task, expiry_task).await;
        let both_started = started(&mut poller, &mut expiry).await;
        poller.release();
        expiry.release();
        let result = timeout(HANG_GUARD, source.shutdown()).await;
        let joined = source.task_joined == [true; 2];
        let finished_before_cleanup = poller.abort.is_finished() && expiry.abort.is_finished();
        let repeated = timeout(HANG_GUARD, source.shutdown()).await;
        cleanup_owned(&mut source).await;
        let both_retired = retired(&mut poller, &mut expiry).await;

        assert!(
            both_started && both_retired,
            "controlled tasks did not retire"
        );
        assert!(
            matches!(result, Ok(Err(e)) if e == expected) && joined && finished_before_cleanup,
            "FILE_SOURCE_TASK_FAILURE_CLASSIFICATION"
        );
        assert!(
            matches!(repeated, Ok(Err(e)) if e == expected),
            "FILE_SOURCE_FAILURE_NOT_IDEMPOTENT"
        );
        assert!(
            !format!("{expected} {expected:?}").contains("synthetic task panic payload"),
            "FILE_SOURCE_JOIN_ERROR_PAYLOAD_EXPOSED"
        );
    }
}

#[tokio::test]
async fn file_source_drop_after_cancelled_shutdown_retires_owned_tasks() {
    let (poller_task, mut poller) = gated_task(false);
    let (expiry_task, mut expiry) = gated_task(false);
    let mut source = controlled_source(poller_task, expiry_task).await;
    let both_started = started(&mut poller, &mut expiry).await;
    let mut shutdown = Box::pin(source.shutdown());
    let was_pending = poll_once(shutdown.as_mut()).is_pending();
    drop(shutdown);
    drop(source);
    poller.release();
    expiry.release();
    let both_retired = retired(&mut poller, &mut expiry).await;
    let resumed = poller.ran_after_release.load(Ordering::SeqCst)
        || expiry.ran_after_release.load(Ordering::SeqCst);
    let both_finished = finish_detached(&poller, &expiry).await;

    assert!(
        both_started && both_retired && both_finished,
        "task fixture cleanup failed"
    );
    assert!(
        was_pending && !resumed,
        "FILE_SOURCE_CANCELLED_SHUTDOWN_DROP_DETACHED_TASK"
    );
}

#[tokio::test]
async fn file_source_closed_empty_stream_returns_reload_error_in_one_poll() {
    let dir = FixtureDir::new("closed");
    let mut source = dir.source();
    let result = timeout(HANG_GUARD, source.shutdown()).await;
    cleanup_owned(&mut source).await;
    tokio::task::yield_now().await;
    let mut initial = Box::pin(source.wait_for_initial_identity(Duration::from_secs(3_600)));
    let observed = poll_once(initial.as_mut());
    drop(initial);
    drop(source);

    assert!(matches!(result, Ok(Ok(()))), "shutdown did not join");
    assert!(
        matches!(observed, Poll::Ready(Err(IdentityReloadError::IoError))),
        "FILE_SOURCE_CLOSED_STREAM_DID_NOT_RETURN"
    );
}

#[tokio::test]
async fn file_source_legacy_expiry_helper_still_clears_expired_identity() {
    let dir = FixtureDir::new("expiry");
    write_valid_identity(&dir);
    let mut state = reload_identity(
        &dir.0.join("svid.crt"),
        &dir.0.join("svid.key"),
        &[dir.0.join("bundle.crt")],
    )
    .await
    .unwrap();
    let expired = opc_types::Timestamp::from_offset_datetime(
        ::time::OffsetDateTime::now_utc() - ::time::Duration::seconds(1),
    );
    state.identity.expires_at = expired;
    state.svid.expires_at = expired;
    let (state_tx, state_rx) = watch::channel(Some(state));
    let (event_tx, mut events) = broadcast::channel(4);
    let monitor = crate::spawn_expiry_monitor(state_tx, event_tx);
    let event = timeout(HANG_GUARD, events.recv()).await;
    let cleared = state_rx.borrow().is_none();
    monitor.abort();
    let _ = monitor.await;

    assert!(
        matches!(event, Ok(Ok(IdentityReloadEvent::Failure { error }))
        if error == IdentityReloadError::ExpiredSvid.to_string()),
        "FILE_SOURCE_LEGACY_EXPIRY_EVENT_CHANGED"
    );
    assert!(cleared, "FILE_SOURCE_LEGACY_EXPIRY_STATE_NOT_CLEARED");
}
