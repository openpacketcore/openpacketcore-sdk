use super::*;
use crate::health::Readiness;
use crate::profile::RuntimeProfile;
use crate::task::{TaskError, TaskKind, TaskSpec};
use crate::testkit::FakeClock;

fn make_profile() -> RuntimeProfile {
    RuntimeProfile::conformance("test-nf")
}

#[tokio::test]
async fn test_fatal_task_failure_triggers_shutdown() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("fatal-task");
    supervisor
        .register(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Fatal,
            RestartPolicy::default(),
        )
        .await
        .unwrap();

    // Spawn a task that immediately fails
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Fatal,
            RestartPolicy::no_restart(),
            || {
                Box::pin(async {
                    Err(TaskError::Failed(
                        "fatal error".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // Wait for task to run and fail
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Fatal task failure should cancel the shutdown token
    assert!(
        shutdown.is_shutdown_requested(),
        "Fatal task failure should trigger shutdown"
    );
}

#[test]
fn fatal_task_failure_alarms_are_task_scoped() {
    let profile = make_profile();
    let alarms = SharedAlarmManager::default();
    let error = TaskError::Failed(
        "fatal error".into(),
        std::sync::Arc::new(std::io::Error::other("test")),
    );

    metrics::raise_fatal_task_alarm(&alarms, &profile, &TaskName::new("fatal-task-a"), &error);
    metrics::raise_fatal_task_alarm(&alarms, &profile, &TaskName::new("fatal-task-b"), &error);

    let active = alarms.active_alarms();
    assert_eq!(active.len(), 2);
    assert!(active
        .iter()
        .any(|alarm| { alarm.alarm_type.as_str() == "test-nf.runtime.task.failure.fatal-task-a" }));
    assert!(active
        .iter()
        .any(|alarm| { alarm.alarm_type.as_str() == "test-nf.runtime.task.failure.fatal-task-b" }));

    metrics::clear_runtime_task_failure_alarms(&alarms, &profile);
    assert_eq!(alarms.active_count(), 0);
}

#[tokio::test]
async fn test_shutdown_all_drain_requests_shutdown_signal() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("cooperative-drain-task");
    let shutdown_for_task = shutdown.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
            move || {
                let shutdown_inner = shutdown_for_task.clone();
                Box::pin(async move {
                    shutdown_inner.shutdown_acknowledged().await;
                    Ok(())
                }) as _
            },
        )
        .await
        .unwrap();

    tokio::task::yield_now().await;

    supervisor.shutdown_all(ShutdownPolicy::Drain).await;

    assert!(shutdown.is_shutdown_requested());
    let tasks = supervisor.tasks.read().await;
    let state = tasks.get(&name).unwrap();
    assert!(!state.handle.as_ref().unwrap().is_running());
}

#[tokio::test]
async fn test_degrade_task_failure_marks_degraded() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("degrade-task");
    supervisor
        .register(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy::default(),
        )
        .await
        .unwrap();

    // Spawn a task that immediately fails
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
            || {
                Box::pin(async {
                    Err(TaskError::Failed(
                        "degrade error".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // Wait for task to run and fail
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Degrade task failure should not cancel shutdown token
    assert!(
        !shutdown.is_shutdown_requested(),
        "Degrade task failure should not trigger immediate shutdown"
    );

    // Readiness should be degraded
    let readiness = supervisor.readiness().await;
    assert_eq!(
        readiness,
        Readiness::Degraded,
        "Degrade task failure should mark readiness as Degraded"
    );
}

#[tokio::test]
async fn test_best_effort_task_failure_no_health_impact() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("best-effort-task");
    supervisor
        .register(
            name.clone(),
            TaskKind::BackgroundSync,
            Criticality::BestEffort,
            RestartPolicy::default(),
        )
        .await
        .unwrap();

    // Spawn a task that immediately fails
    supervisor
        .spawn(
            name.clone(),
            TaskKind::BackgroundSync,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            || {
                Box::pin(async {
                    Err(TaskError::Failed(
                        "best-effort error".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // Wait for task to run and fail
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Best-effort should not cancel shutdown token
    assert!(
        !shutdown.is_shutdown_requested(),
        "Best-effort task failure should not trigger shutdown"
    );

    // Readiness should still be ready (no other tasks)
    let readiness = supervisor.readiness().await;
    assert_eq!(
        readiness,
        Readiness::Ready,
        "Best-effort task failure should not impact readiness"
    );
}

#[tokio::test]
async fn test_readiness_not_ready_when_no_tasks() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown);

    // With no tasks registered, readiness should be NotReady (no running tasks)
    let readiness = supervisor.readiness().await;
    assert_eq!(
        readiness,
        Readiness::NotReady,
        "No tasks should mean NotReady"
    );
}

#[tokio::test]
async fn test_register_inserts_into_hashmap() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown);

    let name = TaskName::new("registered-task");

    // Register a task
    supervisor
        .register(
            name.clone(),
            TaskKind::Listener,
            Criticality::Degrade,
            RestartPolicy::default(),
        )
        .await
        .unwrap();

    // The task should be in the hashmap
    let tasks = supervisor.tasks.read().await;
    assert!(
        tasks.contains_key(&name),
        "Registered task should be in the hashmap"
    );
}

#[tokio::test]
async fn test_register_prevents_duplicates() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown);

    let name = TaskName::new("dup-task");

    // First registration should succeed
    supervisor
        .register(
            name.clone(),
            TaskKind::Listener,
            Criticality::Degrade,
            RestartPolicy::default(),
        )
        .await
        .unwrap();

    // Second registration should fail
    let result = supervisor
        .register(
            name.clone(),
            TaskKind::Listener,
            Criticality::Degrade,
            RestartPolicy::default(),
        )
        .await;
    assert!(result.is_err(), "Duplicate registration should fail");
}

#[tokio::test]
async fn test_spawn_spec_rejects_restartable_one_shot_future() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown);

    let spec = TaskSpec::new(
        "restartable-one-shot",
        TaskKind::ProtocolWorker,
        Criticality::Degrade,
        async { Ok(()) },
    )
    .with_restart(RestartPolicy {
        max_restarts: 1,
        window_secs: 60,
        base_backoff_ms: 10,
        max_backoff_ms: 100,
        jitter: 0.0,
    });

    let err = supervisor
        .spawn_spec(spec)
        .await
        .expect_err("one-shot TaskSpec cannot be restartable");
    assert!(
        err.to_string().contains("use Supervisor::spawn"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_task_fails_twice_then_succeeds() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown);

    let name = TaskName::new("fail-twice-then-succeed-task");
    let run_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let run_count_clone = run_count.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy {
                max_restarts: 3,
                window_secs: 60,
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone.clone();
                Box::pin(async move {
                    let count = rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if count < 2 {
                        Err(TaskError::Failed(
                            "temporary failure".into(),
                            std::sync::Arc::new(std::io::Error::other("test")),
                        ))
                    } else {
                        // Succeeds and remains running (sleeps forever)
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Ok(())
                    }
                }) as _
            },
        )
        .await
        .unwrap();

    // Give it time to run and retry
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify task ran exactly 3 times (2 failures + 1 currently running success)
    assert_eq!(run_count.load(std::sync::atomic::Ordering::SeqCst), 3);

    // Verify that because it eventually succeeded and is running, the task is not degraded
    let readiness = supervisor.readiness().await;
    assert_eq!(readiness, Readiness::Ready);
}

#[tokio::test]
async fn test_task_exhausts_max_restarts() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown);

    let name = TaskName::new("exhausts-restarts-task");
    let run_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let run_count_clone = run_count.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy {
                max_restarts: 2,
                window_secs: 60,
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone.clone();
                Box::pin(async move {
                    rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(TaskError::Failed(
                        "persistent failure".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // Give it time to run, fail, retry up to max_restarts (2) and exhaust budget (total 3 attempts)
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify task ran 3 times (1 initial run + 2 restarts)
    assert_eq!(run_count.load(std::sync::atomic::Ordering::SeqCst), 3);

    // Health should be Degraded after exhausting budget
    let readiness = supervisor.readiness().await;
    assert_eq!(readiness, Readiness::Degraded);
}

#[tokio::test]
async fn test_task_panic_during_async_execution() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("panicking-task");
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Fatal,
            RestartPolicy::no_restart(),
            || {
                Box::pin(async {
                    panic!("async panic trigger");
                    #[allow(unreachable_code)]
                    Ok(())
                }) as _
            },
        )
        .await
        .unwrap();

    // Wait for task to run and panic
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The async panic should be caught and trigger fatal shutdown
    assert!(
        shutdown.is_shutdown_requested(),
        "Async panic should trigger fatal shutdown"
    );
}

#[tokio::test]
async fn test_unexpected_clean_exit_outside_shutdown_causes_failure() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("clean-exit-task");
    let run_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let run_count_clone = run_count.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy {
                max_restarts: 3,
                window_secs: 60,
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone.clone();
                Box::pin(async move {
                    rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(()) // Exits cleanly
                }) as _
            },
        )
        .await
        .unwrap();

    // Give it time to run, exit, detect failure (since shutdown is false), and retry
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Since it exited cleanly outside shutdown, it must have been treated as a failure and restarted
    assert!(run_count.load(std::sync::atomic::Ordering::SeqCst) > 1);

    // Readiness should be degraded (or not ready) because it keeps exiting and failing
    let readiness = supervisor.readiness().await;
    assert_ne!(readiness, Readiness::Ready);
}

#[tokio::test]
async fn test_draining_tasks_do_not_restart() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("draining-failed-task");
    let run_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let run_count_clone = run_count.clone();
    let shutdown_clone = shutdown.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy {
                max_restarts: 3,
                window_secs: 60,
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone.clone();
                let sd = shutdown_clone.clone();
                Box::pin(async move {
                    rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // Trigger shutdown during/after the first run
                    sd.request_shutdown();
                    Err(TaskError::Failed(
                        "drain error".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // Give it time to run
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Task must run exactly once and should NOT restart since shutdown was requested
    assert_eq!(run_count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_task_restarts_across_expired_window() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let clock = Arc::new(FakeClock::new());
    let supervisor = Supervisor::new_with_clock(profile, shutdown.clone(), clock.clone());

    let name = TaskName::new("expired-window-task");
    let run_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let run_count_clone = run_count.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy {
                max_restarts: 1, // Only allowed 1 restart per window
                window_secs: 1,  // 1 second window
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone.clone();
                Box::pin(async move {
                    rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(TaskError::Failed(
                        "temp fail".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // 1st run: fails. Restarts (since max_restarts is 1).
    tokio::task::yield_now().await;
    // The supervisor is now waiting in clock.sleep(backoff). We advance the clock to complete the backoff sleep.
    clock.advance(Duration::from_millis(2));
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // 2nd run: fails. failures_in_window becomes 2, which is > 1. Restart budget exhausted. It exits.
    assert_eq!(run_count.load(std::sync::atomic::Ordering::SeqCst), 2);

    // Advance fake time past the restart window.
    clock.advance(Duration::from_millis(1200));
    tokio::task::yield_now().await;

    // Spawn a new run after the window has expired
    let run_count_clone2 = run_count.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            RestartPolicy {
                max_restarts: 1,
                window_secs: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone2.clone();
                Box::pin(async move {
                    rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(TaskError::Failed(
                        "second window fail".into(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                }) as _
            },
        )
        .await
        .unwrap();

    // 3rd run: fails.
    // Since the window (1s) has expired since the last failure, failures_in_window is reset to 0, then becomes 1.
    // It should be allowed to restart!
    tokio::task::yield_now().await;
    // Advance clock past backoff to let the 4th run execute
    clock.advance(Duration::from_millis(2));
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // 4th run: fails. failures_in_window becomes 2. Restart budget exhausted. Exits.
    assert_eq!(run_count.load(std::sync::atomic::Ordering::SeqCst), 4);
}

#[tokio::test]
async fn heartbeat_monitor_detects_timeout_without_readiness_poll() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let clock = Arc::new(FakeClock::new());
    let supervisor = Supervisor::new_with_clock(profile, shutdown.clone(), clock.clone());
    let monitor = supervisor.start_heartbeat_monitor();

    tokio::task::yield_now().await;

    let name = TaskName::new("hung-fatal-task");
    supervisor
        .spawn_internal(
            name.clone(),
            TaskKind::ProtocolWorker,
            Criticality::Fatal,
            RestartPolicy::no_restart(),
            Some(Duration::from_millis(50)),
            || Box::pin(async { std::future::pending::<Result<(), TaskError>>().await }) as _,
        )
        .await
        .unwrap();

    for _ in 0..120 {
        if shutdown.is_shutdown_requested() {
            break;
        }
        clock.advance(Duration::from_millis(25));
        tokio::task::yield_now().await;
    }

    assert!(
        shutdown.is_shutdown_requested(),
        "background heartbeat monitor must trigger fatal shutdown"
    );
    let fatal = supervisor.fatal_task_failure().await;
    assert!(
        fatal.as_ref().is_some_and(|(task, _)| task == &name),
        "fatal failure should identify the hung task: {fatal:?}"
    );

    monitor.abort();
}

#[tokio::test]
async fn test_best_effort_clean_exit_no_restart_no_failure() {
    let profile = make_profile();
    let shutdown = ShutdownToken::new();
    let supervisor = Supervisor::new(profile, shutdown.clone());

    let name = TaskName::new("best-effort-clean-exit-task");
    let run_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let run_count_clone = run_count.clone();
    supervisor
        .spawn(
            name.clone(),
            TaskKind::BackgroundSync,
            Criticality::BestEffort,
            RestartPolicy {
                max_restarts: 3,
                window_secs: 60,
                base_backoff_ms: 1,
                max_backoff_ms: 10,
                jitter: 0.0,
            },
            move || {
                let rc = run_count_clone.clone();
                Box::pin(async move {
                    rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(()) // Exits cleanly
                }) as _
            },
        )
        .await
        .unwrap();

    // Give it time to run
    tokio::time::sleep(Duration::from_millis(50)).await;

    // BestEffort clean exit must run exactly once and should NOT restart or mark failed
    assert_eq!(run_count.load(std::sync::atomic::Ordering::SeqCst), 1);

    let readiness = supervisor.readiness().await;
    assert_eq!(readiness, Readiness::Ready);
}
