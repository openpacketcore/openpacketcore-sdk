use super::*;
use crate::runtime::UnixSignalKind;
use crate::task::TaskError;
use opc_alarm::{
    AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity,
    SharedAlarmManager,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn test_builder_installs_panic_hook_during_process_init() {
    let instance_id = uuid::Uuid::new_v4();
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "panic-hook-test".to_string(),
        instance_id,
        ..Default::default()
    };

    let handle = Builder::new(profile.clone()).build().await.unwrap();

    // Read metadata from the handle — not from the global — so this test
    // is deterministic regardless of parallel test execution order.
    assert_eq!(handle.panic_hook_metadata.nf_kind, profile.nf_kind);
    assert_eq!(handle.panic_hook_metadata.instance_id, instance_id);
}

#[tokio::test]
async fn test_run_returns_fatal_task_failure() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fatal-run-test".to_string(),
        ..Default::default()
    };

    let result = run(profile, |supervisor, _shutdown| {
        Box::pin(async move {
            supervisor
                .spawn(
                    TaskName::new("fatal-run-task"),
                    TaskKind::ProtocolWorker,
                    Criticality::Fatal,
                    RestartPolicy::no_restart(),
                    || {
                        Box::pin(async {
                            Err(TaskError::Failed(
                                "fatal run failure".to_string(),
                                std::sync::Arc::new(std::io::Error::other("fatal test")),
                            ))
                        })
                    },
                )
                .await
                .unwrap();
        })
    })
    .await;

    match result {
        Err(RuntimeError::TaskCriticalFailure(task, TaskError::Failed(message, _))) => {
            assert_eq!(task, "fatal-run-task");
            assert_eq!(message, "fatal run failure");
        }
        other => panic!("expected fatal task failure, got {other:?}"),
    }
}

async fn wait_for_active_alarm_count(alarms: &SharedAlarmManager, expected: usize) {
    for _ in 0..50 {
        if alarms.active_count() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "expected {expected} active alarms, got {} with history {:?}",
        alarms.active_count(),
        alarms.all_alarms()
    );
}

async fn wait_for_runtime_phase(handle: &RuntimeHandle, expected: RuntimePhase) {
    for _ in 0..50 {
        if handle.phase().await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("runtime did not reach phase {expected:?}");
}

#[tokio::test]
async fn runtime_readiness_tracks_active_alarm_impact() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "alarm-readiness-test".to_string(),
        ..Default::default()
    };
    let alarms = SharedAlarmManager::default();

    let handle = Builder::new(profile)
        .with_alarm_manager(alarms.clone())
        .with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("ready-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        move || {
                            let task_shutdown = task_shutdown.clone();
                            Box::pin(async move {
                                task_shutdown.shutdown_acknowledged().await;
                                Ok(())
                            })
                        },
                    )
                    .await
                    .unwrap();
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_runtime_phase(&handle, RuntimePhase::Ready).await;
    assert_eq!(handle.readiness().await, Readiness::Ready);

    let affected_object = AffectedObject::NfInstance {
        kind: "alarm-readiness-test".to_string(),
        instance: "1".to_string(),
    };
    alarms.raise(
        AlarmType::new("alarm-readiness-test.major"),
        Severity::Major,
        ProbableCause::ConfigApplyFailed,
        affected_object.clone(),
        Some("system".to_string()),
        None,
        None,
        RedactedText::new("major test alarm"),
        AlarmDetails::empty(),
    );
    assert_eq!(handle.readiness().await, Readiness::Degraded);

    alarms.raise(
        AlarmType::new("alarm-readiness-test.critical"),
        Severity::Critical,
        ProbableCause::ConfigApplyFailed,
        affected_object.clone(),
        Some("system".to_string()),
        None,
        None,
        RedactedText::new("critical test alarm"),
        AlarmDetails::empty(),
    );
    assert_eq!(handle.readiness().await, Readiness::NotReady);

    alarms.clear(
        &AlarmType::new("alarm-readiness-test.critical"),
        ProbableCause::ConfigApplyFailed,
        &affected_object,
        Some("system"),
        None,
        None,
    );
    assert_eq!(handle.readiness().await, Readiness::Degraded);

    handle.shutdown().await;
}

#[tokio::test]
async fn runtime_clears_stale_task_failure_alarm_after_healthy_restart() {
    let instance_id = uuid::Uuid::new_v4();
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "restart-alarm-test".to_string(),
        instance_id,
        ..Default::default()
    };
    let alarms = SharedAlarmManager::default();

    let failed = Builder::new(profile.clone())
        .with_alarm_manager(alarms.clone())
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("fatal-startup-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                Err(TaskError::Failed(
                                    "fatal startup task".to_string(),
                                    std::sync::Arc::new(std::io::Error::other("boom")),
                                ))
                            })
                        },
                    )
                    .await
                    .unwrap();
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_active_alarm_count(&alarms, 1).await;
    let active = alarms.active_alarms();
    assert_eq!(active[0].severity, Severity::Critical);
    assert_eq!(
        active[0].probable_cause,
        ProbableCause::Other("opc-runtime.task-failure".to_string())
    );
    assert_eq!(
        active[0].alarm_type.as_str(),
        "restart-alarm-test.runtime.task.failure.fatal-startup-task"
    );

    failed.complete_shutdown().await;

    let healthy = Builder::new(profile)
        .with_alarm_manager(alarms.clone())
        .with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("healthy-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        move || {
                            let task_shutdown = task_shutdown.clone();
                            Box::pin(async move {
                                task_shutdown.shutdown_acknowledged().await;
                                Ok(())
                            })
                        },
                    )
                    .await
                    .unwrap();
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_runtime_phase(&healthy, RuntimePhase::Ready).await;
    wait_for_active_alarm_count(&alarms, 0).await;
    assert_eq!(
        alarms
            .all_alarms()
            .iter()
            .map(|alarm| alarm.state)
            .collect::<Vec<_>>(),
        vec![
            opc_alarm::AlarmState::Raised,
            opc_alarm::AlarmState::Cleared
        ]
    );
    healthy.shutdown().await;
}

#[derive(Debug, thiserror::Error)]
#[error("custom test error: {message}")]
struct CustomTestError {
    message: String,
}

#[test]
fn test_task_error_clone_preserves_source_type() {
    let original_source = CustomTestError {
        message: "inner details".to_string(),
    };
    let err = TaskError::Failed("my-task".to_string(), std::sync::Arc::new(original_source));

    let cloned_err = err.clone();

    match cloned_err {
        TaskError::Failed(task, source) => {
            assert_eq!(task, "my-task");
            let downcasted = source
                .downcast_ref::<CustomTestError>()
                .expect("original error type must be preserved in cloned source");
            assert_eq!(downcasted.message, "inner details");
        }
        _ => panic!("expected TaskError::Failed"),
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn test_builder_fails_closed_when_sigterm_registration_fails() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Production,
        nf_kind: "sigterm-fail-closed-test".to_string(),
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let result = Builder::new(profile)
        .with_signal_factory(Arc::new(|kind| match kind {
            UnixSignalKind::Sigterm => Err(std::io::Error::other("sigterm disabled for test")),
            UnixSignalKind::Sigint => kind.register(),
        }))
        .build()
        .await;

    match result {
        Err(RuntimeError::Bootstrap(source)) => {
            let message = source.to_string();
            assert!(
                message.contains("SIGTERM"),
                "unexpected error message: {message}"
            );
        }
        other => {
            panic!("expected bootstrap failure when SIGTERM registration fails, got {other:?}")
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn test_builder_allows_sigterm_registration_failure_in_dev_when_sigint_is_available() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "sigterm-dev-fallback-test".to_string(),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_signal_factory(Arc::new(|kind| match kind {
            UnixSignalKind::Sigterm => Err(std::io::Error::other("sigterm disabled for test")),
            UnixSignalKind::Sigint => kind.register(),
        }))
        .build()
        .await
        .expect("dev mode should continue when SIGINT remains available");

    assert!(
        handle.signal_handle.is_some(),
        "SIGINT should keep signal handling active when SIGTERM is unavailable in dev mode"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn test_builder_skips_sigint_registration_when_disabled_in_production() {
    let sigterm_calls = Arc::new(AtomicUsize::new(0));
    let sigint_calls = Arc::new(AtomicUsize::new(0));
    let sigterm_calls_for_factory = sigterm_calls.clone();
    let sigint_calls_for_factory = sigint_calls.clone();

    let profile = RuntimeProfile {
        mode: RuntimeMode::Production,
        nf_kind: "sigint-disabled-production-test".to_string(),
        sigint_handling: SigintHandling::Disabled,
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_signal_factory(Arc::new(move |kind| match kind {
            UnixSignalKind::Sigterm => {
                sigterm_calls_for_factory.fetch_add(1, Ordering::SeqCst);
                kind.register()
            }
            UnixSignalKind::Sigint => {
                sigint_calls_for_factory.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::other(
                    "sigint should not be registered when disabled",
                ))
            }
        }))
        .build()
        .await
        .expect("production mode should still install SIGTERM when SIGINT is disabled");

    assert_eq!(sigterm_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        sigint_calls.load(Ordering::SeqCst),
        0,
        "SIGINT registration should be skipped when disabled"
    );
    assert!(
        handle.signal_handle.is_some(),
        "SIGTERM alone should keep signal handling active"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn test_builder_can_explicitly_enable_sigint_in_production() {
    let sigint_calls = Arc::new(AtomicUsize::new(0));
    let sigint_calls_for_factory = sigint_calls.clone();

    let profile = RuntimeProfile {
        mode: RuntimeMode::Production,
        nf_kind: "sigint-enabled-production-test".to_string(),
        sigint_handling: SigintHandling::GracefulShutdown,
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_signal_factory(Arc::new(move |kind| match kind {
            UnixSignalKind::Sigterm => kind.register(),
            UnixSignalKind::Sigint => {
                sigint_calls_for_factory.fetch_add(1, Ordering::SeqCst);
                kind.register()
            }
        }))
        .build()
        .await
        .expect("production mode should allow explicitly enabling SIGINT");

    assert_eq!(
        sigint_calls.load(Ordering::SeqCst),
        1,
        "explicit production SIGINT handling should register the signal stream"
    );
    assert!(handle.signal_handle.is_some());
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn test_builder_fails_closed_when_explicit_sigint_registration_fails() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Production,
        nf_kind: "sigint-fail-closed-test".to_string(),
        sigint_handling: SigintHandling::GracefulShutdown,
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let result = Builder::new(profile)
        .with_signal_factory(Arc::new(|kind| match kind {
            UnixSignalKind::Sigterm => kind.register(),
            UnixSignalKind::Sigint => Err(std::io::Error::other("sigint disabled for test")),
        }))
        .build()
        .await;

    match result {
        Err(RuntimeError::Bootstrap(source)) => {
            let message = source.to_string();
            assert!(
                message.contains("SIGINT"),
                "unexpected error message: {message}"
            );
        }
        other => {
            panic!(
                "expected bootstrap failure when explicit SIGINT registration fails, got {other:?}"
            )
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn test_dropping_last_runtime_handle_cleans_up_background_resources() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "drop-cleanup-test".to_string(),
        ..Default::default()
    };

    let handle = Builder::new(profile).build().await.unwrap();
    let signal_weak = Arc::downgrade(
        handle
            .signal_handle
            .as_ref()
            .expect("signal handler should be installed under unix"),
    );
    let drains_weak = Arc::downgrade(&handle.drains_executed);

    drop(handle);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if signal_weak.upgrade().is_none() && drains_weak.upgrade().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dropping the final runtime handle should tear down background resources");
}

#[tokio::test]
async fn test_production_budget_enforcement_fail_closed() {
    let profile_no_budget = RuntimeProfile {
        mode: RuntimeMode::Production,
        nf_kind: "budget-test".to_string(),
        budget: None,
        ..Default::default()
    };
    let res = Builder::new(profile_no_budget).build().await;
    assert!(
        res.is_err(),
        "Must fail closed without budget in production"
    );
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("Production profile requires an explicit ResourceBudget"),
        "Wrong error: {}",
        err
    );

    let profile_invalid_budget = RuntimeProfile {
        mode: RuntimeMode::Production,
        nf_kind: "budget-test".to_string(),
        budget: Some(ResourceBudget {
            max_tasks: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    let res2 = Builder::new(profile_invalid_budget).build().await;
    assert!(
        res2.is_err(),
        "Must fail closed with invalid budget in production"
    );
    let err2 = res2.unwrap_err().to_string();
    assert!(
        err2.contains("max_tasks must be > 0 and <= 100,000"),
        "Wrong error: {}",
        err2
    );
}

#[tokio::test]
async fn test_budget_limit_max_tasks_enforced() {
    crate::metrics::METRICS.reset_all();

    let budget = ResourceBudget {
        max_tasks: 2,
        ..Default::default()
    };

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "budget-limit-test".to_string(),
        budget: Some(budget),
        ..Default::default()
    };

    let handle = Builder::new(profile).build().await.unwrap();

    let supervisor = handle.supervisor();

    supervisor
        .spawn(
            TaskName::new("task-1"),
            TaskKind::ProtocolWorker,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            || Box::pin(async { Ok(()) }),
        )
        .await
        .unwrap();

    supervisor
        .spawn(
            TaskName::new("task-2"),
            TaskKind::ProtocolWorker,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            || Box::pin(async { Ok(()) }),
        )
        .await
        .unwrap();

    let res = supervisor
        .spawn(
            TaskName::new("task-3"),
            TaskKind::ProtocolWorker,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            || Box::pin(async { Ok(()) }),
        )
        .await;

    assert!(
        res.is_err(),
        "Must reject task registration exceeding budget max_tasks"
    );
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("Resource budget limit exceeded"),
        "Wrong error: {}",
        err
    );
    assert_eq!(
        crate::metrics::METRICS
            .runtime_budget_exhausted
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(!err.contains("secret"), "Errors must be redacted");
    assert!(!err.contains("/"), "Errors must not contain paths");

    handle.shutdown().await;
}
