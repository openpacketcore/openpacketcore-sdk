use super::*;
use crate::runtime::UnixSignalKind;
use crate::task::TaskError;
use opc_alarm::{
    AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity,
    SharedAlarmManager,
};
use opc_crypto_provider::testkit::FakeCryptoModule;
use opc_crypto_provider::{
    probe_capability_report, CapabilitySet, CryptoCapability, PolicyError, ProviderIdentity,
    ProviderPolicy,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn try_with_init_error_returns_from_build() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-error-test".to_string(),
        ..Default::default()
    };

    let result = Builder::new(profile)
        .try_with_init(|_supervisor, _shutdown| {
            Box::pin(async { Err(RuntimeError::Supervisor("init failed".to_string())) })
        })
        .build()
        .await;

    match result {
        Err(RuntimeError::Supervisor(message)) => assert_eq!(message, "init failed"),
        other => panic!("expected init supervisor error, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn failed_try_with_init_never_promotes_ready() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-phase-test".to_string(),
        ..Default::default()
    };
    let phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let phases_for_observer = phases.clone();

    let result = Builder::new(profile)
        .with_phase_observer(move |phase| {
            phases_for_observer.lock().unwrap().push(phase);
        })
        .try_with_init(|_supervisor, _shutdown| {
            Box::pin(async { Err(RuntimeError::Supervisor("phase test failed".to_string())) })
        })
        .build()
        .await;

    assert!(matches!(result, Err(RuntimeError::Supervisor(_))));
    let observed = phases.lock().unwrap().clone();
    assert!(
        !observed.contains(&RuntimePhase::Ready),
        "failed init must not notify Ready: {observed:?}"
    );
    assert!(
        observed.contains(&RuntimePhase::Stopped),
        "startup-abort cleanup should stop the runtime: {observed:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn failed_try_with_init_after_spawn_cleans_up_task() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-cleanup-test".to_string(),
        drain_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let dropped = Arc::new(AtomicBool::new(false));
    let (started_tx, mut started_rx) = tokio::sync::watch::channel(false);

    let result = Builder::new(profile)
        .try_with_init({
            let dropped = dropped.clone();
            move |supervisor, _shutdown| {
                let dropped = dropped.clone();
                let started_tx = started_tx.clone();
                Box::pin(async move {
                    supervisor
                        .spawn(
                            TaskName::new("partially-started-task"),
                            TaskKind::ProtocolWorker,
                            Criticality::Fatal,
                            RestartPolicy::no_restart(),
                            move || {
                                let dropped = dropped.clone();
                                let started_tx = started_tx.clone();
                                Box::pin(async move {
                                    let _guard = DropFlag(dropped);
                                    started_tx.send_replace(true);
                                    std::future::pending::<Result<(), TaskError>>().await
                                })
                            },
                        )
                        .await?;

                    while !*started_rx.borrow_and_update() {
                        if started_rx.changed().await.is_err() {
                            break;
                        }
                    }

                    Err(RuntimeError::Supervisor(
                        "init failed after spawn".to_string(),
                    ))
                })
            }
        })
        .build()
        .await;

    assert!(matches!(result, Err(RuntimeError::Supervisor(_))));
    assert!(
        dropped.load(Ordering::SeqCst),
        "startup-abort cleanup must stop partially spawned tasks"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn successful_try_with_init_spawns_listener_before_ready() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-listener-test".to_string(),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .try_with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("required-listener"),
                        TaskKind::Listener,
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
                    .await?;
                Ok(())
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_runtime_phase(&handle, RuntimePhase::Ready).await;
    assert_eq!(handle.readiness().await, Readiness::Ready);
    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn successful_try_with_init_gated_listener_waits_for_ready_signal() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-gated-listener-test".to_string(),
        ..Default::default()
    };
    let (serve_tx, serve_rx) = tokio::sync::watch::channel(false);

    let handle = Builder::new(profile)
        .try_with_init(move |supervisor, shutdown| {
            let serve_rx = serve_rx.clone();
            Box::pin(async move {
                let task_name = TaskName::new("gated-required-listener");
                supervisor
                    .register(
                        task_name.clone(),
                        TaskKind::Listener,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                    )
                    .await?;
                supervisor.set_readiness_gated(&task_name, true).await;

                let supervisor_for_task = supervisor.clone();
                let task_name_for_task = task_name.clone();
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        task_name,
                        TaskKind::Listener,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        move || {
                            let supervisor_for_task = supervisor_for_task.clone();
                            let task_name_for_task = task_name_for_task.clone();
                            let task_shutdown = task_shutdown.clone();
                            let mut serve_rx = serve_rx.clone();
                            Box::pin(async move {
                                while !*serve_rx.borrow_and_update() {
                                    if serve_rx.changed().await.is_err() {
                                        return Ok(());
                                    }
                                }
                                supervisor_for_task
                                    .set_task_ready(&task_name_for_task, true)
                                    .await;
                                task_shutdown.shutdown_acknowledged().await;
                                Ok(())
                            })
                        },
                    )
                    .await?;
                Ok(())
            })
        })
        .build()
        .await
        .unwrap();

    assert_eq!(handle.phase().await, RuntimePhase::PeerWarmup);
    assert_eq!(handle.readiness().await, Readiness::NotReady);

    serve_tx.send_replace(true);
    wait_for_runtime_phase(&handle, RuntimePhase::Ready).await;
    assert_eq!(handle.readiness().await, Readiness::Ready);
    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_registration_during_try_with_init_fails_build() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-duplicate-register-test".to_string(),
        ..Default::default()
    };

    let result = Builder::new(profile)
        .try_with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                let task_name = TaskName::new("duplicate-task");
                supervisor
                    .register(
                        task_name.clone(),
                        TaskKind::Listener,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                    )
                    .await?;
                supervisor
                    .register(
                        task_name,
                        TaskKind::Listener,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                    )
                    .await?;
                Ok(())
            })
        })
        .build()
        .await;

    match result {
        Err(RuntimeError::Supervisor(message)) => {
            assert!(message.contains("already registered"));
        }
        other => panic!("expected duplicate registration error, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_running_spawn_during_try_with_init_fails_build() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fallible-init-duplicate-spawn-test".to_string(),
        drain_timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let result = Builder::new(profile)
        .try_with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                let task_name = TaskName::new("duplicate-running-task");
                supervisor
                    .spawn(
                        task_name.clone(),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || Box::pin(std::future::pending::<Result<(), TaskError>>()),
                    )
                    .await?;
                supervisor
                    .spawn(
                        task_name,
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || Box::pin(std::future::pending::<Result<(), TaskError>>()),
                    )
                    .await?;
                Ok(())
            })
        })
        .build()
        .await;

    match result {
        Err(RuntimeError::Supervisor(message)) => {
            assert!(message.contains("already running"));
        }
        other => panic!("expected duplicate running task error, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn try_run_returns_init_error() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "try-run-init-error-test".to_string(),
        ..Default::default()
    };

    let result = try_run(profile, |_supervisor, _shutdown| {
        Box::pin(async { Err(RuntimeError::Supervisor("try_run init failed".to_string())) })
    })
    .await;

    match result {
        Err(RuntimeError::Supervisor(message)) => assert_eq!(message, "try_run init failed"),
        other => panic!("expected try_run init error, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn try_run_with_hooks_returns_init_error() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "try-run-hooks-init-error-test".to_string(),
        ..Default::default()
    };

    let result = try_run_with_hooks(profile, Vec::new(), |_supervisor, _shutdown| {
        Box::pin(async {
            Err(RuntimeError::Supervisor(
                "try_run_with_hooks init failed".to_string(),
            ))
        })
    })
    .await;

    match result {
        Err(RuntimeError::Supervisor(message)) => {
            assert_eq!(message, "try_run_with_hooks init failed");
        }
        other => panic!("expected try_run_with_hooks init error, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn try_with_init_replaces_prior_with_init_callback() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "init-replacement-try-wins-test".to_string(),
        ..Default::default()
    };
    let marker = Arc::new(AtomicUsize::new(0));

    let handle = Builder::new(profile)
        .with_init({
            let marker = marker.clone();
            move |_supervisor, _shutdown| {
                Box::pin(async move {
                    marker.store(1, Ordering::SeqCst);
                })
            }
        })
        .try_with_init({
            let marker = marker.clone();
            move |_supervisor, _shutdown| {
                Box::pin(async move {
                    marker.store(2, Ordering::SeqCst);
                    Ok(())
                })
            }
        })
        .build()
        .await
        .unwrap();

    assert_eq!(marker.load(Ordering::SeqCst), 2);
    handle.complete_shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn with_init_replaces_prior_try_with_init_callback() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "init-replacement-with-wins-test".to_string(),
        ..Default::default()
    };
    let marker = Arc::new(AtomicUsize::new(0));

    let handle = Builder::new(profile)
        .try_with_init({
            let marker = marker.clone();
            move |_supervisor, _shutdown| {
                Box::pin(async move {
                    marker.store(1, Ordering::SeqCst);
                    Ok(())
                })
            }
        })
        .with_init({
            let marker = marker.clone();
            move |_supervisor, _shutdown| {
                Box::pin(async move {
                    marker.store(2, Ordering::SeqCst);
                })
            }
        })
        .build()
        .await
        .unwrap();

    assert_eq!(marker.load(Ordering::SeqCst), 2);
    handle.complete_shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn wait_stopped_returns_immediately_when_already_stopped() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "wait-stopped-already-stopped-test".to_string(),
        ..Default::default()
    };
    let handle = Builder::new(profile).build().await.unwrap();
    handle.complete_shutdown().await;

    tokio::time::timeout(Duration::from_millis(50), handle.wait_stopped())
        .await
        .expect("wait_stopped should return immediately for stopped runtime");
}

#[tokio::test(flavor = "current_thread")]
async fn wait_stopped_completes_after_explicit_shutdown() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "wait-stopped-explicit-shutdown-test".to_string(),
        drain_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let handle = Builder::new(profile)
        .with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("explicit-shutdown-task"),
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

    handle.shutdown().await;
    tokio::time::timeout(Duration::from_millis(50), handle.wait_stopped())
        .await
        .expect("wait_stopped should complete after explicit shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn wait_stopped_completes_after_complete_shutdown() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "wait-stopped-complete-shutdown-test".to_string(),
        drain_timeout: Duration::from_millis(50),
        ..Default::default()
    };
    let handle = Builder::new(profile)
        .with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("complete-shutdown-task"),
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

    handle.complete_shutdown().await;
    tokio::time::timeout(Duration::from_millis(50), handle.wait_stopped())
        .await
        .expect("wait_stopped should complete after complete_shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn wait_stopped_completes_after_fatal_task_failure() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "wait-stopped-fatal-task-test".to_string(),
        shutdown_grace: Duration::from_millis(1),
        drain_timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("fatal-wait-stopped-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                Err(TaskError::Failed(
                                    "fatal wait_stopped failure".to_string(),
                                    std::sync::Arc::new(std::io::Error::other("fatal")),
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

    tokio::time::timeout(Duration::from_secs(1), handle.wait_stopped())
        .await
        .expect("wait_stopped should complete after fatal task shutdown");
    assert!(handle.supervisor().fatal_task_failure().await.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn wait_stopped_wakes_multiple_concurrent_waiters() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "wait-stopped-multi-waiter-test".to_string(),
        shutdown_grace: Duration::from_millis(1),
        drain_timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("multi-waiter-task"),
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

    let waiters = (0..4)
        .map(|_| {
            let handle = handle.clone();
            tokio::spawn(async move {
                handle.wait_stopped().await;
            })
        })
        .collect::<Vec<_>>();

    handle.shutdown().await;

    for waiter in waiters {
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be notified")
            .expect("waiter task should not panic");
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
        "Wrong error: {err}"
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
        "Wrong error: {err2}"
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
        "Wrong error: {err}"
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

// =============================================================================
// SecurityInit startup hook (issue #334, slice 2)
// =============================================================================

fn crypto_fixture_module(capabilities: CapabilitySet) -> Arc<FakeCryptoModule> {
    let identity = match ProviderIdentity::from_parts("runtime fixture", "0.0.1") {
        Ok(identity) => identity,
        Err(error) => panic!("valid identity labels: {error}"),
    };
    Arc::new(FakeCryptoModule::new(identity).with_advertised_capabilities(capabilities))
}

/// Startup phases whose `SecurityInit` hook probes `module` and admits it
/// against `policy`, mapping a typed policy rejection into
/// `BootstrapError::SecurityInit` — the consumer-side wiring this slice
/// enables.
fn crypto_admission_phases(module: Arc<FakeCryptoModule>, policy: ProviderPolicy) -> StartupPhases {
    StartupPhases {
        init_security: Some(Box::new(move |_profile: &RuntimeProfile| {
            let module = module.clone();
            Box::pin(async move {
                let report = probe_capability_report(module.as_ref()).await;
                policy
                    .admit(&report)
                    .map(|_admission| ())
                    .map_err(|err| BootstrapError::SecurityInit(Box::new(err)))
            })
        })),
        ..Default::default()
    }
}

#[tokio::test]
async fn startup_phases_init_security_defaults_to_noop() {
    let phases = StartupPhases::default();
    assert!(phases.init_security.is_none());
    assert!(phases
        .init_security(&RuntimeProfile::default())
        .await
        .is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn failing_security_init_hook_fails_build_before_any_listener_exists() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "security-init-failure-test".to_string(),
        ..Default::default()
    };
    let observed_phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let phases_for_observer = observed_phases.clone();
    let listener_constructed = Arc::new(AtomicBool::new(false));
    let listener_flag = listener_constructed.clone();

    let phases = StartupPhases {
        init_security: Some(Box::new(|_profile: &RuntimeProfile| {
            Box::pin(async {
                Err(BootstrapError::SecurityInit(Box::new(
                    std::io::Error::other("required crypto capability unavailable"),
                )))
            })
        })),
        ..Default::default()
    };

    let result = Builder::new(profile)
        .with_phases(phases)
        .with_phase_observer(move |phase| {
            phases_for_observer.lock().unwrap().push(phase);
        })
        .try_with_init(move |_supervisor, _shutdown| {
            let listener_flag = listener_flag.clone();
            Box::pin(async move {
                // A product binds its listeners here (see the crate docs);
                // recording the flag stands in for listener construction.
                listener_flag.store(true, Ordering::SeqCst);
                Ok(())
            })
        })
        .build()
        .await;

    match result {
        Err(RuntimeError::Bootstrap(err)) => assert!(
            matches!(
                err.downcast_ref::<BootstrapError>(),
                Some(BootstrapError::SecurityInit(_))
            ),
            "expected SecurityInit bootstrap error, got {err:?}"
        ),
        other => panic!("expected bootstrap error from failed security init, got {other:?}"),
    }
    assert!(
        !listener_constructed.load(Ordering::SeqCst),
        "no listener may ever be constructed after a SecurityInit failure"
    );
    let observed = observed_phases.lock().unwrap().clone();
    assert_eq!(
        observed,
        vec![
            RuntimePhase::ProcessInit,
            RuntimePhase::TelemetryInit,
            RuntimePhase::SecurityInit,
        ],
        "failure must abort before ConfigBootstrap/ResourcePreflight/ServiceBind/PeerWarmup"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn security_init_hook_success_runs_in_phase_order_and_allows_ready() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "security-init-success-test".to_string(),
        ..Default::default()
    };
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let events_for_observer = events.clone();
    let events_for_hook = events.clone();

    let phases = StartupPhases {
        init_security: Some(Box::new(move |_profile: &RuntimeProfile| {
            let events_for_hook = events_for_hook.clone();
            Box::pin(async move {
                events_for_hook
                    .lock()
                    .unwrap()
                    .push("init_security".to_string());
                Ok(())
            })
        })),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_phases(phases)
        .with_phase_observer(move |phase| {
            events_for_observer.lock().unwrap().push(phase.to_string());
        })
        .try_with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("security-init-success-listener"),
                        TaskKind::Listener,
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
                    .await?;
                Ok(())
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_runtime_phase(&handle, RuntimePhase::Ready).await;
    assert_eq!(handle.readiness().await, Readiness::Ready);
    handle.shutdown().await;

    let recorded = events.lock().unwrap().clone();
    let position = |name: &str| {
        recorded
            .iter()
            .position(|event| event == name)
            .unwrap_or_else(|| panic!("event {name:?} not recorded: {recorded:?}"))
    };
    assert_eq!(
        recorded
            .iter()
            .filter(|event| *event == "init_security")
            .count(),
        1,
        "security hook must run exactly once: {recorded:?}"
    );
    assert!(
        position("SecurityInit") < position("init_security"),
        "hook must run inside the SecurityInit phase: {recorded:?}"
    );
    assert!(
        position("init_security") < position("ConfigBootstrap"),
        "hook must finish before ConfigBootstrap: {recorded:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn absent_security_init_hook_keeps_existing_startup_sequence() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "security-init-absent-test".to_string(),
        ..Default::default()
    };
    let observed_phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let phases_for_observer = observed_phases.clone();

    // Default StartupPhases: no security hook configured. Startup must behave
    // exactly as it did before the hook existed.
    let handle = Builder::new(profile)
        .with_phase_observer(move |phase| {
            phases_for_observer.lock().unwrap().push(phase);
        })
        .try_with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("security-init-absent-listener"),
                        TaskKind::Listener,
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
                    .await?;
                Ok(())
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_runtime_phase(&handle, RuntimePhase::Ready).await;
    assert_eq!(handle.readiness().await, Readiness::Ready);
    handle.shutdown().await;

    let observed = observed_phases.lock().unwrap().clone();
    assert!(
        observed.len() >= 8,
        "expected the full startup sequence: {observed:?}"
    );
    assert_eq!(
        &observed[..8],
        &[
            RuntimePhase::ProcessInit,
            RuntimePhase::TelemetryInit,
            RuntimePhase::SecurityInit,
            RuntimePhase::ConfigBootstrap,
            RuntimePhase::ResourcePreflight,
            RuntimePhase::ServiceBind,
            RuntimePhase::PeerWarmup,
            RuntimePhase::Ready,
        ],
        "absent hook must preserve the pre-hook startup sequence"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn missing_required_crypto_capability_fails_startup_before_service_bind() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "crypto-admission-reject-test".to_string(),
        ..Default::default()
    };
    let module = crypto_fixture_module(CapabilitySet::empty());
    let policy = ProviderPolicy::new().require(CryptoCapability::Tls);
    let observed_phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let phases_for_observer = observed_phases.clone();
    let listener_constructed = Arc::new(AtomicBool::new(false));
    let listener_flag = listener_constructed.clone();

    let result = Builder::new(profile)
        .with_phases(crypto_admission_phases(module, policy))
        .with_phase_observer(move |phase| {
            phases_for_observer.lock().unwrap().push(phase);
        })
        .try_with_init(move |_supervisor, _shutdown| {
            let listener_flag = listener_flag.clone();
            Box::pin(async move {
                listener_flag.store(true, Ordering::SeqCst);
                Ok(())
            })
        })
        .build()
        .await;

    match result {
        Err(RuntimeError::Bootstrap(err)) => match err.downcast_ref::<BootstrapError>() {
            Some(BootstrapError::SecurityInit(source)) => {
                match source.downcast_ref::<PolicyError>() {
                    Some(PolicyError::CapabilityUnavailable { missing }) => assert_eq!(
                        *missing,
                        CapabilitySet::from_slice(&[CryptoCapability::Tls]),
                        "expected exactly the unadvertised capability to be reported missing"
                    ),
                    other => {
                        panic!("expected a typed CapabilityUnavailable rejection, got {other:?}")
                    }
                }
            }
            other => panic!("expected SecurityInit bootstrap error, got {other:?}"),
        },
        other => panic!("expected bootstrap error from rejected admission, got {other:?}"),
    }
    assert!(
        !listener_constructed.load(Ordering::SeqCst),
        "no listener may be constructed when crypto admission is rejected"
    );
    let observed = observed_phases.lock().unwrap().clone();
    assert!(
        !observed.contains(&RuntimePhase::ConfigBootstrap)
            && !observed.contains(&RuntimePhase::ServiceBind)
            && !observed.contains(&RuntimePhase::Ready),
        "rejected admission must abort before ConfigBootstrap/ServiceBind: {observed:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn advertised_crypto_capability_admits_and_startup_completes() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "crypto-admission-accept-test".to_string(),
        ..Default::default()
    };
    let module = crypto_fixture_module(CapabilitySet::empty().with(CryptoCapability::Tls));
    let policy = ProviderPolicy::new().require(CryptoCapability::Tls);

    let handle = Builder::new(profile)
        .with_phases(crypto_admission_phases(module.clone(), policy))
        .try_with_init(|supervisor, shutdown| {
            Box::pin(async move {
                let task_shutdown = shutdown.clone();
                supervisor
                    .spawn(
                        TaskName::new("crypto-admission-accept-listener"),
                        TaskKind::Listener,
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
                    .await?;
                Ok(())
            })
        })
        .build()
        .await
        .unwrap();

    wait_for_runtime_phase(&handle, RuntimePhase::Ready).await;
    assert_eq!(handle.readiness().await, Readiness::Ready);
    handle.shutdown().await;

    // Observability companion: the admitted module's bounded report attaches
    // to the crypto provider gate. The gate reports; the SecurityInit hook
    // above is what enforced.
    let report = probe_capability_report(module.as_ref()).await;
    let gates = HealthGateSet::new().with_gate(
        HealthGate::new(known_gates::CRYPTO_PROVIDER, GateImpact::BlocksReadiness)
            .with_status(GateStatus::Passing)
            .with_details(serde_json::to_value(&report).unwrap()),
    );
    assert_eq!(gates.readiness(), Readiness::Ready);
    let json = serde_json::to_string(&gates).unwrap();
    assert!(json.contains("\"crypto_provider\":"));
    assert!(json.contains("\"effective\":[\"tls\"]"));
}
