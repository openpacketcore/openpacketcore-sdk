use opc_alarm::{Severity, SharedAlarmManager};
use opc_runtime::{
    Builder, Clock, Criticality, DrainHook, FakeClock, RestartPolicy, RuntimeMode, RuntimePhase,
    RuntimeProfile, TaskKind, TaskName,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// Every test here builds a runtime, and `Builder::build` registers a
// process-wide SIGTERM handler; the sequential wrapper actually delivers
// SIGTERM to the whole process. If two runtimes are live at once, a SIGTERM
// meant for one is also delivered to the other — a flaky cross-test race.
// Serialize every test so only one runtime (and one signal handler) exists at
// a time.
static SIGNAL_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct SimpleHook {
    called: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl DrainHook for SimpleHook {
    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.called.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct DelayedHook {
    called: Arc<AtomicBool>,
    clock: Arc<FakeClock>,
    delay: Duration,
    entered_sleep: Option<Arc<tokio::sync::Notify>>,
}

#[async_trait::async_trait]
impl DrainHook for DelayedHook {
    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(notify) = &self.entered_sleep {
            notify.notify_one();
        }
        self.clock.sleep(self.delay).await;
        self.called.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingHook {
    called: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl DrainHook for FailingHook {
    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.called.store(true, Ordering::SeqCst);
        Err(std::io::Error::other("failing hook error").into())
    }
}

struct ConfigurableFailingHook {
    called: Arc<AtomicBool>,
    error_msg: String,
}

#[async_trait::async_trait]
impl DrainHook for ConfigurableFailingHook {
    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.called.store(true, Ordering::SeqCst);
        Err(std::io::Error::other(self.error_msg.clone()).into())
    }
}

#[tokio::test]
async fn run_all_graceful_shutdown_tests_sequentially() {
    let _serial = SIGNAL_SERIAL.lock().await;
    println!("Starting sequential graceful shutdown tests...");
    println!("Running test_drain_hook_is_called_on_shutdown_impl...");
    test_drain_hook_is_called_on_shutdown_impl().await;
    println!("Running test_drain_hook_timeout_respects_fake_clock_impl...");
    test_drain_hook_timeout_respects_fake_clock_impl().await;
    println!("Running test_drain_hook_completes_when_fake_clock_advanced_impl...");
    test_drain_hook_completes_when_fake_clock_advanced_impl().await;
    println!("Running test_failing_drain_hook_does_not_abort_shutdown_impl...");
    test_failing_drain_hook_does_not_abort_shutdown_impl().await;
    println!("Running test_nrf_drain_hook_adapter_graceful_deregistration_impl...");
    test_nrf_drain_hook_adapter_graceful_deregistration_impl().await;
    println!("Running test_run_executes_hooks_impl...");
    test_run_executes_hooks_impl().await;
    println!("Running test_drain_hooks_are_idempotent_and_run_once_impl...");
    test_drain_hooks_are_idempotent_and_run_once_impl().await;
    println!("Running test_shutdown_immediate_drop_race_impl...");
    test_shutdown_immediate_drop_race_impl().await;
    println!("Running test_mistuned_budgets_starvation_impl...");
    test_mistuned_budgets_starvation_impl().await;
    println!("Running test_drain_incomplete_alarm_impl...");
    test_drain_incomplete_alarm_impl().await;
    println!("Running test_failing_drain_hook_raises_alarm_impl...");
    test_failing_drain_hook_raises_alarm_impl().await;
    println!("Running test_multiple_failing_drain_hooks_aggregated_alarm_impl...");
    test_multiple_failing_drain_hooks_aggregated_alarm_impl().await;
    println!("Running test_mixed_drain_hooks_executes_all_and_raises_alarm_impl...");
    test_mixed_drain_hooks_executes_all_and_raises_alarm_impl().await;
    println!("Running test_required_nrf_drain_hook_missing_fails_in_production_impl...");
    test_required_nrf_drain_hook_missing_fails_in_production_impl().await;
    println!("Running test_required_nrf_drain_hook_missing_warns_in_dev_impl...");
    test_required_nrf_drain_hook_missing_warns_in_dev_impl().await;

    #[cfg(unix)]
    {
        println!("Running test_sigterm_triggers_graceful_shutdown_impl...");
        test_sigterm_triggers_graceful_shutdown_impl().await;
        println!("Running test_sigterm_during_init_never_promotes_ready_impl...");
        test_sigterm_during_init_never_promotes_ready_impl().await;
    }
    println!("All sequential graceful shutdown tests passed successfully!");
}

async fn test_drain_hook_is_called_on_shutdown_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(SimpleHook {
        called: called.clone(),
    });

    let handle = Builder::new(profile)
        .with_drain_hook(hook)
        .build()
        .await
        .unwrap();

    assert!(!called.load(Ordering::SeqCst));

    handle.shutdown().await;

    assert!(
        called.load(Ordering::SeqCst),
        "Drain hook must be called on shutdown"
    );
}

async fn test_drain_hook_timeout_respects_fake_clock_impl() {
    let clock = Arc::new(FakeClock::new());

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(2), // 2 seconds grace
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let entered_sleep = Arc::new(tokio::sync::Notify::new());
    let hook = Arc::new(DelayedHook {
        called: called.clone(),
        clock: clock.clone(),
        delay: Duration::from_secs(5), // 5 seconds delay (exceeds grace)
        entered_sleep: Some(entered_sleep.clone()),
    });

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_drain_hook(hook)
        .build()
        .await
        .unwrap();

    assert!(!called.load(Ordering::SeqCst));

    // Spawn shutdown in a separate task since it will block on clock.sleep
    let handle_clone = handle.clone();
    let shutdown_task = tokio::spawn(async move {
        handle_clone.shutdown().await;
    });

    entered_sleep.notified().await;

    // Advance the clock past the 2 seconds shutdown grace limit, but before 5 seconds
    clock.advance(Duration::from_secs(3));

    // Wait for the shutdown sequence to complete
    shutdown_task.await.unwrap();

    // The hook should have timed out and therefore not set called to true
    assert!(
        !called.load(Ordering::SeqCst),
        "Drain hook must time out and not complete successfully"
    );
}

async fn test_drain_hook_completes_when_fake_clock_advanced_impl() {
    let clock = Arc::new(FakeClock::new());

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(10), // 10 seconds grace
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let entered_sleep = Arc::new(tokio::sync::Notify::new());
    let hook = Arc::new(DelayedHook {
        called: called.clone(),
        clock: clock.clone(),
        delay: Duration::from_secs(5), // 5 seconds delay (within grace)
        entered_sleep: Some(entered_sleep.clone()),
    });

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_drain_hook(hook)
        .build()
        .await
        .unwrap();

    assert!(!called.load(Ordering::SeqCst));

    // Spawn shutdown in a separate task
    let handle_clone = handle.clone();
    let shutdown_task = tokio::spawn(async move {
        handle_clone.shutdown().await;
    });

    entered_sleep.notified().await;

    // Advance the clock past the 5 seconds delay
    clock.advance(Duration::from_secs(6));

    // Wait for the shutdown sequence to complete
    shutdown_task.await.unwrap();

    // The hook should have successfully completed
    assert!(
        called.load(Ordering::SeqCst),
        "Drain hook must complete successfully when advanced"
    );
}

async fn test_failing_drain_hook_does_not_abort_shutdown_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(FailingHook {
        called: called.clone(),
    });

    let handle = Builder::new(profile)
        .with_drain_hook(hook)
        .build()
        .await
        .unwrap();

    assert!(!called.load(Ordering::SeqCst));

    // Shutdown should proceed and complete successfully even if the hook returns Err
    handle.shutdown().await;

    assert!(
        called.load(Ordering::SeqCst),
        "Failing drain hook must still be called on shutdown"
    );
}

#[cfg(unix)]
async fn test_sigterm_triggers_graceful_shutdown_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev, // Non-conformance mode to activate drain monitor
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_millis(150),
        drain_timeout: Duration::from_millis(400),
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(SimpleHook {
        called: called.clone(),
    });

    let handle = Builder::new(profile)
        .with_drain_hook(hook)
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("sigterm-slow-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Degrade,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(std::future::pending::<
                                Result<(), opc_runtime::task::TaskError>,
                            >())
                        },
                    )
                    .await
                    .unwrap();
            })
        })
        .build()
        .await
        .unwrap();

    assert!(!called.load(Ordering::SeqCst));

    let start_instant = std::time::Instant::now();

    // Send SIGTERM immediately (proving signal registration is synchronous in Builder::build)
    let pid = std::process::id();
    let status = std::process::Command::new("kill")
        .args(["-s", "TERM", &pid.to_string()])
        .status()
        .expect("should run kill command");

    assert!(status.success(), "kill command should succeed");

    tokio::time::timeout(Duration::from_secs(5), handle.wait_stopped())
        .await
        .expect("SIGTERM must trigger full graceful shutdown to Stopped phase within 5 seconds");
    assert!(
        called.load(Ordering::SeqCst),
        "SIGTERM must trigger the drain hook execution"
    );

    let elapsed = start_instant.elapsed();
    assert!(
        elapsed < Duration::from_millis(600),
        "Full graceful shutdown from SIGTERM took {elapsed:?}, exceeding the configured drain deadline"
    );
}

#[cfg(unix)]
async fn test_sigterm_during_init_never_promotes_ready_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_millis(100),
        ..Default::default()
    };

    let phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let init_started = Arc::new(tokio::sync::Notify::new());
    let release_init = Arc::new(tokio::sync::Notify::new());

    let phases_for_builder = phases.clone();
    let init_started_for_builder = init_started.clone();
    let release_init_for_builder = release_init.clone();

    let build_task = tokio::spawn(async move {
        Builder::new(profile)
            .with_phase_observer(move |phase| {
                phases_for_builder.lock().unwrap().push(phase);
            })
            .with_init(move |_supervisor, _shutdown| {
                Box::pin(async move {
                    init_started_for_builder.notify_one();
                    release_init_for_builder.notified().await;
                })
            })
            .build()
            .await
            .unwrap()
    });

    init_started.notified().await;

    let pid = std::process::id();
    let status = std::process::Command::new("kill")
        .args(["-s", "TERM", &pid.to_string()])
        .status()
        .expect("should run kill command");
    assert!(status.success(), "kill command should succeed");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            {
                let phases = phases.lock().unwrap();
                if phases.contains(&RuntimePhase::Draining) {
                    assert!(
                        !phases.contains(&RuntimePhase::Ready),
                        "runtime must not become ready after SIGTERM arrives during init"
                    );
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("SIGTERM during init should transition to Draining before init returns");

    release_init.notify_one();
    let handle = build_task.await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), handle.wait_stopped())
        .await
        .expect("runtime should complete shutdown after init is released");

    let phases = phases.lock().unwrap();
    assert!(
        !phases.contains(&RuntimePhase::Ready),
        "runtime must never report Ready when SIGTERM arrives during init"
    );
}

async fn test_nrf_drain_hook_adapter_graceful_deregistration_impl() {
    use opc_sbi::nrf::{NfProfile, NfStatus, NrfDrainHook};
    use opc_sbi::testkit::MockNrf;
    use opc_types::{NfInstanceId, NfType};

    let mock_nrf = Arc::new(MockNrf::new());
    let nf_instance_id = NfInstanceId::new("upf-01").unwrap();
    let profile = NfProfile {
        nf_instance_id: nf_instance_id.clone(),
        nf_type: NfType::new("upf").unwrap(),
        nf_status: NfStatus::Registered,
        ipv4_addresses: vec!["10.0.0.1".into()],
        fqdn: None,
        plmn_list: vec![],
        s_nssais: vec![],
        nf_services: vec![],
        priority: 10,
        capacity: 100,
    };

    // Register with mock NRF
    mock_nrf.register(profile).unwrap();
    assert!(
        mock_nrf.heartbeat(&nf_instance_id).is_ok(),
        "NF must be registered"
    );

    // Wrap in NrfDrainHook adapter
    let nrf_hook = Arc::new(NrfDrainHook::new(mock_nrf.clone(), nf_instance_id.clone()));

    let runtime_profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    // Register the adapter hook with opc_runtime
    let handle = Builder::new(runtime_profile)
        .with_drain_hook(nrf_hook)
        .build()
        .await
        .unwrap();

    // Trigger graceful shutdown
    handle.shutdown().await;

    // Verify NRF deregistration hook was actually called and NF is deregistered
    assert_eq!(
        mock_nrf.heartbeat(&nf_instance_id),
        Err(opc_sbi::testkit::MockNrfError::NotFound),
        "NF must be successfully deregistered from MockNrf during graceful shutdown"
    );
}

async fn test_run_executes_hooks_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(SimpleHook {
        called: called.clone(),
    });

    let shutdown_token_cell = Arc::new(tokio::sync::Mutex::new(None));
    let shutdown_token_cell_clone = shutdown_token_cell.clone();

    // Spawn run in background task
    let profile_clone = profile.clone();
    let hooks = vec![hook.clone() as Arc<dyn DrainHook>];
    let run_task = tokio::spawn(async move {
        opc_runtime::run_with_hooks(profile_clone, hooks, move |_supervisor, shutdown| {
            Box::pin(async move {
                let mut cell = shutdown_token_cell_clone.lock().await;
                *cell = Some(shutdown);
            })
        })
        .await
    });

    // Wait for shutdown token to be set by init callback
    let mut token = None;
    for _ in 0..50 {
        {
            let cell = shutdown_token_cell.lock().await;
            if cell.is_some() {
                token = cell.clone();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let token = token.unwrap();
    assert!(!called.load(Ordering::SeqCst));

    // Request graceful shutdown
    token.request_shutdown();

    // Wait for the runtime to exit
    run_task.await.unwrap().unwrap();

    // The registered hook must have been executed successfully
    assert!(
        called.load(Ordering::SeqCst),
        "run must execute the registered drain hooks"
    );
}

async fn test_drain_hooks_are_idempotent_and_run_once_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    struct CountHook {
        count: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl DrainHook for CountHook {
        async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let hook = Arc::new(CountHook {
        count: called_count.clone(),
    });

    let handle = Builder::new(profile)
        .with_drain_hook(hook)
        .build()
        .await
        .unwrap();

    assert_eq!(called_count.load(Ordering::SeqCst), 0);

    // Call shutdown first
    handle.shutdown().await;
    assert_eq!(called_count.load(Ordering::SeqCst), 1);

    // Call complete_shutdown next
    handle.complete_shutdown().await;
    assert_eq!(
        called_count.load(Ordering::SeqCst),
        1,
        "Drain hooks must only be executed once (idempotent)"
    );
}

#[tokio::test]
async fn test_phase_ready_timing_race_prevention() {
    let _serial = SIGNAL_SERIAL.lock().await;
    use opc_runtime::{Criticality, RestartPolicy, TaskKind};
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "test-cnf".to_string(),
        ..Default::default()
    };

    let phases = Arc::new(std::sync::Mutex::new(Vec::new()));
    let phases_clone = phases.clone();

    let _handle = Builder::new(profile)
        .with_phase_observer(move |phase| {
            phases_clone.lock().unwrap().push(phase);
        })
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                // 1. Spawn a task that becomes ready immediately
                supervisor
                    .spawn(
                        TaskName::new("task-immediate"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || Box::pin(async { Ok(()) }),
                    )
                    .await
                    .unwrap();

                // 2. Yield control to tokio to simulate scheduler interleaving
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(50)).await;

                // 3. Spawn a second task that is NOT ready (sleeps for 10s)
                supervisor
                    .spawn(
                        TaskName::new("task-delayed"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                tokio::time::sleep(Duration::from_secs(10)).await;
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

    let phases_snapshot = phases.lock().unwrap().clone();

    // VERIFICATION:
    // Under the raced implementation, the background monitor will have woken up when task-immediate
    // became ready (and task-delayed was not yet registered), transitioning the phase to Ready.
    // Under the fixed implementation, the background task will not run until AFTER both tasks are registered,
    // and since task-delayed is not ready, the runtime phase will remain at PeerWarmup.
    assert!(
        !phases_snapshot.contains(&RuntimePhase::Ready),
        "BUG: Runtime phase transitioned to Ready before all caller tasks finished spawning and became ready! Phases seen: {phases_snapshot:?}"
    );
}

#[tokio::test]
async fn test_fake_clock_monotonicity() {
    let _serial = SIGNAL_SERIAL.lock().await;
    let clock = FakeClock::synchronized();
    let base = clock.monotonic();
    clock.advance(Duration::from_secs(10));
    let elapsed = clock.monotonic().duration_since(base);
    assert_eq!(
        elapsed,
        Duration::from_secs(10),
        "monotonic time must advance correctly and not overflow base"
    );
}

#[tokio::test]
async fn test_degrade_count_recovery() {
    let _serial = SIGNAL_SERIAL.lock().await;
    use opc_runtime::{Criticality, RestartPolicy, TaskKind};

    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "test-cnf".to_string(),
        ..Default::default()
    };

    let restart_policy = RestartPolicy {
        max_restarts: 5,
        window_secs: 60,
        base_backoff_ms: 10,
        max_backoff_ms: 50,
        jitter: 0.0,
    };

    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failed_capture = failed.clone();
    let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let recovered_capture = recovered.clone();

    let clock = Arc::new(FakeClock::synchronized());

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_init(move |supervisor, _shutdown| {
            let failed_capture = failed_capture.clone();
            let recovered_capture = recovered_capture.clone();
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("task-degrade-recovery"),
                        TaskKind::ProtocolWorker,
                        Criticality::Degrade,
                        restart_policy,
                        move || {
                            let failed = failed_capture.clone();
                            let recovered = recovered_capture.clone();
                            Box::pin(async move {
                                if !failed.swap(true, Ordering::SeqCst) {
                                    Err(opc_runtime::TaskError::Aborted(
                                        "intentional failure".to_string(),
                                    ))
                                } else {
                                    recovered.store(true, Ordering::SeqCst);
                                    tokio::time::sleep(Duration::from_secs(3600)).await;
                                    Ok(())
                                }
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

    let supervisor = handle.supervisor();

    // Periodically advance the fake clock until the task is marked as recovered
    let mut success = false;
    for _ in 0..100 {
        if recovered.load(Ordering::SeqCst) {
            success = true;
            break;
        }
        clock.advance(Duration::from_millis(50));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(success, "Task did not recover in time");

    let health = supervisor.health().await;
    assert_eq!(
        health.degrade_count, 0,
        "degrade_count must be 0 after recovery. Health: {health:?}"
    );
}

#[tokio::test]
async fn test_single_task_shutdown_isolation() {
    let _serial = SIGNAL_SERIAL.lock().await;
    use opc_runtime::{Criticality, RestartPolicy, ShutdownPolicy, TaskKind};
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "test-cnf".to_string(),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                // Spawn task 1
                supervisor
                    .spawn(
                        TaskName::new("task-1"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                Ok(())
                            })
                        },
                    )
                    .await
                    .unwrap();

                // Spawn task 2
                supervisor
                    .spawn(
                        TaskName::new("task-2"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                tokio::time::sleep(Duration::from_secs(10)).await;
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

    let supervisor = handle.supervisor();

    // Verify both tasks are running initially
    let health_initial = supervisor.health().await;
    assert!(health_initial.task_states.get("task-1").unwrap().running);
    assert!(health_initial.task_states.get("task-2").unwrap().running);

    // Shutdown only task-1 immediately (abort)
    supervisor
        .shutdown_task(&TaskName::new("task-1"), ShutdownPolicy::Immediate)
        .await;

    // Verify task-1 is stopped but task-2 is still running!
    let health_after = supervisor.health().await;
    assert!(
        !health_after.task_states.get("task-1").unwrap().running,
        "task-1 must be stopped"
    );
    assert!(
        health_after.task_states.get("task-2").unwrap().running,
        "task-2 must still be running"
    );
}

#[tokio::test]
async fn test_high_concurrency_stress() {
    let _serial = SIGNAL_SERIAL.lock().await;
    use opc_runtime::{
        Criticality, RestartPolicy, RuntimeProfile, ShutdownPolicy, ShutdownToken, Supervisor,
        TaskKind,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;

    let profile = RuntimeProfile::conformance("stress-nf");
    let shutdown = ShutdownToken::new();
    let clock = Arc::new(opc_runtime::FakeClock::synchronized());
    let supervisor = Arc::new(Supervisor::new_with_clock(
        profile,
        shutdown.clone(),
        clock.clone(),
    ));

    // Target: Spawn 50 tasks concurrently
    let num_tasks = 50;
    let barrier = Arc::new(Barrier::new(num_tasks + 1));
    let mut join_handles = vec![];

    for i in 0..num_tasks {
        let supervisor = supervisor.clone();
        let barrier = barrier.clone();
        let name = opc_runtime::TaskName::new(format!("stress-task-{i}"));
        let restart_policy = RestartPolicy {
            max_restarts: 10,
            window_secs: 5,
            base_backoff_ms: 1,
            max_backoff_ms: 10,
            jitter: 0.1,
        };

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            // Randomize whether we call register or spawn first to test all paths
            if i % 2 == 0 {
                let _ = supervisor
                    .register(
                        name.clone(),
                        TaskKind::ProtocolWorker,
                        if i % 3 == 0 {
                            Criticality::Fatal
                        } else if i % 3 == 1 {
                            Criticality::Degrade
                        } else {
                            Criticality::BestEffort
                        },
                        restart_policy,
                    )
                    .await;
            }

            // Spawn a task that fails occasionally
            let rc = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let _ = supervisor
                .spawn(
                    name.clone(),
                    TaskKind::ProtocolWorker,
                    if i % 3 == 0 {
                        Criticality::Fatal
                    } else if i % 3 == 1 {
                        Criticality::Degrade
                    } else {
                        Criticality::BestEffort
                    },
                    restart_policy,
                    move || {
                        let rc = rc.clone();
                        Box::pin(async move {
                            let count = rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if count.is_multiple_of(2) {
                                // Fail
                                Err(opc_runtime::TaskError::Failed(
                                    "injected stress failure".to_string(),
                                    std::sync::Arc::new(std::io::Error::other("stress")),
                                ))
                            } else {
                                // Sleep/idle
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                Ok(())
                            }
                        })
                    },
                )
                .await;
        });
        join_handles.push(handle);
    }

    // Release all spawning tasks simultaneously
    barrier.wait().await;

    // Concurrent readers of health and readiness, and clock advances
    let clock_clone = clock.clone();
    let supervisor_clone = supervisor.clone();
    let reader_handle = tokio::spawn(async move {
        for _ in 0..50 {
            let _ = supervisor_clone.readiness().await;
            let _ = supervisor_clone.health().await;
            clock_clone.advance(Duration::from_millis(5));
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    // Wait for spawns to finish
    for handle in join_handles {
        handle.await.unwrap();
    }

    reader_handle.await.unwrap();

    // Now, let's concurrently advance/set clock and check readiness
    let clock_clone = clock.clone();
    let clock_writer_1 = tokio::spawn(async move {
        for _ in 0..50 {
            clock_clone.advance(Duration::from_millis(10));
            tokio::task::yield_now().await;
        }
    });

    let clock_clone2 = clock.clone();
    let clock_writer_2 = tokio::spawn(async move {
        for _ in 0..50 {
            clock_clone2.set_time(Duration::from_millis(5000));
            tokio::task::yield_now().await;
        }
    });

    clock_writer_1.await.unwrap();
    clock_writer_2.await.unwrap();

    // Finally, shut down all concurrently
    let supervisor_clone2 = supervisor.clone();
    let shutdown_handle = tokio::spawn(async move {
        supervisor_clone2
            .shutdown_all(ShutdownPolicy::Immediate)
            .await;
    });

    shutdown_handle.await.unwrap();
}

async fn test_shutdown_immediate_drop_race_impl() {
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "race-test-cnf".to_string(),
        shutdown_grace: Duration::from_millis(10),
        drain_timeout: Duration::from_millis(20),
        ..Default::default()
    };

    let called_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    struct RaceHook {
        count: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl DrainHook for RaceHook {
        async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let hook = Arc::new(RaceHook {
        count: called_count.clone(),
    });
    let task_started = Arc::new(tokio::sync::Notify::new());
    let task_dropped = Arc::new(AtomicBool::new(false));

    let task_started_for_init = task_started.clone();
    let task_dropped_for_init = task_dropped.clone();
    let handle = Builder::new(profile)
        .with_drain_hook(hook)
        .with_init(move |supervisor, _shutdown| {
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("race-drain-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        move || {
                            let task_started = task_started_for_init.clone();
                            let task_dropped = task_dropped_for_init.clone();
                            Box::pin(async move {
                                struct DropFlag(Arc<AtomicBool>);

                                impl Drop for DropFlag {
                                    fn drop(&mut self) {
                                        self.0.store(true, Ordering::SeqCst);
                                    }
                                }

                                let _drop_flag = DropFlag(task_dropped);
                                task_started.notify_one();
                                std::future::pending::<Result<(), opc_runtime::TaskError>>().await
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

    assert_eq!(called_count.load(Ordering::SeqCst), 0);
    tokio::time::timeout(Duration::from_secs(2), task_started.notified())
        .await
        .expect("supervised task must start before shutdown race");

    // Call shutdown and drop the last handle immediately.
    let shutdown = handle.shutdown_token().clone();
    let mut rx = shutdown.subscribe();
    handle.shutdown().await;
    drop(handle);

    // Let background thread execute.
    let stopped = tokio::time::timeout(Duration::from_secs(2), async move {
        loop {
            if *rx.borrow_and_update() == opc_runtime::shutdown::ShutdownPhase::Stopped {
                break;
            }
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
    .await;

    assert!(
        stopped.is_ok(),
        "Runtime must reach Stopped phase even if handle is dropped immediately after shutdown"
    );
    assert_eq!(
        called_count.load(Ordering::SeqCst),
        1,
        "Drain hook must run exactly once in shutdown+drop race"
    );
    assert!(
        task_dropped.load(Ordering::SeqCst),
        "Supervisor drain must stop supervised tasks in shutdown+drop race"
    );
}

async fn test_mistuned_budgets_starvation_impl() {
    let clock = Arc::new(FakeClock::synchronized());
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(6),
        drain_timeout: Duration::from_secs(4),
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(SimpleHook {
        called: called.clone(),
    });

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_drain_hook(hook)
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("starved-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                tokio::time::sleep(Duration::from_secs(10)).await;
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

    let supervisor = handle.supervisor().clone();

    // Since we're in conformance mode, complete_shutdown drives the sequence synchronously.
    let handle_clone = handle.clone();
    let shutdown_task = tokio::spawn(async move {
        handle_clone.complete_shutdown().await;
    });

    // Advance clock past the hook timeout + observation window
    clock.advance(Duration::from_secs(4));

    shutdown_task.await.unwrap();

    // Check that the task was stopped
    let health = supervisor.health().await;
    assert!(!health.task_states.get("starved-task").unwrap().running);
}

async fn test_drain_incomplete_alarm_impl() {
    let clock = Arc::new(FakeClock::synchronized());
    let alarms = SharedAlarmManager::default();
    let profile = RuntimeProfile {
        mode: RuntimeMode::Dev,
        nf_kind: "alarm-test-cnf".to_string(),
        shutdown_grace: Duration::from_millis(50),
        drain_timeout: Duration::from_millis(100),
        ..Default::default()
    };

    struct BlockedHook;
    #[async_trait::async_trait]
    impl DrainHook for BlockedHook {
        async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            std::future::pending::<Result<(), Box<dyn std::error::Error + Send + Sync>>>().await
        }
    }

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_alarm_manager(alarms.clone())
        .with_drain_hook(Arc::new(BlockedHook))
        .build()
        .await
        .unwrap();

    // Trigger shutdown
    let shutdown = handle.shutdown_token().clone();
    let mut rx = shutdown.subscribe();
    handle.shutdown().await;
    drop(handle);

    // Advance clock past the hook timeout (50ms)
    clock.advance(Duration::from_millis(60));
    tokio::task::yield_now().await;
    clock.advance(Duration::from_millis(100));

    // Wait for stopped
    let stopped = tokio::time::timeout(Duration::from_secs(1), async move {
        loop {
            if *rx.borrow_and_update() == opc_runtime::shutdown::ShutdownPhase::Stopped {
                break;
            }
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(
        stopped.is_ok(),
        "runtime must stop after raising drain incomplete alarm"
    );

    // Verify that the alarm is raised
    let active = alarms.active_alarms();
    assert!(
        !active.is_empty(),
        "Alarm must be raised on drain hook timeout"
    );
    assert_eq!(
        active[0].alarm_type.as_str(),
        "alarm-test-cnf.runtime.drain.incomplete"
    );
    assert_eq!(active[0].severity, Severity::Major);
}

async fn test_failing_drain_hook_raises_alarm_impl() {
    let alarms = SharedAlarmManager::default();
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "failing-hook-test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let hook = Arc::new(FailingHook {
        called: called.clone(),
    });

    let handle = Builder::new(profile)
        .with_alarm_manager(alarms.clone())
        .with_drain_hook(hook)
        .build()
        .await
        .unwrap();

    assert!(!called.load(Ordering::SeqCst));

    handle.shutdown().await;

    assert!(
        called.load(Ordering::SeqCst),
        "Failing drain hook must still be called on shutdown"
    );

    // Verify that the alarm is raised
    let active = alarms.active_alarms();
    assert!(
        !active.is_empty(),
        "Alarm must be raised on drain hook failure"
    );
    assert_eq!(
        active[0].alarm_type.as_str(),
        "failing-hook-test-cnf.runtime.drain.incomplete"
    );
    assert_eq!(active[0].severity, Severity::Major);
}

async fn test_multiple_failing_drain_hooks_aggregated_alarm_impl() {
    let alarms = SharedAlarmManager::default();
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "multi-failing-hook-test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called1 = Arc::new(AtomicBool::new(false));
    let hook1 = Arc::new(ConfigurableFailingHook {
        called: called1.clone(),
        error_msg: "first hook failure".to_string(),
    });

    let called2 = Arc::new(AtomicBool::new(false));
    let hook2 = Arc::new(ConfigurableFailingHook {
        called: called2.clone(),
        error_msg: "second hook failure".to_string(),
    });

    let handle = Builder::new(profile)
        .with_alarm_manager(alarms.clone())
        .with_drain_hook(hook1)
        .with_drain_hook(hook2)
        .build()
        .await
        .unwrap();

    assert!(!called1.load(Ordering::SeqCst));
    assert!(!called2.load(Ordering::SeqCst));

    handle.shutdown().await;

    assert!(
        called1.load(Ordering::SeqCst),
        "First failing drain hook must be called on shutdown"
    );
    assert!(
        called2.load(Ordering::SeqCst),
        "Second failing drain hook must be called on shutdown"
    );

    // Verify that a combined alarm is raised with all errors aggregated
    let active = alarms.active_alarms();
    assert!(
        !active.is_empty(),
        "Alarm must be raised on drain hook failure"
    );
    assert_eq!(
        active[0].alarm_type.as_str(),
        "multi-failing-hook-test-cnf.runtime.drain.incomplete"
    );
    assert_eq!(active[0].severity, Severity::Major);

    let alarm_text = active[0].text.as_str();
    assert!(
        alarm_text.contains("first hook failure"),
        "Alarm text must contain the first hook failure: {alarm_text}"
    );
    assert!(
        alarm_text.contains("second hook failure"),
        "Alarm text must contain the second hook failure: {alarm_text}"
    );

    // Confirm that the shutdown continues to Stopped phase
    assert!(
        handle.is_stopped().await,
        "Shutdown must transition to Stopped phase"
    );
}

async fn test_mixed_drain_hooks_executes_all_and_raises_alarm_impl() {
    let alarms = SharedAlarmManager::default();
    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "mixed-hook-test-cnf".to_string(),
        shutdown_grace: Duration::from_secs(5),
        ..Default::default()
    };

    let called_success = Arc::new(AtomicBool::new(false));
    let hook_success = Arc::new(SimpleHook {
        called: called_success.clone(),
    });

    let called_fail = Arc::new(AtomicBool::new(false));
    let hook_fail = Arc::new(ConfigurableFailingHook {
        called: called_fail.clone(),
        error_msg: "failed hook in mixed setup".to_string(),
    });

    let handle = Builder::new(profile)
        .with_alarm_manager(alarms.clone())
        .with_drain_hook(hook_success)
        .with_drain_hook(hook_fail)
        .build()
        .await
        .unwrap();

    assert!(!called_success.load(Ordering::SeqCst));
    assert!(!called_fail.load(Ordering::SeqCst));

    handle.shutdown().await;

    // A mix of succeeding and failing drain hooks executes all hooks
    assert!(
        called_success.load(Ordering::SeqCst),
        "Succeeding drain hook must still be called on shutdown"
    );
    assert!(
        called_fail.load(Ordering::SeqCst),
        "Failing drain hook must still be called on shutdown"
    );

    // Verify that the alarm is raised
    let active = alarms.active_alarms();
    assert!(
        !active.is_empty(),
        "Alarm must be raised since at least one drain hook failed"
    );
    assert_eq!(
        active[0].alarm_type.as_str(),
        "mixed-hook-test-cnf.runtime.drain.incomplete"
    );
    assert_eq!(active[0].severity, Severity::Major);

    let alarm_text = active[0].text.as_str();
    assert!(
        alarm_text.contains("failed hook in mixed setup"),
        "Alarm text must contain the failure details: {alarm_text}"
    );

    // Confirm that the shutdown continues to Stopped phase
    assert!(
        handle.is_stopped().await,
        "Shutdown must transition to Stopped phase"
    );
}

async fn test_required_nrf_drain_hook_missing_fails_in_production_impl() {
    let mut profile = RuntimeProfile::production("amf", uuid::Uuid::new_v4());
    profile.budget = Some(opc_runtime::ResourceBudget::default());
    profile.requires_nrf_drain_hook = true;

    let result = Builder::new(profile).build().await;

    assert!(
        result.is_err(),
        "Building runtime with missing NRF hook in production mode must fail"
    );
    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("missing required drain hook: NrfDrainHook"),
        "Error message should mention NrfDrainHook: {err_str}"
    );
}

async fn test_required_nrf_drain_hook_missing_warns_in_dev_impl() {
    let mut profile = RuntimeProfile::dev("amf");
    profile.requires_nrf_drain_hook = true;

    let result = Builder::new(profile).build().await;

    assert!(
        result.is_ok(),
        "Building runtime with missing NRF hook in dev mode must succeed (only warn)"
    );
}
