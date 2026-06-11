//! Testkit — fake clock, fake tasks, and shutdown test harness per RFC 008.
//!
//! Provides deterministic time-based testing without real-time delays.
//! The fake clock allows tests to:
//! - Control time progression explicitly
//! - Test timer-based behavior deterministically
//! - Simulate shutdown timing without actual waiting

use crate::shutdown::ShutdownToken;
use crate::task::{Criticality, TaskKind, TaskSpec};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::RwLock;

// =============================================================================
// Clock trait (RFC 008 §15)
// =============================================================================

/// Wall-clock timestamp (nanoseconds since UNIX epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }
    pub fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl From<Duration> for Timestamp {
    fn from(d: Duration) -> Self {
        Self(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    }
}

impl From<Timestamp> for Duration {
    fn from(t: Timestamp) -> Self {
        Duration::from_nanos(t.0)
    }
}

#[async_trait]
/// Clock trait for time abstraction (RFC 008 §15).
///
/// Allows tests to use deterministic fake time while production
/// uses the real system clock.
pub trait Clock: Send + Sync {
    /// Returns the current wall-clock timestamp.
    fn now(&self) -> Timestamp;
    /// Returns a monotonic instant for measuring elapsed durations.
    fn monotonic(&self) -> StdInstant;
    /// Sleeps for the given duration using the clock's time source.
    async fn sleep(&self, duration: Duration);
}

/// Real clock backed by the system clock.
#[derive(Debug, Clone, Default)]
pub struct RealClock;

#[async_trait]
impl Clock for RealClock {
    fn now(&self) -> Timestamp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp::from(now)
    }

    fn monotonic(&self) -> StdInstant {
        StdInstant::now()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[derive(Debug)]
struct SleepWaiter {
    deadline_mono_ns: u64,
    notify: Arc<tokio::sync::Notify>,
}

struct SleepGuard {
    waiters: Arc<std::sync::Mutex<Vec<SleepWaiter>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl Drop for SleepGuard {
    fn drop(&mut self) {
        // Defensive: if the mutex is poisoned, we avoid panicking during drop
        if let Ok(mut waiters) = self.waiters.lock() {
            waiters.retain(|w| !Arc::ptr_eq(&w.notify, &self.notify));
        }
    }
}

/// Fake clock for deterministic time-based testing.
///
/// Provides deterministic time progression for tests:
/// - `advance()` moves time forward explicitly
/// - `set_time()` sets a specific time
/// - `fake_time()` returns the current fake time
#[derive(Debug, Clone)]
pub struct FakeClock {
    /// Internal time stored as u64 nanoseconds since epoch.
    time_ns: Arc<AtomicU64>,
    /// Real start time when using real time mode.
    real_start: Option<StdInstant>,
    /// Whether to use real time or fake time.
    use_fake: bool,
    /// Fake monotonic base (captured at construction for deterministic elapsed measurements).
    fake_monotonic_base: StdInstant,
    /// Monotonic fake counter that only moves forward.
    monotonic_ns: Arc<AtomicU64>,
    /// List of waiters currently parked sleeping.
    waiters: Arc<std::sync::Mutex<Vec<SleepWaiter>>>,
}

impl FakeClock {
    /// Create a new fake clock starting at UNIX epoch.
    pub fn new() -> Self {
        Self {
            time_ns: Arc::new(AtomicU64::new(0)),
            real_start: None,
            use_fake: true,
            fake_monotonic_base: StdInstant::now(),
            monotonic_ns: Arc::new(AtomicU64::new(0)),
            waiters: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Create a fake clock synchronized with the current real time.
    pub fn synchronized() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let current = now.as_secs() * 1_000_000_000 + u64::from(now.subsec_nanos());
        Self {
            time_ns: Arc::new(AtomicU64::new(current)),
            real_start: None,
            use_fake: true,
            fake_monotonic_base: StdInstant::now(),
            monotonic_ns: Arc::new(AtomicU64::new(0)),
            waiters: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn monotonic_ns(&self) -> u64 {
        if !self.use_fake {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            return now.as_nanos() as u64;
        }
        self.monotonic_ns.load(Ordering::SeqCst)
    }

    fn wake_waiters(&self) {
        let current_mono_ns = self.monotonic_ns();
        let mut triggered = Vec::new();
        if let Ok(mut waiters) = self.waiters.lock() {
            waiters.retain(|w| {
                if w.deadline_mono_ns <= current_mono_ns {
                    triggered.push(w.notify.clone());
                    false
                } else {
                    true
                }
            });
        }
        for notify in triggered {
            notify.notify_one();
        }
    }

    /// Advance the fake clock by the given duration.
    pub fn advance(&self, duration: Duration) {
        if !self.use_fake {
            return;
        }
        let delta = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);

        loop {
            let current = self.time_ns.load(Ordering::SeqCst);
            let nanos = current.saturating_add(delta);
            if self
                .time_ns
                .compare_exchange_weak(current, nanos, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.monotonic_ns.fetch_add(delta, Ordering::SeqCst);
                break;
            }
        }

        self.wake_waiters();
    }

    /// Set the fake clock to a specific time.
    pub fn set_time(&self, duration: Duration) {
        if !self.use_fake {
            return;
        }
        let target_nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);

        loop {
            let current = self.time_ns.load(Ordering::SeqCst);
            if self
                .time_ns
                .compare_exchange_weak(current, target_nanos, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if target_nanos > current {
                    let delta = target_nanos - current;
                    self.monotonic_ns.fetch_add(delta, Ordering::SeqCst);
                }
                break;
            }
        }

        self.wake_waiters();
    }

    /// Disable fake time — use real time.
    #[allow(dead_code)]
    pub fn use_real_time(&mut self) {
        self.use_fake = false;
        self.real_start = Some(StdInstant::now());
    }

    /// Get current fake time as Duration since epoch.
    pub fn fake_time(&self) -> Duration {
        if !self.use_fake {
            if let Some(start) = self.real_start {
                return start.elapsed();
            }
            return Duration::ZERO;
        }
        Duration::from_nanos(self.time_ns.load(Ordering::SeqCst))
    }

    /// Sleep for the given duration (only advances in fake mode).
    async fn sleep_internal(&self, duration: Duration) {
        if self.use_fake {
            let start_mono_ns = self.monotonic_ns();
            let deadline_mono_ns = start_mono_ns
                .saturating_add(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX));

            if self.monotonic_ns() >= deadline_mono_ns {
                tokio::task::yield_now().await;
                return;
            }

            let notify = Arc::new(tokio::sync::Notify::new());
            let rx = notify.notified();

            let guard;

            {
                let mut waiters = self.waiters.lock().unwrap();
                if self.monotonic_ns() >= deadline_mono_ns {
                    drop(waiters);
                    tokio::task::yield_now().await;
                    return;
                }
                waiters.push(SleepWaiter {
                    deadline_mono_ns,
                    notify: notify.clone(),
                });
                guard = SleepGuard {
                    waiters: self.waiters.clone(),
                    notify: notify.clone(),
                };
            }

            rx.await;
            drop(guard);
        } else {
            tokio::time::sleep(duration).await;
        }
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        if !self.use_fake {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            return Timestamp::from(now);
        }
        Timestamp::from_nanos(self.time_ns.load(Ordering::SeqCst))
    }

    fn monotonic(&self) -> StdInstant {
        if !self.use_fake {
            return StdInstant::now();
        }
        let mono_ns = self.monotonic_ns.load(Ordering::SeqCst);
        let fake_elapsed = Duration::from_nanos(mono_ns);
        self.fake_monotonic_base
            .checked_add(fake_elapsed)
            .unwrap_or(self.fake_monotonic_base)
    }

    async fn sleep(&self, duration: Duration) {
        self.sleep_internal(duration).await;
    }
}

/// Global fake clock instance for tests.
#[derive(Debug)]
pub struct FakeClockGlobal {
    clock: RwLock<Option<FakeClock>>,
}

impl FakeClockGlobal {
    pub fn new() -> Self {
        Self {
            clock: RwLock::new(None),
        }
    }

    /// Set the global fake clock.
    #[allow(dead_code)]
    pub async fn set(&self, clock: FakeClock) {
        let mut guard = self.clock.write().await;
        *guard = Some(clock);
    }

    /// Get the current global clock, or create a new real one.
    #[allow(dead_code)]
    pub async fn get(&self) -> FakeClock {
        let guard = self.clock.read().await;
        guard.clone().unwrap_or_else(FakeClock::synchronized)
    }

    /// Clear the global clock.
    #[allow(dead_code)]
    pub async fn clear(&self) {
        let mut guard = self.clock.write().await;
        *guard = None;
    }
}

impl Default for FakeClockGlobal {
    fn default() -> Self {
        Self::new()
    }
}

/// Scoped fake clock that resets on drop.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ScopedFakeClock {
    global: Arc<FakeClockGlobal>,
}

impl ScopedFakeClock {
    pub fn new(global: Arc<FakeClockGlobal>) -> Self {
        Self { global }
    }

    pub async fn scope<F: std::future::Future>(&self, clock: FakeClock, f: F) -> F::Output {
        self.global.set(clock).await;
        let result = f.await;
        self.global.clear().await;
        result
    }
}

/// Test harness for SIGTERM-style shutdown testing per RFC 008 section 17.2.
#[derive(Debug)]
pub struct ShutdownTestHarness {
    pub shutdown_token: ShutdownToken,
}

impl ShutdownTestHarness {
    /// Create a new test harness.
    pub fn new() -> Self {
        let token = ShutdownToken::new();
        Self {
            shutdown_token: token,
        }
    }

    /// Request shutdown and verify the token reflects it.
    pub fn trigger_shutdown(&self) {
        self.shutdown_token.request_shutdown();
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_token.is_shutdown_requested()
    }
}

impl Default for ShutdownTestHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Test task builder for creating supervised test tasks.
#[derive(Debug, Clone)]
pub struct TestTaskBuilder {
    name: String,
    kind: TaskKind,
    criticality: Criticality,
    will_fail: bool,
    fail_count: usize,
    run_duration: Duration,
    attempt: Arc<std::sync::atomic::AtomicUsize>,
}

impl TestTaskBuilder {
    /// Create a new test task builder.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: TaskKind::ProtocolWorker,
            criticality: Criticality::Degrade,
            will_fail: false,
            fail_count: 0,
            run_duration: Duration::from_secs(60),
            attempt: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Set the task kind.
    pub fn kind(mut self, kind: TaskKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the criticality.
    pub fn criticality(mut self, criticality: Criticality) -> Self {
        self.criticality = criticality;
        self
    }

    /// Make the task fail after a certain count.
    #[allow(dead_code)]
    pub fn fail_after(mut self, count: usize) -> Self {
        self.will_fail = true;
        self.fail_count = count;
        self
    }

    /// Set the run duration.
    pub fn run_duration(mut self, duration: Duration) -> Self {
        self.run_duration = duration;
        self
    }

    /// Build the TaskSpec.
    #[allow(dead_code)]
    pub fn build(self) -> TaskSpec {
        let run_duration = self.run_duration;
        let will_fail = self.will_fail;
        let fail_count = self.fail_count;
        let attempt = self.attempt.clone();

        let task_fn = async move {
            let current_attempt = attempt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if will_fail && current_attempt >= fail_count {
                tokio::time::sleep(Duration::from_millis(5)).await;
                return Err(crate::task::TaskError::Failed(
                    "injected test task failure".to_string(),
                    std::sync::Arc::new(std::io::Error::other("injected failure")),
                ));
            }
            tokio::time::sleep(run_duration).await;
            Ok(())
        };

        TaskSpec::new(self.name, self.kind, self.criticality, task_fn)
    }

    /// Build a restartable task factory.
    #[allow(dead_code)]
    pub fn build_factory(
        self,
    ) -> impl Fn() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::task::TaskError>> + Send>,
    > + Send
           + 'static {
        let builder = self;
        move || {
            let b = builder.clone();
            b.build().task_fn
        }
    }
}

/// Create a fake clock instance for the current test scope.
pub fn fake_clock() -> FakeClock {
    FakeClock::synchronized()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Readiness;

    #[test]
    fn test_fake_clock_advance() {
        let clock = FakeClock::new();
        assert_eq!(clock.fake_time(), Duration::ZERO);

        clock.advance(Duration::from_secs(10));
        assert_eq!(clock.fake_time(), Duration::from_secs(10));

        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.fake_time(), Duration::from_secs(15));
    }

    #[test]
    fn test_fake_clock_set_time() {
        let clock = FakeClock::new();
        clock.advance(Duration::from_secs(10));
        let m1 = clock.monotonic();

        clock.set_time(Duration::from_secs(100));
        assert_eq!(clock.fake_time(), Duration::from_secs(100));
        let m2 = clock.monotonic();
        assert!(m2 >= m1);

        clock.set_time(Duration::from_secs(5));
        assert_eq!(clock.fake_time(), Duration::from_secs(5));
        let m3 = clock.monotonic();
        assert!(m3 >= m2);
    }

    #[test]
    fn test_fake_clock_default() {
        let clock = FakeClock::default();
        assert_eq!(clock.fake_time(), Duration::ZERO);
    }

    #[tokio::test]
    async fn test_shutdown_harness_basic() {
        let harness = ShutdownTestHarness::new();
        assert!(!harness.is_shutdown_requested());

        harness.trigger_shutdown();
        assert!(harness.is_shutdown_requested());
    }

    // =============================================================================
    // Drain ordering integration tests (RFC 008 §10.2)
    // =============================================================================

    use crate::shutdown::ShutdownPhase;
    use crate::{Builder, RestartPolicy, RuntimeMode, RuntimePhase, TaskName};
    use std::sync::atomic::Ordering;

    /// Verify drain ordering per RFC 008 §10.2:
    /// 1. Shutdown requested
    /// 2. Readiness transitions to Draining/NotReady
    /// 3. This happens BEFORE tasks are stopped
    #[tokio::test]
    async fn test_drain_ordering_readiness_before_stop() {
        let task_state = Arc::new(std::sync::atomic::AtomicU32::new(0)); // 0: NotStarted, 1: Running, 2: Stopped
        let task_started_notify = Arc::new(tokio::sync::Notify::new());
        let task_stop_notify = Arc::new(tokio::sync::Notify::new());
        let readiness_drained_notify = Arc::new(tokio::sync::Notify::new());

        let task_state_clone = task_state.clone();
        let task_started_notify_clone = task_started_notify.clone();
        let task_stop_notify_clone = task_stop_notify.clone();
        let readiness_drained_clone = readiness_drained_notify.clone();

        // Use Dev mode so drain monitor is active
        let profile = crate::profile::RuntimeProfile {
            mode: RuntimeMode::Dev,
            nf_kind: "test".to_string(),
            ..Default::default()
        };

        let handle = Builder::new(profile)
            .with_phase_observer(move |phase| {
                if phase >= RuntimePhase::Draining {
                    readiness_drained_clone.notify_one();
                }
            })
            .with_init(move |supervisor, _shutdown| {
                let task_state_inner = task_state_clone.clone();
                let task_started_notify_inner = task_started_notify_clone.clone();
                let task_stop_notify_inner = task_stop_notify_clone.clone();
                Box::pin(async move {
                    let task_name = TaskName::new("ordering-test-task");
                    supervisor
                        .register(
                            task_name.clone(),
                            TaskKind::ProtocolWorker,
                            Criticality::Degrade,
                            RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();

                    supervisor
                        .spawn(
                            task_name.clone(),
                            TaskKind::ProtocolWorker,
                            Criticality::Degrade,
                            RestartPolicy::no_restart(),
                            move || {
                                let task_state_inner = task_state_inner.clone();
                                let task_started_notify_inner = task_started_notify_inner.clone();
                                let task_stop_notify_inner = task_stop_notify_inner.clone();
                                Box::pin(async move {
                                    task_state_inner.store(1, Ordering::SeqCst);
                                    task_started_notify_inner.notify_one();

                                    // Wait explicitly for permission to exit
                                    task_stop_notify_inner.notified().await;

                                    task_state_inner.store(2, Ordering::SeqCst);
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

        let shutdown_token = handle.shutdown_token().clone();

        // Wait for task to enter Running state (state = 1)
        task_started_notify.notified().await;

        // Trigger shutdown via the token
        shutdown_token.request_shutdown();

        // Wait for readiness to transition to Draining
        let timeout = Duration::from_secs(5);
        tokio::time::timeout(timeout, readiness_drained_notify.notified())
            .await
            .expect("timeout waiting for readiness to drain");

        // Readiness has transitioned to Draining/NotReady
        // Verify the task is still in Running state when Draining begins
        assert_eq!(
            task_state.load(Ordering::SeqCst),
            1,
            "Task must be in Running state when Draining begins"
        );

        // Permit the task to stop now
        task_stop_notify.notify_one();

        // Wait/poll until the task reaches state 2
        let start = std::time::Instant::now();
        while task_state.load(Ordering::SeqCst) != 2 {
            if start.elapsed() > Duration::from_secs(2) {
                panic!("Timeout waiting for task to transition to Stopped (state 2)");
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(
            task_state.load(Ordering::SeqCst),
            2,
            "Task must have transitioned to Stopped (state 2)"
        );
    }

    /// Verify shutdown token can be observed by subscribers, including via the latest replayed state.
    #[tokio::test]
    async fn test_shutdown_token_subscription() {
        let harness = ShutdownTestHarness::new();

        // Multiple subscribers should all receive the signal
        let token = &harness.shutdown_token;

        let received_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received_count_clone = received_count.clone();

        // Spawn a receiver
        let mut rx = token.subscribe();
        tokio::spawn(async move {
            let mut count = 0usize;
            while rx.changed().await.is_ok() {
                let phase = *rx.borrow_and_update();
                if phase != crate::shutdown::ShutdownPhase::Running {
                    count += 1;
                    break;
                }
            }
            received_count_clone.store(count, Ordering::SeqCst);
        });

        // Give receiver time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Trigger shutdown
        harness.trigger_shutdown();

        // Wait for propagation
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Shutdown should have propagated to the subscriber
        assert!(harness.is_shutdown_requested());
        assert_eq!(received_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_test_task_builder() {
        let task = TestTaskBuilder::new("test-task")
            .kind(TaskKind::Listener)
            .criticality(Criticality::Fatal)
            .build();

        assert_eq!(task.name.to_string(), "test-task");
        assert_eq!(task.kind, TaskKind::Listener);
        assert_eq!(task.criticality, Criticality::Fatal);
    }

    #[tokio::test]
    async fn test_test_task_builder_fail_after() {
        let task = TestTaskBuilder::new("failing-task").fail_after(0).build();

        let res = task.task_fn.await;
        assert!(res.is_err(), "Built failing task should fail when executed");
    }

    #[tokio::test]
    async fn test_test_task_builder_build_factory() {
        let builder = TestTaskBuilder::new("factory-task")
            .run_duration(Duration::from_millis(1))
            .fail_after(1); // Fails on 2nd run

        let factory = builder.build_factory();

        // 1st run: should succeed (since current_attempt is 0, which is < 1)
        let res1 = factory().await;
        assert!(res1.is_ok(), "1st run of factory-task should succeed");

        // 2nd run: should fail (since current_attempt is 1, which is >= 1)
        let res2 = factory().await;
        assert!(res2.is_err(), "2nd run of factory-task should fail");
    }

    // =============================================================================
    // Startup phase ordering test (RFC 008 §6 / acceptance gate)
    // =============================================================================

    /// Verify startup phase ordering per RFC 008 startup state machine:
    /// ProcessInit → TelemetryInit → SecurityInit → ConfigBootstrap →
    /// ResourcePreflight → ServiceBind → PeerWarmup → Ready
    ///
    /// The phase transitions are synchronous and sequential in Builder::build(),
    /// so reaching Ready implies all intermediate phases were visited.
    #[tokio::test]
    async fn test_startup_phase_ordering() {
        let profile = crate::RuntimeProfile {
            mode: RuntimeMode::Dev,
            nf_kind: "test".to_string(),
            ..Default::default()
        };

        let transitions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transitions_clone = transitions.clone();

        let handle = Builder::new(profile)
            .with_phase_observer(move |phase| {
                transitions_clone.lock().unwrap().push(phase);
            })
            .with_init(|supervisor, _shutdown| {
                Box::pin(async move {
                    supervisor
                        .register(
                            TaskName::new("dummy"),
                            TaskKind::Listener,
                            Criticality::BestEffort,
                            RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();
                    supervisor
                        .spawn(
                            TaskName::new("dummy"),
                            TaskKind::Listener,
                            Criticality::BestEffort,
                            RestartPolicy::no_restart(),
                            || Box::pin(async { Ok(()) }),
                        )
                        .await
                        .unwrap();
                })
            })
            .build()
            .await
            .unwrap();

        // Verify the runtime reaches Ready
        let phase = handle.phase().await;
        assert_eq!(
            phase,
            RuntimePhase::Ready,
            "runtime should reach Ready phase"
        );

        // Verify the exact sequence of transitions
        let expected = vec![
            RuntimePhase::ProcessInit,
            RuntimePhase::TelemetryInit,
            RuntimePhase::SecurityInit,
            RuntimePhase::ConfigBootstrap,
            RuntimePhase::ResourcePreflight,
            RuntimePhase::ServiceBind,
            RuntimePhase::PeerWarmup,
            RuntimePhase::Ready,
        ];
        let actual = transitions.lock().unwrap().clone();
        assert_eq!(
            actual, expected,
            "Startup phases must transition in the correct RFC 008 order"
        );
    }

    /// Verify shutdown phase transitions: Ready -> Draining
    ///
    /// In Dev mode the drain monitor handles the transition asynchronously,
    /// so we poll until we observe Draining or timeout.
    #[tokio::test]
    async fn test_shutdown_phase_transitions() {
        let profile = crate::RuntimeProfile {
            mode: RuntimeMode::Dev,
            nf_kind: "test".to_string(),
            ..Default::default()
        };

        let handle = Builder::new(profile)
            .with_init(|supervisor, _shutdown| {
                Box::pin(async move {
                    supervisor
                        .register(
                            TaskName::new("dummy"),
                            TaskKind::Listener,
                            Criticality::BestEffort,
                            RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();
                    supervisor
                        .spawn(
                            TaskName::new("dummy"),
                            TaskKind::Listener,
                            Criticality::BestEffort,
                            RestartPolicy::no_restart(),
                            || Box::pin(async { Ok(()) }),
                        )
                        .await
                        .unwrap();
                })
            })
            .build()
            .await
            .unwrap();
        assert_eq!(handle.phase().await, RuntimePhase::Ready);

        // Trigger shutdown
        handle.shutdown_token().request_shutdown();

        // Poll until phase transitions to Draining (drain monitor processes async)
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        loop {
            let phase = handle.phase().await;
            if phase >= RuntimePhase::Draining {
                break;
            }
            assert!(
                start.elapsed() < timeout,
                "timeout waiting for Draining phase"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn test_gated_readiness_listener() {
        let profile = crate::RuntimeProfile {
            mode: RuntimeMode::Dev,
            nf_kind: "test".to_string(),
            ..Default::default()
        };

        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_clone = notify.clone();

        let handle = Builder::new(profile)
            .with_init(move |supervisor, _shutdown| {
                let notify_inner = notify_clone.clone();
                let supervisor_inner = supervisor.clone();
                Box::pin(async move {
                    let task_name = TaskName::new("gated-listener");
                    supervisor
                        .register(
                            task_name.clone(),
                            TaskKind::Listener,
                            Criticality::Degrade,
                            RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();

                    // Mark as readiness gated
                    supervisor.set_readiness_gated(&task_name, true).await;

                    supervisor
                        .spawn(
                            task_name.clone(),
                            TaskKind::Listener,
                            Criticality::Degrade,
                            RestartPolicy::no_restart(),
                            move || {
                                let notify_innermost = notify_inner.clone();
                                let supervisor_innermost = supervisor_inner.clone();
                                Box::pin(async move {
                                    // Wait on notify (simulate blocked before bind)
                                    notify_innermost.notified().await;

                                    // Signal ready
                                    supervisor_innermost
                                        .set_task_ready(&TaskName::new("gated-listener"), true)
                                        .await;

                                    // Keep running
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

        // The task is spawned but blocked before bind, so the handle.readiness() should be NotReady
        assert_eq!(handle.readiness().await, Readiness::NotReady);
        assert_eq!(handle.phase().await, RuntimePhase::PeerWarmup);

        // Notify the task to let it proceed and bind
        notify.notify_one();

        // Yield to allow task to execute and call set_task_ready
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The task should now be ready, transitioning the runtime to Ready
        // even before any readiness probe polls the handle.
        assert_eq!(handle.phase().await, RuntimePhase::Ready);
        assert_eq!(handle.readiness().await, Readiness::Ready);
    }

    #[tokio::test]
    async fn test_conformance_mode_shutdown() {
        let profile = crate::RuntimeProfile {
            mode: RuntimeMode::Conformance,
            nf_kind: "test".to_string(),
            drain_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        let task_active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_active_clone = task_active.clone();

        let handle = Builder::new(profile)
            .with_init(move |supervisor, _shutdown| {
                let task_active_inner = task_active_clone.clone();
                Box::pin(async move {
                    let task_name = TaskName::new("conformance-task");
                    supervisor
                        .register(
                            task_name.clone(),
                            TaskKind::ProtocolWorker,
                            Criticality::Degrade,
                            RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();

                    supervisor
                        .spawn(
                            task_name.clone(),
                            TaskKind::ProtocolWorker,
                            Criticality::Degrade,
                            RestartPolicy::no_restart(),
                            move || {
                                let task_active_innermost = task_active_inner.clone();
                                Box::pin(async move {
                                    task_active_innermost.store(true, Ordering::SeqCst);
                                    // Run forever
                                    loop {
                                        tokio::time::sleep(Duration::from_secs(1)).await;
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

        // The task should be active
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            task_active.load(Ordering::SeqCst),
            "Conformance task should be active"
        );

        // Trigger graceful shutdown in Conformance mode
        handle.shutdown().await;

        // The runtime should reach Stopped phase immediately/synchronously
        assert_eq!(handle.phase().await, RuntimePhase::Stopped);
        assert!(handle.is_stopped().await);
        let shutdown_rx = handle.shutdown_token().subscribe();
        assert_eq!(*shutdown_rx.borrow(), ShutdownPhase::Stopped);

        // Verify task was aborted
        let supervisor = handle.supervisor();
        let tasks = supervisor.tasks.read().await;
        let state = tasks.get(&TaskName::new("conformance-task")).unwrap();
        let is_running = state.handle.as_ref().is_some_and(|h| h.is_running());
        assert!(!is_running, "Conformance task should be stopped");
    }

    #[tokio::test]
    async fn test_fake_clock_sleep_deterministic() {
        let clock = FakeClock::new();
        let sleep_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sleep_done_clone = sleep_done.clone();

        let clock_clone = clock.clone();
        let handle = tokio::spawn(async move {
            clock_clone.sleep(Duration::from_secs(10)).await;
            sleep_done_clone.store(true, Ordering::SeqCst);
        });

        // Yield to allow sleep to park
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Verify sleep has not completed yet
        assert!(!sleep_done.load(Ordering::SeqCst));

        // Advance fake time, but not enough to reach the deadline
        clock.advance(Duration::from_secs(5));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!sleep_done.load(Ordering::SeqCst));

        // Advance fake time past the deadline
        clock.advance(Duration::from_secs(6));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // The sleep should be completed now
        handle.await.unwrap();
        assert!(sleep_done.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_drain_timeout_deterministic() {
        use crate::profile::RuntimeMode;
        use crate::supervisor::Supervisor;
        use crate::task::RestartPolicy;
        use crate::task::ShutdownPolicy;
        use crate::task::TaskName;
        use crate::RuntimeProfile;

        let profile = RuntimeProfile {
            mode: RuntimeMode::Production,
            nf_kind: "test".to_string(),
            drain_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let shutdown = ShutdownToken::new();
        let clock = Arc::new(FakeClock::new());
        let supervisor = Supervisor::new_with_clock(profile, shutdown.clone(), clock.clone());

        let name = TaskName::new("slow-drain-task");
        supervisor
            .spawn(
                name.clone(),
                TaskKind::ProtocolWorker,
                Criticality::Degrade,
                RestartPolicy::no_restart(),
                move || {
                    Box::pin(async move {
                        // Sleep indefinitely
                        loop {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                        }
                        #[allow(unreachable_code)]
                        Ok(())
                    }) as _
                },
            )
            .await
            .unwrap();

        // Start shutdown of the task in a separate future
        let supervisor_clone = supervisor.clone();
        let name_clone = name.clone();
        let shutdown_fut = tokio::spawn(async move {
            supervisor_clone
                .shutdown_task(&name_clone, ShutdownPolicy::Drain)
                .await;
        });

        // Yield to allow the task to start and get parked in wait_for_task / sleep(5s)
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Ensure it is still running (has not been aborted yet)
        {
            let tasks = supervisor.tasks.read().await;
            let state = tasks.get(&name).unwrap();
            assert!(state.handle.as_ref().unwrap().is_running());
        }

        // Advance the fake clock by 5 seconds (drain_timeout)
        clock.advance(Duration::from_secs(5));

        // The shutdown_task future should now complete
        shutdown_fut.await.unwrap();

        // The task must be aborted/stopped
        {
            let tasks = supervisor.tasks.read().await;
            let state = tasks.get(&name).unwrap();
            assert!(!state.handle.as_ref().unwrap().is_running());
        }
    }

    #[tokio::test]
    async fn test_fake_clock_sleep_monotonic_rewind() {
        let clock = FakeClock::new();
        let sleep_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sleep_done_clone = sleep_done.clone();

        let clock_clone = clock.clone();
        let handle = tokio::spawn(async move {
            // Start a FakeClock sleep for 100ms
            clock_clone.sleep(Duration::from_millis(100)).await;
            sleep_done_clone.store(true, Ordering::SeqCst);
        });

        // Yield to allow sleep to park
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Verify sleep has not completed yet
        assert!(!sleep_done.load(Ordering::SeqCst));

        // Advance time forward by 50ms
        clock.advance(Duration::from_millis(50));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!sleep_done.load(Ordering::SeqCst));

        // Call set_time() to rewind 30ms (from 50ms to 20ms)
        clock.set_time(Duration::from_millis(20));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!sleep_done.load(Ordering::SeqCst));

        // Advance forward by 50ms (total forward = 100ms)
        clock.advance(Duration::from_millis(50));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Assert the sleep completed (monotonic time reached deadline despite the rewind)
        handle.await.unwrap();
        assert!(sleep_done.load(Ordering::SeqCst));
    }
}
