//! Shutdown token and drain orchestration per RFC 008 section 10.
//!
//! Implements SIGTERM-style graceful drain with proper ordering:
//! 1. Stop accepting new external work
//! 2. Mark readiness false
//! 3. Notify NRF/deregister where applicable
//! 4. Stop management writes except emergency recovery
//! 5. Drain protocol workers up to timeout
//! 6. Flush audit and evidence breadcrumbs
//! 7. Checkpoint local state where applicable
//! 8. Shut down listeners and background tasks

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::watch;

/// Callback invoked during the drain sequence, before supervised workers are
/// stopped (e.g. NRF deregistration per RFC 008 section 10.2 step 3).
///
/// Register hooks via `Builder::with_drain_hook`; profiles can make a hook
/// mandatory by name (`requires_nrf_drain_hook` expects `"NrfDrainHook"`).
/// All hooks run concurrently and share a single timeout of
/// `min(shutdown_grace, drain_timeout)`; a hook error or timeout raises a
/// drain-incomplete alarm but does not stop the shutdown sequence.
///
/// Downstream implementations commonly need to annotate their impl block with
/// `#[async_trait::async_trait]` and depend directly on the `async-trait`
/// crate. `opc-runtime` does not re-export that macro.
#[async_trait]
pub trait DrainHook: Send + Sync {
    /// Returns the descriptive name of the drain hook, used for logging and startup validation.
    fn name(&self) -> &'static str {
        "GenericDrainHook"
    }

    /// Gracefully drains or deregisters resources on shutdown.
    ///
    /// Implementations must be cancellation-safe because the runtime may drop
    /// this future when the shutdown grace timeout expires.
    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Closed outcome of a shutdown request on one [`ShutdownToken`].
///
/// The disposition is value-free by design: it carries no task payload, peer,
/// subscriber, address, key, packet, mutation, or descriptor data — only
/// whether the calling invocation performed the first effective transition.
/// Callers that own shutdown observability use it to record one initiation
/// per effective transition instead of one log event per API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShutdownDisposition {
    /// This invocation won the token's initiation gate: it performed the
    /// cancellation-flag transition that every shutdown request shares, and
    /// the phase advances to `Draining` with it unless the phase was already
    /// advanced past `Draining` through a separate phase transition.
    Initiated,
    /// Shutdown had already been requested on the token; this invocation
    /// performed no new initiation.
    AlreadyRequested,
}

/// Shutdown token for propagating termination signals through the CNF.
///
/// This is a lightweight cancellation primitive inspired by `CancellationToken`
/// from `tokio-util`. It propagates SIGTERM-style graceful drain signals.
///
/// Shutdown request state is monotonic and idempotent: a token has exactly one
/// effective initiation, and [`ShutdownToken::request_shutdown`] /
/// [`ShutdownToken::cancel`] report it through [`ShutdownDisposition`]. Both
/// methods are deliberately silent — they emit no tracing events — so repeated
/// or concurrent invocations cannot amplify shutdown logs; the caller that
/// owns the initiation record decides whether to emit one.
#[derive(Debug, Clone)]
pub struct ShutdownToken {
    inner: Arc<ShutdownInner>,
}

#[derive(Debug)]
struct ShutdownInner {
    cancelled: AtomicBool,
    phase: std::sync::atomic::AtomicU8,
    /// Watch channel for phase updates.
    phase_tx: watch::Sender<ShutdownPhase>,
}

/// Observable position in the RFC 008 section 10.2 drain sequence.
///
/// Phases only advance forward (the `Ord` ordering matches drain order);
/// attempts to move backwards are ignored. Observe transitions through
/// `ShutdownToken::subscribe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum ShutdownPhase {
    /// Normal operation.
    #[default]
    Running,
    /// New work is being rejected.
    Draining,
    /// No new connections accepted.
    NoNewConnections,
    /// Management writes stopped.
    ManagementStopped,
    /// Protocol workers draining.
    ProtocolDraining,
    /// Audit/state flushed.
    Flushed,
    /// Fully stopped.
    Stopped,
}

impl std::fmt::Display for ShutdownPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownPhase::Running => write!(f, "Running"),
            ShutdownPhase::Draining => write!(f, "Draining"),
            ShutdownPhase::NoNewConnections => write!(f, "NoNewConnections"),
            ShutdownPhase::ManagementStopped => write!(f, "ManagementStopped"),
            ShutdownPhase::ProtocolDraining => write!(f, "ProtocolDraining"),
            ShutdownPhase::Flushed => write!(f, "Flushed"),
            ShutdownPhase::Stopped => write!(f, "Stopped"),
        }
    }
}

impl ShutdownToken {
    /// Create a new shutdown token.
    pub fn new() -> Self {
        let (phase_tx, _) = watch::channel(ShutdownPhase::Running);
        Self {
            inner: Arc::new(ShutdownInner {
                cancelled: AtomicBool::new(false),
                phase: std::sync::atomic::AtomicU8::new(ShutdownPhase::Running.as_u8()),
                phase_tx,
            }),
        }
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Request graceful shutdown.
    ///
    /// Idempotent and monotonic: only the invocation that wins the token's
    /// initiation gate returns [`ShutdownDisposition::Initiated`]; every
    /// later or racing invocation returns
    /// [`ShutdownDisposition::AlreadyRequested`] and performs no new
    /// initiation (the phase advance it still performs is itself idempotent).
    /// This method emits no tracing events, so repeated and concurrent
    /// invocations across token clones cannot amplify shutdown logs; callers
    /// that own the initiation record inspect the returned disposition
    /// instead.
    pub fn request_shutdown(&self) -> ShutdownDisposition {
        self.initiate_drain()
    }

    /// Cancel — request termination via the standard drain sequence.
    ///
    /// Shares one initiation gate with [`ShutdownToken::request_shutdown`]:
    /// racing the two methods yields exactly one
    /// [`ShutdownDisposition::Initiated`] in total. Like `request_shutdown`,
    /// this method is silent and reports the transition through the returned
    /// disposition.
    ///
    /// The monotonic phase invariant prevents skipping directly to `Stopped`.
    pub fn cancel(&self) -> ShutdownDisposition {
        self.initiate_drain()
    }

    /// Advance the observable shutdown phase monotonically.
    pub(crate) fn transition_phase(&self, new_phase: ShutdownPhase) {
        self.advance_phase(new_phase);
    }

    /// Flip the cancellation flag exactly once and advance to `Draining`.
    fn initiate_drain(&self) -> ShutdownDisposition {
        let initiated = self
            .inner
            .cancelled
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        self.advance_phase(ShutdownPhase::Draining);
        if initiated {
            ShutdownDisposition::Initiated
        } else {
            ShutdownDisposition::AlreadyRequested
        }
    }

    /// Get a future that completes when shutdown is requested.
    pub async fn shutdown_acknowledged(&self) {
        let mut rx = self.inner.phase_tx.subscribe();
        if self.is_shutdown_requested() || *rx.borrow_and_update() != ShutdownPhase::Running {
            return;
        }
        loop {
            if rx.changed().await.is_err() {
                return;
            }
            if self.is_shutdown_requested() || *rx.borrow_and_update() != ShutdownPhase::Running {
                return;
            }
        }
    }

    /// Wait until shutdown reaches at least the requested phase.
    ///
    /// The shutdown phase model is monotonic, so this returns immediately if
    /// the token is already at or beyond `phase`. This method is
    /// notification-only: it does not request shutdown, mutate the token, or
    /// consume the token.
    ///
    /// The wait subscribes before checking the current value to avoid
    /// lost-wakeup races. If the underlying watch channel is closed, the method
    /// returns defensively.
    pub async fn wait_for_phase(&self, phase: ShutdownPhase) {
        let mut rx = self.inner.phase_tx.subscribe();
        loop {
            if *rx.borrow_and_update() >= phase {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Subscribe to shutdown phase changes.
    ///
    /// New subscribers immediately observe the latest phase through
    /// `Receiver::borrow()` / `borrow_and_update()`.
    pub fn subscribe(&self) -> watch::Receiver<ShutdownPhase> {
        self.inner.phase_tx.subscribe()
    }

    fn current_phase(&self) -> ShutdownPhase {
        ShutdownPhase::from_u8(self.inner.phase.load(Ordering::SeqCst))
    }

    /// Publish a phase without allowing an older publisher to regress the
    /// watch value after a newer atomic transition has completed.
    fn publish_phase(&self, phase: ShutdownPhase) {
        self.inner.phase_tx.send_if_modified(|published| {
            if *published < phase {
                *published = phase;
                true
            } else {
                false
            }
        });
    }

    fn advance_phase(&self, new_phase: ShutdownPhase) -> PhaseAdvance {
        loop {
            let current_phase = self.current_phase();
            if current_phase >= new_phase {
                return PhaseAdvance {
                    prior: current_phase,
                    actual: current_phase,
                    advanced: false,
                };
            }

            if self
                .inner
                .phase
                .compare_exchange(
                    current_phase.as_u8(),
                    new_phase.as_u8(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                self.publish_phase(new_phase);
                // A racing transition may already have advanced the atomic
                // phase again but not published it yet. Help publish that
                // latest observation while preserving watch monotonicity.
                let actual = self.current_phase();
                self.publish_phase(actual);
                return PhaseAdvance {
                    prior: current_phase,
                    actual,
                    advanced: true,
                };
            }
        }
    }
}

/// Outcome of a single phase-advance attempt on a shutdown token.
struct PhaseAdvance {
    /// Phase observed immediately before the attempt.
    prior: ShutdownPhase,
    /// Phase the token is at after the attempt.
    actual: ShutdownPhase,
    /// True only when this attempt moved the phase strictly forward.
    advanced: bool,
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownPhase {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => ShutdownPhase::Running,
            1 => ShutdownPhase::Draining,
            2 => ShutdownPhase::NoNewConnections,
            3 => ShutdownPhase::ManagementStopped,
            4 => ShutdownPhase::ProtocolDraining,
            5 => ShutdownPhase::Flushed,
            6 => ShutdownPhase::Stopped,
            _ => ShutdownPhase::Stopped,
        }
    }
}

/// Drain guard that ensures proper shutdown ordering.
#[derive(Debug)]
pub struct DrainGuard {
    token: ShutdownToken,
    phase: ShutdownPhase,
}

impl DrainGuard {
    /// Create a new drain guard.
    pub fn new(token: ShutdownToken) -> Self {
        let phase = token.current_phase();
        Self { token, phase }
    }

    /// Transition to a new drain phase.
    ///
    /// The transition event is emitted only when the token actually advances,
    /// so repeated or backwards transition requests do not amplify logs.
    pub fn transition(&mut self, new_phase: ShutdownPhase) {
        let advance = self.token.advance_phase(new_phase);
        self.phase = advance.actual;
        if advance.advanced {
            // Attribute only the phase this invocation actually won. A racing
            // publisher may already have moved `actual` farther forward.
            tracing::debug!(from = %advance.prior, to = %new_phase, "drain phase transition");
        }
    }

    /// Check if shutdown is requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.token.is_shutdown_requested()
    }

    /// Get current drain phase.
    pub fn phase(&self) -> ShutdownPhase {
        self.phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_token_basic() {
        let token = ShutdownToken::new();
        assert!(!token.is_shutdown_requested());

        token.request_shutdown();
        assert!(token.is_shutdown_requested());
    }

    #[tokio::test]
    async fn test_shutdown_token_cancel() {
        let token = ShutdownToken::new();
        assert!(!token.is_shutdown_requested());

        token.cancel();
        assert!(token.is_shutdown_requested());
    }

    #[tokio::test]
    async fn test_shutdown_acknowledged() {
        let token = ShutdownToken::new();

        let handle = tokio::spawn({
            let token = token.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                token.request_shutdown();
            }
        });

        token.shutdown_acknowledged().await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_late_subscriber_sees_current_shutdown_phase() {
        let token = ShutdownToken::new();
        token.request_shutdown();

        let rx = token.subscribe();
        assert_eq!(*rx.borrow(), ShutdownPhase::Draining);
    }

    #[tokio::test]
    async fn wait_for_phase_running_returns_immediately() {
        let token = ShutdownToken::new();

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            token.wait_for_phase(ShutdownPhase::Running),
        )
        .await
        .expect("Running wait should return immediately for a new token");
    }

    #[tokio::test]
    async fn wait_for_phase_draining_returns_immediately_after_shutdown_request() {
        let token = ShutdownToken::new();
        token.request_shutdown();

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            token.wait_for_phase(ShutdownPhase::Draining),
        )
        .await
        .expect("Draining wait should return after shutdown is already requested");
    }

    #[tokio::test]
    async fn wait_for_phase_protocol_draining_completes_after_transition() {
        let token = ShutdownToken::new();
        let mut waiter = tokio::spawn({
            let token = token.clone();
            async move {
                token.wait_for_phase(ShutdownPhase::ProtocolDraining).await;
            }
        });

        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "waiter should remain pending before ProtocolDraining"
        );

        token.transition_phase(ShutdownPhase::ProtocolDraining);

        tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiter)
            .await
            .expect("ProtocolDraining waiter should complete")
            .expect("waiter task should not panic");
    }

    #[tokio::test]
    async fn wait_for_phase_draining_completes_when_phase_skips_to_stopped() {
        let token = ShutdownToken::new();
        let mut waiter = tokio::spawn({
            let token = token.clone();
            async move {
                token.wait_for_phase(ShutdownPhase::Draining).await;
            }
        });

        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "waiter should remain pending before shutdown advances"
        );

        token.transition_phase(ShutdownPhase::Stopped);

        tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiter)
            .await
            .expect("Draining waiter should complete when phase skips to Stopped")
            .expect("waiter task should not panic");
    }

    #[tokio::test]
    async fn wait_for_phase_stopped_completes_only_at_stopped() {
        let token = ShutdownToken::new();
        let mut waiter = tokio::spawn({
            let token = token.clone();
            async move {
                token.wait_for_phase(ShutdownPhase::Stopped).await;
            }
        });

        token.transition_phase(ShutdownPhase::ProtocolDraining);
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "Stopped waiter should remain pending before Stopped"
        );

        token.transition_phase(ShutdownPhase::Stopped);

        tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiter)
            .await
            .expect("Stopped waiter should complete at Stopped")
            .expect("waiter task should not panic");
    }

    #[tokio::test]
    async fn wait_for_phase_wakes_multiple_waiters_on_same_target() {
        let token = ShutdownToken::new();
        let waiters = (0..4)
            .map(|_| {
                let token = token.clone();
                tokio::spawn(async move {
                    token.wait_for_phase(ShutdownPhase::ProtocolDraining).await;
                })
            })
            .collect::<Vec<_>>();

        tokio::task::yield_now().await;
        for waiter in &waiters {
            assert!(
                !waiter.is_finished(),
                "waiter should remain pending before target phase"
            );
        }

        token.transition_phase(ShutdownPhase::ProtocolDraining);

        for waiter in waiters {
            tokio::time::timeout(std::time::Duration::from_millis(50), waiter)
                .await
                .expect("waiter should complete")
                .expect("waiter task should not panic");
        }
    }

    #[tokio::test]
    async fn wait_for_phase_waiters_complete_when_each_target_is_reached() {
        let token = ShutdownToken::new();
        let mut draining_waiter = tokio::spawn({
            let token = token.clone();
            async move {
                token.wait_for_phase(ShutdownPhase::Draining).await;
            }
        });
        let mut protocol_waiter = tokio::spawn({
            let token = token.clone();
            async move {
                token.wait_for_phase(ShutdownPhase::ProtocolDraining).await;
            }
        });

        tokio::task::yield_now().await;
        assert!(
            !draining_waiter.is_finished(),
            "Draining waiter should remain pending before Draining"
        );
        assert!(
            !protocol_waiter.is_finished(),
            "ProtocolDraining waiter should remain pending before ProtocolDraining"
        );

        token.transition_phase(ShutdownPhase::Draining);

        tokio::time::timeout(std::time::Duration::from_millis(50), &mut draining_waiter)
            .await
            .expect("Draining waiter should complete")
            .expect("Draining waiter task should not panic");
        assert!(
            !protocol_waiter.is_finished(),
            "ProtocolDraining waiter should remain pending at Draining"
        );

        token.transition_phase(ShutdownPhase::ProtocolDraining);

        tokio::time::timeout(std::time::Duration::from_millis(50), &mut protocol_waiter)
            .await
            .expect("ProtocolDraining waiter should complete")
            .expect("ProtocolDraining waiter task should not panic");
    }

    #[test]
    fn test_shutdown_phase_advances_monotonically_to_stopped() {
        let token = ShutdownToken::new();

        token.cancel();
        token.transition_phase(ShutdownPhase::ProtocolDraining);
        token.transition_phase(ShutdownPhase::Stopped);
        token.request_shutdown();

        let rx = token.subscribe();
        assert_eq!(*rx.borrow(), ShutdownPhase::Stopped);
    }

    #[test]
    fn test_shutdown_phase_ordering() {
        assert!(ShutdownPhase::Running < ShutdownPhase::Draining);
        assert!(ShutdownPhase::Draining < ShutdownPhase::NoNewConnections);
        assert!(ShutdownPhase::NoNewConnections < ShutdownPhase::Stopped);
    }

    #[test]
    fn test_drain_guard_transitions() {
        let token = ShutdownToken::new();
        let mut guard = DrainGuard::new(token.clone());

        assert_eq!(guard.phase(), ShutdownPhase::Running);
        assert!(!guard.is_shutdown_requested());

        guard.transition(ShutdownPhase::Draining);
        assert_eq!(guard.phase(), ShutdownPhase::Draining);

        guard.transition(ShutdownPhase::Stopped);
        assert_eq!(guard.phase(), ShutdownPhase::Stopped);
    }

    #[test]
    fn stale_phase_publication_cannot_regress_subscribers() {
        let token = ShutdownToken::new();
        token.transition_phase(ShutdownPhase::Stopped);
        let mut subscriber = token.subscribe();
        assert_eq!(*subscriber.borrow_and_update(), ShutdownPhase::Stopped);

        // Model a lower-phase publisher that won an earlier atomic CAS but
        // completed its watch publication after the Stopped publisher.
        token.publish_phase(ShutdownPhase::Draining);

        assert_eq!(*subscriber.borrow(), ShutdownPhase::Stopped);
        assert!(matches!(subscriber.has_changed(), Ok(false)));
    }

    #[test]
    fn drain_guard_reflects_the_tokens_monotonic_phase() {
        let token = ShutdownToken::new();
        token.transition_phase(ShutdownPhase::ProtocolDraining);
        let mut guard = DrainGuard::new(token);
        assert_eq!(guard.phase(), ShutdownPhase::ProtocolDraining);

        guard.transition(ShutdownPhase::Draining);
        assert_eq!(guard.phase(), ShutdownPhase::ProtocolDraining);
    }

    #[test]
    fn request_shutdown_initiates_once_and_is_idempotent() {
        let token = ShutdownToken::new();

        assert_eq!(token.request_shutdown(), ShutdownDisposition::Initiated);
        assert!(token.is_shutdown_requested());
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);

        for _ in 0..4 {
            assert_eq!(
                token.request_shutdown(),
                ShutdownDisposition::AlreadyRequested
            );
        }
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);
    }

    #[test]
    fn cancel_then_request_shutdown_share_one_initiation() {
        let token = ShutdownToken::new();

        assert_eq!(token.cancel(), ShutdownDisposition::Initiated);
        assert_eq!(
            token.request_shutdown(),
            ShutdownDisposition::AlreadyRequested
        );
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);
    }

    #[test]
    fn request_shutdown_then_cancel_share_one_initiation() {
        let token = ShutdownToken::new();

        assert_eq!(token.request_shutdown(), ShutdownDisposition::Initiated);
        assert_eq!(token.cancel(), ShutdownDisposition::AlreadyRequested);
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);
    }

    #[test]
    fn repeated_requests_after_later_phase_do_not_move_phase_backwards() {
        let token = ShutdownToken::new();

        assert_eq!(token.request_shutdown(), ShutdownDisposition::Initiated);
        token.transition_phase(ShutdownPhase::Stopped);

        assert_eq!(
            token.request_shutdown(),
            ShutdownDisposition::AlreadyRequested
        );
        assert_eq!(token.cancel(), ShutdownDisposition::AlreadyRequested);
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Stopped);
    }

    #[test]
    fn concurrent_request_and_cancel_yield_one_initiation() {
        let token = ShutdownToken::new();
        let initiated = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for thread in 0..8 {
                let token = token.clone();
                let initiated = Arc::clone(&initiated);
                scope.spawn(move || {
                    for iteration in 0..200 {
                        let disposition = if (thread + iteration) % 2 == 0 {
                            token.request_shutdown()
                        } else {
                            token.cancel()
                        };
                        if disposition == ShutdownDisposition::Initiated {
                            initiated.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
        });

        assert_eq!(
            initiated.load(Ordering::SeqCst),
            1,
            "exactly one invocation may win the effective transition"
        );
        assert!(token.is_shutdown_requested());
        assert_eq!(*token.subscribe().borrow(), ShutdownPhase::Draining);
    }

    #[test]
    fn concurrent_requests_keep_phase_sequence_monotonic() {
        let token = ShutdownToken::new();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));

        let watcher = {
            let mut rx = token.subscribe();
            let observed = Arc::clone(&observed);
            std::thread::spawn(move || loop {
                // `borrow_and_update` is level-triggered: every read sees the
                // latest phase, so the observed sequence can drop values but
                // never reorder or regress them.
                let phase = *rx.borrow_and_update();
                observed
                    .lock()
                    .expect("observer holds the lock")
                    .push(phase);
                if phase == ShutdownPhase::Stopped {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            })
        };

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let token = token.clone();
                scope.spawn(move || {
                    for _ in 0..200 {
                        token.request_shutdown();
                    }
                });
            }
        });
        token.transition_phase(ShutdownPhase::Stopped);

        watcher.join().expect("observer thread must finish");
        let sequence = observed.lock().expect("observer holds the lock");
        assert!(
            sequence.windows(2).all(|pair| pair[0] <= pair[1]),
            "phase sequence must never move backwards: {sequence:?}"
        );
        assert_eq!(sequence.last().copied(), Some(ShutdownPhase::Stopped));
    }
}
