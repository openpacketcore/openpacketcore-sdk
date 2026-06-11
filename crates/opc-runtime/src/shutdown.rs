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

/// Shutdown token for propagating termination signals through the CNF.
///
/// This is a lightweight cancellation primitive inspired by `CancellationToken`
/// from `tokio-util`. It propagates SIGTERM-style graceful drain signals.
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
    pub fn request_shutdown(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.advance_phase(ShutdownPhase::Draining);
        tracing::info!("shutdown requested");
    }

    /// Cancel — request termination via the standard drain sequence.
    ///
    /// The monotonic phase invariant prevents skipping directly to `Stopped`.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.advance_phase(ShutdownPhase::Draining);
        tracing::warn!("shutdown cancellation requested");
    }

    /// Advance the observable shutdown phase monotonically.
    pub(crate) fn transition_phase(&self, new_phase: ShutdownPhase) {
        self.advance_phase(new_phase);
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

    /// Subscribe to shutdown phase changes.
    ///
    /// New subscribers immediately observe the latest phase through
    /// `Receiver::borrow()` / `borrow_and_update()`.
    pub fn subscribe(&self) -> watch::Receiver<ShutdownPhase> {
        self.inner.phase_tx.subscribe()
    }

    fn advance_phase(&self, new_phase: ShutdownPhase) -> ShutdownPhase {
        loop {
            let current_raw = self.inner.phase.load(Ordering::SeqCst);
            let current_phase = ShutdownPhase::from_u8(current_raw);
            if current_phase >= new_phase {
                return current_phase;
            }

            if self
                .inner
                .phase
                .compare_exchange(
                    current_raw,
                    new_phase.as_u8(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                self.inner.phase_tx.send_replace(new_phase);
                let actual = ShutdownPhase::from_u8(self.inner.phase.load(Ordering::SeqCst));
                if actual > new_phase {
                    self.inner.phase_tx.send_replace(actual);
                }
                return actual;
            }
        }
    }
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
        Self {
            token,
            phase: ShutdownPhase::Running,
        }
    }

    /// Transition to a new drain phase.
    pub fn transition(&mut self, new_phase: ShutdownPhase) {
        tracing::debug!(from = %self.phase, to = %new_phase, "drain phase transition");
        self.phase = new_phase;
        self.token.transition_phase(new_phase);
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
}
