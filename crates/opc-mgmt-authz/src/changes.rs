//! Ordered authorization changes, with a barrier at the protocol output boundary.

use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use tokio::sync::{mpsc, oneshot, OwnedMutexGuard};

use crate::{AuthzError, ResolvedPolicy};

/// Shared output barrier for one subscription. Activation closes the barrier
/// before changing the policy, and acknowledgement reopens it only after the
/// complete dependency set has been checked. Failure takes priority over queued
/// data, so neither a full data queue nor a blocked provider delays termination.
#[derive(Clone, Default)]
pub struct AuthorizationGate(Arc<Mutex<GateState>>);

#[derive(Default)]
struct GateState {
    revision: u64,
    pending: bool,
    failed: bool,
    waker: Option<Waker>,
}

impl AuthorizationGate {
    /// Polls protocol output while holding the activation barrier. The closure
    /// must only poll an in-memory queue; it must not block or call a provider.
    pub fn poll_output<T>(
        &self,
        cx: &mut Context<'_>,
        ready: impl FnOnce(&mut Context<'_>) -> Poll<Option<T>>,
    ) -> Poll<Result<Option<T>, AuthzError>> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(Err(AuthzError::PolicyUnavailable));
        };
        if state.failed {
            return Poll::Ready(Err(AuthzError::PolicyUnavailable));
        }
        state.waker = Some(cx.waker().clone());
        if state.pending {
            Poll::Pending
        } else {
            ready(cx).map(Ok)
        }
    }

    /// Stops output immediately, without waiting for an audit or data writer.
    pub fn terminate(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.failed = true;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }

    /// Current activation revision, including a pending reevaluation.
    pub fn revision(&self) -> Result<u64, AuthzError> {
        let state = self.0.lock().map_err(|_| AuthzError::PolicyUnavailable)?;
        if state.failed {
            Err(AuthzError::PolicyUnavailable)
        } else {
            Ok(state.revision)
        }
    }

    /// Commits schema-only authorization bookkeeping only if no activation
    /// raced its evaluation. A race fails closed before data can be emitted.
    pub fn at_revision<T>(
        &self,
        revision: u64,
        commit: impl FnOnce() -> T,
    ) -> Result<T, AuthzError> {
        let state = self.0.lock().map_err(|_| AuthzError::PolicyUnavailable)?;
        if state.failed || state.revision != revision {
            return Err(AuthzError::PolicyUnavailable);
        }
        Ok(commit())
    }

    fn begin(&self, revision: u64) -> Result<(), AuthzError> {
        let mut state = self.0.lock().map_err(|_| AuthzError::PolicyUnavailable)?;
        if state.failed {
            return Err(AuthzError::PolicyUnavailable);
        }
        state.revision = revision;
        state.pending = true;
        Ok(())
    }

    fn release(&self, revision: u64) -> Result<(), AuthzError> {
        let mut state = self.0.lock().map_err(|_| AuthzError::PolicyUnavailable)?;
        if state.failed || state.revision != revision {
            return Err(AuthzError::PolicyUnavailable);
        }
        state.pending = false;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
        Ok(())
    }
}

/// One lossless control notification. Dropping it without acknowledgement closes
/// the stream's gate; its publisher then observes server-side closure.
pub struct AuthorizationChange {
    revision: u64,
    gate: AuthorizationGate,
    completion: Option<oneshot::Sender<()>>,
}

impl AuthorizationChange {
    /// Revision that must be evaluated before acknowledging this notification.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn acknowledge(mut self) -> Result<(), AuthzError> {
        self.gate.release(self.revision)?;
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(());
        }
        Ok(())
    }
}

impl Drop for AuthorizationChange {
    fn drop(&mut self) {
        if self.completion.is_some() {
            self.gate.terminate();
        }
    }
}

/// Atomic initial context and an ordered control receiver for one subscription.
pub struct AuthorizationWatch {
    revision: u64,
    initial: Option<ResolvedPolicy>,
    receiver: mpsc::UnboundedReceiver<Result<AuthorizationChange, AuthzError>>,
    gate: AuthorizationGate,
    // An immutable source explicitly keeps its control channel open forever.
    _immutable: Option<mpsc::UnboundedSender<Result<AuthorizationChange, AuthzError>>>,
}

impl AuthorizationWatch {
    /// Explicit opt-in for a source whose policy and resolved principal remain
    /// immutable for the entire subscription. Do not use for a live datastore.
    pub fn immutable(initial: ResolvedPolicy, gate: AuthorizationGate) -> Result<Self, AuthzError> {
        let (sender, receiver) = mpsc::unbounded_channel();
        gate.begin(0)?;
        Ok(Self {
            revision: 0,
            initial: Some(initial),
            receiver,
            gate,
            _immutable: Some(sender),
        })
    }

    /// Initial revision captured under the source's registration lock.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Takes the context captured atomically with registration, exactly once.
    pub fn take_initial(&mut self) -> Result<ResolvedPolicy, AuthzError> {
        self.initial.take().ok_or(AuthzError::PolicyUnavailable)
    }

    /// Enables initial output after authorization. If activation already began,
    /// output remains gated until that revision has been reevaluated.
    pub fn initial_evaluated(&self) -> Result<(), AuthzError> {
        if self.gate.revision()? == self.revision {
            self.gate.release(self.revision)?;
        }
        Ok(())
    }

    /// Waits for a control change without polling the policy source. A closed
    /// channel or non-consecutive revision fails closed.
    pub async fn changed(&mut self) -> Result<AuthorizationChange, AuthzError> {
        let change = self
            .receiver
            .recv()
            .await
            .ok_or(AuthzError::PolicyUnavailable)??;
        if self.revision.checked_add(1) != Some(change.revision) {
            self.gate.terminate();
            return Err(AuthzError::PolicyUnavailable);
        }
        Ok(change)
    }

    /// Acknowledges a completed, successful reevaluation for this exact revision.
    /// On denial/failure, terminate the gate and drop the change instead.
    pub fn acknowledge(&mut self, change: AuthorizationChange) -> Result<(), AuthzError> {
        if self.revision.checked_add(1) != Some(change.revision) {
            self.gate.terminate();
            return Err(AuthzError::PolicyUnavailable);
        }
        self.revision = change.revision;
        change.acknowledge()
    }
}

struct Listener {
    gate: Weak<Mutex<GateState>>,
    sender: mpsc::UnboundedSender<Result<AuthorizationChange, AuthzError>>,
}

#[derive(Default)]
struct HubState {
    revision: u64,
    failed: bool,
    listeners: Vec<Listener>,
}

impl Drop for HubState {
    fn drop(&mut self) {
        for listener in &self.listeners {
            if let Some(gate) = listener.gate.upgrade() {
                AuthorizationGate(gate).terminate();
            }
        }
    }
}

/// Serializes policy/context activation and wakes every stream attached to this
/// source. Waking all attached streams is conservative when affected scope is
/// unknown. Registration and the initial context capture share the same lock as
/// activation, so no revision can fall between them.
#[derive(Clone, Default)]
pub struct AuthorizationChangeHub {
    state: Arc<Mutex<HubState>>,
    activation: Arc<tokio::sync::Mutex<()>>,
}

impl AuthorizationChangeHub {
    /// Registers before resolving the first snapshot. `resolve` must read the
    /// context that `prepare_change` updates, and must not call back into this hub.
    pub fn register(
        &self,
        gate: AuthorizationGate,
        resolve: impl FnOnce() -> Result<ResolvedPolicy, AuthzError>,
    ) -> Result<AuthorizationWatch, AuthzError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthzError::PolicyUnavailable)?;
        if state.failed {
            return Err(AuthzError::PolicyUnavailable);
        }
        let initial = resolve()?;
        let (sender, receiver) = mpsc::unbounded_channel();
        gate.begin(state.revision)?;
        state
            .listeners
            .retain(|listener| !listener.sender.is_closed());
        state.listeners.push(Listener {
            gate: Arc::downgrade(&gate.0),
            sender,
        });
        Ok(AuthorizationWatch {
            revision: state.revision,
            initial: Some(initial),
            receiver,
            gate,
            _immutable: None,
        })
    }

    /// Gates all attached output before activating a new policy/context. Later
    /// activations wait until `complete` has received every acknowledgement or
    /// observed server-side closure. The separated prepare/complete steps also
    /// support deterministic notification-delivery barriers in integration tests.
    /// Dropping a prepared change without completion fails the entire source.
    pub async fn prepare_change(
        &self,
        apply: impl FnOnce(),
    ) -> Result<PendingAuthorizationChange, AuthzError> {
        let serial = self.activation.clone().lock_owned().await;
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthzError::PolicyUnavailable)?;
        if state.failed {
            return Err(AuthzError::PolicyUnavailable);
        }
        let revision = state
            .revision
            .checked_add(1)
            .ok_or(AuthzError::PolicyUnavailable)?;
        state
            .listeners
            .retain(|listener| !listener.sender.is_closed());
        let mut listeners = Vec::new();
        for listener in &state.listeners {
            if let Some(gate) = listener.gate.upgrade() {
                let gate = AuthorizationGate(gate);
                if gate.begin(revision).is_ok() {
                    listeners.push((listener.sender.clone(), gate));
                }
            }
        }
        apply();
        state.revision = revision;
        Ok(PendingAuthorizationChange {
            hub: self.clone(),
            revision,
            listeners,
            serial: Some(serial),
            completed: false,
        })
    }

    /// Activates a revision and waits for its complete acknowledgement boundary.
    pub async fn activate(&self, apply: impl FnOnce()) -> Result<u64, AuthzError> {
        self.prepare_change(apply).await?.complete().await
    }

    /// Fails all attached streams when refresh or notification delivery fails
    /// and its affected scope cannot be established. This source remains failed.
    pub fn fail(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.failed = true;
            for listener in &state.listeners {
                if let Some(gate) = listener.gate.upgrade() {
                    AuthorizationGate(gate).terminate();
                }
                let _ = listener.sender.send(Err(AuthzError::PolicyUnavailable));
            }
        }
    }
}

/// An activated revision with output gated while control delivery is pending.
/// Retaining this object retains the activation lock; a later revision cannot
/// restore a permission before streams have observed this one.
pub struct PendingAuthorizationChange {
    hub: AuthorizationChangeHub,
    revision: u64,
    listeners: Vec<(
        mpsc::UnboundedSender<Result<AuthorizationChange, AuthzError>>,
        AuthorizationGate,
    )>,
    serial: Option<OwnedMutexGuard<()>>,
    completed: bool,
}

impl PendingAuthorizationChange {
    /// Delivers the revision and waits for every active stream to reevaluate or
    /// close on the server. A dropped receiver is a closed stream, not a lost
    /// notification to a still-active stream.
    pub async fn complete(mut self) -> Result<u64, AuthzError> {
        let mut acknowledgements = Vec::new();
        for (sender, gate) in self.listeners.drain(..) {
            let (completion, acknowledged) = oneshot::channel();
            let change = AuthorizationChange {
                revision: self.revision,
                gate,
                completion: Some(completion),
            };
            if sender.send(Ok(change)).is_ok() {
                acknowledgements.push(acknowledged);
            }
        }
        for acknowledged in acknowledgements {
            let _ = acknowledged.await;
        }
        self.completed = true;
        self.serial.take();
        Ok(self.revision)
    }
}

impl Drop for PendingAuthorizationChange {
    fn drop(&mut self) {
        if !self.completed {
            self.hub.fail();
        }
    }
}
