//! In-process NETCONF session termination registry.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// Maximum NETCONF session id.
///
/// RFC 6241 represents `session-id` as an unsigned 32-bit value. Session id `0`
/// is not assigned to live sessions.
pub(crate) const NETCONF_MAX_SESSION_ID: u64 = u32::MAX as u64;

/// Returns true if `session_id` can be advertised in NETCONF `<hello>` and
/// addressed by `<kill-session>`.
pub(crate) const fn is_valid_session_id(session_id: u64) -> bool {
    session_id != 0 && session_id <= NETCONF_MAX_SESSION_ID
}

/// Converts a validated local session id into the public `<hello>` type.
pub(crate) fn session_id_for_hello(session_id: u64) -> Option<NonZeroU32> {
    let session_id = u32::try_from(session_id).ok()?;
    NonZeroU32::new(session_id)
}

/// Shared registry of live NETCONF sessions for base `<kill-session>`.
///
/// The registry stores only session ids and termination signals. It deliberately
/// does not store principals, peer addresses, or request payloads.
#[derive(Clone)]
pub struct SessionRegistry {
    inner: Arc<Mutex<RegistryState>>,
    async_gate: Arc<Semaphore>,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryState::default())),
            async_gate: Arc::new(Semaphore::new(1)),
        }
    }
}

impl SessionRegistry {
    /// Builds an empty session registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves the single cancellation-independent registry worker slot.
    ///
    /// Atomic NETCONF operations use fail-fast admission. Ordinary async
    /// registry calls wait asynchronously before spawning, so there is never
    /// more than one blocking mutex owner or waiter for a registry, even when
    /// multiple server instances share it.
    pub(crate) fn try_acquire_atomic(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.async_gate).try_acquire_owned()
    }

    async fn run_async<R, F>(&self, operation: F) -> Result<R, SessionRegistryError>
    where
        R: Send + 'static,
        F: FnOnce(SessionRegistry) -> R + Send + 'static,
    {
        tokio::runtime::Handle::try_current().map_err(|_| SessionRegistryError::Unavailable)?;
        let permit = Arc::clone(&self.async_gate)
            .acquire_owned()
            .await
            .map_err(|_| SessionRegistryError::Unavailable)?;
        let registry = self.clone();
        let task = catch_unwind(AssertUnwindSafe(|| {
            tokio::task::spawn_blocking(move || {
                let result = operation(registry);
                (result, permit)
            })
        }))
        .map_err(|_| SessionRegistryError::Unavailable)?;
        let (result, permit) = task.await.map_err(|_| SessionRegistryError::Unavailable)?;
        drop(permit);
        Ok(result)
    }

    /// Registers a live session without parking an async executor worker.
    pub(crate) async fn register_async(
        &self,
        session_id: u64,
    ) -> Result<SessionRegistration, SessionRegistryError> {
        self.run_async(move |registry| registry.register(session_id))
            .await?
    }

    /// Acquires a running write lease without parking an async executor worker.
    pub(crate) async fn begin_running_write_async(
        &self,
        session_id: u64,
    ) -> Result<RunningWriteResult, SessionRegistryError> {
        self.run_async(move |registry| registry.begin_running_write(session_id))
            .await
    }

    /// Acquires a candidate write lease without parking an async executor worker.
    pub(crate) async fn begin_candidate_write_async(
        &self,
        session_id: u64,
    ) -> Result<CandidateWriteResult, SessionRegistryError> {
        self.run_async(move |registry| registry.begin_candidate_write(session_id))
            .await
    }

    /// Acquires a startup write lease without parking an async executor worker.
    pub(crate) async fn begin_startup_write_async(
        &self,
        session_id: u64,
    ) -> Result<StartupWriteResult, SessionRegistryError> {
        self.run_async(move |registry| registry.begin_startup_write(session_id))
            .await
    }

    /// Registers one live session id until the returned registration is dropped.
    pub(crate) fn register(
        &self,
        session_id: u64,
    ) -> Result<SessionRegistration, SessionRegistryError> {
        if !is_valid_session_id(session_id) {
            return Err(SessionRegistryError::InvalidSessionId);
        }
        let (kill_tx, kill_rx) = watch::channel(false);
        let entry = Arc::new(SessionEntry {
            kill_tx,
            active: AtomicBool::new(true),
        });
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        if state.sessions.contains_key(&session_id) {
            return Err(SessionRegistryError::DuplicateSessionId);
        }
        state.sessions.insert(session_id, Arc::clone(&entry));
        Ok(SessionRegistration {
            registry: self.clone(),
            session_id,
            entry,
            kill_rx,
        })
    }

    /// Requests termination after `before_signal` succeeds.
    ///
    /// The hook is used by the NETCONF server to durably record a success audit
    /// event before any target session observes the termination signal. A live
    /// exact-generation entry is the linearization point: disappearance before
    /// that check is `NotFound`; disappearance while the hook runs remains
    /// `Terminated`. A temporary receiver pins that generation across the hook,
    /// so immediate reuse of the same numeric id cannot receive the old signal.
    pub(crate) fn terminate_after<F, E>(
        &self,
        session_id: u64,
        before_signal: F,
    ) -> Result<KillSessionResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(entry) = state.sessions.get(&session_id).cloned() else {
            return Ok(KillSessionResult::NotFound);
        };
        if !entry.active.load(Ordering::Acquire) || entry.kill_tx.receiver_count() == 0 {
            state.sessions.remove(&session_id);
            state.release_running_lock(session_id);
            state.release_running_write(session_id);
            state.release_candidate_lock(session_id);
            state.release_candidate_write(session_id);
            state.release_startup_lock(session_id);
            state.release_startup_write(session_id);
            return Ok(KillSessionResult::NotFound);
        }
        // Pin the exact generation's liveness across audit and signal. The
        // actual session may concurrently begin Drop, but the post-audit send
        // cannot be rewritten to NotFound merely because its receiver vanished.
        let _liveness_pin = entry.kill_tx.subscribe();
        before_signal()?;
        // The liveness pin makes send infallible with respect to receiver
        // disappearance. Ignore the result without exposing any stale receiver.
        let _ = entry.kill_tx.send(true);
        Ok(KillSessionResult::Terminated)
    }

    /// Acquires the global running datastore lock after `before_lock` succeeds.
    pub(crate) fn lock_running_after<F, E>(
        &self,
        session_id: u64,
        before_lock: F,
    ) -> Result<LockRunningResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(session) = state.sessions.get(&session_id).cloned() else {
            return Ok(LockRunningResult::SessionNotRegistered);
        };
        if let Some(owner) = state.running_lock.as_ref() {
            return Ok(LockRunningResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        if let Some(owner) = state.running_write.as_ref() {
            return Ok(LockRunningResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        before_lock()?;
        state.running_lock = Some(RunningLock {
            session_id,
            session,
        });
        Ok(LockRunningResult::Acquired)
    }

    /// Acquires a short-lived running datastore write guard.
    pub(crate) fn begin_running_write(&self, session_id: u64) -> RunningWriteResult {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(session) = state.sessions.get(&session_id).cloned() else {
            return RunningWriteResult::SessionNotRegistered;
        };
        if let Some(owner) = state.running_lock.as_ref() {
            if owner.session_id != session_id {
                return RunningWriteResult::Denied {
                    owner_session_id: owner.session_id,
                };
            }
        }
        if let Some(owner) = state.running_write.as_ref() {
            return RunningWriteResult::Denied {
                owner_session_id: owner.session_id,
            };
        }
        let lease = Arc::new(AtomicBool::new(true));
        state.running_write = Some(RunningWrite {
            session_id,
            session,
            lease: Arc::clone(&lease),
        });
        RunningWriteResult::Acquired(RunningWriteGuard {
            registry: self.clone(),
            lease,
        })
    }

    /// Releases the global running datastore lock after `before_unlock`
    /// succeeds.
    pub(crate) fn unlock_running_after<F, E>(
        &self,
        session_id: u64,
        before_unlock: F,
    ) -> Result<UnlockRunningResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        if !state.sessions.contains_key(&session_id) {
            return Ok(UnlockRunningResult::SessionNotRegistered);
        }
        match state.running_lock.as_ref() {
            Some(owner) if owner.session_id == session_id => {
                before_unlock()?;
                state.running_lock = None;
                Ok(UnlockRunningResult::Unlocked)
            }
            Some(owner) => Ok(UnlockRunningResult::NotOwner {
                owner_session_id: owner.session_id,
            }),
            None => Ok(UnlockRunningResult::NotLocked),
        }
    }

    /// Acquires the global candidate datastore lock after `before_lock` succeeds.
    pub(crate) fn lock_candidate_after<F, E>(
        &self,
        session_id: u64,
        before_lock: F,
    ) -> Result<LockCandidateResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(session) = state.sessions.get(&session_id).cloned() else {
            return Ok(LockCandidateResult::SessionNotRegistered);
        };
        if let Some(owner) = state.candidate_lock.as_ref() {
            return Ok(LockCandidateResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        if let Some(owner) = state.candidate_write.as_ref() {
            return Ok(LockCandidateResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        before_lock()?;
        state.candidate_lock = Some(CandidateLock {
            session_id,
            session,
        });
        Ok(LockCandidateResult::Acquired)
    }

    /// Acquires a short-lived candidate datastore write guard.
    pub(crate) fn begin_candidate_write(&self, session_id: u64) -> CandidateWriteResult {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(session) = state.sessions.get(&session_id).cloned() else {
            return CandidateWriteResult::SessionNotRegistered;
        };
        if let Some(owner) = state.candidate_lock.as_ref() {
            if owner.session_id != session_id {
                return CandidateWriteResult::Denied {
                    owner_session_id: owner.session_id,
                };
            }
        }
        if let Some(owner) = state.candidate_write.as_ref() {
            return CandidateWriteResult::Denied {
                owner_session_id: owner.session_id,
            };
        }
        let lease = Arc::new(AtomicBool::new(true));
        state.candidate_write = Some(CandidateWrite {
            session_id,
            session,
            lease: Arc::clone(&lease),
        });
        CandidateWriteResult::Acquired(CandidateWriteGuard {
            registry: self.clone(),
            lease,
        })
    }

    /// Releases the global candidate datastore lock after `before_unlock`
    /// succeeds.
    pub(crate) fn unlock_candidate_after<F, E>(
        &self,
        session_id: u64,
        before_unlock: F,
    ) -> Result<UnlockCandidateResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        if !state.sessions.contains_key(&session_id) {
            return Ok(UnlockCandidateResult::SessionNotRegistered);
        }
        match state.candidate_lock.as_ref() {
            Some(owner) if owner.session_id == session_id => {
                before_unlock()?;
                state.candidate_lock = None;
                Ok(UnlockCandidateResult::Unlocked)
            }
            Some(owner) => Ok(UnlockCandidateResult::NotOwner {
                owner_session_id: owner.session_id,
            }),
            None => Ok(UnlockCandidateResult::NotLocked),
        }
    }

    /// Acquires the global startup datastore lock after `before_lock` succeeds.
    pub(crate) fn lock_startup_after<F, E>(
        &self,
        session_id: u64,
        before_lock: F,
    ) -> Result<LockStartupResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(session) = state.sessions.get(&session_id).cloned() else {
            return Ok(LockStartupResult::SessionNotRegistered);
        };
        if let Some(owner) = state.startup_lock.as_ref() {
            return Ok(LockStartupResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        if let Some(owner) = state.startup_write.as_ref() {
            return Ok(LockStartupResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        before_lock()?;
        state.startup_lock = Some(StartupLock {
            session_id,
            session,
        });
        Ok(LockStartupResult::Acquired)
    }

    /// Acquires a short-lived startup datastore write guard.
    pub(crate) fn begin_startup_write(&self, session_id: u64) -> StartupWriteResult {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        let Some(session) = state.sessions.get(&session_id).cloned() else {
            return StartupWriteResult::SessionNotRegistered;
        };
        if let Some(owner) = state.startup_lock.as_ref() {
            if owner.session_id != session_id {
                return StartupWriteResult::Denied {
                    owner_session_id: owner.session_id,
                };
            }
        }
        if let Some(owner) = state.startup_write.as_ref() {
            return StartupWriteResult::Denied {
                owner_session_id: owner.session_id,
            };
        }
        let lease = Arc::new(AtomicBool::new(true));
        state.startup_write = Some(StartupWrite {
            session_id,
            session,
            lease: Arc::clone(&lease),
        });
        StartupWriteResult::Acquired(StartupWriteGuard {
            registry: self.clone(),
            lease,
        })
    }

    /// Releases the global startup datastore lock after `before_unlock`
    /// succeeds.
    pub(crate) fn unlock_startup_after<F, E>(
        &self,
        session_id: u64,
        before_unlock: F,
    ) -> Result<UnlockStartupResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        if !state.sessions.contains_key(&session_id) {
            return Ok(UnlockStartupResult::SessionNotRegistered);
        }
        match state.startup_lock.as_ref() {
            Some(owner) if owner.session_id == session_id => {
                before_unlock()?;
                state.startup_lock = None;
                Ok(UnlockStartupResult::Unlocked)
            }
            Some(owner) => Ok(UnlockStartupResult::NotOwner {
                owner_session_id: owner.session_id,
            }),
            None => Ok(UnlockStartupResult::NotLocked),
        }
    }

    fn deregister(&self, session_id: u64, entry: &Arc<SessionEntry>) {
        entry.active.store(false, Ordering::Release);
        let Ok(mut state) = self.inner.try_lock() else {
            // All entry points lazily reap inactive generations. Drop must
            // never wait behind an audit hook or park an async runtime thread.
            return;
        };
        state.prune_inactive();
        if state
            .sessions
            .get(&session_id)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            state.sessions.remove(&session_id);
            state.release_running_lock(session_id);
            state.release_running_write(session_id);
            state.release_candidate_lock(session_id);
            state.release_candidate_write(session_id);
            state.release_startup_lock(session_id);
            state.release_startup_write(session_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_session_for_test(&self, session_id: u64) -> bool {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.sessions.contains_key(&session_id)
    }

    #[cfg(test)]
    pub(crate) fn running_lock_owner_for_test(&self) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.running_lock.as_ref().map(|lock| lock.session_id)
    }

    #[cfg(test)]
    pub(crate) fn running_write_owner_for_test(&self) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.running_write.as_ref().map(|write| write.session_id)
    }

    #[cfg(test)]
    pub(crate) fn candidate_lock_owner_for_test(&self) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.candidate_lock.as_ref().map(|lock| lock.session_id)
    }

    #[cfg(test)]
    pub(crate) fn candidate_write_owner_for_test(&self) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.candidate_write.as_ref().map(|write| write.session_id)
    }

    #[cfg(test)]
    pub(crate) fn startup_lock_owner_for_test(&self) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.startup_lock.as_ref().map(|lock| lock.session_id)
    }

    #[cfg(test)]
    pub(crate) fn startup_write_owner_for_test(&self) -> Option<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        state.prune_inactive();
        state.startup_write.as_ref().map(|write| write.session_id)
    }
}

#[derive(Debug, Default)]
struct RegistryState {
    sessions: HashMap<u64, Arc<SessionEntry>>,
    running_lock: Option<RunningLock>,
    running_write: Option<RunningWrite>,
    candidate_lock: Option<CandidateLock>,
    candidate_write: Option<CandidateWrite>,
    startup_lock: Option<StartupLock>,
    startup_write: Option<StartupWrite>,
}

impl RegistryState {
    fn prune_inactive(&mut self) {
        self.sessions
            .retain(|_, entry| entry.active.load(Ordering::Acquire));
        if self
            .running_lock
            .as_ref()
            .is_some_and(|owner| !owner.session.active.load(Ordering::Acquire))
        {
            self.running_lock = None;
        }
        if self
            .candidate_lock
            .as_ref()
            .is_some_and(|owner| !owner.session.active.load(Ordering::Acquire))
        {
            self.candidate_lock = None;
        }
        if self
            .startup_lock
            .as_ref()
            .is_some_and(|owner| !owner.session.active.load(Ordering::Acquire))
        {
            self.startup_lock = None;
        }
        if self.running_write.as_ref().is_some_and(|owner| {
            !owner.session.active.load(Ordering::Acquire) || !owner.lease.load(Ordering::Acquire)
        }) {
            self.running_write = None;
        }
        if self.candidate_write.as_ref().is_some_and(|owner| {
            !owner.session.active.load(Ordering::Acquire) || !owner.lease.load(Ordering::Acquire)
        }) {
            self.candidate_write = None;
        }
        if self.startup_write.as_ref().is_some_and(|owner| {
            !owner.session.active.load(Ordering::Acquire) || !owner.lease.load(Ordering::Acquire)
        }) {
            self.startup_write = None;
        }
    }

    fn release_running_lock(&mut self, session_id: u64) {
        if self
            .running_lock
            .as_ref()
            .is_some_and(|lock| lock.session_id == session_id)
        {
            self.running_lock = None;
        }
    }

    fn release_running_write(&mut self, session_id: u64) {
        if self
            .running_write
            .as_ref()
            .is_some_and(|write| write.session_id == session_id)
        {
            self.running_write = None;
        }
    }

    fn release_candidate_lock(&mut self, session_id: u64) {
        if self
            .candidate_lock
            .as_ref()
            .is_some_and(|lock| lock.session_id == session_id)
        {
            self.candidate_lock = None;
        }
    }

    fn release_candidate_write(&mut self, session_id: u64) {
        if self
            .candidate_write
            .as_ref()
            .is_some_and(|write| write.session_id == session_id)
        {
            self.candidate_write = None;
        }
    }

    fn release_startup_lock(&mut self, session_id: u64) {
        if self
            .startup_lock
            .as_ref()
            .is_some_and(|lock| lock.session_id == session_id)
        {
            self.startup_lock = None;
        }
    }

    fn release_startup_write(&mut self, session_id: u64) {
        if self
            .startup_write
            .as_ref()
            .is_some_and(|write| write.session_id == session_id)
        {
            self.startup_write = None;
        }
    }
}

#[derive(Debug)]
struct SessionEntry {
    kill_tx: watch::Sender<bool>,
    active: AtomicBool,
}

#[derive(Debug, Clone)]
struct RunningLock {
    session_id: u64,
    session: Arc<SessionEntry>,
}

#[derive(Debug, Clone)]
struct RunningWrite {
    session_id: u64,
    session: Arc<SessionEntry>,
    lease: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct CandidateLock {
    session_id: u64,
    session: Arc<SessionEntry>,
}

#[derive(Debug, Clone)]
struct CandidateWrite {
    session_id: u64,
    session: Arc<SessionEntry>,
    lease: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct StartupLock {
    session_id: u64,
    session: Arc<SessionEntry>,
}

#[derive(Debug, Clone)]
struct StartupWrite {
    session_id: u64,
    session: Arc<SessionEntry>,
    lease: Arc<AtomicBool>,
}

/// Drop guard for an in-flight running datastore write.
pub(crate) struct RunningWriteGuard {
    registry: SessionRegistry,
    lease: Arc<AtomicBool>,
}

impl Drop for RunningWriteGuard {
    fn drop(&mut self) {
        self.lease.store(false, Ordering::Release);
        if let Ok(mut state) = self.registry.inner.try_lock() {
            state.prune_inactive();
        }
    }
}

/// Drop guard for an in-flight candidate datastore write.
pub(crate) struct CandidateWriteGuard {
    registry: SessionRegistry,
    lease: Arc<AtomicBool>,
}

/// Drop guard for an in-flight startup datastore write.
pub(crate) struct StartupWriteGuard {
    registry: SessionRegistry,
    lease: Arc<AtomicBool>,
}

impl Drop for StartupWriteGuard {
    fn drop(&mut self) {
        self.lease.store(false, Ordering::Release);
        if let Ok(mut state) = self.registry.inner.try_lock() {
            state.prune_inactive();
        }
    }
}

impl Drop for CandidateWriteGuard {
    fn drop(&mut self) {
        self.lease.store(false, Ordering::Release);
        if let Ok(mut state) = self.registry.inner.try_lock() {
            state.prune_inactive();
        }
    }
}

/// Live-session registration handle.
pub(crate) struct SessionRegistration {
    registry: SessionRegistry,
    session_id: u64,
    entry: Arc<SessionEntry>,
    kill_rx: watch::Receiver<bool>,
}

impl SessionRegistration {
    /// Registered session id.
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns true once another session has requested termination.
    pub fn is_terminated(&self) -> bool {
        *self.kill_rx.borrow()
    }

    /// Waits until another session requests termination.
    pub(crate) async fn terminated(&mut self) {
        loop {
            if self.is_terminated() {
                return;
            }
            if self.kill_rx.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        self.registry.deregister(self.session_id, &self.entry);
    }
}

/// Session registry registration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRegistryError {
    /// The session id is outside the NETCONF session-id range.
    InvalidSessionId,
    /// The session id is already registered.
    DuplicateSessionId,
    /// The bounded async registry worker could not be admitted or completed.
    Unavailable,
}

/// Result of a `<kill-session>` termination request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillSessionResult {
    /// The target session was live and has been signaled to terminate.
    Terminated,
    /// No live target session exists.
    NotFound,
}

/// Result of a running datastore lock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockRunningResult {
    /// The calling session now owns the running lock.
    Acquired,
    /// The running lock is already owned by a NETCONF session.
    Denied {
        /// NETCONF session id that owns the lock.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of a running datastore unlock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlockRunningResult {
    /// The calling session's running lock was released.
    Unlocked,
    /// No running lock is currently active.
    NotLocked,
    /// A different NETCONF session owns the running lock.
    NotOwner {
        /// NETCONF session id that owns the lock.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of acquiring a short-lived running write guard.
pub(crate) enum RunningWriteResult {
    /// The calling session may write running until the guard is dropped.
    Acquired(RunningWriteGuard),
    /// The running datastore is locked or being written by another session.
    Denied {
        /// NETCONF session id that currently owns running.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of a candidate datastore lock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockCandidateResult {
    /// The calling session now owns the candidate lock.
    Acquired,
    /// The candidate lock is already owned by a NETCONF session.
    Denied {
        /// NETCONF session id that owns the lock.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of a candidate datastore unlock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlockCandidateResult {
    /// The calling session's candidate lock was released.
    Unlocked,
    /// No candidate lock is currently active.
    NotLocked,
    /// A different NETCONF session owns the candidate lock.
    NotOwner {
        /// NETCONF session id that owns the lock.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of acquiring a short-lived candidate write guard.
pub(crate) enum CandidateWriteResult {
    /// The calling session may write candidate until the guard is dropped.
    Acquired(CandidateWriteGuard),
    /// The candidate datastore is locked or being written by another session.
    Denied {
        /// NETCONF session id that currently owns candidate.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of a startup datastore lock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockStartupResult {
    /// The calling session now owns the startup lock.
    Acquired,
    /// The startup lock is already owned by a NETCONF session.
    Denied {
        /// NETCONF session id that owns the lock.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of a startup datastore unlock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnlockStartupResult {
    /// The calling session's startup lock was released.
    Unlocked,
    /// No startup lock is currently active.
    NotLocked,
    /// A different NETCONF session owns the startup lock.
    NotOwner {
        /// NETCONF session id that owns the lock.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

/// Result of acquiring a short-lived startup write guard.
pub(crate) enum StartupWriteResult {
    /// The calling session may write startup until the guard is dropped.
    Acquired(StartupWriteGuard),
    /// The startup datastore is locked or being written by another session.
    Denied {
        /// NETCONF session id that currently owns startup.
        owner_session_id: u64,
    },
    /// The current session id is not registered in this registry.
    SessionNotRegistered,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn duplicate_session_id_is_rejected() {
        let registry = SessionRegistry::new();
        let _first = registry.register(7).expect("first registration");

        assert!(matches!(
            registry.register(7),
            Err(SessionRegistryError::DuplicateSessionId)
        ));
    }

    #[test]
    fn invalid_session_ids_are_rejected() {
        let registry = SessionRegistry::new();

        assert!(matches!(
            registry.register(0),
            Err(SessionRegistryError::InvalidSessionId)
        ));
        assert!(matches!(
            registry.register(NETCONF_MAX_SESSION_ID + 1),
            Err(SessionRegistryError::InvalidSessionId)
        ));
    }

    #[tokio::test]
    async fn terminate_signals_registered_session_and_drop_deregisters() {
        let registry = SessionRegistry::new();
        let mut registration = registry.register(42).expect("register");

        assert_eq!(
            registry.terminate_after(42, || Ok::<(), ()>(())),
            Ok(KillSessionResult::Terminated)
        );
        registration.terminated().await;
        assert!(registration.is_terminated());

        drop(registration);
        assert_eq!(
            registry.terminate_after(42, || Ok::<(), ()>(())),
            Ok(KillSessionResult::NotFound)
        );
    }

    #[test]
    fn terminate_after_failure_does_not_signal_session() {
        let registry = SessionRegistry::new();
        let registration = registry.register(42).expect("register");

        let result = registry.terminate_after(42, || Err("audit failed"));

        assert_eq!(result, Err("audit failed"));
        assert!(!registration.is_terminated());
        assert!(matches!(
            registry.register(42),
            Err(SessionRegistryError::DuplicateSessionId)
        ));
    }

    #[test]
    fn inactive_generation_with_live_receiver_is_not_found_before_audit() {
        let registry = SessionRegistry::new();
        let registration = registry.register(42).expect("register");
        // Model Registration::drop after its release-store but before the
        // receiver field is dropped. A receiver count alone must not revive it.
        registration.entry.active.store(false, Ordering::Release);
        let mut audited = false;

        let result = registry.terminate_after(42, || {
            audited = true;
            Ok::<(), ()>(())
        });

        assert_eq!(result, Ok(KillSessionResult::NotFound));
        assert!(!audited);
        drop(registration);
        let replacement = registry.register(42).expect("same-id replacement");
        assert!(!replacement.is_terminated());
    }

    #[test]
    fn disappearance_during_audit_terminates_only_the_exact_generation() {
        let registry = SessionRegistry::new();
        let mut old_generation = Some(registry.register(42).expect("register"));

        let result = registry.terminate_after(42, || {
            drop(old_generation.take());
            Ok::<(), ()>(())
        });

        assert_eq!(result, Ok(KillSessionResult::Terminated));
        let replacement = registry.register(42).expect("same-id replacement");
        assert!(
            !replacement.is_terminated(),
            "old generation's kill signal leaked across id reuse"
        );
        assert_eq!(
            registry.terminate_after(42, || Ok::<(), ()>(())),
            Ok(KillSessionResult::Terminated)
        );
        assert!(replacement.is_terminated());
    }

    #[test]
    fn stale_entry_without_receiver_is_not_found_without_hook() {
        let registry = SessionRegistry::new();
        let (kill_tx, kill_rx) = watch::channel(false);
        drop(kill_rx);
        registry
            .inner
            .lock()
            .expect("registry mutex")
            .sessions
            .insert(
                42,
                Arc::new(SessionEntry {
                    kill_tx,
                    active: AtomicBool::new(true),
                }),
            );

        let result = registry.terminate_after(42, || panic!("hook must not run"));

        assert_eq!(result, Ok::<_, ()>(KillSessionResult::NotFound));
        assert!(!registry
            .inner
            .lock()
            .expect("registry mutex")
            .sessions
            .contains_key(&42));
    }

    #[test]
    fn running_lock_is_acquired_denied_and_released_by_owner() {
        let registry = SessionRegistry::new();
        let _owner = registry.register(10).expect("owner");
        let _other = registry.register(11).expect("other");

        assert_eq!(
            registry.lock_running_after(10, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Acquired)
        );
        assert_eq!(registry.running_lock_owner_for_test(), Some(10));
        assert_eq!(
            registry.lock_running_after(11, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Denied {
                owner_session_id: 10
            })
        );
        assert_eq!(
            registry.unlock_running_after(11, || Ok::<(), ()>(())),
            Ok(UnlockRunningResult::NotOwner {
                owner_session_id: 10
            })
        );
        assert_eq!(
            registry.unlock_running_after(10, || Ok::<(), ()>(())),
            Ok(UnlockRunningResult::Unlocked)
        );
        assert_eq!(registry.running_lock_owner_for_test(), None);
        assert_eq!(
            registry.unlock_running_after(10, || Ok::<(), ()>(())),
            Ok(UnlockRunningResult::NotLocked)
        );
    }

    #[test]
    fn running_lock_audit_failure_prevents_state_change() {
        let registry = SessionRegistry::new();
        let _owner = registry.register(10).expect("owner");

        let result = registry.lock_running_after(10, || Err("audit failed"));

        assert_eq!(result, Err("audit failed"));
        assert_eq!(registry.running_lock_owner_for_test(), None);
    }

    #[test]
    fn running_lock_released_when_session_deregisters() {
        let registry = SessionRegistry::new();
        let owner = registry.register(10).expect("owner");
        assert_eq!(
            registry.lock_running_after(10, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Acquired)
        );

        drop(owner);

        assert_eq!(registry.running_lock_owner_for_test(), None);
    }

    #[test]
    fn running_write_guard_denies_parallel_writes_and_releases_on_drop() {
        let registry = SessionRegistry::new();
        let _first = registry.register(10).expect("register first");
        let _second = registry.register(11).expect("register second");

        let guard = match registry.begin_running_write(10) {
            RunningWriteResult::Acquired(guard) => guard,
            _ => panic!("first writer should acquire"),
        };
        assert_eq!(registry.running_write_owner_for_test(), Some(10));

        assert!(matches!(
            registry.begin_running_write(11),
            RunningWriteResult::Denied {
                owner_session_id: 10
            }
        ));
        assert!(matches!(
            registry.lock_running_after(11, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Denied {
                owner_session_id: 10
            })
        ));

        drop(guard);
        assert_eq!(registry.running_write_owner_for_test(), None);
        assert!(matches!(
            registry.begin_running_write(11),
            RunningWriteResult::Acquired(_)
        ));
    }

    #[test]
    fn running_write_respects_existing_running_lock_owner() {
        let registry = SessionRegistry::new();
        let _first = registry.register(10).expect("register first");
        let _second = registry.register(11).expect("register second");

        assert_eq!(
            registry.lock_running_after(10, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Acquired)
        );
        assert!(matches!(
            registry.begin_running_write(11),
            RunningWriteResult::Denied {
                owner_session_id: 10
            }
        ));
        assert!(matches!(
            registry.begin_running_write(10),
            RunningWriteResult::Acquired(_)
        ));
    }

    #[test]
    fn candidate_lock_is_independent_from_running_lock() {
        let registry = SessionRegistry::new();
        let _running_owner = registry.register(10).expect("running owner");
        let _candidate_owner = registry.register(11).expect("candidate owner");

        assert_eq!(
            registry.lock_running_after(10, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Acquired)
        );
        assert_eq!(
            registry.lock_candidate_after(11, || Ok::<(), ()>(())),
            Ok(LockCandidateResult::Acquired)
        );

        assert_eq!(registry.running_lock_owner_for_test(), Some(10));
        assert_eq!(registry.candidate_lock_owner_for_test(), Some(11));
    }

    #[test]
    fn candidate_write_guard_denies_parallel_candidate_writes_and_releases_on_drop() {
        let registry = SessionRegistry::new();
        let _first = registry.register(10).expect("register first");
        let _second = registry.register(11).expect("register second");

        let guard = match registry.begin_candidate_write(10) {
            CandidateWriteResult::Acquired(guard) => guard,
            _ => panic!("first candidate writer should acquire"),
        };
        assert_eq!(registry.candidate_write_owner_for_test(), Some(10));

        assert!(matches!(
            registry.begin_candidate_write(11),
            CandidateWriteResult::Denied {
                owner_session_id: 10
            }
        ));
        assert!(matches!(
            registry.lock_candidate_after(11, || Ok::<(), ()>(())),
            Ok(LockCandidateResult::Denied {
                owner_session_id: 10
            })
        ));

        drop(guard);
        assert_eq!(registry.candidate_write_owner_for_test(), None);
        assert!(matches!(
            registry.begin_candidate_write(11),
            CandidateWriteResult::Acquired(_)
        ));
    }

    #[test]
    fn candidate_lock_and_write_release_when_session_deregisters() {
        let registry = SessionRegistry::new();
        let owner = registry.register(10).expect("owner");
        assert_eq!(
            registry.lock_candidate_after(10, || Ok::<(), ()>(())),
            Ok(LockCandidateResult::Acquired)
        );
        let guard = match registry.begin_candidate_write(10) {
            CandidateWriteResult::Acquired(guard) => guard,
            _ => panic!("candidate write should acquire for lock owner"),
        };
        assert_eq!(registry.candidate_lock_owner_for_test(), Some(10));
        assert_eq!(registry.candidate_write_owner_for_test(), Some(10));

        drop(owner);

        assert_eq!(registry.candidate_lock_owner_for_test(), None);
        assert_eq!(registry.candidate_write_owner_for_test(), None);
        drop(guard);
    }

    #[test]
    fn startup_lock_and_write_release_when_session_deregisters() {
        let registry = SessionRegistry::new();
        let owner = registry.register(10).expect("owner");
        assert_eq!(
            registry.lock_startup_after(10, || Ok::<(), ()>(())),
            Ok(LockStartupResult::Acquired)
        );
        let guard = match registry.begin_startup_write(10) {
            StartupWriteResult::Acquired(guard) => guard,
            _ => panic!("startup write should acquire for lock owner"),
        };
        assert_eq!(registry.startup_lock_owner_for_test(), Some(10));
        assert_eq!(registry.startup_write_owner_for_test(), Some(10));

        drop(owner);

        assert_eq!(registry.startup_lock_owner_for_test(), None);
        assert_eq!(registry.startup_write_owner_for_test(), None);
        drop(guard);
    }
}
