//! In-process NETCONF session termination registry.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

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
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

impl SessionRegistry {
    /// Builds an empty session registry.
    pub fn new() -> Self {
        Self::default()
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
        let entry = Arc::new(SessionEntry { kill_tx });
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
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
    /// event before any target session observes the termination signal. It is
    /// called while the registry map is locked so the target cannot deregister
    /// between the existence check and the signal.
    pub(crate) fn terminate_after<F, E>(
        &self,
        session_id: u64,
        before_signal: F,
    ) -> Result<KillSessionResult, E>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        let Some(entry) = state.sessions.get(&session_id).cloned() else {
            return Ok(KillSessionResult::NotFound);
        };
        if entry.kill_tx.receiver_count() == 0 {
            state.sessions.remove(&session_id);
            state.release_running_lock(session_id);
            state.release_running_write(session_id);
            state.release_candidate_lock(session_id);
            state.release_candidate_write(session_id);
            state.release_startup_lock(session_id);
            state.release_startup_write(session_id);
            return Ok(KillSessionResult::NotFound);
        }
        before_signal()?;
        if entry.kill_tx.send(true).is_ok() {
            Ok(KillSessionResult::Terminated)
        } else {
            state.sessions.remove(&session_id);
            state.release_running_lock(session_id);
            state.release_running_write(session_id);
            state.release_candidate_lock(session_id);
            state.release_candidate_write(session_id);
            state.release_startup_lock(session_id);
            state.release_startup_write(session_id);
            Ok(KillSessionResult::NotFound)
        }
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
        if !state.sessions.contains_key(&session_id) {
            return Ok(LockRunningResult::SessionNotRegistered);
        }
        if let Some(owner) = state.running_lock {
            return Ok(LockRunningResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        if let Some(owner) = state.running_write {
            return Ok(LockRunningResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        before_lock()?;
        state.running_lock = Some(RunningLock { session_id });
        Ok(LockRunningResult::Acquired)
    }

    /// Acquires a short-lived running datastore write guard.
    pub(crate) fn begin_running_write(&self, session_id: u64) -> RunningWriteResult {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        if !state.sessions.contains_key(&session_id) {
            return RunningWriteResult::SessionNotRegistered;
        }
        if let Some(owner) = state.running_lock {
            if owner.session_id != session_id {
                return RunningWriteResult::Denied {
                    owner_session_id: owner.session_id,
                };
            }
        }
        if let Some(owner) = state.running_write {
            return RunningWriteResult::Denied {
                owner_session_id: owner.session_id,
            };
        }
        state.running_write = Some(RunningWrite { session_id });
        RunningWriteResult::Acquired(RunningWriteGuard {
            registry: self.clone(),
            session_id,
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
        if !state.sessions.contains_key(&session_id) {
            return Ok(UnlockRunningResult::SessionNotRegistered);
        }
        match state.running_lock {
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
        if !state.sessions.contains_key(&session_id) {
            return Ok(LockCandidateResult::SessionNotRegistered);
        }
        if let Some(owner) = state.candidate_lock {
            return Ok(LockCandidateResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        if let Some(owner) = state.candidate_write {
            return Ok(LockCandidateResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        before_lock()?;
        state.candidate_lock = Some(CandidateLock { session_id });
        Ok(LockCandidateResult::Acquired)
    }

    /// Acquires a short-lived candidate datastore write guard.
    pub(crate) fn begin_candidate_write(&self, session_id: u64) -> CandidateWriteResult {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        if !state.sessions.contains_key(&session_id) {
            return CandidateWriteResult::SessionNotRegistered;
        }
        if let Some(owner) = state.candidate_lock {
            if owner.session_id != session_id {
                return CandidateWriteResult::Denied {
                    owner_session_id: owner.session_id,
                };
            }
        }
        if let Some(owner) = state.candidate_write {
            return CandidateWriteResult::Denied {
                owner_session_id: owner.session_id,
            };
        }
        state.candidate_write = Some(CandidateWrite { session_id });
        CandidateWriteResult::Acquired(CandidateWriteGuard {
            registry: self.clone(),
            session_id,
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
        if !state.sessions.contains_key(&session_id) {
            return Ok(UnlockCandidateResult::SessionNotRegistered);
        }
        match state.candidate_lock {
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
        if !state.sessions.contains_key(&session_id) {
            return Ok(LockStartupResult::SessionNotRegistered);
        }
        if let Some(owner) = state.startup_lock {
            return Ok(LockStartupResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        if let Some(owner) = state.startup_write {
            return Ok(LockStartupResult::Denied {
                owner_session_id: owner.session_id,
            });
        }
        before_lock()?;
        state.startup_lock = Some(StartupLock { session_id });
        Ok(LockStartupResult::Acquired)
    }

    /// Acquires a short-lived startup datastore write guard.
    pub(crate) fn begin_startup_write(&self, session_id: u64) -> StartupWriteResult {
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        if !state.sessions.contains_key(&session_id) {
            return StartupWriteResult::SessionNotRegistered;
        }
        if let Some(owner) = state.startup_lock {
            if owner.session_id != session_id {
                return StartupWriteResult::Denied {
                    owner_session_id: owner.session_id,
                };
            }
        }
        if let Some(owner) = state.startup_write {
            return StartupWriteResult::Denied {
                owner_session_id: owner.session_id,
            };
        }
        state.startup_write = Some(StartupWrite { session_id });
        StartupWriteResult::Acquired(StartupWriteGuard {
            registry: self.clone(),
            session_id,
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
        if !state.sessions.contains_key(&session_id) {
            return Ok(UnlockStartupResult::SessionNotRegistered);
        }
        match state.startup_lock {
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
        let mut state = self.inner.lock().unwrap_or_else(|err| err.into_inner());
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
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .sessions
            .contains_key(&session_id)
    }

    #[cfg(test)]
    pub(crate) fn running_lock_owner_for_test(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .running_lock
            .map(|lock| lock.session_id)
    }

    #[cfg(test)]
    pub(crate) fn running_write_owner_for_test(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .running_write
            .map(|write| write.session_id)
    }

    #[cfg(test)]
    pub(crate) fn candidate_lock_owner_for_test(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .candidate_lock
            .map(|lock| lock.session_id)
    }

    #[cfg(test)]
    pub(crate) fn candidate_write_owner_for_test(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .candidate_write
            .map(|write| write.session_id)
    }

    #[cfg(test)]
    pub(crate) fn startup_lock_owner_for_test(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .startup_lock
            .map(|lock| lock.session_id)
    }

    #[cfg(test)]
    pub(crate) fn startup_write_owner_for_test(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .startup_write
            .map(|write| write.session_id)
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
    fn release_running_lock(&mut self, session_id: u64) {
        if self
            .running_lock
            .is_some_and(|lock| lock.session_id == session_id)
        {
            self.running_lock = None;
        }
    }

    fn release_running_write(&mut self, session_id: u64) {
        if self
            .running_write
            .is_some_and(|write| write.session_id == session_id)
        {
            self.running_write = None;
        }
    }

    fn release_candidate_lock(&mut self, session_id: u64) {
        if self
            .candidate_lock
            .is_some_and(|lock| lock.session_id == session_id)
        {
            self.candidate_lock = None;
        }
    }

    fn release_candidate_write(&mut self, session_id: u64) {
        if self
            .candidate_write
            .is_some_and(|write| write.session_id == session_id)
        {
            self.candidate_write = None;
        }
    }

    fn release_startup_lock(&mut self, session_id: u64) {
        if self
            .startup_lock
            .is_some_and(|lock| lock.session_id == session_id)
        {
            self.startup_lock = None;
        }
    }

    fn release_startup_write(&mut self, session_id: u64) {
        if self
            .startup_write
            .is_some_and(|write| write.session_id == session_id)
        {
            self.startup_write = None;
        }
    }
}

#[derive(Debug)]
struct SessionEntry {
    kill_tx: watch::Sender<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunningLock {
    session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunningWrite {
    session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateLock {
    session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateWrite {
    session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartupLock {
    session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartupWrite {
    session_id: u64,
}

/// Drop guard for an in-flight running datastore write.
pub(crate) struct RunningWriteGuard {
    registry: SessionRegistry,
    session_id: u64,
}

impl Drop for RunningWriteGuard {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .inner
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.release_running_write(self.session_id);
    }
}

/// Drop guard for an in-flight candidate datastore write.
pub(crate) struct CandidateWriteGuard {
    registry: SessionRegistry,
    session_id: u64,
}

/// Drop guard for an in-flight startup datastore write.
pub(crate) struct StartupWriteGuard {
    registry: SessionRegistry,
    session_id: u64,
}

impl Drop for StartupWriteGuard {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .inner
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.release_startup_write(self.session_id);
    }
}

impl Drop for CandidateWriteGuard {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .inner
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.release_candidate_write(self.session_id);
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
    fn stale_entry_without_receiver_is_not_found_without_hook() {
        let registry = SessionRegistry::new();
        let (kill_tx, kill_rx) = watch::channel(false);
        drop(kill_rx);
        registry
            .inner
            .lock()
            .expect("registry mutex")
            .sessions
            .insert(42, Arc::new(SessionEntry { kill_tx }));

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
