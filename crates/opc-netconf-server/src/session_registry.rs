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
    inner: Arc<Mutex<HashMap<u64, Arc<SessionEntry>>>>,
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
        let mut sessions = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        if sessions.contains_key(&session_id) {
            return Err(SessionRegistryError::DuplicateSessionId);
        }
        sessions.insert(session_id, Arc::clone(&entry));
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
        let mut sessions = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        let Some(entry) = sessions.get(&session_id).cloned() else {
            return Ok(KillSessionResult::NotFound);
        };
        if entry.kill_tx.receiver_count() == 0 {
            sessions.remove(&session_id);
            return Ok(KillSessionResult::NotFound);
        }
        before_signal()?;
        if entry.kill_tx.send(true).is_ok() {
            Ok(KillSessionResult::Terminated)
        } else {
            sessions.remove(&session_id);
            Ok(KillSessionResult::NotFound)
        }
    }

    fn deregister(&self, session_id: u64, entry: &Arc<SessionEntry>) {
        let mut sessions = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        if sessions
            .get(&session_id)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            sessions.remove(&session_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_session_for_test(&self, session_id: u64) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .contains_key(&session_id)
    }
}

#[derive(Debug)]
struct SessionEntry {
    kill_tx: watch::Sender<bool>,
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

#[cfg(test)]
mod tests {
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
            .insert(42, Arc::new(SessionEntry { kill_tx }));

        let result = registry.terminate_after(42, || panic!("hook must not run"));

        assert_eq!(result, Ok::<_, ()>(KillSessionResult::NotFound));
        assert!(registry
            .inner
            .lock()
            .expect("registry mutex")
            .get(&42)
            .is_none());
    }
}
