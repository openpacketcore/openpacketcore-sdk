//! Process ownership and caller lifetimes. None of this state is durable.

use super::*;
use crate::FencedTransitionV2RequestId;
use std::collections::BTreeMap;

/// Whether an exact retained request can be considered for a consensus void.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FencedTransitionV2VoidEligibility {
    /// This journal was not created under the exclusive ownership contract.
    UnsupportedJournal,
    /// Its current owner has a caller within its original deadline, or the
    /// caller prepared a row without registering a deadline.
    WaitingCaller,
    /// The caller returned, its deadline elapsed, or the row was inherited.
    Ready,
}

struct CallState {
    physical_id: Mutex<Option<FencedTransitionV2RequestId>>,
    deadline: Option<tokio::time::Instant>,
    lifecycle: Mutex<CallLifecycle>,
    terminal: Mutex<Option<crate::FencedTransitionV2Status>>,
}

#[derive(Default)]
struct CallLifecycle {
    returned: bool,
    reclamation_started: bool,
}

/// A read-only in-memory notice of this handle's exact deciding receipt.
#[derive(Clone)]
pub struct FencedTransitionV2RecoveryNotice(Arc<CallState>);

impl FencedTransitionV2RecoveryNotice {
    /// Whether an exact terminal void receipt has been observed.
    pub fn was_voided(&self) -> bool {
        matches!(self.terminal_status(), Some(crate::FencedTransitionV2Status::Recorded(result)) if matches!(*result, Err(StoreError::FencedTransitionVoided)))
    }
    /// Return the exact deciding receipt observed by reclamation, if any.
    pub fn terminal_status(&self) -> Option<crate::FencedTransitionV2Status> {
        self.0
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// The lifetime of a current owner's original call, including preparation.
///
/// Retain it through the original deadline when an attempt returns unknown.
/// A known return, cancellation, or drop permits void after exact NotFound;
/// it does not itself release or void any row.
pub struct FencedTransitionV2RecoveryCall {
    notice: FencedTransitionV2RecoveryNotice,
    _owner: Arc<RecoveryJournalInner>,
}

impl FencedTransitionV2RecoveryCall {
    /// Record a known return or cancellation. An unknown return must keep
    /// this registration alive until the original deadline or handle drop.
    pub fn returned(&self) {
        self.notice
            .0
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .returned = true;
    }

    /// Clear prior return/cancellation eligibility before dispatch resumes.
    /// False means reclamation already claimed this request; the caller must
    /// resolve its receipt instead of dispatching the original again.
    pub fn dispatch_started(&self) -> bool {
        let mut lifecycle = self
            .notice
            .0
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lifecycle.reclamation_started {
            return false;
        }
        lifecycle.returned = false;
        true
    }

    /// Retain a notice without changing the original call's lifetime.
    pub fn notice(&self) -> FencedTransitionV2RecoveryNotice {
        self.notice.clone()
    }
}

impl Drop for FencedTransitionV2RecoveryCall {
    fn drop(&mut self) {
        self.returned();
    }
}

#[derive(Default)]
struct Lifetimes {
    inherited: BTreeSet<[u8; FENCED_TRANSITION_REQUEST_ID_BYTES]>,
    calls: BTreeMap<[u8; FENCED_TRANSITION_REQUEST_ID_BYTES], Arc<CallState>>,
}

pub(super) struct RecoveryOwnership {
    lifetimes: Mutex<Lifetimes>,
    // RecoveryJournalInner closes SQLite before dropping this descriptor.
    // Closing an independent main-file descriptor while SQLite is alive can
    // otherwise release SQLite's process-scoped POSIX locks.
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<std::fs::File>,
}

#[cfg(unix)]
pub(super) fn lock(
    path: &SecureJournalPathGuard,
) -> Result<nix::fcntl::Flock<std::fs::File>, StoreError> {
    use nix::{
        fcntl::{openat, Flock, FlockArg, OFlag},
        sys::stat::{fstat, Mode},
    };
    path.verify().map_err(|_| recovery_unavailable())?;
    let descriptor = openat(
        &path.parent,
        path.leaf_name.as_os_str(),
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| recovery_unavailable())?;
    let stat = fstat(&descriptor).map_err(|_| recovery_unavailable())?;
    if !path.leaf_identity.matches(&stat) {
        return Err(recovery_unavailable());
    }
    Flock::lock(
        std::fs::File::from(descriptor),
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, error)| lock_error(error))
}

#[cfg(unix)]
pub(super) fn lock_error(error: nix::errno::Errno) -> StoreError {
    if error == nix::errno::Errno::EWOULDBLOCK {
        recovery_owner_locked()
    } else {
        StoreError::BackendUnavailable(
            "protected fenced-transition V2 recovery journal locking unavailable".into(),
        )
    }
}

impl RecoveryOwnership {
    #[cfg(unix)]
    pub(super) fn new(
        lock: nix::fcntl::Flock<std::fs::File>,
        inherited: BTreeSet<[u8; FENCED_TRANSITION_REQUEST_ID_BYTES]>,
    ) -> Self {
        Self {
            lifetimes: Mutex::new(Lifetimes {
                inherited,
                calls: BTreeMap::new(),
            }),
            _lock: lock,
        }
    }

    pub(super) fn inserted(
        &self,
        id: FencedTransitionRequestId,
        physical: FencedTransitionV2RequestId,
    ) {
        let mut lifetimes = self
            .lifetimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lifetimes.inherited.remove(id.as_bytes());
        if let Some(call) = lifetimes.calls.get(id.as_bytes()) {
            *call
                .physical_id
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(physical);
        }
    }

    pub(super) fn removed(&self, id: FencedTransitionRequestId) {
        let mut lifetimes = self
            .lifetimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lifetimes.inherited.remove(id.as_bytes());
        lifetimes.calls.remove(id.as_bytes());
    }
}

impl FencedTransitionV2RecoveryJournal {
    /// Register a caller before preparation can make its row visible.
    ///
    /// The registration is shared by every clone and facade using this
    /// journal. No deadline or process identifier is written to disk.
    pub async fn begin_call(
        &self,
        id: FencedTransitionRequestId,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2RecoveryCall, StoreError> {
        let state = Arc::new(CallState {
            physical_id: Mutex::new(None),
            deadline: Some(deadline),
            lifecycle: Mutex::new(CallLifecycle::default()),
            terminal: Mutex::new(None),
        });
        let call = FencedTransitionV2RecoveryCall {
            notice: FencedTransitionV2RecoveryNotice(Arc::clone(&state)),
            _owner: Arc::clone(&self.inner),
        };
        if let Some(ownership) = self.inner.ownership.clone() {
            let registered = Arc::clone(&state);
            self.with_connection(false, move |conn, key| {
                let transaction = recovery_read_transaction(conn)?;
                let (_, members) = verify_recovery_metadata_with_members(&transaction, key, None)?;
                let live = members
                    .into_iter()
                    .map(|row| row.request_id)
                    .collect::<BTreeSet<_>>();
                transaction.commit().map_err(|_| recovery_unavailable())?;
                let mut lifetimes = ownership
                    .lifetimes
                    .lock()
                    .map_err(|_| recovery_unavailable())?;
                // The operation permit waits for a cancelled blocking insert
                // to finish before absent completed registrations are pruned.
                lifetimes.calls.retain(|id, call| {
                    live.contains(id)
                        || !call
                            .lifecycle
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .returned
                });
                if live.contains(id.as_bytes()) || lifetimes.calls.contains_key(id.as_bytes()) {
                    return Err(StoreError::FencedTransitionRequestConflict);
                }
                if lifetimes.calls.len() >= FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES {
                    return Err(StoreError::FencedTransitionHistoryFull);
                }
                lifetimes.calls.insert(*id.as_bytes(), registered);
                Ok(())
            })
            .await?;
        }
        Ok(call)
    }

    /// Check the caller-lifetime policy for a retained exact physical request.
    /// This is not a receipt or permission to remove the row.
    pub(crate) fn void_reclamation_eligibility(
        &self,
        id: FencedTransitionRequestId,
        physical: FencedTransitionV2RequestId,
    ) -> FencedTransitionV2VoidEligibility {
        let Some(ownership) = &self.inner.ownership else {
            return FencedTransitionV2VoidEligibility::UnsupportedJournal;
        };
        let lifetimes = ownership
            .lifetimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lifetimes.inherited.contains(id.as_bytes()) {
            return FencedTransitionV2VoidEligibility::Ready;
        }
        if lifetimes.calls.get(id.as_bytes()).is_some_and(|call| {
            *call
                .physical_id
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                == Some(physical)
                && (call
                    .lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .returned
                    || call
                        .deadline
                        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline))
        }) {
            FencedTransitionV2VoidEligibility::Ready
        } else {
            FencedTransitionV2VoidEligibility::WaitingCaller
        }
    }

    /// Serialize the final reclamation decision with a possible redispatch.
    /// A claim remains receipt-only even if the void reply is lost, because
    /// that void may still be in flight. Retrying the same void is permitted.
    pub(crate) fn try_begin_void(
        &self,
        id: FencedTransitionRequestId,
        physical: FencedTransitionV2RequestId,
    ) -> bool {
        let Some(ownership) = &self.inner.ownership else {
            return false;
        };
        let lifetimes = ownership
            .lifetimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(call) = lifetimes.calls.get(id.as_bytes()) else {
            // The caller authenticated the retained row before this method.
            // Only inheritance proves the prior owner is gone. A current
            // trait-level caller can still dispatch, and supplies no deadline
            // unless it registers a call before preparing this row.
            return lifetimes.inherited.contains(id.as_bytes());
        };
        if *call
            .physical_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            != Some(physical)
        {
            return false;
        }
        let mut lifecycle = call
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lifetimes.inherited.contains(id.as_bytes())
            || lifecycle.returned
            || lifecycle.reclamation_started
            || call
                .deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            lifecycle.reclamation_started = true;
            true
        } else {
            false
        }
    }

    /// Observe an exact retained request without releasing its caller fence.
    /// The caller must first authenticate this request in the journal.
    pub(super) fn notice_for_exact(
        &self,
        id: FencedTransitionRequestId,
        physical: FencedTransitionV2RequestId,
    ) -> Option<FencedTransitionV2RecoveryNotice> {
        let ownership = self.inner.ownership.as_ref()?;
        let mut lifetimes = ownership
            .lifetimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !lifetimes.calls.contains_key(id.as_bytes()) {
            // A late completion must not recreate a registration after its row
            // was removed. Current callers register before insertion; only a
            // still-retained inherited row can need its first notice here.
            if !lifetimes.inherited.contains(id.as_bytes()) {
                return None;
            }
            if lifetimes.calls.len() >= FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES {
                return None;
            }
            lifetimes.calls.insert(
                *id.as_bytes(),
                Arc::new(CallState {
                    physical_id: Mutex::new(Some(physical)),
                    deadline: None,
                    lifecycle: Mutex::new(CallLifecycle {
                        returned: true,
                        reclamation_started: false,
                    }),
                    terminal: Mutex::new(None),
                }),
            );
        }
        let call = lifetimes.calls.get(id.as_bytes())?;
        let matches = *call
            .physical_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == Some(physical);
        matches.then(|| FencedTransitionV2RecoveryNotice(Arc::clone(call)))
    }

    pub(crate) fn record_terminal(
        &self,
        id: FencedTransitionRequestId,
        physical: FencedTransitionV2RequestId,
        status: &crate::FencedTransitionV2Status,
    ) {
        if !matches!(status, crate::FencedTransitionV2Status::Recorded(_)) {
            return;
        }
        if let Some(notice) = self.notice_for_exact(id, physical) {
            let mut terminal = notice
                .0
                .terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if terminal.is_none() {
                *terminal = Some(status.clone());
            }
        }
    }
}
