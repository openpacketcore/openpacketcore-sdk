//! Completion ownership for retained authority admission.

use super::*;
use tokio::runtime::Handle;
use tokio::sync::SemaphorePermit;
use tokio::task::JoinHandle;

/// A completed join of a retained opener and any unclaimed backend disposal.
///
/// This reports resource retirement separately from admission or mutation
/// outcome. It does not establish storage freshness or authorize provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedConfigOpenRetirement {
    /// The opener and disposal have finished; no backend escaped this operation.
    /// Its SQLite connection and retained lock have been released.
    Released {
        /// Admission's final error. `Indeterminate` remains indeterminate after
        /// retirement: joining is not rollback or authoritative readback.
        admission_error: RetainedConfigError,
    },
    /// The opener finished and `wait` returned its backend. The caller owns that
    /// backend's lifetime, including clones and work using its connection. This
    /// operation cannot establish the retirement of those transferred owners.
    BackendReturned,
}

// Field order matters even when a detached task's unclaimed output is dropped:
// close SQLite and release FileAdmission before making the slot available.
struct AdmissionOutput {
    result: Result<SqliteBackend, RetainedConfigError>,
    _admission_slot: SemaphorePermit<'static>,
}

enum OpenState {
    Opening(JoinHandle<AdmissionOutput>),
    Discarding(JoinHandle<()>),
    Retired(RetainedConfigOpenRetirement),
}

/// Owns a retained opener until its worker and unclaimed result are retired.
///
/// Start with one of `SqliteBackend::begin_provision_config_authority`,
/// `SqliteBackend::begin_provision_config_member_repair`, or
/// `SqliteBackend::begin_reopen_config_authority`. Beginning requires a running
/// Tokio runtime; `wait` also requires its time driver.
///
/// `wait` borrows the operation and uses the original absolute deadline. If a
/// polled wait is cancelled or expires, cancellation is requested and no later
/// wait may grant a backend. Keep the operation and call `cancel_and_join` to
/// observe actual retirement. Both futures borrow rather than consume the
/// owner; dropping either future leaves its handles available for another join.
///
/// Blocking I/O cannot be forcefully aborted. Joining has no deadline and can
/// wait indefinitely for I/O or SQLite close. A completed but unclaimed success
/// still owns its connection, retained lock and admission slot until it is
/// returned or discarded. There are at most four such operations per process.
///
/// Dropping this owner only requests cancellation and relinquishes the join
/// handles; it never proves retirement. Drop attempts to move handle/result
/// destruction to the captured runtime's blocking pool. If that runtime has
/// shut down, destruction may run synchronously. Keep the runtime available
/// and explicitly join before shutdown when a retirement guarantee is needed.
#[must_use = "retain the operation and join cancellation to observe retirement"]
pub struct RetainedConfigOpen {
    work: Arc<AdmissionWork>,
    state: OpenState,
    runtime: Handle,
}

impl fmt::Debug for RetainedConfigOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedConfigOpen(<redacted>)")
    }
}

impl RetainedConfigOpen {
    pub(super) fn start(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
        intent: OpenIntent,
        work: Arc<AdmissionWork>,
    ) -> Result<Self, RetainedConfigError> {
        let runtime = Handle::try_current().map_err(|_| RetainedConfigError::Unavailable)?;
        let admission_slot = ADMISSION_GATE
            .try_acquire()
            .map_err(|_| RetainedConfigError::AdmissionBound)?;
        let worker_work = Arc::clone(&work);
        let worker = runtime.spawn_blocking(move || {
            let result =
                open_authority_sync(options, audit_key, intent, &worker_work).map_err(|error| {
                    if worker_work.mutated.load(Ordering::Acquire) {
                        RetainedConfigError::Indeterminate
                    } else {
                        error
                    }
                });
            #[cfg(test)]
            if let Ok(backend) = &result {
                if let Some(hook) = &worker_work.completion_hook {
                    hook(backend);
                }
                worker_work.stage("worker_succeeded");
            }
            AdmissionOutput {
                result,
                _admission_slot: admission_slot,
            }
        });
        Ok(Self {
            work,
            state: OpenState::Opening(worker),
            runtime,
        })
    }

    /// Request cooperative cancellation; this does not wait or prove retirement.
    ///
    /// Subsequent waits cannot grant an unclaimed backend. A backend previously
    /// returned to the caller is unaffected. Mutation may already have occurred.
    pub fn cancel(&self) {
        self.work.cancelled.store(true, Ordering::Release);
    }

    /// Await admission within its original absolute deadline, returning at most
    /// one backend. Polling and then dropping this future requests cancellation.
    ///
    /// Expiry returns `Indeterminate` without waiting for blocking work or close.
    /// The operation retains those owners for `cancel_and_join`. Repeated waits
    /// after a backend was returned yield `InvalidRequest`.
    pub async fn wait(&mut self) -> Result<SqliteBackend, RetainedConfigError> {
        let _cancellation = CancelOnDrop(Arc::clone(&self.work));
        let worker = match &mut self.state {
            OpenState::Opening(worker) => worker,
            OpenState::Discarding(_) => return Err(RetainedConfigError::Indeterminate),
            OpenState::Retired(RetainedConfigOpenRetirement::Released { admission_error }) => {
                return Err(*admission_error);
            }
            OpenState::Retired(RetainedConfigOpenRetirement::BackendReturned) => {
                return Err(RetainedConfigError::InvalidRequest);
            }
        };
        if self.work.check().is_err() {
            return Err(RetainedConfigError::Indeterminate);
        }
        let joined = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.work.deadline),
            worker,
        )
        .await
        {
            Ok(joined) => joined,
            Err(_) => return Err(RetainedConfigError::Indeterminate),
        };
        match joined {
            Ok(output) => {
                #[cfg(test)]
                self.work.stage("before_transfer");
                // Tokio timeout polls a ready handle before its timer. Admission
                // must still be valid at the point a capability is transferred.
                if output.result.is_ok() && self.work.check().is_err() {
                    self.discard(output);
                    return Err(RetainedConfigError::Indeterminate);
                }
                let AdmissionOutput {
                    result,
                    _admission_slot,
                } = output;
                self.state = OpenState::Retired(match &result {
                    Ok(_) => RetainedConfigOpenRetirement::BackendReturned,
                    Err(error) => RetainedConfigOpenRetirement::Released {
                        admission_error: *error,
                    },
                });
                result
            }
            Err(_) => {
                self.state = OpenState::Retired(RetainedConfigOpenRetirement::Released {
                    admission_error: RetainedConfigError::Indeterminate,
                });
                Err(RetainedConfigError::Indeterminate)
            }
        }
    }

    /// Cancel, discard any unclaimed success, and join actual resource retirement.
    ///
    /// There is no time bound on this join. Cancelling this future preserves the
    /// opening or disposal handle inside `self`, so another call can finish it.
    /// A returned `Released` value proves those owners are gone even if its
    /// admission error is `Indeterminate`. `BackendReturned` instead means the
    /// caller already owns the backend and this operation cannot retire it.
    /// Repeating a completed join returns the same report.
    pub async fn cancel_and_join(&mut self) -> RetainedConfigOpenRetirement {
        self.cancel();
        loop {
            match &mut self.state {
                OpenState::Opening(worker) => {
                    let joined = worker.await;
                    match joined {
                        Ok(output) => {
                            if let Err(error) = &output.result {
                                self.state =
                                    OpenState::Retired(RetainedConfigOpenRetirement::Released {
                                        admission_error: *error,
                                    });
                                // There is no backend in this output. Releasing
                                // the slot here cannot perform SQLite close.
                                drop(output);
                            } else {
                                self.discard(output);
                            }
                        }
                        Err(_) => {
                            self.state =
                                OpenState::Retired(RetainedConfigOpenRetirement::Released {
                                    admission_error: RetainedConfigError::Indeterminate,
                                });
                        }
                    }
                }
                OpenState::Discarding(worker) => {
                    // Await the stored handle by reference, including if a prior
                    // shutdown future was cancelled while SQLite close blocked.
                    let _ = worker.await;
                    self.state = OpenState::Retired(RetainedConfigOpenRetirement::Released {
                        admission_error: RetainedConfigError::Indeterminate,
                    });
                }
                OpenState::Retired(report) => return *report,
            }
        }
    }

    fn discard(&mut self, output: AdmissionOutput) {
        // No await separates taking the opening output and storing its disposal
        // handle. A cancelled future therefore cannot detach this ownership.
        self.state = OpenState::Discarding(self.runtime.spawn_blocking(move || drop(output)));
    }
}

impl Drop for RetainedConfigOpen {
    fn drop(&mut self) {
        self.cancel();
        if matches!(self.state, OpenState::Retired(_)) {
            return;
        }
        let state = std::mem::replace(
            &mut self.state,
            OpenState::Retired(RetainedConfigOpenRetirement::Released {
                admission_error: RetainedConfigError::Indeterminate,
            }),
        );
        // Best effort only: relinquishing a handle is not a completion report.
        drop(self.runtime.spawn_blocking(move || drop(state)));
    }
}

impl SqliteBackend {
    /// Begin explicit new-authority provisioning and retain completion ownership.
    ///
    /// Requires the same independently authorized new storage and authority as
    /// `provision_config_authority`; this is never a restart fallback. Beginning
    /// starts work immediately. See `RetainedConfigOpen` for cancellation/join.
    pub fn begin_provision_config_authority(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(options, audit_key, OpenIntent::NewAuthority)
    }

    /// Begin explicit replacement of one existing member's storage, retaining
    /// completion ownership. The authenticated member-repair disposition and
    /// prohibition on local genesis are identical to `provision_config_member_repair`.
    pub fn begin_provision_config_member_repair(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(options, audit_key, OpenIntent::RepairMember)
    }

    /// Begin existing-only reopening and retain completion ownership. Validation,
    /// original WAL recovery and rejection follow `reopen_config_authority`.
    /// No error authorizes creating or replacing retained authority.
    pub fn begin_reopen_config_authority(
        options: RetainedConfigOptions,
        audit_key: AuditKey,
    ) -> Result<RetainedConfigOpen, RetainedConfigError> {
        begin_open_authority(options, audit_key, OpenIntent::Reopen)
    }
}

#[cfg(all(test, unix))]
mod tests;
