//! Private native backend dispatch. Every selected read enters the same WAL
//! owner as application before any SQL connection or reader-lane admission.

use super::*;
use consensus::wal::Wal;
use std::io;

pub(super) fn unavailable() -> StoreError {
    StoreError::BackendUnavailable("native session state is unavailable".into())
}

impl SqliteSessionBackend {
    pub(super) fn native_enabled(&self) -> bool {
        #[cfg(test)]
        if self
            .private_wal_test
            .as_ref()
            .is_some_and(|backend| backend.is_native())
        {
            return true;
        }
        self.native_owner
            .as_ref()
            .is_some_and(|owner| owner.selected())
    }

    fn native_current(&self) -> Result<Arc<Wal>, StoreError> {
        #[cfg(test)]
        if let Some(test) = self
            .private_wal_test
            .as_ref()
            .filter(|test| test.is_native())
        {
            return test.current().map_err(|_| unavailable());
        }
        self.native_owner
            .as_ref()
            .filter(|owner| owner.selected())
            .ok_or_else(unavailable)?
            .current()
            .map_err(|_| unavailable())
    }

    /// Acquire the existing store-wide worker permit before spawning. A
    /// dropped caller cancels its queued closure; an active worker retains
    /// its permit and immutable capture until its checked work finishes.
    pub(super) async fn native_read_task<T, F>(&self, read: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(
                &crate::consensus::native::NativeState,
                &dyn Fn() -> io::Result<()>,
            ) -> Result<T, StoreError>
            + Send
            + 'static,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(SQLITE_OPERATION_MAX_WORK)
            .ok_or_else(unavailable)?;
        self.native_read_task_at(deadline, Arc::clone(&self.operation_workers), read)
            .await
    }

    pub(super) async fn native_read_task_at<T, F>(
        &self,
        deadline: tokio::time::Instant,
        workers: Arc<tokio::sync::Semaphore>,
        read: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(
                &crate::consensus::native::NativeState,
                &dyn Fn() -> io::Result<()>,
            ) -> Result<T, StoreError>
            + Send
            + 'static,
    {
        let permit = tokio::time::timeout_at(deadline, workers.acquire_owned())
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let wal = self.native_current()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let task_cancellation = Arc::clone(&cancellation);
        let operation_deadline = deadline.into_std();
        let queued = Arc::new(StdMutex::new(Some((permit, wal, read))));
        let task_queued = Arc::clone(&queued);
        let task = tokio::task::spawn_blocking(move || {
            let (_permit, wal, read) = task_queued
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let check = || {
                if task_cancellation.load(Ordering::Acquire)
                    || std::time::Instant::now() >= operation_deadline
                {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native read work budget exhausted",
                    ))
                } else {
                    Ok(())
                }
            };
            Some(
                wal.native_public_read(&check, read)
                    .map_err(|_| unavailable())
                    .and_then(|result| result),
            )
        });
        let mut cancel_on_drop = RestoreScanCancellation {
            cancellation,
            abort: task.abort_handle(),
            armed: true,
            cancel_queued: Some(Box::new(move || {
                drop(
                    queued
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take(),
                );
            })),
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => Err(unavailable()),
            Ok(completed) => {
                cancel_on_drop.disarm();
                completed
                    .map_err(|_| unavailable())?
                    .ok_or_else(unavailable)?
            }
        }
    }

    pub(super) fn native_read<T>(
        &self,
        read: impl FnOnce(&Wal) -> io::Result<T>,
    ) -> Option<io::Result<T>> {
        self.native_enabled().then(|| {
            self.native_current()
                .map_err(|_| io::Error::other("native owner unavailable"))
                .and_then(|wal| read(&wal))
        })
    }

    pub(super) fn native_v2_mutation_snapshot(
        &self,
        acceptance: &FixedQuorumActivatedV2MutationSnapshotRequest,
    ) -> Option<Result<FixedQuorumActivatedV2MutationSnapshot, StoreError>> {
        self.native_read(|wal| {
            #[cfg(test)]
            if self
                .consensus_operator_recovery_failure
                .load(Ordering::Acquire)
                || self
                    .fixed_quorum_v2_mutation_snapshot_cut
                    .load(Ordering::Acquire)
            {
                return Err(io::Error::other("native injected authority failure"));
            }
            wal.native_fixed_read(
                acceptance.storage_identity,
                &acceptance.expected_members,
                &acceptance.expected_bindings,
                acceptance.expected_placement_policy,
                false,
                self.database_path.as_deref().map(PathBuf::as_path),
                |state, exact| {
                    if !exact
                        || acceptance.storage_identity != acceptance.scope_identity
                        || acceptance.voters != acceptance.expected_members
                    {
                        return Err(io::Error::other("native fixed authority differs"));
                    }
                    Ok(
                        if state.v2_activation_matches(
                            acceptance.scope_identity,
                            &acceptance.voters,
                            acceptance.profile_digest,
                        ) {
                            FixedQuorumActivatedV2MutationSnapshot::Activated {
                                applied_logical_time: state.logical_time(),
                            }
                        } else {
                            FixedQuorumActivatedV2MutationSnapshot::Unactivated
                        },
                    )
                },
            )
        })
        .map(|result| result.map_err(|_| unavailable()))
    }

    pub(super) fn native_v2_status_batch(
        &self,
        acceptance: &FixedQuorumFencedTransitionV2StatusReadRequest,
        requests: &[crate::FencedTransitionV2Request],
    ) -> Option<Result<FixedQuorumFencedTransitionV2StatusBatchRead, StoreError>> {
        self.native_read(|wal| {
            if requests.is_empty() {
                return Err(io::Error::other("native status cohort unavailable"));
            }
            #[cfg(test)]
            if self
                .consensus_operator_recovery_failure
                .load(Ordering::Acquire)
            {
                return Err(io::Error::other("native status cohort unavailable"));
            }
            wal.native_fixed_receipt_read(
                acceptance.storage_identity,
                &acceptance.expected_members,
                &acceptance.expected_bindings,
                acceptance.expected_placement_policy,
                false,
                self.database_path.as_deref().map(PathBuf::as_path),
                requests,
                |state, exact, receipts| {
                    if !exact
                        || acceptance.storage_identity != acceptance.scope_identity
                        || acceptance.voters != acceptance.expected_members
                    {
                        return Err(io::Error::other("native fixed status authority differs"));
                    }
                    if acceptance.require_activation
                        && !state.v2_activation_matches(
                            acceptance.scope_identity,
                            &acceptance.voters,
                            acceptance.profile_digest,
                        )
                    {
                        return Ok(Ok(
                            FixedQuorumFencedTransitionV2StatusBatchRead::Unactivated,
                        ));
                    }
                    Ok(requests
                        .iter()
                        .map(|request| match receipts {
                            Some(receipts) => state.status_with_receipts(request, receipts),
                            None => state.status(request),
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(FixedQuorumFencedTransitionV2StatusBatchRead::Activated))
                },
            )
        })
        .map(|result| result.map_err(|_| unavailable())?)
    }
}
