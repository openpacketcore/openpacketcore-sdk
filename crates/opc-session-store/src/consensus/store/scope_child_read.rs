//! One full barrier and one bounded backend cut for authority and all requested children.

use super::*;
use crate::scope_authority::{ScopeAuthorityError, ScopeAuthorityStamp};
use crate::scope_batch::*;
use crate::scope_scan::backend::CapturedBackend;
use crate::scope_scan::headers::{
    decode_headers, validate_applied, CapturedHeaders, RawScopeRecord,
};
use crate::scope_scan::ScopeScanError;
use crate::scope_storage::{self, ScopeRow};
use crate::sqlite::scope_scan::{read_raw_record, SqliteScopeScan};
use std::io;

fn unavailable(_: impl fmt::Debug) -> ScopeChildReadError {
    ScopeBatchError::Unavailable.into()
}

fn header_error(error: ScopeScanError) -> ScopeChildReadError {
    match error {
        ScopeScanError::Unauthorized => ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized),
        ScopeScanError::StaleAuthority => {
            ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority)
        }
        ScopeScanError::Retired => ScopeBatchError::Scope(ScopeAuthorityError::Retired),
        ScopeScanError::FreshInstallationRequired | ScopeScanError::ScopeFault(_) => {
            ScopeBatchError::FormatMismatch
        }
        _ => ScopeBatchError::Unavailable,
    }
    .into()
}

#[derive(Clone)]
struct ReadCheck {
    control: ScopeChildReadControl,
    deadline: tokio::time::Instant,
}

impl ReadCheck {
    fn interrupted(&self) -> bool {
        self.control.is_cancelled() || tokio::time::Instant::now() >= self.deadline
    }

    fn check(&self) -> io::Result<()> {
        if self.interrupted() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "scope child read ended",
            ))
        } else {
            Ok(())
        }
    }
}

/// The async caller owns the cut while waiting for its independently verified
/// dispatch class. No backend mutex or process gate is retained across that wait.
pub(crate) struct ChildReadCut {
    backend: CapturedBackend,
    headers: CapturedHeaders,
    store: ConsensusSessionStore,
    configuration: SessionConsumerScope,
    request: ScopeChildReadRequest,
    check: ReadCheck,
    // Fixed-topology reads retain their existing topology admission semantics.
    _admission: Option<ConsumerScopeAdmission>,
    #[cfg(any(test, feature = "test-control"))]
    _capture_count: CaptureCount,
}

#[cfg(any(test, feature = "test-control"))]
struct CaptureCount(ConsensusSessionStore);

#[cfg(any(test, feature = "test-control"))]
impl CaptureCount {
    fn new(store: &ConsensusSessionStore) -> Self {
        store
            .inner
            .scope_child_read_cuts_for_test
            .fetch_add(1, Ordering::AcqRel);
        Self(store.clone())
    }
}

#[cfg(any(test, feature = "test-control"))]
impl Drop for CaptureCount {
    fn drop(&mut self) {
        self.0
            .inner
            .scope_child_read_cuts_for_test
            .fetch_sub(1, Ordering::AcqRel);
    }
}

impl ChildReadCut {
    pub(crate) fn stamp(&self) -> &ScopeAuthorityStamp {
        self.headers
            .authority
            .stamp()
            .expect("captured active authority")
    }

    pub(crate) fn deadline(&self) -> tokio::time::Instant {
        self.check.deadline
    }

    pub(crate) async fn materialize<G: Send + 'static>(
        self,
        admission: G,
    ) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        let store = self.store.clone();
        let configuration = self.configuration;
        let deadline = self.deadline();
        let control = self.check.control.clone();
        before(&control, deadline, async {
            store
                .require_scope_read_authority_before(configuration, deadline)
                .await
                .map_err(unavailable)
        })
        .await?;
        let worker = tokio::task::spawn_blocking(move || {
            // Keep execution credit until all materialization has drained,
            // including after the async observer is cancelled.
            let result = self.read_children();
            drop(self);
            drop(admission);
            result
        });
        let rows = drain_worker(worker, &control, deadline).await?;
        before(&control, deadline, async {
            store
                .require_scope_read_authority_before(configuration, deadline)
                .await
                .map_err(unavailable)
        })
        .await?;
        Ok(rows)
    }

    fn read_children(&self) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        self.read(|read, check| {
            let namespace = self.request.stamp().namespace();
            let mut bytes = 1
                + 2
                + postcard::to_allocvec(namespace).map_err(unavailable)?.len()
                + 1
                + self.request.keys().len() * 33;
            let mut rows = Vec::with_capacity(self.request.keys().len());
            for (index, key) in self.request.keys().iter().copied().enumerate() {
                check().map_err(unavailable)?;
                #[cfg(any(test, feature = "test-control"))]
                if index == 1 {
                    self.store
                        .child_read_pause(ScopeChildReadStage::BetweenKeys, check)
                        .map_err(unavailable)?;
                }
                #[cfg(not(any(test, feature = "test-control")))]
                let _ = index;
                let physical = scope_storage::child_key(namespace, key)?;
                let row = match read(&physical, scope_storage::MAX_SCOPE_ROW_BYTES)? {
                    RawScopeRecord::Missing => None,
                    RawScopeRecord::Corrupt => return Err(ScopeBatchError::FormatMismatch.into()),
                    RawScopeRecord::Present(record) => {
                        match ScopeRow::from_record(&record)
                            .map_err(|_| ScopeBatchError::FormatMismatch)?
                        {
                            ScopeRow::Child(row)
                                if row.namespace() == namespace && row.key() == key =>
                            {
                                if row.batch_revision() > self.headers.checkpoint.revision
                                    || row.revision().birth() > self.headers.checkpoint.birth_floor
                                {
                                    return Err(ScopeBatchError::FormatMismatch.into());
                                }
                                if row.value().is_some() {
                                    Some(row)
                                } else {
                                    None
                                }
                            }
                            _ => return Err(ScopeBatchError::FormatMismatch.into()),
                        }
                    }
                };
                if let Some(row) = &row {
                    let length = row
                        .encode_canonical()
                        .map_err(|_| ScopeBatchError::FormatMismatch)?
                        .len();
                    bytes += 4 + length;
                    if bytes > MAX_SCOPE_CHILD_OBSERVATION_BYTES {
                        return Err(ScopeChildReadError::ObservationTooLarge);
                    }
                }
                rows.push(row);
            }
            check().map_err(unavailable)?;
            Ok(rows)
        })
    }

    fn read<T>(
        &self,
        work: impl FnOnce(
            &mut dyn FnMut(&SessionKey, usize) -> Result<RawScopeRecord, ScopeChildReadError>,
            &dyn Fn() -> io::Result<()>,
        ) -> Result<T, ScopeChildReadError>,
    ) -> Result<T, ScopeChildReadError> {
        read_backend(&self.backend, &self.check, work)
    }
}

fn read_backend<T>(
    backend: &CapturedBackend,
    check: &ReadCheck,
    work: impl FnOnce(
        &mut dyn FnMut(&SessionKey, usize) -> Result<RawScopeRecord, ScopeChildReadError>,
        &dyn Fn() -> io::Result<()>,
    ) -> Result<T, ScopeChildReadError>,
) -> Result<T, ScopeChildReadError> {
    match backend {
        #[cfg(target_os = "linux")]
        CapturedBackend::Native { owner, capture } => {
            let owner = owner.upgrade().ok_or(ScopeBatchError::Unavailable)?;
            owner
                .native_scope_read(capture, &|| check.check(), |records, current| {
                    Ok(work(
                        &mut |key, maximum| {
                            current().map_err(unavailable)?;
                            Ok(RawScopeRecord::from_native(
                                records.records().get(key),
                                maximum,
                            ))
                        },
                        current,
                    ))
                })
                .map_err(unavailable)?
        }
        CapturedBackend::Sqlite(capture) => {
            let cancellation = check.clone();
            capture
                .read(
                    move || cancellation.interrupted(),
                    |connection, current| {
                        Ok(work(
                            &mut |key, maximum| {
                                current().map_err(unavailable)?;
                                read_raw_record(connection, key, maximum).map_err(unavailable)
                            },
                            current,
                        ))
                    },
                )
                .map_err(unavailable)?
        }
    }
}

pub(crate) async fn before<T>(
    control: &ScopeChildReadControl,
    deadline: tokio::time::Instant,
    work: impl std::future::Future<Output = Result<T, ScopeChildReadError>>,
) -> Result<T, ScopeChildReadError> {
    tokio::select! {
        biased;
        () = control.cancelled() => Err(ScopeBatchError::Unavailable.into()),
        () = tokio::time::sleep_until(deadline) => Err(ScopeBatchError::Unavailable.into()),
        result = work => result,
    }
}

async fn drain_worker<T>(
    mut worker: tokio::task::JoinHandle<Result<T, ScopeChildReadError>>,
    control: &ScopeChildReadControl,
    deadline: tokio::time::Instant,
) -> Result<T, ScopeChildReadError> {
    tokio::select! {
        biased;
        () = control.cancelled() => {},
        () = tokio::time::sleep_until(deadline) => control.cancel(),
        result = &mut worker => return result.map_err(unavailable)?,
    }
    // Returning a timeout must follow destruction of the cut, not merely a
    // detached blocking task. Every backend wait observes this cancellation.
    drop(worker.await);
    Err(ScopeBatchError::Unavailable.into())
}

impl ConsensusSessionStore {
    pub(crate) async fn scope_child_read_cut(
        &self,
        request: ScopeChildReadRequest,
        control: ScopeChildReadControl,
    ) -> Result<ChildReadCut, ScopeChildReadError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        let (configuration, barrier, admission) = before(&control, deadline, async {
            let (identity, _) = self.current_scope().map_err(unavailable)?;
            if identity.cluster_id() != request.stamp().scope().store() {
                return Err(ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized).into());
            }
            let configuration = SessionConsumerScope::new(identity);
            drop(
                self.admit_scope_read_before(configuration, deadline)
                    .await
                    .map_err(unavailable)?,
            );
            let barrier = self
                .scope_read_barrier_before(deadline)
                .await
                .map_err(unavailable)?;
            let admission = self
                .admit_scope_read_before(configuration, deadline)
                .await
                .map_err(unavailable)?;
            if !self
                .activated_scope_profile_is_current(deadline)
                .await
                .map_err(unavailable)?
            {
                return Err(
                    ScopeBatchError::Scope(ScopeAuthorityError::ProfileNotActivated).into(),
                );
            }
            Ok((configuration, barrier, admission))
        })
        .await?;
        let store = self.clone();
        let worker_control = control.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let opening = ReadCheck {
                control: worker_control.clone(),
                deadline,
            };
            opening.check().map_err(unavailable)?;
            #[cfg(any(test, feature = "test-control"))]
            store
                .child_read_pause(ScopeChildReadStage::BeforeCapture, &|| opening.check())
                .map_err(unavailable)?;
            // Start no later than the physical capture, so admission and every
            // subsequent materialization step fit within the fixed maximum.
            let check = ReadCheck {
                control: worker_control,
                deadline: tokio::time::Instant::now() + SCOPE_CHILD_READ_MAX_CUT_LIFETIME,
            };
            let backend = store.capture_child_backend(barrier, &check)?;
            #[cfg(any(test, feature = "test-control"))]
            store
                .child_read_pause(ScopeChildReadStage::AfterCapture, &|| check.check())
                .map_err(unavailable)?;
            let headers = read_backend(&backend, &check, |read, _| {
                decode_headers(
                    request.stamp().namespace(),
                    request.stamp(),
                    |key, maximum| read(key, maximum).map_err(|_| ScopeScanError::Unavailable),
                )
                .map_err(header_error)
            })?;
            check.check().map_err(unavailable)?;
            Ok(ChildReadCut {
                #[cfg(any(test, feature = "test-control"))]
                _capture_count: CaptureCount::new(&store),
                backend,
                headers,
                store,
                configuration,
                request,
                check,
                _admission: admission,
            })
        });
        drain_worker(worker, &control, deadline).await
    }

    fn capture_child_backend(
        &self,
        barrier: Option<LogId<SessionConsensusNodeId>>,
        check: &ReadCheck,
    ) -> Result<CapturedBackend, ScopeChildReadError> {
        #[cfg(target_os = "linux")]
        if let Some(wal) = self
            .inner
            .private_wal
            .as_ref()
            .filter(|wal| wal.is_native())
        {
            // The point-read caller owns bounded proof/read credit and a fixed
            // lifetime. It does not allocate a retained scan or replay lane.
            let capture = wal
                .native_scope_capture(&|| check.check(), |_| Ok(true))
                .map_err(unavailable)?
                .ok_or(ScopeBatchError::Unavailable)?;
            validate_applied(barrier, capture.applied()).map_err(header_error)?;
            return Ok(CapturedBackend::Native {
                owner: Arc::downgrade(wal),
                capture: Box::new(capture),
            });
        }
        let source = self
            .inner
            .scope_database
            .as_ref()
            .ok_or(ScopeBatchError::Unavailable)?;
        let capture =
            SqliteScopeScan::capture(source, self.inner.storage_identity, &|| check.check())
                .map_err(unavailable)?;
        validate_applied(barrier, capture.applied()).map_err(header_error)?;
        Ok(CapturedBackend::Sqlite(Box::new(capture)))
    }

    /// Pause one child read at a real capture/materialization boundary.
    #[cfg(any(test, feature = "test-control"))]
    pub fn pause_next_scope_child_read_for_test(
        &self,
        stage: ScopeChildReadStage,
    ) -> ScopeChildReadPause {
        let state = Arc::new(crate::scope_batch::child_read_control::PauseState::default());
        *self.inner.scope_child_read_pause.lock().unwrap() = Some((stage, state.clone()));
        ScopeChildReadPause(state)
    }

    /// Number of opened child cuts still owning their backend and admission resources.
    #[cfg(any(test, feature = "test-control"))]
    pub fn scope_child_read_cuts_for_test(&self) -> u64 {
        self.inner
            .scope_child_read_cuts_for_test
            .load(Ordering::Acquire)
    }

    #[cfg(any(test, feature = "test-control"))]
    fn child_read_pause(
        &self,
        stage: ScopeChildReadStage,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let pause = {
            let mut pause = self.inner.scope_child_read_pause.lock().unwrap();
            if pause.as_ref().is_some_and(|(target, _)| *target == stage) {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, pause)) = pause {
            pause.pause(check)?;
        }
        Ok(())
    }
}
