//! Full-barrier opening and local authority checks for retained scope cuts.

use super::*;
use crate::scope_authority::{ScopeAuthorityRequest, ScopeAuthorityStamp, ScopeNamespace};
use crate::scope_scan::admission::CaptureCost;
use crate::scope_scan::backend::{CapturedBackend, CapturedScope, ScopeRead, ScopeReadResult};
#[cfg(target_os = "linux")]
use crate::scope_scan::headers::RawScopeRecord;
use crate::scope_scan::headers::{decode_headers_with_handover, validate_applied, CapturedHeaders};
use crate::scope_scan::registry::RegistryError;
use crate::scope_scan::runtime::ViewError;
use crate::scope_scan::{progress::PageLimits, protocol::PageProtocol};
use crate::scope_scan::{ScopeCut, ScopeRestoreView, ScopeScanError};
use crate::sqlite::scope_scan::{read_raw_record, SqliteScopeScan};
use rand::{rngs::SysRng, TryRng};
use std::io;

fn unavailable(_: impl fmt::Debug) -> ScopeScanError {
    ScopeScanError::Unavailable
}

fn view_error(error: ViewError) -> ScopeScanError {
    match error {
        ViewError::Ended(_) => ScopeScanError::RestartRequired,
        _ => ScopeScanError::Unavailable,
    }
}

fn admission_error(error: RegistryError) -> ScopeScanError {
    match error {
        RegistryError::Admission(_) | RegistryError::EpochExhausted => {
            ScopeScanError::CapacityRefused
        }
        RegistryError::Ended(_) => ScopeScanError::RestartRequired,
        RegistryError::Runtime(error) => view_error(error),
        _ => ScopeScanError::Unavailable,
    }
}

impl ConsensusSessionStore {
    /// Count actual scope quorum-barrier entries for local-guard qualification.
    #[cfg(any(test, feature = "test-control"))]
    pub fn scope_read_barrier_count_for_test(&self) -> u64 {
        self.inner
            .scope_read_barriers_for_test
            .load(Ordering::Relaxed)
    }

    pub(crate) fn scope_scan_metrics(&self) -> crate::scope_scan::ScopeScanMetrics {
        self.inner.scope_views.metrics()
    }

    pub(crate) async fn validate_scope_scan_current(
        &self,
        namespace: ScopeNamespace,
        stamp: ScopeAuthorityStamp,
        classification: bool,
    ) -> Result<(), ScopeScanError> {
        let class = if classification {
            ScopeWorkClass::EmergencyClassification
        } else {
            ScopeWorkClass::Normal
        };
        let permit = self
            .inner
            .proposal_admission
            .reserve_for(scheduling::scope_key(namespace.scope()), class)
            .await
            .map_err(unavailable)?
            .start()
            .await
            .map_err(unavailable)?;
        let registry = Arc::clone(&self.inner.scope_views);
        let epoch = registry
            .current_epoch()
            .ok_or(ScopeScanError::RestartRequired)?;
        let (identity, _) = self.current_scope().map_err(unavailable)?;
        if identity.cluster_id() != namespace.scope().store() {
            return Err(ScopeScanError::Unauthorized);
        }
        let current = SessionConsumerScope::new(identity);
        let store = self.clone();
        let handle = tokio::runtime::Handle::current();
        crate::scope_scan::runtime::run_local_guard(permit, move |cancelled| {
            let check = || {
                if cancelled.is_cancelled() || !registry.is_current(epoch) {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "local scope guard ended",
                    ))
                } else {
                    Ok(())
                }
            };
            check().map_err(unavailable)?;
            handle.block_on(store.scope_scan_local_configuration(
                current,
                epoch,
                tokio::time::Instant::now() + Duration::from_secs(1),
            ))?;
            store.scope_scan_current_headers(&namespace, &stamp, cancelled, &check)?;
            check().map_err(unavailable)?;
            handle.block_on(store.scope_scan_local_configuration(
                current,
                epoch,
                tokio::time::Instant::now() + Duration::from_secs(1),
            ))?;
            check().map_err(unavailable)
        })
        .await
    }

    pub(crate) async fn open_scope_restore(
        &self,
        namespace: ScopeNamespace,
        stamp: ScopeAuthorityStamp,
        limits: PageLimits,
        succession: Option<ScopeAuthorityRequest>,
    ) -> Result<ScopeRestoreView, ScopeScanError> {
        let key = scheduling::scope_key(namespace.scope());
        let resident = self
            .inner
            .proposal_admission
            .reserve_for(key, ScopeWorkClass::Normal)
            .await
            .map_err(unavailable)?;
        let permit = resident.start().await.map_err(unavailable)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(ScopeScanError::Unavailable)?;
        let (identity, _) = self.current_scope().map_err(unavailable)?;
        if identity.cluster_id() != namespace.scope().store() {
            return Err(ScopeScanError::Unauthorized);
        }
        let current = SessionConsumerScope::new(identity);
        drop(
            self.admit_scope_read_before(current, deadline)
                .await
                .map_err(unavailable)?,
        );
        let barrier = self
            .scope_read_barrier_before(deadline)
            .await
            .map_err(unavailable)?;
        self.require_scope_read_authority_before(current, deadline)
            .await
            .map_err(unavailable)?;
        // Retention queueing owns only the resident entitlement. It must not
        // retain this execution credit, an immutable root or a transaction.
        let resident = permit.finish_unknown();
        let registry = Arc::clone(&self.inner.scope_views);
        let cost = self.scope_scan_capture_cost()?;
        let registered = registry
            .admit(key, cost, None, resident)
            .await
            .map_err(admission_error)?;
        let epoch = registered.epoch;
        #[cfg(target_os = "linux")]
        let reservation = registered.reservation.clone();
        let store = self.clone();
        let worker_namespace = namespace.clone();
        let handle = tokio::runtime::Handle::current();
        let operation = registered
            .runtime
            .start_normal(move |slot, cancelled| {
                let check = || {
                    if cancelled.is_cancelled() || !registry.is_current(epoch) {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "scope scan opening ended",
                        ))
                    } else {
                        Ok(())
                    }
                };
                let local = || {
                    check().map_err(unavailable)?;
                    handle.block_on(store.scope_scan_local_configuration(
                        current,
                        epoch,
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    ))?;
                    store.scope_scan_current_headers(
                        &worker_namespace,
                        &stamp,
                        cancelled,
                        &check,
                    )?;
                    check().map_err(unavailable)
                };
                local()?;
                let deadline = std::time::Instant::now() + Duration::from_secs(1);
                let (capture, applied, headers) = {
                    #[cfg(target_os = "linux")]
                    if let Some(wal) = store
                        .inner
                        .private_wal
                        .as_ref()
                        .filter(|wal| wal.is_native())
                    {
                        let capture = wal
                            .native_scope_capture(&check, |bytes| {
                                registry
                                    .adjust_native_cost(&reservation, bytes as u64)
                                    .map_err(|_| {
                                        io::Error::other("scope capture reservation is unavailable")
                                    })
                            })
                            .map_err(unavailable)?
                            .ok_or(ScopeScanError::Unavailable)?;
                        let applied = validate_applied(barrier, capture.applied())?;
                        let headers = wal
                            .native_scope_read(&capture, &check, |records, current| {
                                current()?;
                                Ok(decode_headers_with_handover(
                                    &worker_namespace,
                                    &stamp,
                                    succession.as_ref(),
                                    |key, maximum| {
                                        current().map_err(unavailable)?;
                                        Ok(RawScopeRecord::from_native(
                                            records.records().get(key),
                                            maximum,
                                        ))
                                    },
                                ))
                            })
                            .map_err(unavailable)??;
                        (
                            CapturedBackend::Native {
                                owner: Arc::downgrade(wal),
                                capture: Box::new(capture),
                            },
                            applied,
                            headers,
                        )
                    } else {
                        store.scope_scan_sqlite_capture(
                            &worker_namespace,
                            &stamp,
                            succession.as_ref(),
                            barrier,
                            cancelled,
                            &check,
                            deadline,
                        )?
                    }
                    #[cfg(not(target_os = "linux"))]
                    store.scope_scan_sqlite_capture(
                        &worker_namespace,
                        &stamp,
                        succession.as_ref(),
                        barrier,
                        cancelled,
                        &check,
                        deadline,
                    )?
                };
                local()?;
                let mut capture_id = [0; 16];
                SysRng
                    .try_fill_bytes(&mut capture_id)
                    .map_err(unavailable)?;
                let cut = ScopeCut {
                    namespace: worker_namespace.clone(),
                    authority_revision: headers.authority.revision(),
                    batch_revision: headers.checkpoint.revision,
                    applied,
                    epoch,
                    capture_id,
                    serving_node: store.inner.local_node_id,
                };
                let (protocol, initial_cursor) =
                    PageProtocol::new(cut.clone(), &stamp, headers.checkpoint.birth_floor, limits)?;
                *slot = Some(CapturedScope {
                    backend: capture,
                    protocol,
                });
                Ok::<_, ScopeScanError>((cut, headers, initial_cursor))
            })
            .map_err(view_error)?;
        let (cut, headers, initial_cursor) = operation.result().await.map_err(view_error)??;
        Ok(ScopeRestoreView {
            configuration: current,
            cut,
            initial_cursor,
            registered,
            authority: headers.authority,
            checkpoint: headers.checkpoint.into(),
        })
    }

    pub(crate) async fn read_scope_restore(
        &self,
        view: &ScopeRestoreView,
        request: ScopeRead,
        classification: bool,
    ) -> Result<ScopeReadResult, ScopeScanError> {
        if view.cut.serving_node != self.inner.local_node_id {
            return Err(ScopeScanError::Unauthorized);
        }
        let registry = Arc::clone(&self.inner.scope_views);
        if !registry.owns(&view.registered.reservation)
            || !registry.is_current(view.cut.epoch)
            || !view.is_retained()
        {
            return Err(ScopeScanError::RestartRequired);
        }
        let stamp = view
            .authority
            .stamp()
            .ok_or(ScopeScanError::Unauthorized)?
            .clone();
        let namespace = view.cut.namespace.clone();
        let epoch = view.cut.epoch;
        let (identity, _) = self.current_scope().map_err(unavailable)?;
        if identity.cluster_id() != namespace.scope().store() {
            return Err(ScopeScanError::Unauthorized);
        }
        let current = view.configuration;
        let control = view.registered.runtime.control();
        if identity != current.consensus_identity() {
            if let Some(control) = control.upgrade() {
                control.invalidate(
                    crate::scope_scan::activity::ViewInvalidation::ConfigurationChanged,
                );
            }
            return Err(ScopeScanError::RestartRequired);
        }
        let store = self.clone();
        let handle = tokio::runtime::Handle::current();
        let worker =
            move |slot: &mut Option<CapturedScope>,
                  cancelled: &crate::scope_scan::runtime::ViewCancellation| {
                let check = || {
                    if cancelled.is_cancelled() || !registry.is_current(epoch) {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "scope scan view ended",
                        ))
                    } else {
                        Ok(())
                    }
                };
                let configuration = || {
                    if store.current_scope().map_err(unavailable)?.0 != current.consensus_identity()
                    {
                        if let Some(control) = control.upgrade() {
                            control.invalidate(
                                crate::scope_scan::activity::ViewInvalidation::ConfigurationChanged,
                            );
                        }
                        return Err(ScopeScanError::RestartRequired);
                    }
                    Ok(())
                };
                let local = || {
                    check().map_err(|_| ScopeScanError::RestartRequired)?;
                    configuration()?;
                    let deadline = std::time::Instant::now() + Duration::from_secs(1);
                    let authority = handle.block_on(store.scope_scan_local_configuration(
                        current,
                        epoch,
                        tokio::time::Instant::from_std(deadline),
                    ));
                    configuration()?;
                    authority?;
                    let headers =
                        store.scope_scan_current_headers(&namespace, &stamp, cancelled, &check);
                    configuration()?;
                    headers?;
                    check().map_err(unavailable)
                };
                // Writer waiting belongs to the caller's restore deadline.
                // Exhausting item work must not suppress a completed prefix.
                local()?;
                let capture = slot.as_mut().ok_or(ScopeScanError::RestartRequired)?;
                let cancellation = cancelled.clone();
                let captured_registry = Arc::clone(&registry);
                let result = capture.read(request, move || {
                    cancellation.is_cancelled() || !captured_registry.is_current(epoch)
                });
                local()?;
                result
            };
        let operation = if classification {
            let cancellation = view.registered.runtime.cancellation();
            let resident = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(ScopeScanError::RestartRequired),
                resident = self.inner.proposal_admission.reserve_for(
                    scheduling::scope_key(view.cut.namespace.scope()),
                    ScopeWorkClass::EmergencyClassification,
                ) => resident.map_err(unavailable)?,
            };
            view.registered
                .runtime
                .start_classification(resident, worker)
        } else {
            view.registered.runtime.start_normal(worker)
        }
        .map_err(view_error)?;
        operation.result().await.map_err(view_error)?
    }

    fn scope_scan_capture_cost(&self) -> Result<CaptureCost, ScopeScanError> {
        #[cfg(target_os = "linux")]
        if let Some(wal) = self
            .inner
            .private_wal
            .as_ref()
            .filter(|wal| wal.is_native())
        {
            return wal
                .native_scope_cost(&|| Ok(()))
                .map(|bytes| CaptureCost::Native(bytes as u64))
                .map_err(unavailable);
        }
        Ok(CaptureCost::Sqlite)
    }

    pub(crate) async fn scope_scan_local_configuration(
        &self,
        current: SessionConsumerScope,
        epoch: u64,
        deadline: tokio::time::Instant,
    ) -> Result<(), ScopeScanError> {
        if !self.inner.scope_views.is_current(epoch) {
            return Err(ScopeScanError::RestartRequired);
        }
        tokio::time::timeout_at(
            deadline,
            self.require_scope_read_authority_before(current, deadline),
        )
        .await
        .map_err(unavailable)?
        .map_err(unavailable)?;
        if !self.inner.scope_views.is_current(epoch) {
            return Err(ScopeScanError::RestartRequired);
        }
        Ok(())
    }

    fn scope_scan_current_headers(
        &self,
        namespace: &ScopeNamespace,
        stamp: &ScopeAuthorityStamp,
        cancelled: &crate::scope_scan::runtime::ViewCancellation,
        check: &dyn Fn() -> io::Result<()>,
    ) -> Result<CapturedHeaders, ScopeScanError> {
        check().map_err(unavailable)?;
        #[cfg(target_os = "linux")]
        if let Some(wal) = self
            .inner
            .private_wal
            .as_ref()
            .filter(|wal| wal.is_native())
        {
            return wal
                .native_scope_headers(self.inner.storage_identity, namespace, stamp, check)
                .map_err(unavailable)?;
        }
        let source = self
            .inner
            .scope_database
            .as_ref()
            .ok_or(ScopeScanError::Unavailable)?;
        let headers = tokio::runtime::Handle::current()
            .block_on(self.inner.backend.scope_scan_current_headers(
                source,
                self.inner.storage_identity,
                namespace,
                stamp,
                cancelled,
            ))
            .map_err(unavailable)??;
        check().map_err(unavailable)?;
        Ok(headers)
    }

    #[allow(clippy::too_many_arguments)]
    fn scope_scan_sqlite_capture(
        &self,
        namespace: &ScopeNamespace,
        stamp: &ScopeAuthorityStamp,
        succession: Option<&ScopeAuthorityRequest>,
        barrier: Option<LogId<SessionConsensusNodeId>>,
        cancelled: &crate::scope_scan::runtime::ViewCancellation,
        check: &dyn Fn() -> io::Result<()>,
        deadline: std::time::Instant,
    ) -> Result<
        (
            CapturedBackend,
            LogId<SessionConsensusNodeId>,
            CapturedHeaders,
        ),
        ScopeScanError,
    > {
        let source = self
            .inner
            .scope_database
            .as_ref()
            .ok_or(ScopeScanError::Unavailable)?;
        let capture = SqliteScopeScan::capture(source, self.inner.storage_identity, check)
            .map_err(unavailable)?;
        let applied = validate_applied(barrier, capture.applied())?;
        let cancelled = cancelled.clone();
        let headers = capture
            .read(
                move || cancelled.is_cancelled() || std::time::Instant::now() >= deadline,
                |connection, current| {
                    Ok(decode_headers_with_handover(
                        namespace,
                        stamp,
                        succession,
                        |key, maximum| {
                            current().map_err(unavailable)?;
                            read_raw_record(connection, key, maximum).map_err(unavailable)
                        },
                    ))
                },
            )
            .map_err(unavailable)??;
        self.inner.scope_views.observe_wal(capture.wal_bytes().ok());
        Ok((CapturedBackend::Sqlite(Box::new(capture)), applied, headers))
    }
}
