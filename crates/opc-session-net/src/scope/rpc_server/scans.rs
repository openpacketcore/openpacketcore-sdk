//! Per-listener ownership of bounded retained observations, with fresh admission per call.
use super::*;
use opc_session_store::scope_scan::*;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

#[derive(Default)]
struct State {
    closed: bool,
    views: HashMap<[u8; 16], Arc<ScopeRestoreView>>,
}
#[derive(Default)]
pub(super) struct ScanViews(Mutex<State>);
impl ScanViews {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(super) fn begin_close(&self) {
        self.state().closed = true;
    }
    pub(super) async fn shutdown(&self) {
        let views = {
            let mut state = self.state();
            state.closed = true;
            std::mem::take(&mut state.views)
        };
        for (_, view) in views {
            view.close().await;
        }
    }
    pub(super) fn reap(&self) {
        let snapshot: Vec<_> = self
            .state()
            .views
            .iter()
            .map(|(id, view)| (*id, view.clone()))
            .collect();
        for (id, view) in snapshot {
            if !view.is_retained() {
                let removed = {
                    let mut state = self.state();
                    if state
                        .views
                        .get(&id)
                        .is_some_and(|current| Arc::ptr_eq(current, &view))
                    {
                        state.views.remove(&id)
                    } else {
                        None
                    }
                };
                drop(removed);
            }
        }
    }
    fn insert(&self, view: Arc<ScopeRestoreView>) -> Result<(), ScopeScanError> {
        self.reap();
        let token = ScopeScanViewToken::new(
            view.authority()
                .stamp()
                .ok_or(ScopeScanError::Unauthorized)?,
            view.cut(),
        )?;
        let mut state = self.state();
        if state.closed {
            return Err(ScopeScanError::RestartRequired);
        }
        if state.views.contains_key(token.capture_id()) {
            return Err(ScopeScanError::Unavailable);
        }
        state.views.insert(*token.capture_id(), view);
        Ok(())
    }
    fn get(
        &self,
        token: &ScopeScanViewToken,
    ) -> Result<Arc<ScopeRestoreView>, ScopeScanRequestFailure> {
        let view = {
            let state = self.state();
            if state.closed {
                return Err(ended());
            }
            state
                .views
                .get(token.capture_id())
                .cloned()
                .ok_or_else(ended)?
        };
        if view.authority().stamp() != Some(token.stamp())
            || view.cut().namespace() != token.stamp().namespace()
            || view.cut().serving_node() != token.serving_node()
        {
            return Err(ScopeScanRequestFailure::Final(ScopeScanError::Unauthorized));
        }
        if let Some(cause) = view.retry_cause() {
            return Err(ScopeScanRequestFailure::Retryable(cause));
        }
        Ok(view)
    }
    fn remove(&self, token: &ScopeScanViewToken, view: &Arc<ScopeRestoreView>) {
        let removed = {
            let mut state = self.state();
            if state
                .views
                .get(token.capture_id())
                .is_some_and(|current| Arc::ptr_eq(current, view))
            {
                state.views.remove(token.capture_id())
            } else {
                None
            }
        };
        drop(removed);
    }
}

fn ended() -> ScopeScanRequestFailure {
    ScopeScanRequestFailure::Retryable(ScopeScanRetryCause::ViewEnded)
}
fn failure(error: ScopeScanError, view: Option<&ScopeRestoreView>) -> ScopeScanRequestFailure {
    match error {
        ScopeScanError::Unavailable => {
            ScopeScanRequestFailure::Retryable(ScopeScanRetryCause::Unavailable)
        }
        ScopeScanError::RestartRequired => ScopeScanRequestFailure::Retryable(
            view.and_then(ScopeRestoreView::retry_cause)
                .unwrap_or(ScopeScanRetryCause::ViewEnded),
        ),
        error => ScopeScanRequestFailure::Final(error),
    }
}

impl ScopeServer {
    pub(super) async fn scan_current(
        &self,
        context: &Context,
        stamp: &ScopeAuthorityStamp,
        classification: bool,
    ) -> Result<(), ScopeScanError> {
        let service = ScopeScanStore::new(
            self.config.store.clone(),
            stamp.namespace().clone(),
            Arc::new(Routing(context.clone())),
        )?;
        let identity = context
            .identity()
            .map_err(|_| ScopeScanError::Unauthorized)?;
        if classification {
            service
                .validate_classification_current(&identity, stamp)
                .await
        } else {
            service.validate_current(&identity, stamp).await
        }
    }

    pub(super) async fn dispatch_scan(
        &self,
        request: &ScopeScanRequest,
        admission: Arc<VerifiedScopeCall>,
        views: &ScanViews,
    ) -> Result<(ResultStatus, [u8; 32], Vec<u8>, Option<ScopeAuthorityStamp>), ScopeRpcError> {
        let result = async {
            if let Some(error) = admission.scan_failure {
                return Err(failure(error, None));
            }
            let identity = admission
                .context
                .identity()
                .map_err(|_| ScopeScanRequestFailure::Final(ScopeScanError::Unauthorized))?;
            let service = ScopeScanStore::new(
                self.config.store.clone(),
                request.stamp().namespace().clone(),
                admission,
            )
            .map_err(|error| failure(error, None))?;
            match request {
                ScopeScanRequest::Open(request) => {
                    let bounded = request
                        .limits()
                        .for_transport(MAX_SCOPE_SCAN_REPLY_BYTES)
                        .map_err(|error| failure(error, None))?;
                    if bounded.payload_bytes() != request.limits().payload_bytes() {
                        return Err(ScopeScanRequestFailure::Final(
                            ScopeScanError::InvalidPageLimits,
                        ));
                    }
                    let view = Arc::new(
                        service
                            .open_restore_request(&identity, request)
                            .await
                            .map_err(|error| failure(error, None))?,
                    );
                    if let Err(error) = views.insert(view.clone()) {
                        view.close().await;
                        return Err(failure(error, None));
                    }
                    Ok(ScopeScanResponse::Open(ScopeScanOpenReply::from(
                        view.as_ref(),
                    )))
                }
                ScopeScanRequest::Page {
                    view: token,
                    cursor,
                } => {
                    let view = views.get(token)?;
                    service
                        .page(&identity, &view, cursor)
                        .await
                        .map(ScopeScanResponse::Page)
                        .map_err(|error| failure(error, Some(&view)))
                }
                ScopeScanRequest::Lookup { view: token, key }
                | ScopeScanRequest::Classify { view: token, key } => {
                    let view = views.get(token)?;
                    let result = if matches!(request, ScopeScanRequest::Classify { .. }) {
                        service.classify(&identity, &view, *key).await
                    } else {
                        service.lookup(&identity, &view, *key).await
                    };
                    result
                        .map(ScopeScanResponse::Lookup)
                        .map_err(|error| failure(error, Some(&view)))
                }
                ScopeScanRequest::Close(token) => {
                    service
                        .validate_current(&identity, token.stamp())
                        .await
                        .map_err(|error| failure(error, None))?;
                    let view = match views.get(token) {
                        Ok(view) => view,
                        Err(ScopeScanRequestFailure::Retryable(_)) => {
                            return Ok(ScopeScanResponse::Closed)
                        }
                        Err(error) => return Err(error),
                    };
                    views.remove(token, &view);
                    view.close().await;
                    Ok(ScopeScanResponse::Closed)
                }
            }
        }
        .await;
        let response = result.unwrap_or_else(ScopeScanResponse::Failure);
        Ok((
            ResultStatus::ScanObservation,
            [0; 32],
            response
                .encode_canonical()
                .map_err(|_| ScopeRpcError::Invalid)?,
            None,
        ))
    }
}
