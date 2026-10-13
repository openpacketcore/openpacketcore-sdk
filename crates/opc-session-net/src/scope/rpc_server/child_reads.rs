//! One bounded cut owns method-17 authorization, dispatch admission and materialization.

use super::*;
use opc_session_store::scope_batch::{ScopeChildReadControl, ScopeChildReadError};

impl ScopeServer {
    pub(super) async fn dispatch_child_read(
        &self,
        connection: &mut ScopeTlsConnection<TcpStream>,
        request: &ScopeChildReadRequest,
        admission: Arc<VerifiedScopeCall>,
        reply_deadline: &mut Option<Instant>,
    ) -> Result<(ResultStatus, [u8; 32], Vec<u8>, Option<ScopeAuthorityStamp>), ScopeRpcError> {
        admission.check().map_err(authority_error)?;
        let identity = admission.context.identity()?;
        let store = ScopeBatchStore::new(
            self.config.store.clone(),
            request.stamp().namespace().clone(),
            admission.clone(),
        )
        .map_err(|_| ScopeRpcError::Invalid)?;
        let control = ScopeChildReadControl::default();
        let result = {
            let reading = store.read_current_with_admission(
                &identity,
                request.stamp(),
                request.keys(),
                control.clone(),
                |current, deadline| {
                    *reply_deadline = Some(deadline);
                    async move {
                        admission.check().map_err(ScopeBatchError::from)?;
                        let public_key = admission
                            .public_key
                            .ok_or(ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized))?;
                        // Independent of the carried execution check: bind the
                        // actual current execution at this cut to the proven key.
                        if current.execution().identity().as_str()
                            != admission.context.route.principal.as_str()
                            || current.execution().boot_key() != &hash(&public_key)
                        {
                            return Err(
                                ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized).into()
                            );
                        }
                        let permit = self
                            .config
                            .scheduler
                            .reserve(
                                opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                                    &admission.context.scope,
                                ),
                                work_class(admission.context.route.class),
                            )
                            .await
                            .map_err(|_| ScopeBatchError::Unavailable)?
                            .start()
                            .await
                            .map_err(|_| ScopeBatchError::Unavailable)?;
                        admission.check().map_err(ScopeBatchError::from)?;
                        Ok(permit)
                    }
                },
            );
            tokio::pin!(reading);
            tokio::select! {
                biased;
                _ = connection.read_u8() => {
                    // Cancellation must drain the blocking owner before the
                    // caller releases the retained proof and response budget.
                    control.cancel();
                    let _ = reading.await;
                    return Err(ScopeRpcError::Retry);
                }
                result = &mut reading => result,
            }
        };
        let body = match result {
            Ok(rows) => super::super::child_read_wire::encode_observation(request, &rows)
                .map_err(|_| ScopeRpcError::Retry)?,
            Err(ScopeChildReadError::ObservationTooLarge) => vec![1],
            Err(ScopeChildReadError::Batch(ScopeBatchError::Unavailable)) => {
                // The store has already destroyed its cut and drained its worker.
                *reply_deadline = None;
                return Err(ScopeRpcError::Retry);
            }
            Err(ScopeChildReadError::Batch(ScopeBatchError::Scope(
                ScopeAuthorityError::Unauthorized,
            ))) => return Err(ScopeRpcError::Unauthorized),
            Err(ScopeChildReadError::Batch(error)) => {
                *reply_deadline = None;
                return Ok((
                    ResultStatus::BatchError,
                    [0; 32],
                    error
                        .encode_canonical()
                        .map_err(|_| ScopeRpcError::Invalid)?,
                    None,
                ));
            }
            Err(_) => return Err(ScopeRpcError::Retry),
        };
        Ok((
            ResultStatus::ChildObservation,
            [0; 32],
            body,
            Some(request.stamp().clone()),
        ))
    }
}
