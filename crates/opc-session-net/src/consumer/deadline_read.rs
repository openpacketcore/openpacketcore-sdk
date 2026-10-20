//! Read-only calls with separate pre-write and caller-owned response deadlines.
//!
//! The closed request types below cannot represent a mutation. Both wire
//! revisions retain their existing authenticated call/response machinery.

use super::*;
use opc_session_store::{FencedTransitionV2HistoryState, FencedTransitionV2Request};

pub(super) enum DeadlineV1Read {
    Get(opc_session_store::SessionKey),
    PreflightRecordExpiry(Vec<RecordExpiryPreflight>),
    CompareAndSetStatus(Box<SessionConsumerCompareAndSetRequest>),
    LeaseMutationStatus(Box<SessionConsumerLeaseMutationRequest>),
}

pub(super) enum DeadlineV2Read {
    HistoryState,
    Status(Box<FencedTransitionV2Request>),
}

fn call_boundary(
    client: &StatelessSessionConsumerClient,
    started: tokio::time::Instant,
    budget: PreparedCheckpointBudget,
) -> tokio::time::Instant {
    let deadline = budget.original_deadline();
    let attempt =
        started
            .checked_add(budget.physical_attempt_timeout().min(
                effective_consumer_operation_timeout(client.operation_timeout),
            ))
            .map_or(deadline, |end| end.min(deadline));
    let (configured, _) = client.pre_request_deadline(started, deadline);
    attempt.min(configured)
}

impl PersistentSessionConsumerClient {
    /// Read the exact ordinary lease receipt within the caller's checkpoint budget.
    ///
    /// This retains the request's original identity and complete lease body,
    /// and submits at most one read; it never replays the mutation. The response
    /// may use the remaining original deadline, while pool admission, setup and
    /// Call write keep the physical-attempt cap and any earlier configured
    /// pre-request limit. It shares the extended-read capacity reservation with
    /// [`Self::get_with_budget`] and the other budget-bearing reads.
    ///
    /// Store errors and wire rejections retain [`Self::lease_mutation_status`]'s
    /// mapping, including `Unauthorized` to [`StoreError::BackendUnavailable`].
    /// Transport authority revocation returns [`StoreError::TopologyAuthorityRevoked`]
    /// immediately. Any other possibly transmitted failure spends the remaining
    /// original deadline, preventing an overlapping retry. A newly observed
    /// successful status at or after that deadline is unavailable.
    /// `NotFound` before the deadline leaves the outcome open; it is not proof
    /// that the original acquire never committed or cannot still commit.
    pub async fn lease_mutation_status_with_budget(
        &self,
        request: &SessionConsumerLeaseMutationRequest,
        budget: PreparedCheckpointBudget,
    ) -> Result<SessionConsumerLeaseMutationStatus, StoreError> {
        let result = self
            .execute_v1_read_with_budget(
                DeadlineV1Read::LeaseMutationStatus(Box::new(request.clone())),
                budget,
            )
            .await;
        lease_mutation_status_result(
            result,
            budget.original_deadline(),
            tokio::time::Instant::now(),
        )
    }

    /// Read authoritative state within the caller's immutable checkpoint budget.
    ///
    /// The response may use the remaining original deadline. Pool admission,
    /// setup and Call write retain the physical-attempt cap (and any earlier
    /// configured pre-request limit). This submits at most one physical read.
    /// No mutation can be submitted through this entry point.
    /// Wire rejections use the same mapping as [`Self::get`], including
    /// `Unauthorized` to [`StoreError::BackendUnavailable`]. A transport-level
    /// loss of authority remains [`StoreError::TopologyAuthorityRevoked`].
    ///
    /// ```compile_fail
    /// # use opc_session_net::PersistentSessionConsumerClient;
    /// # use opc_session_store::{FencedTransitionRequest, PreparedCheckpointBudget};
    /// async fn transition(client: &PersistentSessionConsumerClient, request: FencedTransitionRequest, budget: PreparedCheckpointBudget) {
    ///     client.get_with_budget(request, budget).await;
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// # use opc_session_net::PersistentSessionConsumerClient;
    /// # use opc_session_store::{SessionOp, PreparedCheckpointBudget};
    /// async fn batch(client: &PersistentSessionConsumerClient, operations: Vec<SessionOp>, budget: PreparedCheckpointBudget) {
    ///     client.get_with_budget(operations, budget).await;
    /// }
    /// ```
    pub async fn get_with_budget(
        &self,
        key: opc_session_store::SessionKey,
        budget: PreparedCheckpointBudget,
    ) -> Result<Option<opc_session_store::StoredSessionRecord>, StoreError> {
        match self
            .execute_v1_read_with_budget(DeadlineV1Read::Get(key), budget)
            .await
        {
            Ok(SessionConsumerResponse::Get(value)) => {
                value.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(value)) => Err(rejection_into_store_error(value)),
            Err(error) if read_authority_revoked(&error) => {
                Err(StoreError::TopologyAuthorityRevoked)
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer authoritative read unavailable".into(),
            )),
        }
    }

    /// Validate expiry authority within the caller's immutable checkpoint budget.
    ///
    /// This follows [`Self::get_with_budget`]'s split deadline contract and
    /// submits only the payload-free expiry descriptors, never a mutation.
    /// Wire rejections keep [`Self::preflight_record_expiry`]'s classification.
    pub async fn preflight_record_expiry_with_budget(
        &self,
        preflights: Vec<RecordExpiryPreflight>,
        budget: PreparedCheckpointBudget,
    ) -> Result<(), StoreError> {
        match self
            .execute_v1_read_with_budget(DeadlineV1Read::PreflightRecordExpiry(preflights), budget)
            .await
        {
            Ok(SessionConsumerResponse::PreflightRecordExpiry(value)) => {
                value.map_err(SessionConsumerStoreError::into_store_error)
            }
            Ok(SessionConsumerResponse::Rejected(value)) => Err(rejection_into_store_error(value)),
            Err(error) if read_authority_revoked(&error) => {
                Err(StoreError::TopologyAuthorityRevoked)
            }
            Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
                "consumer expiry authority unavailable".into(),
            )),
        }
    }

    /// Read one voter's linearized V2 history using the caller's original budget.
    ///
    /// This narrow authority read has the same pre-write and response deadlines
    /// as [`Self::get_with_budget`]. It neither dispatches a transition nor
    /// creates a new retry budget. Callers retain ownership of quorum policy.
    ///
    /// ```compile_fail
    /// # use opc_session_net::PersistentSessionConsumerClient;
    /// # use opc_session_store::{SessionConsumerV2Request, PreparedCheckpointBudget};
    /// async fn void(client: &PersistentSessionConsumerClient, void_request: SessionConsumerV2Request, budget: PreparedCheckpointBudget) {
    ///     client.fenced_transition_v2_history_state_with_budget(void_request, budget).await;
    /// }
    /// ```
    pub async fn fenced_transition_v2_history_state_with_budget(
        &self,
        budget: PreparedCheckpointBudget,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        let response = self
            .execute_v2_read_with_budget(DeadlineV2Read::HistoryState, budget)
            .await;
        if prepared_fenced_v2::v2_authority_revoked(&response) {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        match response {
            Ok(SessionConsumerV2Response::FencedTransitionV2HistoryState(Ok(state))) => Ok(state),
            _ => Err(StoreError::BackendUnavailable(
                "consumer history authority unavailable".into(),
            )),
        }
    }

    pub(super) async fn execute_v1_read_with_budget(
        &self,
        read: DeadlineV1Read,
        budget: PreparedCheckpointBudget,
    ) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
        let (request_id, operation) = match read {
            DeadlineV1Read::Get(key) => (
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::Get { key },
            ),
            DeadlineV1Read::PreflightRecordExpiry(preflights) => (
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::PreflightRecordExpiry { preflights },
            ),
            DeadlineV1Read::CompareAndSetStatus(request) => (
                request.request_id(),
                SessionConsumerOperation::CompareAndSetStatus { request },
            ),
            DeadlineV1Read::LeaseMutationStatus(request) => (
                request.request_id(),
                SessionConsumerOperation::LeaseMutationStatus { request },
            ),
        };
        let boundary = call_boundary(&self.pool.client, tokio::time::Instant::now(), budget);
        let result = self
            .execute_classified_with_deadlines(
                &self.request(request_id, operation),
                budget.original_deadline(),
                1,
                Some(boundary),
            )
            .await;
        settle_v1_read_result(result, budget.original_deadline()).await
    }

    pub(super) async fn execute_v2_read_with_budget(
        &self,
        read: DeadlineV2Read,
        budget: PreparedCheckpointBudget,
    ) -> Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError> {
        if self.fenced_mutation_roster_transport_enabled() {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            });
        }
        let operation = match read {
            DeadlineV2Read::HistoryState => {
                SessionConsumerV2Operation::FencedTransitionV2HistoryState
            }
            DeadlineV2Read::Status(request) => {
                SessionConsumerV2Operation::FencedTransitionV2Status { request }
            }
        };
        let request = SessionConsumerV2Request::new(self.scope(), operation);
        if request.validate().is_err() {
            return Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause: SessionConsumerClientError::Protocol,
            });
        }
        self.v2_pool.ensure_idle_reaper();
        let started = tokio::time::Instant::now();
        let boundary = call_boundary(&self.v2_pool.client, started, budget);
        let result = self
            .v2_pool
            .execute_classified_once(
                &request,
                PersistentV2CallAttempt {
                    operation_started: started,
                    admission_started: started,
                    admission_deadline: boundary,
                    pre_request_deadline: boundary,
                    pre_request_budget_active: true,
                    deadline: boundary,
                    read_response_deadline: Some(budget.original_deadline()),
                    status_write_accepted: None,
                },
            )
            .await;
        if result.is_ok()
            && !prepared_fenced_v2::v2_authority_revoked(&result)
            && tokio::time::Instant::now() >= budget.original_deadline()
        {
            // The actor can publish before D while this caller is not polled
            // until D or later. Such a completion cannot establish history,
            // a receipt, or cached authority. Revocation remains terminal.
            return Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
                cause: SessionConsumerClientError::Deadline,
            });
        }
        if matches!(
            result,
            Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable { cause })
                if !matches!(cause, SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked)
        ) {
            // After a Call write, a closed transport is not a completed
            // server read. Keep the caller's deadline spent so an outer
            // voter loop cannot overlap that possibly-running operation.
            tokio::time::sleep_until(budget.original_deadline()).await;
        }
        result
    }
}

fn lease_mutation_status_result(
    result: Result<SessionConsumerResponse, SessionConsumerCallError>,
    deadline: tokio::time::Instant,
    observed_at: tokio::time::Instant,
) -> Result<SessionConsumerLeaseMutationStatus, StoreError> {
    match result {
        Ok(SessionConsumerResponse::LeaseMutationStatus(Ok(status))) if observed_at < deadline => {
            Ok(status)
        }
        Ok(SessionConsumerResponse::LeaseMutationStatus(Err(error))) => {
            Err(error.into_store_error())
        }
        Ok(SessionConsumerResponse::Rejected(rejection)) => {
            Err(rejection_into_store_error(rejection))
        }
        Err(error) if read_authority_revoked(&error) => Err(StoreError::TopologyAuthorityRevoked),
        Ok(_) | Err(_) => Err(StoreError::BackendUnavailable(
            "consumer lease receipt status unavailable".into(),
        )),
    }
}

pub(super) async fn settle_v1_read_result(
    result: Result<SessionConsumerResponse, SessionConsumerCallError>,
    deadline: tokio::time::Instant,
) -> Result<SessionConsumerResponse, SessionConsumerCallError> {
    if matches!(
        result,
        Err(SessionConsumerCallError::MayHaveSent(cause))
            if !matches!(cause, SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked)
    ) {
        tokio::time::sleep_until(deadline).await;
    }
    result
}

pub(super) fn read_authority_revoked(error: &SessionConsumerCallError) -> bool {
    matches!(
        error,
        SessionConsumerCallError::BeforeCallWrite(
            SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked
        ) | SessionConsumerCallError::MayHaveSent(
            SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_lease_receipt_budget_result_rejects_success_at_or_after_deadline() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        for status in [
            SessionConsumerLeaseMutationStatus::NotFound,
            SessionConsumerLeaseMutationStatus::RequestConflict,
            SessionConsumerLeaseMutationStatus::Recorded(Box::new(Ok(
                SessionConsumerLeaseMutationResult::Release,
            ))),
        ] {
            let response = SessionConsumerResponse::LeaseMutationStatus(Ok(status.clone()));
            assert_eq!(
                lease_mutation_status_result(
                    Ok(response.clone()),
                    deadline,
                    deadline - std::time::Duration::from_nanos(1),
                ),
                Ok(status),
            );
            for observed_at in [deadline, deadline + std::time::Duration::from_nanos(1)] {
                assert!(matches!(
                    lease_mutation_status_result(Ok(response.clone()), deadline, observed_at),
                    Err(StoreError::BackendUnavailable(_))
                ));
            }
        }
    }
}
