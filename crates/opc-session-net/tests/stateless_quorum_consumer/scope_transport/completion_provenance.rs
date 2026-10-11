//! A public port can reproduce every observation, but cannot mint native provenance.
use super::*;
use opc_session_store::scope_scheduler::ScopeScheduler;

struct Admission(ScopeAuthorityStamp);
#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeId,
        execution: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if authenticated == self.0.execution().identity()
            && scope == self.0.scope()
            && execution.is_none_or(|execution| execution == self.0.execution())
        {
            Ok(ScopeAuthorityRole::Worker)
        } else {
            Err(ScopeAuthorityError::Unauthorized)
        }
    }
    async fn verify_closure(
        &self,
        _: &SessionConsumerIdentity,
        _: &ScopeAuthorityStamp,
        _: &ScopeClosureEvidence,
        _: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        Err(ScopeAuthorityError::Unauthorized)
    }
}

struct ForgedPort {
    cut: ScopeBatchReopen,
    outcome: ScopeBatchOutcome,
    context: ScopeBatchCompletionContext,
}
#[async_trait]
impl ScopeBatchPort for ForgedPort {
    async fn reopen(&self, _: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        Ok(self.cut.clone())
    }
    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        _: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        let mut forged = serde_json::to_value(&self.outcome).unwrap();
        forged["request_digest"] = serde_json::to_value(request.digest()?).unwrap();
        forged["lane"] = request.lane().into();
        forged["sequence"] = request.sequence().into();
        let forged: ScopeBatchOutcome = serde_json::from_value(forged).unwrap();
        assert!(forged.matches_request(request));
        Ok(forged)
    }
    async fn cancel(
        &self,
        _: &ScopeBatchAttempt,
        _: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        panic!("a forged applied observation resolves without cancellation")
    }
    fn completion_context(
        &self,
        _: &ScopeBatchRequest,
        _: ScopeWorkClass,
        _: &ScopeBatchCompletionOutcome,
        _: ScopeBatchCompletionRetention,
    ) -> Option<ScopeBatchCompletionContext> {
        Some(self.context.clone())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn check(
    client: &ScopeClient,
    other_client: &ScopeClient,
    authority: &CommittedScopeAuthority,
    batches: &ScopeBatchCoordinator,
    request: &ScopeBatchRequest,
    completion: &ScopeBatchCompletion,
    store: Arc<opc_session_store::ConsensusSessionStore>,
    scheduler: ScopeScheduler,
) {
    let verified = client
        .verify_batch_completion(authority, request, completion)
        .unwrap();
    assert_eq!(verified.class(), ScopeWorkClass::Normal);
    let ScopeBatchCompletionOutcome::Applied(outcome) = completion.outcome() else {
        panic!("applied")
    };
    assert_eq!(verified.outcome(), outcome.as_ref());
    assert!(
        !batches.ack(completion.attempt()),
        "readback owns a retention pin"
    );
    assert_eq!(
        other_client
            .verify_batch_completion(authority, request, completion)
            .err(),
        Some(ScopeBatchError::OutcomeUnknown),
        "same execution does not retag another concrete client"
    );
    for field in ["request_id", "operations", "stamp"] {
        let mut altered = serde_json::to_value(request).unwrap();
        match field {
            "request_id" => altered[field] = serde_json::to_value([99_u8; 16]).unwrap(),
            "operations" => {
                altered[field][0]["Create"]["value"] = serde_json::to_value(value(99)).unwrap()
            }
            "stamp" => {
                altered[field]["namespace"]["scope"]["slot"] =
                    serde_json::to_value([99_u8; 32]).unwrap()
            }
            _ => unreachable!(),
        }
        let altered: ScopeBatchRequest = serde_json::from_value(altered).unwrap();
        assert_ne!(&altered, request, "fixture really changes {field}");
        assert!(
            client
                .verify_batch_completion(authority, &altered, completion)
                .is_err(),
            "{field}"
        );
    }
    // Reopening the same native factory preserves the already delivered proof.
    let reopened = client
        .batches(authority, ScopeWorkClass::Emergency, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        client
            .verify_batch_completion(authority, request, completion)
            .unwrap()
            .class(),
        ScopeWorkClass::Normal
    );
    assert!(!reopened.ack(completion.attempt()));

    let local = ScopeBatchStore::new(
        store.clone(),
        authority.stamp().scope().clone(),
        Arc::new(Admission(authority.stamp().clone())),
    )
    .unwrap();
    let cut = local
        .reopen(authority.stamp().execution().identity())
        .await
        .unwrap();
    let log = store.status().last_log_index;
    for (index, class) in [ScopeWorkClass::Normal, ScopeWorkClass::Emergency]
        .into_iter()
        .enumerate()
    {
        for copied in [false, true] {
            let context = if copied {
                completion.context().unwrap().clone()
            } else {
                ScopeBatchCompletionContext::new((request.clone(), class, outcome.clone()))
            };
            let forged = ScopeBatchCoordinator::open_port(
                Arc::new(ForgedPort {
                    cut: cut.clone(),
                    outcome: *outcome.clone(),
                    context,
                }),
                authority,
                scheduler.clone(),
                class,
            )
            .await
            .unwrap();
            let operations = request.operations().to_vec();
            let saved = Arc::new(std::sync::Mutex::new(None));
            let retained = saved.clone();
            let id = 110 + (index * 2) as u8 + u8::from(copied);
            let handle = forged
                .reserve_lane(3, class)
                .await
                .unwrap()
                .submit(|context| async move {
                    let request = context.request([id; 16], operations, vec![])?;
                    *retained.lock().unwrap() = Some(request.clone());
                    Ok(request)
                })
                .await
                .unwrap();
            let fake = handle.completion().await;
            assert!(matches!(
                fake.outcome(),
                ScopeBatchCompletionOutcome::Applied(_)
            ));
            assert_eq!(
                client
                    .verify_batch_completion(
                        authority,
                        saved.lock().unwrap().as_ref().unwrap(),
                        &fake
                    )
                    .err(),
                Some(ScopeBatchError::OutcomeUnknown),
                "public port facts or copied proof cannot retag a completion"
            );
            assert!(forged.ack(fake.attempt()));
        }
    }
    assert_eq!(
        store.status().last_log_index,
        log,
        "forged completions never submitted anything"
    );
    let _ = client
        .batches(authority, ScopeWorkClass::Normal, Duration::from_secs(2))
        .await
        .unwrap();
    drop(verified);
}
