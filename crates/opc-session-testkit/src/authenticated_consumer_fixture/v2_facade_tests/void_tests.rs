use super::*;
use futures_util::FutureExt;

fn stall_original(fixture: &AuthenticatedPreparedFencedTransitionFixture, enabled: bool) {
    for voter in &fixture.voters {
        voter
            .service
            .stall_fenced_transition_v2_mutation
            .store(enabled, Ordering::Release);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_sweep_preserves_an_unregistered_trait_callers_receipt() {
    use opc_session_store::{
        fenced_transition::FencedTransitionV2Effect, EncryptingSessionBackend,
        FencedTransitionV2JournalScope, ProtectedFencedTransitionV2Backend,
    };
    use sha2::{Digest, Sha256};

    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let provider = CountingProvider::new();
        let journal = fixture.open_recovery_journal().unwrap();
        let clients = fixture.persistent_clients().unwrap();
        // Reproduce a caller composing the public sealed port with the same
        // journal authority as the facade, but without calling begin_call.
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/session-consumer/prepared-fenced-v2-recovery-scope/v1\0");
        digest.update(fixture.client_config.local_spiffe_identity_commitment().unwrap());
        digest.update(clients[0].scope().consensus_identity().cluster_id().as_bytes());
        let wrapper = EncryptingSessionBackend::new(
            Arc::new(fixture.cluster.store(0)),
            Arc::clone(&provider),
            "void-trait-caller",
        )
        .with_fenced_transition_v2_recovery_journal(Arc::clone(&journal))
        .with_fenced_transition_v2_journal_scope(FencedTransitionV2JournalScope::from_bytes(
            digest.finalize().into(),
        ));
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(clients).await.unwrap();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(activated, provider, "void-trait-caller", journal).unwrap();
        let deadline = soon();
        let prepared = wrapper.prepare_protected_fenced_transition_v2(create(request_id(919), 919, PAYLOAD)).await.unwrap();
        let report = facade.reclaim_resolved_fenced_transitions(8, budget(deadline)).await.unwrap();
        assert_eq!(report.waiting_callers(), 1);
        assert_eq!(report.voided(), 0);
        assert_eq!(report.reclaimed(), 0);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 1);
        assert!(tokio::time::Instant::now() < deadline);
        assert!(matches!(wrapper.protected_fenced_transition_v2_effect(&prepared).await, FencedTransitionV2Effect::Resolved(Ok(_))));
        assert!(matches!(wrapper.protected_fenced_transition_v2_status(&prepared).await.unwrap(), FencedTransitionV2Status::Recorded(result) if result.is_ok()));
        assert!(wrapper.discard_protected_fenced_transition_v2(&prepared).await.unwrap());
    }).catch_unwind().await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_profile_preserves_the_legacy_capability_decoder_and_operations() {
    // Freeze the original V2 consumer vocabulary, without either extension
    // operation or a new capability variant. Exercise every original /2
    // operation against the real service over its authenticated client lane.
    #[derive(Debug, serde::Deserialize, PartialEq)]
    enum LegacyCapability {
        V2,
    }
    #[derive(Debug, serde::Deserialize)]
    #[serde(
        tag = "response",
        content = "body",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum LegacyReply {
        FencedTransitionV2Capability(
            Result<LegacyCapability, opc_session_store::SessionConsumerStoreError>,
        ),
        FencedTransitionV2HistoryState(
            Result<opc_session_store::FencedTransitionV2HistoryState, SessionConsumerStoreError>,
        ),
        FencedTransitionV2(
            Result<
                FencedTransitionOutcome,
                opc_session_store::SessionConsumerV2FencedTransitionError,
            >,
        ),
        FencedTransitionV2Batch(
            Result<
                Vec<opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchResult>,
                opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError,
            >,
        ),
        FencedTransitionV2Status(
            Result<
                opc_session_store::SessionConsumerV2FencedTransitionStatus,
                SessionConsumerStoreError,
            >,
        ),
    }
    #[derive(serde::Serialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum LegacyOperation {
        FencedTransitionV2Capability,
        FencedTransitionV2HistoryState,
        FencedTransitionV2 {
            request: Box<opc_session_store::FencedTransitionV2Request>,
        },
        FencedTransitionV2Batch {
            requests: Vec<opc_session_store::FencedTransitionV2Request>,
        },
        FencedTransitionV2Status {
            request: Box<opc_session_store::FencedTransitionV2Request>,
        },
    }
    fn legacy_clients(
        fixture: &AuthenticatedPreparedFencedTransitionFixture,
    ) -> Vec<PersistentSessionConsumerClient> {
        fixture
            .voters
            .iter()
            .map(|voter| {
                PersistentSessionConsumerClient::from_stateless(
                    StatelessSessionConsumerClient::new(
                        voter.address,
                        rustls_pki_types::ServerName::IpAddress(voter.address.ip().into()),
                        voter.authority.clone(),
                        fixture.client_config.clone(),
                    ),
                )
                .unwrap()
            })
            .collect()
    }
    async fn legacy_call(
        client: &PersistentSessionConsumerClient,
        operation: LegacyOperation,
    ) -> LegacyReply {
        let bytes = serde_json::to_vec(&operation).unwrap();
        let operation: SessionConsumerV2Operation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&operation).unwrap(), bytes);
        let response = client
            .execute_v2(&SessionConsumerV2Request::new(client.scope(), operation))
            .await
            .unwrap();
        serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap()
    }
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        for client in legacy_clients(&fixture) {
            client.prewarm_v2().await.unwrap();
            let LegacyReply::FencedTransitionV2Capability(result) = legacy_call(&client, LegacyOperation::FencedTransitionV2Capability).await else { panic!("legacy capability reply"); };
            assert_eq!(result.unwrap(), LegacyCapability::V2);
        }
        let facade = fixture
            .open_local_aead_v2(CountingProvider::new(), "legacy-capability")
            .await
            .unwrap();
        let transition = create(request_id(909), 909, PAYLOAD);
        let deadline = soon();
        let mut prepared = facade
            .prepare_fenced_transition(transition.clone(), budget(deadline))
            .await
            .unwrap();
        committed_v2(&mut prepared, &transition, deadline).await;
        let mut recovered = recovered_v2(
            facade
                .recover_fenced_transition_status(prepared.request_id(), budget(deadline))
                .await
                .unwrap(),
        );
        let status = recovered.status_once(deadline).await;
        assert!(
            matches!(&status, Ok(FencedTransitionV2Status::Recorded(result)) if result.is_ok()),
            "{status:?}"
        );
        let physical = fixture.voters.iter().find_map(|voter| voter.service.last_fenced_transition_v2_request.lock().unwrap().clone()).unwrap();
        for client in legacy_clients(&fixture) {
            client.prewarm_v2().await.unwrap();
            assert!(matches!(legacy_call(&client, LegacyOperation::FencedTransitionV2HistoryState).await, LegacyReply::FencedTransitionV2HistoryState(Ok(_))));
            assert!(matches!(legacy_call(&client, LegacyOperation::FencedTransitionV2 { request: Box::new(physical.clone()) }).await, LegacyReply::FencedTransitionV2(Ok(_))));
            assert!(matches!(legacy_call(&client, LegacyOperation::FencedTransitionV2Batch { requests: vec![physical.clone()] }).await, LegacyReply::FencedTransitionV2Batch(Ok(results)) if results.len() == 1 && results[0].result().is_ok()));
            assert!(matches!(legacy_call(&client, LegacyOperation::FencedTransitionV2Status { request: Box::new(physical.clone()) }).await, LegacyReply::FencedTransitionV2Status(Ok(_))));
        }
        prepared.release_resolved().await.unwrap();
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
    })
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_unavailable_row_advances_past_status_resolvable_rows_and_wraps() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let journal = fixture.open_recovery_journal().unwrap();
        let provider = CountingProvider::new();
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(fixture.persistent_clients().unwrap()).await.unwrap();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(activated, Arc::clone(&provider), "void-cursor", Arc::clone(&journal)).unwrap();
        drop(facade.prepare_fenced_transition(create(request_id(911), 911, PAYLOAD), budget(soon())).await.unwrap());
        for voter in &fixture.voters { voter.service.stall_fenced_transition_v2_void_response.store(true, Ordering::Release); }
        let unknown = facade.reclaim_resolved_fenced_transitions(8, budget(soon())).await.unwrap();
        assert_eq!(unknown.reclaimed(), 0);
        assert_eq!(unknown.retained(), 1);
        drop(facade);
        for voter in &fixture.voters {
            voter.service.stall_fenced_transition_v2_void_response.store(false, Ordering::Release);
            voter.service.unavailable_fenced_transition_v2_capability.store(true, Ordering::Release);
        }
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(fixture.persistent_clients().unwrap()).await.unwrap();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(activated, provider, "void-cursor", journal).unwrap();
        for ordinal in [910, 912] { drop(facade.prepare_fenced_transition(create(request_id(ordinal), ordinal, PAYLOAD), budget(soon())).await.unwrap()); }
        let report = facade.reclaim_resolved_fenced_transitions(3, budget(soon())).await.unwrap();
        assert!(!report.interrupted(), "{report:?}");
        assert_eq!(report.examined(), 3, "{report:?}");
        assert_eq!(report.voided(), 1, "{report:?}");
        assert_eq!(report.reclaimed(), 1, "recorded status behind the unavailable first row: {report:?}");
        assert_eq!(report.retained(), 2, "{report:?}");
        let wrapped = facade.reclaim_resolved_fenced_transitions(3, budget(soon())).await.unwrap();
        assert_eq!(wrapped.examined(), 0, "finish the cursor page and wrap: {wrapped:?}");
        // Permit the first committed void reply, but hold the second until
        // this sweep returns. This deterministically spends that attempt's
        // unchanged 250ms cap, as host scheduling can, without losing its
        // durable receipt or relying on an arbitrary sleep.
        let response_gate = Arc::new(tokio::sync::Semaphore::new(1));
        for voter in &fixture.voters {
            *voter.service.fenced_transition_v2_void_response_gate.lock().unwrap() = Some(Arc::clone(&response_gate));
        }
        for voter in &fixture.voters { voter.service.unavailable_fenced_transition_v2_capability.store(false, Ordering::Release); }
        // An unknown void advances the cursor and retains its row; a caller
        // must sweep again to observe its exact receipt. Keep one original
        // five-second budget for the entire drain, including every retry.
        let deadline = soon();
        let mut reports = Vec::new();
        let mut voided = 0;
        let mut reclaimed = 0;
        let drained = tokio::time::timeout_at(deadline, async {
            loop {
                let report = facade.reclaim_resolved_fenced_transitions(3, budget(deadline)).await
                    .unwrap_or_else(|error| panic!("retry drain failed: {error:?}; reports={reports:?}"));
                voided += report.voided();
                reclaimed += report.reclaimed();
                reports.push(report);
                if reports.len() == 1 {
                    assert!(!report.interrupted(), "first retry sweep must complete: {reports:?}");
                    assert_eq!(report.examined(), 2, "one pass reaches rows on both sides of the prior cursor: {reports:?}");
                    assert!(report.voided() < 2, "the held reply must force a partial sweep: {report:?}");
                    response_gate.add_permits(1);
                }
                if facade.retained_fenced_transitions().await.unwrap() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }).await;
        assert!(drained.is_ok(), "retry drain exceeded its unchanged five-second budget: {reports:?}");
        assert_eq!(voided, 2, "retry rows on both sides of the prior cursor: {reports:?}");
        assert_eq!(reclaimed, 2, "both retry rows removed exactly once: {reports:?}");
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0, "{reports:?}");
    }).catch_unwind().await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_available_rows_drain_in_one_sweep_after_cursor_wrap() {
    let fixture = Arc::new(
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap(),
    );
    let result = std::panic::AssertUnwindSafe(async {
        let journal = fixture.open_recovery_journal().unwrap();
        let provider = CountingProvider::new();
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(fixture.persistent_clients().unwrap()).await.unwrap();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(activated, Arc::clone(&provider), "void-cursor", Arc::clone(&journal)).unwrap();
        drop(facade.prepare_fenced_transition(create(request_id(911), 911, PAYLOAD), budget(soon())).await.unwrap());
        for voter in &fixture.voters { voter.service.stall_fenced_transition_v2_void_response.store(true, Ordering::Release); }
        let unknown = facade.reclaim_resolved_fenced_transitions(8, budget(soon())).await.unwrap();
        assert_eq!(unknown.reclaimed(), 0);
        assert_eq!(unknown.retained(), 1);
        drop(facade);
        for voter in &fixture.voters {
            voter.service.stall_fenced_transition_v2_void_response.store(false, Ordering::Release);
            voter.service.unavailable_fenced_transition_v2_capability.store(true, Ordering::Release);
        }
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(fixture.persistent_clients().unwrap()).await.unwrap();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(activated, Arc::clone(&provider), "void-cursor", Arc::clone(&journal)).unwrap();
        for ordinal in [910, 912] { drop(facade.prepare_fenced_transition(create(request_id(ordinal), ordinal, PAYLOAD), budget(soon())).await.unwrap()); }
        let report = facade.reclaim_resolved_fenced_transitions(3, budget(soon())).await.unwrap();
        assert!(!report.interrupted(), "{report:?}");
        assert_eq!(report.examined(), 3, "{report:?}");
        assert_eq!(report.voided(), 1, "{report:?}");
        assert_eq!(report.reclaimed(), 1, "recorded status behind the unavailable first row");
        assert_eq!(report.retained(), 2, "{report:?}");
        let wrapped = facade.reclaim_resolved_fenced_transitions(3, budget(soon())).await.unwrap();
        assert_eq!(wrapped.examined(), 0, "finish the cursor page and wrap");
        for voter in &fixture.voters { voter.service.unavailable_fenced_transition_v2_capability.store(false, Ordering::Release); }
        drop(facade);
        // With available void capability and no held response, one sweep
        // must reach and remove both rows on either side of the old cursor.
        // Reopen the same journal with clients created on the frozen runtime,
        // so host scheduling cannot spend a void attempt's protocol deadline.
        let fixture = Arc::clone(&fixture);
        with_fixture_protocol_clock("one available void sweep", async move {
            let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(fixture.persistent_clients().unwrap()).await.unwrap();
            let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(activated, provider, "void-cursor", journal).unwrap();
            let drained = facade.reclaim_resolved_fenced_transitions(3, budget(soon())).await.unwrap();
            assert!(!drained.interrupted(), "one available sweep completes: {drained:?}");
            assert_eq!(drained.examined(), 2, "one available sweep reaches both rows: {drained:?}");
            assert_eq!(drained.voided(), 2, "one available sweep voids both rows: {drained:?}");
            assert_eq!(drained.reclaimed(), 2, "both rows are removed in the same sweep: {drained:?}");
            assert_eq!(drained.retained(), 0, "{drained:?}");
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0, "{drained:?}");
        }).await;
    }).catch_unwind().await;
    Arc::try_unwrap(fixture)
        .unwrap_or_else(|_| panic!("the frozen client released the fixture"))
        .shutdown()
        .await
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_lost_before_bind_drains_the_row_and_resolves_the_live_handle() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture.open_local_aead_v2(CountingProvider::new(), "void-lost").await.unwrap();
        let transition = create(request_id(901), 901, PAYLOAD);
        let deadline = soon();
        let mut prepared = facade.prepare_fenced_transition(transition, budget(deadline)).await.unwrap();
        stall_original(&fixture, true);
        assert!(matches!(prepared.execute_once().await, Err(FencedTransitionExecuteError::OutcomeUnknown { .. })));
        let waiting = facade.reclaim_resolved_fenced_transitions(8, budget(soon())).await.unwrap();
        assert_eq!(waiting.waiting_callers(), 1);
        assert_eq!(waiting.reclaimed(), 0);
        tokio::time::sleep_until(deadline).await;
        let report = facade.reclaim_resolved_fenced_transitions(8, budget(soon())).await.unwrap();
        assert_eq!(report.voided(), 1, "{report:?}");
        assert_eq!(report.reclaimed(), 1);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
        assert!(matches!(prepared.status_once(soon()).await, Ok(FencedTransitionV2Status::Recorded(result)) if matches!(*result, Err(StoreError::FencedTransitionVoided))));
        prepared.release_resolved().await.unwrap();
        for store in &fixture.cluster.stores {
            assert!(store.get(&session_key(901)).await.unwrap().is_none());
        }
    }).catch_unwind().await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_keeps_a_waiting_call_then_drains_after_cancellation() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture
            .open_local_aead_v2(CountingProvider::new(), "void-cancel")
            .await
            .unwrap();
        let mut prepared = facade
            .prepare_fenced_transition(create(request_id(902), 902, PAYLOAD), budget(soon()))
            .await
            .unwrap();
        let waiting = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(waiting.waiting_callers(), 1);
        assert_eq!(waiting.reclaimed(), 0);
        stall_original(&fixture, true);
        let call = tokio::spawn(async move { prepared.execute_once().await });
        let deadline = soon();
        while fixture.voters.iter().all(|voter| {
            voter
                .service
                .fenced_transition_v2_calls
                .load(Ordering::Acquire)
                == 0
        }) {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        let report = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(report.voided(), 1, "{report:?}");
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
    })
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_cancelled_preflight_then_redispatch_protects_the_live_call() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture
            .open_local_aead_v2(CountingProvider::new(), "void-redispatch")
            .await
            .unwrap();
        let mut prepared = facade
            .prepare_fenced_transition(create(request_id(908), 908, PAYLOAD), budget(soon()))
            .await
            .unwrap();
        // One poll starts authenticated preflight, which awaits its blocking
        // journal read before dispatch. Drop that pending future, then reuse
        // the original handle within its unchanged deadline.
        let mut cancelled = Box::pin(prepared.execute_once());
        assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
        drop(cancelled);
        assert!(fixture.voters.iter().all(|voter| voter
            .service
            .fenced_transition_v2_calls
            .load(Ordering::Acquire)
            == 0));
        stall_original(&fixture, true);
        let call = tokio::spawn(async move { prepared.execute_once().await });
        let deadline = soon();
        while fixture.voters.iter().all(|voter| {
            voter
                .service
                .fenced_transition_v2_calls
                .load(Ordering::Acquire)
                == 0
        }) {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let report = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(report.waiting_callers(), 1);
        assert_eq!(report.reclaimed(), 0);
        call.abort();
        let _ = call.await;
        let report = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(report.voided(), 1, "{report:?}");
    })
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_older_voter_is_reported_and_the_row_stays_retained() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let clients = fixture.persistent_clients().unwrap();
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(clients.clone()).await.unwrap();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
            activated, CountingProvider::new(), "void-old-voter", fixture.open_recovery_journal().unwrap(),
        ).unwrap();
        for ordinal in 920..923 {
            drop(facade.prepare_fenced_transition(create(request_id(ordinal), ordinal, PAYLOAD), budget(soon())).await.unwrap());
        }
        for voter in &fixture.voters {
            voter
                .service
                .legacy_fenced_transition_v2_capability
                .store(true, Ordering::Release);
        }
        let report = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(report.unsupported(), 3);
        assert_eq!(report.reclaimed(), 0);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 3);
        let repeated = facade.reclaim_resolved_fenced_transitions(8, budget(soon())).await.unwrap();
        assert_eq!(repeated.unsupported(), 3);
        assert_eq!(repeated.reclaimed(), 0);
        for voter in &fixture.voters {
            voter
                .service
                .legacy_fenced_transition_v2_capability
                .store(false, Ordering::Release);
        }
        // A definite answer is tied to each connection, so only replacement
        // lanes may observe the fixture's newly enabled support.
        for client in &clients {
            client.request_reauthentication().unwrap();
            client.prewarm_v2().await.unwrap();
        }
        let report = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(report.voided(), 3);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
    })
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_unknown_response_retains_until_exact_status_confirms_it() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture
            .open_local_aead_v2(CountingProvider::new(), "void-response-loss")
            .await
            .unwrap();
        drop(
            facade
                .prepare_fenced_transition(create(request_id(904), 904, PAYLOAD), budget(soon()))
                .await
                .unwrap(),
        );
        for voter in &fixture.voters {
            voter
                .service
                .stall_fenced_transition_v2_void_response
                .store(true, Ordering::Release);
        }
        let unknown = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert!(!unknown.interrupted());
        assert_eq!(unknown.reclaimed(), 0);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 1);
        let confirmed = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert_eq!(confirmed.voided(), 1);
        assert_eq!(confirmed.reclaimed(), 1);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
    })
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_one_unavailable_capability_does_not_veto_certified_quorum() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture
            .open_local_aead_v2(CountingProvider::new(), "void-unavailable-capability")
            .await
            .unwrap();
        drop(
            facade
                .prepare_fenced_transition(create(request_id(907), 907, PAYLOAD), budget(soon()))
                .await
                .unwrap(),
        );
        fixture.voters[1]
            .service
            .unavailable_fenced_transition_v2_capability
            .store(true, Ordering::Release);
        let report = facade
            .reclaim_resolved_fenced_transitions(8, budget(soon()))
            .await
            .unwrap();
        assert!(!report.interrupted());
        assert_eq!(report.unsupported(), 0);
        assert_eq!(report.voided(), 1, "{report:?}");
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
    })
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_inherited_row_is_reclaimed_without_the_previous_call_deadline() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let previous_deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        let facade = fixture.open_local_aead_v2(CountingProvider::new(), "void-restart").await.unwrap();
        drop(facade.prepare_fenced_transition(create(request_id(905), 905, PAYLOAD), budget(previous_deadline)).await.unwrap());
        drop(facade);
        let reopened = fixture.open_local_aead_v2(CountingProvider::new(), "void-restart").await.unwrap();
        let mut handle = recovered_v2(reopened.recover_fenced_transition_status(request_id(905), budget(soon())).await.unwrap());
        let report = reopened.reclaim_resolved_fenced_transitions(8, budget(soon())).await.unwrap();
        assert_eq!(report.voided(), 1, "{report:?}");
        assert_eq!(reopened.retained_fenced_transitions().await.unwrap(), 0);
        assert!(tokio::time::Instant::now() < previous_deadline);
        assert!(matches!(handle.status_once(soon()).await, Ok(FencedTransitionV2Status::Recorded(result)) if matches!(*result, Err(StoreError::FencedTransitionVoided))));
        handle.release_resolved().await.unwrap();
    }).catch_unwind().await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_void_drains_after_the_leader_loses_authority_during_the_original_call() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture.open_local_aead_v2(CountingProvider::new(), "void-authority-loss").await.unwrap();
        let mut prepared = facade.prepare_fenced_transition(create(request_id(906), 906, PAYLOAD), budget(soon())).await.unwrap();
        let leader_id = fixture.cluster.store(0).status().leader_id.unwrap();
        let leader = fixture.cluster.stores.iter().position(|store| store.status().node_id == leader_id).unwrap();
        stall_original(&fixture, true);
        let call = tokio::spawn(async move { let result = prepared.execute_once().await; (prepared, result) });
        let deadline = soon();
        while fixture.voters.iter().all(|voter| voter.service.fenced_transition_v2_calls.load(Ordering::Acquire) == 0) {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        fixture.cluster.set_node_online(leader, false);
        let (mut prepared, result) = call.await.unwrap();
        assert!(matches!(result, Err(FencedTransitionExecuteError::OutcomeUnknown { .. })));
        assert!(!fixture.cluster.store(leader).probe_durable_readiness().await.is_ready());
        let survivor = (leader + 1) % 3;
        fixture.cluster.wait_node_durable_ready(survivor).await;
        assert_ne!(fixture.cluster.store(survivor).status().leader_id, Some(leader_id));
        fixture.cluster.set_node_online(leader, true);
        fixture.cluster.wait_ready(true).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while facade.retained_fenced_transitions().await.unwrap() != 0 {
            assert!(tokio::time::Instant::now() < deadline);
            facade.reclaim_resolved_fenced_transitions(8, budget(deadline)).await.unwrap();
        }
        assert!(matches!(prepared.status_once(soon()).await, Ok(FencedTransitionV2Status::Recorded(result)) if matches!(*result, Err(StoreError::FencedTransitionVoided))));
        prepared.release_resolved().await.unwrap();
        for store in &fixture.cluster.stores {
            assert!(store.get(&session_key(906)).await.unwrap().is_none());
        }
    }).catch_unwind().await;
    for index in 0..3 {
        fixture.cluster.set_node_online(index, true);
    }
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "production-capacity qualification; see the terminal void decision record"]
async fn consumer_full_journal_void_reclaims_all_inherited_unbound_rows() {
    full_journal_void_case(FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES).await;
}

#[cfg(feature = "test-control")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_small_full_journal_void_reclaims_all_inherited_unbound_rows() {
    full_journal_void_case(16).await;
}

async fn full_journal_void_case(capacity: usize) {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    #[cfg(feature = "test-control")]
    let fixture = {
        let mut fixture = fixture;
        fixture.recovery_capacity = capacity;
        fixture
    };
    #[cfg(not(feature = "test-control"))]
    assert_eq!(capacity, FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES);
    let started = std::time::Instant::now();
    let prepared_count = AtomicUsize::new(0);
    let reclaimed_count = AtomicUsize::new(0);
    let result =
        std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(if capacity == FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES { 900 } else { 60 }), async {
            let provider = CountingProvider::new();
            let facade = fixture
                .open_local_aead_v2(Arc::clone(&provider), "void-full")
                .await
                .unwrap();
            for ordinal in 0..capacity as u64 {
                drop(
                    facade
                        .prepare_fenced_transition(
                            create(request_id(10_000 + ordinal), 10_000 + ordinal, PAYLOAD),
                            budget(soon()),
                        )
                        .await
                        .unwrap(),
                );
                prepared_count.store(ordinal as usize + 1, Ordering::Release);
                if (ordinal + 1) % 512 == 0 {
                    eprintln!(
                        "full_journal_void phase=prepare prepared={} elapsed_ms={}",
                        ordinal + 1,
                        started.elapsed().as_millis()
                    );
                }
            }
            assert_eq!(
                facade.retained_fenced_transitions().await.unwrap(),
                capacity
            );
            assert!(matches!(
                facade
                    .prepare_fenced_transition(
                        create(request_id(99_999), 99_999, PAYLOAD),
                        budget(soon())
                    )
                    .await,
                Err(StoreError::FencedTransitionHistoryFull)
            ));
            drop(facade);
            let facade = fixture
                .open_local_aead_v2(Arc::clone(&provider), "void-full")
                .await
                .unwrap();
            let mut reclaimed = 0;
            while facade.retained_fenced_transitions().await.unwrap() != 0 {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                let report = facade
                    .reclaim_resolved_fenced_transitions(256, budget(deadline))
                    .await
                    .unwrap();
                assert_eq!(report.unsupported(), 0);
                assert_eq!(report.waiting_callers(), 0);
                reclaimed += report.reclaimed();
                reclaimed_count.store(reclaimed, Ordering::Release);
                eprintln!(
                    "full_journal_void phase=reclaim reclaimed={reclaimed} examined={} retained={} interrupted={} elapsed_ms={}",
                    report.examined(),
                    report.retained(),
                    report.interrupted(),
                    started.elapsed().as_millis()
                );
            }
            assert_eq!(reclaimed, capacity);
            assert_eq!(
                fixture.diagnostics().fenced_transition_v2_calls(),
                0,
                "reclamation never dispatches an original"
            );
            for ordinal in [10_000, 10_000 + capacity as u64 / 2, 10_000 + capacity as u64 - 1] {
                for store in &fixture.cluster.stores {
                    assert!(store.get(&session_key(ordinal)).await.unwrap().is_none());
                }
            }
            let transition = create(request_id(99_999), 99_999, PAYLOAD);
            let deadline = soon();
            let mut prepared = facade
                .prepare_fenced_transition(transition.clone(), budget(deadline))
                .await
                .unwrap();
            committed_v2(&mut prepared, &transition, deadline).await;
            prepared.release_resolved().await.unwrap();
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
        }))
        .catch_unwind()
        .await;
    fixture.shutdown().await.unwrap();
    match result {
        Ok(result) => result.unwrap_or_else(|_| {
            panic!(
                "full journal void timed out: prepared={}, reclaimed={}",
                prepared_count.load(Ordering::Acquire),
                reclaimed_count.load(Ordering::Acquire)
            )
        }),
        Err(error) => std::panic::resume_unwind(error),
    }
}
