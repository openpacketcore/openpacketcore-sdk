use super::*;
use futures_util::FutureExt;
use opc_session_store::{Clock, FencedTransitionV2Profile, SessionLeaseManager};
use opc_types::Timestamp;
use std::sync::atomic::AtomicU64;

#[derive(Debug)]
struct StoreClock {
    origin: Timestamp,
    seconds: AtomicU64,
}

impl StoreClock {
    fn advance(&self, seconds: u64) {
        self.seconds.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for StoreClock {
    fn now_utc(&self) -> Timestamp {
        Timestamp::from_offset_datetime(
            *self.origin.as_offset_datetime()
                + Duration::from_secs(self.seconds.load(Ordering::SeqCst)),
        )
    }
}

async fn fixture() -> (
    AuthenticatedPreparedFencedTransitionFixture,
    Arc<StoreClock>,
) {
    let clock = Arc::new(StoreClock {
        origin: Timestamp::now_utc(),
        seconds: AtomicU64::new(0),
    });
    let source: Arc<dyn Clock> = clock.clone();
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_with_profile_options(
        [scope()],
        true,
        true,
        Some((FencedTransitionV2Profile::V2WithLeaseDeferral, source)),
    )
    .await
    .unwrap();
    (fixture, clock)
}

fn successor(
    predecessor: &FencedTransitionOutcome,
    id: FencedTransitionRequestId,
) -> FencedTransitionRequest {
    let owner = OwnerId::new("synthetic-successor").unwrap();
    let lease = FencedTransitionLease::acquire(
        predecessor.lease().key().clone(),
        owner.clone(),
        predecessor.lease().fence(),
        Duration::from_secs(30),
    )
    .unwrap();
    FencedTransitionRequest::new(
        id,
        lease.clone(),
        FencedTransitionMutation::update(
            predecessor.committed_generation(),
            StoredSessionRecord {
                key: predecessor.lease().key().clone(),
                generation: predecessor.committed_generation().next().unwrap(),
                owner,
                fence: lease.committed_fence().unwrap(),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("fixture-v2-facade"),
                expires_at: None,
                payload: EncryptedSessionPayload::new(PAYLOAD),
            },
        ),
    )
    .unwrap()
}

async fn predecessor(
    facade: &SessionConsumerPreparedFencedTransitionV2Backend,
    label: u64,
) -> FencedTransitionOutcome {
    let request = create(request_id(label), label, PAYLOAD);
    let deadline = soon();
    let mut prepared = facade
        .prepare_fenced_transition(request.clone(), budget(deadline))
        .await
        .unwrap();
    let outcome = committed_v2(&mut prepared, &request, deadline).await;
    prepared.release_resolved().await.unwrap();
    outcome
}

async fn deferred(
    prepared: &mut SessionConsumerPreparedFencedTransitionV2,
    deadline: tokio::time::Instant,
) {
    match prepared.execute_once().await {
        Err(FencedTransitionExecuteError::LeaseDeferred) => {}
        Err(FencedTransitionExecuteError::OutcomeUnknown { request_id }) => {
            assert_eq!(request_id, prepared.request_id());
        }
        other => panic!("a live predecessor must defer without a business effect: {other:?}"),
    }
    assert!(matches!(
        prepared.status_until_terminal(deadline).await.unwrap(),
        FencedTransitionV2Status::LeaseDeferred { .. }
    ));
    assert_eq!(
        prepared.release_resolved().await,
        Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
    );
    assert_eq!(
        prepared.execute_once().await,
        Err(FencedTransitionExecuteError::NotTransmitted),
        "a deferral requires the explicit SDK resume operation"
    );
}

fn sealed_request(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
    id: FencedTransitionRequestId,
) -> opc_session_store::FencedTransitionV2Request {
    fixture
        .voters
        .iter()
        .filter_map(|voter| {
            voter
                .service
                .last_fenced_transition_v2_request
                .lock()
                .unwrap()
                .clone()
        })
        .find(|request| request.request_id().nonce().as_bytes() == id.as_bytes())
        .unwrap()
}

fn status_fault(fixture: &AuthenticatedPreparedFencedTransitionFixture, fault: u8) {
    for voter in &fixture.voters {
        voter
            .service
            .fenced_transition_v2_status_fault
            .store(fault, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_lease_deferral_full_journal_retains_one_binding_and_reuses_completion_capacity() {
    let (fixture, clock) = fixture().await;
    // Exercise the same authenticated admission fence in both profiles. The
    // test-control profile supplies the existing small-capacity fixture hook;
    // ordinary builds fill the complete production bound rather than skip.
    #[cfg(feature = "test-control")]
    let fixture = {
        let mut fixture = fixture;
        fixture.recovery_capacity = 4;
        fixture
    };
    let capacity = if cfg!(feature = "test-control") {
        4
    } else {
        FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES
    };
    let result = std::panic::AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(
            if capacity == FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES {
                900
            } else {
                60
            },
        ),
        async {
            let provider = CountingProvider::new();
            let facade = fixture
                .open_local_aead_v2(Arc::clone(&provider), "lease-deferral-full")
                .await
                .unwrap();
            let prior = predecessor(&facade, 2000).await;
            let request = successor(&prior, request_id(2001));
            let id = request.request_id();
            let deadline = soon();
            let mut prepared = facade
                .prepare_fenced_transition(request.clone(), budget(deadline))
                .await
                .unwrap();
            deferred(&mut prepared, deadline).await;
            let exact = sealed_request(&fixture, id);
            drop(prepared);
            let mut fillers = Vec::new();
            for ordinal in 1..capacity as u64 {
                fillers.push(
                    facade
                        .prepare_fenced_transition(
                            create(request_id(20_000 + ordinal), 30_000 + ordinal, PAYLOAD),
                            budget(soon()),
                        )
                        .await
                        .unwrap(),
                );
            }
            assert_eq!(
                facade.retained_fenced_transitions().await.unwrap(),
                capacity
            );
            let calls = fixture.diagnostics().fenced_transition_v2_calls();
            let provider_calls = provider.calls();
            let extra = create(request_id(99_000), 99_000, PAYLOAD);
            assert!(matches!(
                facade
                    .prepare_fenced_transition(extra.clone(), budget(soon()))
                    .await,
                Err(StoreError::FencedTransitionHistoryFull)
            ));
            assert_eq!(provider.calls(), provider_calls);
            assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), calls);
            for _ in 1..16 {
                let deadline = soon();
                let mut resumed = facade
                    .resume_deferred_fenced_transition(id, budget(deadline))
                    .await
                    .unwrap()
                    .unwrap();
                deferred(&mut resumed, deadline).await;
                assert_eq!(sealed_request(&fixture, id), exact);
                assert_eq!(
                    facade.retained_fenced_transitions().await.unwrap(),
                    capacity
                );
                assert_eq!(provider.calls(), provider_calls);
                assert_eq!(
                    fixture
                        .cluster
                        .store(0)
                        .fenced_transition_v2_history_state()
                        .await
                        .unwrap()
                        .bound_entries(),
                    2
                );
            }
            assert_eq!(
                fixture.diagnostics().fenced_transition_v2_calls(),
                calls + 15
            );
            clock.advance(31);
            let deadline = soon();
            let mut resumed = facade
                .resume_deferred_fenced_transition(id, budget(deadline))
                .await
                .unwrap()
                .unwrap();
            let result = committed_v2(&mut resumed, &request, deadline).await;
            assert_eq!(result.committed_generation(), Generation::new(2));
            resumed.release_resolved().await.unwrap();
            assert_eq!(
                facade.retained_fenced_transitions().await.unwrap(),
                capacity - 1
            );
            assert_eq!(
                fixture.diagnostics().fenced_transition_v2_calls(),
                calls + 16
            );
            let replacement = facade
                .prepare_fenced_transition(extra, budget(soon()))
                .await
                .unwrap();
            assert_eq!(
                facade.retained_fenced_transitions().await.unwrap(),
                capacity
            );
            assert_eq!(
                fixture.diagnostics().fenced_transition_v2_calls(),
                calls + 16
            );
            drop(replacement);
            drop(fillers);
        },
    ))
    .catch_unwind()
    .await;
    fixture.shutdown().await.unwrap();
    match result {
        Ok(completed) => {
            completed.expect("full deferral journal proof finishes within its fixed watchdog")
        }
        Err(error) => std::panic::resume_unwind(error),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_lease_deferral_reuses_one_sealed_binding_across_sixteen_refusals_and_restart() {
    let (fixture, clock) = fixture().await;
    let result = std::panic::AssertUnwindSafe(async {
        let provider = CountingProvider::new();
        let mut facade = fixture
            .open_local_aead_v2(Arc::clone(&provider), "lease-deferral")
            .await
            .unwrap();
        let prior = predecessor(&facade, 1334).await;
        let request = successor(&prior, request_id(1335));
        let id = request.request_id();
        let mut deadline = soon();
        let mut prepared = facade
            .prepare_fenced_transition(request.clone(), budget(deadline))
            .await
            .unwrap();
        let provider_calls = provider.calls();
        let calls = fixture.diagnostics().fenced_transition_v2_calls();
        let mut exact = None;
        for refusal in 0..16 {
            deferred(&mut prepared, deadline).await;
            let sent = sealed_request(&fixture, id);
            assert_eq!(exact.get_or_insert_with(|| sent.clone()), &sent);
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 1);
            assert_eq!(provider.calls(), provider_calls, "resume never seals again");
            assert_eq!(
                fixture
                    .cluster
                    .store(0)
                    .fenced_transition_v2_history_state()
                    .await
                    .unwrap()
                    .bound_entries(),
                2
            );
            let observed = facade
                .observe_fenced_transition(prior.lease().key())
                .await
                .unwrap();
            assert_eq!(observed.current_fence(), prior.lease().fence());
            assert_eq!(
                observed.record().unwrap().generation,
                prior.committed_generation()
            );
            drop(prepared);
            if refusal == 7 {
                drop(facade);
                facade = fixture
                    .open_local_aead_v2(Arc::clone(&provider), "lease-deferral")
                    .await
                    .unwrap();
                let mut recovered = recovered_v2(
                    facade
                        .recover_fenced_transition_status(id, budget(soon()))
                        .await
                        .unwrap(),
                );
                assert_eq!(recovered.request_id(), id);
                assert_eq!(
                    recovered.release_resolved().await,
                    Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
                );
            }
            deadline = soon();
            prepared = facade
                .resume_deferred_fenced_transition(id, budget(deadline))
                .await
                .unwrap()
                .expect("exact deferral authorizes the same sealed request");
            assert_eq!(prepared.request_id(), id);
            assert!(
                prepared.abandon_unexecuted().await.is_err(),
                "a resumed binding cannot be abandoned"
            );
        }
        assert_eq!(
            fixture.diagnostics().fenced_transition_v2_calls(),
            calls + 16
        );
        clock.advance(31);
        let completed = committed_v2(&mut prepared, &request, deadline).await;
        assert_eq!(completed.committed_generation(), Generation::new(2));
        assert_eq!(sealed_request(&fixture, id), exact.unwrap());
        assert_eq!(provider.calls(), provider_calls);
        assert_eq!(
            fixture.diagnostics().fenced_transition_v2_calls(),
            calls + 17
        );
        assert!(
            facade
                .resume_deferred_fenced_transition(id, budget(soon()))
                .await
                .unwrap()
                .is_none(),
            "a terminal receipt never re-arms execution"
        );
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
async fn consumer_lease_deferral_unknown_commit_and_unavailable_or_absent_status_never_rearm() {
    let (fixture, clock) = fixture().await;
    let result = std::panic::AssertUnwindSafe(async {
        let provider = CountingProvider::new();
        let facade = fixture
            .open_local_aead_v2(Arc::clone(&provider), "lease-deferral-unknown")
            .await
            .unwrap();
        let prior = predecessor(&facade, 1340).await;
        let request = successor(&prior, request_id(1341));
        let id = request.request_id();
        let deadline = soon();
        let mut prepared = facade
            .prepare_fenced_transition(request, budget(deadline))
            .await
            .unwrap();
        deferred(&mut prepared, deadline).await;
        drop(prepared);
        clock.advance(31);
        let mut resumed = facade
            .resume_deferred_fenced_transition(id, budget(soon()))
            .await
            .unwrap()
            .unwrap();
        fixture.lose_next_fenced_transition_v2_response();
        assert_eq!(
            resumed.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id: id })
        );
        let exact = sealed_request(&fixture, id);
        let calls = fixture.diagnostics().fenced_transition_v2_calls();
        let provider_calls = provider.calls();
        drop(resumed);
        drop(facade);
        let facade = fixture
            .open_local_aead_v2(Arc::clone(&provider), "lease-deferral-unknown")
            .await
            .unwrap();
        status_fault(&fixture, 1);
        assert!(facade
            .resume_deferred_fenced_transition(id, budget(soon()))
            .await
            .is_err());
        status_fault(&fixture, 2);
        assert!(facade
            .resume_deferred_fenced_transition(id, budget(soon()))
            .await
            .unwrap()
            .is_none());
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 1);
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), calls);
        assert_eq!(provider.calls(), provider_calls);
        status_fault(&fixture, 0);
        let deadline = soon();
        let mut recovered = recovered_v2(
            facade
                .recover_fenced_transition_status(id, budget(deadline))
                .await
                .unwrap(),
        );
        assert!(
            matches!(recovered.status_until_terminal(deadline).await.unwrap(),
            FencedTransitionV2Status::Recorded(result) if result.is_ok())
        );
        assert!(facade
            .resume_deferred_fenced_transition(id, budget(soon()))
            .await
            .unwrap()
            .is_none());
        assert_eq!(sealed_request(&fixture, id), exact);
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), calls);
        recovered.release_resolved().await.unwrap();
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
async fn consumer_lease_deferral_rechecks_renewal_and_new_owner_after_resume_authority() {
    let (fixture, clock) = fixture().await;
    let result = std::panic::AssertUnwindSafe(async {
        let facade = fixture.open_local_aead_v2(CountingProvider::new(), "lease-deferral-race").await.unwrap();
        let prior = predecessor(&facade, 1350).await;
        let request = successor(&prior, request_id(1351));
        let id = request.request_id();
        let deadline = soon();
        let mut prepared = facade.prepare_fenced_transition(request, budget(deadline)).await.unwrap();
        deferred(&mut prepared, deadline).await;
        drop(prepared);
        let deadline = soon();
        let mut resumed = facade.resume_deferred_fenced_transition(id, budget(deadline)).await.unwrap().unwrap();
        clock.advance(20);
        fixture.cluster.store(0).renew(prior.lease(), Duration::from_secs(30)).await.unwrap();
        clock.advance(11);
        deferred(&mut resumed, deadline).await;
        drop(resumed);
        let deadline = soon();
        let mut resumed = facade.resume_deferred_fenced_transition(id, budget(deadline)).await.unwrap().unwrap();
        clock.advance(20);
        let current = fixture.cluster.store(0).acquire(prior.lease().key(), OwnerId::new("synthetic-third-owner").unwrap(), Duration::from_secs(30)).await.unwrap();
        match resumed.execute_once().await {
            Err(FencedTransitionExecuteError::Rejected(StoreError::StaleFence)) => {}
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id }) => assert_eq!(request_id, id),
            other => panic!("stale original fence must never mutate: {other:?}"),
        }
        assert!(matches!(resumed.status_until_terminal(deadline).await.unwrap(),
            FencedTransitionV2Status::Recorded(result) if matches!(*result, Err(StoreError::StaleFence))));
        let observed = facade.observe_fenced_transition(prior.lease().key()).await.unwrap();
        assert_eq!(observed.current_fence(), current.fence());
        assert_eq!(observed.record().unwrap().generation, Generation::new(1));
        resumed.release_resolved().await.unwrap();
    }).catch_unwind().await;
    fixture.shutdown().await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
