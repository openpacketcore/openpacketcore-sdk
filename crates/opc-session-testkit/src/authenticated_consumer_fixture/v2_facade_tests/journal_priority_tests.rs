use super::*;
use opc_session_store::scope_scheduler::ScopeWorkClass;
use ScopeWorkClass::{Emergency as Urgent, Normal as Ordinary};

const CLASSES: [ScopeWorkClass; 5] = [
    ScopeWorkClass::SafetyControl,
    ScopeWorkClass::Emergency,
    ScopeWorkClass::EmergencyClassification,
    ScopeWorkClass::Normal,
    ScopeWorkClass::Maintenance,
];

pub(super) fn admissions(
    journal: &opc_session_store::FencedTransitionV2RecoveryJournal,
) -> [usize; 5] {
    CLASSES.map(|class| journal.operation_admissions_for_test(class))
}

pub(super) fn assert_only_class_advanced(
    before: [usize; 5],
    after: [usize; 5],
    class: opc_session_store::scope_scheduler::ScopeWorkClass,
) {
    for (index, candidate) in CLASSES.into_iter().enumerate() {
        if candidate == class {
            assert!(after[index] > before[index]);
        } else {
            assert_eq!(after[index], before[index]);
        }
    }
}

#[tokio::test]
async fn fixture_v2_emergency_inventory_precedes_queued_ordinary_reads() {
    for remote in [false, true] {
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
                .await
                .expect("start inventory fixture");
        let journal = fixture.open_recovery_journal().expect("owned journal");
        let activated =
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
                fixture.persistent_clients().expect("fixture clients"),
            )
            .await
            .expect("activate exact voters");
        let facade = if remote {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_remote_sealing(
                activated,
                Arc::new(MemoryRemoteSealProvider::new(
                    KeyId::new("fixture-inventory-priority").expect("key ID"),
                    KeyPurpose::Session,
                    tenant(),
                    Zeroizing::new([0x6e; AES_256_GCM_SIV_KEY_LEN]),
                )),
                "fixture-inventory-priority",
                Arc::clone(&journal),
            )
        } else {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
                activated,
                CountingProvider::new(),
                "fixture-inventory-priority",
                Arc::clone(&journal),
            )
        }
        .expect("compose facade");
        let running = journal.hold_operation_for_test().await.expect("hold gate");
        let mut ordinary = Vec::new();
        for _ in 0..3 {
            let mut read = Box::pin(facade.retained_fenced_transitions());
            assert!(futures_util::poll!(&mut read).is_pending());
            ordinary.push(read);
        }
        let mut emergency = Box::pin(facade.retained_fenced_transitions_with_journal_class(Urgent));
        assert!(futures_util::poll!(&mut emergency).is_pending());
        let before = admissions(&journal);
        drop(running);
        // Poll the older ordinary reader first. Priority must come from the
        // native gate rather than this test's choice of the next future.
        let _ = futures_util::poll!(ordinary[0].as_mut());
        let completion = futures_util::poll!(&mut emergency);
        let after = admissions(&journal);
        drop(ordinary);
        let count = match completion {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => emergency.as_mut().await,
        }
        .expect("inventory completes");
        drop(emergency);
        let default_before = admissions(&journal);
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
        let default_after = admissions(&journal);
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
        drop(facade);
        drop(journal);
        fixture.shutdown().await.expect("shut down fixture");
        assert_eq!(count, 0, "inventory neither creates nor mutates a row");
        assert_eq!(
            after[3], before[3],
            "queued ordinary inventory must not precede the emergency read"
        );
        assert_only_class_advanced(before, after, Urgent);
        assert_only_class_advanced(default_before, default_after, Ordinary);
    }
}

#[tokio::test]
async fn fixture_v2_inventory_class_cancellation_and_deadline_release_priority() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .expect("start inventory deadline fixture");
    let journal = fixture.open_recovery_journal().expect("owned journal");
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("fixture clients"),
        )
        .await
        .expect("activate exact voters");
    let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
        activated,
        CountingProvider::new(),
        "fixture-inventory-deadline",
        Arc::clone(&journal),
    )
    .expect("compose facade");
    for class in CLASSES {
        let running = journal.hold_operation_for_test().await.expect("hold gate");
        let before = admissions(&journal);
        let mut cancelled = Box::pin(facade.retained_fenced_transitions_with_journal_class(class));
        assert!(futures_util::poll!(&mut cancelled).is_pending());
        drop(cancelled);
        let mut expired = Box::pin(facade.retained_fenced_transitions_with_journal_class(class));
        assert!(futures_util::poll!(&mut expired).is_pending());
        tokio::time::pause();
        // Keep the existing default consumer window, including its boundary.
        tokio::time::advance(Duration::from_secs(10)).await;
        let result = futures_util::poll!(&mut expired);
        drop(expired);
        tokio::time::resume();
        assert!(matches!(
            result,
            std::task::Poll::Ready(Err(StoreError::BackendUnavailable(_)))
        ));
        assert_eq!(admissions(&journal), before);
        drop(running);

        let before = admissions(&journal);
        assert_eq!(
            facade
                .retained_fenced_transitions_with_journal_class(class)
                .await
                .expect("a later classified inventory call can retry"),
            0
        );
        assert_only_class_advanced(before, admissions(&journal), class);
        let before = admissions(&journal);
        assert_eq!(
            facade
                .retained_fenced_transitions()
                .await
                .expect("cancelled and expired calls leave no priority registration"),
            0
        );
        assert_only_class_advanced(before, admissions(&journal), Ordinary);
    }
    assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
    drop(facade);
    drop(journal);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test]
async fn fixture_v2_urgent_journal_class_reaches_prepare_recovery_and_handles() {
    for remote in [false, true] {
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
                .await
                .expect("start owned-journal fixture");
        let journal = fixture.open_recovery_journal().expect("owned journal");
        let activated =
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
                fixture.persistent_clients().expect("fixture clients"),
            )
            .await
            .expect("activate exact voters");
        let facade = if remote {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_remote_sealing(
                activated,
                Arc::new(MemoryRemoteSealProvider::new(
                    KeyId::new("fixture-journal-priority").expect("key ID"),
                    KeyPurpose::Session,
                    tenant(),
                    Zeroizing::new([0x6e; AES_256_GCM_SIV_KEY_LEN]),
                )),
                "fixture-journal-priority",
                Arc::clone(&journal),
            )
        } else {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
                activated,
                CountingProvider::new(),
                "fixture-journal-priority",
                Arc::clone(&journal),
            )
        }
        .expect("compose facade");
        let deadline = soon();
        let original_budget = budget(deadline);
        let request = create(request_id(70), 70, PAYLOAD);
        let running = journal.hold_operation_for_test().await.expect("hold gate");
        let before = admissions(&journal);
        let mut ordinary =
            Box::pin(facade.recover_fenced_transition_status(request_id(71), original_budget));
        assert!(futures_util::poll!(&mut ordinary).is_pending());
        let mut urgent = Box::pin(facade.prepare_fenced_transition_with_journal_class(
            request.clone(),
            original_budget,
            Urgent,
        ));
        assert!(futures_util::poll!(&mut urgent).is_pending());
        assert_eq!(admissions(&journal), before);
        drop(running);
        // Keep the earlier ordinary future parked. Any accidental ordinary
        // admission in the urgent preparation would wait behind it and expire.
        let mut prepared = urgent
            .await
            .expect("urgent preparation overtakes queued lookup");
        assert_only_class_advanced(before, admissions(&journal), Urgent);
        assert_eq!(prepared.request_id(), request.request_id());

        let before = admissions(&journal);
        assert!(ordinary.await.expect("default ordinary lookup").is_none());
        assert_only_class_advanced(before, admissions(&journal), Ordinary);

        let before = admissions(&journal);
        committed_v2(&mut prepared, &request, deadline).await;
        assert_only_class_advanced(before, admissions(&journal), Urgent);

        let before = admissions(&journal);
        let mut recovered = recovered_v2(
            facade
                .recover_fenced_transition_status_with_journal_class(
                    request.request_id(),
                    original_budget,
                    Urgent,
                )
                .await
                .expect("urgent receipt-only recovery"),
        );
        assert_only_class_advanced(before, admissions(&journal), Urgent);
        let before = admissions(&journal);
        assert!(matches!(
            recovered.status_until_terminal(deadline).await.expect("exact receipt"),
            FencedTransitionV2Status::Recorded(result) if result.is_ok()
        ));
        assert_only_class_advanced(before, admissions(&journal), Urgent);
        let before = admissions(&journal);
        recovered
            .release_resolved()
            .await
            .expect("exact resolved removal");
        assert_only_class_advanced(before, admissions(&journal), Urgent);

        let before = admissions(&journal);
        let mut default = facade
            .prepare_fenced_transition(create(request_id(72), 72, PAYLOAD), budget(soon()))
            .await
            .expect("unchanged default prepare");
        default
            .abandon_unexecuted()
            .await
            .expect("default handle removal");
        assert_only_class_advanced(before, admissions(&journal), Ordinary);
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 1);
        drop(default);
        drop(recovered);
        drop(prepared);
        drop(facade);
        drop(journal);
        fixture.shutdown().await.expect("shut down fixture");
    }
}

#[tokio::test]
async fn fixture_v2_cancelled_journal_class_waiters_preserve_absence_and_deadlines() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .expect("start owned-journal fixture");
    let journal = fixture.open_recovery_journal().expect("owned journal");
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("clients"),
        )
        .await
        .expect("activate exact voters");
    let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
        activated,
        CountingProvider::new(),
        "fixture-cancelled-journal-class",
        Arc::clone(&journal),
    )
    .expect("facade");
    for class in CLASSES {
        let running = journal.hold_operation_for_test().await.expect("hold gate");
        let before = admissions(&journal);
        let deadline = soon();
        let original_budget = budget(deadline);
        let mut cancelled = Box::pin(facade.prepare_fenced_transition_with_journal_class(
            create(request_id(73), 73, PAYLOAD),
            original_budget,
            class,
        ));
        assert!(futures_util::poll!(&mut cancelled).is_pending());
        drop(cancelled);
        let mut expired_lookup =
            Box::pin(facade.recover_fenced_transition_status_with_journal_class(
                request_id(73),
                original_budget,
                class,
            ));
        assert!(futures_util::poll!(&mut expired_lookup).is_pending());
        // Expire only the request clock; the immutable caller budget still
        // bounds a waiter that never reaches blocking work.
        tokio::time::pause();
        tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
        assert!(matches!(
            expired_lookup.await,
            Err(StoreError::BackendUnavailable(_))
        ));
        tokio::time::resume();
        assert_eq!(admissions(&journal), before);
        drop(running);
        assert!(facade
            .recover_fenced_transition_status_with_journal_class(
                request_id(73),
                budget(soon()),
                class,
            )
            .await
            .expect("cancelled preparation leaves no row")
            .is_none());
    }
    assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
    drop(facade);
    drop(journal);
    fixture.shutdown().await.expect("shut down fixture");
}

struct PausedPreparationProvider {
    inner: Arc<CountingProvider>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl KeyProvider for PausedPreparationProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.inner.rotate_key(purpose, tenant).await
    }
}

#[tokio::test]
async fn fixture_v2_urgent_call_excludes_ordinary_between_journal_steps_and_releases_on_cancel() {
    for cancel in [false, true] {
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
                .await
                .expect("start fixture");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let journal = Arc::new(
            fixture
                .open_recovery_journal()
                .expect("owned journal")
                .with_preparation_pause_for_test(Arc::clone(&entered), Arc::clone(&release)),
        );
        let activated =
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
                fixture.persistent_clients().expect("clients"),
            )
            .await
            .expect("activate voters");
        let provider = CountingProvider::new();
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
            activated,
            Arc::clone(&provider),
            "fixture-call-priority",
            Arc::clone(&journal),
        )
        .expect("facade");
        let running = journal.hold_operation_for_test().await.expect("hold gate");
        let mut earlier_ordinary = Box::pin(journal.hold_operation_for_test());
        assert!(futures_util::poll!(&mut earlier_ordinary).is_pending());
        let mut urgent = Box::pin(facade.prepare_fenced_transition_with_journal_class(
            create(request_id(74), 74, PAYLOAD),
            budget(soon()),
            Urgent,
        ));
        assert!(futures_util::poll!(&mut urgent).is_pending());
        drop(running);
        tokio::select! {
            result = &mut urgent => panic!("preparation must reach the local journal cut: {result:?}"),
            () = entered.notified() => {},
        }
        // Scope binding and caller registration have finished. The absent-row
        // check has not begun; actively poll both an earlier and a newly
        // arriving ordinary caller between these consecutive local steps.
        let before = admissions(&journal);
        let mut later_ordinary = Box::pin(journal.hold_operation_for_test());
        assert!(futures_util::poll!(&mut later_ordinary).is_pending());
        assert!(
            futures_util::poll!(&mut earlier_ordinary).is_pending(),
            "an urgent consumer call retains priority between its journal steps"
        );
        assert_eq!(admissions(&journal), before);
        let prepared = if cancel {
            drop(urgent);
            None
        } else {
            release.notify_one();
            Some(urgent.await.expect("finish urgent preparation"))
        };
        drop(earlier_ordinary.await.expect("earlier ordinary resumes"));
        drop(later_ordinary.await.expect("later ordinary resumes"));
        if let Some(mut prepared) = prepared {
            prepared.abandon_unexecuted().await.expect("remove row");
        }
        assert_eq!(
            facade.retained_fenced_transitions().await.expect("count"),
            0
        );
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
        drop(facade);
        drop(journal);
        fixture.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn fixture_v2_sealing_releases_priority_and_expiry_prevents_journal_reentry() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .expect("start fixture");
    let journal = fixture.open_recovery_journal().expect("owned journal");
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("clients"),
        )
        .await
        .expect("activate voters");
    let provider = Arc::new(PausedPreparationProvider {
        inner: CountingProvider::new(),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
        activated,
        Arc::clone(&provider),
        "fixture-sealing-priority",
        Arc::clone(&journal),
    )
    .expect("facade");
    let deadline = soon();
    let mut preparing = Box::pin(facade.prepare_fenced_transition_with_journal_class(
        create(request_id(94), 94, PAYLOAD),
        budget(deadline),
        Urgent,
    ));
    tokio::select! {
        result = &mut preparing => panic!("preparation must reach sealing: {result:?}"),
        () = provider.entered.notified() => {},
    }
    let mut ordinary = Box::pin(journal.hold_operation_for_test());
    assert!(
        matches!(
            futures_util::poll!(&mut ordinary),
            std::task::Poll::Ready(Ok(_))
        ),
        "provider I/O must not retain local journal priority"
    );
    let before = admissions(&journal);
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
    provider.release.notify_one();
    let result = futures_util::poll!(&mut preparing);
    assert!(matches!(
        result,
        std::task::Poll::Ready(Err(StoreError::BackendUnavailable(_)))
    ));
    assert_eq!(
        admissions(&journal),
        before,
        "expiry prevents the final insert even when sealing is ready"
    );
    drop(preparing);
    drop(ordinary);
    tokio::time::resume();
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        0
    );
    assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
    drop(facade);
    drop(journal);
    fixture.shutdown().await.expect("shutdown");
}

async fn classified_observation_or_reclamation(
    facade: &SessionConsumerPreparedFencedTransitionV2Backend,
    class: ScopeWorkClass,
    reclaim: bool,
    deadline: tokio::time::Instant,
) -> Result<(), StoreError> {
    if reclaim {
        let report = facade
            .reclaim_resolved_fenced_transitions_with_journal_class(1, budget(deadline), class)
            .await?;
        assert_eq!(report.reclaimed(), 0);
        assert_eq!(report.examined(), 0);
    } else {
        let observed = facade
            .observe_fenced_transition_with_journal_class(&session_key(95), class)
            .await?;
        assert!(observed.record().is_none());
    }
    Ok(())
}

#[tokio::test]
async fn fixture_v2_observation_and_reclamation_classes_cancellation_and_deadlines() {
    for remote in [false, true] {
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
                .await
                .expect("start fixture");
        let journal = fixture.open_recovery_journal().expect("owned journal");
        let activated = SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("clients"),
        ).await.expect("activate voters");
        let facade = if remote {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_remote_sealing(
                activated,
                Arc::new(MemoryRemoteSealProvider::new(
                    KeyId::new("fixture-classified-reads").expect("key ID"),
                    KeyPurpose::Session,
                    tenant(),
                    Zeroizing::new([0x6d; AES_256_GCM_SIV_KEY_LEN]),
                )),
                "fixture-classified-reads",
                Arc::clone(&journal),
            )
        } else {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
                activated,
                CountingProvider::new(),
                "fixture-classified-reads",
                Arc::clone(&journal),
            )
        }
        .expect("facade");
        for class in CLASSES {
            for reclaim in [false, true] {
                let running = journal.hold_operation_for_test().await.expect("hold gate");
                let before = admissions(&journal);
                let mut cancelled = Box::pin(classified_observation_or_reclamation(
                    &facade,
                    class,
                    reclaim,
                    soon(),
                ));
                assert!(futures_util::poll!(&mut cancelled).is_pending());
                drop(cancelled);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                let mut expired = Box::pin(classified_observation_or_reclamation(
                    &facade, class, reclaim, deadline,
                ));
                assert!(futures_util::poll!(&mut expired).is_pending());
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(10)).await;
                let result = futures_util::poll!(&mut expired);
                assert!(matches!(
                    result,
                    std::task::Poll::Ready(Err(StoreError::BackendUnavailable(_)))
                ));
                assert_eq!(admissions(&journal), before);
                drop(expired);
                drop(running);
                tokio::time::resume();
                let before = admissions(&journal);
                classified_observation_or_reclamation(&facade, class, reclaim, soon())
                    .await
                    .expect("classified read");
                assert_only_class_advanced(before, admissions(&journal), class);
                let before = admissions(&journal);
                assert!(facade
                    .observe_fenced_transition(&session_key(95))
                    .await
                    .expect("default observe")
                    .record()
                    .is_none());
                assert_eq!(
                    facade
                        .reclaim_resolved_fenced_transitions(1, budget(soon()))
                        .await
                        .expect("default reclaim")
                        .reclaimed(),
                    0
                );
                assert_only_class_advanced(before, admissions(&journal), Ordinary);
            }
        }
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
        drop(facade);
        drop(journal);
        fixture.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn fixture_v2_journal_view_class_is_the_default_for_consumer_calls() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .expect("start fixture");
    let journal = fixture.open_recovery_journal().expect("owned journal");
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("clients"),
        )
        .await
        .expect("activate voters");
    let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
        activated,
        CountingProvider::new(),
        "fixture-default-journal-class",
        Arc::new(journal.with_operation_class(Urgent)),
    )
    .expect("facade");
    let before = admissions(&journal);
    let mut prepared = facade
        .prepare_fenced_transition(create(request_id(75), 75, PAYLOAD), budget(soon()))
        .await
        .expect("prepare through urgent view");
    assert_only_class_advanced(before, admissions(&journal), Urgent);
    let before = admissions(&journal);
    let recovered = facade
        .recover_fenced_transition_status(request_id(75), budget(soon()))
        .await
        .expect("recover through urgent view");
    assert!(recovered.is_some());
    assert_only_class_advanced(before, admissions(&journal), Urgent);
    let before = admissions(&journal);
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        1
    );
    assert_only_class_advanced(before, admissions(&journal), Urgent);
    prepared.abandon_unexecuted().await.expect("remove row");
    drop(recovered);
    drop(prepared);
    drop(facade);
    drop(journal);
    fixture.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn fixture_v2_every_journal_class_reaches_both_sealers_and_retained_handles() {
    for remote in [false, true] {
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
                .await
                .expect("start fixture");
        let journal = fixture.open_recovery_journal().expect("owned journal");
        let activated =
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
                fixture.persistent_clients().expect("clients"),
            ).await.expect("activate voters");
        let facade = if remote {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_remote_sealing(
                activated,
                Arc::new(MemoryRemoteSealProvider::new(
                    KeyId::new("fixture-ranked-journal").expect("key ID"),
                    KeyPurpose::Session,
                    tenant(),
                    Zeroizing::new([0x6f; AES_256_GCM_SIV_KEY_LEN]),
                )),
                "fixture-ranked-journal",
                Arc::clone(&journal),
            )
        } else {
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
                activated,
                CountingProvider::new(),
                "fixture-ranked-journal",
                Arc::clone(&journal),
            )
        }
        .expect("facade");
        for (ordinal, class) in CLASSES.into_iter().enumerate() {
            let request = create(
                request_id(80 + ordinal as u64),
                80 + ordinal as u64,
                PAYLOAD,
            );
            let deadline = soon();
            let before = admissions(&journal);
            let mut prepared = facade
                .prepare_fenced_transition_with_journal_class(
                    request.clone(),
                    budget(deadline),
                    class,
                )
                .await
                .expect("classified preparation");
            assert_only_class_advanced(before, admissions(&journal), class);
            let before = admissions(&journal);
            committed_v2(&mut prepared, &request, deadline).await;
            assert_only_class_advanced(before, admissions(&journal), class);
            let before = admissions(&journal);
            let mut recovered = recovered_v2(
                facade
                    .recover_fenced_transition_status_with_journal_class(
                        request.request_id(),
                        budget(deadline),
                        class,
                    )
                    .await
                    .expect("classified recovery"),
            );
            assert!(
                matches!(recovered.status_until_terminal(deadline).await.expect("receipt"),
                FencedTransitionV2Status::Recorded(result) if result.is_ok())
            );
            recovered
                .release_resolved()
                .await
                .expect("release resolved row");
            assert_only_class_advanced(before, admissions(&journal), class);
        }
        assert_eq!(
            fixture.diagnostics().fenced_transition_v2_calls(),
            CLASSES.len()
        );
        drop(facade);
        drop(journal);
        fixture.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn fixture_v2_standalone_journal_reads_are_bounded_under_higher_priority_contention() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .expect("start fixture");
    let journal = fixture.open_recovery_journal().expect("owned journal");
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("clients"),
        )
        .await
        .expect("activate voters");
    let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
        activated,
        CountingProvider::new(),
        "fixture-bounded-journal-reads",
        Arc::clone(&journal),
    )
    .expect("facade");
    for observe in [false, true] {
        let urgent = journal.with_operation_class(Urgent);
        let held = urgent
            .hold_operation_for_test()
            .await
            .expect("hold urgent operation");
        let before = admissions(&journal);
        let key = session_key(91);
        let mut read = Box::pin(async {
            if observe {
                facade.observe_fenced_transition(&key).await.map(|_| ())
            } else {
                facade.retained_fenced_transitions().await.map(|_| ())
            }
        });
        assert!(futures_util::poll!(&mut read).is_pending());
        tokio::time::pause();
        // The existing default consumer window is ten seconds.
        tokio::time::advance(Duration::from_secs(10)).await;
        let result = futures_util::poll!(&mut read);
        drop(read);
        tokio::time::resume();
        assert!(matches!(
            result,
            std::task::Poll::Ready(Err(StoreError::BackendUnavailable(_)))
        ));
        assert_eq!(admissions(&journal), before);
        drop(held);
    }
    assert_eq!(
        facade
            .retained_fenced_transitions()
            .await
            .expect("later read can retry"),
        0
    );
    assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
    drop(facade);
    drop(journal);
    fixture.shutdown().await.expect("shutdown");
}
