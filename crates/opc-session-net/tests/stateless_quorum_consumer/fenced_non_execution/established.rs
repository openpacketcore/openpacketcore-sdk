use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_non_execution_established_release_refuses_second_readback_before_fence() {
    let installs = Arc::new(AtomicUsize::new(0));
    let backend = LinuxXfrmBackend::with_instrumented_transport({
        let installs = Arc::clone(&installs);
        move |operation, _| match operation {
            "query_policy" => Err(opc_ipsec_xfrm::XfrmError::NotFound),
            "install_policy" => {
                installs.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            _ => panic!("settlement cannot delete established objects"),
        }
    });
    let mut fixture =
        SettlementFixture::start_with_execution(false, 2, backend, SettlementExecution::Conclusive)
            .await;
    let mut active = match fixture.client.admit(&mut fixture.input).await.unwrap() {
        AdmissionOutcome::Admitted(active) => active,
        _ => panic!("deliver the original admission"),
    };
    let mut second = fixture.readback().await;
    let mut proofs = Vec::new();
    for ordinal in 0..2 {
        let mut member = active.member(MemberOrdinal::new(ordinal).unwrap()).unwrap();
        assert!(matches!(
            fixture.client.prepare_member(&mut member).await.unwrap(),
            MemberPrepareOutcome::Prepared
        ));
        match fixture.client.execute(&mut member).await.unwrap() {
            ExecuteOutcome::Conclusive(proof) => proofs.push(*proof),
            _ => panic!("real actor execution must produce Applied evidence"),
        }
        let retained = &fixture.provider.members[usize::from(ordinal)];
        assert_eq!(
            fixture
                .provider
                .actor
                .finalize_durable_object_roster(
                    &fixture.provider.store,
                    retained.group,
                    XfrmSettlementProvider::generation(),
                    &retained.roster,
                )
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }
    let proofs = CompleteProofSet::new(proofs).unwrap();
    let mut terminal = fixture
        .client
        .prepare_terminal(active.for_terminal(), &proofs)
        .await
        .unwrap();
    assert!(matches!(
        fixture.client.terminalize(&mut terminal).await.unwrap(),
        TerminalizationOutcome::OutcomeUnknown
    ));
    let receipt = match fixture.client.terminal_status(&mut terminal).await.unwrap() {
        TerminalStatus::Committed(TerminalReceipt::Established(receipt)) => receipt,
        _ => panic!("read back the committed Established receipt"),
    };
    for retained in &fixture.provider.members {
        assert_eq!(
            receipt.settled_member_binding(MemberOrdinal::new(retained.member.ordinal()).unwrap()),
            fixture
                .provider
                .bindings
                .lock()
                .unwrap()
                .get(&retained.member.ordinal())
                .copied()
        );
        fixture
            .provider
            .actor
            .release_durable_object_roster_settlement(
                &fixture.provider.store,
                retained.group,
                XfrmSettlementProvider::generation(),
                &retained.roster,
            )
            .await
            .unwrap();
        assert!(
            fixture
                .provider
                .actor
                .prepare_durable_object_roster(
                    &fixture.provider.store,
                    retained.group,
                    XfrmSettlementProvider::generation(),
                    retained.roster.clone(),
                )
                .await
                .is_err(),
            "the Established receipt cannot reopen late preparation"
        );
    }
    // An unrelated publication physically removes the released durable rows.
    let unrelated = XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(
        fixture.provider.members[0]
            .roster
            .member(0)
            .unwrap()
            .request()
            .clone(),
    )])
    .unwrap();
    drop(
        fixture
            .provider
            .actor
            .prepare_durable_object_roster(
                &fixture.provider.store,
                XfrmObjectRosterGroupId::from_bytes([0xFA; 16]).unwrap(),
                XfrmSettlementProvider::generation(),
                unrelated,
            )
            .await
            .unwrap(),
    );
    assert!(
        matches!(
            fixture
                .client
                .admission_status(&fixture.input)
                .await
                .unwrap(),
            RecoveryOutcome::Terminal(TerminalReceipt::Established(_))
        ),
        "readback after release returns only the terminal receipt"
    );
    let before = fixture.provider.observations.lock().unwrap().len();
    let mut negative_proofs = 0;
    for ordinal in 0..2 {
        let mut member = second.member(MemberOrdinal::new(ordinal).unwrap()).unwrap();
        if matches!(
            fixture.client.reconcile(&mut member).await,
            Ok(MemberRecoveryOutcome::Conclusive(_))
        ) {
            negative_proofs += 1;
        }
    }
    let fences = fixture.provider.observations.lock().unwrap().len() - before;
    let dispatches = fixture.provider.reconciliations.load(Ordering::SeqCst);
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    assert_eq!(
        negative_proofs, 0,
        "released Applied members must never become never-started evidence"
    );
    assert_eq!((dispatches, fences), (0, 0), "every readback registration must be refused before provider fence dispatch after Established release");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_non_execution_established_release_discards_reconcile_held_before_fence() {
    let installs = Arc::new(AtomicUsize::new(0));
    let backend = LinuxXfrmBackend::with_instrumented_transport({
        let installs = Arc::clone(&installs);
        move |operation, _| match operation {
            "query_policy" => Err(opc_ipsec_xfrm::XfrmError::NotFound),
            "install_policy" => {
                installs.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            _ => panic!("settlement cannot delete established objects"),
        }
    });
    let mut fixture =
        SettlementFixture::start_with_execution(false, 2, backend, SettlementExecution::Conclusive)
            .await;
    let mut active = match fixture.client.admit(&mut fixture.input).await.unwrap() {
        AdmissionOutcome::Admitted(active) => active,
        _ => panic!("deliver the original admission"),
    };
    let mut second = fixture.readback().await;
    let mut proofs = Vec::new();
    for ordinal in 0..2 {
        let mut member = active.member(MemberOrdinal::new(ordinal).unwrap()).unwrap();
        assert!(matches!(
            fixture.client.prepare_member(&mut member).await.unwrap(),
            MemberPrepareOutcome::Prepared
        ));
        match fixture.client.execute(&mut member).await.unwrap() {
            ExecuteOutcome::Conclusive(proof) => proofs.push(*proof),
            _ => panic!("real actor execution must produce Applied evidence"),
        }
        let retained = &fixture.provider.members[usize::from(ordinal)];
        assert_eq!(
            fixture
                .provider
                .actor
                .finalize_durable_object_roster(
                    &fixture.provider.store,
                    retained.group,
                    XfrmSettlementProvider::generation(),
                    &retained.roster,
                )
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }
    let gate = Arc::new(SettlementObserveGate::default());
    *fixture.provider.reconcile_gate.lock().unwrap() = Some(Arc::clone(&gate));
    assert_eq!(second.retained_member_proof_count_for_test().unwrap(), 0);
    let mut held_member = second.member(MemberOrdinal::new(0).unwrap()).unwrap();
    let pending = tokio::spawn({
        let client = fixture.client.clone();
        async move { client.reconcile(&mut held_member).await }
    });
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .expect("reconcile reaches the one-shot provider gate before fence");
    let proofs = CompleteProofSet::new(proofs).unwrap();
    let mut terminal = fixture
        .client
        .prepare_terminal(active.for_terminal(), &proofs)
        .await
        .unwrap();
    assert!(matches!(
        fixture.client.terminalize(&mut terminal).await.unwrap(),
        TerminalizationOutcome::OutcomeUnknown
    ));
    let receipt = match fixture.client.terminal_status(&mut terminal).await.unwrap() {
        TerminalStatus::Committed(TerminalReceipt::Established(receipt)) => receipt,
        _ => panic!("read back the committed Established receipt"),
    };
    for retained in &fixture.provider.members {
        assert_eq!(
            receipt.settled_member_binding(MemberOrdinal::new(retained.member.ordinal()).unwrap()),
            fixture
                .provider
                .bindings
                .lock()
                .unwrap()
                .get(&retained.member.ordinal())
                .copied()
        );
        fixture
            .provider
            .actor
            .release_durable_object_roster_settlement(
                &fixture.provider.store,
                retained.group,
                XfrmSettlementProvider::generation(),
                &retained.roster,
            )
            .await
            .unwrap();
        assert!(
            fixture
                .provider
                .actor
                .prepare_durable_object_roster(
                    &fixture.provider.store,
                    retained.group,
                    XfrmSettlementProvider::generation(),
                    retained.roster.clone(),
                )
                .await
                .is_err(),
            "the Established receipt cannot reopen late preparation"
        );
    }
    // An unrelated publication physically removes the released durable rows.
    let unrelated = XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(
        fixture.provider.members[0]
            .roster
            .member(0)
            .unwrap()
            .request()
            .clone(),
    )])
    .unwrap();
    drop(
        fixture
            .provider
            .actor
            .prepare_durable_object_roster(
                &fixture.provider.store,
                XfrmObjectRosterGroupId::from_bytes([0xFA; 16]).unwrap(),
                XfrmSettlementProvider::generation(),
                unrelated,
            )
            .await
            .unwrap(),
    );
    assert!(
        matches!(
            fixture
                .client
                .admission_status(&fixture.input)
                .await
                .unwrap(),
            RecoveryOutcome::Terminal(TerminalReceipt::Established(_))
        ),
        "readback after release returns only the terminal receipt"
    );
    gate.release.notify_one();
    let held_result = pending.await.unwrap();
    assert!(
        !matches!(held_result, Ok(MemberRecoveryOutcome::Conclusive(_))),
        "the signed absence observed after release cannot become a member proof"
    );
    assert_eq!(
        second.retained_member_proof_count_for_test().unwrap(),
        0,
        "terminal invalidation retains no new NotApplied proof"
    );
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    let before = fixture.provider.observations.lock().unwrap().len();
    let mut negative_proofs = 0;
    for ordinal in 1..2 {
        let mut member = second.member(MemberOrdinal::new(ordinal).unwrap()).unwrap();
        if matches!(
            fixture.client.reconcile(&mut member).await,
            Ok(MemberRecoveryOutcome::Conclusive(_))
        ) {
            negative_proofs += 1;
        }
    }
    let fences = fixture.provider.observations.lock().unwrap().len() - before;
    let dispatches = fixture.provider.reconciliations.load(Ordering::SeqCst);
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    assert_eq!(
        negative_proofs, 0,
        "released Applied members must never become never-started evidence"
    );
    assert_eq!(
        (dispatches, fences),
        (1, 0),
        "only the already-accepted reconcile reaches the provider; later readbacks stay refused"
    );
}
