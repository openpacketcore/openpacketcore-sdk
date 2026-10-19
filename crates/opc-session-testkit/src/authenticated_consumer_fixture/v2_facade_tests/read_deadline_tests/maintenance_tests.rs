//! Maintenance has bounded per-voter waits; it does not inherit ingress D.

use super::*;

#[tokio::test]
async fn silent_follower_does_not_stop_successive_reclaim_sweeps() {
    let fixture =
        AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable_with_void([scope()])
            .await
            .unwrap();
    let fixture = with_fixture_protocol_clock("silent follower reclamation", async move {
        let clients = clients(&fixture);
        let facade = facade(&fixture, &clients).await;
        let leader = fixture.cluster.store(0).status().leader_id.unwrap();
        let silent = fixture
            .voters
            .iter()
            .position(|voter| voter.authority.node_id() != leader)
            .unwrap();
        let service = &fixture.voters[silent].service;
        service
            .stall_fenced_transition_v2_history_state
            .store(true, Ordering::Release);
        service
            .stall_fenced_transition_v2_status
            .store(true, Ordering::Release);
        let mut total_stalls = 0;
        for pass in 0..2 {
            for row in 0..4 {
                let label = 1700 + pass * 10 + row;
                let prepared = facade
                    .prepare_fenced_transition(
                        create(request_id(label), label, PAYLOAD),
                        read_budget(),
                    )
                    .await
                    .unwrap();
                // Dropping an unexecuted, owned row makes it eligible for the
                // sweep's separately admitted exact void operation.
                drop(prepared);
            }
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 4);
            let budget = read_budget();
            let report = {
                let sweep = facade.reclaim_resolved_fenced_transitions(16, budget);
                tokio::pin!(sweep);
                loop {
                    tokio::select! {
                        result = &mut sweep => break result.unwrap(),
                        () = service.fenced_transition_v2_history_state_stalled.notified() => {},
                        () = service.fenced_transition_v2_status_stalled.notified() => {},
                    }
                    total_stalls += 1;
                    tokio::time::advance(budget.physical_attempt_timeout() - FIXTURE_TIMER_TICK)
                        .await;
                    assert!(futures_util::poll!(&mut sweep).is_pending());
                    tokio::time::advance(FIXTURE_TIMER_TICK * 2).await;
                }
            };
            assert!(!report.interrupted(), "pass {pass}: {report:?}");
            assert_eq!(report.examined(), 4);
            assert_eq!(report.reclaimed(), 4);
            assert_eq!(report.retained(), 0);
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
            assert!(tokio::time::Instant::now() < budget.original_deadline());
            assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
        }
        assert!(total_stalls >= 2, "each sweep reached the silent follower");
        drop(facade);
        for client in clients {
            client.shutdown().await;
        }
        fixture
    })
    .await;
    fixture.shutdown().await.unwrap();
}

#[tokio::test]
async fn activation_priming_uses_the_configured_operation_timeout() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .unwrap();
    let fixture = with_fixture_protocol_clock("bounded activation history prime", async move {
        let clients = clients(&fixture);
        let service = &fixture.voters[0].service;
        service
            .stall_fenced_transition_v2_history_state
            .store(true, Ordering::Release);
        let started = tokio::time::Instant::now();
        let activation =
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
                clients.clone(),
            );
        tokio::pin!(activation);
        tokio::select! {
            result = &mut activation => panic!("prime must reach the silent voter: {result:?}"),
            () = service.fenced_transition_v2_history_state_stalled.notified() => {},
        }
        tokio::time::advance(Duration::from_millis(249)).await;
        assert!(futures_util::poll!(&mut activation).is_pending());
        tokio::time::advance(Duration::from_millis(2)).await;
        activation.await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(251));
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
        for client in clients {
            client.shutdown().await;
        }
        fixture
    })
    .await;
    fixture.shutdown().await.unwrap();
}
