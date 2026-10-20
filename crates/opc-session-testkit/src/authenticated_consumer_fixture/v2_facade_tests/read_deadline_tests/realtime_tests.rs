//! One required heavy-shard check retains the real-time read boundary.

use super::*;

#[tokio::test]
async fn caller_deadline_accepts_in_time_and_rejects_late_valid_replies() {
    // Fixed qualification margins, not a product latency claim:
    // - A real successful reply is held for 500 ms under the original 1 s
    //   caller budget. At release it must still have at least 200 ms left.
    //   This crosses both the 100 ms physical and 250 ms legacy read caps.
    // - The second real reply is held for 700 ms under the existing 400 ms
    //   earlier caller deadline, so release is at least 300 ms too late.
    // Keep these margins fixed. A host that misses them fails this heavy
    // check; do not widen them or infer product timing from a passing run.
    for (hold_ms, caller_ms, accepted) in [(500, 1_000, true), (700, 400, false)] {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let clients = clients(&fixture);
        clients[0].prewarm().await.unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *fixture.voters[0].service.reply_gates[GET].lock().unwrap() = Some(Arc::clone(&gate));
        hold(&fixture, GET, hold_ms);
        let budget = PreparedCheckpointBudget::new(
            tokio::time::Instant::now() + Duration::from_millis(caller_ms),
            Duration::from_millis(100),
        )
        .unwrap();
        let result = {
            let read = clients[0].get_with_budget(session_key(1_950), budget);
            tokio::pin!(read);
            tokio::select! {
                result = &mut read => panic!("read completed before a valid reply was held: {result:?}"),
                () = fixture.voters[0].service.held_reply_started[GET].notified() => {},
            }
            tokio::time::sleep(Duration::from_millis(hold_ms)).await;
            let released = tokio::time::Instant::now();
            if accepted {
                assert!(
                    released + Duration::from_millis(200) < budget.original_deadline(),
                    "the valid reply must arrive with the fixed 200 ms margin"
                );
            } else {
                assert!(released >= budget.original_deadline() + Duration::from_millis(300));
            }
            gate.add_permits(1);
            read.await
        };
        if accepted {
            assert!(matches!(result, Ok(None)));
            assert!(tokio::time::Instant::now() < budget.original_deadline());
        } else {
            assert!(
                result.is_err(),
                "a late valid reply cannot establish authority"
            );
        }
        assert_eq!(held(&fixture, GET), 1, "one physical read, without replay");
        assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 0);
        close(fixture, clients).await;
    }
}
