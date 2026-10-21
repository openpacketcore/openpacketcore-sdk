//! A committed-response observation must precede client deadline advancement.

use super::*;
use futures_util::FutureExt;

#[tokio::test]
async fn committed_reply_suppressed_event_drives_original_deadline_without_replay() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let (fixture, result) = with_fixture_protocol_clock("V2 committed response-loss event", async move {
        let result = std::panic::AssertUnwindSafe(async {
            let facade = fixture
                .open_local_aead_v2(CountingProvider::new(), "fixture-v2-loss-event")
                .await
                .expect("open protected V2 facade");
            let mut events = fixture.subscribe_fenced_transition_v2_response_suppressed();
            let mut late_polled = fixture.subscribe_fenced_transition_v2_response_suppressed();

            // An ordinary successful commit must not announce response loss.
            let ordinary = create(request_id(0x6000), 0x6000, PAYLOAD);
            let mut prepared = facade
                .prepare_fenced_transition(ordinary.clone(), budget(soon()))
                .await
                .expect("prepare ordinary transition");
            let outcome = prepared.execute_once().await.expect("ordinary commit");
            assert!(outcome.matches_request(&ordinary));
            assert_eq!(events.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Empty));
            prepared.release_resolved().await.expect("release ordinary receipt");
            drop(prepared);

            // Reuse the subscription across two separately armed real commits.
            for ordinal in 1..=2 {
                let label = 0x6000 + ordinal;
                let id = request_id(label);
                let request = create(id, label, PAYLOAD);
                let started = tokio::time::Instant::now();
                let deadline = soon();
                let attempt_timeout = budget(deadline).physical_attempt_timeout();
                let mut prepared = facade
                    .prepare_fenced_transition(request.clone(), budget(deadline))
                    .await
                    .expect("prepare response-loss transition");
                fixture.lose_next_fenced_transition_v2_response();
                {
                    let execution = prepared.execute_once();
                    tokio::pin!(execution);
                    tokio::select! {
                        result = &mut execution => panic!("suppressed reply completed before its deadline: {result:?}"),
                        event = events.recv() => event.expect("observe real committed response suppression"),
                    }
                    assert_eq!(tokio::time::Instant::now() - started, Duration::ZERO);
                    assert_eq!(late_polled.try_recv(), Ok(()), "a subscriber need not be polled before emission");
                    assert_eq!(events.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Empty));
                    let mut new_subscriber = fixture.subscribe_fenced_transition_v2_response_suppressed();
                    assert_eq!(new_subscriber.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Empty));

                    let observed = facade.observe_fenced_transition(&session_key(label)).await.expect("authoritative readback at notification");
                    assert_eq!(observed.record().expect("commit precedes event").payload.as_bytes(), PAYLOAD);
                    tokio::time::advance(attempt_timeout - FIXTURE_TIMER_TICK).await;
                    assert!(futures_util::poll!(&mut execution).is_pending(), "the original physical deadline still applies");
                    tokio::time::advance(FIXTURE_TIMER_TICK * 2).await;
                    assert_eq!(execution.await, Err(FencedTransitionExecuteError::OutcomeUnknown { request_id: id }));
                }
                let status = prepared.status_until_terminal(deadline).await.expect("recover exact receipt");
                assert!(matches!(status, FencedTransitionV2Status::Recorded(result) if matches!(&*result, Ok(outcome) if outcome.matches_request(&request))));
                assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), ordinal as usize + 1, "receipt recovery never replays a mutation");
                assert_eq!(tokio::time::Instant::now() - started, attempt_timeout + FIXTURE_TIMER_TICK);
                prepared.release_resolved().await.expect("release recovered receipt");
            }
            assert_eq!(fixture.diagnostics().fenced_transition_calls(), 0);
            assert_eq!(fixture.diagnostics().general_mutation_calls(), 0);
        }).catch_unwind().await;
        (fixture, result)
    }).await;
    fixture.shutdown().await.expect("shut down fixture");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
