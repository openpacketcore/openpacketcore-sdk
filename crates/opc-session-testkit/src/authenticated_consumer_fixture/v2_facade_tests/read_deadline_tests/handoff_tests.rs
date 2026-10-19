//! Resume the caller only after the V2 actor has published its response.

use super::*;
use futures_util::FutureExt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct CallerWake(tokio::sync::Notify);

impl Wake for CallerWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

fn poll_caller<T>(future: Pin<&mut impl Future<Output = T>>, wake: &Arc<CallerWake>) -> Poll<T> {
    let waker = Waker::from(Arc::clone(wake));
    future.poll(&mut Context::from_waker(&waker))
}

async fn finish_actor_without_resuming_caller<T>(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
    mut caller: Pin<&mut impl Future<Output = T>>,
    gate: &tokio::sync::Semaphore,
    deadline: tokio::time::Instant,
) {
    let wake = Arc::new(CallerWake::default());
    let entered = futures_util::future::select_all(
        fixture
            .voters
            .iter()
            .map(|voter| Box::pin(voter.service.held_reply_started[HISTORY].notified())),
    );
    tokio::pin!(entered);
    loop {
        assert!(
            poll_caller(caller.as_mut(), &wake).is_pending(),
            "the real history response is withheld before the actor can finish"
        );
        if held(fixture, HISTORY) != 0 {
            break;
        }
        tokio::select! {
            () = wake.0.notified() => {},
            _ = &mut entered => break,
        }
    }
    assert_eq!(held(fixture, HISTORY), 1);
    // Clear wakes from earlier journal/setup work, then register the caller
    // only on the actor's completion while its real response is still held.
    while wake.0.notified().now_or_never().is_some() {}
    assert!(poll_caller(caller.as_mut(), &wake).is_pending());
    while wake.0.notified().now_or_never().is_some() {}
    gate.add_permits(1);
    // This wake comes from the actor publishing its oneshot. The caller is
    // deliberately not polled, so it cannot consume that queued response yet.
    wake.0.notified().await;
    assert!(
        tokio::time::Instant::now() < deadline,
        "the authenticated actor completion is available before D"
    );
}

fn gate_history(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
) -> Arc<tokio::sync::Semaphore> {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    for voter in &fixture.voters {
        *voter.service.reply_gates[HISTORY].lock().unwrap() = Some(Arc::clone(&gate));
    }
    gate
}

fn history_calls(fixture: &AuthenticatedPreparedFencedTransitionFixture) -> usize {
    fixture
        .voters
        .iter()
        .map(|voter| {
            voter
                .service
                .fenced_transition_v2_history_state_calls
                .load(Ordering::SeqCst)
        })
        .sum()
}

#[tokio::test]
async fn public_history_discards_actor_completion_delivered_at_or_after_deadline() {
    let mut evidence = Vec::new();
    for late_ms in [0, 1] {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let (fixture, outcome) =
            with_fixture_protocol_clock("public history actor handoff", async move {
                let clients = clients(&fixture);
                clients[0].prewarm_v2().await.unwrap();
                let gate = gate_history(&fixture);
                let budget = read_budget();
                let deadline = budget.original_deadline();
                let mut caller =
                    Box::pin(clients[0].fenced_transition_v2_history_state_with_budget(budget));
                finish_actor_without_resuming_caller(&fixture, caller.as_mut(), &gate, deadline)
                    .await;
                tokio::time::advance(
                    deadline - tokio::time::Instant::now() + Duration::from_millis(late_ms),
                )
                .await;
                let rejected = caller.await.is_err();
                let calls = history_calls(&fixture);
                let mutations = fixture.diagnostics().fenced_transition_v2_calls();
                for client in clients {
                    client.shutdown().await;
                }
                (fixture, (late_ms, rejected, calls, mutations))
            })
            .await;
        fixture.shutdown().await.unwrap();
        evidence.push(outcome);
    }
    eprintln!("history handoff (late_ms, rejected, reads, mutations): {evidence:?}");
    assert!(
        evidence
            .iter()
            .all(|(_, rejected, reads, mutations)| *rejected && *reads == 1 && *mutations == 0),
        "{evidence:?}"
    );
}

#[tokio::test]
async fn protected_history_discards_late_handoff_without_caching_authority() {
    let mut evidence = Vec::new();
    for late_ms in [0, 1] {
        let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
            .await
            .unwrap();
        let (fixture, outcome) =
            with_fixture_protocol_clock("protected history actor handoff", async move {
                for voter in &fixture.voters {
                    voter
                        .service
                        .fail_next_fenced_transition_v2_history_state
                        .store(true, Ordering::Release);
                }
                let clients = clients(&fixture);
                let facade = facade(&fixture, &clients).await;
                let gate = gate_history(&fixture);
                let budget = read_budget();
                let deadline = budget.original_deadline();
                let mut caller = Box::pin(
                    facade
                        .prepare_fenced_transition(create(request_id(1200), 1200, PAYLOAD), budget),
                );
                finish_actor_without_resuming_caller(&fixture, caller.as_mut(), &gate, deadline)
                    .await;
                tokio::time::advance(
                    deadline - tokio::time::Instant::now() + Duration::from_millis(late_ms),
                )
                .await;
                let first = caller.await;
                let rejected = first.is_err();
                drop(first);
                let rows_at_expiry = facade.retained_fenced_transitions().await.unwrap();
                let calls_at_expiry = history_calls(&fixture);
                for voter in &fixture.voters {
                    *voter.service.reply_gates[HISTORY].lock().unwrap() = None;
                }
                // A second caller needs fresh authority. A late first reply must
                // not have populated the facade's cached history.
                let mut fresh = facade
                    .prepare_fenced_transition(
                        create(request_id(1201), 1201, PAYLOAD),
                        read_budget(),
                    )
                    .await
                    .unwrap();
                let fresh_reads = history_calls(&fixture) - calls_at_expiry;
                fresh.abandon_unexecuted().await.unwrap();
                let mutations = fixture.diagnostics().fenced_transition_v2_calls();
                drop(facade);
                for client in clients {
                    client.shutdown().await;
                }
                (
                    fixture,
                    (late_ms, rejected, rows_at_expiry, fresh_reads, mutations),
                )
            })
            .await;
        fixture.shutdown().await.unwrap();
        evidence.push(outcome);
    }
    eprintln!("protected handoff (late_ms, rejected, rows, fresh_reads, mutations): {evidence:?}");
    assert!(
        evidence
            .iter()
            .all(|(_, rejected, rows, reads, mutations)| *rejected
                && *rows == 0
                && *reads == 1
                && *mutations == 0),
        "{evidence:?}"
    );
}
