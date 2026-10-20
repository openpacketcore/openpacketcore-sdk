//! Advance protocol time only after a real successful response is withheld.

use super::*;
use std::future::Future;

pub(super) struct ReplyClock {
    holds: tokio::sync::mpsc::UnboundedReceiver<FixtureReplyHold>,
    releases: Vec<(tokio::time::Instant, tokio::sync::oneshot::Sender<()>)>,
}

impl ReplyClock {
    pub(super) fn new(fixture: &AuthenticatedPreparedFencedTransitionFixture) -> Self {
        let (send, holds) = tokio::sync::mpsc::unbounded_channel();
        for voter in &fixture.voters {
            *voter.service.reply_clock.lock().unwrap() = Some(send.clone());
        }
        Self {
            holds,
            releases: Vec::new(),
        }
    }

    fn observe(&mut self, hold: FixtureReplyHold, kind: usize) -> tokio::time::Instant {
        assert_eq!(hold.kind, kind, "the expected successful response is held");
        let deadline = tokio::time::Instant::now() + hold.delay;
        self.releases.push((deadline, hold.release));
        deadline
    }

    async fn advance_to(&mut self, deadline: tokio::time::Instant) {
        loop {
            let next = self
                .releases
                .iter()
                .enumerate()
                .filter(|(_, (at, _))| *at <= deadline)
                .min_by_key(|(_, (at, _))| *at)
                .map(|(index, (at, _))| (index, *at));
            let Some((index, at)) = next else {
                break;
            };
            tokio::time::advance(at.saturating_duration_since(tokio::time::Instant::now())).await;
            let (_, release) = self.releases.swap_remove(index);
            let _ = release.send(());
        }
        tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
    }

    pub(super) async fn read<F: Future>(&mut self, kind: usize, work: F) -> F::Output {
        tokio::pin!(work);
        let mut reads = 0;
        loop {
            tokio::select! {
                result = &mut work => return result,
                hold = self.holds.recv() => {
                    reads += 1;
                    // This is the same one-physical-read requirement asserted
                    // by each caller. Check it before a pre-fix retry can hang
                    // waiting for a new timer after discarding the valid reply.
                    assert_eq!(reads, 1, "a held read must not be replayed");
                    let deadline = self.observe(hold.unwrap(), kind);
                    self.advance_to(deadline).await;
                }
            }
        }
    }

    pub(super) async fn mutation<F: Future>(
        &mut self,
        kind: usize,
        calls: usize,
        bound: Duration,
        work: F,
    ) -> F::Output {
        let started = tokio::time::Instant::now();
        tokio::pin!(work);
        for _ in 0..calls {
            tokio::select! {
                result = &mut work => return result,
                hold = self.holds.recv() => {
                    self.observe(hold.unwrap(), kind);
                }
            }
        }
        // The mutation's original bound is unchanged. The extra existing
        // fixture tick only observes Tokio's millisecond-rounded expiry.
        self.advance_to(started + bound + FIXTURE_TIMER_TICK).await;
        work.await
    }

    pub(super) async fn lost_mutation<F: Future>(
        &mut self,
        fixture: &AuthenticatedPreparedFencedTransitionFixture,
        bound: Duration,
        work: F,
    ) -> F::Output {
        let started = tokio::time::Instant::now();
        tokio::pin!(work);
        let suppressed = fixture.voters.iter().map(|voter| {
            Box::pin(
                voter
                    .service
                    .fenced_transition_response_suppressed
                    .notified(),
            )
        });
        tokio::select! {
            result = &mut work => return result,
            _ = futures_util::future::select_all(suppressed) => {},
        }
        self.advance_to(started + bound + FIXTURE_TIMER_TICK).await;
        work.await
    }

    pub(super) async fn concurrent_reads<F: Future>(
        &mut self,
        clients: &[PersistentSessionConsumerClient],
        bound: Duration,
        work: F,
    ) -> F::Output {
        tokio::pin!(work);
        let mut reads = 0;
        let mut last_reply = tokio::time::Instant::now();
        let mut observed_queue = false;
        loop {
            tokio::select! {
                result = &mut work => return result,
                hold = self.holds.recv() => {
                    reads += 1;
                    assert!(reads <= 2, "two callers may write only two reads");
                    last_reply = last_reply.max(self.observe(hold.unwrap(), STATUS));
                    if reads == 2 {
                        self.advance_to(last_reply).await;
                    }
                }
                () = tokio::task::yield_now(), if reads == 1 && !observed_queue => {
                    if clients.iter().any(|client| client.v2_diagnostics().pool_wait_current != 0) {
                        // The existing pool reservation may queue the second
                        // read. Drive only that observed pre-write wait through
                        // its unchanged cap before it reaches another voter.
                        observed_queue = true;
                        self.advance_to(tokio::time::Instant::now() + bound + FIXTURE_TIMER_TICK).await;
                    }
                }
            }
        }
    }

    pub(super) async fn finish(&mut self) {
        while let Ok(hold) = self.holds.try_recv() {
            let kind = hold.kind;
            self.observe(hold, kind);
        }
        if let Some(deadline) = self.releases.iter().map(|(at, _)| *at).max() {
            self.advance_to(deadline).await;
        }
    }
}

pub(super) async fn shutdown_clients(clients: Vec<PersistentSessionConsumerClient>) {
    for client in clients {
        client.shutdown().await;
    }
}
