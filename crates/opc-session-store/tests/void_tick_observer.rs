//! Keep this regression in its own test process: tracing caches callsite
//! interest globally, so another test's subscriber could hide the first use.

use futures_util::FutureExt;

#[path = "../../opc-consensus/tests/reelection/delivery.rs"]
mod delivery;

fn tick_span() -> tracing::Span {
    tracing::debug_span!(target: "openraft::core::tick", "tick")
}

fn tick_sent(sequence: usize) {
    tracing::debug!(target: "openraft::core::tick", "Tick sent: {}", sequence);
}

fn tick_handled(node: u64) {
    tracing::debug_span!(target: "openraft::core::raft_core", "handle_notify", id = node).in_scope(
        || {
            let _handled = tracing::debug_span!(
                target: "openraft::core::raft_core",
                "handle_tick_election"
            )
            .entered();
        },
    );
}

#[tokio::test(start_paused = true)]
async fn first_callsite_use_without_a_subscriber_preserves_tick_observation() {
    let (observer, _guard) = delivery::TickDelivery::install();
    std::thread::spawn(|| {
        assert!(tick_span().is_disabled());
        tick_sent(1);
        tick_handled(7);
    })
    .join()
    .expect("unobserved test thread");

    let node = delivery::node_span(7).entered();
    let tick = tick_span();
    assert!(
        !tick.is_disabled(),
        "another thread's first callsite use must not disable the observed tick"
    );
    drop(node);

    for sequence in 1..=2 {
        let at = tokio::time::Instant::now();
        tick.in_scope(|| tick_sent(sequence));
        assert!(
            observer.wait(7, at).now_or_never().is_none(),
            "sending a new tick cannot reuse the preceding handler completion"
        );
        tick_handled(7);
        assert!(
            observer.wait(7, at).now_or_never().is_some(),
            "the corresponding completed core handler releases the barrier"
        );
    }
}
