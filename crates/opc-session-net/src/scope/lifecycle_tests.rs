use super::lifecycle::*;
use std::sync::Arc;

#[tokio::test]
async fn candidate_excludes_effects_and_activation_ends_candidate_proofs() {
    let gate = EffectGate::new();
    assert!(gate.enter().await.is_err());
    let candidate = gate.candidate().await.unwrap();
    let mut activation = Box::pin(gate.activate());
    assert!(
        futures_util::poll!(&mut activation).is_pending(),
        "activation cannot race a held candidate proof"
    );
    drop(candidate);
    activation.await.unwrap();
    assert!(gate.candidate().await.is_err());
    let effect = gate.enter().await.unwrap();
    drop(effect);
}
#[tokio::test]
async fn quiescence_blocks_new_effects_then_waits_for_old_submissions_to_drain() {
    let gate = Arc::new(EffectGate::new());
    gate.activate().await.unwrap();
    let first = gate.enter().await.unwrap();
    let second = gate.enter().await.unwrap();
    let close = gate.clone();
    let mut quiescence = Box::pin(close.quiesce());
    assert!(futures_util::poll!(&mut quiescence).is_pending());
    assert!(gate.enter().await.is_err());
    assert!(gate.candidate().await.is_err());
    drop(first);
    assert!(futures_util::poll!(&mut quiescence).is_pending());
    drop(second);
    let closed = quiescence.await.unwrap();
    assert_ne!(closed.fence_nonce(), &[0; 32]);
    assert!(gate.activate().await.is_err(), "quiescence is irreversible");
    assert_eq!(
        closed.fence_nonce(),
        gate.quiesce().await.unwrap().fence_nonce()
    );
}
#[tokio::test]
async fn cancelling_quiescence_never_reopens_and_a_retry_can_finish() {
    let gate = EffectGate::new();
    gate.activate().await.unwrap();
    let held = gate.enter().await.unwrap();
    let mut close = Box::pin(gate.quiesce());
    assert!(futures_util::poll!(&mut close).is_pending());
    drop(close);
    assert!(gate.enter().await.is_err());
    drop(held);
    gate.quiesce().await.unwrap();
    assert!(gate.activate().await.is_err());
}

#[tokio::test]
async fn read_observation_releases_gate_at_wait_and_cannot_resume_after_quiescence() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let gate = EffectGate::new();
    let polls = AtomicUsize::new(0);
    let read = || {
        std::future::poll_fn(|_| {
            polls.fetch_add(1, Ordering::AcqRel);
            std::task::Poll::<()>::Pending
        })
    };
    assert!(gate.observe(read()).await.is_err());
    assert_eq!(polls.load(Ordering::Acquire), 0);
    gate.activate().await.unwrap();
    let mut pending = Box::pin(gate.observe(read()));
    assert!(futures_util::poll!(pending.as_mut()).is_pending());
    assert_eq!(polls.load(Ordering::Acquire), 1);
    // The observation is still pending; a held read guard would block Close.
    tokio::time::timeout(std::time::Duration::from_secs(1), gate.quiesce())
        .await
        .unwrap()
        .unwrap();
    assert!(pending.await.is_err());
    assert!(gate.observe(read()).await.is_err());
    assert_eq!(polls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn quiescence_wakes_a_read_observation_without_transport_progress() {
    let gate = Arc::new(EffectGate::new());
    gate.activate().await.unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let reader = Arc::clone(&gate);
    let observation = tokio::spawn(async move {
        reader
            .observe(async move {
                started.send(()).unwrap();
                std::future::pending::<()>().await;
            })
            .await
    });
    ready.await.unwrap();
    gate.quiesce().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), observation)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}
