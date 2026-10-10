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
