#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

fn context() -> ResolvedPolicy {
    ResolvedPolicy::new(
        Arc::new(opc_nacm::NacmPolicy::empty(opc_nacm::PolicyVersion::new(1))),
        opc_config_model::TrustedPrincipal::new(
            opc_config_model::WorkloadIdentity::User("context-fixture".into()),
            opc_types::TenantId::new("context-fixture").unwrap(),
        ),
    )
}

async fn output(gate: &AuthorizationGate) -> Poll<Result<Option<()>, AuthzError>> {
    std::future::poll_fn(|cx| Poll::Ready(gate.poll_output(cx, |_| Poll::Ready(Some(()))))).await
}

#[tokio::test]
async fn authorization_change_delivery_serializes_revoke_then_restore() {
    let hub = AuthorizationChangeHub::default();
    let gate = AuthorizationGate::default();
    let mut watch = hub.register(gate.clone(), || Ok(context())).unwrap();
    watch.initial_evaluated().unwrap();
    assert!(matches!(output(&gate).await, Poll::Ready(Ok(Some(())))));
    let first = hub.prepare_change(|| {}).await.unwrap();
    assert!(output(&gate).await.is_pending());
    let restored = AtomicBool::new(false);
    let second = hub.prepare_change(|| restored.store(true, Ordering::SeqCst));
    tokio::pin!(second);
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let completion = tokio::spawn(first.complete());
    let change = watch.changed().await.unwrap();
    assert_eq!(change.revision(), 1);
    assert!(!restored.load(Ordering::SeqCst));
    assert!(!completion.is_finished());
    assert!(output(&gate).await.is_pending());
    watch.acknowledge(change).unwrap();
    assert_eq!(completion.await.unwrap().unwrap(), 1);
    let second = second.await.unwrap();
    assert!(restored.load(Ordering::SeqCst));
    let completion = tokio::spawn(second.complete());
    let change = watch.changed().await.unwrap();
    assert_eq!(change.revision(), 2);
    watch.acknowledge(change).unwrap();
    assert_eq!(completion.await.unwrap().unwrap(), 2);
    assert!(matches!(output(&gate).await, Poll::Ready(Ok(Some(())))));
}

#[tokio::test]
async fn authorization_change_delivery_waits_for_every_stream_or_server_closure() {
    let hub = AuthorizationChangeHub::default();
    let mut first = hub
        .register(AuthorizationGate::default(), || Ok(context()))
        .unwrap();
    let second = hub
        .register(AuthorizationGate::default(), || Ok(context()))
        .unwrap();
    let pending = hub.prepare_change(|| {}).await.unwrap();
    let completion = tokio::spawn(pending.complete());
    let change = first.changed().await.unwrap();
    first.acknowledge(change).unwrap();
    assert!(!completion.is_finished());
    drop(second);
    assert_eq!(completion.await.unwrap().unwrap(), 1);
}

#[tokio::test]
async fn authorization_change_delivery_registration_captures_pending_revision() {
    let hub = AuthorizationChangeHub::default();
    let gate = AuthorizationGate::default();
    let mut old = hub.register(gate.clone(), || Ok(context())).unwrap();
    let pending = hub.prepare_change(|| {}).await.unwrap();
    // Registration after activation captures the activated context, while the
    // older watch cannot release output from its earlier initial snapshot.
    let new = hub
        .register(AuthorizationGate::default(), || Ok(context()))
        .unwrap();
    assert_eq!(new.revision(), 1);
    old.initial_evaluated().unwrap();
    assert!(output(&gate).await.is_pending());
    let completion = tokio::spawn(pending.complete());
    let change = old.changed().await.unwrap();
    old.acknowledge(change).unwrap();
    assert_eq!(completion.await.unwrap().unwrap(), 1);
}

#[tokio::test]
async fn authorization_change_delivery_registration_lock_closes_race() {
    let hub = AuthorizationChangeHub::default();
    let changed = Arc::new(AtomicBool::new(false));
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let registering = {
        let hub = hub.clone();
        let changed = changed.clone();
        tokio::task::spawn_blocking(move || {
            hub.register(AuthorizationGate::default(), || {
                entered.send(()).unwrap();
                release_rx.recv().unwrap();
                assert!(!changed.load(Ordering::SeqCst));
                Ok(context())
            })
        })
    };
    entered_rx.await.unwrap();
    assert!(
        hub.state.try_lock().is_err(),
        "initial context capture holds the same lock as notification registration"
    );
    // Both operations share the hub lock. Releasing the registration first
    // leaves a watch that must receive the immediately following activation.
    release.send(()).unwrap();
    let mut watch = registering.await.unwrap().unwrap();
    let pending = hub
        .prepare_change(|| changed.store(true, Ordering::SeqCst))
        .await
        .unwrap();
    let completion = tokio::spawn(pending.complete());
    assert_eq!(watch.revision(), 0);
    let change = watch.changed().await.unwrap();
    assert_eq!(change.revision(), 1);
    watch.acknowledge(change).unwrap();
    completion.await.unwrap().unwrap();
}

#[tokio::test]
async fn authorization_change_delivery_fails_closed() {
    for fault in ["closure", "loss", "gap", "refresh"] {
        let hub = AuthorizationChangeHub::default();
        let gate = AuthorizationGate::default();
        let mut watch = hub.register(gate.clone(), || Ok(context())).unwrap();
        watch.initial_evaluated().unwrap();
        match fault {
            "closure" => drop(hub),
            "loss" => drop(hub.prepare_change(|| {}).await.unwrap()),
            "refresh" => hub.fail(),
            "gap" => {
                let (completion, _) = oneshot::channel();
                hub.state.lock().unwrap().listeners[0]
                    .sender
                    .send(Ok(AuthorizationChange {
                        revision: 2,
                        gate: gate.clone(),
                        completion: Some(completion),
                    }))
                    .ok()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(watch.changed().await.is_err());
        assert!(matches!(
            output(&gate).await,
            Poll::Ready(Err(AuthzError::PolicyUnavailable))
        ));
    }
}

#[tokio::test]
async fn authorization_change_delivery_dropped_reevaluation_closes_output_before_ack() {
    let hub = AuthorizationChangeHub::default();
    let gate = AuthorizationGate::default();
    let mut watch = hub.register(gate.clone(), || Ok(context())).unwrap();
    let pending = hub.prepare_change(|| {}).await.unwrap();
    let completion = tokio::spawn(pending.complete());
    drop(watch.changed().await.unwrap());
    assert_eq!(completion.await.unwrap().unwrap(), 1);
    assert!(matches!(
        output(&gate).await,
        Poll::Ready(Err(AuthzError::PolicyUnavailable))
    ));
}

#[tokio::test]
async fn authorization_change_delivery_source_panic_fails_all_attached_streams() {
    for registration in [false, true] {
        let hub = AuthorizationChangeHub::default();
        let gate = AuthorizationGate::default();
        let _watch = hub.register(gate.clone(), || Ok(context())).unwrap();
        _watch.initial_evaluated().unwrap();
        if registration {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hub.register(AuthorizationGate::default(), || {
                    panic!("synthetic refresh failure")
                })
            }));
        } else {
            let other = hub.clone();
            let _ = tokio::spawn(async move {
                other
                    .activate(|| panic!("synthetic activation failure"))
                    .await
            })
            .await;
        }
        assert!(
            matches!(
                output(&gate).await,
                Poll::Ready(Err(AuthzError::PolicyUnavailable))
            ),
            "failed source must not leave output open or permanently pending"
        );
    }
}
