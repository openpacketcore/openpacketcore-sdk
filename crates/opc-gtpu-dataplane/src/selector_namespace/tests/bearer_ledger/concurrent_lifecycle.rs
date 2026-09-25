//! Real protected-ledger lifecycle overlap, admission and rejection checks.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn held_backend(lab: &Lab, before: bool) -> Arc<HeldAcknowledgement> {
    Arc::new(HeldAcknowledgement {
        inner: Arc::clone(&lab.backend),
        hold_next: AtomicBool::new(false),
        hold_before_effect: before,
        hold_remove: AtomicBool::new(false),
        read_calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    })
}

fn next_child(parent: &GtpuSessionGroup, id: u8, teid: u32) -> GtpuSessionGroup {
    let mut context = parent.entries()[0].context().clone();
    context.local_teid = Teid::new(teid).unwrap();
    context.peer_teid = Teid::new(teid + 0x1000).unwrap();
    context.bearer_mark = crate::GtpBearerMark::new(6);
    GtpuSessionGroup::new(
        GtpuSessionGroupId::new([id; 16]).unwrap(),
        parent.device_id(),
        vec![GtpuSessionEntry::new(context, parent.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap()
}

#[tokio::test]
async fn concurrent_retirement_preserves_retry_order_and_exact_mark_reuse() {
    retirement_progress(true, false).await;
}

#[tokio::test]
async fn concurrent_retirement_dropped_observer_keeps_exact_cleanup_ownership() {
    retirement_progress(false, true).await;
}

async fn retirement_progress(before: bool, cancel_observer: bool) {
    let lab = lab(3).await;
    let concurrent = lab.authority.concurrent_operations();
    let backend = held_backend(&lab, before);
    let parent = concurrent
        .recover_active(backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let first = concurrent
        .reconcile_bearer(
            backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone(),
        )
        .await
        .unwrap();
    let sibling = concurrent
        .recover_active(backend.clone(), lab.sibling.clone())
        .await
        .unwrap();
    backend.hold_remove.store(true, Ordering::SeqCst);
    let mut retirement = concurrent.retire(backend.clone(), first, lab.child.clone());
    tokio::select! {
        () = backend.entered.notified() => {},
        result = &mut retirement => panic!("retirement escaped its exact gate: {result:?}"),
    }
    let retirement = if cancel_observer {
        drop(retirement);
        None
    } else {
        Some(retirement)
    };
    // A retry can observe the exact retired result only after the original
    // supervisor has completed every required readback and durable transition.
    let mut retry = concurrent.recover_retired(backend.clone(), lab.child.clone());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut retry).poll(cx).is_pending())).await
    );
    let other = next_child(&lab.sibling, 4, 0x3001);
    let mut create =
        concurrent.reconcile_bearer(backend.clone(), sibling, lab.sibling.clone(), other.clone());
    let progress = tokio::time::timeout(Duration::from_secs(1), &mut create).await;
    let independent = progress.is_ok();
    backend.release.notify_one();
    if let Some(retirement) = retirement {
        drop(retirement.await.unwrap());
    }
    let other_claim = match progress {
        Ok(result) => result.unwrap(),
        Err(_) => create.await.unwrap(),
    };
    drop(retry.await.unwrap());
    // Reusing the mark requires a new immutable group plus the exact retired
    // predecessor proof. Replaying the old group cannot become a new effect.
    let parent = concurrent
        .recover_active(backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let replacement = next_child(&lab.parent, 5, 0x4001);
    let replacement_claim = concurrent
        .reconcile_bearer(
            backend.clone(),
            parent,
            lab.parent.clone(),
            replacement.clone(),
        )
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        concurrent.retire(backend.clone(), replacement_claim, replacement),
        concurrent.retire(backend.clone(), other_claim, other),
    );
    drop((first.unwrap(), second.unwrap()));
    for parent in [lab.parent, lab.sibling] {
        drop(
            concurrent
                .recover_active(backend.clone(), parent)
                .await
                .unwrap(),
        );
    }
    assert!(
        independent,
        "unrelated create must complete while retirement remains held"
    );
}

#[tokio::test]
async fn concurrent_rejected_unrelated_child_does_not_delay_or_poison_valid_work() {
    let lab = lab(3).await;
    let concurrent = lab.authority.concurrent_operations();
    let backend = held_backend(&lab, true);
    let parent = concurrent
        .recover_active(backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let sibling = concurrent
        .recover_active(backend.clone(), lab.sibling.clone())
        .await
        .unwrap();
    backend.hold_next.store(true, Ordering::SeqCst);
    let mut first = concurrent.reconcile_bearer(
        backend.clone(),
        parent,
        lab.parent.clone(),
        lab.child.clone(),
    );
    tokio::select! {
        () = backend.entered.notified() => {},
        result = &mut first => panic!("installation escaped its exact gate: {result:?}"),
    }
    let invalid = next_child(
        &lab.sibling,
        4,
        lab.sibling.entries()[0].context().local_teid.get(),
    );
    let mut rejection =
        concurrent.reconcile_bearer(backend.clone(), sibling, lab.sibling.clone(), invalid);
    let progress = tokio::time::timeout(Duration::from_secs(1), &mut rejection).await;
    let independent = progress.is_ok();
    backend.release.notify_one();
    drop(first.await.unwrap());
    let rejected = match progress {
        Ok(result) => result,
        Err(_) => rejection.await,
    };
    assert!(matches!(
        rejected,
        Err(GtpuSessionSelectorCoordinatorError::Namespace)
    ));
    let sibling = concurrent
        .recover_active(backend.clone(), lab.sibling.clone())
        .await
        .unwrap();
    let valid = next_child(&lab.sibling, 5, 0x3001);
    let child = concurrent
        .reconcile_bearer(backend.clone(), sibling, lab.sibling.clone(), valid.clone())
        .await
        .unwrap();
    drop(
        concurrent
            .retire(backend.clone(), child, valid)
            .await
            .unwrap(),
    );
    for group in [lab.parent, lab.sibling, lab.child] {
        drop(
            concurrent
                .recover_active(backend.clone(), group)
                .await
                .unwrap(),
        );
    }
    assert!(
        independent,
        "settled rejection must not wait for an unrelated held effect"
    );
}

#[tokio::test]
async fn concurrent_supervisors_reject_at_the_existing_bound_and_release_after_settlement() {
    let lab = lab(3).await;
    let concurrent = lab.authority.concurrent_operations();
    let backend = held_backend(&lab, true);
    let parent = concurrent
        .recover_active(backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    backend.hold_next.store(true, Ordering::SeqCst);
    let mut first = concurrent.reconcile_bearer(
        backend.clone(),
        parent,
        lab.parent.clone(),
        lab.child.clone(),
    );
    tokio::select! {
        () = backend.entered.notified() => {},
        result = &mut first => panic!("installation escaped its exact gate: {result:?}"),
    }
    let pending = (1..SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE)
        .map(|_| concurrent.recover_active(backend.clone(), lab.parent.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        selector_namespace_supervisors(lab.authority.storage_scope_commitment).available_permits(),
        0
    );
    assert!(matches!(
        concurrent
            .recover_active(backend.clone(), lab.sibling.clone())
            .await,
        Err(GtpuSessionSelectorCoordinatorError::Backend)
    ));
    backend.release.notify_one();
    drop(first.await.unwrap());
    for observer in pending {
        drop(observer.await.unwrap());
    }
    drop(
        concurrent
            .recover_active(backend, lab.sibling)
            .await
            .unwrap(),
    );
    assert_eq!(
        selector_namespace_supervisors(lab.authority.storage_scope_commitment).available_permits(),
        SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE,
    );
}
