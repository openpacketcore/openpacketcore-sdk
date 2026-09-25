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
async fn independent_fixtures_do_not_share_admission_capacity() {
    let first = lab(3).await;
    let second = lab(3).await;
    let permits = selector_namespace_supervisors(first.authority.storage_scope_commitment)
        .try_acquire_many_owned(SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE as u32)
        .unwrap();
    let recovery = second
        .authority
        .concurrent_operations()
        .recover_active(second.backend.clone(), second.parent.clone())
        .await;
    drop(permits);
    assert!(
        recovery.is_ok(),
        "an independent fixture must not inherit another fixture's saturation"
    );
}

fn reattached(source: &GtpuSessionGroup, id: u8, teid: u32) -> GtpuSessionGroup {
    let mut context = source.entries()[0].context().clone();
    context.local_teid = Teid::new(teid).unwrap();
    context.peer_teid = Teid::new(teid + 0x1000).unwrap();
    GtpuSessionGroup::new(
        GtpuSessionGroupId::new([id; 16]).unwrap(),
        source.device_id(),
        vec![GtpuSessionEntry::new(context, source.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap()
}

#[tokio::test]
async fn unrelated_unadmitted_cleanup_progresses_during_held_installation() {
    fallback_progress(false, true).await;
}

#[tokio::test]
async fn unrelated_reattach_progresses_before_another_installation_effect() {
    fallback_progress(true, true).await;
}

#[tokio::test]
async fn unrelated_reattach_progresses_before_another_installation_acknowledgement() {
    fallback_progress(true, false).await;
}

async fn fallback_progress(reattach: bool, before: bool) {
    let lab = lab(4).await;
    let concurrent = lab.authority.concurrent_operations();
    let backend = held_backend(&lab, before);
    if reattach {
        let sibling = concurrent
            .recover_active(backend.clone(), lab.sibling.clone())
            .await
            .unwrap();
        drop(
            concurrent
                .retire(backend.clone(), sibling, lab.sibling.clone())
                .await
                .unwrap(),
        );
    }
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
    let desired = reattached(&lab.sibling, 4, 0x3001);
    let mut fallback = Box::pin(async {
        if reattach {
            let claim = concurrent
                .reconcile_reattached(backend.clone(), desired.clone())
                .await?;
            drop(
                concurrent
                    .retire(backend.clone(), claim, desired.clone())
                    .await?,
            );
        } else {
            let claim = concurrent
                .seal_unadmitted(backend.clone(), desired.clone())
                .await?;
            assert!(claim.confirms_group(&lab.authority, &desired));
        }
        Ok::<(), GtpuSessionSelectorCoordinatorError>(())
    });
    let progress = tokio::time::timeout(Duration::from_secs(1), &mut fallback).await;
    let independent = progress.is_ok();
    backend.release.notify_one();
    drop(first.await.unwrap());
    match progress {
        Ok(result) => result.unwrap(),
        Err(_) => fallback.await.unwrap(),
    }
    for group in [lab.parent.clone(), lab.child.clone()] {
        drop(
            concurrent
                .recover_active(backend.clone(), group)
                .await
                .unwrap(),
        );
    }
    assert!(
        independent,
        "unrelated lifecycle fallback must finish while installation is held"
    );
}

#[tokio::test]
async fn concurrent_seal_repeats_only_the_exact_never_admitted_graph() {
    let lab = lab(4).await;
    let concurrent = lab.authority.concurrent_operations();
    let desired = reattached(&lab.sibling, 4, 0x3001);
    let claim = concurrent
        .seal_unadmitted(lab.backend.clone(), desired.clone())
        .await
        .unwrap();
    assert!(claim.confirms_group(&lab.authority, &desired));
    let before = lab.authority.read_state().await.unwrap().1.encode();
    let repeated = concurrent
        .seal_unadmitted(lab.backend.clone(), desired.clone())
        .await
        .unwrap();
    assert!(repeated.confirms_group(&lab.authority, &desired));
    let changed = reattached(&lab.sibling, 4, 0x4001);
    for rejected in [changed, lab.parent.clone(), lab.sibling.clone()] {
        assert!(concurrent
            .seal_unadmitted(lab.backend.clone(), rejected)
            .await
            .is_err());
        assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
    }
    assert!(concurrent
        .reconcile_reattached(lab.backend.clone(), desired)
        .await
        .is_err());
    assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
    for active in [lab.parent, lab.sibling] {
        drop(
            concurrent
                .recover_active(lab.backend.clone(), active)
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn concurrent_reattach_retains_exact_predecessor_and_burned_teid_rules() {
    let lab = lab(4).await;
    let concurrent = lab.authority.concurrent_operations();
    let next = reattached(&lab.sibling, 4, 0x3001);
    assert!(concurrent
        .reconcile_reattached(lab.backend.clone(), next.clone())
        .await
        .is_err());
    let old = concurrent
        .recover_active(lab.backend.clone(), lab.sibling.clone())
        .await
        .unwrap();
    drop(
        concurrent
            .retire(lab.backend.clone(), old, lab.sibling.clone())
            .await
            .unwrap(),
    );
    let before = lab.authority.read_state().await.unwrap().1.encode();
    let old_teid = lab.sibling.entries()[0].context().local_teid.get();
    for invalid in [
        reattached(&lab.sibling, 4, old_teid),
        reattached(&lab.sibling, 2, 0x3001),
        next_child(&lab.sibling, 4, 0x3001),
        reattached(&lab.parent, 4, 0x3001),
    ] {
        assert!(concurrent
            .reconcile_reattached(lab.backend.clone(), invalid)
            .await
            .is_err());
        assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
    }
    let active = concurrent
        .reconcile_reattached(lab.backend.clone(), next.clone())
        .await
        .unwrap();
    assert!(concurrent
        .reconcile_reattached(lab.backend.clone(), next.clone())
        .await
        .is_err());
    drop(
        concurrent
            .retire(lab.backend.clone(), active, next.clone())
            .await
            .unwrap(),
    );
    assert!(concurrent
        .reconcile_reattached(lab.backend.clone(), reattached(&next, 5, old_teid))
        .await
        .is_err());
    let replacement = reattached(&next, 5, 0x4001);
    let active = concurrent
        .reconcile_reattached(lab.backend.clone(), replacement.clone())
        .await
        .unwrap();
    drop(
        concurrent
            .retire(lab.backend.clone(), active, replacement)
            .await
            .unwrap(),
    );
    drop(
        concurrent
            .recover_active(lab.backend.clone(), lab.parent)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn concurrent_reattach_cancellation_retains_conflicts_and_one_successor() {
    let lab = lab(4).await;
    let concurrent = lab.authority.concurrent_operations();
    let backend = held_backend(&lab, true);
    let old = concurrent
        .recover_active(backend.clone(), lab.sibling.clone())
        .await
        .unwrap();
    drop(
        concurrent
            .retire(backend.clone(), old, lab.sibling.clone())
            .await
            .unwrap(),
    );
    let next = reattached(&lab.sibling, 4, 0x3001);
    backend.hold_next.store(true, Ordering::SeqCst);
    let mut first = concurrent.reconcile_reattached(backend.clone(), next.clone());
    tokio::select! {
        () = backend.entered.notified() => {},
        result = &mut first => panic!("reattachment escaped its exact gate: {result:?}"),
    }
    drop(first);
    let mut retry = concurrent.recover_active(backend.clone(), next.clone());
    let competitor = reattached(&lab.sibling, 5, 0x4001);
    let mut conflict = concurrent.reconcile_reattached(backend.clone(), competitor);
    for observer in [&mut retry, &mut conflict] {
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *observer).poll(cx).is_pending()))
                .await
        );
    }
    let mut unrelated = Box::pin(async {
        let parent = concurrent
            .recover_active(backend.clone(), lab.parent.clone())
            .await?;
        concurrent
            .reconcile_bearer(
                backend.clone(),
                parent,
                lab.parent.clone(),
                lab.child.clone(),
            )
            .await
    });
    let progress = tokio::time::timeout(Duration::from_secs(1), &mut unrelated).await;
    let independent = progress.is_ok();
    backend.release.notify_one();
    let child = match progress {
        Ok(result) => result.unwrap(),
        Err(_) => unrelated.await.unwrap(),
    };
    let active = retry.await.unwrap();
    assert!(conflict.await.is_err());
    let (left, right) = tokio::join!(
        concurrent.retire(backend.clone(), active, next),
        concurrent.retire(backend.clone(), child, lab.child.clone()),
    );
    drop((left.unwrap(), right.unwrap()));
    drop(
        concurrent
            .recover_active(backend.clone(), lab.parent.clone())
            .await
            .unwrap(),
    );
    assert!(
        independent,
        "a dropped reattach observer must retain only its actual conflicts"
    );
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
