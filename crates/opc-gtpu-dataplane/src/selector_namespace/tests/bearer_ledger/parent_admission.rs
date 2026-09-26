//! The complete current-parent/child admission boundary and its durable cost.

use super::*;
use std::sync::atomic::Ordering;

async fn admit_child<B>(lab: &Lab<B>, concurrent: bool) -> GtpuSessionSelectorActiveClaim
where
    B: ProtectedSessionBackend + Send + Sync + 'static,
{
    if concurrent {
        lab.authority
            .concurrent_operations()
            .reconcile_bearer_under_active_parent(
                lab.backend.clone(),
                lab.parent.clone(),
                lab.child.clone(),
            )
            .await
            .unwrap()
    } else {
        lab.authority
            .reconcile_bearer_under_active_parent(
                lab.backend.clone(),
                lab.parent.clone(),
                lab.child.clone(),
            )
            .await
            .unwrap()
    }
}

async fn assert_parent_admission_budget(concurrent: bool) {
    let tenant = TenantId::from_static(if concurrent {
        "current-parent-concurrent"
    } else {
        "current-parent-legacy"
    });
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("current-parent-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x47; 32]),
    )
    .unwrap();
    let raw = Arc::new(super::super::worker_lease::RenewalBackend::new());
    let store = SessionStore::new(EncryptingSessionBackend::new(
        raw.clone(),
        keys,
        "current-parent-budget",
    ));
    let lab = lab_with_store(store, tenant, 3).await;
    let counts = || {
        [
            raw.acquisitions.load(Ordering::SeqCst),
            raw.releases.load(Ordering::SeqCst),
            raw.reads.load(Ordering::SeqCst),
            raw.writes.load(Ordering::SeqCst),
        ]
    };
    let before = counts();
    let child = admit_child(&lab, concurrent).await;
    let after = counts();
    let delta: [usize; 4] = std::array::from_fn(|index| after[index] - before[index]);
    drop(
        lab.authority
            .retire(lab.backend.clone(), child, lab.child.clone())
            .await
            .unwrap(),
    );
    for group in [lab.parent, lab.sibling] {
        let active = lab
            .authority
            .recover_active(lab.backend.clone(), group.clone())
            .await
            .unwrap();
        drop(
            lab.authority
                .retire(lab.backend.clone(), active, group)
                .await
                .unwrap(),
        );
    }
    // Three original child transitions and their fresh durable readbacks
    // remain mandatory. Current-parent admission needs one lease lifetime,
    // rather than a separate completed recovery immediately before it.
    assert_eq!(
        delta,
        [1, 1, 11, 3],
        "complete parent/child admission acquisitions/releases/reads/writes"
    );
}

#[tokio::test]
async fn current_parent_admission_uses_one_durable_lease() {
    assert_parent_admission_budget(false).await;
}

#[tokio::test]
async fn concurrent_parent_admission_uses_one_durable_lease() {
    assert_parent_admission_budget(true).await;
}

fn changed_parent(parent: &GtpuSessionGroup, replace_id: bool) -> GtpuSessionGroup {
    let mut context = parent.entries()[0].context().clone();
    let id = if replace_id {
        GtpuSessionGroupId::new([0x70; 16]).unwrap()
    } else {
        context.peer_teid = Teid::new(context.peer_teid.get() + 1).unwrap();
        parent.id()
    };
    GtpuSessionGroup::new(
        id,
        parent.device_id(),
        vec![GtpuSessionEntry::new(context, parent.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap()
}

async fn assert_child_absent(lab: &Lab) {
    let context = lab.child.entries()[0].context();
    for selector in [
        crate::PdpContextSelector::LocalTeid(
            crate::PdpContextLocalTeidSelector::from_context(context).unwrap(),
        ),
        crate::PdpContextSelector::Uplink(
            crate::PdpContextUplinkSelector::from_context(context).unwrap(),
        ),
    ] {
        assert_eq!(
            lab.backend.read_pdp_context(selector).await.unwrap(),
            crate::PdpContextReadback::Absent
        );
    }
}

#[tokio::test]
async fn current_parent_admission_rejects_missing_changed_unrelated_and_retired_parents() {
    for concurrent in [false, true] {
        let lab = lab(3).await;
        let operations = lab.authority.concurrent_operations();
        let admit = |parent| {
            if concurrent {
                operations.reconcile_bearer_under_active_parent(
                    lab.backend.clone(),
                    parent,
                    lab.child.clone(),
                )
            } else {
                lab.authority.reconcile_bearer_under_active_parent(
                    lab.backend.clone(),
                    parent,
                    lab.child.clone(),
                )
            }
        };
        let before = lab.authority.read_state().await.unwrap().1.encode();
        for parent in [
            changed_parent(&lab.parent, true),
            changed_parent(&lab.parent, false),
            lab.sibling.clone(),
        ] {
            assert!(admit(parent).await.is_err());
            assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
            assert_child_absent(&lab).await;
        }
        let active = operations
            .recover_active(lab.backend.clone(), lab.parent.clone())
            .await
            .unwrap();
        drop(
            operations
                .retire(lab.backend.clone(), active, lab.parent.clone())
                .await
                .unwrap(),
        );
        let retired = lab.authority.read_state().await.unwrap().1.encode();
        assert!(admit(lab.parent.clone()).await.is_err());
        assert_eq!(
            lab.authority.read_state().await.unwrap().1.encode(),
            retired
        );
        assert_child_absent(&lab).await;
        drop(
            operations
                .recover_active(lab.backend.clone(), lab.sibling.clone())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn current_parent_admission_keeps_capacity_and_no_duplicate_effect_rules() {
    for concurrent in [false, true] {
        for capacity in [2, 3] {
            let lab = lab(capacity).await;
            let operations = lab.authority.concurrent_operations();
            let admit = || {
                if concurrent {
                    operations.reconcile_bearer_under_active_parent(
                        lab.backend.clone(),
                        lab.parent.clone(),
                        lab.child.clone(),
                    )
                } else {
                    lab.authority.reconcile_bearer_under_active_parent(
                        lab.backend.clone(),
                        lab.parent.clone(),
                        lab.child.clone(),
                    )
                }
            };
            let before = lab.authority.read_state().await.unwrap().1.encode();
            let result = admit().await;
            if capacity == 2 {
                assert!(result.is_err());
                assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
                assert_child_absent(&lab).await;
            } else {
                let active = result.unwrap();
                let installed = lab.authority.read_state().await.unwrap().1.encode();
                assert!(admit().await.is_err());
                assert_eq!(
                    lab.authority.read_state().await.unwrap().1.encode(),
                    installed
                );
                drop(
                    operations
                        .retire(lab.backend.clone(), active, lab.child.clone())
                        .await
                        .unwrap(),
                );
                let retired = lab.authority.read_state().await.unwrap().1.encode();
                assert!(admit().await.is_err());
                assert_eq!(
                    lab.authority.read_state().await.unwrap().1.encode(),
                    retired
                );
                assert_child_absent(&lab).await;
            }
            for parent in [lab.parent.clone(), lab.sibling.clone()] {
                drop(
                    operations
                        .recover_active(lab.backend.clone(), parent)
                        .await
                        .unwrap(),
                );
            }
        }
    }
}

#[tokio::test]
async fn current_parent_admission_cannot_rebind_a_foreign_backend_namespace() {
    let owner = lab(3).await;
    let foreign = lab(3).await;
    let before = owner.authority.read_state().await.unwrap().1.encode();
    for concurrent in [false, true] {
        let result = if concurrent {
            owner
                .authority
                .concurrent_operations()
                .reconcile_bearer_under_active_parent(
                    foreign.backend.clone(),
                    owner.parent.clone(),
                    owner.child.clone(),
                )
                .await
        } else {
            owner
                .authority
                .reconcile_bearer_under_active_parent(
                    foreign.backend.clone(),
                    owner.parent.clone(),
                    owner.child.clone(),
                )
                .await
        };
        assert!(result.is_err());
        assert_eq!(
            owner.authority.read_state().await.unwrap().1.encode(),
            before
        );
        assert_child_absent(&owner).await;
        assert_child_absent(&foreign).await;
    }
    for fixture in [&owner, &foreign] {
        for group in [&fixture.parent, &fixture.sibling] {
            drop(
                fixture
                    .authority
                    .recover_active(fixture.backend.clone(), group.clone())
                    .await
                    .unwrap(),
            );
        }
    }
}

#[tokio::test]
async fn current_parent_admission_rejects_an_exact_active_marked_parent() {
    for concurrent in [false, true] {
        let lab = lab(4).await;
        let child = admit_child(&lab, concurrent).await;
        let mut context = lab.child.entries()[0].context().clone();
        context.local_teid = Teid::new(0x7001).unwrap();
        context.bearer_mark = Some(crate::GtpBearerMark::new(7).unwrap());
        let grandchild = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([0x71; 16]).unwrap(),
            lab.child.device_id(),
            vec![GtpuSessionEntry::new(
                context.clone(),
                lab.child.entries()[0].local_outer_address(),
            )
            .unwrap()],
        )
        .unwrap();
        let before = lab.authority.read_state().await.unwrap().1.encode();
        let result = if concurrent {
            lab.authority
                .concurrent_operations()
                .reconcile_bearer_under_active_parent(
                    lab.backend.clone(),
                    lab.child.clone(),
                    grandchild,
                )
                .await
        } else {
            lab.authority
                .reconcile_bearer_under_active_parent(
                    lab.backend.clone(),
                    lab.child.clone(),
                    grandchild,
                )
                .await
        };
        assert!(result.is_err());
        assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
        for selector in [
            crate::PdpContextSelector::LocalTeid(
                crate::PdpContextLocalTeidSelector::from_context(&context).unwrap(),
            ),
            crate::PdpContextSelector::Uplink(
                crate::PdpContextUplinkSelector::from_context(&context).unwrap(),
            ),
        ] {
            assert_eq!(
                lab.backend.read_pdp_context(selector).await.unwrap(),
                crate::PdpContextReadback::Absent
            );
        }
        drop(
            lab.authority
                .retire(lab.backend.clone(), child, lab.child.clone())
                .await
                .unwrap(),
        );
    }
}

#[tokio::test]
async fn current_parent_admission_preserves_final_readback_and_release_failures() {
    use super::super::worker_lease::RenewalBackend;

    for concurrent in [false, true] {
        for reject_final_read in [false, true] {
            let tenant = TenantId::new(format!(
                "current-parent-fault-{concurrent}-{reject_final_read}"
            ))
            .unwrap();
            let keys = Arc::new(opc_key::MemoryKeyProvider::new());
            keys.insert_active_key(
                opc_key::KeyId::new("current-parent-fault-key").unwrap(),
                opc_key::KeyPurpose::Session,
                tenant.clone(),
                opc_key::Zeroizing::new([0x48; 32]),
            )
            .unwrap();
            let raw = Arc::new(RenewalBackend::new());
            let lab = lab_with_store(
                SessionStore::new(EncryptingSessionBackend::new(
                    raw.clone(),
                    keys,
                    "current-parent-fault",
                )),
                tenant,
                3,
            )
            .await;
            let reads = raw.reads.load(Ordering::SeqCst);
            let writes = raw.writes.load(Ordering::SeqCst);
            if reject_final_read {
                raw.reject_read.store(reads + 11, Ordering::SeqCst);
            } else {
                raw.reject_release.store(true, Ordering::SeqCst);
            }
            let operations = lab.authority.concurrent_operations();
            let result = if concurrent {
                operations
                    .reconcile_bearer_under_active_parent(
                        lab.backend.clone(),
                        lab.parent.clone(),
                        lab.child.clone(),
                    )
                    .await
            } else {
                lab.authority
                    .reconcile_bearer_under_active_parent(
                        lab.backend.clone(),
                        lab.parent.clone(),
                        lab.child.clone(),
                    )
                    .await
            };
            assert!(matches!(
                result,
                Err(GtpuSessionSelectorCoordinatorError::Namespace)
            ));
            // A rejected final readback invokes the existing poison recovery
            // path. Its extra read sees the committed Active successor and
            // refuses to poison it with the older Installing coordinate.
            // Rejected lease release has no additional durable read.
            assert_eq!(
                raw.reads.load(Ordering::SeqCst) - reads,
                if reject_final_read { 12 } else { 11 },
                "concurrent={concurrent}, reject_final_read={reject_final_read}"
            );
            assert_eq!(raw.writes.load(Ordering::SeqCst) - writes, 3);
            raw.reject_release.store(false, Ordering::SeqCst);
            // The installed effect remains exactly recoverable. Neither an
            // unread activation nor a failed lease handoff publishes success,
            // and retrying recovery must not install the child again.
            let child = operations
                .recover_active(lab.backend.clone(), lab.child.clone())
                .await
                .unwrap();
            assert_eq!(raw.writes.load(Ordering::SeqCst) - writes, 3);
            drop(
                operations
                    .retire(lab.backend.clone(), child, lab.child.clone())
                    .await
                    .unwrap(),
            );
            for group in [lab.parent, lab.sibling] {
                let active = operations
                    .recover_active(lab.backend.clone(), group.clone())
                    .await
                    .unwrap();
                drop(
                    operations
                        .retire(lab.backend.clone(), active, group)
                        .await
                        .unwrap(),
                );
            }
        }
    }
}

#[tokio::test]
async fn current_parent_admission_allows_progress_before_an_unrelated_effect_acknowledgement() {
    concurrent_child_progress(false, false, true).await;
}

#[tokio::test]
async fn current_parent_admission_allows_progress_before_an_unrelated_effect() {
    concurrent_child_progress(true, false, true).await;
}

#[tokio::test]
async fn current_parent_admission_retains_a_cancelled_effect_and_independent_progress() {
    concurrent_child_progress(true, true, true).await;
}
