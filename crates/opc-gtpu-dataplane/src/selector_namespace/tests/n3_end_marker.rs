use super::super::n3_end_marker::end_marker_source_is_current;
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// Test double for the coordinator's ownership/acknowledgement contract only.
/// Packet submission and ordering are qualified by the native test instead.
#[derive(Debug, Default)]
pub(super) struct EndMarkerTestState {
    mode: AtomicU8,
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    calls: AtomicUsize,
}

impl EndMarkerTestState {
    pub(super) async fn submit(
        &self,
        request: GtpuN3EndMarkerRequest,
    ) -> Result<GtpuN3EndMarkerReceipt, crate::GtpuError> {
        if self.mode.load(Ordering::SeqCst) == 0 {
            return Err(crate::GtpuError::UnsupportedFeature {
                feature: "n3_end_marker_test_backend",
            });
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        if self.hold.swap(false, Ordering::SeqCst) {
            self.release.notified().await;
        }
        match self.mode.load(Ordering::SeqCst) {
            2 => Err(crate::GtpuError::StateIndeterminate {
                operation: "n3_end_marker_test_acknowledgement",
            }),
            3 => panic!("contained test backend failure"),
            4 => {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while request.is_current() {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("test request must expire within its short worker lease");
                Ok(request.confirm_submitted())
            }
            _ => Ok(request.confirm_submitted()),
        }
    }
}

fn n3(original: &GtpuSessionGroup, qfi: u8) -> GtpuSessionGroup {
    GtpuSessionGroup::new(
        original.id(),
        original.device_id(),
        original
            .entries()
            .iter()
            .cloned()
            .map(|entry| entry.restore_n3_qfi(qfi).unwrap())
            .collect(),
    )
    .unwrap()
}

type RetiredFixture = (
    GtpuSessionSelectorNamespaceAuthority<SqliteSessionBackend>,
    Arc<FaultingSelectorBackend>,
    GtpuSessionSelectorRetiredClaim,
);

async fn retired_fixture(desired: GtpuSessionGroup) -> RetiredFixture {
    let authority = production_authority(desired.device_id()).await;
    let backend = Arc::new(FaultingSelectorBackend::default());
    authority.provision(backend.as_ref()).await.unwrap();
    let active = authority
        .reconcile_fresh(backend.clone(), desired.clone())
        .await
        .unwrap();
    let retired = authority
        .retire(backend.clone(), active, desired)
        .await
        .unwrap();
    (authority, backend, retired)
}

#[tokio::test]
async fn end_marker_requires_exact_bound_terminal_coordinate() {
    let (authority, _, retired) = retired_fixture(n3(&group(1, 1, 10, None), 0)).await;
    let (_, state) = authority.read_state().await.unwrap();
    let scope = authority.storage_scope_commitment;
    assert!(end_marker_source_is_current(&state, scope, &retired));
    assert!(!end_marker_source_is_current(&state, [0; 32], &retired));
    for lifecycle in [
        NamespaceLifecycle::Unprovisioned,
        NamespaceLifecycle::Provisioned,
        NamespaceLifecycle::Initializing,
        NamespaceLifecycle::Decommissioning,
        NamespaceLifecycle::Decommissioned,
    ] {
        let mut changed = state.clone();
        changed.lifecycle = lifecycle;
        assert!(!end_marker_source_is_current(&changed, scope, &retired));
    }
    for mutation in 0..8 {
        let mut changed = state.clone();
        let Some(GroupState::Retired {
            device,
            selectors,
            desired,
            generation,
            operation_nonce,
            retired_dataplane_generation,
            successor,
            ..
        }) = changed.groups.get_mut(&retired.admission.group_fingerprint)
        else {
            panic!("fixture must have a real terminal retirement");
        };
        match mutation {
            0 => device[0] ^= 1,
            1 => selectors[0] ^= 1,
            2 => desired[0] ^= 1,
            3 => *generation = inventory_generation(generation.get() + 1),
            4 => operation_nonce[0] ^= 1,
            5 => {
                *retired_dataplane_generation =
                    NonZeroU64::new(retired_dataplane_generation.get() + 1).unwrap();
            }
            6 => {
                *successor = Some(RetiredSuccessor {
                    group: [0x42; 32],
                    generation: inventory_generation(99),
                });
            }
            7 => {
                changed
                    .canonical_desired
                    .get_mut(&retired.admission.group_fingerprint)
                    .unwrap()[0] = 0xff;
            }
            _ => unreachable!(),
        }
        assert!(
            !end_marker_source_is_current(&changed, scope, &retired),
            "terminal mutation {mutation} must not authorize a send"
        );
    }
    for mutation in 0..5 {
        let mut changed = state.clone();
        match mutation {
            0 => changed.backend_epoch[0] ^= 1,
            1 => changed.pin_commitment[0] ^= 1,
            2 => changed.storage_scope_commitment[0] ^= 1,
            3 => changed.ledger_id[0] ^= 1,
            4 => changed.stable_device.as_mut().unwrap()[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(!end_marker_source_is_current(&changed, scope, &retired));
    }
}

#[tokio::test]
async fn end_marker_refuses_ordinary_retirement_and_preserves_recovery_on_unsupported_backend() {
    let (ordinary_authority, _, ordinary) = retired_fixture(group(1, 1, 10, None)).await;
    let (_, state) = ordinary_authority.read_state().await.unwrap();
    assert!(!end_marker_source_is_current(
        &state,
        ordinary_authority.storage_scope_commitment,
        &ordinary
    ));

    let desired = n3(&group(1, 1, 10, None), 63);
    let (authority, backend, retired) = retired_fixture(desired.clone()).await;
    assert!(matches!(
        authority
            .send_n3_end_markers(backend.clone(), retired)
            .await,
        Err(GtpuN3EndMarkerError::Unsupported)
    ));
    let recovered = authority.recover_retired(backend, desired).await.unwrap();
    let (_, state) = authority.read_state().await.unwrap();
    assert!(end_marker_source_is_current(
        &state,
        authority.storage_scope_commitment,
        &recovered
    ));
}

#[tokio::test]
async fn end_marker_refuses_shared_peer_teid_across_local_tuples_and_qfis() {
    for variant in 0..4 {
        let original = n3(&group(1, 1, 10, None), 0);
        let (authority, backend, retired) = retired_fixture(original.clone()).await;
        let other = group(2, 1, 20, Some(41));
        let mut context = other.entries()[0].context().clone();
        context.peer_teid = original.entries()[0].context().peer_teid;
        if variant == 1 {
            context.uplink_source_port_policy = GtpuUplinkSourcePortPolicy::Selected(40000);
        }
        let local = if variant == 2 {
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
        } else {
            other.entries()[0].local_outer_address()
        };
        let entry = GtpuSessionEntry::new(context, local).unwrap();
        let entry = if variant == 3 {
            entry // Even an ordinary group can still own the receiving tunnel.
        } else {
            entry.restore_n3_qfi(63).unwrap()
        };
        let other = GtpuSessionGroup::new(other.id(), other.device_id(), vec![entry]).unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), other.clone())
            .await
            .unwrap();
        let (_, state) = authority.read_state().await.unwrap();
        assert!(!end_marker_source_is_current(
            &state,
            authority.storage_scope_commitment,
            &retired
        ));
        let _other_retired = authority
            .retire(backend.clone(), active, other)
            .await
            .unwrap();
        let (_, state) = authority.read_state().await.unwrap();
        assert!(!end_marker_source_is_current(
            &state,
            authority.storage_scope_commitment,
            &retired
        ));
        assert!(matches!(
            authority.send_n3_end_markers(backend, retired).await,
            Err(GtpuN3EndMarkerError::Namespace)
        ));
    }
}

#[tokio::test]
async fn end_marker_cannot_follow_consumed_successor_even_after_its_retirement() {
    let original = n3(&group(1, 1, 10, None), 9);
    let (authority, backend, retired) = retired_fixture(original.clone()).await;
    let saved = authority
        .recover_retired(backend.clone(), original.clone())
        .await
        .unwrap();
    let successor = GtpuSessionGroup::new(
        GtpuSessionGroupId::new([2; 16]).unwrap(),
        original.device_id(),
        original.entries().to_vec(),
    )
    .unwrap();
    let reusable = authority
        .authorize_reuse(backend.clone(), successor.clone(), retired)
        .await
        .unwrap();
    let active = authority
        .reconcile_reused(backend.clone(), reusable)
        .await
        .unwrap();
    let _successor_retired = authority
        .retire(backend.clone(), active, successor)
        .await
        .unwrap();
    let (_, state) = authority.read_state().await.unwrap();
    assert!(!end_marker_source_is_current(
        &state,
        authority.storage_scope_commitment,
        &saved
    ));
    assert!(matches!(
        authority.send_n3_end_markers(backend, saved).await,
        Err(GtpuN3EndMarkerError::Namespace)
    ));
}

#[tokio::test]
async fn dropped_end_marker_receiver_keeps_namespace_owned_until_backend_settles() {
    let desired = n3(&group(1, 1, 10, None), 9);
    let (authority, backend, retired) = retired_fixture(desired.clone()).await;
    let saved = authority
        .recover_retired(backend.clone(), desired)
        .await
        .unwrap();
    backend.end_markers.mode.store(1, Ordering::SeqCst);
    backend.end_markers.hold.store(true, Ordering::SeqCst);
    let operation = authority.send_n3_end_markers(backend.clone(), retired);
    tokio::time::timeout(
        Duration::from_secs(3),
        backend.end_markers.entered.notified(),
    )
    .await
    .expect("owned backend operation must start");
    drop(operation);
    let permit = selector_namespace_worker(authority.storage_scope_commitment);
    assert_eq!(permit.available_permits(), 0);

    let mut next = authority.send_n3_end_markers(backend.clone(), saved);
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut next)
        .await
        .is_err());
    assert_eq!(backend.end_markers.calls.load(Ordering::SeqCst), 1);
    assert_eq!(permit.available_permits(), 0);
    backend.end_markers.release.notify_one();
    let completion = tokio::time::timeout(Duration::from_secs(3), next)
        .await
        .expect("settling the first worker must release the namespace")
        .unwrap();
    assert_eq!(backend.end_markers.calls.load(Ordering::SeqCst), 2);
    assert_eq!(completion.datagram_count(), 1);
    let retired = completion.into_retired_claim();
    let (_, state) = authority.read_state().await.unwrap();
    assert!(end_marker_source_is_current(
        &state,
        authority.storage_scope_commitment,
        &retired
    ));
}

#[tokio::test]
async fn failed_or_panicking_end_marker_backend_is_indeterminate_and_recoverable() {
    for mode in [2, 3] {
        let desired = n3(&group(1, 1, 10, None), 9);
        let (authority, backend, retired) = retired_fixture(desired.clone()).await;
        backend.end_markers.mode.store(mode, Ordering::SeqCst);
        assert!(matches!(
            authority
                .send_n3_end_markers(backend.clone(), retired)
                .await,
            Err(GtpuN3EndMarkerError::Backend)
        ));
        let recovered = authority
            .recover_retired(backend.clone(), desired)
            .await
            .unwrap();
        backend.end_markers.mode.store(1, Ordering::SeqCst);
        let completion = authority
            .send_n3_end_markers(backend, recovered)
            .await
            .unwrap();
        assert_eq!(completion.datagram_count(), 1);
        assert_eq!(
            format!("{completion:?}"),
            "GtpuN3EndMarkerCompletion(<redacted>)"
        );
    }
}

#[tokio::test]
async fn expired_end_marker_receipt_cannot_publish_completion() {
    let desired = n3(&group(1, 1, 10, None), 9);
    let (mut authority, backend, retired) = retired_fixture(desired.clone()).await;
    authority.lease_ttl = Duration::from_millis(500);
    backend.end_markers.mode.store(4, Ordering::SeqCst);
    assert!(matches!(
        authority
            .send_n3_end_markers(backend.clone(), retired)
            .await,
        Err(GtpuN3EndMarkerError::Backend)
    ));
    assert_eq!(backend.end_markers.calls.load(Ordering::SeqCst), 1);
    authority.lease_ttl = Duration::from_secs(30);
    drop(authority.recover_retired(backend, desired).await.unwrap());
}
