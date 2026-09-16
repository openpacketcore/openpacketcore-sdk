//! Persisted child-profile bounds, corruption refusal and redaction.

use super::*;
use crate::testkit::GroupedGtpuDataplaneSimulation;
use opc_session_store::EncryptingSessionBackend;

type Protected = EncryptingSessionBackend<SqliteSessionBackend, opc_key::MemoryKeyProvider>;

struct Lab {
    authority: GtpuSessionSelectorNamespaceAuthority<Protected>,
    backend: Arc<GroupedGtpuDataplaneSimulation>,
    parent: GtpuSessionGroup,
    sibling: GtpuSessionGroup,
    child: GtpuSessionGroup,
}

async fn lab(capacity: usize) -> Lab {
    let tenant = TenantId::from_static("bearer-codec-fixture");
    let keys = Arc::new(opc_key::MemoryKeyProvider::new());
    keys.insert_active_key(
        opc_key::KeyId::new("bearer-fixture-key").unwrap(),
        opc_key::KeyPurpose::Session,
        tenant.clone(),
        opc_key::Zeroizing::new([0x68; 32]),
    )
    .unwrap();
    let store = SessionStore::new(EncryptingSessionBackend::new(
        Arc::new(SqliteSessionBackend::in_memory().unwrap()),
        keys,
        "bearer-codec-fixture",
    ));
    let backend = Arc::new(GroupedGtpuDataplaneSimulation::new().unwrap());
    let parent = group(1, 1, 0x1001, None);
    let sibling = group(2, 1, 0x1002, None);
    let child = group_with_paa(
        3,
        1,
        0x1003,
        parent.entries()[0].context().ms_address,
        Some(6),
    );
    let device = backend
        .create_device_with_endpoints(
            crate::CreateGtpDeviceEndpointSetRequest::new(
                crate::CreateGtpDeviceRequest::new("bearer-codec"),
                parent.device_id(),
                crate::GtpuLocalEndpointSet::new(parent.entries()[0].local_outer_address(), None)
                    .unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let rebind = |group: GtpuSessionGroup| {
        let mut context = group.entries()[0].context().clone();
        context.link_ifindex = device.ifindex;
        GtpuSessionGroup::new(
            group.id(),
            group.device_id(),
            vec![GtpuSessionEntry::new(context, group.entries()[0].local_outer_address()).unwrap()],
        )
        .unwrap()
    };
    let parent = rebind(parent);
    let sibling = rebind(sibling);
    let child = rebind(child);
    let authority = GtpuSessionSelectorNamespaceAuthority::provision_protected(
        store,
        SelectorLedgerStorageScope::new(tenant, NetworkFunctionKind::from_static("epdg")),
        backend
            .selector_namespace_bootstrap(parent.device_id())
            .await
            .unwrap(),
        backend.clone(),
        OwnerId::new("bearer-codec-worker").unwrap(),
        SELECTOR_NAMESPACE_MAX_LEASE_TTL,
        capacity,
    )
    .await
    .unwrap();
    for group in [&parent, &sibling] {
        drop(
            authority
                .reconcile_fresh(backend.clone(), group.clone())
                .await
                .unwrap(),
        );
    }
    Lab {
        authority,
        backend,
        parent,
        sibling,
        child,
    }
}

#[tokio::test]
async fn child_profile_capacity_counts_full_canonical_atoms_before_mutation() {
    let lab = lab(2).await;
    let before = lab.authority.read_state().await.unwrap().1.encode();
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    assert!(lab
        .authority
        .reconcile_bearer(
            lab.backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone()
        )
        .await
        .is_err());
    assert_eq!(lab.authority.read_state().await.unwrap().1.encode(), before);
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
    drop(
        lab.authority
            .recover_active(lab.backend, lab.parent)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn child_profile_persisted_legacy_global_mark_collision_is_rejected() {
    let lab = lab(3).await;
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    drop(
        lab.authority
            .reconcile_bearer(
                lab.backend.clone(),
                parent,
                lab.parent.clone(),
                lab.child.clone(),
            )
            .await
            .unwrap(),
    );
    let legacy = group_with_paa(
        4,
        1,
        0x1004,
        IpAddr::V4(Ipv4Addr::new(10, 23, 0, 99)),
        Some(7),
    );
    let mut context = legacy.entries()[0].context().clone();
    context.link_ifindex = lab.parent.entries()[0].context().link_ifindex;
    let legacy = GtpuSessionGroup::new(
        legacy.id(),
        legacy.device_id(),
        vec![GtpuSessionEntry::new(context, legacy.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap();
    drop(
        lab.authority
            .reconcile_fresh(lab.backend.clone(), legacy.clone())
            .await
            .unwrap(),
    );
    let mut corrupt = lab.authority.read_state().await.unwrap().1;
    assert!(NamespaceState::decode(&corrupt.encode()).is_some());
    let old = CanonicalClaim::from_group(&legacy)
        .with_key(&corrupt.selector_digest_key)
        .unwrap();
    let mut context = legacy.entries()[0].context().clone();
    context.bearer_mark = crate::GtpBearerMark::new(6);
    let overlapping = GtpuSessionGroup::new(
        legacy.id(),
        legacy.device_id(),
        vec![GtpuSessionEntry::new(context, legacy.entries()[0].local_outer_address()).unwrap()],
    )
    .unwrap();
    let new = CanonicalClaim::from_group(&overlapping)
        .with_key(&corrupt.selector_digest_key)
        .unwrap();
    let old_atoms = old.selector_atoms(&corrupt.selector_digest_key).unwrap();
    let new_atoms = new.selector_atoms(&corrupt.selector_digest_key).unwrap();
    assert_eq!(old_atoms.difference(&new_atoms).count(), 1);
    assert_eq!(new_atoms.difference(&old_atoms).count(), 1);
    let old_mark = *old_atoms.difference(&new_atoms).next().unwrap();
    let new_mark = *new_atoms.difference(&old_atoms).next().unwrap();
    let owner = corrupt.selectors.remove(&old_mark).unwrap();
    corrupt.selectors.insert(new_mark, owner);
    assert!(corrupt.published_atoms.remove(&old_mark));
    corrupt.published_atoms.insert(new_mark);
    corrupt
        .canonical_desired
        .insert(new.group_fingerprint, Zeroizing::new(new.desired.clone()));
    let GroupState::Active {
        selectors,
        desired,
        atoms,
        ..
    } = corrupt.groups.get_mut(&new.group_fingerprint).unwrap()
    else {
        panic!("fixture must have a live legacy group");
    };
    *selectors = new.selector_set_fingerprint;
    *desired = new.desired_fingerprint;
    *atoms = new_atoms;
    // Every individual descriptor and child relation is internally exact;
    // cross-profile global-mark exclusivity must still reject this record.
    assert!(corrupt.canonical_desired_index_is_exact());
    assert!(corrupt.bearer_relations_are_exact());
    assert!(!corrupt.mark_profiles_are_disjoint());
    assert!(NamespaceState::decode(&corrupt.encode()).is_none());
}

#[tokio::test]
async fn child_profile_persisted_relations_reject_corruption_and_keep_private_data_redacted() {
    let lab = lab(3).await;
    let parent = lab
        .authority
        .recover_active(lab.backend.clone(), lab.parent.clone())
        .await
        .unwrap();
    let active = lab
        .authority
        .reconcile_bearer(
            lab.backend.clone(),
            parent,
            lab.parent.clone(),
            lab.child.clone(),
        )
        .await
        .unwrap();
    let state = lab.authority.read_state().await.unwrap().1;
    let encoded = state.encode();
    assert_eq!(&encoded[..7], b"OPCSN18");
    assert_eq!(NamespaceState::decode(&encoded).unwrap().encode(), encoded);
    let child = CanonicalClaim::from_group(&lab.child)
        .with_key(&state.selector_digest_key)
        .unwrap();
    let parent = CanonicalClaim::from_group(&lab.parent)
        .with_key(&state.selector_digest_key)
        .unwrap();
    let sibling = CanonicalClaim::from_group(&lab.sibling)
        .with_key(&state.selector_digest_key)
        .unwrap();
    for owner in [
        child.group_fingerprint,
        sibling.group_fingerprint,
        [0x37; 32],
    ] {
        let mut corrupt = state.clone();
        corrupt
            .bearer_parents
            .insert(child.group_fingerprint, owner);
        assert!(NamespaceState::decode(&corrupt.encode()).is_none());
    }
    let mut missing = state.clone();
    missing.bearer_parents.clear();
    assert!(NamespaceState::decode(&missing.encode()).is_none());
    let mut nested = state.clone();
    nested
        .bearer_parents
        .insert(parent.group_fingerprint, child.group_fingerprint);
    assert!(NamespaceState::decode(&nested.encode()).is_none());
    let mut capacity = state.clone();
    capacity.capacity = 2;
    assert!(NamespaceState::decode(&capacity.encode()).is_none());
    for len in [encoded.len() - 1, encoded.len() - 32, encoded.len() - 64] {
        assert!(NamespaceState::decode(&encoded[..len]).is_none());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(NamespaceState::decode(&extra).is_none());
    let mut downgraded = encoded.clone();
    downgraded[..7].copy_from_slice(b"OPCSN17");
    assert!(NamespaceState::decode(&downgraded).is_none());
    let rendered = format!(
        "{:?} {:?} {:?}",
        active,
        lab.backend,
        lab.backend
            .selector_namespace_bootstrap(lab.parent.device_id())
            .await
            .unwrap()
    );
    for private in [
        "10.23.0.1",
        "192.0.2.10",
        "192.0.2.1",
        "4099",
        "bearer-fixture-key",
    ] {
        assert!(!rendered.contains(private));
    }
    // Terminal history retains the parent relation through an exact byte roundtrip.
    drop(
        lab.authority
            .retire(lab.backend.clone(), active, lab.child.clone())
            .await
            .unwrap(),
    );
    let retired = lab.authority.read_state().await.unwrap().1.encode();
    assert_eq!(NamespaceState::decode(&retired).unwrap().encode(), retired);
    drop(
        lab.authority
            .recover_retired(lab.backend.clone(), lab.child)
            .await
            .unwrap(),
    );
    drop(
        lab.authority
            .recover_active(lab.backend, lab.sibling)
            .await
            .unwrap(),
    );
}
