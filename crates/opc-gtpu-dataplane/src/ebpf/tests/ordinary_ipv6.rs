//! Inner-IPv6 and IPv4v6 PDP contexts on an ordinary (non-grouped) eBPF
//! attachment. The attachment keeps its IPv4 S2b-U endpoint; each IPv6 context
//! is carried by the family-tagged tc authority as one single-entry record plus
//! its uplink `(/64, mark)` and downlink `(outer, inner, TEID)` selectors.

use super::*;
use crate::{PdpContextMismatchField, PdpContextSelectorOccupancy};
use opc_gtpu_ebpf_common::GtpuSessionPaa;

fn ipv6_prefix() -> Ipv6Addr {
    "2001:db8:45:1::".parse().unwrap()
}

fn ipv6_context() -> GtpPdpContext {
    GtpPdpContext {
        ms_address: IpAddr::V6(ipv6_prefix()),
        ..context()
    }
}

fn ipv6_config(state: &FakeState) -> Option<GtpuSessionDeviceConfig> {
    state
        .pinned_grouped_config
        .get(&PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu"))
        .and_then(GtpuSessionDeviceConfig::decode)
}

fn uplink_key(context: &GtpPdpContext) -> [u8; GTPU_SESSION_UPLINK_KEY_LEN] {
    let IpAddr::V6(address) = context.ms_address else {
        panic!("test helper requires an IPv6 context");
    };
    GtpuSessionUplinkKey::new(
        GtpuSessionPaa::new(GtpuEndpointAddress::Ipv6(address.octets())).unwrap(),
        context
            .bearer_mark
            .map_or([0; 4], |mark| mark.get().to_be_bytes()),
    )
    .encode()
}

fn downlink_key(context: &GtpPdpContext) -> [u8; GTPU_SESSION_DOWNLINK_KEY_LEN] {
    GtpuSessionDownlinkKey::new(
        GtpuSessionIpFamily::Ipv4,
        GtpuSessionIpFamily::Ipv6,
        context.local_teid.get().to_be_bytes(),
    )
    .unwrap()
    .encode()
}

fn local_selector(context: &GtpPdpContext) -> PdpContextSelector {
    PdpContextSelector::LocalTeid(PdpContextLocalTeidSelector::from_context(context).unwrap())
}

fn uplink_selector(context: &GtpPdpContext) -> PdpContextSelector {
    PdpContextSelector::Uplink(PdpContextUplinkSelector::from_context(context).unwrap())
}

#[tokio::test]
async fn ordinary_attachment_installs_reads_and_removes_an_inner_ipv6_context() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let desired = ipv6_context();

    assert_eq!(
        backend
            .install_pdp_context_classified(desired.clone())
            .await
            .unwrap(),
        PdpContextInstallOutcome::Installed
    );
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&desired))
            .await
            .unwrap(),
        PdpContextReadback::Present(desired.clone())
    );
    assert_eq!(
        backend
            .read_pdp_context(uplink_selector(&desired))
            .await
            .unwrap(),
        PdpContextReadback::Present(desired.clone())
    );
    {
        let state = runtime.state();
        let config = ipv6_config(&state).expect("ordinary IPv6 authority is initialized");
        assert_eq!(config.ingress_ifindex(), S2BU_IFINDEX);
        assert_eq!(
            config.local_endpoint(GtpuSessionIpFamily::Ipv4),
            Some(GtpuEndpointAddress::Ipv4([192, 0, 2, 1]))
        );
        assert_eq!(config.local_endpoint(GtpuSessionIpFamily::Ipv6), None);
        let reference = state
            .session_uplink_index
            .get(&(S2BU_IFINDEX, uplink_key(&desired)))
            .copied()
            .expect("uplink /64 selector");
        assert_eq!(
            state
                .session_downlink_index
                .get(&(S2BU_IFINDEX, downlink_key(&desired)))
                .copied(),
            Some(reference),
            "both selectors name one exact authority"
        );
        let reference = GtpuSessionGroupRef::decode(&reference).unwrap();
        let record = GtpuSessionGroupRecord::decode(
            state
                .session_groups
                .get(&(S2BU_IFINDEX, reference.group_id().to_bytes()))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record.phase(), GtpuSessionGroupPhase::Active);
        assert_eq!(record.device_id(), config.device_id());
        assert!(record.entry(GtpuSessionIpFamily::Ipv4).is_none());
        let entry = record.entry(GtpuSessionIpFamily::Ipv6).unwrap();
        assert!(entry.inner_paa().contains(GtpuEndpointAddress::Ipv6(
            "2001:db8:45:1:a:b:c:d"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
        )));
        assert!(!entry.inner_paa().contains(GtpuEndpointAddress::Ipv6(
            "2001:db8:45:2::1".parse::<Ipv6Addr>().unwrap().octets()
        )));
        assert_eq!(
            entry.outer_family(),
            GtpuSessionIpFamily::Ipv4,
            "IPv6 inner traffic keeps the attachment's IPv4 transport"
        );
        assert!(
            state.far.is_empty() && state.pdr.is_empty() && state.sport.is_empty(),
            "an IPv6 context never occupies the IPv4 v5 maps"
        );
    }

    assert_eq!(
        backend
            .install_pdp_context_classified(desired.clone())
            .await
            .unwrap(),
        PdpContextInstallOutcome::ExactAlreadyPresent
    );
    assert_eq!(
        backend
            .remove_pdp_context_exact(desired.clone())
            .await
            .unwrap(),
        PdpContextRemovalOutcome::Removed
    );
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&desired))
            .await
            .unwrap(),
        PdpContextReadback::Absent
    );
    assert_eq!(
        backend
            .read_pdp_context(uplink_selector(&desired))
            .await
            .unwrap(),
        PdpContextReadback::Absent
    );
    let state = runtime.state();
    assert!(state.session_groups.is_empty());
    assert!(state.session_uplink_index.is_empty());
    assert!(state.session_downlink_index.is_empty());
}

#[tokio::test]
async fn ordinary_ipv4v6_contexts_share_one_bearer_teid_per_family() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let ipv4 = context();
    let ipv6 = ipv6_context();
    assert_eq!(ipv4.local_teid, ipv6.local_teid);

    backend.install_pdp_context(ipv4.clone()).await.unwrap();
    backend.install_pdp_context(ipv6.clone()).await.unwrap();
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv4))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv4.clone())
    );
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv6))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv6.clone())
    );

    // A family-scoped removal must never remove the other family's context.
    backend
        .remove_pdp_context(RemovePdpContextRequest::from_context(&ipv6))
        .await
        .unwrap();
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv6))
            .await
            .unwrap(),
        PdpContextReadback::Absent
    );
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv4))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv4.clone())
    );

    backend.install_pdp_context(ipv6.clone()).await.unwrap();
    backend
        .remove_pdp_context(RemovePdpContextRequest::from_context(&ipv4))
        .await
        .unwrap();
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv4))
            .await
            .unwrap(),
        PdpContextReadback::Absent
    );
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv6))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv6)
    );
    assert!(runtime.state().far.is_empty());
}

#[tokio::test]
async fn ordinary_ipv6_marked_bearers_share_one_prefix() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let default = ipv6_context();
    let mut dedicated = ipv6_context();
    dedicated.local_teid = teid(0x1000_0002);
    dedicated.peer_teid = teid(0x2000_0002);
    dedicated.bearer_mark = GtpBearerMark::new(0x51);
    dedicated.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());

    for context in [&default, &dedicated] {
        assert_eq!(
            backend
                .install_pdp_context_classified(context.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed
        );
    }
    for context in [&default, &dedicated] {
        assert_eq!(
            backend
                .read_pdp_context(uplink_selector(context))
                .await
                .unwrap(),
            PdpContextReadback::Present(context.clone())
        );
    }
    assert_eq!(runtime.state().session_groups.len(), 2);
    assert_eq!(
        backend
            .remove_pdp_context_exact(dedicated.clone())
            .await
            .unwrap(),
        PdpContextRemovalOutcome::Removed
    );
    assert_eq!(
        backend
            .read_pdp_context(uplink_selector(&default))
            .await
            .unwrap(),
        PdpContextReadback::Present(default)
    );
}

#[tokio::test]
async fn ordinary_ipv6_conflicts_are_classified_without_mutation() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let installed = ipv6_context();
    backend
        .install_pdp_context_classified(installed.clone())
        .await
        .unwrap();
    let before = {
        let state = runtime.state();
        (
            state.session_groups.clone(),
            state.session_uplink_index.clone(),
            state.session_downlink_index.clone(),
        )
    };

    let mut other_prefix = installed.clone();
    other_prefix.ms_address = IpAddr::V6("2001:db8:45:2::".parse().unwrap());
    let PdpContextInstallOutcome::Conflict(conflict) = backend
        .install_pdp_context_classified(other_prefix)
        .await
        .unwrap()
    else {
        panic!("the occupied local TEID must conflict");
    };
    assert_eq!(conflict.occupied(), PdpContextSelectorOccupancy::LocalTeid);
    assert_eq!(conflict.mismatches(), &[PdpContextMismatchField::MsAddress]);

    let mut other_peer_teid = installed.clone();
    other_peer_teid.peer_teid = teid(0x2000_0009);
    let PdpContextInstallOutcome::Conflict(conflict) = backend
        .install_pdp_context_classified(other_peer_teid.clone())
        .await
        .unwrap()
    else {
        panic!("the occupied selectors must conflict");
    };
    assert_eq!(conflict.occupied(), PdpContextSelectorOccupancy::Both);
    assert!(matches!(
        backend
            .remove_pdp_context_exact(other_peer_teid)
            .await
            .unwrap(),
        PdpContextRemovalOutcome::Conflict(_)
    ));

    let state = runtime.state();
    assert_eq!(
        (
            state.session_groups.clone(),
            state.session_uplink_index.clone(),
            state.session_downlink_index.clone(),
        ),
        before
    );
}

#[tokio::test]
async fn ordinary_ipv6_rejects_non_canonical_or_unsupported_addressing() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();

    let mut with_interface_identifier = ipv6_context();
    with_interface_identifier.ms_address = IpAddr::V6("2001:db8:45:1::7".parse().unwrap());
    assert!(matches!(
        backend.install_pdp_context(with_interface_identifier).await,
        Err(GtpuError::InvalidConfig { .. })
    ));

    let mut multicast = ipv6_context();
    multicast.ms_address = IpAddr::V6("ff0e::".parse().unwrap());
    assert!(matches!(
        backend.install_pdp_context(multicast).await,
        Err(GtpuError::InvalidConfig { .. })
    ));

    let mut outer_ipv6 = ipv6_context();
    outer_ipv6.peer_address = IpAddr::V6("2001:db8:20::1".parse().unwrap());
    assert!(matches!(
        backend.install_pdp_context(outer_ipv6).await,
        Err(GtpuError::UnsupportedFeature { .. })
    ));

    let state = runtime.state();
    assert!(state.session_groups.is_empty());
    assert!(
        ipv6_config(&state).is_none(),
        "a rejected request never initializes the IPv6 authority"
    );
}

#[tokio::test]
async fn ordinary_ipv6_install_completes_an_interrupted_publication() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let desired = ipv6_context();
    backend.install_pdp_context(desired.clone()).await.unwrap();

    // Model an install interrupted after both selectors were published but
    // before the authority record: the selectors fail closed in tc.
    {
        let mut state = runtime.state();
        let reference = GtpuSessionGroupRef::decode(
            state
                .session_uplink_index
                .get(&(S2BU_IFINDEX, uplink_key(&desired)))
                .unwrap(),
        )
        .unwrap();
        state
            .session_groups
            .remove(&(S2BU_IFINDEX, reference.group_id().to_bytes()));
    }
    assert!(matches!(
        backend.read_pdp_context(local_selector(&desired)).await,
        Err(GtpuError::StateIndeterminate { .. })
    ));
    assert!(matches!(
        backend
            .install_pdp_context_classified(desired.clone())
            .await
            .unwrap(),
        PdpContextInstallOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
    ));
    backend.install_pdp_context(desired.clone()).await.unwrap();
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&desired))
            .await
            .unwrap(),
        PdpContextReadback::Present(desired.clone())
    );

    // A removal interrupted after the authority was deleted is completed by
    // the family-scoped removal request.
    {
        let mut state = runtime.state();
        state.session_groups.clear();
    }
    backend
        .remove_pdp_context(RemovePdpContextRequest::from_context(&desired))
        .await
        .unwrap();
    let state = runtime.state();
    assert!(state.session_uplink_index.is_empty());
    assert!(state.session_downlink_index.is_empty());
}

#[tokio::test]
async fn ordinary_ipv6_state_survives_backend_restart() {
    let runtime = Arc::new(FakeRuntime::new());
    let desired = ipv6_context();
    {
        let backend = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(desired.clone()).await.unwrap();
    }
    // Model a process restart: pins survive, the tc attachment is re-adopted.
    suspend_fake_attachment(&mut runtime.state(), S2BU_IFINDEX);
    let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
    restarted.resolve_device("s2bu").await.unwrap();
    assert_eq!(
        restarted
            .read_pdp_context(local_selector(&desired))
            .await
            .unwrap(),
        PdpContextReadback::Present(desired.clone())
    );
    assert_eq!(
        restarted.remove_pdp_context_exact(desired).await.unwrap(),
        PdpContextRemovalOutcome::Removed
    );
}

#[tokio::test]
async fn ordinary_backend_reports_inner_ipv6_capability() {
    let (backend, _runtime) = backend_with_fake();
    assert_eq!(
        backend.pdp_inner_ipv6_capability(),
        GtpuCapability::Available
    );
}

#[tokio::test]
async fn cleanup_only_recovery_removes_stale_ordinary_ipv6_contexts() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let ipv4 = context();
    let ipv6 = ipv6_context();
    for stale in [&ipv4, &ipv6] {
        assert_eq!(
            backend
                .install_pdp_context_classified(stale.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed
        );
    }
    simulate_process_loss(&runtime, false);

    let recovered = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
    assert_eq!(
        recovered
            .acquire_cleanup_only_recovery(cleanup_request(
                Ipv4Addr::new(192, 0, 2, 1),
                S2BU_IFINDEX,
            ))
            .await
            .unwrap(),
        RetainedGraphCleanupClassification::Acquired,
        "the ordinary attachment's own inner-IPv6 authority is cleanup authority"
    );
    assert!(!runtime.state().uplink_filter_ready.contains(&S2BU_IFINDEX));
    assert_eq!(
        recovered
            .read_pdp_context(local_selector(&ipv6))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv6.clone())
    );
    for stale in [&ipv6, &ipv4] {
        assert_eq!(
            recovered
                .remove_pdp_context_exact(stale.clone())
                .await
                .unwrap(),
            PdpContextRemovalOutcome::Removed
        );
    }
    let state = runtime.state();
    assert!(state.session_groups.is_empty());
    assert!(state.session_uplink_index.is_empty());
    assert!(state.session_downlink_index.is_empty());
}

#[tokio::test]
async fn cleanup_only_recovery_still_refuses_a_grouped_journal_on_an_ordinary_graph() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    backend
        .install_pdp_context_classified(ipv6_context())
        .await
        .unwrap();
    runtime.state().session_transactions.insert(
        (S2BU_IFINDEX, [0x5a; GTPU_SESSION_GROUP_ID_LEN]),
        [0; GTPU_SESSION_TRANSACTION_VALUE_LEN],
    );
    simulate_process_loss(&runtime, false);

    let recovered = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
    assert_eq!(
        recovered
            .acquire_cleanup_only_recovery(cleanup_request(
                Ipv4Addr::new(192, 0, 2, 1),
                S2BU_IFINDEX,
            ))
            .await
            .unwrap(),
        RetainedGraphCleanupClassification::Refused(RetainedGraphCleanupRefusal::NotCurrentSchema),
        "a grouped transaction journal is a different writer domain"
    );
}

#[tokio::test]
async fn ipv6_scoped_removal_never_reaches_the_ipv4_context_on_the_same_teid() {
    let (backend, _runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let ipv4 = context();
    backend.install_pdp_context(ipv4.clone()).await.unwrap();

    backend
        .remove_pdp_context(RemovePdpContextRequest {
            address_family: GtpAddressFamily::Ipv6,
            ..RemovePdpContextRequest::from_context(&ipv4)
        })
        .await
        .unwrap();
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv4))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv4)
    );
}

fn second_ipv6_context() -> GtpPdpContext {
    GtpPdpContext {
        ms_address: IpAddr::V6("2001:db8:45:2::".parse().unwrap()),
        local_teid: Teid::new(context().local_teid.get() + 1).unwrap(),
        ..context()
    }
}

fn ordinary_authority_present(state: &FakeState) -> (bool, bool) {
    let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
    (
        state.pinned_grouped_config.contains_key(&pin_dir),
        state.grouped_schema_ready.contains(&pin_dir),
    )
}

/// The family-tagged authority exists only while an inner-IPv6 context does.
/// Removing the last one retires it, so a drained graph is identical to one
/// that never carried inner IPv6 (legacy terminal-successor recovery requires
/// both slots zero).
#[tokio::test]
async fn ordinary_ipv6_authority_is_retired_with_the_last_inner_ipv6_context() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let ipv4 = context();
    let first = ipv6_context();
    let second = second_ipv6_context();
    for desired in [&ipv4, &first, &second] {
        backend.install_pdp_context(desired.clone()).await.unwrap();
    }
    assert_eq!(ordinary_authority_present(&runtime.state()), (true, true));
    assert_eq!(
        backend.remove_pdp_context_exact(first).await.unwrap(),
        PdpContextRemovalOutcome::Removed
    );
    assert_eq!(
        ordinary_authority_present(&runtime.state()),
        (true, true),
        "another inner-IPv6 context still needs the authority"
    );
    assert_eq!(
        backend
            .remove_pdp_context_exact(second.clone())
            .await
            .unwrap(),
        PdpContextRemovalOutcome::Removed
    );
    assert_eq!(ordinary_authority_present(&runtime.state()), (false, false));
    // IPv4 is untouched, and a later inner-IPv6 install initializes afresh.
    assert_eq!(
        backend
            .read_pdp_context(local_selector(&ipv4))
            .await
            .unwrap(),
        PdpContextReadback::Present(ipv4)
    );
    assert_eq!(
        backend
            .install_pdp_context_classified(second)
            .await
            .unwrap(),
        PdpContextInstallOutcome::Installed
    );
    assert_eq!(ordinary_authority_present(&runtime.state()), (true, true));
}

/// A drained authority left by an interrupted retirement is retired by the
/// next inner-IPv6 removal on that attachment, even for an absent context.
#[tokio::test]
async fn ordinary_ipv6_removal_completes_an_interrupted_retirement() {
    for schema_written in [true, false] {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let config = GtpuSessionDeviceConfig::new(
            GtpuSessionDeviceId::new([0x42; GTPU_SESSION_GROUP_ID_LEN]).unwrap(),
            S2BU_IFINDEX,
            Some([192, 0, 2, 1]),
            None,
        )
        .unwrap();
        {
            let mut state = runtime.state();
            let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
            state
                .pinned_grouped_config
                .insert(pin_dir.clone(), config.encode());
            if schema_written {
                state.grouped_schema_ready.insert(pin_dir);
            }
        }
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&ipv6_context()))
            .await
            .unwrap();
        assert_eq!(
            ordinary_authority_present(&runtime.state()),
            (false, false),
            "schema written: {schema_written}"
        );
    }
}

/// Exact retry must finish authority retirement even when a crash left no
/// selector to remove, including on a fenced cleanup-only attachment.
#[tokio::test]
async fn exact_ipv6_removal_completes_interrupted_retirement() {
    for cleanup_only in [false, true] {
        for schema_written in [false, true] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let config = GtpuSessionDeviceConfig::new(
                GtpuSessionDeviceId::new([0x42; GTPU_SESSION_GROUP_ID_LEN]).unwrap(),
                S2BU_IFINDEX,
                Some([192, 0, 2, 1]),
                None,
            )
            .unwrap();
            {
                let mut state = runtime.state();
                let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
                state
                    .pinned_grouped_config
                    .insert(pin_dir.clone(), config.encode());
                if schema_written {
                    state.grouped_schema_ready.insert(pin_dir);
                }
            }
            let backend = if cleanup_only {
                simulate_process_loss(&runtime, false);
                let recovered = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
                assert_eq!(
                    recovered
                        .acquire_cleanup_only_recovery(cleanup_request(
                            Ipv4Addr::new(192, 0, 2, 1),
                            S2BU_IFINDEX,
                        ))
                        .await
                        .unwrap(),
                    RetainedGraphCleanupClassification::Acquired
                );
                recovered
            } else {
                backend
            };
            assert_eq!(
                backend
                    .remove_pdp_context_exact(ipv6_context())
                    .await
                    .unwrap(),
                PdpContextRemovalOutcome::AlreadyAbsent
            );
            assert_eq!(
                ordinary_authority_present(&runtime.state()),
                (false, false),
                "cleanup-only: {cleanup_only}, schema written: {schema_written}"
            );
            assert_eq!(
                backend
                    .remove_pdp_context_exact(ipv6_context())
                    .await
                    .unwrap(),
                PdpContextRemovalOutcome::AlreadyAbsent,
                "a completed retry remains idempotent"
            );
        }
    }
}

/// A crash between the authority's config and schema writes leaves a
/// config-only authority with nothing published. Cleanup-only recovery
/// accepts it as the ordinary attachment's own authority, exactly as the
/// ordinary install path resumes it.
#[tokio::test]
async fn cleanup_only_recovery_accepts_a_config_only_ordinary_authority() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let config = GtpuSessionDeviceConfig::new(
        GtpuSessionDeviceId::new([0x42; GTPU_SESSION_GROUP_ID_LEN]).unwrap(),
        S2BU_IFINDEX,
        Some([192, 0, 2, 1]),
        None,
    )
    .unwrap();
    runtime.state().pinned_grouped_config.insert(
        PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu"),
        config.encode(),
    );
    simulate_process_loss(&runtime, false);

    let recovered = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
    assert_eq!(
        recovered
            .acquire_cleanup_only_recovery(cleanup_request(
                Ipv4Addr::new(192, 0, 2, 1),
                S2BU_IFINDEX,
            ))
            .await
            .unwrap(),
        RetainedGraphCleanupClassification::Acquired
    );
}

/// Whichever selector write an interrupted publication completed, the
/// family-scoped removal by local TEID finds and removes it: no uplink
/// selector can be orphaned beyond the downlink selector's reach.
#[tokio::test]
async fn ordinary_ipv6_teid_removal_leaves_no_selector_after_an_interrupted_publication() {
    for failed_put in ["session_uplink_put", "session_downlink_put"] {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let desired = ipv6_context();
        runtime.fail_in_order([failed_put]);
        assert!(
            backend.install_pdp_context(desired.clone()).await.is_err(),
            "{failed_put}"
        );
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&desired))
            .await
            .unwrap();
        let state = runtime.state();
        assert!(state.session_groups.is_empty(), "{failed_put}");
        assert!(state.session_uplink_index.is_empty(), "{failed_put}");
        assert!(state.session_downlink_index.is_empty(), "{failed_put}");
    }
}

/// A failed final retirement must not report `Removed`: one transient failure is
/// completed in the same call, a persistent one stays retryable.
#[tokio::test]
async fn exact_ipv6_removal_reports_a_failed_retirement() {
    for failures in [1, 2] {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let first = ipv6_context();
        backend.install_pdp_context(first.clone()).await.unwrap();
        for _ in 0..failures {
            runtime
                .state()
                .failures
                .push_back("retire_ordinary_family_authority");
        }
        let outcome = backend
            .remove_pdp_context_exact(first.clone())
            .await
            .unwrap();
        let present = ordinary_authority_present(&runtime.state());
        if failures == 1 {
            assert_eq!(outcome, PdpContextRemovalOutcome::Removed);
            assert_eq!(present, (false, false));
        } else {
            assert_eq!(
                outcome,
                PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::MutationUnconfirmed
                )
            );
            assert_eq!(present, (true, true));
            assert_eq!(
                backend
                    .remove_pdp_context_exact(first.clone())
                    .await
                    .unwrap(),
                PdpContextRemovalOutcome::AlreadyAbsent
            );
            assert_eq!(ordinary_authority_present(&runtime.state()), (false, false));
        }
    }
}
