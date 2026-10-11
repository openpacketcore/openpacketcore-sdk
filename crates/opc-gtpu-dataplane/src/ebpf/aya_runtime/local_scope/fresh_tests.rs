use super::*;
use crate::local_scope_quorum::{child_key, execution, Quorum};
use opc_ipsec_xfrm::{
    ExclusiveNamespaceResetAcknowledgement, LinuxXfrmBackendConfig, LinuxXfrmDscpMarkingConfig,
    NamespaceBoundLinuxXfrmBackend, XfrmDscpLocalGraph,
};
use opc_local_kernel_lifecycle::{
    LocalKernelLifecycle, LocalResetParticipants, NoLocalCompanions, ScopeKernelAuthority,
};
use std::os::unix::fs::PermissionsExt;
use sys::tc::{ContainmentBank, LocalHookSpec, LocalKernelScope, LocalScopeSpec};

struct Cleanup(PathBuf, PathBuf);
pub(super) fn session_request(
    device: crate::GtpuSessionDeviceId,
    ifindex: u32,
    id: u8,
    selector: u8,
) -> crate::GtpuSessionGroup {
    use crate::*;
    let context = GtpPdpContext {
        local_teid: Teid::new(700 + u32::from(selector)).unwrap(),
        peer_teid: Teid::new(800 + u32::from(selector)).unwrap(),
        ms_address: std::net::IpAddr::from([10, 79, 0, selector]),
        peer_address: "192.0.2.2".parse().unwrap(),
        link_ifindex: ifindex,
        downlink_source_port_policy: GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        downlink_inner_mtu: None,
    };
    GtpuSessionGroup::new(
        GtpuSessionGroupId::new([id; 16]).unwrap(),
        device,
        vec![GtpuSessionEntry::new(context, "192.0.2.1".parse().unwrap()).unwrap()],
    )
    .unwrap()
}
fn marked_sa_request() -> opc_ipsec_xfrm::ScopedXfrmRequest {
    use opc_ipsec_xfrm::*;
    let source = IpAddress::Ipv4([127, 0, 0, 1]);
    let destination = IpAddress::Ipv4([127, 0, 0, 2]);
    let sa = SaParameters {
        selector: XfrmSelector::new(source, destination, 0),
        id: XfrmId {
            destination,
            spi: 4096,
            protocol: 50,
        },
        source_address: source,
        request_id: XfrmRequestId::new(79),
        auth: None,
        crypt: None,
        aead: Some((
            AeadAlgorithm::rfc4106_gcm_aes(128),
            KeyMaterial::new(vec![0x72; 20]),
        )),
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: Some(XfrmLookupMark::full(79)),
        output_mark: None,
        if_id: None,
        egress_dscp: Some(DscpCodepoint::new(46).unwrap()),
    };
    let policy = PolicyParameters {
        selector: sa.selector.clone(),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        mark: sa.mark,
        if_id: None,
        templates: vec![XfrmTemplate {
            id: XfrmId { spi: 0, ..sa.id },
            source_address: source,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
    };
    ScopedXfrmRequest::new(sa, policy).unwrap()
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_dir_all(&self.1);
    }
}
#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
fn native_fresh_gtpu_dscp_graphs_open_only_together_under_real_activation() {
    fresh_lifecycle(false, false, false);
}
#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
fn native_shutdown_owns_reset_after_caller_cancellation_while_draining() {
    fresh_lifecycle(true, false, false);
}
#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_sessions_keep_undo_publication_and_backpressure_owned() {
    fresh_lifecycle(false, true, false);
}
#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
fn native_arp_and_packets_cross_only_the_intended_lifecycle_boundaries() {
    fresh_lifecycle(false, false, true);
}
fn fresh_lifecycle(cancel_shutdown: bool, qualify_sessions: bool, packets: bool) {
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    let root = PathBuf::from(format!(
        "/sys/fs/bpf/opc-local-fresh-{}",
        std::process::id()
    ));
    let locks = std::env::temp_dir().join(format!("opc-local-fresh-lock-{}", std::process::id()));
    let _cleanup = Cleanup(root.clone(), locks.clone());
    for path in [&root, &locks] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let interface = if packets {
        super::packet_tests::setup();
        "core0"
    } else {
        "lo"
    };
    let ifindex = sys::ifindex_by_name(interface).unwrap();
    let slot =
        |hook, priority, protocol| TcSlot::new(ifindex, hook, 0, protocol, priority, 1).unwrap();
    let hooks = [TcHook::Ingress, TcHook::Egress]
        .map(|hook| {
            LocalHookSpec::new(
                ContainmentBank::new(slot(hook, 1, 0x806), slot(hook, 2, 3)).unwrap(),
                ContainmentBank::new(slot(hook, 3, 0x806), slot(hook, 4, 3)).unwrap(),
            )
            .unwrap()
        })
        .to_vec();
    let scope = LocalKernelScope::open(
        LocalScopeSpec::new(
            root.clone(),
            locks.join("guard"),
            [79; 16],
            hooks,
            vec![
                slot(TcHook::Ingress, 50, 3),
                slot(TcHook::Egress, 50, 3),
                slot(TcHook::Egress, 60, 3),
            ],
        )
        .unwrap(),
    )
    .unwrap();
    let gtpu_graph =
        crate::EbpfLocalGraph::new(format!("gtpu/{interface}").into(), ifindex, 50).unwrap();
    let dscp_graph =
        XfrmDscpLocalGraph::new(format!("dscp/{interface}").into(), ifindex, 60).unwrap();
    let lifecycle = LocalKernelLifecycle::new(
        scope.clone(),
        vec![Arc::new(gtpu_graph.clone()), Arc::new(dscp_graph.clone())],
        vec![],
        vec![ifindex],
    )
    .unwrap();
    let gtpu = crate::EbpfGtpuDataplaneBackend::for_local_scope(
        lifecycle.bind_graph(gtpu_graph.artifact()).unwrap(),
    )
    .unwrap();
    let mut dscp = LinuxXfrmDscpMarkingConfig::new([interface.to_owned()], 16).unwrap();
    dscp.bpffs_pin_root = root.join("dscp");
    let xfrm = NamespaceBoundLinuxXfrmBackend::for_local_scope(
        lifecycle.clone(),
        LinuxXfrmBackendConfig::default(),
        Some(dscp),
        ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state(),
    )
    .unwrap();
    let reset_owner = Arc::new(super::packet_tests::CheckedReset {
        inner: xfrm.local_reset_participant().unwrap(),
        verify_packets: std::sync::atomic::AtomicBool::new(false),
    });
    let participants = || {
        LocalResetParticipants::new(
            reset_owner.clone(),
            Arc::new(opc_route_steering::LinuxRouteSteeringBackend::new()),
            Arc::new(NoLocalCompanions::new(scope.clone())),
        )
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(lifecycle
            .observe_empty(participants())
            .await
            .unwrap()
            .is_some());
        let reset = lifecycle.reset(participants()).await.unwrap();
        if packets {
            super::packet_tests::check("closed");
        }
        super::abandon_tests::exercise(gtpu.inner.local_scope.as_ref().unwrap(), &reset).await;
        let profile = xfrm.admit_scoped_profile(&reset).await.unwrap();
        let quorum = Quorum::open().await;
        let authority = ScopeKernelAuthority::new(
            lifecycle.clone(),
            execution(),
            quorum.committed.clone(),
            quorum.authority.clone(),
            quorum.batches.clone(),
        )
        .await
        .unwrap();
        let activation = quorum.create_request(70).await;
        quorum.lose_next_commit_reply();
        assert!(authority
            .commit_activation(activation.clone(), child_key(70))
            .await
            .is_err());
        assert!(quorum.lost_commit_reply());
        quorum.set_available(true);
        while quorum
            .authority
            .current(execution().identity())
            .await
            .is_err()
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let effect = authority
            .commit_activation(activation, child_key(70))
            .await
            .unwrap();
        assert!(
            xfrm.install_scoped(&profile, effect.clone(), marked_sa_request())
                .await
                .is_err(),
            "a DSCP-bearing SA cannot precede its companion graph"
        );
        assert!(lifecycle.open(&reset, effect.clone()).await.is_err());
        let request = crate::CreateGtpDeviceEndpointSetRequest::new(
            crate::CreateGtpDeviceRequest::new(interface),
            crate::GtpuSessionDeviceId::new([7; GTPU_SESSION_GROUP_ID_LEN]).unwrap(),
            crate::GtpuLocalEndpointSet::new("192.0.2.1".parse().unwrap(), None).unwrap(),
        )
        .unwrap();
        let gtpu_ready = gtpu
            .rebuild_local_graph(&reset, request.clone())
            .await
            .expect("fresh GTP-U build");
        gtpu_ready.recheck().unwrap();
        assert!(
            lifecycle.open(&reset, effect.clone()).await.is_err(),
            "DSCP remains required"
        );
        let dscp_ready = xfrm
            .rebuild_scoped_dscp(&reset)
            .await
            .expect("fresh DSCP build");
        assert_eq!(dscp_ready.len(), 1);
        dscp_ready[0].recheck().unwrap();
        let sa_effect = authority
            .commit_activation(quorum.create_request(71).await, child_key(71))
            .await
            .unwrap();
        let sa_receipt = xfrm
            .install_scoped(&profile, sa_effect, marked_sa_request())
            .await
            .unwrap();
        assert!(xfrm.read_scoped(&sa_receipt).await.unwrap());
        let session_effect = authority
            .commit_activation(quorum.create_request(72).await, child_key(72))
            .await
            .unwrap();
        let session = session_request(request.device_id(), ifindex, 72, 1);
        let session_receipt = gtpu
            .install_scoped(&gtpu_ready, session_effect.clone(), session.clone())
            .await
            .expect("scoped GTP-U session");
        assert!(gtpu.read_scoped(&session_receipt).await.unwrap());
        let sibling_effect = authority
            .commit_activation(quorum.create_request(73).await, child_key(73))
            .await
            .unwrap();
        let sibling = gtpu
            .install_scoped(
                &gtpu_ready,
                sibling_effect,
                session_request(request.device_id(), ifindex, 73, 2),
            )
            .await
            .unwrap();
        let sibling = if qualify_sessions {
            super::session_tests::exercise(
                super::session_tests::Fixture {
                    backend: &gtpu,
                    graph: &gtpu_ready,
                    authority: &authority,
                    quorum: &quorum,
                    device: request.device_id(),
                    ifindex,
                },
                &session_receipt,
                sibling,
            )
            .await
        } else {
            sibling
        };
        assert!(!root
            .join("gtpu")
            .join(RECONCILER_CONTROL_DIRECTORY)
            .exists());
        for path in [
            root.join("gtpu"),
            root.join(format!("gtpu/{interface}")),
            root.join("dscp"),
            root.join(format!("dscp/{interface}")),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let completion = lifecycle.open(&reset, effect.clone()).await.unwrap();
        completion.recheck().unwrap();
        if packets {
            super::packet_tests::check("open");
        }
        quorum.set_available(false);
        lifecycle
            .open(&reset, effect.clone())
            .await
            .unwrap()
            .recheck()
            .unwrap();
        assert!(xfrm.read_scoped(&sa_receipt).await.unwrap());
        assert!(gtpu.read_scoped(&session_receipt).await.unwrap());
        gtpu.install_scoped(&gtpu_ready, session_effect, session)
            .await
            .unwrap();
        gtpu.remove_scoped(&session_receipt).await.unwrap();
        assert!(!gtpu.read_scoped(&session_receipt).await.unwrap());
        assert!(
            gtpu.read_scoped(&sibling).await.unwrap(),
            "unrelated healthy group survives exact undo"
        );
        assert!(xfrm.read_scoped(&sa_receipt).await.unwrap());
        assert_eq!(
            scope
                .inventory()
                .unwrap()
                .iter()
                .flat_map(|dump| dump.entries())
                .filter(|filter| !filter.is_summary())
                .count(),
            3,
            "steady state has exactly three data hooks and no containment"
        );
        gtpu.rebuild_local_graph(&reset, request)
            .await
            .unwrap()
            .recheck()
            .unwrap();
        xfrm.rebuild_scoped_dscp(&reset).await.unwrap();
        if packets {
            super::packet_tests::check("open");
            reset_owner
                .verify_packets
                .store(true, std::sync::atomic::Ordering::Release);
        }
        quorum.set_available(true);
        let replacement = if cancel_shutdown {
            let blocker = gtpu_ready.begin_operation().await.unwrap();
            let shutdown_authority = authority.clone();
            let shutdown_participants = participants();
            let shutdown = tokio::spawn(async move {
                shutdown_authority
                    .shutdown_local(shutdown_participants)
                    .await
            });
            while effect.recheck_local_execution().is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            shutdown.abort();
            assert!(shutdown.await.unwrap_err().is_cancelled());
            drop(blocker);
            while !gtpu_graph
                .inspect(&scope)
                .is_ok_and(|inventory| inventory.is_locally_empty())
                || !dscp_graph
                    .inspect(&scope)
                    .is_ok_and(|inventory| inventory.is_locally_empty())
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            lifecycle.reset(participants()).await.unwrap()
        } else {
            authority
                .shutdown_local(participants())
                .await
                .expect("contained normal shutdown")
        };
        assert!(completion.recheck().is_err());
        assert!(gtpu_ready.recheck().is_err());
        assert!(dscp_ready[0].recheck().is_err());
        replacement.startup_observation().unwrap();
        if packets {
            super::packet_tests::check("closed");
        }
        assert!(gtpu_graph.inspect(&scope).unwrap().is_locally_empty());
        assert!(dscp_graph.inspect(&scope).unwrap().is_locally_empty());
        drop(effect);
        drop(authority);
        assert!(
            matches!(
                ScopeKernelAuthority::new(
                    lifecycle.clone(),
                    execution(),
                    quorum.committed.clone(),
                    quorum.authority.clone(),
                    quorum.batches.clone()
                )
                .await,
                Err(opc_local_kernel_lifecycle::LocalEffectError::Closed)
            ),
            "reconstructing an adapter cannot reopen the closed local execution"
        );
        quorum.close().await;
    });
}
