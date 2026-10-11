use super::*;
use opc_ipsec_xfrm::{
    AllocateSpiRequest, ExclusiveNamespaceResetAcknowledgement, InstallPolicyRequest, IpAddress,
    LinuxXfrmBackend, LinuxXfrmBackendConfig, LinuxXfrmDscpMarkingConfig,
    NamespaceBoundLinuxXfrmBackend, PolicyParameters, XfrmAction, XfrmBackend, XfrmDirection,
    XfrmDscpLocalGraph, XfrmSelector,
};
use opc_local_kernel_lifecycle::{
    LocalCompanionReset, LocalKernelLifecycle, LocalLifecycleError, LocalResetParticipants,
    LocalXfrmReset,
};
use opc_route_steering::{
    FirewallMark, IpPrefix, LinuxRouteSteeringBackend, OwnedRouteRuleScope, OwnedRouteRuleSet,
    RouteReadback, RouteRequest, RouteSteeringBackend, RouteSteeringIpFamily, RuleRequest,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use sys::tc::{
    ContainedScope, ContainmentBank, LocalHookSpec, LocalKernelScope, LocalScopeSpec, TcClient,
    TcVerdict,
};

struct Cleanup(PathBuf, PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_dir_all(&self.1);
    }
}

struct CheckedCompanions {
    scope: LocalKernelScope,
    xfrm: Arc<dyn LocalXfrmReset>,
    routes: Arc<LinuxRouteSteeringBackend>,
    owned: OwnedRouteRuleScope,
    completed: AtomicBool,
    interrupt: bool,
    attempts: AtomicUsize,
    egresses: [u32; 1],
}
#[async_trait::async_trait]
impl LocalCompanionReset for CheckedCompanions {
    fn local_scope(&self) -> &LocalKernelScope {
        &self.scope
    }
    fn plaintext_egresses(&self) -> &[u32] {
        &self.egresses
    }
    async fn is_empty(&self) -> Result<bool, LocalLifecycleError> {
        Ok(self.completed.load(Ordering::Acquire))
    }
    async fn reset_contained(&self, contained: &ContainedScope) -> Result<(), LocalLifecycleError> {
        contained.recheck()?;
        assert!(
            self.xfrm.is_empty().await.unwrap(),
            "SPD/SAD must already be absent"
        );
        let routes = self
            .routes
            .snapshot_owned_route_rules(self.owned)
            .await
            .unwrap();
        assert!(
            routes.routes().is_empty() && routes.rules().is_empty(),
            "owned routes/rules must retire before companion completion"
        );
        let dumps = self.scope.inventory()?;
        for slot in self.scope.spec().data_slots() {
            assert!(
                dumps.iter().any(|dump| dump.find(*slot).is_some()),
                "every GTP-U/DSCP hook must outlive companion cleanup"
            );
        }
        self.completed.store(true, Ordering::Release);
        let attempt = self.attempts.fetch_add(1, Ordering::AcqRel);
        if self.interrupt && attempt == 0 {
            return Err(LocalLifecycleError::Indeterminate);
        }
        assert!(
            !self.interrupt || attempt != 1,
            "injected reset panic after native XFRM/routes and companion completion"
        );
        Ok(())
    }
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
fn native_pinless_gtpu_and_dscp_retire_together_after_xfrm_routes_and_companions() {
    combined(false);
}
#[test]
#[ignore = "requires CAP_SYS_ADMIN/CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
fn native_recreated_bpffs_in_retained_namespace_resets_and_rebuilds_both_backends() {
    combined(true);
}
fn combined(replace_mount: bool) {
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let root = PathBuf::from(format!(
        "/sys/fs/bpf/opc-local-combined-{}",
        std::process::id()
    ));
    let locks =
        std::env::temp_dir().join(format!("opc-local-combined-lock-{}", std::process::id()));
    let _cleanup = Cleanup(root.clone(), locks.clone());
    let gtpu_leaf = root.join("gtpu/lo");
    for path in [
        &root,
        &root.join("gtpu"),
        &gtpu_leaf,
        &root.join("dscp"),
        &locks,
    ] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ifindex = sys::ifindex_by_name("lo").unwrap();
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    tc::qdisc_add_clsact("lo").unwrap();
    let mut old_gtpu = EbpfLoader::new()
        .default_map_pin_directory(&gtpu_leaf)
        .load(DATAPATH_OBJECT)
        .unwrap();
    let mut links = Vec::new();
    load_program(&mut old_gtpu, PROG_UPLINK).unwrap();
    let observer = old_gtpu
        .program(PROG_UPLINK)
        .unwrap()
        .fd()
        .unwrap()
        .try_clone()
        .unwrap();
    load_program(&mut old_gtpu, PROG_DOWNLINK).unwrap();
    for (name, direction) in [
        (PROG_UPLINK, TcAttachType::Egress),
        (PROG_DOWNLINK, TcAttachType::Ingress),
    ] {
        let program: &mut SchedClassifier = old_gtpu.program_mut(name).unwrap().try_into().unwrap();
        let link = program
            .attach_with_options(
                "lo",
                direction,
                TcAttachOptions::Netlink(NlOptions {
                    priority: 50,
                    handle: TC_HANDLE,
                    classid: None,
                }),
            )
            .unwrap();
        links.push(program.take_link(link).unwrap());
    }
    let mut dscp = LinuxXfrmDscpMarkingConfig::new(["lo".to_owned()], 16).unwrap();
    dscp.bpffs_pin_root = root.join("dscp");
    let old_dscp = LinuxXfrmBackend::with_dscp_marking(dscp.clone()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let routes = Arc::new(LinuxRouteSteeringBackend::new());
    let owned =
        OwnedRouteRuleScope::new(RouteSteeringIpFamily::Ipv4, 10001, ifindex, Some(10), 10001)
            .unwrap();
    let route = RouteRequest {
        destination: IpPrefix::new(std::net::Ipv4Addr::new(192, 0, 2, 0).into(), 24),
        oif_ifindex: ifindex,
        table: 10001,
        priority: Some(10),
        locked_mtu: None,
    };
    let mut foreign_route = route.clone();
    foreign_route.table = 10002;
    runtime.block_on(async {
        old_dscp
            .allocate_spi(AllocateSpiRequest {
                destination: IpAddress::Ipv4([192, 0, 2, 2]),
                protocol: 50,
                min_spi: 4097,
                max_spi: 4097,
            })
            .await
            .unwrap();
        old_dscp
            .install_policy(InstallPolicyRequest {
                parameters: PolicyParameters {
                    selector: XfrmSelector::new(
                        IpAddress::Ipv4([192, 0, 2, 1]),
                        IpAddress::Ipv4([192, 0, 2, 2]),
                        0,
                    ),
                    direction: XfrmDirection::Out,
                    action: XfrmAction::Block,
                    priority: 10001,
                    templates: vec![],
                    mark: None,
                    if_id: None,
                },
            })
            .await
            .unwrap();
        routes
            .reconcile_owned_route_rules(
                OwnedRouteRuleSet::new(
                    owned,
                    vec![route],
                    vec![RuleRequest {
                        source: None,
                        destination: None,
                        fwmark: Some(FirewallMark {
                            value: 1,
                            mask: u32::MAX,
                        }),
                        table: 10001,
                        priority: 10001,
                        family: Some(RouteSteeringIpFamily::Ipv4),
                    }],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        routes.converge_route(foreign_route.clone()).await.unwrap();
    });
    drop(old_gtpu);
    drop(old_dscp);
    if replace_mount {
        let namespace = fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
        let old_root = fs::File::open(&root).unwrap();
        let old_device = old_root.metadata().unwrap().dev();
        assert!(std::process::Command::new("umount")
            .args(["-l", "/sys/fs/bpf"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("mount")
            .args(["-t", "bpf", "-o", "mode=0700", "bpf", "/sys/fs/bpf"])
            .status()
            .unwrap()
            .success());
        for path in [&root, &root.join("gtpu"), &root.join("dscp")] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_ne!(fs::metadata(&root).unwrap().dev(), old_device);
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
            namespace
        );
        drop(old_root);
    } else {
        fs::remove_dir_all(&gtpu_leaf).unwrap();
        fs::remove_dir_all(root.join("dscp/lo")).unwrap();
    }

    let mut hooks = Vec::new();
    let mut slots = Vec::new();
    for direction in [TcHook::Ingress, TcHook::Egress] {
        let slot = |p, proto| TcSlot::new(ifindex, direction, 0, proto, p, 1).unwrap();
        hooks.push(
            LocalHookSpec::new(
                ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
                ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
            )
            .unwrap(),
        );
        slots.push(slot(50, 3));
    }
    slots.push(TcSlot::new(ifindex, TcHook::Egress, 0, 3, 60, 1).unwrap());
    let scope = LocalKernelScope::open(
        LocalScopeSpec::new(root, locks.join("guard"), [75; 16], hooks, slots).unwrap(),
    )
    .unwrap();
    let foreign_slot = TcSlot::new(ifindex, TcHook::Egress, 0, 3, 100, 9).unwrap();
    TcClient::new()
        .unwrap()
        .create_gact(foreign_slot, [99; 16], TcVerdict::Pass)
        .unwrap();
    let gtpu = Arc::new(crate::EbpfLocalGraph::new("gtpu/lo".into(), ifindex, 50).unwrap());
    let dscp_graph = Arc::new(XfrmDscpLocalGraph::new("dscp/lo".into(), ifindex, 60).unwrap());
    gtpu.inspect(&scope)
        .expect("complete pinless GTP-U predecessor");
    dscp_graph
        .inspect(&scope)
        .expect("complete pinless DSCP predecessor");
    let lifecycle = LocalKernelLifecycle::new(
        scope.clone(),
        vec![gtpu.clone(), dscp_graph.clone()],
        vec![owned],
        vec![ifindex],
    )
    .unwrap();
    let xfrm = NamespaceBoundLinuxXfrmBackend::for_local_scope(
        lifecycle.clone(),
        LinuxXfrmBackendConfig::default(),
        Some(dscp),
        ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state(),
    )
    .unwrap();
    let xfrm_port = xfrm.local_reset_participant().unwrap();
    let companions = Arc::new(CheckedCompanions {
        scope: scope.clone(),
        xfrm: xfrm_port.clone(),
        routes: routes.clone(),
        owned,
        completed: AtomicBool::new(false),
        interrupt: replace_mount,
        attempts: AtomicUsize::new(0),
        egresses: [ifindex],
    });
    let participants =
        || LocalResetParticipants::new(xfrm_port.clone(), routes.clone(), companions.clone());
    runtime.block_on(async {
        assert!(!xfrm_port.is_empty().await.unwrap());
        assert!(lifecycle
            .observe_empty(participants())
            .await
            .unwrap()
            .is_none());
        let receipt = lifecycle.reset(participants()).await.unwrap();
        assert!(companions.completed.load(Ordering::Acquire));
        assert_eq!(
            companions.attempts.load(Ordering::Acquire),
            if replace_mount { 3 } else { 1 }
        );
        assert!(gtpu.inspect(&scope).unwrap().is_locally_empty());
        assert!(dscp_graph.inspect(&scope).unwrap().is_locally_empty());
        assert!(
            receipt.residue_count().unwrap() > 0,
            "outside program FD must be diagnostic residue"
        );
        let backend = crate::EbpfGtpuDataplaneBackend::for_local_scope(
            lifecycle.bind_graph(gtpu.artifact()).unwrap(),
        )
        .unwrap();
        let request = crate::CreateGtpDeviceEndpointSetRequest::new(
            crate::CreateGtpDeviceRequest::new("lo"),
            crate::GtpuSessionDeviceId::new([9; GTPU_SESSION_GROUP_ID_LEN]).unwrap(),
            crate::GtpuLocalEndpointSet::new("127.0.0.1".parse().unwrap(), None).unwrap(),
        )
        .unwrap();
        backend
            .rebuild_local_graph(&receipt, request)
            .await
            .expect("harmless outside FD does not gate fresh GTP-U rebuild")
            .recheck()
            .unwrap();
        let rebuilt = xfrm
            .rebuild_scoped_dscp(&receipt)
            .await
            .expect("all graphs retired before fresh DSCP rebuild");
        assert_eq!(rebuilt.len(), 1);
        rebuilt[0].recheck().unwrap();
        let dumps = scope.inventory().unwrap();
        let neighbor = dumps
            .iter()
            .find_map(|dump| dump.find(foreign_slot))
            .unwrap();
        assert_eq!(neighbor.gact().unwrap().cookie(), &[99; 16]);
        assert_eq!(
            routes.read_route(&foreign_route).await.unwrap(),
            RouteReadback::ExactPresent
        );
        let before = receipt.residue_count().unwrap();
        drop(observer);
        assert_eq!(
            receipt.observe_release().unwrap(),
            before,
            "closing an outside FD does not prove global object release"
        );
    });
    drop(links);
}
