use super::*;
use aya::programs::{links::LinkOrder, Xdp, XdpMode};
use std::os::unix::fs::PermissionsExt;
use sys::tc::{
    ContainmentBank, LocalHookSpec, LocalKernelScope, LocalScopeSpec, TcClient, TcVerdict,
};

struct Cleanup(Vec<PathBuf>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}
#[test]
#[ignore = "requires TCX/XDP support, private bpffs/netns and CAP_BPF/CAP_NET_ADMIN"]
fn native_containment_refuses_live_tcx_xdp_and_earlier_foreign_classifiers() {
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    super::packet_tests::setup();
    let base = PathBuf::from(format!(
        "/sys/fs/bpf/opc-local-coverage-{}",
        std::process::id()
    ));
    let root = base.join("scope");
    let maps = base.join("foreign");
    let xdp_maps = base.join("xdp");
    let locks = std::env::temp_dir().join(format!("opc-local-coverage-{}", std::process::id()));
    let _cleanup = Cleanup(vec![base.clone(), locks.clone()]);
    for path in [&base, &root, &maps, &xdp_maps, &locks] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ifindex = sys::ifindex_by_name("core0").unwrap();
    let slot =
        |hook, priority, protocol| TcSlot::new(ifindex, hook, 0, protocol, priority, 1).unwrap();
    let hooks = [TcHook::Ingress, TcHook::Egress]
        .map(|hook| {
            LocalHookSpec::new(
                ContainmentBank::new(slot(hook, 10, 0x806), slot(hook, 20, 3)).unwrap(),
                ContainmentBank::new(slot(hook, 30, 0x806), slot(hook, 40, 3)).unwrap(),
            )
            .unwrap()
        })
        .to_vec();
    let scope = LocalKernelScope::open(
        LocalScopeSpec::new(root, locks.join("guard"), [84; 16], hooks, vec![]).unwrap(),
    )
    .unwrap();
    tc::qdisc_add_clsact("core0").unwrap();
    let mut tc = TcClient::new().unwrap();
    let neighbor = tc
        .create_gact(slot(TcHook::Egress, 90, 3), [88; 16], TcVerdict::Pass)
        .unwrap();
    let earlier = tc
        .create_gact(slot(TcHook::Ingress, 5, 3), [89; 16], TcVerdict::Pass)
        .unwrap();
    assert!(scope.inspect().is_err());
    assert!(scope.contain().is_err());
    assert_eq!(
        tc.dump(ifindex, TcHook::Ingress)
            .unwrap()
            .find(earlier.slot())
            .unwrap()
            .gact(),
        earlier.gact()
    );
    tc.delete_exact(&earlier).unwrap();

    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(&maps)
        .load(DATAPATH_OBJECT)
        .unwrap();
    for (name, hook) in [
        (PROG_DOWNLINK, TcAttachType::Ingress),
        (PROG_UPLINK, TcAttachType::Egress),
    ] {
        load_program(&mut ebpf, name).unwrap();
        let program: &mut SchedClassifier = ebpf.program_mut(name).unwrap().try_into().unwrap();
        let link = program
            .attach_with_options("core0", hook, TcAttachOptions::TcxOrder(LinkOrder::first()))
            .unwrap();
        assert!(
            scope.inspect().is_err(),
            "read-only inspection must query TCX on both hooks"
        );
        assert!(
            scope.contain().is_err(),
            "a live TCX program bypasses clsact containment"
        );
        program.detach(link).unwrap();
    }
    let object = aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../opc-ipsec-lb/bpf/opc-ipsec-lb-xdp.bpf.o"
    ));
    let mut xdp = EbpfLoader::new()
        .default_map_pin_directory(&xdp_maps)
        .load(object)
        .unwrap();
    let program: &mut Xdp = xdp
        .program_mut("opc_ipsec_lb_xdp")
        .unwrap()
        .try_into()
        .unwrap();
    program.load().unwrap();
    let link = program.attach("core0", XdpMode::Skb).unwrap();
    assert!(
        scope.inspect().is_err(),
        "read-only inspection must check ingress XDP"
    );
    assert!(
        scope.contain().is_err(),
        "a live ingress XDP program precedes every tc filter"
    );
    program.detach(link).unwrap();

    let hardware = std::process::Command::new("tc")
        .args([
            "filter", "add", "dev", "core0", "ingress", "protocol", "all", "pref", "80", "handle",
            "1", "matchall", "skip_sw", "action", "pass",
        ])
        .output()
        .unwrap();
    if hardware.status.success() {
        assert!(scope.inspect().is_err());
        assert!(
            scope.contain().is_err(),
            "a hardware-only classifier cannot prove software coverage"
        );
        assert!(std::process::Command::new("tc")
            .args([
                "filter", "del", "dev", "core0", "ingress", "protocol", "all", "pref", "80",
                "handle", "1", "matchall"
            ])
            .status()
            .unwrap()
            .success());
    } else {
        assert!(
            String::from_utf8_lossy(&hardware.stderr).contains("not supported"),
            "{}",
            String::from_utf8_lossy(&hardware.stderr)
        );
    }
    scope.contain().unwrap().recheck().unwrap();
    assert_eq!(
        tc.dump(ifindex, TcHook::Egress)
            .unwrap()
            .find(neighbor.slot())
            .unwrap()
            .gact(),
        neighbor.gact(),
        "foreign neighbor identity survives every refusal and successful containment"
    );
}
