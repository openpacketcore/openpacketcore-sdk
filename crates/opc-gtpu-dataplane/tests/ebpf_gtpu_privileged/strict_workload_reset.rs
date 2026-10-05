use super::*;
use opc_gtpu_dataplane::EbpfStrictWorkloadResetReport;
use std::io::Read;
use std::net::{TcpListener, TcpStream};

const EXCLUSION: &str = "GTPU_CURRENT_HISTORICAL_25_EXCLUSION_V1";

#[allow(clippy::await_holding_lock)]
pub(super) async fn predecessor_priority_with_and_without_pins(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for pins in [true, false] {
        for selector in [false, true] {
            let net = TestNet::provision();
            let scoped = WorkloadTestScope::new();
            let root = scoped.scope.bpffs_pin_root();
            let graph = root.join("s2bu");
            install_exclusive_predecessor(&graph, "s2bu", 53)?;
            // This foreign filter shares the predecessor's classifier. Only
            // the predecessor's handles may be removed at another priority.
            run(
                "tc",
                &[
                    "filter",
                    "add",
                    "dev",
                    "s2bu",
                    "ingress",
                    "pref",
                    "53",
                    "protocol",
                    "all",
                    "handle",
                    "2",
                    "bpf",
                    "bytecode",
                    "1,6 0 0 0",
                    "action",
                    "pass",
                ],
            );
            let foreign_id = String::from_utf8(filters("s2bu", "ingress"))?
                .lines()
                .find(|line| line.contains("handle 0x2"))
                .unwrap()
                .to_owned();
            if !pins {
                for entry in fs::read_dir(&graph)? {
                    fs::remove_file(entry?.path())?;
                }
                fs::remove_dir(&graph)?;
            }
            if selector {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(root.join(format!("SELECTOR_AUTHORITY_V1_{}", "a".repeat(64))))?;
            }
            let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
            assert_counts(
                backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?,
                usize::from(selector),
                0,
                0,
            );
            assert!(!tc_filters("ingress").contains("opc_gtpu"));
            assert!(!tc_filters("egress").contains("opc_gtpu"));
            assert!(String::from_utf8(filters("s2bu", "ingress"))?.contains(&foreign_id));
            assert_workload_attach_forwards(&backend, &net).await?;
        }
    }
    // Scope entries and map references still locate the SDK's own hooks on
    // other interfaces. Unknown map pin names must not hide those hooks.
    for declared in [true, false] {
        let net = TestNet::provision();
        let _other = ExclusiveTestInterface::new(std::ffi::OsStr::new("other0"));
        let scoped = WorkloadTestScope::new();
        let graph = scoped
            .scope
            .bpffs_pin_root()
            .join(if declared { "other0" } else { "s2bu" });
        install_exclusive_predecessor(&graph, "other0", 53)?;
        if !declared {
            for entry in fs::read_dir(&graph)? {
                let entry = entry?;
                fs::rename(
                    entry.path(),
                    graph.join(format!("UNKNOWN_{}", entry.file_name().to_str().unwrap())),
                )?;
            }
        }
        let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        assert_counts(
            backend
                .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?,
            0,
            0,
            0,
        );
        assert!(!String::from_utf8(filters("other0", "ingress"))?.contains("opc_gtpu"));
        assert!(!String::from_utf8(filters("other0", "egress"))?.contains("opc_gtpu"));
        assert_workload_attach_forwards(&backend, &net).await?;
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn alternative_name_without_pins() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    run(
        "ip",
        &["link", "property", "add", "dev", "s2bu", "altname", "s2alt"],
    );
    let scoped = WorkloadTestScope::new();
    let graph = scoped.scope.bpffs_pin_root().join("s2bu");
    install_exclusive_predecessor(&graph, "s2bu", 53)?;
    for entry in fs::read_dir(&graph)? {
        fs::remove_file(entry?.path())?;
    }
    fs::remove_dir(&graph)?;
    let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
    assert_counts(
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, "s2alt")
            .await?,
        0,
        0,
        0,
    );
    assert_workload_attach_forwards(&backend, &net).await?;
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn interrupted_exclusion_publication() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    let scoped = WorkloadTestScope::new();
    let root = scoped.scope.bpffs_pin_root();
    let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
    backend
        .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
        .await?;
    let marker = ordinary_exclusion(&root, "s2bu");
    let identity = fs::metadata(&marker).map(|m| (m.dev(), m.ino()))?;
    let legacy = marker
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let staging = root.join("GTPU_RECONCILER_LOCKS").join(format!(
        "{legacy}-current-historical-25-exclusion-v1-{}",
        "a".repeat(32)
    ));
    create_test_owned_private_directory_tree(&staging, "interrupted staging directory");
    create_test_owned_private_directory_tree(
        &staging.join(EXCLUSION),
        "interrupted exclusion publication",
    );
    assert_counts(
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
            .await?,
        0,
        0,
        0,
    );
    assert!(!staging.exists());
    assert_eq!(fs::metadata(&marker).map(|m| (m.dev(), m.ino()))?, identity);
    assert_counts(
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
            .await?,
        0,
        0,
        0,
    );
    assert_workload_attach_forwards(&backend, &net).await?;
    Ok(())
}

const FOREIGN_PROGRAM: &str = "foreign_uplink0";

fn foreign_program(
    graph: &Path,
    wrong_capacity: bool,
) -> Result<aya::Ebpf, Box<dyn std::error::Error>> {
    create_test_owned_private_directory_tree(graph, "foreign program maps");
    let mut object = FROZEN_PRE_REDIRECT_OBJECT.to_vec();
    assert_eq!(PROG_UPLINK.len(), FOREIGN_PROGRAM.len());
    let mut renamed = 0;
    for offset in 0..=object.len() - PROG_UPLINK.len() {
        if &object[offset..offset + PROG_UPLINK.len()] == PROG_UPLINK.as_bytes() {
            object[offset..offset + PROG_UPLINK.len()].copy_from_slice(FOREIGN_PROGRAM.as_bytes());
            renamed += 1;
        }
    }
    assert!(renamed > 0);
    let mut loader = EbpfLoader::new();
    loader.default_map_pin_directory(graph);
    if wrong_capacity {
        loader.map_max_entries(MAP_UPLINK_FAR, 1);
    }
    let mut ebpf = loader.load(&object)?;
    let program: &mut SchedClassifier = ebpf.program_mut(FOREIGN_PROGRAM).unwrap().try_into()?;
    program.load()?;
    Ok(ebpf)
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn map_reference_authority() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // An unknown name and a known name with the wrong definition are both
    // foreign. Matching both makes this a product scope map, regardless of the
    // program's name; a foreign program on another interface must then refuse.
    for (pin_name, map_name, wrong_capacity, named) in [
        ("UNKNOWN_MAP", MAP_UPLINK_FAR, false, false),
        (MAP_UPLINK_FAR, MAP_CONFIG, false, false),
        (MAP_UPLINK_FAR, MAP_UPLINK_FAR, true, false),
        (MAP_UPLINK_FAR, MAP_UPLINK_FAR, false, false),
        (MAP_UPLINK_FAR, MAP_UPLINK_FAR, false, true),
    ] {
        let net = TestNet::provision();
        let _other = ExclusiveTestInterface::new(std::ffi::OsStr::new("other0"));
        let scoped = WorkloadTestScope::new();
        let outside = net.pin_root.join("foreign_maps");
        let mut ebpf = foreign_program(&outside, wrong_capacity)?;
        let interface = if named { "s2bu" } else { "other0" };
        ensure_clsact(interface);
        let program: &mut SchedClassifier =
            ebpf.program_mut(FOREIGN_PROGRAM).unwrap().try_into()?;
        let map_ids = program.info()?.map_ids()?.unwrap();
        let link = program.attach_with_options(
            interface,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                priority: 53,
                handle: TcHandle::new(0, 7),
                classid: None,
            }),
        )?;
        std::mem::forget(program.take_link(link)?);
        let before = filters(interface, "ingress");
        assert!(String::from_utf8_lossy(&before).contains(FOREIGN_PROGRAM));
        assert!(!String::from_utf8_lossy(&before).contains("opc_gtpu"));
        let graph = scoped.scope.bpffs_pin_root().join("s2bu");
        create_test_owned_private_directory_tree(&graph, "scope map alias");
        let pin = graph.join(pin_name);
        let map = MapData::from_pin(outside.join(map_name))?;
        let map_id = map.info()?.id();
        map.pin(&pin)?;
        assert!(map_ids.contains(&map_id));
        drop(map);
        drop(ebpf);
        let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        let own_map = pin_name == MAP_UPLINK_FAR && map_name == MAP_UPLINK_FAR && !wrong_capacity;
        if own_map && !named {
            assert!(matches!(
                backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await,
                Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_exclusive_workload_external_program_reference"
                })
            ));
            assert!(pin.exists());
            assert_eq!(filters(interface, "ingress"), before);
            run(
                "tc",
                &["filter", "del", "dev", interface, "ingress", "pref", "53"],
            );
        } else {
            assert_counts(
                backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?,
                0,
                usize::from(named),
                0,
            );
            assert!(!pin.exists());
            if named {
                assert!(
                    !String::from_utf8(filters(interface, "ingress"))?.contains(FOREIGN_PROGRAM)
                );
            } else {
                assert_eq!(filters(interface, "ingress"), before);
            }
        }
        assert_counts(
            backend
                .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?,
            0,
            0,
            0,
        );
        assert_workload_attach_forwards(&backend, &net).await?;
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn foreign_pinned_link_releases_other_interface(
) -> Result<(), Box<dyn std::error::Error>> {
    use aya::programs::links::{FdLink, LinkOrder};
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    let _other = ExclusiveTestInterface::new(std::ffi::OsStr::new("other0"));
    let scoped = WorkloadTestScope::new();
    let pin = scoped.scope.bpffs_pin_root().join("foreign_link");
    let mut ebpf = foreign_program(&net.pin_root.join("foreign_maps"), false)?;
    let program: &mut SchedClassifier = ebpf.program_mut(FOREIGN_PROGRAM).unwrap().try_into()?;
    match program.attach_with_options(
        "other0",
        TcAttachType::Egress,
        TcAttachOptions::TcxOrder(LinkOrder::first()),
    ) {
        Ok(link) => {
            let link: FdLink = program.take_link(link)?.try_into()?;
            drop(link.pin(&pin)?);
        }
        Err(aya::programs::ProgramError::SyscallError(error))
            if matches!(error.io_error.raw_os_error(), Some(22 | 95))
                && aya::util::KernelVersion::current()?
                    < aya::util::KernelVersion::new(6, 6, 0) =>
        {
            eprintln!("kernel does not support TCX links; foreign pinned-link case unavailable");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    drop(ebpf);
    assert_eq!(
        SchedClassifier::query_tcx("other0", TcAttachType::Egress)?
            .1
            .len(),
        1
    );
    let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
    assert_counts(
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
            .await?,
        0,
        0,
        0,
    );
    assert!(!pin.exists());
    assert!(SchedClassifier::query_tcx("other0", TcAttachType::Egress)?
        .1
        .is_empty());
    println!("OPC_GTPU_STRICT_PINNED_LINK_EXERCISED");
    assert_workload_attach_forwards(&backend, &net).await?;
    Ok(())
}

fn assert_counts(
    report: EbpfStrictWorkloadResetReport,
    selectors: usize,
    filters: usize,
    exclusions: usize,
) {
    assert_eq!(report.selector_markers, selectors);
    assert_eq!(report.tc_filters, filters);
    assert_eq!(report.exclusion_marker_directories, exclusions);
}

fn ordinary_exclusion(root: &Path, interface: &str) -> PathBuf {
    let legacy_name = Sha256::digest(interface.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    root.join("GTPU_RECONCILER_LOCKS")
        .join(legacy_name)
        .join(EXCLUSION)
}

async fn attach_interfaces(
    backend: &EbpfGtpuDataplaneBackend,
    interfaces: [&str; 2],
) -> Result<(), GtpuError> {
    let mut devices = Vec::new();
    for interface in interfaces {
        let mut request = CreateGtpDeviceRequest::new(interface);
        request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        devices.push(backend.create_device(request).await?);
    }
    for device in devices {
        backend.remove_device(&device).await?;
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn absent_interfaces_and_interruption() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    for names in [["reset_a", "reset_b"], ["reset_b", "reset_a"]] {
        let scoped = WorkloadTestScope::new();
        let root = scoped.scope.bpffs_pin_root();
        let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, names[0])
            .await?;
        let marker = ordinary_exclusion(&root, names[0]);
        let identity = fs::metadata(&marker).map(|m| (m.dev(), m.ino()))?;
        let _second = ExclusiveTestInterface::new(std::ffi::OsStr::new(names[1]));
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, names[1])
            .await?;
        assert_eq!(fs::metadata(&marker).map(|m| (m.dev(), m.ino()))?, identity);
        let _first = ExclusiveTestInterface::new(std::ffi::OsStr::new(names[0]));
        attach_interfaces(&backend, names).await?;

        // An interrupted finish can leave the other interface's retained lock
        // without its marker after its graph has already disappeared.
        let other_marker = ordinary_exclusion(&root, names[1]);
        fs::remove_dir(&other_marker)?;
        let partial = root.join("interrupted_layout");
        create_test_owned_private_directory_tree(&partial, "interrupted strict reset");
        synthetic_workload_pin(&partial.join("remaining_pin"))?;
        assert_counts(
            backend
                .reset_strict_exclusive_workload_graph(scoped.scope, names[0])
                .await?,
            0,
            0,
            0,
        );
        assert!(other_marker.is_dir());
        assert!(!partial.exists());
        attach_interfaces(&backend, names).await?;
    }

    // A new namespace may reset every intended name before creating any link.
    // This order must work independently of interface enumeration.
    let scoped = WorkloadTestScope::new();
    let scope = scoped.scope;
    in_netns(&net.ue_ns, move || {
        run("ip", &["address", "add", "192.0.2.1/32", "dev", "lo"]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let backend = EbpfGtpuDataplaneBackend::for_workload(scope);
            for name in ["reset_a", "reset_b"] {
                assert_counts(
                    backend
                        .reset_strict_exclusive_workload_graph(scope, name)
                        .await
                        .unwrap(),
                    0,
                    0,
                    0,
                );
            }
            let _first = ExclusiveTestInterface::new(std::ffi::OsStr::new("reset_a"));
            let _second = ExclusiveTestInterface::new(std::ffi::OsStr::new("reset_b"));
            attach_interfaces(&backend, ["reset_a", "reset_b"])
                .await
                .unwrap();
        });
    });
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn entire_priority_then_attach() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    ensure_clsact("s2bu");
    run(
        "tc",
        &[
            "filter", "add", "dev", "s2bu", "ingress", "pref", "49", "handle", "1", "matchall",
            "action", "pass",
        ],
    );
    let other_priority = filters("s2bu", "ingress");
    for case in ["u32", "protocol", "bpf", "chain"] {
        for strict in [false, true] {
            let scoped = WorkloadTestScope::new();
            let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
            let mut command = vec!["filter", "add", "dev", "s2bu", "ingress", "pref", "50"];
            match case {
                "u32" => command.extend([
                    "protocol", "all", "u32", "match", "u32", "0", "0", "action", "pass",
                ]),
                "protocol" => command.extend([
                    "protocol", "ip", "handle", "1", "matchall", "action", "pass",
                ]),
                "bpf" => command.extend([
                    "protocol",
                    "all",
                    "handle",
                    "2",
                    "bpf",
                    "bytecode",
                    "1,6 0 0 0",
                    "action",
                    "pass",
                ]),
                "chain" => command.extend([
                    "chain", "7", "protocol", "all", "handle", "1", "matchall", "action", "pass",
                ]),
                _ => unreachable!(),
            }
            run("tc", &command);
            let before = filters("s2bu", "ingress");
            if !strict {
                backend
                    .reset_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?;
                assert_eq!(
                    filters("s2bu", "ingress"),
                    before,
                    "ordinary reset must retain {case}"
                );
            }
            let report = backend
                .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?;
            // u32 exposes its hash table and its rule as separate filter entries.
            assert_counts(report, 0, if case == "u32" { 2 } else { 1 }, 0);
            assert_eq!(
                filters("s2bu", "ingress"),
                other_priority,
                "configured priority must be empty after {case}"
            );
            assert_workload_attach_forwards(&backend, &net).await?;
        }
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn scope_entry_does_not_grant_foreign_filter_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    let _other = ExclusiveTestInterface::new(std::ffi::OsStr::new("other0"));
    foreign_filter("other0", "ingress", "0", "all");
    let before = filters("other0", "ingress");
    let scoped = WorkloadTestScope::new();
    let entry = scoped.scope.bpffs_pin_root().join("other0");
    synthetic_workload_pin(&entry)?;
    let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
    assert_counts(
        backend
            .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
            .await?,
        0,
        0,
        0,
    );
    assert!(!entry.exists());
    assert_eq!(filters("other0", "ingress"), before);
    assert_workload_attach_forwards(&backend, &net).await?;
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn selector_marker_shapes() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for prefix in [
        "SELECTOR_AUTHORITY_V1_",
        "SELECTOR_DECOMMISSIONED_V1_",
        "SELECTOR_TERMINAL_FENCE_V1_",
    ] {
        for plain_pin in [false, true] {
            let scoped = WorkloadTestScope::new();
            let marker = scoped
                .scope
                .bpffs_pin_root()
                .join(format!("{prefix}{}", "b".repeat(64)));
            if plain_pin {
                synthetic_workload_pin(&marker)?;
            } else {
                fs::DirBuilder::new().mode(0o700).create(&marker)?;
            }
            let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
            assert!(matches!(
                backend
                    .reset_exclusive_workload_graph(scoped.scope, "absent0")
                    .await,
                Err(GtpuError::UnsupportedFeature {
                    feature: "workload_cleanup_bound_selector_namespace"
                })
            ));
            assert!(marker.exists());
            assert_counts(
                backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "absent0")
                    .await?,
                1,
                0,
                0,
            );
            assert!(!marker.exists());
            assert_counts(
                backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "absent0")
                    .await?,
                0,
                0,
                0,
            );
        }
    }
    Ok(())
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn owned_restart_reports_zero() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    for stopped_cleanly in [false, true] {
        let scoped = WorkloadTestScope::new();
        let owner = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        let mut request = CreateGtpDeviceRequest::new("s2bu");
        request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let device = owner.create_device(request).await?;
        if stopped_cleanly {
            owner.remove_device(&device).await?;
        }
        drop(owner);
        let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        assert_counts(
            backend
                .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?,
            0,
            0,
            0,
        );
        assert_counts(
            backend
                .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?,
            0,
            0,
            0,
        );
        assert_workload_attach_forwards(&backend, &net).await?;
    }
    Ok(())
}

fn operation_and_writer(root: &Path) -> (PathBuf, PathBuf) {
    let controls = root.join("GTPU_RECONCILER_LOCKS");
    let operation = fs::read_dir(&controls)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.to_str().unwrap().ends_with("-operation-v1"))
        .unwrap();
    let writer = controls.join(
        operation
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .trim_end_matches("-operation-v1"),
    );
    (operation, writer)
}

fn foreign_filter(interface: &str, direction: &str, chain: &str, protocol: &str) {
    ensure_clsact(interface);
    run(
        "tc",
        &[
            "filter", "add", "dev", interface, direction, "chain", chain, "protocol", protocol,
            "pref", "50", "handle", "1", "matchall", "action", "pass",
        ],
    );
}

fn filters(interface: &str, direction: &str) -> Vec<u8> {
    let result = Command::new("tc")
        .args(["filter", "show", "dev", interface, direction])
        .output()
        .unwrap();
    assert!(result.status.success());
    result.stdout
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn layout_matrix_and_forwarding() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    let neighbor = WorkloadTestScope::new();
    let neighbor_pin = neighbor.scope.bpffs_pin_root().join("neighbor");
    synthetic_workload_pin(&neighbor_pin)?;
    let neighbor_id = MapInfo::from_pin(&neighbor_pin)?.id();
    let _other = ExclusiveTestInterface::new(std::ffi::OsStr::new("other0"));
    foreign_filter("other0", "ingress", "7", "all");
    let other_before = filters("other0", "ingress");
    in_netns(&net.pgw_ns, || {
        foreign_filter("s2bup", "egress", "7", "all")
    });
    let remote_before = in_netns(&net.pgw_ns, || filters("s2bup", "egress"));

    // Each selector class alone, the two other layouts alone, and all together.
    for layout in [1_u8, 2, 4, 8, 16, 31] {
        for strict in [false, true] {
            let scoped = WorkloadTestScope::new();
            let root = scoped.scope.bpffs_pin_root();
            let backend = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
            backend
                .reset_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?;
            let (operation, writer) = operation_and_writer(&root);
            let lock_identities = [&operation, &writer]
                .map(|path| fs::metadata(path).map(|m| (m.dev(), m.ino())).unwrap());
            let mut markers = Vec::new();
            for (bit, prefix, parent) in [
                (1, "SELECTOR_AUTHORITY_V1_", &writer),
                (2, "SELECTOR_DECOMMISSIONED_V1_", &root),
                (4, "SELECTOR_TERMINAL_FENCE_V1_", &operation),
            ] {
                if layout & bit != 0 {
                    let path = parent.join(format!("{prefix}{}", "b".repeat(64)));
                    fs::DirBuilder::new().mode(0o700).create(&path)?;
                    synthetic_workload_pin(&path.join("partial_record"))?;
                    markers.push(path);
                }
            }
            if layout & 8 != 0 {
                // Both directions, nonzero chains and a non-ETH_P_ALL protocol.
                for (direction, chain, protocol) in [
                    ("ingress", "7", "all"),
                    ("egress", "9", "all"),
                    ("ingress", "11", "ip"),
                ] {
                    foreign_filter("s2bu", direction, chain, protocol);
                }
            }
            let mut exclusions = Vec::new();
            if layout & 16 != 0 {
                for parent in [&root, &writer, &operation] {
                    let path = parent.join(EXCLUSION);
                    fs::DirBuilder::new().mode(0o700).create(&path)?;
                    let nested = path.join("nested").join(EXCLUSION);
                    create_test_owned_private_directory_tree(
                        &path.join("nested"),
                        "exclusion contents",
                    );
                    create_test_owned_private_directory_tree(&nested, "nested exclusion");
                    synthetic_workload_pin(&nested.join("residue"))?;
                    exclusions.push(path);
                }
            }
            let hook_before = [filters("s2bu", "ingress"), filters("s2bu", "egress")];
            if strict {
                let report = backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?;
                assert_eq!(report.selector_markers, (layout & 7).count_ones() as usize);
                assert_eq!(report.tc_filters, if layout & 8 != 0 { 3 } else { 0 });
                assert_eq!(
                    report.exclusion_marker_directories,
                    if layout & 16 != 0 { 6 } else { 0 }
                );
                assert!(markers.iter().chain(&exclusions).all(|path| !path.exists()));
                let repeated = backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?;
                assert_counts(repeated, 0, 0, 0);
                assert_workload_attach_forwards(&backend, &net).await?;
            } else {
                let result = backend
                    .reset_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await;
                if layout & 7 != 0 {
                    assert!(
                        matches!(
                            result,
                            Err(GtpuError::UnsupportedFeature {
                                feature: "workload_cleanup_bound_selector_namespace"
                            })
                        ),
                        "{result:?}"
                    );
                    assert!(markers.iter().all(|path| path.exists()));
                    assert_eq!(
                        [filters("s2bu", "ingress"), filters("s2bu", "egress")],
                        hook_before
                    );
                } else {
                    result?;
                    let mut request = CreateGtpDeviceRequest::new("s2bu");
                    request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
                    let error = backend.create_device(request).await.unwrap_err();
                    if layout & 8 != 0 {
                        assert!(matches!(error, GtpuError::AlreadyExists), "{error:?}");
                        assert_eq!(
                            [filters("s2bu", "ingress"), filters("s2bu", "egress")],
                            hook_before
                        );
                    }
                    if layout & 16 != 0 {
                        assert!(
                            matches!(
                                error,
                                GtpuError::StateIndeterminate {
                                    operation: "ebpf_selector_marker_unknown"
                                }
                            ),
                            "{error:?}"
                        );
                        assert!(
                            writer.join(EXCLUSION).exists() && operation.join(EXCLUSION).exists()
                        );
                    }
                }
                // Finish the fixture with the authorized strict lifecycle.
                backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?;
            }
            assert_eq!(
                [&operation, &writer]
                    .map(|path| fs::metadata(path).map(|m| (m.dev(), m.ino())).unwrap()),
                lock_identities
            );
            assert_eq!(MapInfo::from_pin(&neighbor_pin)?.id(), neighbor_id);
            assert_eq!(filters("other0", "ingress"), other_before);
            assert_eq!(
                in_netns(&net.pgw_ns, || filters("s2bup", "egress")),
                remote_before
            );
        }
    }
    Ok(())
}

async fn reset(
    backend: &EbpfGtpuDataplaneBackend,
    scope: opc_gtpu_dataplane::EbpfWorkloadScope,
    strict: bool,
) -> Result<EbpfStrictWorkloadResetReport, GtpuError> {
    if strict {
        backend
            .reset_strict_exclusive_workload_graph(scope, "s2bu")
            .await
    } else {
        backend
            .reset_exclusive_workload_graph(scope, "s2bu")
            .await
            .map(|()| EbpfStrictWorkloadResetReport::default())
    }
}

fn guard_residue(root: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), Box<dyn std::error::Error>> {
    let (operation, writer) = operation_and_writer(root);
    let mut selectors = Vec::new();
    for (parent, prefix) in [
        (writer.as_path(), "SELECTOR_AUTHORITY_V1_"),
        (root, "SELECTOR_DECOMMISSIONED_V1_"),
        (operation.as_path(), "SELECTOR_TERMINAL_FENCE_V1_"),
    ] {
        let marker = parent.join(format!("{prefix}{}", "b".repeat(64)));
        fs::DirBuilder::new().mode(0o700).create(&marker)?;
        synthetic_workload_pin(&marker.join("partial_record"))?;
        selectors.push(marker);
    }
    let mut exclusions = Vec::new();
    for parent in [root, &writer, &operation] {
        let marker = parent.join(EXCLUSION);
        create_test_owned_private_directory_tree(&marker, "foreign guard exclusion");
        let nested = marker.join("nested").join(EXCLUSION);
        create_test_owned_private_directory_tree(
            &marker.join("nested"),
            "guard exclusion contents",
        );
        create_test_owned_private_directory_tree(&nested, "nested guard exclusion");
        synthetic_workload_pin(&nested.join("residue"))?;
        exclusions.push(marker);
    }
    for (direction, chain, protocol) in [
        ("ingress", "7", "all"),
        ("egress", "9", "all"),
        ("ingress", "11", "ip"),
    ] {
        foreign_filter("s2bu", direction, chain, protocol);
    }
    Ok((selectors, exclusions))
}

fn failure_parts(error: &GtpuError) -> (&GtpuError, EbpfStrictWorkloadResetReport) {
    match error {
        GtpuError::StrictWorkloadResetIncomplete { source, report, .. } => (source, *report),
        error => (error, EbpfStrictWorkloadResetReport::default()),
    }
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn writer_and_reference_guards() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    // Re-execute this fixture to retain a program descriptor in another live
    // process. Socket acknowledgement proves acquisition before parent reset.
    if let Ok(socket) = env::var("OPC_RESET_REFERENCE_SOCKET") {
        let id = env::var("OPC_RESET_REFERENCE_PROGRAM")?.parse::<u32>()?;
        let _program = loaded_programs()
            .map(Result::unwrap)
            .find(|info| info.id() == id)
            .unwrap()
            .fd()?;
        let mut stream = TcpStream::connect(socket)?;
        stream.write_all(&[1])?;
        stream.read_exact(&mut [0])?;
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let net = TestNet::provision();
    for strict in [false, true] {
        let scoped = WorkloadTestScope::new();
        let root = scoped.scope.bpffs_pin_root();
        let graph = root.join("s2bu");
        let owner = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        let mut request = CreateGtpDeviceRequest::new("s2bu");
        request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        owner.create_device(request).await?;
        let (selectors, exclusions) = guard_residue(&root)?;
        let replacement = EbpfGtpuDataplaneBackend::for_workload(scoped.scope);
        let before = pin_directory_listing(&graph);
        let hooks = [tc_filters("ingress"), tc_filters("egress")];
        assert!(matches!(
            reset(&replacement, scoped.scope, strict).await,
            Err(GtpuError::RetryRequired {
                operation: "ebpf_workload_cleanup_writer_busy"
            })
        ));
        assert!(matches!(
            reset(&owner, scoped.scope, strict).await,
            Err(GtpuError::AlreadyExists)
        ));
        assert_eq!(pin_directory_listing(&graph), before);
        assert_eq!([tc_filters("ingress"), tc_filters("egress")], hooks);
        assert!(selectors
            .iter()
            .chain(&exclusions)
            .all(|path| path.exists()));
        drop(owner);
        let (operation, _) = operation_and_writer(&root);
        let held = fs::File::open(operation)?;
        rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        assert!(matches!(
            reset(&replacement, scoped.scope, strict).await,
            Err(GtpuError::RetryRequired {
                operation: "ebpf_workload_cleanup_writer_busy"
            })
        ));
        drop(held);

        if !strict {
            // Selector refusal precedes the reference check in the ordinary
            // lifecycle. Pin that refusal before removing only these fixture
            // markers to exercise its reference guard with the other layouts.
            assert!(matches!(
                reset(&replacement, scoped.scope, false).await,
                Err(GtpuError::UnsupportedFeature {
                    feature: "workload_cleanup_bound_selector_namespace"
                })
            ));
            assert!(selectors
                .iter()
                .chain(&exclusions)
                .all(|path| path.exists()));
            assert_eq!([tc_filters("ingress"), tc_filters("egress")], hooks);
            for marker in &selectors {
                fs::remove_file(marker.join("partial_record"))?;
                fs::remove_dir(marker)?;
            }
        }

        let map_id = MapInfo::from_pin(graph.join(MAP_UPLINK_FAR))?.id();
        let program_id = loaded_programs()
            .map(Result::unwrap)
            .find(|info| {
                info.map_ids()
                    .unwrap()
                    .is_some_and(|ids| ids.contains(&map_id))
            })
            .unwrap()
            .id();
        let program = HeldProgram::new(program_id)?;
        let first_error = reset(&replacement, scoped.scope, strict).await.unwrap_err();
        let (source, removed) = failure_parts(&first_error);
        assert!(matches!(
            source,
            GtpuError::StateIndeterminate {
                operation: "ebpf_exclusive_workload_detached_program_reference"
            }
        ));
        assert_counts(removed, 0, if strict { 3 } else { 0 }, 0);
        assert_eq!(pin_directory_listing(&graph), before);
        assert!(exclusions.iter().all(|path| path.exists()));
        assert_eq!(selectors.iter().all(|path| path.exists()), strict);
        for (direction, chain) in [("ingress", "chain 7"), ("egress", "chain 9")] {
            assert_eq!(tc_filters(direction).contains(chain), !strict);
            assert!(!tc_filters(direction).contains("opc_gtpu"));
        }
        assert!(matches!(
            reset(&replacement, scoped.scope, strict).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_exclusive_workload_external_program_reference"
            })
        ));
        assert_eq!(pin_directory_listing(&graph), before);
        program.release()?;
        let report = reset(&replacement, scoped.scope, strict).await?;
        if strict {
            // Filters removed by the failed attempt are represented by its
            // error report; this successful retry counts only the remainder.
            assert_counts(report, 3, 0, 6);
        } else {
            assert_counts(report, 0, 0, 0);
            assert_counts(
                replacement
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?,
                0,
                3,
                2,
            );
        }
        assert_counts(
            replacement
                .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                .await?,
            0,
            0,
            0,
        );
        assert_workload_attach_forwards(&replacement, &net).await?;
    }
    Ok(())
}

struct HeldProgram {
    child: std::process::Child,
    stream: Option<TcpStream>,
}

impl HeldProgram {
    fn new(id: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let child = Command::new(env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "workload_strict_reset_writer_and_reference_guards",
                "--test-threads=1",
            ])
            .env(
                "OPC_RESET_REFERENCE_SOCKET",
                listener.local_addr()?.to_string(),
            )
            .env("OPC_RESET_REFERENCE_PROGRAM", id.to_string())
            .stdout(Stdio::null())
            .spawn()?;
        let mut held = Self {
            child,
            stream: None,
        };
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "reference holder did not acknowledge within three minutes",
                    )
                })?;
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(remaining))?;
                    let mut ready = [0];
                    stream.read_exact(&mut ready)?;
                    assert_eq!(ready, [1]);
                    stream.set_read_timeout(None)?;
                    held.stream = Some(stream);
                    return Ok(held);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        held.child.try_wait()?.is_none(),
                        "reference holder exited before acknowledgement"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn release(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stream.as_mut().unwrap().write_all(&[1])?;
        assert!(self.child.wait()?.success());
        Ok(())
    }
}

impl Drop for HeldProgram {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn external_namespace_guard() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for strict in [false, true] {
        let net = TestNet::provision();
        let scoped = WorkloadTestScope::new();
        let scope = scoped.scope;
        let graph = scope.bpffs_pin_root().join("s2bu");
        run("ip", &["link", "set", "s2bu", "netns", &net.pgw_ns]);
        let remote_hooks = in_netns(&net.pgw_ns, move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let remote = EbpfGtpuDataplaneBackend::for_workload(scope);
                let mut request = CreateGtpDeviceRequest::new("s2bu");
                request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
                remote.create_device(request).await.unwrap();
                drop(remote);
                [tc_filters("ingress"), tc_filters("egress")]
            })
        });
        let before = pin_directory_listing(&graph);
        let replacement = EbpfGtpuDataplaneBackend::for_workload(scope);
        assert!(matches!(
            reset(&replacement, scope, strict).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_exclusive_workload_external_program_reference"
            })
        ));
        assert_eq!(pin_directory_listing(&graph), before);
        assert_eq!(
            in_netns(&net.pgw_ns, || [
                tc_filters("ingress"),
                tc_filters("egress")
            ]),
            remote_hooks
        );
        run("ip", &["-n", &net.pgw_ns, "link", "del", "s2bu"]);
        reset(&replacement, scope, strict).await?;
        assert!(!graph.exists());
    }
    Ok(())
}
