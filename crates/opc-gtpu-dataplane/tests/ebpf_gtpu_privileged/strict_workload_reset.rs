use super::*;
use opc_gtpu_dataplane::EbpfStrictWorkloadResetReport;
use std::io::Read;
use std::net::{TcpListener, TcpStream};

const EXCLUSION: &str = "GTPU_CURRENT_HISTORICAL_25_EXCLUSION_V1";

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
                // The ordinary exclusion created by the initial reset is
                // removed and recreated too; every nested marker is counted.
                assert_eq!(
                    report.exclusion_marker_directories,
                    if layout & 16 != 0 { 7 } else { 1 }
                );
                assert!(markers.iter().chain(&exclusions).all(|path| !path.exists()));
                let repeated = backend
                    .reset_strict_exclusive_workload_graph(scoped.scope, "s2bu")
                    .await?;
                assert_eq!(
                    repeated,
                    EbpfStrictWorkloadResetReport {
                        selector_markers: 0,
                        tc_filters: 0,
                        exclusion_marker_directories: 1,
                    }
                );
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
                    assert!(backend.create_device(request).await.is_err());
                    if layout & 8 != 0 {
                        assert_eq!(
                            [filters("s2bu", "ingress"), filters("s2bu", "egress")],
                            hook_before
                        );
                    }
                    if layout & 16 != 0 {
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
) -> Result<(), GtpuError> {
    if strict {
        backend
            .reset_strict_exclusive_workload_graph(scope, "s2bu")
            .await
            .map(|_| ())
    } else {
        backend.reset_exclusive_workload_graph(scope, "s2bu").await
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
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
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
        assert!(matches!(
            reset(&replacement, scoped.scope, strict).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_exclusive_workload_detached_program_reference"
            })
        ));
        assert_eq!(pin_directory_listing(&graph), before);
        assert!(matches!(
            reset(&replacement, scoped.scope, strict).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_exclusive_workload_external_program_reference"
            })
        ));
        assert_eq!(pin_directory_listing(&graph), before);
        program.release()?;
        reset(&replacement, scoped.scope, strict).await?;
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
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut ready = [0];
                    stream.read_exact(&mut ready)?;
                    assert_eq!(ready, [1]);
                    held.stream = Some(stream);
                    return Ok(held);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
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
