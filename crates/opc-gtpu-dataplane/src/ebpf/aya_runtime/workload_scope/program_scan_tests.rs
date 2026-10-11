use super::*;
use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;

struct Fixture {
    root: PathBuf,
    unrelated_dir: PathBuf,
    unrelated: Option<Ebpf>,
    unrelated_id: u32,
    retired: Rc<Cell<bool>>,
    runtime: AyaGtpuRuntime,
    ifindex: u32,
}

impl Fixture {
    fn new() -> Self {
        assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
        let sequence = CAPABILITY_PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/sys/fs/bpf/opc-gtpu-sibling-scan-{}-{sequence}",
            std::process::id()
        ));
        let unrelated_dir = root.with_file_name(format!(
            "opc-gtpu-sibling-unrelated-{}-{sequence}",
            std::process::id()
        ));
        let mut fixture = Self {
            root,
            unrelated_dir,
            unrelated: None,
            unrelated_id: 0,
            retired: Rc::new(Cell::new(false)),
            runtime: AyaGtpuRuntime::new(),
            ifindex: sys::ifindex_by_name("lo").expect("fresh namespace loopback"),
        };
        for path in [&fixture.root, &fixture.unrelated_dir] {
            fs::create_dir(path)
                .unwrap_or_else(|error| panic!("create private scan fixture {path:?}: {error}"));
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Load this first: find_map must encounter the disappearing ID before
        // the still-live owned target, rather than short-circuiting before it.
        let mut unrelated = EbpfLoader::new()
            .default_map_pin_directory(&fixture.unrelated_dir)
            .load(DATAPATH_OBJECT)
            .expect("load unrelated maps");
        let info = load_program(&mut unrelated, PROG_UPLINK).expect("load unrelated program");
        fixture.unrelated_id = info.id();
        fixture.unrelated = Some(unrelated);
        fixture
    }

    fn pin_dir(&self) -> PathBuf {
        self.root.join("lo")
    }

    fn attach(&self) -> ProgramInfo {
        self.runtime
            .attach(
                "lo",
                self.ifindex,
                &self.pin_dir(),
                50,
                [192, 0, 2, 1],
                None,
                None,
            )
            .expect("attach and retain the owned programs across the scan");
        let devices = self.runtime.devices.lock().unwrap();
        let owned = devices[&self.ifindex]
            .ebpf
            .program(PROG_UPLINK)
            .unwrap()
            .info()
            .unwrap();
        assert!(self.unrelated_id < owned.id());
        let unrelated_ids = self
            .unrelated
            .as_ref()
            .unwrap()
            .program(PROG_UPLINK)
            .unwrap()
            .info()
            .unwrap()
            .map_ids()
            .unwrap()
            .unwrap();
        assert!(owned
            .map_ids()
            .unwrap()
            .unwrap()
            .iter()
            .all(|id| !unrelated_ids.contains(id)));
        owned
    }

    fn retire_during(&mut self, stage: ProgramScanStage) {
        let mut unrelated = self.unrelated.take();
        let id = self.unrelated_id;
        let retired = Rc::clone(&self.retired);
        PROGRAM_SCAN_TEST_HOOK.with(|hook| {
            assert!(hook.borrow().is_none());
            *hook.borrow_mut() = Some(Box::new(move |observed_stage, info| {
                if observed_stage != stage || info.id() != id || retired.get() {
                    return Ok(());
                }
                // Aya's ID iterator is private. Repeat its real reopen at the
                // SDK iterator boundary after dropping the final kernel owner.
                // No fabricated errno stands in for the retirement proof.
                drop(unrelated.take());
                let result = info.fd();
                assert!(matches!(&result, Err(error) if program_id_disappeared_during_scan(error)));
                retired.set(true);
                println!("OPC_GTPU_SIBLING_PROGRAM_RETIRED stage={stage:?} id={id}");
                match stage {
                    ProgramScanStage::Enumeration => result.map(drop),
                    // The production map_ids() must perform the failing reopen.
                    ProgramScanStage::MapIds => Ok(()),
                }
            }));
        });
    }

    fn finish_scan(&self) {
        PROGRAM_SCAN_TEST_HOOK.with(|hook| hook.borrow_mut().take());
        assert!(
            self.retired.get(),
            "the selected scan must retire the real program"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        PROGRAM_SCAN_TEST_HOOK.with(|hook| hook.borrow_mut().take());
        if self
            .runtime
            .devices
            .lock()
            .unwrap()
            .contains_key(&self.ifindex)
        {
            let _ = self.runtime.detach("lo", self.ifindex, &self.pin_dir(), 50);
        }
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.unrelated_dir);
    }
}

fn assert_inspection_errors_fail_closed<T>(
    stage: ProgramScanStage,
    scan: impl Fn() -> Result<T, GtpuError>,
) {
    for (call, errno) in [
        ("bpf_prog_get_fd_by_id", rustix::io::Errno::PERM),
        ("bpf_prog_get_fd_by_id", rustix::io::Errno::ACCESS),
        ("bpf_prog_get_fd_by_id", rustix::io::Errno::IO),
        ("bpf_prog_get_info_by_fd", rustix::io::Errno::NOENT),
    ] {
        let observed = Rc::new(Cell::new(false));
        let called = Rc::clone(&observed);
        PROGRAM_SCAN_TEST_HOOK.with(|hook| {
            assert!(hook.borrow().is_none());
            *hook.borrow_mut() = Some(Box::new(move |observed_stage, _| {
                if observed_stage != stage {
                    return Ok(());
                }
                called.set(true);
                // Synthetic errors are negative controls only. Retirement
                // above is always a real kernel operation on a loaded ID.
                Err(ProgramError::SyscallError(aya::sys::SyscallError {
                    call,
                    io_error: errno.into(),
                }))
            }));
        });
        let result = scan();
        PROGRAM_SCAN_TEST_HOOK.with(|hook| hook.borrow_mut().take());
        assert!(
            observed.get(),
            "the scan must reach the {stage:?} error control"
        );
        assert!(result.is_err(), "{call}: {errno} must still fail closed");
    }
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, writable bpffs, and a fresh netns"]
fn sibling_scan_historical_references_tolerates_retirement() {
    for stage in [ProgramScanStage::Enumeration, ProgramScanStage::MapIds] {
        for live_reference in [false, true] {
            let mut fixture = Fixture::new();
            let pin_dir = fixture.pin_dir();
            fs::create_dir(&pin_dir).unwrap();
            let mut graph = EbpfLoader::new()
                .default_map_pin_directory(&pin_dir)
                .load(pre_selector_stamp_traffic_observation_v1_artifact::object_for_privileged_generation_harness())
                .expect("load the real historical 25-map graph");
            let ids = std::array::from_fn(|index| {
                MapInfo::from_pin(
                    pin_dir.join(PRE_SELECTOR_STAMP_TRAFFIC_OBSERVATION_V1_MAP_NAMES[index]),
                )
                .unwrap()
                .id()
            });
            if live_reference {
                load_program(&mut graph, PROG_UPLINK).expect("retain a live graph reference");
            }
            fixture.retire_during(stage);
            let result = AyaGtpuRuntime::historical_25_program_references_absent(&ids);
            fixture.finish_scan();
            assert_eq!(
                result.unwrap(),
                !live_reference,
                "retirement must not hide a live historical graph reference"
            );
            for (name, id) in PRE_SELECTOR_STAMP_TRAFFIC_OBSERVATION_V1_MAP_NAMES
                .iter()
                .zip(ids)
            {
                assert_eq!(MapInfo::from_pin(pin_dir.join(name)).unwrap().id(), id);
            }
            if live_reference {
                assert_inspection_errors_fail_closed(stage, || {
                    AyaGtpuRuntime::historical_25_program_references_absent(&ids)
                });
            }
        }
    }
    println!("OPC_GTPU_SIBLING_SCAN_PROVEN site=historical_references");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, writable bpffs, and a fresh netns"]
fn sibling_scan_generation_tolerates_retirement() {
    let mut fixture = Fixture::new();
    let owned = fixture.attach();
    fixture.retire_during(ProgramScanStage::Enumeration);
    let result =
        AyaGtpuRuntime::require_no_foreign_generation(fixture.ifindex, 50, OPERATION, true);
    fixture.finish_scan();
    let programs = result.expect("retired unrelated program must not hide the current generation");
    assert_eq!(programs.len(), 2);
    assert!(programs
        .iter()
        .any(|program| program.occupant.program_id == Some(owned.id())));
    assert_inspection_errors_fail_closed(ProgramScanStage::Enumeration, || {
        AyaGtpuRuntime::require_no_foreign_generation(fixture.ifindex, 50, OPERATION, true)
    });

    let foreign_dir = fixture.root.join("foreign");
    fs::create_dir(&foreign_dir).unwrap();
    let mut foreign = EbpfLoader::new()
        .default_map_pin_directory(&foreign_dir)
        .load(pre_redirect_artifact::object_for_tag_proof())
        .expect("load a real foreign generation");
    let program: &mut SchedClassifier = foreign
        .program_mut(PROG_UPLINK)
        .unwrap()
        .try_into()
        .unwrap();
    program.load().unwrap();
    program
        .attach_with_options(
            "lo",
            TcAttachType::Egress,
            TcAttachOptions::Netlink(NlOptions {
                priority: 51,
                handle: TC_HANDLE,
                classid: None,
            }),
        )
        .unwrap();
    assert!(matches!(
        AyaGtpuRuntime::require_no_foreign_generation(fixture.ifindex, 50, OPERATION, true),
        Err(GtpuError::DatapathGenerationMismatch { .. })
    ));
    assert_eq!(
        slot_owner(fixture.ifindex, TcAttachType::Egress, 50)
            .unwrap()
            .unwrap()
            .program_id,
        Some(owned.id())
    );
    drop(foreign);
    println!("OPC_GTPU_SIBLING_SCAN_PROVEN site=generation");
}

fn check_owner_scan(scan: impl Fn(&FilterOwner, &ProgramInfo, &[u32]) -> Result<bool, GtpuError>) {
    let mut fixture = Fixture::new();
    let owned = fixture.attach();
    let ids = owned.map_ids().unwrap().unwrap();
    let owner = FilterOwner {
        name: PROG_UPLINK.into(),
        program_id: Some(owned.id()),
    };
    fixture.retire_during(ProgramScanStage::Enumeration);
    let result = scan(&owner, &owned, &ids);
    fixture.finish_scan();
    assert!(result.expect("retired unrelated program must not hide the owned target"));
    owned
        .fd()
        .expect("the owned program stays open across the scan");

    assert_inspection_errors_fail_closed(ProgramScanStage::Enumeration, || {
        scan(&owner, &owned, &ids)
    });
    let missing = FilterOwner {
        program_id: Some(fixture.unrelated_id),
        ..owner.clone()
    };
    assert!(
        scan(&missing, &owned, &ids).is_err(),
        "a missing required target still fails closed"
    );
    let mut foreign = EbpfLoader::new()
        .default_map_pin_directory(&fixture.unrelated_dir)
        .load(DATAPATH_OBJECT)
        .unwrap();
    let foreign_info = load_program(&mut foreign, PROG_UPLINK).unwrap();
    assert!(
        !scan(
            &owner,
            &foreign_info,
            &foreign_info.map_ids().unwrap().unwrap()
        )
        .unwrap(),
        "a live program with a different map graph must not be adopted"
    );
    assert_eq!(
        slot_owner(fixture.ifindex, TcAttachType::Egress, 50)
            .unwrap()
            .unwrap()
            .program_id,
        Some(owned.id())
    );
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, writable bpffs, and a fresh netns"]
fn sibling_scan_artifact_owner_tolerates_retirement() {
    check_owner_scan(|owner, artifact, _| owner_matches_artifact(owner, PROG_UPLINK, artifact));
    println!("OPC_GTPU_SIBLING_SCAN_PROVEN site=artifact_owner");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, writable bpffs, and a fresh netns"]
fn sibling_scan_legacy_record_owner_tolerates_retirement() {
    check_owner_scan(|owner, artifact, ids| {
        owner_matches_legacy_v2_record(
            owner,
            PROG_UPLINK,
            owner.program_id.unwrap(),
            artifact.tag(),
            ids,
        )
    });
    println!("OPC_GTPU_SIBLING_SCAN_PROVEN site=legacy_record_owner");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, writable bpffs, and a fresh netns"]
fn sibling_scan_legacy_artifact_owner_tolerates_retirement() {
    check_owner_scan(|owner, artifact, ids| {
        legacy_v2_artifact_owner_tag(
            owner,
            PROG_UPLINK,
            LegacyV2ProgramTags {
                sha1: artifact.tag(),
                sha256: artifact.tag(),
            },
            ids,
        )
        .map(|matched| matched.is_some())
    });
    println!("OPC_GTPU_SIBLING_SCAN_PROVEN site=legacy_artifact_owner");
}

#[test]
#[ignore = "requires CAP_BPF/CAP_NET_ADMIN, writable bpffs, and a fresh netns"]
fn sibling_scan_workload_references_tolerates_retirement() {
    for stage in [ProgramScanStage::Enumeration, ProgramScanStage::MapIds] {
        for live_reference in [false, true] {
            let mut fixture = Fixture::new();
            let owned = fixture.attach();
            let ownership = Arc::clone(
                &fixture.runtime.devices.lock().unwrap()[&fixture.ifindex]._reconciler_ownership,
            );
            let lock =
                AyaGtpuRuntime::acquire_operation_control_lock(&ownership, OPERATION).unwrap();
            let maps = CURRENT_MAP_NAMES
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    let path = fixture.pin_dir().join(name);
                    let data = MapData::from_pin(&path).unwrap();
                    let metadata = fs::metadata(path).unwrap();
                    (
                        index,
                        InspectedMap {
                            id: data.info().unwrap().id(),
                            _data: data,
                            pin_identity: (metadata.dev(), metadata.ino()),
                        },
                    )
                })
                .collect();
            let programs =
                AyaGtpuRuntime::require_no_foreign_generation(fixture.ifindex, 50, OPERATION, true)
                    .unwrap();
            let port = KernelCleanup {
                ownership,
                lock,
                ifindex: Some(fixture.ifindex),
                tc_priority: 50,
                graph_identity: None,
                maps,
                programs,
            };
            let foreign = live_reference.then(|| {
                let mut foreign = EbpfLoader::new()
                    .default_map_pin_directory(fixture.pin_dir())
                    .load(DATAPATH_OBJECT)
                    .unwrap();
                let foreign_info = load_program(&mut foreign, PROG_UPLINK).unwrap();
                assert_ne!(foreign_info.id(), owned.id());
                foreign
            });
            fixture.retire_during(stage);
            let result = port.references_are_owned(true);
            fixture.finish_scan();
            if live_reference {
                assert!(
                    matches!(
                        result,
                        Err(GtpuError::RetryRequired {
                            operation: "ebpf_workload_cleanup_program_references"
                        })
                    ),
                    "a simultaneous unrelated retirement must not hide the live foreign reference"
                );
            } else {
                result.expect("retirement must not refuse the still-live owned hooks");
            }
            assert_inspection_errors_fail_closed(stage, || port.references_are_owned(true));
            for (index, map) in &port.maps {
                assert_eq!(
                    MapInfo::from_pin(fixture.pin_dir().join(CURRENT_MAP_NAMES[*index]))
                        .unwrap()
                        .id(),
                    map.id
                );
            }
            drop(foreign);
            port.references_are_owned(true)
                .expect("dropping the foreign owner restores the proof");
            assert!(
                matches!(
                    port.references_are_owned(false),
                    Err(GtpuError::RetryRequired {
                        operation: "ebpf_workload_cleanup_program_references"
                    })
                ),
                "live local programs still block the post-fence proof"
            );
            assert_eq!(
                slot_owner(fixture.ifindex, TcAttachType::Egress, 50)
                    .unwrap()
                    .unwrap()
                    .program_id,
                Some(owned.id())
            );
        }
    }
    exclusive_workload_references_tolerate_retirement();
    println!("OPC_GTPU_SIBLING_SCAN_PROVEN site=workload_references");
}

fn exclusive_workload_references_tolerate_retirement() {
    for stage in [ProgramScanStage::Enumeration, ProgramScanStage::MapIds] {
        for live_reference in [false, true] {
            let mut fixture = Fixture::new();
            let owned = fixture.attach();
            let maps = if live_reference {
                owned.map_ids().unwrap().unwrap().into_iter().collect()
            } else {
                HashSet::from([u32::MAX])
            };
            fixture.retire_during(stage);
            let result = exclusive_workload_scope::map_references(&maps);
            fixture.finish_scan();
            let references = result.expect("unrelated retirement must not refuse the scan");
            assert!(!references.contains(&fixture.unrelated_id));
            if live_reference {
                assert!(references.contains(&owned.id()), "keep every live owner");
            } else {
                assert!(references.is_empty());
            }
            assert_inspection_errors_fail_closed(stage, || {
                exclusive_workload_scope::map_references(&maps)
            });
            assert_eq!(
                slot_owner(fixture.ifindex, TcAttachType::Egress, 50)
                    .unwrap()
                    .unwrap()
                    .program_id,
                Some(owned.id())
            );
        }
    }
}
