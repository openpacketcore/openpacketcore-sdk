use super::*;
use sys::tc::{ArtifactMap, ArtifactProgram, ArtifactSpec, TcHook, TcSlot};
mod runtime;
mod session_kernel;
mod sessions;
pub(in super::super) use runtime::Runtime;

#[cfg(test)]
mod abandon_tests;
#[cfg(test)]
mod combined_tests;
#[cfg(test)]
mod coverage_tests;
#[cfg(test)]
mod fresh_tests;
#[cfg(test)]
mod packet_tests;
#[cfg(test)]
mod session_tests;

pub(in super::super) fn preserved_directories(spec: &ArtifactSpec) -> Vec<PathBuf> {
    let parent = spec
        .directory()
        .parent()
        .expect("validated artifact directory");
    vec![parent.join(RECONCILER_CONTROL_DIRECTORY)]
}

pub(in super::super) fn require_no_selector_history(
    scope: &sys::tc::LocalKernelScope,
    spec: &ArtifactSpec,
    inventory: &sys::tc::ArtifactInventory,
) -> Result<(), sys::tc::ScopeError> {
    use sys::tc::ScopeError;
    // The legacy namespace leaves are inode-bound hashes, not interface
    // names. Any such history belongs to its existing recovery lifecycle.
    // Never read it as a local lifecycle journal or erase it. An empty control root is
    // harmless and retained; any child (even an empty lock leaf) refuses.
    for path in preserved_directories(spec) {
        if let Some(directory) = scope.pin_directory(&path)? {
            if !directory.entries()?.is_empty() {
                return Err(ScopeError::Conflict);
            }
        }
    }
    let mut stamp_name = [0_u8; 16];
    let name = kernel_program_name(MAP_SESSION_SELECTOR_STAMPS);
    stamp_name[..name.len()].copy_from_slice(name);
    if let Some(map) = inventory
        .maps()
        .find(|map| map.identity().name == stamp_name)
    {
        let data = MapData::from_fd(map.try_clone_fd().map_err(|_| ScopeError::Inspection)?)
            .map_err(|_| ScopeError::Inspection)?;
        let stamps = BpfHashMap::<
            _,
            [u8; GTPU_SESSION_GROUP_ID_LEN],
            [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
        >::try_from(aya::maps::Map::HashMap(data))
        .map_err(|_| ScopeError::Inspection)?;
        match stamps.keys().next() {
            None => {}
            Some(Ok(_)) => return Err(ScopeError::Conflict),
            Some(Err(_)) => return Err(ScopeError::Inspection),
        }
    }
    scope.verify()
}

pub(in super::super) fn artifact_spec(
    directory: PathBuf,
    ifindex: u32,
    priority: u16,
) -> Result<ArtifactSpec, GtpuError> {
    static TAGS: OnceLock<Result<(LegacyV2ProgramTags, LegacyV2ProgramTags), GtpuError>> =
        OnceLock::new();
    let tags = TAGS
        .get_or_init(|| AyaGtpuRuntime::current_artifact_tags_from(DATAPATH_OBJECT))
        .as_ref()
        .map_err(Clone::clone)?;
    let object =
        AyaObject::parse(DATAPATH_OBJECT).map_err(|_| state_indeterminate("ebpf_local_image"))?;
    let maps = CURRENT_MAP_SPECS
        .iter()
        .map(|spec| {
            let map = object
                .maps
                .get(spec.name)
                .ok_or_else(|| state_indeterminate("ebpf_local_image"))?;
            let (btf_key_type_id, btf_value_type_id) = match map {
                aya_obj::Map::Btf(map)
                    if spec.map_type != bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32 =>
                {
                    (map.def.btf_key_type_id, map.def.btf_value_type_id)
                }
                _ => (0, 0),
            };
            Ok(ArtifactMap {
                name: spec.name.to_owned(),
                map_type: map.map_type(),
                key_size: map.key_size(),
                value_size: map.value_size(),
                max_entries: map.max_entries(),
                flags: map.map_flags(),
                btf_key_type_id,
                btf_value_type_id,
                map_extra: map.map_extra(),
                pinned: map.pinning() == PinningType::ByName,
            })
        })
        .collect::<Result<Vec<_>, GtpuError>>()?;
    let program = |name: &str, tags: LegacyV2ProgramTags, maps: &[&str]| {
        let mut tags = vec![tags.sha1.to_be_bytes(), tags.sha256.to_be_bytes()];
        tags.sort();
        tags.dedup();
        ArtifactProgram {
            name: name.to_owned(),
            tags,
            maps: maps.iter().map(|name| (*name).to_owned()).collect(),
        }
    };
    let programs = vec![
        program(PROG_UPLINK, tags.0, &CURRENT_UPLINK_PROGRAM_MAP_NAMES),
        program(PROG_DOWNLINK, tags.1, &CURRENT_DOWNLINK_PROGRAM_MAP_NAMES),
    ];
    let slot = |hook| {
        TcSlot::new(ifindex, hook, 0, 3, priority, u32::from(TC_HANDLE)).map_err(|_| {
            GtpuError::invalid_config("ebpf.local_scope", "invalid exact tc coordinates")
        })
    };
    ArtifactSpec::new(
        directory,
        maps,
        programs,
        vec![(slot(TcHook::Egress)?, 0), (slot(TcHook::Ingress)?, 1)],
    )
    .map_err(|_| {
        GtpuError::invalid_config(
            "ebpf.local_scope",
            "invalid current-image graph declaration",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use sys::bpf::GlobalObjectDisposition;
    use sys::tc::{
        ContainmentBank, LocalHookSpec, LocalKernelScope, LocalScopeSpec, TcClient, TcVerdict,
    };

    struct Cleanup(PathBuf, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_dir_all(&self.1);
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Boundary {
        None,
        LegacyReset,
        SelectorStamp,
        SelectorMarker,
    }
    fn graph_retirement(
        pinless: bool,
        partial: bool,
        foreign: bool,
        changed_slot: bool,
        boundary: Boundary,
    ) {
        assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
        let root = PathBuf::from(format!(
            "/sys/fs/bpf/opc-local-graph-{}",
            std::process::id()
        ));
        let locks =
            std::env::temp_dir().join(format!("opc-local-graph-lock-{}", std::process::id()));
        let _cleanup = Cleanup(root.clone(), locks.clone());
        let relative = PathBuf::from("gtpu/lo");
        let pin_dir = root.join(&relative);
        for path in [&root, &root.join("gtpu"), &pin_dir, &locks] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ifindex = sys::ifindex_by_name("lo").unwrap();
        let mut hooks = Vec::new();
        let mut slots = Vec::new();
        for hook in [TcHook::Ingress, TcHook::Egress] {
            let slot =
                |priority, protocol| TcSlot::new(ifindex, hook, 0, protocol, priority, 1).unwrap();
            hooks.push(
                LocalHookSpec::new(
                    ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
                    ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
                )
                .unwrap(),
            );
            slots.push(slot(50, 3));
        }
        let scope = LocalKernelScope::open(
            LocalScopeSpec::new(root.clone(), locks.join("guard"), [71; 16], hooks, slots).unwrap(),
        )
        .unwrap();
        let graph = super::super::super::EbpfLocalGraph::new(relative, ifindex, 50).unwrap();
        assert!(graph.inspect(&scope).unwrap().is_locally_empty());
        if boundary == Boundary::LegacyReset {
            let lifecycle = opc_local_kernel_lifecycle::LocalKernelLifecycle::new(
                scope.clone(),
                vec![Arc::new(graph.clone())],
                vec![],
                vec![ifindex],
            )
            .unwrap();
            let backend = crate::EbpfGtpuDataplaneBackend::for_local_scope(
                lifecycle.bind_graph(graph.artifact()).unwrap(),
            )
            .unwrap();
            let old_scope = crate::EbpfWorkloadScope::new([1; 32]).unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async {
                let results = [
                    backend.reset_workload_graph(old_scope, "lo").await,
                    backend
                        .clone()
                        .reset_exclusive_workload_graph(old_scope, "lo")
                        .await,
                    backend
                        .reset_strict_exclusive_workload_graph(old_scope, "lo")
                        .await
                        .map(|_| ()),
                ];
                for result in results {
                    assert!(
                        matches!(result, Err(GtpuError::LegacyResetOnLocalScope)),
                        "{result:?}"
                    );
                }
            });
            assert!(graph.inspect(&scope).unwrap().is_locally_empty());
            assert!(fs::read_dir(&pin_dir).unwrap().next().is_none());
            return;
        }
        tc::qdisc_add_clsact("lo").unwrap();
        let mut ebpf = EbpfLoader::new()
            .default_map_pin_directory(&pin_dir)
            .load(DATAPATH_OBJECT)
            .unwrap();
        let mut links = Vec::new();
        for (name, hook) in [
            (PROG_UPLINK, TcAttachType::Egress),
            (PROG_DOWNLINK, TcAttachType::Ingress),
        ] {
            load_program(&mut ebpf, name).unwrap();
            let program: &mut SchedClassifier = ebpf.program_mut(name).unwrap().try_into().unwrap();
            let link = program
                .attach_with_options(
                    "lo",
                    hook,
                    TcAttachOptions::Netlink(NlOptions {
                        priority: 50,
                        handle: 1.into(),
                        ..NlOptions::default()
                    }),
                )
                .unwrap();
            links.push(ManuallyDrop::new(program.take_link(link).unwrap()));
        }
        let observer = ebpf
            .program(PROG_UPLINK)
            .unwrap()
            .fd()
            .unwrap()
            .try_clone()
            .unwrap();
        let foreign_slot = TcSlot::new(ifindex, TcHook::Ingress, 0, 3, 100, 7).unwrap();
        let mut tc = TcClient::new().unwrap();
        tc.create_gact(foreign_slot, [99; 16], TcVerdict::Pass)
            .unwrap();
        let before = graph
            .inspect(&scope)
            .expect("complete current image must be recognized");
        assert!(!before.is_locally_empty());
        let (programs, maps) = runtime::loaded_objects(&ebpf).unwrap();
        let installed = before
            .into_installed(programs, maps)
            .expect("every fresh graph role is complete");
        installed.recheck().unwrap();
        if boundary == Boundary::SelectorStamp {
            let mut stamps =
                BpfHashMap::<
                    _,
                    [u8; GTPU_SESSION_GROUP_ID_LEN],
                    [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
                >::try_from(ebpf.map_mut(MAP_SESSION_SELECTOR_STAMPS).unwrap())
                .unwrap();
            stamps
                .insert(
                    [9; GTPU_SESSION_GROUP_ID_LEN],
                    [1; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
                    0,
                )
                .unwrap();
        }
        if boundary == Boundary::SelectorMarker {
            let control = root.join("gtpu").join(RECONCILER_CONTROL_DIRECTORY);
            let writer = control.join("lo");
            let marker = writer.join(format!("SELECTOR_AUTHORITY_V1_{}", "01".repeat(32)));
            for path in [&control, &writer, &marker] {
                fs::create_dir(path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        if matches!(boundary, Boundary::SelectorStamp | Boundary::SelectorMarker) {
            assert!(
                graph.inspect(&scope).is_err(),
                "ordinary local reset must preserve selector history"
            );
            assert!(pin_dir.join(MAP_SESSION_SELECTOR_STAMPS).exists());
            assert_eq!(
                scope
                    .inventory()
                    .unwrap()
                    .iter()
                    .flat_map(|dump| dump.entries())
                    .filter(|filter| graph.artifact().slots().any(|slot| slot == filter.slot()))
                    .count(),
                2
            );
            return;
        }
        let mut foreign_owner = None;
        if foreign {
            const FOREIGN: &str = "foreign_uplink0";
            assert_eq!(PROG_UPLINK.len(), FOREIGN.len());
            let mut object = DATAPATH_OBJECT.to_vec();
            for offset in 0..=object.len() - PROG_UPLINK.len() {
                if &object[offset..offset + PROG_UPLINK.len()] == PROG_UPLINK.as_bytes() {
                    object[offset..offset + PROG_UPLINK.len()].copy_from_slice(FOREIGN.as_bytes());
                }
            }
            let mut other = EbpfLoader::new()
                .default_map_pin_directory(&pin_dir)
                .load(&object)
                .unwrap();
            load_program(&mut other, FOREIGN).unwrap();
            graph
                .inspect(&scope)
                .expect("an outside descriptor has no local forwarding effect");
            let program: &mut SchedClassifier =
                other.program_mut(FOREIGN).unwrap().try_into().unwrap();
            let link = program
                .attach_with_options(
                    "lo",
                    TcAttachType::Egress,
                    TcAttachOptions::Netlink(NlOptions {
                        priority: 110,
                        handle: 8.into(),
                        ..NlOptions::default()
                    }),
                )
                .unwrap();
            assert!(
                graph.inspect(&scope).is_err(),
                "a foreign program using our maps on a covered hook blocks retirement"
            );
            program.detach(link).unwrap();
            foreign_owner = Some(other);
        }
        if pinless {
            fs::remove_dir_all(&pin_dir).unwrap();
        }
        drop(ebpf); // links persist exactly as after predecessor process death
        let contained = scope.contain().unwrap();
        if partial {
            let slot = TcSlot::new(ifindex, TcHook::Egress, 0, 3, 50, 1).unwrap();
            let filter = scope
                .inventory()
                .unwrap()
                .into_iter()
                .find_map(|dump| dump.find(slot).cloned())
                .unwrap();
            contained.delete_data(&filter).unwrap();
        }
        if pinless || partial || foreign {
            assert!(
                installed.recheck().is_err(),
                "incomplete/replaced graphs never remain ready"
            );
        }
        drop(installed);
        if foreign {
            graph
                .inspect(&scope)
                .expect("detached outside references cannot block local retirement");
            assert!(scope.inventory().unwrap().iter().any(|dump| dump
                .find(TcSlot::new(ifindex, TcHook::Ingress, 0, 3, 50, 1).unwrap())
                .is_some()));
        }
        let inventory = graph
            .inspect(&scope)
            .expect("pin loss and a detached retained program are inspectable");
        if changed_slot {
            let slot = TcSlot::new(ifindex, TcHook::Ingress, 0, 3, 50, 1).unwrap();
            let observed = scope
                .inventory()
                .unwrap()
                .into_iter()
                .find_map(|dump| dump.find(slot).cloned())
                .unwrap();
            contained.delete_data(&observed).unwrap();
            tc.create_gact(slot, [34; 16], TcVerdict::Pass).unwrap();
            assert!(
                inventory.retire(&contained).is_err(),
                "old inventory cannot authorize a replacement occupant"
            );
            let dumps = scope.inventory().unwrap();
            let replacement = dumps.iter().find_map(|dump| dump.find(slot)).unwrap();
            assert_eq!(replacement.gact().unwrap().cookie(), &[34; 16]);
            assert!(pin_dir.exists(), "refusal must retain the graph pins");
            contained.recheck().unwrap();
            return;
        }
        let mut retired = inventory
            .retire(&contained)
            .expect("local effects retire with an outside observer FD");
        retired.local().recheck().unwrap();
        assert_eq!(
            retired.global(),
            GlobalObjectDisposition::StillReferencedOrUnproven
        );
        assert!(retired.residue_count() > 0);
        assert!(graph.inspect(&scope).unwrap().is_locally_empty());
        let dumps = scope.inventory().unwrap();
        let neighbor = dumps
            .iter()
            .find_map(|dump| dump.find(foreign_slot))
            .unwrap();
        assert_eq!(neighbor.gact().unwrap().cookie(), &[99; 16]);
        assert_eq!(neighbor.gact().unwrap().verdict(), TcVerdict::Pass);
        contained.recheck().unwrap();
        // The retained descriptor still denotes the old object, independently
        // of local retirement. Scoped cleanup never reopens IDs to prove release.
        use std::os::fd::AsFd;
        sys::bpf::ProgramHandle::from_fd(observer.as_fd())
            .unwrap()
            .recheck()
            .unwrap();
        drop(observer);
        drop(foreign_owner);
        assert_eq!(
            retired.observe_release(),
            GlobalObjectDisposition::StillReferencedOrUnproven
        );
        drop(links);
    }
    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_changed_occupant_invalidates_prior_artifact_inventory() {
        graph_retirement(false, false, false, true, Boundary::None);
    }

    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_current_graph_retires_locally_with_external_program_fd() {
        graph_retirement(false, false, false, false, Boundary::None);
    }
    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_pinless_partial_graph_retires_with_external_program_fd() {
        graph_retirement(true, true, false, false, Boundary::None);
    }
    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_pinless_graph_preserves_foreign_reference_and_neighbor() {
        graph_retirement(true, false, true, false, Boundary::None);
    }

    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_all_three_legacy_resets_refuse_a_bound_local_scope() {
        graph_retirement(false, false, false, false, Boundary::LegacyReset);
    }
    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_local_graph_preserves_selector_stamp_history() {
        graph_retirement(false, false, false, false, Boundary::SelectorStamp);
    }
    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_local_graph_preserves_selector_control_history() {
        graph_retirement(false, false, false, false, Boundary::SelectorMarker);
    }
}
