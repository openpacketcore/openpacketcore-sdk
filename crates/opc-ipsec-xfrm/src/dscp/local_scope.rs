//! The shipped DSCP graph's exact, non-adopting local inventory.

use crate::XfrmError;
use opc_linux_gtpu_sys::tc::{ArtifactInventory, ArtifactSpec, LocalKernelScope, ScopeError};
use std::path::PathBuf;

/// Current-image DSCP graph bound to one exact egress slot and private pin leaf.
///
/// The embedded artifact supplies the program tags and complete map layout.
/// Inspection keeps native object descriptors, and never adopts a predecessor.
#[derive(Clone, Debug)]
pub struct XfrmDscpLocalGraph {
    spec: ArtifactSpec,
}

impl XfrmDscpLocalGraph {
    /// Declare one interface's current-image DSCP graph within a held scope.
    pub fn new(
        relative_pin_directory: PathBuf,
        ifindex: u32,
        priority: u16,
    ) -> Result<Self, XfrmError> {
        #[cfg(target_os = "linux")]
        {
            artifact_spec(relative_pin_directory, ifindex, priority).map(|spec| Self { spec })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (relative_pin_directory, ifindex, priority);
            Err(XfrmError::UnsupportedPlatform)
        }
    }

    /// Fresh descriptor-backed inventory; absence is distinct from inspection failure.
    pub fn inspect(&self, scope: &LocalKernelScope) -> Result<ArtifactInventory, ScopeError> {
        ArtifactInventory::inspect(scope, &self.spec)
    }

    /// The artifact-derived catalog for a combined GTP-U/DSCP reset.
    pub fn artifact(&self) -> &ArtifactSpec {
        &self.spec
    }
}

impl opc_local_kernel_lifecycle::LocalArtifact for XfrmDscpLocalGraph {
    fn artifact(&self) -> &ArtifactSpec {
        &self.spec
    }
    fn inspect(
        &self,
        scope: &LocalKernelScope,
    ) -> Result<ArtifactInventory, opc_local_kernel_lifecycle::LocalLifecycleError> {
        XfrmDscpLocalGraph::inspect(self, scope).map_err(Into::into)
    }
}

#[cfg(target_os = "linux")]
fn artifact_spec(
    directory: PathBuf,
    ifindex: u32,
    priority: u16,
) -> Result<ArtifactSpec, XfrmError> {
    use aya_obj::{btf::Btf, maps::PinningType, Features, Object};
    use opc_ipsec_xfrm_ebpf_common::{MAP_MARK_CONFIG, MARK_CONFIG_VALUE_LEN, PROG_EGRESS_DSCP};
    use opc_linux_gtpu_sys::tc::{ArtifactMap, ArtifactProgram, TcHook, TcSlot};
    use sha2::{Digest, Sha256};

    let invalid = || XfrmError::StateIndeterminate {
        operation: "dscp_local_image",
    };
    let mut object = Object::parse(super::aya_runtime::DATAPATH_OBJECT).map_err(|_| invalid())?;
    if object.maps.len() != 1 || object.programs.len() != 1 {
        return Err(invalid());
    }
    let map = object.maps.get(MAP_MARK_CONFIG).ok_or_else(invalid)?;
    if map.map_type() != 2
        || map.key_size() != 4
        || map.value_size() != MARK_CONFIG_VALUE_LEN as u32
        || map.max_entries() != 1
        || map.map_flags() != 0
        || map.map_extra() != 0
        || map.pinning() != PinningType::ByName
    {
        return Err(invalid());
    }
    let map = ArtifactMap {
        name: MAP_MARK_CONFIG.to_owned(),
        map_type: map.map_type(),
        key_size: map.key_size(),
        value_size: map.value_size(),
        max_entries: map.max_entries(),
        flags: map.map_flags(),
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        map_extra: map.map_extra(),
        pinned: true,
    };
    if object.has_btf_relocations() {
        object
            .relocate_btf(&Btf::from_sys_fs().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    }
    let sections = object
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    let maps = object.maps.clone();
    object
        .relocate_maps(
            maps.iter().map(|(name, map)| (name.as_str(), 1, map)),
            &sections,
        )
        .map_err(|_| invalid())?;
    object.relocate_calls(&sections).map_err(|_| invalid())?;
    let mut legacy = object.clone();
    legacy.sanitize_functions(&Features::default());
    object.sanitize_functions(&Features::new(
        true, true, true, true, true, true, true, None,
    ));
    let bytes = |object: &Object| -> Result<Vec<u8>, XfrmError> {
        let program = object.programs.get(PROG_EGRESS_DSCP).ok_or_else(invalid)?;
        let function = object
            .functions
            .get(&program.function_key())
            .ok_or_else(invalid)?;
        // BPF's tag normalization erases the map FD/value immediate pair.
        let mut bytes = Vec::with_capacity(function.instructions.len() * 8);
        let mut previous_map = false;
        for insn in &function.instructions {
            let map = !previous_map && insn.code == 0x18 && matches!(insn.src_reg(), 1 | 2);
            let tail = previous_map
                && insn.code == 0
                && insn.src_reg() == 0
                && insn.dst_reg() == 0
                && insn.off == 0;
            let immediate = if map || tail { 0 } else { insn.imm };
            let registers = if cfg!(target_endian = "little") {
                insn.dst_reg() | insn.src_reg() << 4
            } else {
                insn.src_reg() | insn.dst_reg() << 4
            };
            bytes.extend_from_slice(&[insn.code, registers]);
            bytes.extend_from_slice(&insn.off.to_ne_bytes());
            bytes.extend_from_slice(&immediate.to_ne_bytes());
            previous_map = map;
        }
        Ok(bytes)
    };
    let modern = bytes(&object)?;
    if modern != bytes(&legacy)? {
        return Err(invalid());
    }
    let mut sha1 = [0; 8];
    let mut sha256 = [0; 8];
    sha1.copy_from_slice(&sha1::Sha1::digest(&modern)[..8]);
    sha256.copy_from_slice(&Sha256::digest(&modern)[..8]);
    let mut tags = vec![sha1, sha256];
    tags.sort();
    tags.dedup();
    let program = ArtifactProgram {
        name: PROG_EGRESS_DSCP.to_owned(),
        tags,
        maps: vec![MAP_MARK_CONFIG.to_owned()],
    };
    let invalid_spec =
        || XfrmError::invalid_config("dscp.local_scope", "invalid exact graph coordinates");
    let slot =
        TcSlot::new(ifindex, TcHook::Egress, 0, 3, priority, 1).map_err(|_| invalid_spec())?;
    ArtifactSpec::new(directory, vec![map], vec![program], vec![(slot, 0)])
        .map_err(|_| invalid_spec())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use aya::programs::tc::{NlOptions, TcAttachOptions, TcHandle};
    use aya::programs::{tc, SchedClassifier, TcAttachType};
    use aya::EbpfLoader;
    use opc_ipsec_xfrm_ebpf_common::{MAP_MARK_CONFIG, PROG_EGRESS_DSCP};
    use opc_linux_gtpu_sys::bpf::GlobalObjectDisposition;
    use opc_linux_gtpu_sys::tc::{ContainmentBank, LocalHookSpec, LocalScopeSpec, TcHook, TcSlot};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn dscp_current_catalog_is_an_exact_single_egress_graph() {
        let graph = XfrmDscpLocalGraph::new("dscp/lo".into(), 1, 60).unwrap();
        assert_eq!(
            graph.artifact().directory(),
            std::path::Path::new("dscp/lo")
        );
        assert_eq!(
            graph.artifact().slots().collect::<Vec<_>>(),
            vec![TcSlot::new(1, TcHook::Egress, 0, 3, 60, 1).unwrap()]
        );
        assert!(XfrmDscpLocalGraph::new("../lo".into(), 1, 60).is_err());
        assert!(XfrmDscpLocalGraph::new("dscp/lo".into(), 0, 60).is_err());
    }

    struct Cleanup(PathBuf, PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_dir_all(&self.1);
        }
    }

    #[test]
    #[ignore = "requires CAP_BPF/CAP_NET_ADMIN, private bpffs and private netns"]
    fn native_pinless_dscp_is_retired_with_an_outside_program_fd() {
        assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
        let root = PathBuf::from(format!("/sys/fs/bpf/opc-local-dscp-{}", std::process::id()));
        let locks =
            std::env::temp_dir().join(format!("opc-local-dscp-lock-{}", std::process::id()));
        let _cleanup = Cleanup(root.clone(), locks.clone());
        let leaf = root.join("dscp/lo");
        for path in [&root, &root.join("dscp"), &leaf, &locks] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ifindex = opc_linux_gtpu_sys::ifindex_by_name("lo").unwrap();
        let slot = |priority, protocol| {
            TcSlot::new(ifindex, TcHook::Egress, 0, protocol, priority, 1).unwrap()
        };
        let hook = LocalHookSpec::new(
            ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
            ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
        )
        .unwrap();
        let scope = LocalKernelScope::open(
            LocalScopeSpec::new(
                root,
                locks.join("guard"),
                [72; 16],
                vec![hook],
                vec![slot(60, 3)],
            )
            .unwrap(),
        )
        .unwrap();
        let graph = XfrmDscpLocalGraph::new("dscp/lo".into(), ifindex, 60).unwrap();
        assert!(graph.inspect(&scope).unwrap().is_locally_empty());
        tc::qdisc_add_clsact("lo").unwrap();
        let mut ebpf = EbpfLoader::new()
            .default_map_pin_directory(&leaf)
            .load(super::super::aya_runtime::DATAPATH_OBJECT)
            .unwrap();
        let program: &mut SchedClassifier = ebpf
            .program_mut(PROG_EGRESS_DSCP)
            .unwrap()
            .try_into()
            .unwrap();
        program.load().unwrap();
        program.pin(leaf.join(PROG_EGRESS_DSCP)).unwrap();
        let observer = program.fd().unwrap().try_clone().unwrap();
        let link_id = program
            .attach_with_options(
                "lo",
                TcAttachType::Egress,
                TcAttachOptions::Netlink(NlOptions {
                    priority: 60,
                    handle: TcHandle::new(0, 1),
                    classid: None,
                }),
            )
            .unwrap();
        let link = program.take_link(link_id).unwrap();
        drop(ebpf);
        assert!(!graph.inspect(&scope).unwrap().is_locally_empty());
        fs::remove_file(leaf.join(MAP_MARK_CONFIG)).unwrap();
        fs::remove_file(leaf.join(PROG_EGRESS_DSCP)).unwrap();
        let inventory = graph
            .inspect(&scope)
            .expect("pin-less current image is recognized");
        let contained = scope.contain().unwrap();
        let mut retired = inventory.retire(&contained).unwrap();
        retired.local().recheck().unwrap();
        assert_eq!(
            retired.global(),
            GlobalObjectDisposition::StillReferencedOrUnproven
        );
        assert!(graph.inspect(&scope).unwrap().is_locally_empty());
        contained.recheck().unwrap();
        use std::os::fd::AsFd;
        opc_linux_gtpu_sys::bpf::ProgramHandle::from_fd(observer.as_fd())
            .unwrap()
            .recheck()
            .unwrap();
        drop(observer);
        assert_eq!(
            retired.observe_release(),
            GlobalObjectDisposition::StillReferencedOrUnproven
        );
        drop(link);
    }
}
