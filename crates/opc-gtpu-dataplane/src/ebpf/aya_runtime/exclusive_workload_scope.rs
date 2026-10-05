//! Content-independent cleanup bounded by an explicitly exclusive scope.

use super::*;
use crate::ebpf::validate_interface_name;
use crate::ebpf::workload_scope::{
    cleanup_exclusive, ExclusiveCleanupInventory, ExclusiveWorkloadCleanup,
};
use crate::ebpf::EbpfStrictWorkloadResetReport;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;

const OPERATION: &str = "ebpf_exclusive_workload_cleanup";
const PROGRAM_SCAN: &str = "ebpf_exclusive_workload_program_scan";
const PROGRAM_RELEASE_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// Complete filter placement, including filters without an SDK program name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Filter {
    parent: u32,
    chain: u32,
    protocol: u16,
    priority: u16,
    handle: u32,
    kind: Vec<u8>,
    sdk: bool,
    program_id: Option<u32>,
}

impl Filter {
    pub(super) fn from_attributes(
        attributes: &[u8],
        parent: u32,
        chain: u32,
        protocol: u16,
        priority: u16,
        handle: u32,
    ) -> Result<Self, ()> {
        let kind = find_attribute(attributes, sys::TCA_KIND).ok_or(())?;
        let program_id = if kind == b"bpf\0" {
            find_attribute(attributes, sys::TCA_OPTIONS)
                .and_then(|options| find_attribute(options, sys::TCA_BPF_ID))
                .map(|bytes| bytes.try_into().map(u32::from_ne_bytes).map_err(|_| ()))
                .transpose()?
        } else {
            None
        };
        Ok(Self {
            parent,
            chain,
            protocol,
            priority,
            handle,
            kind: kind.to_vec(),
            // Exactly the predicate ordinary attachment uses, without a tag
            // or generation test that could strand a predecessor's hooks.
            sdk: bpf_filter_owner(attributes)
                .is_some_and(|owner| SdkDatapathProgram::from_filter_name(&owner.name).is_some()),
            program_id,
        })
    }

    fn owned_slot(&self, priority: u16, strict: bool) -> bool {
        (strict || self.chain == 0 && self.protocol == TC_PROTOCOL_ALL)
            && self.priority == priority
            && self.handle == u32::from(TC_HANDLE)
    }

    fn detach(&self, ifindex: u32) -> Result<(), GtpuError> {
        // Zero would delete the whole priority rather than one filter.
        if self.handle == 0 {
            return Err(state_indeterminate(OPERATION));
        }
        let socket = sys::open_route_netlink_socket().map_err(io_error)?;
        let mut attributes = Vec::new();
        append_tc_attribute(&mut attributes, TCA_CHAIN, &self.chain.to_ne_bytes())
            .map_err(io_error)?;
        let request = build_tc_request(
            sys::RTM_DELTFILTER,
            sys::NLM_F_REQUEST | sys::NLM_F_ACK,
            TC_NETLINK_SEQUENCE,
            socket.port_id(),
            tc_ifindex(ifindex).map_err(io_error)?,
            self.handle,
            self.parent,
            (u32::from(self.priority) << 16) | u32::from(self.protocol),
            &attributes,
        )
        .map_err(io_error)?;
        execute_tc_mutation(
            &socket,
            &request,
            TcMutationExpectation {
                sequence: TC_NETLINK_SEQUENCE,
                port_id: socket.port_id(),
                request_type: sys::RTM_DELTFILTER,
                echo: None,
            },
        )
        .map_err(io_error)
    }
}

pub(super) fn reset(
    runtime: &AyaGtpuRuntime,
    ifindex: Option<u32>,
    pin_dir: &Path,
    priority: u16,
    strict: bool,
) -> Result<EbpfStrictWorkloadResetReport, GtpuError> {
    if !runtime
        .devices
        .lock()
        .map_err(|_| state_indeterminate(OPERATION))?
        .is_empty()
    {
        return Err(GtpuError::AlreadyExists);
    }
    let root_path = pin_dir
        .parent()
        .ok_or_else(|| state_indeterminate(OPERATION))?;
    let leaf = pin_dir
        .file_name()
        .ok_or_else(|| state_indeterminate(OPERATION))?;
    let (root, metadata) = AyaGtpuRuntime::open_or_create_bpffs_namespace_root(root_path)?;
    let control = ensure_directory(&root, OsStr::new(RECONCILER_CONTROL_DIRECTORY))?;
    lock(&control)?;
    let control_metadata = AyaGtpuRuntime::verify_control_directory(&control, None, OPERATION)?;
    let namespace = AyaGtpuRuntime::selector_namespace_pin_commitment(
        control_metadata.dev(),
        control_metadata.ino(),
        leaf,
    )?;
    let writer_name = AyaGtpuRuntime::lower_hex(&namespace);
    let legacy_name = AyaGtpuRuntime::historical_25_legacy_leaf_name(leaf)?;
    // Lock the same inodes ordinary and historical writers use, without
    // requiring their records to decode. Never replace a lock directory.
    let legacy = ensure_directory(&control, OsStr::new(&legacy_name))?;
    lock(&legacy)?;
    let writer = ensure_directory(&control, OsStr::new(&writer_name))?;
    lock(&writer)?;
    let operation_name = AyaGtpuRuntime::selector_namespace_operation_lock_name(&namespace);
    let operation = ensure_directory(&control, OsStr::new(&operation_name))?;
    lock(&operation)?;
    let mut port = ExclusiveCleanup {
        root_path: root_path.to_owned(),
        root_identity: (metadata.dev(), metadata.ino()),
        nodes: vec![Node {
            path: PathBuf::new(),
            parent: 0,
            identity: (metadata.dev(), metadata.ino()),
            directory: Some(root),
            map: None,
            program_id: None,
            object_pin: false,
            _pin: None,
            keep: true,
            removed: false,
        }],
        locks: vec![control, legacy, writer, operation],
        leaves: [leaf
            .to_str()
            .ok_or_else(|| state_indeterminate(OPERATION))?
            .to_owned()]
        .into_iter()
        .collect(),
        interfaces: vec![Interface {
            name: leaf
                .to_str()
                .ok_or_else(|| state_indeterminate(OPERATION))?
                .to_owned(),
            ifindex,
            by_name: true,
            hooks: Vec::new(),
        }],
        priority,
        strict,
        report: EbpfStrictWorkloadResetReport::default(),
        retired_programs: HashSet::new(),
    };
    cleanup_exclusive(&mut port)?;
    Ok(port.report)
}

fn io_error(error: impl Into<io::Error>) -> GtpuError {
    GtpuError::io(OPERATION, error.into())
}

fn open_beneath(parent: &File, name: &Path, flags: rustix::fs::OFlags) -> Result<File, GtpuError> {
    rustix::fs::openat2(
        parent,
        name,
        flags | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_XDEV,
    )
    .map(File::from)
    .map_err(io_error)
}

fn ensure_directory(parent: &File, name: &OsStr) -> Result<File, GtpuError> {
    match rustix::fs::mkdirat(parent, name, rustix::fs::Mode::from_bits_truncate(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(io_error(error)),
    }
    open_beneath(
        parent,
        Path::new(name),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
    )
}

fn finish_exclusion(
    control: &File,
    legacy_name: &str,
    expected: Option<(u64, u64)>,
) -> Result<Option<File>, GtpuError> {
    let (legacy, staging_name) = match open_beneath(
        control,
        Path::new(legacy_name),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
    ) {
        Ok(legacy) => (legacy, None),
        Err(GtpuError::Io {
            kind: io::ErrorKind::NotFound,
            ..
        }) if expected.is_none() => {
            // Once the graph leaf is gone, an interruption must not publish
            // an empty exclusion whose hashed name cannot be recovered from
            // an absent interface. Publish its complete marker atomically.
            let name = AyaGtpuRuntime::historical_25_ordinary_exclusion_staging_name(
                legacy_name,
                &historical_25_handoff_nonce()?,
            );
            rustix::fs::mkdirat(
                control,
                name.as_str(),
                rustix::fs::Mode::from_bits_truncate(0o700),
            )
            .map_err(io_error)?;
            let directory = open_beneath(
                control,
                Path::new(&name),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            )?;
            lock(&directory)?;
            (directory, Some(name))
        }
        Err(error) => return Err(error),
    };
    AyaGtpuRuntime::verify_control_directory(&legacy, expected, OPERATION)?;
    let marker = ensure_directory(&legacy, OsStr::new(HISTORICAL_25_ORDINARY_EXCLUSION_MARKER))?;
    AyaGtpuRuntime::verify_empty_marker_directory(&marker, None, OPERATION)?;
    if let Some(staging_name) = staging_name {
        rustix::fs::renameat_with(
            control,
            staging_name.as_str(),
            control,
            legacy_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io_error)?;
        // Keep the newly published lock inode held through the final check.
        Ok(Some(legacy))
    } else {
        Ok(None)
    }
}

fn lock(directory: &File) -> Result<(), GtpuError> {
    match rustix::fs::flock(
        directory,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    ) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::AGAIN) => Err(GtpuError::RetryRequired {
            operation: "ebpf_workload_cleanup_writer_busy",
        }),
        Err(error) => Err(io_error(error)),
    }
}

fn entries(directory: &File) -> Result<Vec<OsString>, GtpuError> {
    let scan = rustix::fs::openat(
        directory,
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io_error)?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&scan).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn selector_marker(name: &OsStr) -> bool {
    [
        b"SELECTOR_AUTHORITY_".as_slice(),
        b"SELECTOR_DECOMMISSIONED_",
        b"SELECTOR_TERMINAL_FENCE_",
    ]
    .iter()
    .any(|prefix| name.as_bytes().starts_with(prefix))
}

struct Node {
    path: PathBuf,
    parent: usize,
    identity: (u64, u64),
    directory: Option<File>,
    // Holding maps prevents map-ID reuse across reference scans and unlink.
    map: Option<(MapData, u32)>,
    program_id: Option<u32>,
    object_pin: bool,
    // Keep the pin inode alive as well as its object, preventing inode reuse.
    _pin: Option<File>,
    keep: bool,
    removed: bool,
}

struct ExclusiveCleanup {
    root_path: PathBuf,
    root_identity: (u64, u64),
    nodes: Vec<Node>,
    locks: Vec<File>,
    leaves: BTreeSet<String>,
    interfaces: Vec<Interface>,
    priority: u16,
    strict: bool,
    report: EbpfStrictWorkloadResetReport,
    retired_programs: HashSet<u32>,
}

struct Interface {
    name: String,
    ifindex: Option<u32>,
    by_name: bool,
    hooks: Vec<Filter>,
}

impl ExclusiveCleanup {
    fn directory(&self, index: usize) -> Result<&File, GtpuError> {
        self.nodes
            .get(index)
            .and_then(|node| node.directory.as_ref())
            .ok_or_else(|| state_indeterminate(OPERATION))
    }

    fn inventory_directory(&mut self, parent: usize) -> Result<bool, GtpuError> {
        for name in entries(self.directory(parent)?)? {
            // Only the strict assertion says these cannot protect a bound
            // selector's permanent history, including torn marker layouts.
            if !self.strict && selector_marker(&name) {
                return Ok(true);
            }
            let path = self.nodes[parent].path.join(&name);
            let descriptor = open_beneath(
                self.directory(parent)?,
                Path::new(&name),
                rustix::fs::OFlags::PATH,
            )?;
            let metadata = descriptor.metadata().map_err(io_error)?;
            let identity = (metadata.dev(), metadata.ino());
            if metadata.dev() != self.root_identity.0 || metadata.file_type().is_symlink() {
                return Err(state_indeterminate(OPERATION));
            }
            let directory = if metadata.is_dir() {
                let directory = open_beneath(
                    self.directory(parent)?,
                    Path::new(&name),
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                )?;
                let actual = directory.metadata().map_err(io_error)?;
                if (actual.dev(), actual.ino()) != identity {
                    return Err(state_indeterminate(OPERATION));
                }
                // Any directory in the control hierarchy may be a predecessor
                // writer or operation lock. Refuse a live holder before effects.
                if path.starts_with(RECONCILER_CONTROL_DIRECTORY)
                    && !self.locks.iter().any(|held| {
                        held.metadata()
                            .is_ok_and(|meta| (meta.dev(), meta.ino()) == identity)
                    })
                {
                    lock(&directory)?;
                }
                Some(directory)
            } else {
                None
            };
            let (map, program_id) = if directory.is_none() {
                // Reopen the inspected inode, not the name a writer could
                // replace between the O_PATH open and BPF_OBJ_GET.
                let pin = PathBuf::from("/proc/self/fd").join(descriptor.as_raw_fd().to_string());
                let data = MapData::from_pin(pin).map_err(|_| state_indeterminate(OPERATION))?;
                // BPF_OBJ_GET accepts several object types. Do not interpret a
                // program or link descriptor as a map with a coincident ID.
                let fdinfo = fs::read_to_string(format!(
                    "/proc/self/fdinfo/{}",
                    data.fd().as_fd().as_raw_fd()
                ))
                .map_err(io_error)?;
                let field = |key| {
                    fdinfo
                        .lines()
                        .find_map(|line| line.strip_prefix(key))
                        .and_then(|id| id.parse::<u32>().ok())
                };
                if field("link_id:\t").is_some() {
                    (None, field("prog_id:\t"))
                } else if let Some(id) = field("map_id:\t") {
                    (Some((data, id)), None)
                } else {
                    // Program and link pins belong to the declared root.
                    // Removing a link pin releases its attachment when it is
                    // the final reference. Do not hold its FD during the wait.
                    let id = field("prog_id:\t").ok_or_else(|| state_indeterminate(OPERATION))?;
                    (None, Some(id))
                }
            } else {
                (None, None)
            };
            let direct_control_child =
                self.nodes[parent].path == Path::new(RECONCILER_CONTROL_DIRECTORY);
            let stem = name
                .as_bytes()
                .strip_suffix(RECONCILER_OPERATION_LOCK_SUFFIX.as_bytes())
                .unwrap_or(name.as_bytes());
            let lock_name = stem.len() == 64
                && stem
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
            let keep = directory.is_some()
                && (path == Path::new(RECONCILER_CONTROL_DIRECTORY)
                    || direct_control_child && lock_name
                    || !self.strict
                        && self.nodes[parent].keep
                        && self.nodes[parent].parent != 0
                        && self.nodes[self.nodes[parent].parent].path
                            == Path::new(RECONCILER_CONTROL_DIRECTORY)
                        && name == HISTORICAL_25_ORDINARY_EXCLUSION_MARKER);
            if keep {
                AyaGtpuRuntime::verify_control_directory(
                    directory
                        .as_ref()
                        .ok_or_else(|| state_indeterminate(OPERATION))?,
                    Some(identity),
                    OPERATION,
                )?;
            }
            if parent == 0 {
                if let Some(name) = name
                    .to_str()
                    .filter(|name| validate_interface_name(name).is_ok())
                {
                    self.leaves.insert(name.to_owned());
                }
            }
            let index = self.nodes.len();
            let object_pin = directory.is_none() && map.is_none();
            self.nodes.push(Node {
                path,
                parent,
                identity,
                directory,
                map,
                program_id,
                object_pin,
                _pin: Some(descriptor),
                keep,
                removed: false,
            });
            self.revalidate_node(index)?;
        }
        Ok(false)
    }

    fn revalidate_node(&self, index: usize) -> Result<(), GtpuError> {
        let (root, metadata) =
            AyaGtpuRuntime::open_bpffs_namespace_root(&self.root_path, false, OPERATION)?;
        if (metadata.dev(), metadata.ino()) != self.root_identity {
            return Err(state_indeterminate(OPERATION));
        }
        if index != 0 {
            let node = &self.nodes[index];
            let current = open_beneath(&root, &node.path, rustix::fs::OFlags::PATH)?;
            let metadata = current.metadata().map_err(io_error)?;
            if (metadata.dev(), metadata.ino()) != node.identity {
                return Err(state_indeterminate(OPERATION));
            }
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<(), GtpuError> {
        self.revalidate_interface()?;
        for (index, node) in self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| !node.removed)
        {
            self.revalidate_node(index)?;
            if let Some(directory) = &node.directory {
                let mut expected = self
                    .nodes
                    .iter()
                    .enumerate()
                    .filter(|(child, node)| *child != 0 && node.parent == index && !node.removed)
                    .map(|(_, node)| {
                        node.path
                            .file_name()
                            .map(OsStr::to_os_string)
                            .ok_or_else(|| state_indeterminate(OPERATION))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                expected.sort_unstable();
                if entries(directory)? != expected {
                    return Err(state_indeterminate(OPERATION));
                }
            }
        }
        Ok(())
    }

    fn filters(&self, ifindex: u32) -> Result<Vec<Filter>, GtpuError> {
        let mut filters = Vec::new();
        for direction in [TcAttachType::Egress, TcAttachType::Ingress] {
            let dump = filter_dump(
                ifindex,
                direction,
                self.priority,
                None,
                LegacyV2ProgramScan::Disabled,
            )?;
            if dump.workload_filters_indeterminate {
                return Err(state_indeterminate(OPERATION));
            }
            filters.extend(dump.workload_filters);
        }
        let mut positions = HashSet::new();
        if filters.iter().any(|filter| {
            !positions.insert((
                filter.parent,
                filter.chain,
                filter.protocol,
                filter.priority,
                filter.handle,
            ))
        }) {
            return Err(state_indeterminate(OPERATION));
        }
        Ok(filters)
    }

    fn inventory_interfaces(&mut self) -> Result<(), GtpuError> {
        self.revalidate_interface()?;
        let mut referenced = self.referencing_programs()?;
        let declared = self.leaves.clone();
        let mut interfaces = declared
            .iter()
            .map(|name| {
                Ok(Interface {
                    name: name.clone(),
                    ifindex: interface_index(name)?,
                    by_name: true,
                    hooks: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, GtpuError>>()?;
        // Resolve declared names directly to their indices. The namespace's
        // primary-name list need not contain a caller's alternative name.
        let mut declared_indices = HashSet::new();
        for interface in &mut interfaces {
            if let Some(ifindex) = interface.ifindex {
                if !declared_indices.insert(ifindex) {
                    continue;
                }
                interface.hooks = self
                    .filters(ifindex)?
                    .into_iter()
                    .filter(|filter| {
                        filter.sdk
                            || filter.owned_slot(self.priority, self.strict)
                            || filter.program_id.is_some_and(|id| referenced.contains(&id))
                    })
                    .collect();
                for hook in &interface.hooks {
                    if let Some(id) = hook.program_id {
                        referenced.remove(&id);
                    }
                }
            }
        }
        // Map references recover the identity of a renamed interface even
        // when no pin leaf has its new name. On unrelated devices, only that
        // reference grants authority; names or slot placement alone do not.
        for interface in nix::net::if_::if_nameindex().map_err(io_error)?.iter() {
            let Ok(name) = interface.name().to_str() else {
                continue;
            };
            // A prior reset can remove the graph before finishing an existing
            // exclusion. Recover that marker from its retained lock name; this
            // does not grant authority over any additional interface hooks.
            let legacy_path = Path::new(RECONCILER_CONTROL_DIRECTORY).join(
                AyaGtpuRuntime::historical_25_legacy_leaf_name(OsStr::new(name))?,
            );
            if self
                .nodes
                .iter()
                .any(|node| node.keep && node.path == legacy_path)
            {
                self.leaves.insert(name.to_owned());
            }
            if declared_indices.contains(&interface.index()) || referenced.is_empty() {
                continue;
            }
            // Discovery cannot make an unrelated device a prerequisite. Its
            // qdisc may use a different parent/shared block or exceed the
            // parser bound/deadline. Unresolved map references still refuse
            // map removal after all identifiable hooks have been detached.
            let Ok(filters) = self.filters(interface.index()) else {
                continue;
            };
            let hooks = filters
                .into_iter()
                .filter(|filter| filter.program_id.is_some_and(|id| referenced.contains(&id)))
                .collect::<Vec<_>>();
            if !hooks.is_empty() {
                for hook in &hooks {
                    if let Some(id) = hook.program_id {
                        referenced.remove(&id);
                    }
                }
                self.leaves.insert(name.to_owned());
                interfaces.push(Interface {
                    name: name.to_owned(),
                    ifindex: Some(interface.index()),
                    by_name: false,
                    hooks,
                });
            }
        }
        self.interfaces = interfaces;
        self.revalidate_interface()
    }

    fn revalidate_interface(&self) -> Result<(), GtpuError> {
        for interface in &self.interfaces {
            if interface_index(&interface.name)? != interface.ifindex {
                return Err(state_indeterminate(
                    "ebpf_exclusive_workload_interface_changed",
                ));
            }
        }
        Ok(())
    }

    fn referencing_programs(&self) -> Result<HashSet<u32>, GtpuError> {
        let maps = self
            .nodes
            .iter()
            .filter_map(|node| node.map.as_ref().map(|(_, id)| *id))
            .collect::<HashSet<_>>();
        let mut references = HashSet::new();
        if maps.is_empty() {
            return Ok(references);
        }
        for info in scan_programs()? {
            let referenced = match info.map_ids() {
                Ok(Some(ids)) => ids,
                // A program can retire between the global ID scan and its
                // metadata read. ENOENT proves that reference has gone.
                Err(error) if program_disappeared(&error) => continue,
                Err(error) => return Err(program_error(PROGRAM_SCAN, &error)),
                Ok(None) => return Err(state_indeterminate(PROGRAM_SCAN)),
            };
            if referenced.iter().any(|id| maps.contains(id)) {
                references.insert(info.id());
            }
        }
        Ok(references)
    }

    fn require_unreferenced(&self) -> Result<(), GtpuError> {
        let references = self.referencing_programs()?;
        if references
            .iter()
            .any(|id| !self.retired_programs.contains(id))
        {
            return Err(state_indeterminate(
                "ebpf_exclusive_workload_external_program_reference",
            ));
        }
        if !references.is_empty() {
            return Err(state_indeterminate(
                "ebpf_exclusive_workload_detached_program_reference",
            ));
        }
        Ok(())
    }

    fn verify_detached_hooks(&self) -> Result<(), GtpuError> {
        self.revalidate_interface()?;
        for interface in &self.interfaces {
            if let Some(ifindex) = interface.ifindex {
                if self.filters(ifindex)?.iter().any(|filter| {
                    interface.by_name
                        && (filter.sdk || filter.owned_slot(self.priority, self.strict))
                        || interface.hooks.iter().any(|old| {
                            (
                                old.parent,
                                old.chain,
                                old.protocol,
                                old.priority,
                                old.handle,
                            ) == (
                                filter.parent,
                                filter.chain,
                                filter.protocol,
                                filter.priority,
                                filter.handle,
                            )
                        })
                }) {
                    return Err(state_indeterminate("ebpf_exclusive_workload_hooks_changed"));
                }
            }
        }
        Ok(())
    }
}

fn interface_index(name: &str) -> Result<Option<u32>, GtpuError> {
    match nix::net::if_::if_nametoindex(name) {
        Ok(index) => Ok(Some(index)),
        Err(nix::errno::Errno::ENODEV | nix::errno::Errno::ENXIO) => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn program_disappeared(error: &ProgramError) -> bool {
    matches!(error, ProgramError::SyscallError(error) if error.io_error.kind() == io::ErrorKind::NotFound)
}

fn scan_programs() -> Result<Vec<ProgramInfo>, GtpuError> {
    let mut programs = Vec::new();
    for info in loaded_programs() {
        match info {
            Ok(info) => programs.push(info),
            Err(error) if program_disappeared(&error) => {}
            Err(error) => return Err(program_error(PROGRAM_SCAN, &error)),
        }
    }
    Ok(programs)
}

impl ExclusiveWorkloadCleanup for ExclusiveCleanup {
    fn inventory(&mut self) -> Result<ExclusiveCleanupInventory, GtpuError> {
        // Iterative traversal avoids a process-stack limit on old nested
        // layouts. Descendants always receive greater indices than parents.
        let mut pending = vec![0];
        while let Some(parent) = pending.pop() {
            let first_child = self.nodes.len();
            if self.inventory_directory(parent)? {
                return Ok(ExclusiveCleanupInventory {
                    interfaces: Vec::new(),
                    object_pins: Vec::new(),
                    pins: Vec::new(),
                    selector_bound: true,
                });
            }
            pending.extend(
                (first_child..self.nodes.len())
                    .filter(|index| self.nodes[*index].directory.is_some()),
            );
        }
        self.inventory_interfaces()?;
        self.revalidate()?;
        let (object_pins, pins) = (1..self.nodes.len())
            .rev()
            .filter(|index| !self.nodes[*index].keep)
            .partition(|index| self.nodes[*index].object_pin);
        Ok(ExclusiveCleanupInventory {
            interfaces: (0..self.interfaces.len()).collect(),
            object_pins,
            pins,
            selector_bound: false,
        })
    }

    fn detach_interface(&mut self, index: usize) -> Result<(), GtpuError> {
        let hooks = self.interfaces[index].hooks.clone();
        if let Some(ifindex) = self.interfaces[index].ifindex {
            for hook in hooks {
                self.revalidate()?;
                if !self.filters(ifindex)?.contains(&hook) {
                    return Err(state_indeterminate(OPERATION));
                }
                hook.detach(ifindex)?;
                self.report.tc_filters += 1;
                if let Some(id) = hook.program_id {
                    self.retired_programs.insert(id);
                }
            }
        }
        self.revalidate()
    }

    fn unpin(&mut self, index: usize) -> Result<(), GtpuError> {
        self.revalidate()?;
        let node = &self.nodes[index];
        if !node.object_pin {
            self.require_unreferenced()?;
        }
        let name = node
            .path
            .file_name()
            .ok_or_else(|| state_indeterminate(OPERATION))?;
        rustix::fs::unlinkat(
            self.directory(node.parent)?,
            name,
            if node.directory.is_some() {
                rustix::fs::AtFlags::REMOVEDIR
            } else {
                rustix::fs::AtFlags::empty()
            },
        )
        .map_err(io_error)?;
        if selector_marker(name) {
            self.report.selector_markers += 1;
        }
        if node.directory.is_some() && name == HISTORICAL_25_ORDINARY_EXCLUSION_MARKER {
            self.report.exclusion_marker_directories += 1;
        }
        if let Some(id) = node.program_id {
            self.retired_programs.insert(id);
        }
        self.nodes[index].removed = true;
        self.nodes[index]._pin = None;
        self.revalidate()
    }

    fn wait_for_detached_programs(&mut self) -> Result<(), GtpuError> {
        self.verify_detached_hooks()?;
        let deadline = std::time::Instant::now() + PROGRAM_RELEASE_WAIT;
        loop {
            let retired_still_loaded = !self.retired_programs.is_empty()
                && scan_programs()?
                    .iter()
                    .any(|info| self.retired_programs.contains(&info.id()));
            // A previous call or namespace teardown can have detached these
            // references already. Give them the same one bounded grace period
            // before classifying anything this call did not retire as external.
            if !retired_still_loaded && self.referencing_programs()?.is_empty() {
                break;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        }
        self.require_unreferenced()
    }

    fn finish(&mut self) -> Result<(), GtpuError> {
        self.revalidate()?;
        self.require_unreferenced()?;
        self.verify_detached_hooks()?;
        // Finish every inventoried leaf, including names from before a rename.
        // The ordinary form preserves earlier exclusions; strict reset rebuilds
        // them. Resetting another interface must not strand ordinary attachment.
        let control = self
            .nodes
            .iter()
            .position(|node| node.path == Path::new(RECONCILER_CONTROL_DIRECTORY))
            .ok_or_else(|| state_indeterminate(OPERATION))?;
        for leaf in &self.leaves {
            self.revalidate_node(control)?;
            let legacy_name = AyaGtpuRuntime::historical_25_legacy_leaf_name(OsStr::new(leaf))?;
            let legacy_path = Path::new(RECONCILER_CONTROL_DIRECTORY).join(&legacy_name);
            let expected = self
                .nodes
                .iter()
                .find(|node| node.keep && node.path == legacy_path)
                .map(|node| node.identity);
            if let Some(lock) = finish_exclusion(self.directory(control)?, &legacy_name, expected)?
            {
                self.locks.push(lock);
            }
        }
        self.revalidate_interface()?;
        self.revalidate_node(control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter_message(kind: &[u8], name: Option<&[u8]>, id: Option<&[u8]>) -> Vec<u8> {
        let mut attributes = Vec::new();
        append_tc_attribute(&mut attributes, sys::TCA_KIND, kind).unwrap();
        let mut options = Vec::new();
        if let Some(name) = name {
            append_tc_attribute(&mut options, sys::TCA_BPF_NAME, name).unwrap();
        }
        if let Some(id) = id {
            append_tc_attribute(&mut options, sys::TCA_BPF_ID, id).unwrap();
        }
        append_tc_attribute(&mut attributes, sys::TCA_OPTIONS, &options).unwrap();
        append_tc_attribute(&mut attributes, TCA_CHAIN, &7_u32.to_ne_bytes()).unwrap();
        build_tc_request(
            sys::RTM_NEWTFILTER,
            sys::NLM_F_MULTI,
            11,
            13,
            17,
            7,
            sys::TC_H_CLSACT_INGRESS,
            (53 << 16) | u32::from(0x0800_u16.to_be()),
            &attributes,
        )
        .unwrap()
    }

    fn parse(message: &[u8], state: &mut TfilterDumpState) -> Result<DumpOutcome, GtpuError> {
        parse_tfilter_dump(
            message,
            50,
            TfilterDumpExpectation {
                sequence: 11,
                port_id: 13,
                ifindex: 17,
                parent: sys::TC_H_CLSACT_INGRESS,
                protocol: None,
                legacy_v2_scan: LegacyV2ProgramScan::Disabled,
            },
            state,
        )
    }

    #[test]
    fn strict_slot_includes_every_chain_and_protocol_only_at_declared_placement() {
        let mut filter = Filter {
            parent: sys::TC_H_CLSACT_INGRESS,
            chain: 0,
            protocol: TC_PROTOCOL_ALL,
            priority: 50,
            handle: u32::from(TC_HANDLE),
            kind: b"matchall\0".to_vec(),
            sdk: false,
            program_id: None,
        };
        for chain in [0, 7, u32::MAX] {
            for protocol in [TC_PROTOCOL_ALL, 0x0800_u16.to_be(), 0x86dd_u16.to_be()] {
                filter.chain = chain;
                filter.protocol = protocol;
                assert!(filter.owned_slot(50, true));
                assert_eq!(
                    filter.owned_slot(50, false),
                    chain == 0 && protocol == TC_PROTOCOL_ALL
                );
                assert!(!filter.owned_slot(51, true));
            }
        }
        filter.handle = 2;
        assert!(!filter.owned_slot(50, true));
        filter.handle = 0;
        assert!(!filter.owned_slot(50, true));
    }

    #[test]
    fn exclusive_filter_dump_retains_coordinates_and_nameless_program_ids() {
        for (kind, name, id, sdk, expected_id) in [
            (
                b"bpf\0".as_slice(),
                Some(b"opc_gtpu_uplink\0".as_slice()),
                Some(73_u32),
                true,
                Some(73),
            ),
            (b"bpf\0".as_slice(), None, Some(74_u32), false, Some(74)),
            (b"matchall\0".as_slice(), None, None, false, None),
        ] {
            let id_bytes = id.map(u32::to_ne_bytes);
            let message =
                filter_message(kind, name, id_bytes.as_ref().map(|value| value.as_slice()));
            let mut state = TfilterDumpState::default();
            assert!(matches!(
                parse(&message, &mut state).unwrap(),
                DumpOutcome::More
            ));
            assert!(!state.workload_filters_indeterminate);
            assert_eq!(
                state.workload_filters,
                vec![Filter {
                    parent: sys::TC_H_CLSACT_INGRESS,
                    chain: 7,
                    protocol: 0x0800_u16.to_be(),
                    priority: 53,
                    handle: 7,
                    kind: kind.to_vec(),
                    sdk,
                    program_id: expected_id,
                }]
            );
        }
        let malformed_id = filter_message(b"bpf\0", None, Some(&[1, 2, 3]));
        let mut state = TfilterDumpState::default();
        parse(&malformed_id, &mut state).unwrap();
        assert!(state.workload_filters_indeterminate);
        assert!(state.workload_filters.is_empty());
    }

    #[test]
    fn exclusive_filter_dump_keeps_ingress_qdisc_and_shared_block_answers_unproven() {
        let original = filter_message(b"matchall\0", None, None);
        let mut ingress = original.clone();
        ingress[28..32].copy_from_slice(&0xffff_0000_u32.to_ne_bytes());
        let mut shared_block = original;
        shared_block[20..24].copy_from_slice(&(-1_i32).to_ne_bytes());
        for message in [ingress, shared_block] {
            let mut state = TfilterDumpState::default();
            assert!(matches!(
                parse(&message, &mut state),
                Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_tc_filter_dump"
                })
            ));
            assert!(state.workload_filters.is_empty());
        }
    }

    #[test]
    fn exclusive_filter_dump_bounds_non_sdk_inventory_without_changing_ordinary_results() {
        let mut message = filter_message(b"matchall\0", None, None);
        let mut state = TfilterDumpState::default();
        for handle in 1_u32..=256 {
            message[24..28].copy_from_slice(&handle.to_ne_bytes());
            parse(&message, &mut state).unwrap();
        }
        assert!(
            state.workload_filters_indeterminate,
            "an oversized inventory is not authoritative"
        );
        assert!(
            state.workload_filters.len() <= 64,
            "allocation must remain bounded"
        );
        assert!(state.sdk_programs.is_empty());
        assert!(state.owner.is_none());
    }
}
