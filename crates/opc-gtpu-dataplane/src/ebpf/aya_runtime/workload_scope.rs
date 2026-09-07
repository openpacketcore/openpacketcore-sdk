//! Workload-local garbage collection. There is no remote owner or cleanup WAL:
//! the stable namespace and existing writer flock bound each fresh inventory.

use super::*;
use crate::ebpf::workload_scope::{cleanup, CleanupInventory, WorkloadCleanup};

const OPERATION: &str = "ebpf_workload_cleanup";

pub(super) fn reset(
    runtime: &AyaGtpuRuntime,
    ifindex: Option<u32>,
    pin_dir: &Path,
    tc_priority: u16,
) -> Result<(), GtpuError> {
    if !runtime
        .devices
        .lock()
        .map_err(|_| GtpuError::io(OPERATION, super::super::poisoned_lock()))?
        .is_empty()
    {
        return Err(GtpuError::AlreadyExists);
    }
    let writer_busy = |error| match error {
        GtpuError::AlreadyExists => GtpuError::RetryRequired {
            operation: "ebpf_workload_cleanup_writer_busy",
        },
        error => error,
    };
    let exclusion =
        AyaGtpuRuntime::acquire_optional_existing_historical_25_ordinary_exclusion(pin_dir)
            .map_err(writer_busy)?;
    let ownership =
        AyaGtpuRuntime::acquire_reconciler_ownership_inner(pin_dir, None, true, exclusion)
            .map_err(writer_busy)?;
    let lock = AyaGtpuRuntime::acquire_operation_control_lock(&ownership, OPERATION)?;
    let mut port = KernelCleanup {
        ownership,
        lock,
        ifindex,
        tc_priority,
        graph_identity: None,
        maps: HashMap::new(),
        programs: Vec::new(),
    };
    cleanup(&mut port)
}

struct InspectedMap {
    // Retaining the descriptor prevents kernel map-ID reuse during cleanup.
    _data: MapData,
    id: u32,
    pin_identity: (u64, u64),
}

struct KernelCleanup {
    ownership: Arc<ReconcilerOwnership>,
    lock: OperationControlLock,
    ifindex: Option<u32>,
    tc_priority: u16,
    graph_identity: Option<(u64, u64)>,
    maps: HashMap<usize, InspectedMap>,
    programs: Vec<CurrentSdkProgram>,
}

impl KernelCleanup {
    fn control(&self) -> Result<File, GtpuError> {
        AyaGtpuRuntime::revalidate_current_control_path(&self.ownership, &self.lock, OPERATION)
    }

    fn references_are_owned(&self, allow_local_hooks: bool) -> Result<(), GtpuError> {
        let ids = self.maps.values().map(|map| map.id).collect::<HashSet<_>>();
        if ids.is_empty() {
            return Ok(());
        }
        let allowed = if allow_local_hooks {
            self.programs
                .iter()
                .filter_map(|program| program.occupant.program_id)
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        for result in loaded_programs() {
            let info = result.map_err(|error| program_error(OPERATION, &error))?;
            let referenced = info
                .map_ids()
                .map_err(|error| program_error(OPERATION, &error))?
                .ok_or_else(|| state_indeterminate(OPERATION))?;
            if referenced.iter().any(|id| ids.contains(id)) && !allowed.contains(&info.id()) {
                return Err(GtpuError::RetryRequired {
                    operation: "ebpf_workload_cleanup_program_references",
                });
            }
        }
        Ok(())
    }
}

impl WorkloadCleanup for KernelCleanup {
    fn inventory(&mut self) -> Result<CleanupInventory, GtpuError> {
        let control = self.control()?;
        if self.ownership.historical_25_handoff.is_some()
            || AyaGtpuRuntime::read_current_recovery_proof(&self.ownership)?.is_some()
            || AyaGtpuRuntime::read_current_terminal_proof(&self.ownership)?.is_some()
            || AyaGtpuRuntime::read_current_finalized_successor_record(&self.ownership, OPERATION)?
                .is_some()
            || !AyaGtpuRuntime::ordinary_current_root_layout_is_exact(&self.ownership, OPERATION)?
        {
            return Err(GtpuError::AlreadyExists);
        }
        let selector_bound =
            !AyaGtpuRuntime::marker_inventory_identity_snapshot(&control)?.is_empty();

        let graph = match AyaGtpuRuntime::open_current_pin_cleanup_descriptors(
            &self.ownership,
            None,
            OPERATION,
        ) {
            Ok((_, graph)) => Some(graph),
            Err(GtpuError::Io {
                kind: io::ErrorKind::NotFound,
                ..
            }) => None,
            Err(error) => return Err(error),
        };
        if let Some(graph) = graph {
            let metadata = AyaGtpuRuntime::verify_private_bpffs_directory(&graph, OPERATION)?;
            self.graph_identity = Some((metadata.dev(), metadata.ino()));
            let entries = AyaGtpuRuntime::current_directory_entries_at(&graph, OPERATION)?;
            if entries
                .iter()
                .any(|name| !CURRENT_MAP_NAMES.contains(&name.as_str()))
            {
                return Err(GtpuError::AlreadyExists);
            }
            for (index, spec) in CURRENT_MAP_SPECS.iter().enumerate() {
                if !entries.contains(spec.name) {
                    continue;
                }
                let identity = AyaGtpuRuntime::pin_leaf_identity(&graph, spec.name, OPERATION)?;
                let path = AyaGtpuRuntime::historical_25_descriptor_relative_pin_path(
                    &graph, spec.name, OPERATION,
                )?;
                let data = MapData::from_pin(path).map_err(|_| state_indeterminate(OPERATION))?;
                let info = data.info().map_err(|_| state_indeterminate(OPERATION))?;
                if info
                    .map_type()
                    .map_err(|_| state_indeterminate(OPERATION))? as u32
                    != spec.map_type
                    || info.name() != kernel_program_name(spec.name)
                    || info.key_size() != spec.key_size
                    || info.value_size() != spec.value_size
                    || info.max_entries() != spec.max_entries
                    || info.map_flags() != 0
                    || AyaGtpuRuntime::pin_leaf_identity(&graph, spec.name, OPERATION)? != identity
                {
                    return Err(GtpuError::AlreadyExists);
                }
                self.maps.insert(
                    index,
                    InspectedMap {
                        id: info.id(),
                        _data: data,
                        pin_identity: identity,
                    },
                );
            }
        }
        if let Some(ifindex) = self.ifindex {
            self.programs = AyaGtpuRuntime::require_no_foreign_generation(
                ifindex,
                self.tc_priority,
                OPERATION,
                self.graph_identity.is_some(),
            )?;
            AyaGtpuRuntime::require_current_program_pin_graph(
                &self.programs,
                &self.ownership.canonical_pin_dir,
            )?;
        }
        // A writer in an old network namespace can still be alive even when
        // the interface is absent in this namespace. Scan all loaded programs.
        self.references_are_owned(true)?;
        self.control()?;
        let mut pins = self.maps.keys().copied().collect::<Vec<_>>();
        pins.sort_unstable();
        Ok(CleanupInventory {
            pins,
            selector_bound,
        })
    }

    fn detach_owned_hooks(&mut self) -> Result<(), GtpuError> {
        self.control()?;
        self.references_are_owned(true)?;
        if let Some(ifindex) = self.ifindex {
            AyaGtpuRuntime::fence_current_hooks(ifindex, self.tc_priority, &self.programs)
                .map_err(|_| state_indeterminate(OPERATION))?;
        }
        self.control()?;
        // Also catches a program attached to another namespace or kept alive
        // through another descriptor. Unpinning is forbidden until it is gone.
        self.references_are_owned(false)
    }

    fn unpin(&mut self, index: usize) -> Result<(), GtpuError> {
        self.control()?;
        self.references_are_owned(false)?;
        let map = self
            .maps
            .get(&index)
            .ok_or_else(|| state_indeterminate(OPERATION))?;
        let spec = CURRENT_MAP_SPECS
            .get(index)
            .ok_or_else(|| state_indeterminate(OPERATION))?;
        let (_, graph) = AyaGtpuRuntime::open_current_pin_cleanup_descriptors(
            &self.ownership,
            self.graph_identity,
            OPERATION,
        )?;
        if AyaGtpuRuntime::pin_leaf_identity(&graph, spec.name, OPERATION)? != map.pin_identity {
            return Err(state_indeterminate(OPERATION));
        }
        AyaGtpuRuntime::unlink_current_pin_leaf(
            &self.ownership,
            self.graph_identity,
            spec.name,
            map.id,
            OPERATION,
        )?;
        self.control()?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), GtpuError> {
        self.control()?;
        self.references_are_owned(false)?;
        if self.graph_identity.is_some() {
            AyaGtpuRuntime::remove_current_pin_dir(
                &self.ownership,
                self.graph_identity,
                OPERATION,
            )?;
        }
        self.control()?;
        Ok(())
    }
}
