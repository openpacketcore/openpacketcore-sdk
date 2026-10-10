//! Current-image policy is supplied by the backend. This module only checks
//! exact graph relationships and performs descriptor-backed local retirement.

use super::*;
use crate::bpf::{GlobalObjectDisposition, MapHandle, MapIdentity, ProgramHandle, ProgramIdentity};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A backend's expected map definition from its embedded current image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMap {
    /// Full map symbol and optional pin-leaf name.
    pub name: String,
    /// Kernel map type.
    pub map_type: u32,
    /// Key width in bytes.
    pub key_size: u32,
    /// Value width in bytes.
    pub value_size: u32,
    /// Maximum entry count.
    pub max_entries: u32,
    /// Map creation flags.
    pub flags: u32,
    /// BTF key type ID, zero for a legacy map definition.
    pub btf_key_type_id: u32,
    /// BTF value type ID, zero for a legacy map definition.
    pub btf_value_type_id: u32,
    /// Map-specific creation information.
    pub map_extra: u64,
    /// Whether this image permits a pin for the map.
    pub pinned: bool,
}
impl ArtifactMap {
    fn matches(&self, observed: &MapIdentity) -> bool {
        observed.name == kernel_name(&self.name)
            && observed.map_type == self.map_type
            && observed.key_size == self.key_size
            && observed.value_size == self.value_size
            && observed.max_entries == self.max_entries
            && observed.flags == self.flags
            && observed.map_extra == self.map_extra
            && observed.btf_key_type_id == self.btf_key_type_id
            && observed.btf_value_type_id == self.btf_value_type_id
            && ((self.btf_key_type_id == 0 && self.btf_value_type_id == 0)
                == (observed.btf_id == 0))
            && observed.btf_vmlinux_value_type_id == 0
            && observed.btf_vmlinux_id == 0
            && observed.ifindex == 0
            && observed.netns_dev == 0
            && observed.netns_ino == 0
    }
}

/// A backend's expected tc program and complete referenced-map relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProgram {
    /// Current-image program symbol, also the expected tc name.
    pub name: String,
    /// Exact kernel tag candidates for the qualified image/kernel profiles.
    pub tags: Vec<[u8; 8]>,
    /// Complete map symbols referenced by the program, without duplicates.
    pub maps: Vec<String>,
}

/// Current-image catalog bound to exact data slots and one relative pin leaf.
///
/// This low-level declaration supplies no distributed authority. Public
/// backends derive its contents from their own embedded object, not a caller's
/// claimed program name or tag. All slots must also belong to the held scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSpec {
    directory: PathBuf,
    maps: BTreeMap<String, ArtifactMap>,
    programs: Vec<ArtifactProgram>,
    slots: BTreeMap<TcSlot, usize>,
}
impl ArtifactSpec {
    /// Validate an unambiguous current-image graph declaration.
    ///
    /// Each slot's integer selects a program in `programs`. Program symbols may
    /// also name owned program pins. Other pin names and every pinned link are
    /// conflicts. Empty directories are retained across reset.
    pub fn new(
        directory: PathBuf,
        maps: Vec<ArtifactMap>,
        programs: Vec<ArtifactProgram>,
        slots: Vec<(TcSlot, usize)>,
    ) -> Result<Self, ScopeError> {
        let valid_name = |name: &str| {
            !name.is_empty()
                && name.len() <= 127
                && name.is_ascii()
                && !name
                    .bytes()
                    .any(|byte| byte == 0 || byte == b'/' || byte == b'.')
        };
        if directory.is_absolute()
            || directory.as_os_str().is_empty()
            || directory.as_os_str().as_encoded_bytes().len() > 1024
            || directory.components().count() > 8
            || !directory
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            || directory
                .as_os_str()
                .as_encoded_bytes()
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b".." || part.contains(&0))
            || maps.is_empty()
            || maps.len() > 64
            || programs.is_empty()
            || programs.len() > 8
            || slots.is_empty()
            || slots.len() > 64
        {
            return Err(ScopeError::InvalidSpec);
        }
        let mut catalog = BTreeMap::new();
        let mut names = BTreeSet::new();
        for map in maps {
            if !valid_name(&map.name)
                || map.map_type == 0
                || map.max_entries == 0
                || !names.insert(kernel_name(&map.name))
                || catalog.insert(map.name.clone(), map).is_some()
            {
                return Err(ScopeError::InvalidSpec);
            }
        }
        for program in &programs {
            if !valid_name(&program.name)
                || !names.insert(kernel_name(&program.name))
                || catalog.contains_key(&program.name)
                || program.tags.is_empty()
                || program.tags.len() > 4
                || program.tags.iter().collect::<BTreeSet<_>>().len() != program.tags.len()
                || program.maps.is_empty()
                || program.maps.iter().collect::<BTreeSet<_>>().len() != program.maps.len()
                || program.maps.iter().any(|name| !catalog.contains_key(name))
            {
                return Err(ScopeError::InvalidSpec);
            }
        }
        let mut positions = BTreeMap::new();
        for (slot, program) in slots {
            if program >= programs.len() || positions.insert(slot, program).is_some() {
                return Err(ScopeError::InvalidSpec);
            }
        }
        Ok(Self {
            directory,
            maps: catalog,
            programs,
            slots: positions,
        })
    }
    /// Relative directory inspected for this graph's optional surviving pins.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Exact declared tc positions.
    pub fn slots(&self) -> impl Iterator<Item = TcSlot> + '_ {
        self.slots.keys().copied()
    }

    fn program_role(&self, info: &ProgramIdentity) -> Result<usize, ScopeError> {
        self.programs
            .iter()
            .position(|program| {
                info.program_type == 3
                    && info.ifindex == 0
                    && info.name == kernel_name(&program.name)
                    && program.tags.contains(&info.tag)
            })
            .ok_or(ScopeError::Conflict)
    }

    fn program_graph(
        &self,
        info: &ProgramIdentity,
        maps: &BTreeMap<u32, MapIdentity>,
    ) -> Result<(usize, BTreeMap<String, u32>), ScopeError> {
        let index = self.program_role(info)?;
        let program = &self.programs[index];
        if info.map_ids.len() != program.maps.len()
            || info.map_ids.iter().collect::<BTreeSet<_>>().len() != info.map_ids.len()
        {
            return Err(ScopeError::Conflict);
        }
        let mut named = BTreeMap::new();
        for id in &info.map_ids {
            let observed = maps.get(id).ok_or(ScopeError::Inspection)?;
            let expected = program
                .maps
                .iter()
                .find_map(|name| self.maps.get(name).filter(|map| map.matches(observed)))
                .ok_or(ScopeError::Conflict)?;
            if observed.id != *id || named.insert(expected.name.clone(), *id).is_some() {
                return Err(ScopeError::Conflict);
            }
        }
        Ok((index, named))
    }
}

fn kernel_name(name: &str) -> [u8; 16] {
    let mut result = [0; 16];
    let length = name.len().min(15);
    result[..length].copy_from_slice(&name.as_bytes()[..length]);
    result
}
fn merge_graph(
    current: &mut BTreeMap<String, u32>,
    additional: BTreeMap<String, u32>,
) -> Result<(), ScopeError> {
    for (name, id) in &additional {
        if current.get(name).is_some_and(|old| old != id)
            || current
                .iter()
                .any(|(old_name, old_id)| old_id == id && old_name != name)
        {
            return Err(ScopeError::Conflict);
        }
    }
    current.extend(additional);
    Ok(())
}

fn inspect_occupant<'a>(
    filter: &'a TcFilterIdentity,
    expected: &ArtifactProgram,
) -> Result<&'a TcBpfIdentity, ScopeError> {
    if !super::containment::software_only(filter) {
        return Err(ScopeError::Conflict);
    }
    let attached = filter.bpf().ok_or(ScopeError::Conflict)?;
    if (attached.name() != expected.name.as_bytes()
        && attached.name() != &kernel_name(&expected.name)[..expected.name.len().min(15)])
        || !expected.tags.contains(attached.tag())
    {
        return Err(ScopeError::Conflict);
    }
    Ok(attached)
}

fn check_fresh_loads<P, M>(
    program_ids: &BTreeSet<u32>,
    maps: &BTreeMap<u32, M>,
    loaded_programs: &BTreeMap<u32, P>,
    loaded_maps: &BTreeMap<u32, M>,
) -> Result<(), ScopeError> {
    if program_ids
        .iter()
        .any(|id| !loaded_programs.contains_key(id))
        || maps.keys().any(|id| !loaded_maps.contains_key(id))
    {
        return Err(ScopeError::Conflict);
    }
    Ok(())
}

/// A local retirement inventory from exact tc slots and private pinned objects.
///
/// Inspection never reopens a BPF ID. Pinless tc observations authorize only
/// exact contained retirement, not complete graph readiness. Fresh installation
/// additionally supplies all load descriptors for a full map-relationship proof.
pub struct ArtifactInventory {
    scope: LocalKernelScope,
    spec: ArtifactSpec,
    filters: Vec<TcFilterIdentity>,
    pins: Vec<PinnedObject>,
    programs: BTreeMap<u32, ProgramHandle>,
    program_ids: BTreeSet<u32>,
    maps: BTreeMap<u32, MapHandle>,
}
impl std::fmt::Debug for ArtifactInventory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArtifactInventory")
    }
}
impl ArtifactInventory {
    /// The exact catalog whose roles and slots this observation inspected.
    pub fn artifact(&self) -> &ArtifactSpec {
        &self.spec
    }
    /// The acquired writer domain retained by this observation.
    pub fn scope(&self) -> &LocalKernelScope {
        &self.scope
    }
    /// Map definitions protected against ID reuse by this inventory's FDs.
    pub fn map_identities(&self) -> impl Iterator<Item = &MapIdentity> {
        self.maps.values().map(MapHandle::identity)
    }
    /// Owned map handles, available only from retained load or private-pin FDs.
    pub fn maps(&self) -> impl Iterator<Item = &MapHandle> {
        self.maps.values()
    }
    /// Program IDs observed at owned slots or through owned pins. A tc-only ID
    /// is a diagnostic observation, never a descriptor or global release proof.
    pub fn observed_program_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.program_ids.iter().copied()
    }
    /// Program identities protected against ID reuse by this inventory's FDs.
    /// Copies may be retained for non-gating release diagnostics across retries.
    pub fn program_identities(&self) -> impl Iterator<Item = &ProgramIdentity> {
        self.programs.values().map(ProgramHandle::identity)
    }
    /// Inspect exact slots, private pins and references on covered local hooks.
    ///
    /// The backend supplies a catalog derived from its embedded current image.
    /// The caller serializes every producer using this held writer domain.
    pub fn inspect(scope: &LocalKernelScope, spec: &ArtifactSpec) -> Result<Self, ScopeError> {
        if spec
            .slots
            .keys()
            .any(|slot| !scope.spec().data_slots().contains(slot))
        {
            return Err(ScopeError::InvalidSpec);
        }
        let dumps = scope.inventory()?;
        let mut result = Self {
            scope: scope.clone(),
            spec: spec.clone(),
            filters: Vec::new(),
            pins: Vec::new(),
            programs: BTreeMap::new(),
            program_ids: BTreeSet::new(),
            maps: BTreeMap::new(),
        };
        let mut named = BTreeMap::new();
        if let Some(directory) = scope.pin_directory(&spec.directory)? {
            for name in directory.entries()? {
                let pin = directory.inspect(&name)?;
                match pin.identity() {
                    PinnedIdentity::Map(info) => {
                        let expected = spec
                            .maps
                            .get(&name)
                            .filter(|map| map.pinned && map.matches(info))
                            .ok_or(ScopeError::Conflict)?;
                        merge_graph(
                            &mut named,
                            BTreeMap::from([(expected.name.clone(), info.id)]),
                        )?;
                        let map = pin.map()?;
                        if map.identity() != info {
                            return Err(ScopeError::Conflict);
                        }
                        result.maps.insert(info.id, map);
                    }
                    PinnedIdentity::Program(info) => {
                        let role = spec.program_role(info)?;
                        if spec.programs[role].name != name {
                            return Err(ScopeError::Conflict);
                        }
                        let program = pin.program()?;
                        if program.identity() != info {
                            return Err(ScopeError::Conflict);
                        }
                        result.program_ids.insert(info.id);
                        result.programs.insert(info.id, program);
                    }
                }
                result.pins.push(pin);
            }
        }
        for (slot, expected_index) in &spec.slots {
            let mut occupants = dumps.iter().filter_map(|dump| dump.find(*slot));
            let Some(filter) = occupants.next() else {
                continue;
            };
            if occupants.next().is_some() {
                return Err(ScopeError::Conflict);
            }
            let attached = inspect_occupant(filter, &spec.programs[*expected_index])?;
            if let Some(program) = result.programs.get(&attached.program_id()) {
                if spec.program_role(program.identity())? != *expected_index
                    || program.identity().tag != *attached.tag()
                {
                    return Err(ScopeError::Conflict);
                }
            }
            // A crash may leave only the attachment. Retire that exact tc
            // occupant under writer exclusion and fresh containment, without
            // opening a node-global ID or claiming an unseen map graph.
            result.program_ids.insert(attached.program_id());
            result.filters.push(filter.clone());
        }
        check_local_references(scope.spec().data_slots(), spec, &result.program_ids, &dumps)?;
        result.recheck_objects()?;
        scope.verify()?;
        Ok(result)
    }

    fn recheck_objects(&self) -> Result<(), ScopeError> {
        self.scope.verify()?;
        for pin in &self.pins {
            pin.recheck()?;
        }
        for program in self.programs.values() {
            program.recheck().map_err(|_| ScopeError::Inspection)?;
        }
        for map in self.maps.values() {
            map.recheck().map_err(|_| ScopeError::Inspection)?;
        }
        Ok(())
    }
    /// Whether this graph has no local tc attachment or surviving pin.
    ///
    /// Harmless retained, unattached current-image programs are not effects.
    pub fn is_locally_empty(&self) -> bool {
        self.filters.is_empty() && self.pins.is_empty()
    }

    /// Require every current-image slot, program, map and declared map pin.
    /// The returned proof retains the observed native FDs across later rechecks.
    pub fn into_installed(
        mut self,
        programs: Vec<ProgramHandle>,
        maps: Vec<MapHandle>,
    ) -> Result<InstalledArtifact, ScopeError> {
        // Fresh readiness uses every load descriptor, including unpinned BTF
        // maps. Discovery alone never adopts a surviving predecessor graph.
        if programs.len() != self.spec.programs.len() || maps.len() != self.spec.maps.len() {
            return Err(ScopeError::Conflict);
        }
        let mut loaded_programs = BTreeMap::new();
        for program in programs {
            let id = program.identity().id;
            if self
                .programs
                .get(&id)
                .is_some_and(|old| old.identity() != program.identity())
                || loaded_programs.insert(id, program).is_some()
            {
                return Err(ScopeError::Conflict);
            }
        }
        let mut loaded_maps = BTreeMap::new();
        for map in maps {
            let id = map.identity().id;
            if self
                .maps
                .get(&id)
                .is_some_and(|old| old.identity() != map.identity())
                || loaded_maps.insert(id, map).is_some()
            {
                return Err(ScopeError::Conflict);
            }
        }
        check_fresh_loads(
            &self.program_ids,
            &self.maps,
            &loaded_programs,
            &loaded_maps,
        )?;
        self.programs = loaded_programs;
        self.maps = loaded_maps;
        self.require_complete()?;
        self.recheck_objects()?;
        Ok(InstalledArtifact { inventory: self })
    }
    fn require_complete(&self) -> Result<(), ScopeError> {
        if self.filters.len() != self.spec.slots.len()
            || self.programs.len() != self.spec.programs.len()
            || self.maps.len() != self.spec.maps.len()
        {
            return Err(ScopeError::Conflict);
        }
        let metadata = self
            .maps
            .iter()
            .map(|(id, handle)| (*id, handle.identity().clone()))
            .collect();
        let mut roles = BTreeSet::new();
        let mut named = BTreeMap::new();
        for program in self.programs.values() {
            let (role, maps) = self.spec.program_graph(program.identity(), &metadata)?;
            if !roles.insert(role) {
                return Err(ScopeError::Conflict);
            }
            merge_graph(&mut named, maps)?;
        }
        for (name, expected) in &self.spec.maps {
            let observed = self
                .maps
                .values()
                .find(|map| expected.matches(map.identity()))
                .ok_or(ScopeError::Conflict)?;
            if expected.pinned && !self.pins.iter().any(|pin| {
                matches!(pin.identity(), PinnedIdentity::Map(map) if map == observed.identity())
            }) {
                return Err(ScopeError::Conflict);
            }
            merge_graph(
                &mut named,
                BTreeMap::from([(name.clone(), observed.identity().id)]),
            )?;
        }
        for (slot, role) in &self.spec.slots {
            let filter = self
                .filters
                .iter()
                .find(|filter| filter.slot() == *slot)
                .and_then(TcFilterIdentity::bpf)
                .ok_or(ScopeError::Conflict)?;
            let program = self
                .programs
                .get(&filter.program_id())
                .ok_or(ScopeError::Conflict)?;
            if self.spec.program_graph(program.identity(), &metadata)?.0 != *role {
                return Err(ScopeError::Conflict);
            }
        }
        Ok(())
    }

    /// Retire exactly this graph under a freshly verified containment bank.
    ///
    /// Every deletion rechecks its binding. Own program FDs close after detach
    /// and program unpin; own map FDs close after local reference checks and map
    /// unpin. Global release remains unproven; it never gates the local
    /// retirement result. Unknown content is never erased here.
    pub fn retire(self, contained: &ContainedScope) -> Result<RetiredArtifact, ScopeError> {
        retire_artifacts(vec![self], contained)?
            .pop()
            .ok_or(ScopeError::Inspection)
    }
}

/// One complete installed current-image graph, with retained object identities.
/// This is local readback only, not committed execution or session authority.
pub struct InstalledArtifact {
    inventory: ArtifactInventory,
}
impl InstalledArtifact {
    /// Current-image catalog whose complete identity is retained.
    pub fn artifact(&self) -> &ArtifactSpec {
        self.inventory.artifact()
    }
    pub(super) fn scope(&self) -> &LocalKernelScope {
        self.inventory.scope()
    }
    pub(super) fn filters(&self) -> &[TcFilterIdentity] {
        &self.inventory.filters
    }
    /// Freshly verify all slots/pins and the identities of every retained FD.
    pub fn recheck(&self) -> Result<(), ScopeError> {
        self.inventory.recheck_objects()?;
        let fresh = ArtifactInventory::inspect(&self.inventory.scope, &self.inventory.spec)?;
        self.inventory.require_complete()?;
        if fresh.filters.len() != self.inventory.filters.len()
            || fresh.pins.len() != self.inventory.pins.len()
            || fresh.program_ids != self.inventory.program_ids
            || fresh.filters.iter().any(|filter| {
                !self
                    .inventory
                    .filters
                    .iter()
                    .any(|old| old.entry == filter.entry)
            })
            || fresh.programs.iter().any(|(id, program)| {
                self.inventory
                    .programs
                    .get(id)
                    .is_none_or(|old| old.identity() != program.identity())
            })
            || fresh.maps.iter().any(|(id, map)| {
                self.inventory
                    .maps
                    .get(id)
                    .is_none_or(|old| old.identity() != map.identity())
            })
        {
            return Err(ScopeError::Conflict);
        }
        self.inventory.recheck_objects()
    }
}

/// Retire a complete group in one phase order: all hooks, all program pins,
/// all own program FDs, then map pins and map FDs. Inspect every graph before
/// any effect. This is local BPF retirement; callers compose XFRM and route
/// barriers before entering it. Global descriptor residue never gates success.
pub fn retire_artifacts(
    inventories: Vec<ArtifactInventory>,
    contained: &ContainedScope,
) -> Result<Vec<RetiredArtifact>, ScopeError> {
    retire_artifacts_checked(inventories, contained, || Ok(()))
}

/// Retire with a caller's per-attempt check before each graph phase, filter
/// deletion and pin unlink. An interrupted caller must freshly inspect and
/// retry under retained containment; partial progress never proves completion.
pub fn retire_artifacts_checked(
    inventories: Vec<ArtifactInventory>,
    contained: &ContainedScope,
    check: impl Fn() -> Result<(), ScopeError>,
) -> Result<Vec<RetiredArtifact>, ScopeError> {
    check()?;
    if inventories.len() > 64 {
        return Err(ScopeError::InvalidSpec);
    }
    contained.recheck()?;
    let mut slots = BTreeSet::new();
    let mut maps = BTreeSet::new();
    for inventory in &inventories {
        if !inventory.scope.same_scope(contained.scope())
            || inventory.spec.slots.keys().any(|slot| !slots.insert(*slot))
            || inventory.maps.keys().any(|id| !maps.insert(*id))
        {
            return Err(ScopeError::Conflict);
        }
    }
    let mut ports = inventories
        .into_iter()
        .map(|inventory| {
            let residue_count = inventory.program_ids.len() + inventory.maps.len();
            RetiringGraph {
                inventory,
                contained,
                check: &check,
                residue_count,
            }
        })
        .collect::<Vec<_>>();
    super::artifact_batch::run_checked(&mut ports, &check)?;
    let mut result = Vec::with_capacity(ports.len());
    for port in ports {
        check()?;
        let local = LocalEffectsRetired {
            scope: port.inventory.scope,
            spec: port.inventory.spec,
        };
        local.recheck()?;
        let retired = RetiredArtifact {
            local,
            global: GlobalObjectDisposition::StillReferencedOrUnproven,
            residue_count: port.residue_count,
        };
        result.push(retired);
    }
    contained.recheck()?;
    Ok(result)
}

struct RetiringGraph<'a> {
    inventory: ArtifactInventory,
    contained: &'a ContainedScope,
    check: &'a dyn Fn() -> Result<(), ScopeError>,
    residue_count: usize,
}
impl super::artifact_batch::RetirementPort for RetiringGraph<'_> {
    fn preflight(&mut self) -> Result<(), ScopeError> {
        self.contained.recheck()?;
        self.inventory.recheck_objects()?;
        self.references()
    }
    fn detach(&mut self) -> Result<(), ScopeError> {
        for filter in &self.inventory.filters {
            self.inventory.recheck_objects()?;
            (self.check)()?;
            self.contained.delete_data(filter)?;
        }
        self.inventory.filters.clear();
        Ok(())
    }
    fn unpin_programs(&mut self) -> Result<(), ScopeError> {
        let mut map_pins = Vec::new();
        for pin in self.inventory.pins.drain(..) {
            if matches!(pin.identity(), PinnedIdentity::Program(_)) {
                (self.check)()?;
                self.contained.unlink_pin(&pin)?;
            } else {
                map_pins.push(pin);
            }
        }
        self.inventory.pins = map_pins;
        Ok(())
    }
    fn close_programs(&mut self) {
        self.inventory.programs.clear();
    }
    fn references(&mut self) -> Result<(), ScopeError> {
        check_local_references(
            self.inventory.scope.spec().data_slots(),
            &self.inventory.spec,
            &self.inventory.program_ids,
            &self.inventory.scope.inventory()?,
        )
    }
    fn unpin_maps(&mut self) -> Result<(), ScopeError> {
        while let Some(pin) = self.inventory.pins.pop() {
            self.references()?;
            self.inventory.recheck_objects()?;
            (self.check)()?;
            self.contained.unlink_pin(&pin)?;
        }
        Ok(())
    }
    fn close_maps(&mut self) {
        self.inventory.maps.clear();
    }
}

fn check_local_references(
    scope_slots: &[TcSlot],
    spec: &ArtifactSpec,
    owned: &BTreeSet<u32>,
    dumps: &[TcFilterDump],
) -> Result<(), ScopeError> {
    for filter in dumps.iter().flat_map(TcFilterDump::entries) {
        let Some(program) = filter.bpf() else {
            if filter.kind() == b"bpf" && !filter.is_summary() {
                return Err(ScopeError::Conflict);
            }
            continue;
        };
        // Other declared graphs are retired by the same coordinator. An
        // undeclared BPF neighbor could retain/use our maps; tc does not expose
        // that relationship. Preserve it and refuse instead of reopening its
        // ID. The same owned ID at another graph's coordinate also conflicts.
        if !scope_slots.contains(&filter.slot())
            || (owned.contains(&program.program_id()) && !spec.slots.contains_key(&filter.slot()))
        {
            return Err(ScopeError::Conflict);
        }
    }
    Ok(())
}

/// Local graph retirement observation bound to the retained writer domain.
///
/// Only fresh local absence mints this value. It does not claim global object
/// release or authorize activation, and all graphs in a shared scope must
/// finish retirement before any one backend rebuilds.
pub struct LocalEffectsRetired {
    scope: LocalKernelScope,
    spec: ArtifactSpec,
}
impl std::fmt::Debug for LocalEffectsRetired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalEffectsRetired")
    }
}
impl LocalEffectsRetired {
    /// Verify exact slot and pin absence again under the same writer domain.
    pub fn recheck(&self) -> Result<(), ScopeError> {
        for dump in self.scope.inventory()? {
            if self
                .spec
                .slots
                .keys()
                .any(|slot| dump.find(*slot).is_some())
            {
                return Err(ScopeError::Conflict);
            }
        }
        if self
            .scope
            .pin_directory(&self.spec.directory)?
            .is_some_and(|directory| {
                directory
                    .entries()
                    .map_or(true, |entries| !entries.is_empty())
            })
        {
            return Err(ScopeError::Conflict);
        }
        self.scope.verify()
    }
    /// Still-held local writer domain.
    pub fn scope(&self) -> &LocalKernelScope {
        &self.scope
    }
}

/// Local retirement plus independent observational global-release diagnostics.
pub struct RetiredArtifact {
    local: LocalEffectsRetired,
    global: GlobalObjectDisposition,
    residue_count: usize,
}
impl std::fmt::Debug for RetiredArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetiredArtifact")
            .field("global", &self.global)
            .field("residue_count", &self.residue_count)
            .finish()
    }
}
impl RetiredArtifact {
    /// The rebuild gate: verified local effects have retired.
    pub fn local(&self) -> &LocalEffectsRetired {
        &self.local
    }
    /// Global release uncertainty, which never gates rebuild or activation.
    pub const fn global(&self) -> GlobalObjectDisposition {
        self.global
    }
    /// Number of observed old IDs whose release remains unproven. Unpinned
    /// predecessor map IDs may be unavailable, so this is a lower bound.
    pub const fn residue_count(&self) -> usize {
        self.residue_count
    }
    /// Return the retained global-release uncertainty without reopening IDs.
    /// Scoped cleanup does not request node-global inspection privileges.
    pub fn observe_release(&mut self) -> GlobalObjectDisposition {
        self.global
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> ArtifactSpec {
        ArtifactSpec::new(
            PathBuf::from("gtpu/lo"),
            vec![ArtifactMap {
                name: "map".into(),
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
                btf_key_type_id: 0,
                btf_value_type_id: 0,
                map_extra: 0,
                pinned: true,
            }],
            vec![ArtifactProgram {
                name: "program".into(),
                tags: vec![[1; 8]],
                maps: vec!["map".into()],
            }],
            vec![(TcSlot::new(1, TcHook::Ingress, 0, 3, 50, 1).unwrap(), 0)],
        )
        .unwrap()
    }
    fn map() -> MapIdentity {
        MapIdentity {
            id: 2,
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
            flags: 0,
            name: kernel_name("map"),
            ifindex: 0,
            btf_vmlinux_value_type_id: 0,
            btf_id: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_id: 0,
            map_extra: 0,
            netns_dev: 0,
            netns_ino: 0,
        }
    }
    fn program() -> ProgramIdentity {
        ProgramIdentity {
            id: 1,
            program_type: 3,
            tag: [1; 8],
            name: kernel_name("program"),
            load_time_ns: 77,
            map_ids: vec![2],
            ifindex: 0,
        }
    }

    fn occupant(name: &str, tag: [u8; 8], flags: u32) -> TcFilterIdentity {
        use super::super::tests::{attr, done, message};
        // Independent Linux UAPI fixture: one direct-action BPF classifier at
        // an exact slot, including the kernel's observed offload disposition.
        let mut body = vec![0; 4];
        body.extend(7_u32.to_ne_bytes());
        body.extend(1_u32.to_ne_bytes());
        body.extend(0xffff_fff3_u32.to_ne_bytes());
        body.extend(((60_u32 << 16) | u32::from(3_u16.to_be())).to_ne_bytes());
        body.extend(attr(1, b"bpf\0"));
        body.extend(attr(11, &0_u32.to_ne_bytes()));
        let mut terminated_name = name.as_bytes().to_vec();
        terminated_name.push(0);
        body.extend(attr(
            2,
            &[
                attr(7, &terminated_name),
                attr(8, &1_u32.to_ne_bytes()),
                attr(9, &flags.to_ne_bytes()),
                attr(10, &tag),
                attr(11, &42_u32.to_ne_bytes()),
            ]
            .concat(),
        ));
        let mut parser = super::super::wire::Dump::new(7, TcHook::Egress, 9, 77);
        parser.consume(&message(44, 2, &body)).unwrap();
        parser.consume(&done()).unwrap();
        let mut entries = parser.finish().unwrap();
        assert_eq!(entries.len(), 1);
        TcFilterIdentity {
            entry: entries.pop().unwrap(),
            origin: Arc::new(()),
        }
    }

    #[test]
    fn owned_occupant_requires_software_only_disposition() {
        let expected = &spec().programs[0];
        for flags in [1, 8, 9] {
            let filter = occupant("program", [1; 8], flags);
            assert_eq!(
                inspect_occupant(&filter, expected).unwrap().program_id(),
                42
            );
        }
        for flags in [0, 2, 4, 6, 16] {
            let filter = occupant("program", [1; 8], flags);
            assert_eq!(
                inspect_occupant(&filter, expected),
                Err(ScopeError::Conflict),
                "offload disposition {flags} does not prove software-only execution"
            );
        }
    }

    #[test]
    fn owned_occupant_requires_current_image_tag_even_when_name_matches() {
        let expected = &spec().programs[0];
        let current = occupant("program", [1; 8], 8);
        assert!(inspect_occupant(&current, expected).is_ok());
        let foreign = occupant("program", [2; 8], 8);
        assert_eq!(
            inspect_occupant(&foreign, expected),
            Err(ScopeError::Conflict)
        );
        let renamed = occupant("other", [1; 8], 8);
        assert_eq!(
            inspect_occupant(&renamed, expected),
            Err(ScopeError::Conflict)
        );
        let long = ArtifactProgram {
            name: "current_image_program".into(),
            tags: vec![[1; 8]],
            maps: vec!["map".into()],
        };
        for name in [&long.name[..], &long.name[..15]] {
            assert!(inspect_occupant(&occupant(name, [1; 8], 8), &long).is_ok());
            assert_eq!(
                inspect_occupant(&occupant(name, [2; 8], 8), &long),
                Err(ScopeError::Conflict)
            );
        }
    }

    #[test]
    fn fresh_readiness_refuses_an_extra_observed_program_without_a_load_fd() {
        let loaded_programs = BTreeMap::from([(42, ())]);
        let loaded_maps = BTreeMap::from([(7, ())]);
        assert!(check_fresh_loads(
            &BTreeSet::from([42]),
            &loaded_maps,
            &loaded_programs,
            &loaded_maps,
        )
        .is_ok());
        assert_eq!(
            check_fresh_loads(
                &BTreeSet::from([41, 42]),
                &loaded_maps,
                &loaded_programs,
                &loaded_maps,
            ),
            Err(ScopeError::Conflict),
            "a stale pinned program cannot join a freshly loaded graph"
        );
        assert_eq!(
            check_fresh_loads(
                &BTreeSet::from([42]),
                &BTreeMap::from([(7, ()), (8, ())]),
                &loaded_programs,
                &loaded_maps,
            ),
            Err(ScopeError::Conflict),
        );
    }

    #[test]
    fn current_artifact_requires_complete_map_definition_and_relationship() {
        let spec = spec();
        let maps = BTreeMap::from([(2, map())]);
        assert_eq!(
            spec.program_graph(&program(), &maps).unwrap().1,
            BTreeMap::from([("map".into(), 2)])
        );
        for change in 0..10 {
            let mut changed = map();
            match change {
                0 => changed.key_size += 1,
                1 => changed.value_size += 1,
                2 => changed.max_entries += 1,
                3 => changed.flags = 1,
                4 => changed.name = kernel_name("other"),
                5 => changed.map_type = 1,
                6 => changed.ifindex = 1,
                7 => changed.map_extra = 1,
                8 => changed.btf_key_type_id = 1,
                _ => changed.netns_ino = 1,
            }
            assert!(
                spec.program_graph(&program(), &BTreeMap::from([(2, changed)]))
                    .is_err(),
                "map field {change}"
            );
        }
        for change in 0..6 {
            let mut changed = program();
            match change {
                0 => changed.tag = [9; 8],
                1 => changed.name = kernel_name("foreign"),
                2 => changed.program_type = 1,
                3 => changed.map_ids.clear(),
                4 => changed.map_ids.push(2),
                _ => changed.ifindex = 1,
            }
            assert!(
                spec.program_graph(&changed, &maps).is_err(),
                "program field {change}"
            );
        }
    }
    #[test]
    fn joined_graph_never_aliases_roles_or_splits_shared_map_identity() {
        let original = BTreeMap::from([("map".into(), 2)]);
        for additional in [
            BTreeMap::from([("other".into(), 2)]),
            BTreeMap::from([("map".into(), 3)]),
        ] {
            let mut current = original.clone();
            assert!(merge_graph(&mut current, additional).is_err());
            assert_eq!(current, original);
        }
    }
    #[test]
    fn foreign_bpf_neighbors_refuse_without_reopening_their_objects() {
        let origin = Arc::new(());
        let mut parser = super::super::wire::Dump::new(7, TcHook::Egress, 9, 77);
        parser
            .consume(&super::super::tests::filter(1, 3, 0))
            .unwrap();
        parser.consume(&super::super::tests::done()).unwrap();
        let mut dump = TcFilterDump {
            entries: parser
                .finish()
                .unwrap()
                .into_iter()
                .map(|entry| TcFilterIdentity {
                    entry,
                    origin: origin.clone(),
                })
                .collect(),
        };
        let observed = &dump.entries[0];
        let slot = observed.slot();
        let id = observed.bpf().unwrap().program_id();
        let mut spec = spec();
        spec.slots = BTreeMap::from([(slot, 0)]);
        assert!(check_local_references(
            &[slot],
            &spec,
            &BTreeSet::from([id]),
            std::slice::from_ref(&dump)
        )
        .is_ok());
        // A neighboring BPF filter remains a conflict even when we cannot
        // prove whether it shares maps. No foreign descriptors are opened.
        assert_eq!(
            check_local_references(&[], &spec, &BTreeSet::new(), std::slice::from_ref(&dump)),
            Err(ScopeError::Conflict)
        );
        let mut other_graph = spec.clone();
        other_graph.slots.clear();
        assert_eq!(
            check_local_references(
                &[slot],
                &other_graph,
                &BTreeSet::from([id]),
                std::slice::from_ref(&dump)
            ),
            Err(ScopeError::Conflict)
        );
        assert!(check_local_references(
            &[slot],
            &other_graph,
            &BTreeSet::new(),
            std::slice::from_ref(&dump)
        )
        .is_ok());
        dump.entries[0].entry.bpf = None;
        assert_eq!(
            check_local_references(&[], &spec, &BTreeSet::new(), &[dump]),
            Err(ScopeError::Conflict),
            "an unrecognized BPF attachment cannot prove reference absence"
        );
    }
}
