//! Bounded object inspection. Kernel IDs are observations, never ownership.

use std::io;

/// The exact syscall stage that failed during object inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionCall {
    /// Reopening a program ID observed in the local scope.
    OpenProgram,
    /// Reading metadata through a retained program descriptor.
    ProgramInfo,
    /// Opening a map ID.
    OpenMap,
    /// Reading metadata through a retained map descriptor.
    MapInfo,
}

/// Value-free inspection failure retaining its syscall origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionError {
    call: InspectionCall,
    kind: io::ErrorKind,
    errno: Option<i32>,
}
impl InspectionError {
    pub(crate) fn new(call: InspectionCall, error: io::Error) -> Self {
        Self {
            call,
            kind: error.kind(),
            errno: error.raw_os_error(),
        }
    }
    /// Origin of the failed inspection.
    pub const fn call(self) -> InspectionCall {
        self.call
    }
    /// Redacted I/O error category.
    pub const fn kind(self) -> io::ErrorKind {
        self.kind
    }
    /// Whether an observed program disappeared before it could be retained.
    pub fn program_retired(self) -> bool {
        self.call == InspectionCall::OpenProgram && self.errno == Some(2)
    }
}
impl std::fmt::Display for InspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bpf_inspection_{:?}_{:?}", self.call, self.kind)
    }
}
impl std::error::Error for InspectionError {}

/// Immutable program identity read through one held descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramIdentity {
    /// Kernel program ID, protected from reuse while its descriptor is held.
    pub id: u32,
    /// Kernel BPF program type.
    pub program_type: u32,
    /// Kernel bytecode tag.
    pub tag: [u8; 8],
    /// Exact kernel name including zero padding.
    pub name: [u8; 16],
    /// Load identity, in kernel boot-time nanoseconds; not an authority clock.
    pub load_time_ns: u64,
    /// Complete sorted, distinct map-ID set.
    pub map_ids: Vec<u32>,
    /// Offload interface, zero for a software-only program.
    pub ifindex: u32,
}

/// Complete map definition relevant to a current-image artifact graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapIdentity {
    /// Kernel map ID, protected from reuse while its descriptor is held.
    pub id: u32,
    /// Kernel BPF map type.
    pub map_type: u32,
    /// Key width in bytes.
    pub key_size: u32,
    /// Value width in bytes.
    pub value_size: u32,
    /// Maximum entry count.
    pub max_entries: u32,
    /// Creation flags.
    pub flags: u32,
    /// Exact kernel name including zero padding.
    pub name: [u8; 16],
    /// Offload interface, zero for a software-only map.
    pub ifindex: u32,
    /// Kernel type ID for struct-ops maps.
    pub btf_vmlinux_value_type_id: u32,
    /// BTF object ID.
    pub btf_id: u32,
    /// BTF key type ID.
    pub btf_key_type_id: u32,
    /// BTF value type ID.
    pub btf_value_type_id: u32,
    /// Kernel BTF object ID.
    pub btf_vmlinux_id: u32,
    /// Map-specific creation information.
    pub map_extra: u64,
    /// Offload namespace device identity.
    pub netns_dev: u64,
    /// Offload namespace inode identity.
    pub netns_ino: u64,
}

/// Observational global-release result, separate from local effect retirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobalObjectDisposition {
    /// Every formerly owned ID is absent or now denotes a different identity.
    GoneObserved,
    /// At least one old identity remains, or inspection could not prove release.
    StillReferencedOrUnproven,
}

/// One program and its immutable identity, protected from ID reuse by an FD.
pub struct ProgramHandle {
    inner: crate::platform::ObservedProgram,
    identity: ProgramIdentity,
}
impl std::fmt::Debug for ProgramHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProgramHandle")
    }
}
impl ProgramHandle {
    /// Retain an already owned load/pin descriptor without reopening its ID.
    #[cfg(unix)]
    pub fn from_fd(fd: std::os::fd::BorrowedFd<'_>) -> Result<Self, InspectionError> {
        Self::from_observed(crate::platform::ObservedProgram::from_fd(fd)?)
    }
    pub(crate) fn from_observed(
        inner: crate::platform::ObservedProgram,
    ) -> Result<Self, InspectionError> {
        let identity = inner.info()?;
        Ok(Self { inner, identity })
    }
    pub(crate) fn raw_fd(&self) -> i32 {
        self.inner.raw_fd()
    }
    /// Reopen one specific live program and retain it throughout inspection.
    pub fn open(id: u32) -> Result<Self, InspectionError> {
        let mut port = Native;
        let inner = port.open_program(id)?;
        let identity = port.program_info(&inner)?;
        if identity.id != id {
            return Err(InspectionError::new(
                InspectionCall::ProgramInfo,
                io::ErrorKind::InvalidData.into(),
            ));
        }
        Ok(Self { inner, identity })
    }
    /// Immutable identity observed through the retained descriptor.
    pub fn identity(&self) -> &ProgramIdentity {
        &self.identity
    }
    /// Read again through the same descriptor, without reopening an ID.
    pub fn recheck(&self) -> Result<(), InspectionError> {
        if self.inner.info()? != self.identity {
            return Err(InspectionError::new(
                InspectionCall::ProgramInfo,
                io::ErrorKind::InvalidData.into(),
            ));
        }
        Ok(())
    }
}

/// One map and its complete definition, protected from ID reuse by an FD.
pub struct MapHandle {
    inner: crate::platform::ObservedMap,
    identity: MapIdentity,
}
impl std::fmt::Debug for MapHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MapHandle")
    }
}
impl MapHandle {
    /// Retain an already owned load/pin descriptor without reopening its ID.
    #[cfg(unix)]
    pub fn from_fd(fd: std::os::fd::BorrowedFd<'_>) -> Result<Self, InspectionError> {
        Self::from_observed(crate::platform::ObservedMap::from_fd(fd)?)
    }
    pub(crate) fn from_observed(
        inner: crate::platform::ObservedMap,
    ) -> Result<Self, InspectionError> {
        let identity = inner.info()?;
        Ok(Self { inner, identity })
    }
    /// Clone the retained descriptor for a typed map reader; never reopen an ID.
    #[cfg(unix)]
    pub fn try_clone_fd(&self) -> io::Result<std::os::fd::OwnedFd> {
        self.inner.try_clone_fd()
    }
    /// Reopen one specific map and retain it throughout identity-sensitive work.
    pub fn open(id: u32) -> Result<Self, InspectionError> {
        let inner = crate::platform::ObservedMap::open(id)?;
        let identity = inner.info()?;
        if identity.id != id {
            return Err(InspectionError::new(
                InspectionCall::MapInfo,
                io::ErrorKind::InvalidData.into(),
            ));
        }
        Ok(Self { inner, identity })
    }
    /// Complete immutable map definition.
    pub fn identity(&self) -> &MapIdentity {
        &self.identity
    }
    /// Verify the retained descriptor still reports the exact same definition.
    pub fn recheck(&self) -> Result<(), InspectionError> {
        if self.inner.info()? != self.identity {
            return Err(InspectionError::new(
                InspectionCall::MapInfo,
                io::ErrorKind::InvalidData.into(),
            ));
        }
        Ok(())
    }
}

/// Inspect only explicitly supplied local IDs, retaining each live descriptor.
///
/// IDs come from owned load handles, private pins or the covered local hooks;
/// this never enumerates node-wide programs. Duplicate IDs are inspected once.
/// Only `BPF_PROG_GET_FD_BY_ID` ENOENT is skipped; metadata and permission
/// failures never prove absence. Callers retain local writer exclusion.
pub fn programs(ids: &[u32]) -> Result<Vec<ProgramHandle>, InspectionError> {
    inventory(&mut Native, ids).map(|items| {
        items
            .into_iter()
            .map(|(inner, identity)| ProgramHandle { inner, identity })
            .collect()
    })
}

/// Observe release after the caller closes its own cleanup descriptors.
///
/// Call before loading replacement objects. A different identity at an old ID
/// proves reuse; equal metadata, including an indistinguishable map definition,
/// remains unproven. Harmless observer FDs may retain that result indefinitely.
/// This diagnostic never grants permission to delete or blocks local retirement.
pub fn observe_global_release(
    programs: &[ProgramIdentity],
    maps: &[MapIdentity],
) -> GlobalObjectDisposition {
    if programs
        .iter()
        .any(|old| program_release(&mut Native, old) != GlobalObjectDisposition::GoneObserved)
    {
        return GlobalObjectDisposition::StillReferencedOrUnproven;
    }
    for old in maps {
        match MapHandle::open(old.id) {
            Err(error) if error.call == InspectionCall::OpenMap && error.errno == Some(2) => {}
            Ok(map) if map.identity() != old => {}
            _ => return GlobalObjectDisposition::StillReferencedOrUnproven,
        }
    }
    GlobalObjectDisposition::GoneObserved
}

struct Native;
impl Inspection for Native {
    type Program = crate::platform::ObservedProgram;
    fn open_program(&mut self, id: u32) -> Result<Self::Program, InspectionError> {
        crate::platform::ObservedProgram::open(id)
    }
    fn program_info(
        &mut self,
        program: &Self::Program,
    ) -> Result<ProgramIdentity, InspectionError> {
        program.info()
    }
}

trait Inspection {
    type Program;
    fn open_program(&mut self, id: u32) -> Result<Self::Program, InspectionError>;
    fn program_info(&mut self, program: &Self::Program)
        -> Result<ProgramIdentity, InspectionError>;
}

fn inventory<P: Inspection>(
    port: &mut P,
    ids: &[u32],
) -> Result<Vec<(P::Program, ProgramIdentity)>, InspectionError> {
    let mut result = Vec::new();
    for id in ids
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        if id == 0 {
            return Err(InspectionError::new(
                InspectionCall::OpenProgram,
                io::ErrorKind::InvalidData.into(),
            ));
        }
        let program = match port.open_program(id) {
            Err(error) if error.program_retired() => continue,
            result => result?,
        };
        let info = port.program_info(&program)?;
        if info.id != id {
            return Err(InspectionError::new(
                InspectionCall::ProgramInfo,
                io::ErrorKind::InvalidData.into(),
            ));
        }
        result.push((program, info));
    }
    Ok(result)
}

fn program_release<P: Inspection>(port: &mut P, old: &ProgramIdentity) -> GlobalObjectDisposition {
    match port.open_program(old.id) {
        Err(error) if error.program_retired() => GlobalObjectDisposition::GoneObserved,
        Ok(program) => match port.program_info(&program) {
            Ok(info) if info != *old => GlobalObjectDisposition::GoneObserved,
            _ => GlobalObjectDisposition::StillReferencedOrUnproven,
        },
        _ => GlobalObjectDisposition::StillReferencedOrUnproven,
    }
}

#[cfg(test)]
mod tests;
