use super::*;
use std::path::PathBuf;

/// Value-free refusal from a held local kernel scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// Another local writer holds the unchanged exclusion inode.
    Busy,
    /// The declared scope has ambiguous or overlapping coordinates.
    InvalidSpec,
    /// A required native capability is unavailable.
    Unsupported,
    /// The current thread no longer belongs to the held namespace.
    NamespaceChanged,
    /// The private bpffs root or its mount was replaced.
    RootChanged,
    /// The stable exclusion inode or its parent was replaced.
    LockChanged,
    /// A required native inspection did not finish successfully.
    Inspection,
    /// Observed configuration differs from the declared owned object.
    Conflict,
    /// A reserved containment occupant belongs to another installation cookie.
    OwnerCookieMismatch,
    /// A path can bypass the proposed containment bank.
    Coverage,
    /// This bounded attempt exhausted its local execution budget.
    AttemptExpired,
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local_scope_{self:?}")
    }
}
impl std::error::Error for ScopeError {}
impl From<io::Error> for ScopeError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock => Self::Busy,
            io::ErrorKind::Unsupported => Self::Unsupported,
            _ => Self::Inspection,
        }
    }
}

/// Read-only classification of the reserved containment banks on all hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentInspection {
    /// Every reserved containment slot is absent.
    Absent,
    /// Every hook has owned coverage, with no incomplete occupied bank.
    OwnedAndContained,
    /// All present bank components are owned, but a bank or hook is incomplete.
    /// This is predecessor state for an authorized reset, not a retry failure.
    OwnedPartial,
}

/// Read-only tc/topology observation, without authority to change kernel state.
/// It makes no statement about XFRM, routes, companions or private pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcScopeInspection {
    pub(super) containment: ContainmentInspection,
    pub(super) other_filters_present: bool,
    pub(super) foreign_filters_present: bool,
}
impl TcScopeInspection {
    /// Classification of all declared containment banks.
    pub const fn containment(self) -> ContainmentInspection {
        self.containment
    }
    /// Whether a non-summary filter exists outside the declared data and
    /// containment slots. This diagnostic does not classify owned effects.
    pub const fn foreign_filters_present(self) -> bool {
        self.foreign_filters_present
    }
    /// Whether every covered hook lacks both containment and other filters.
    /// Known classifier summaries alone do not constitute a filter.
    pub fn is_empty(self) -> bool {
        self.containment == ContainmentInspection::Absent && !self.other_filters_present
    }
}

/// ARP-pass then all-protocol-drop coordinates for one containment bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentBank {
    pub(super) arp: TcSlot,
    pub(super) drop: TcSlot,
}
impl ContainmentBank {
    /// Validate a same-hook, chain-zero ARP exception followed by a drop.
    pub fn new(arp: TcSlot, drop: TcSlot) -> Result<Self, ScopeError> {
        if arp.ifindex != drop.ifindex
            || arp.hook != drop.hook
            || arp.chain != 0
            || drop.chain != 0
            || arp.protocol != 0x806
            || drop.protocol != 3
            || arp.priority >= drop.priority
            || arp.handle == 0
            || drop.handle == 0
        {
            return Err(ScopeError::InvalidSpec);
        }
        Ok(Self { arp, drop })
    }
    /// Exact ARP-pass slot.
    pub const fn arp_slot(self) -> TcSlot {
        self.arp
    }
    /// Exact all-protocol-drop slot.
    pub const fn drop_slot(self) -> TcSlot {
        self.drop
    }
}

/// Two disjoint containment banks for one covered device direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalHookSpec {
    pub(super) banks: [ContainmentBank; 2],
}
impl LocalHookSpec {
    /// Validate two independent banks on the same hook.
    pub fn new(a: ContainmentBank, b: ContainmentBank) -> Result<Self, ScopeError> {
        let priorities = [
            a.arp.priority,
            a.drop.priority,
            b.arp.priority,
            b.drop.priority,
        ];
        if a.arp.ifindex != b.arp.ifindex
            || a.arp.hook != b.arp.hook
            || priorities
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 4
        {
            return Err(ScopeError::InvalidSpec);
        }
        Ok(Self { banks: [a, b] })
    }
    /// Covered device index.
    pub const fn ifindex(self) -> u32 {
        self.banks[0].arp.ifindex
    }
    /// Covered direction.
    pub const fn hook(self) -> TcHook {
        self.banks[0].arp.hook
    }
    /// A/B coordinates.
    pub const fn banks(self) -> [ContainmentBank; 2] {
        self.banks
    }
}

/// Finite ownership declaration checked against held local kernel handles.
#[derive(Debug, Clone)]
pub struct LocalScopeSpec {
    pub(super) root: PathBuf,
    pub(super) lock: PathBuf,
    pub(super) cookie: [u8; 16],
    pub(super) hooks: Vec<LocalHookSpec>,
    pub(super) data_slots: Vec<TcSlot>,
}
impl LocalScopeSpec {
    /// Explicit exact data coordinates, disjoint from both containment banks.
    pub fn data_slots(&self) -> &[TcSlot] {
        &self.data_slots
    }
    /// Every declared covered hook, including plaintext egress without DSCP.
    pub fn hooks(&self) -> &[LocalHookSpec] {
        &self.hooks
    }
    /// Configured root spelling. Native operations still use the held descriptors.
    pub fn pin_root(&self) -> &std::path::Path {
        &self.root
    }
    /// Validate paths, all covered hooks, and their disjoint exact data slots.
    ///
    /// The lock must be stable outside bpffs and shared by every local writer.
    /// A hook may have no tc data slot, for example an XFRM plaintext egress.
    pub fn new(
        root: PathBuf,
        lock: PathBuf,
        cookie: [u8; 16],
        hooks: Vec<LocalHookSpec>,
        data_slots: Vec<TcSlot>,
    ) -> Result<Self, ScopeError> {
        let valid_path = |path: &std::path::Path| {
            path.is_absolute()
                && path.file_name().is_some()
                && !path.as_os_str().as_encoded_bytes().contains(&0)
                && !path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
        };
        if !valid_path(&root)
            || !valid_path(&lock)
            || lock.starts_with(&root)
            || cookie == [0; 16]
            || hooks.is_empty()
            || hooks.len() > 32
            || data_slots.len() > 256
        {
            return Err(ScopeError::InvalidSpec);
        }
        let distinct_hooks = hooks
            .iter()
            .map(|item| (item.ifindex(), item.hook()))
            .collect::<std::collections::BTreeSet<_>>();
        let distinct_slots = data_slots.iter().collect::<std::collections::BTreeSet<_>>();
        if distinct_hooks.len() != hooks.len() || distinct_slots.len() != data_slots.len() {
            return Err(ScopeError::InvalidSpec);
        }
        for slot in &data_slots {
            let hook = hooks
                .iter()
                .find(|item| item.ifindex() == slot.ifindex && item.hook() == slot.hook)
                .ok_or(ScopeError::InvalidSpec)?;
            if slot.handle == 0
                || hook
                    .banks
                    .iter()
                    .any(|bank| slot.priority <= bank.drop.priority)
            {
                return Err(ScopeError::InvalidSpec);
            }
        }
        Ok(Self {
            root,
            lock,
            cookie,
            hooks,
            data_slots,
        })
    }
}

/// Shared lifetime exclusion for one declared local kernel scope.
///
/// Clones share the held descriptors and one serial driver. They do not acquire
/// a second writer lock, and the last owner releases the original lock inode.
#[derive(Clone)]
pub struct LocalKernelScope {
    inner: Arc<ScopeInner>,
}
struct ScopeInner {
    spec: LocalScopeSpec,
    handles: Arc<crate::platform::LocalScopeHandles>,
    driver: std::sync::Mutex<Driver>,
}
impl std::fmt::Debug for LocalKernelScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalKernelScope")
    }
}

/// Freshly established containment bound to its still-held local scope.
///
/// Every protected mutation rechecks coverage; retaining this object alone
/// cannot turn an old observation into authority to remove a kernel effect.
#[derive(Debug, Clone)]
pub struct ContainedScope {
    scope: LocalKernelScope,
}

/// Identity of a map or program pinned beneath the held private root.
///
/// Pinned links and unknown object kinds cannot supply deletion authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinnedIdentity {
    /// Complete map identity read through a retained descriptor.
    Map(crate::bpf::MapIdentity),
    /// Complete program identity read through a retained descriptor.
    Program(crate::bpf::ProgramIdentity),
}

/// Descriptor-relative directory beneath the still-held local root.
#[derive(Clone)]
pub struct PinDirectory {
    inner: Arc<crate::platform::LocalPinDirectory>,
}
impl std::fmt::Debug for PinDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinDirectory")
    }
}
impl PinDirectory {
    /// Recheck that this descriptor still names its configured private leaf.
    pub fn recheck(&self) -> Result<(), ScopeError> {
        self.inner.verify()
    }
    /// Rechecked descriptor-relative path for APIs that require a pin path.
    /// Keep this directory alive through the call and recheck before each
    /// mutation; retaining a string alone does not retain its descriptor.
    pub fn descriptor_path(&self) -> Result<std::path::PathBuf, ScopeError> {
        self.inner.descriptor_path()
    }
    /// Complete bounded list of leaf names, rechecking the directory binding.
    pub fn entries(&self) -> Result<Vec<String>, ScopeError> {
        self.inner.entries()
    }
    /// Hold one exact map/program pin and its inode and object binding.
    pub fn inspect(&self, name: &str) -> Result<PinnedObject, ScopeError> {
        self.inner.inspect(name).map(|inner| PinnedObject { inner })
    }
}

/// One retained pin inode and BPF object, with no path-only deletion authority.
pub struct PinnedObject {
    inner: crate::platform::LocalPin,
}
impl std::fmt::Debug for PinnedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedObject")
    }
}
impl PinnedObject {
    pub(super) fn program(&self) -> Result<crate::bpf::ProgramHandle, ScopeError> {
        crate::bpf::ProgramHandle::from_observed(self.inner.program()?)
            .map_err(|_| ScopeError::Inspection)
    }
    pub(super) fn map(&self) -> Result<crate::bpf::MapHandle, ScopeError> {
        crate::bpf::MapHandle::from_observed(self.inner.map()?).map_err(|_| ScopeError::Inspection)
    }
    /// Exact observed map or program identity.
    pub fn identity(&self) -> &PinnedIdentity {
        self.inner.identity()
    }
    /// Recheck both inode and object identity through the held directory.
    pub fn recheck(&self) -> Result<(), ScopeError> {
        self.inner.verify()
    }
}

impl LocalKernelScope {
    /// Whether both handles retain the same acquired writer domain.
    /// Equal path strings or namespace IDs do not substitute for this binding.
    pub fn is_same_instance(&self, other: &Self) -> bool {
        self.same_scope(other)
    }
    pub(super) fn same_scope(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
    /// Hold the exact netns, private bpffs root, and stable exclusion inode.
    ///
    /// The current thread must remain in this namespace for every operation.
    /// This acquires exclusion and inspects devices; it does not close traffic.
    pub fn open(spec: LocalScopeSpec) -> Result<Self, ScopeError> {
        let handles = Arc::new(crate::platform::LocalScopeHandles::open(
            &spec.root, &spec.lock,
        )?);
        let kernel = NativeKernel {
            handles: Arc::clone(&handles),
            tc: TcClient::new()?,
        };
        let driver = Driver::new(spec.clone(), Box::new(kernel))?;
        Ok(Self {
            inner: Arc::new(ScopeInner {
                spec,
                handles,
                driver: std::sync::Mutex::new(driver),
            }),
        })
    }
    /// Declared exact ownership boundary.
    pub fn spec(&self) -> &LocalScopeSpec {
        &self.inner.spec
    }
    /// Verify the held descriptors and all captured interface identities.
    pub fn verify(&self) -> Result<(), ScopeError> {
        self.inner.handles.verify()?;
        self.inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .verify_all()
    }
    /// Inspect TCX, topology and every bank without creating or removing even
    /// a qdisc. Owned partial banks are reported normally; foreign occupants,
    /// bypasses and unsupported capabilities remain typed refusals.
    ///
    /// This observation grants neither containment nor startup authority.
    pub fn inspect(&self) -> Result<TcScopeInspection, ScopeError> {
        self.inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .inspect()
    }
    /// Close every declared path and return fresh coverage evidence.
    ///
    /// Calling this authorizes disruption of these paths. ARP passes. Every
    /// other frame drops while closed, including control traffic on the hooks.
    pub fn contain(&self) -> Result<ContainedScope, ScopeError> {
        self.inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .contain()?;
        Ok(ContainedScope {
            scope: self.clone(),
        })
    }
    /// Refuse a predecessor's different installation cookie before any effect.
    /// This read does not prove containment or authorize disruption.
    pub fn verify_containment_owner(&self) -> Result<(), ScopeError> {
        self.inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .check_containment_owner()
            .map(|_| ())
    }
    /// Return false only when every reserved containment slot is absent.
    /// Present occupants must prove complete owned coverage on every hook;
    /// partial or foreign banks return an error, never an empty observation.
    pub fn containment_present(&self) -> Result<bool, ScopeError> {
        let mut driver = self
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?;
        let present = driver.check_containment_owner()?;
        if present {
            driver.recheck()?;
        }
        Ok(present)
    }
    /// Complete per-hook inventories under the same held writer domain.
    ///
    /// This is tc evidence only, not proof that XFRM or owned pins are empty.
    pub fn inventory(&self) -> Result<Vec<TcFilterDump>, ScopeError> {
        self.inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .inventory()
    }
    /// Complete bounded inventory of names immediately beneath the held root.
    /// Unknown contents must be accounted for before whole-scope retirement.
    pub fn pin_root_entries(&self) -> Result<Vec<String>, ScopeError> {
        self.verify()?;
        let entries = self.inner.handles.root_entries()?;
        self.verify()?;
        Ok(entries)
    }
    /// Open a bounded relative directory without symlinks or mount crossings.
    ///
    /// Every ancestor must remain private. A missing directory is an explicit
    /// inventory observation; no directory or pin is created by inspection.
    pub fn pin_directory(
        &self,
        relative: &std::path::Path,
    ) -> Result<Option<PinDirectory>, ScopeError> {
        self.verify()?;
        crate::platform::LocalPinDirectory::open(Arc::clone(&self.inner.handles), relative)
            .map(|directory| directory.map(|inner| PinDirectory { inner }))
    }
}

impl ContainedScope {
    /// Attach a fresh data program only to a declared empty slot, under current
    /// coverage. The kernel owns the attachment; object drops never detach it.
    pub fn attach_data(
        &self,
        slot: TcSlot,
        program: &crate::bpf::ProgramHandle,
        name: &str,
    ) -> Result<(), ScopeError> {
        let mut driver = self
            .scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?;
        driver.recheck()?;
        if !driver.spec.data_slots.contains(&slot) {
            return Err(ScopeError::InvalidSpec);
        }
        driver.verify_interface(slot.ifindex())?;
        driver.kernel.attach(slot, program, name)?;
        driver.recheck()
    }
    /// Remove at most one exact owned containment filter after rechecking all
    /// installed graph FDs and declared data slots. `true` means a fresh read
    /// found no containment filters left. The caller must check committed
    /// activation before each step and supervise re-containment on any failure.
    pub fn open_next(&self, graphs: &[&super::InstalledArtifact]) -> Result<bool, ScopeError> {
        let filters = self.installed_filters(graphs)?;
        self.scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .open_next(&filters)
    }
    /// Passive exact graph/topology readback with no containment filters left.
    /// This never removes a filter or turns a local observation into authority.
    pub fn opening_is_complete(
        &self,
        graphs: &[&super::InstalledArtifact],
    ) -> Result<bool, ScopeError> {
        let filters = self.installed_filters(graphs)?;
        let mut driver = self
            .scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?;
        driver.begin();
        Ok(driver.open_snapshot(&filters)?.is_empty())
    }
    fn installed_filters(
        &self,
        graphs: &[&super::InstalledArtifact],
    ) -> Result<Vec<TcFilterIdentity>, ScopeError> {
        let mut filters = Vec::new();
        let mut slots = std::collections::BTreeSet::new();
        for graph in graphs {
            if !self.scope.same_scope(graph.scope()) {
                return Err(ScopeError::Conflict);
            }
            graph.recheck()?;
            for filter in graph.filters() {
                if !slots.insert(filter.slot()) {
                    return Err(ScopeError::Conflict);
                }
                filters.push(filter.clone());
            }
        }
        if slots != self.scope.spec().data_slots().iter().copied().collect() {
            return Err(ScopeError::Conflict);
        }
        Ok(filters)
    }
    /// Create only private normal-component directories beneath the held root.
    /// Existing symlinks, mount crossings and shared directories refuse; they
    /// are never repaired. This grants no object adoption or traffic activation.
    pub fn ensure_pin_directory(
        &self,
        relative: &std::path::Path,
    ) -> Result<PinDirectory, ScopeError> {
        self.recheck()?;
        let inner =
            crate::platform::LocalPinDirectory::create(self.scope.inner.handles.clone(), relative)?;
        self.recheck()?;
        Ok(PinDirectory { inner })
    }
    /// The exact lifetime guard that owns this observation.
    pub fn scope(&self) -> &LocalKernelScope {
        &self.scope
    }
    /// Re-prove every covered hook before an external protected effect.
    pub fn recheck(&self) -> Result<(), ScopeError> {
        self.scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .recheck()
    }
    /// Rebuild one bank only after its alternate has independently closed.
    pub fn replace_bank(&self, ifindex: u32, hook: TcHook, bank: usize) -> Result<(), ScopeError> {
        self.scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .replace_bank(ifindex, hook, bank)
    }
    /// Delete one declared data slot after fresh coverage and exact recheck.
    pub fn delete_data(&self, expected: &TcFilterIdentity) -> Result<(), ScopeError> {
        self.scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?
            .delete_data(expected)
    }
    /// Unlink one exact inspected pin under fresh containment and exclusion.
    ///
    /// The owner must first validate its current-image artifact and references.
    /// A replaced inode or object is a conflict, including the same object
    /// repinned at a fresh inode. The held descriptor survives unlink.
    pub fn unlink_pin(&self, pin: &PinnedObject) -> Result<(), ScopeError> {
        let mut driver = self
            .scope
            .inner
            .driver
            .lock()
            .map_err(|_| ScopeError::Inspection)?;
        driver.recheck()?;
        pin.inner.unlink(&self.scope.inner.handles)?;
        driver.recheck()
    }
}

pub(super) trait Kernel: Send {
    fn attach(
        &mut self,
        _slot: TcSlot,
        _program: &crate::bpf::ProgramHandle,
        _name: &str,
    ) -> Result<(), ScopeError> {
        Err(ScopeError::Unsupported)
    }
    fn set_deadline(&mut self, _deadline: Instant) {}
    fn verify(&self) -> Result<(), ScopeError>;
    fn interface(&mut self, ifindex: u32) -> Result<topology::InterfaceIdentity, ScopeError>;
    fn topology(&mut self, spec: LocalHookSpec) -> Result<topology::Topology, ScopeError>;
    fn ensure_clsact(&mut self, ifindex: u32) -> Result<(), ScopeError>;
    fn dump(&mut self, spec: LocalHookSpec) -> Result<TcFilterDump, ScopeError>;
    fn create(
        &mut self,
        slot: TcSlot,
        cookie: [u8; 16],
        verdict: TcVerdict,
    ) -> Result<(), ScopeError>;
    fn delete(&mut self, expected: &TcFilterIdentity) -> Result<(), ScopeError>;
}
struct NativeKernel {
    handles: Arc<crate::platform::LocalScopeHandles>,
    tc: TcClient,
}
impl Kernel for NativeKernel {
    fn attach(
        &mut self,
        slot: TcSlot,
        program: &crate::bpf::ProgramHandle,
        name: &str,
    ) -> Result<(), ScopeError> {
        self.handles.verify()?;
        self.tc.create_classifier(slot, program, name)?;
        Ok(())
    }
    fn set_deadline(&mut self, deadline: Instant) {
        self.tc.attempt_deadline = Some(deadline);
    }
    fn verify(&self) -> Result<(), ScopeError> {
        self.handles.verify()
    }
    fn interface(&mut self, ifindex: u32) -> Result<topology::InterfaceIdentity, ScopeError> {
        Ok(topology::inspect_link(&mut self.tc, ifindex)?.0)
    }
    fn topology(&mut self, spec: LocalHookSpec) -> Result<topology::Topology, ScopeError> {
        let (_, xdp_absent) = topology::inspect_link(&mut self.tc, spec.ifindex())?;
        let (clsact, shared, hardware) = topology::inspect_qdisc(&mut self.tc, spec.ifindex())?;
        let tcx_count =
            crate::platform::tcx_program_count(spec.ifindex(), spec.hook() == TcHook::Ingress)?;
        Ok(topology::Topology {
            ifindex: spec.ifindex(),
            clsact,
            shared,
            hardware,
            tcx_count,
            xdp_absent,
        })
    }
    fn ensure_clsact(&mut self, ifindex: u32) -> Result<(), ScopeError> {
        Ok(topology::ensure_clsact(&mut self.tc, ifindex)?)
    }
    fn dump(&mut self, spec: LocalHookSpec) -> Result<TcFilterDump, ScopeError> {
        Ok(self.tc.dump(spec.ifindex(), spec.hook())?)
    }
    fn create(
        &mut self,
        slot: TcSlot,
        cookie: [u8; 16],
        verdict: TcVerdict,
    ) -> Result<(), ScopeError> {
        self.handles.verify()?;
        self.tc.create_gact(slot, cookie, verdict)?;
        Ok(())
    }
    fn delete(&mut self, expected: &TcFilterIdentity) -> Result<(), ScopeError> {
        self.handles.verify()?;
        Ok(self.tc.delete_exact(expected)?)
    }
}

pub(super) struct Driver {
    pub(super) spec: LocalScopeSpec,
    pub(super) kernel: Box<dyn Kernel>,
    interfaces: std::collections::BTreeMap<u32, topology::InterfaceIdentity>,
    deadline: Instant,
}
impl Driver {
    pub(super) fn open_next(&mut self, expected: &[TcFilterIdentity]) -> Result<bool, ScopeError> {
        self.begin();
        let owned = self.open_snapshot(expected)?;
        let Some(next) = owned.first() else {
            return Ok(true);
        };
        self.verify_interface(next.slot().ifindex())?;
        // ACK loss is deliberately an error even if deletion happened. The
        // higher-level supervisor must establish closure before returning it.
        self.kernel.delete(next)?;
        if self
            .open_snapshot(expected)?
            .iter()
            .any(|actual| actual.slot() == next.slot())
        {
            return Err(ScopeError::Conflict);
        }
        Ok(false)
    }
    fn open_snapshot(
        &mut self,
        expected: &[TcFilterIdentity],
    ) -> Result<Vec<TcFilterIdentity>, ScopeError> {
        let slots = expected
            .iter()
            .map(TcFilterIdentity::slot)
            .collect::<std::collections::BTreeSet<_>>();
        if expected.len() != slots.len() || slots != self.spec.data_slots.iter().copied().collect()
        {
            return Err(ScopeError::Conflict);
        }
        let mut owned = Vec::new();
        for spec in self.spec.hooks.clone() {
            let (dump, topology) = self.snapshot(spec)?;
            containment::eligible_path(spec, &topology)?;
            if !topology.clsact
                || dump.entries().iter().any(|entry| {
                    entry.slot().ifindex() != spec.ifindex()
                        || entry.slot().hook() != spec.hook()
                        || !containment::software_only(entry)
                })
            {
                return Err(ScopeError::Coverage);
            }
            for filter in expected.iter().filter(|filter| {
                filter.slot().ifindex() == spec.ifindex() && filter.slot().hook() == spec.hook()
            }) {
                if dump.find(filter.slot()).map(|actual| &actual.entry) != Some(&filter.entry) {
                    return Err(ScopeError::Conflict);
                }
            }
            let mut own_slots = std::collections::BTreeSet::new();
            for bank in spec.banks {
                // Keep the ARP pass until its bank's drop is gone. ARP never
                // crosses a temporary drop-only bank during opening.
                for (slot, verdict) in [(bank.drop, TcVerdict::Drop), (bank.arp, TcVerdict::Pass)] {
                    own_slots.insert(slot);
                    if let Some(filter) = dump.find(slot) {
                        if !containment::matches_role(&dump, slot, self.spec.cookie, verdict) {
                            return Err(ScopeError::Conflict);
                        }
                        owned.push(filter.clone());
                    }
                }
            }
            let last_drop = spec
                .banks
                .iter()
                .map(|bank| bank.drop.priority)
                .max()
                .ok_or(ScopeError::InvalidSpec)?;
            if dump.entries().iter().any(|filter| {
                let slot = filter.slot();
                !filter.is_summary()
                    && slot.chain == 0
                    && slot.priority <= last_drop
                    && !own_slots.contains(&slot)
            }) {
                return Err(ScopeError::Coverage);
            }
        }
        Ok(owned)
    }
    pub(super) fn new(
        spec: LocalScopeSpec,
        mut kernel: Box<dyn Kernel>,
    ) -> Result<Self, ScopeError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        kernel.set_deadline(deadline);
        kernel.verify()?;
        let mut interfaces = std::collections::BTreeMap::new();
        for hook in &spec.hooks {
            interfaces.insert(hook.ifindex(), kernel.interface(hook.ifindex())?);
        }
        let mut driver = Self {
            spec,
            kernel,
            interfaces,
            deadline,
        };
        driver.check_containment_owner()?;
        Ok(driver)
    }
    fn begin(&mut self) {
        self.deadline = Instant::now() + Duration::from_secs(10);
        self.kernel.set_deadline(self.deadline);
    }
    fn verify_interface(&mut self, ifindex: u32) -> Result<(), ScopeError> {
        if Instant::now() >= self.deadline {
            return Err(ScopeError::AttemptExpired);
        }
        self.kernel.verify()?;
        if self.interfaces.get(&ifindex) != Some(&self.kernel.interface(ifindex)?) {
            return Err(ScopeError::Conflict);
        }
        Ok(())
    }
    fn snapshot(
        &mut self,
        spec: LocalHookSpec,
    ) -> Result<(TcFilterDump, topology::Topology), ScopeError> {
        self.verify_interface(spec.ifindex())?;
        let topology = self.kernel.topology(spec)?;
        let dump = self.kernel.dump(spec)?;
        if Instant::now() >= self.deadline {
            return Err(ScopeError::AttemptExpired);
        }
        Ok((dump, topology))
    }
    pub(super) fn verify_all(&mut self) -> Result<(), ScopeError> {
        self.begin();
        for spec in self.spec.hooks.clone() {
            self.verify_interface(spec.ifindex())?;
        }
        Ok(())
    }
    pub(super) fn inventory(&mut self) -> Result<Vec<TcFilterDump>, ScopeError> {
        self.begin();
        let mut result = Vec::new();
        for spec in self.spec.hooks.clone() {
            self.verify_interface(spec.ifindex())?;
            result.push(self.kernel.dump(spec)?);
        }
        Ok(result)
    }
    pub(super) fn inspect(&mut self) -> Result<TcScopeInspection, ScopeError> {
        self.begin();
        let mut any_bank = false;
        let mut all_contained = true;
        let mut other_filters_present = false;
        let mut foreign_filters_present = false;
        for spec in self.spec.hooks.clone() {
            let (dump, topology) = self.snapshot(spec)?;
            let observed = containment::inspect(
                spec,
                self.spec.cookie,
                &self.spec.data_slots,
                &dump,
                &topology,
            )?;
            any_bank |= observed.containment != ContainmentInspection::Absent;
            all_contained &= observed.containment == ContainmentInspection::OwnedAndContained;
            other_filters_present |= observed.other_filters_present;
            foreign_filters_present |= observed.foreign_filters_present;
            self.verify_interface(spec.ifindex())?;
        }
        Ok(TcScopeInspection {
            containment: if all_contained {
                ContainmentInspection::OwnedAndContained
            } else if any_bank {
                ContainmentInspection::OwnedPartial
            } else {
                ContainmentInspection::Absent
            },
            other_filters_present,
            foreign_filters_present,
        })
    }
    pub(super) fn contain(&mut self) -> Result<(), ScopeError> {
        self.begin();
        self.check_containment_owner()?;
        for spec in self.spec.hooks.clone() {
            self.contain_hook(spec)?;
        }
        self.recheck_inner()
    }
    fn contain_hook(&mut self, spec: LocalHookSpec) -> Result<(), ScopeError> {
        let (mut dump, topology) = self.snapshot(spec)?;
        containment::check_owner(spec, self.spec.cookie, &dump)?;
        containment::eligible_path(spec, &topology)?;
        if containment::coverage(spec, self.spec.cookie, &dump, &topology).is_ok() {
            return Ok(());
        }
        if !topology.clsact {
            self.verify_interface(spec.ifindex())?;
            self.kernel.ensure_clsact(spec.ifindex())?;
            dump = self.snapshot(spec)?.0;
        }
        for index in 0..2 {
            if containment::can_install(spec, self.spec.cookie, index, &dump) {
                self.install_bank(spec, index)?;
                return Ok(());
            }
        }
        Err(ScopeError::Coverage)
    }
    fn check_containment_owner(&mut self) -> Result<bool, ScopeError> {
        let dumps = self.inventory()?;
        let mut present = false;
        for (hook, dump) in self.spec.hooks.iter().zip(&dumps) {
            containment::check_owner(*hook, self.spec.cookie, dump)?;
            present |= hook
                .banks
                .iter()
                .any(|bank| dump.find(bank.arp).is_some() || dump.find(bank.drop).is_some());
        }
        Ok(present)
    }
    fn install_bank(&mut self, spec: LocalHookSpec, index: usize) -> Result<(), ScopeError> {
        let bank = spec.banks[index];
        // ARP acceptance is established before the all-protocol drop.
        for (slot, verdict) in [(bank.arp, TcVerdict::Pass), (bank.drop, TcVerdict::Drop)] {
            let (dump, topology) = self.snapshot(spec)?;
            containment::eligible_path(spec, &topology)?;
            if !topology.clsact || !containment::can_install(spec, self.spec.cookie, index, &dump) {
                return Err(ScopeError::Coverage);
            }
            if containment::matches_role(&dump, slot, self.spec.cookie, verdict) {
                continue;
            }
            self.verify_interface(spec.ifindex())?;
            self.kernel.create(slot, self.spec.cookie, verdict)?;
        }
        let (dump, topology) = self.snapshot(spec)?;
        if !containment::coverage(spec, self.spec.cookie, &dump, &topology)?[index] {
            return Err(ScopeError::Coverage);
        }
        Ok(())
    }
    pub(super) fn recheck(&mut self) -> Result<(), ScopeError> {
        self.begin();
        self.recheck_inner()
    }
    fn recheck_inner(&mut self) -> Result<(), ScopeError> {
        for spec in self.spec.hooks.clone() {
            let (dump, topology) = self.snapshot(spec)?;
            containment::coverage(spec, self.spec.cookie, &dump, &topology)?;
        }
        Ok(())
    }
    pub(super) fn replace_bank(
        &mut self,
        ifindex: u32,
        hook: TcHook,
        bank: usize,
    ) -> Result<(), ScopeError> {
        self.begin();
        if bank > 1 {
            return Err(ScopeError::InvalidSpec);
        }
        let spec = self
            .spec
            .hooks
            .iter()
            .find(|spec| spec.ifindex() == ifindex && spec.hook() == hook)
            .copied()
            .ok_or(ScopeError::InvalidSpec)?;
        let alternate = 1 - bank;
        self.install_bank(spec, alternate)?;
        let (initial, topology) = self.snapshot(spec)?;
        if !containment::coverage(spec, self.spec.cookie, &initial, &topology)?[alternate] {
            return Err(ScopeError::Coverage);
        }
        let target = spec.banks[bank];
        let retiring: Vec<_> = [target.drop, target.arp]
            .into_iter()
            .filter_map(|slot| initial.find(slot).cloned())
            .collect();
        // This private serial transition starts from a complete alternate.
        // Previously verified terminal components cannot bypass its non-ARP
        // drop. Remove the retiring drop before its ARP exception; no general
        // coverage observation is exported for the intermediate partial bank.
        for expected in &retiring {
            let (current, topology) = self.snapshot(spec)?;
            let actual = current.find(expected.slot()).ok_or(ScopeError::Conflict)?;
            if actual.entry != expected.entry {
                return Err(ScopeError::Conflict);
            }
            let projected = TcFilterDump {
                entries: current
                    .entries
                    .into_iter()
                    .filter(|entry| {
                        !retiring.iter().any(|old| {
                            old.entry == entry.entry
                                && containment::matches_role(
                                    &initial,
                                    old.slot(),
                                    self.spec.cookie,
                                    if old.slot() == target.arp {
                                        TcVerdict::Pass
                                    } else {
                                        TcVerdict::Drop
                                    },
                                )
                        })
                    })
                    .collect(),
            };
            if !containment::coverage(spec, self.spec.cookie, &projected, &topology)?[alternate] {
                return Err(ScopeError::Coverage);
            }
            self.verify_interface(ifindex)?;
            self.kernel.delete(expected)?;
        }
        self.install_bank(spec, bank)?;
        self.recheck_inner()
    }
    pub(super) fn delete_data(&mut self, expected: &TcFilterIdentity) -> Result<(), ScopeError> {
        self.begin();
        let slot = expected.slot();
        if !self.spec.data_slots.contains(&slot) {
            return Err(ScopeError::InvalidSpec);
        }
        let spec = self
            .spec
            .hooks
            .iter()
            .find(|spec| spec.ifindex() == slot.ifindex && spec.hook() == slot.hook)
            .copied()
            .ok_or(ScopeError::InvalidSpec)?;
        let (dump, topology) = self.snapshot(spec)?;
        containment::coverage(spec, self.spec.cookie, &dump, &topology)?;
        if dump.find(slot).map(|entry| &entry.entry) != Some(&expected.entry) {
            return Err(ScopeError::Conflict);
        }
        self.verify_interface(slot.ifindex)?;
        self.kernel.delete(expected)?;
        let (after, topology) = self.snapshot(spec)?;
        containment::coverage(spec, self.spec.cookie, &after, &topology)?;
        if after.find(slot).is_some() {
            return Err(ScopeError::Conflict);
        }
        Ok(())
    }
}
