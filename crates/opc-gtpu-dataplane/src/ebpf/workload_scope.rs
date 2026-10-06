//! Locally owned workload state with repeatable teardown.

use super::EbpfGtpuDataplaneBackend;
use crate::GtpuError;
use std::{fmt, path::PathBuf};

/// Stable, opaque identity for an exclusively owned workload pin namespace.
///
/// The caller supplies a collision-resistant digest of its tenant and stable
/// workload identity. Replacements must use the same identity; different
/// workloads must use different identities. This is a resource naming boundary,
/// not an authorization mechanism against other privileged host processes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EbpfWorkloadScope([u8; 32]);

/// Identifier-free counts of foreign objects removed by a strict workload reset.
///
/// Zero counts on a completed attempt mean no foreign objects of these classes
/// were found. SDK hooks, valid ordinary exclusions, SDK exclusion-publication
/// staging directories directly under the control directory, ordinary pins and
/// other directories are not counted.
/// Released pinned links are uncounted because the SDK has no ownership catalog
/// to classify them as foreign. Failed attempts with confirmed removals return
/// these counts in [`GtpuError::StrictWorkloadResetIncomplete`]; accumulate them
/// across retries. Uncertain effects of a failed mutation remain unknown.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EbpfStrictWorkloadResetReport {
    /// Selector-authority, decommission and legacy selector-terminal entries.
    pub selector_markers: usize,
    /// Detached kernel filter entries that do not match the SDK attach predicate.
    /// Includes u32 table entries, but excludes classifier summaries.
    pub tc_filters: usize,
    /// Removed exclusion-marker directories outside valid ordinary exclusions
    /// and SDK exclusion-publication staging directories directly under the
    /// control directory.
    pub exclusion_marker_directories: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkloadReset {
    Conservative,
    Exclusive,
    StrictExclusive,
}

impl EbpfWorkloadScope {
    /// Construct a workload scope from a nonzero opaque identity digest.
    ///
    /// # Errors
    /// Returns an invalid-configuration error for the all-zero identity.
    pub fn new(identity: [u8; 32]) -> Result<Self, GtpuError> {
        if identity == [0; 32] {
            return Err(GtpuError::invalid_config(
                "ebpf.workload_scope",
                "workload identity must be nonzero",
            ));
        }
        Ok(Self(identity))
    }

    /// Deterministic direct child of bpffs reserved for this workload.
    #[must_use]
    pub fn bpffs_pin_root(self) -> PathBuf {
        let mut name = String::from("opc-gtpu-workload-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.0 {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        PathBuf::from("/sys/fs/bpf").join(name)
    }
}

impl fmt::Debug for EbpfWorkloadScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EbpfWorkloadScope").finish_non_exhaustive()
    }
}

impl EbpfGtpuDataplaneBackend {
    /// Create a backend with pins and local writer locks isolated by workload.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn for_workload(scope: EbpfWorkloadScope) -> Self {
        Self::with_config(super::EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: scope.bpffs_pin_root(),
            ..super::EbpfGtpuDataplaneBackendConfig::default()
        })
    }

    /// Remove the stopped current-schema graph for one workload interface.
    ///
    /// Call only after the workload's previous forwarding generation has been
    /// invalidated and ingress isolated. The runtime takes the existing local
    /// writer and operation locks, verifies the exact local hooks and map
    /// references, detaches those hooks, and unpins only recognized objects in
    /// this scope. Only the unbound interface-name IPv4 graph is supported;
    /// grouped selector namespaces retain their separate lifecycle. It accepts
    /// partial pin sets left by interrupted creation or cleanup. Missing
    /// objects are success on a subsequent call.
    ///
    /// This does not preserve sessions. It never attaches forwarding programs,
    /// enters another network namespace, or cleans another node. Empty writer
    /// lock directories remain so that concurrent processes always lock the
    /// same inode. Reboot removes the remaining in-memory bpffs state.
    ///
    /// # Errors
    /// Refuses a backend configured for a different or shared pin root, any
    /// locally managed device, an active writer, foreign objects or program
    /// references, and external retained-graph recovery authority. A failed
    /// cleanup may have detached hooks or removed some pins. A busy writer lock
    /// or remaining program references returns `RetryRequired`; retry this method
    /// before ordinary attachment. An inspection failure never authorizes
    /// deletion. Callers must not serve when cleanup fails.
    pub async fn reset_workload_graph(
        &self,
        scope: EbpfWorkloadScope,
        interface: &str,
    ) -> Result<(), GtpuError> {
        self.reset_workload(scope, interface, WorkloadReset::Conservative)
            .await
            .map(|_| ())
    }

    /// Reconcile an exclusively owned workload scope to absence.
    ///
    /// # Ownership contract
    /// The caller owns the entire root, its pinned programs and links, and the
    /// named interface plus every root leaf naming an interface in the current
    /// network namespace. Stop the old writer, invalidate its forwarding
    /// generation and isolate ingress on all those interfaces first. Never
    /// combine this operation with externally authorized retained-graph recovery.
    /// A scope that was ever bound to a selector namespace cannot use this reset.
    ///
    /// With several interfaces, reset every intended interface before the first
    /// [`crate::GtpuDataplaneBackend::create_device`]. Missing pins cannot identify
    /// unnamed interfaces. Once this backend manages any device, it refuses all
    /// resets until its managed devices are removed.
    ///
    /// On those interfaces reset detaches the configured clsact ingress/egress
    /// slots (chain zero, `ETH_P_ALL`, configured priority, handle `0:1`), every
    /// SDK filter matched by the ordinary attach predicate, and every filter
    /// whose program references a scope map, regardless of priority or handle.
    /// Map references also find renamed interfaces in this namespace; only the
    /// referencing filters on those devices are detached. Other filters remain.
    /// Declared names resolve to kernel indices, including alternative names.
    /// Failed, oversized or unparseable dumps on other interfaces and non-UTF-8
    /// names are skipped during discovery; unresolved map references still refuse.
    /// Direct tc deletion stays in the calling network namespace. Unlinking a
    /// scope's pinned link detaches its attachment wherever it is, including
    /// another interface, namespace or hook type, when the final reference ends.
    /// The declaration that every pinned object belongs to the workload covers
    /// that effect.
    ///
    /// Unlike [`Self::reset_workload_graph`], unknown map names/shapes, retained
    /// records, partial layouts and pinned links/programs do not restrict cleanup.
    /// All interface hooks and object pins retire before map pins. The reset
    /// waits up to **250 ms** for retired program IDs and scope-map references,
    /// including references left by a previous call, then scans references before
    /// each map unpin. Empty writer-lock directories and existing exclusion
    /// markers retain their inodes. Success permits ordinary attachment on this
    /// backend; no sessions survive. Repetition on an absent scope succeeds.
    /// Foreign filters outside the ordinary owned slot can survive successful
    /// reset and still block ordinary attach: another handle or protocol at the
    /// configured priority in chain zero (including other classifier kinds,
    /// such as u32), or a non-SDK `ETH_P_ALL` filter at handle `0:1` in another
    /// chain. A directory named `GTPU_CURRENT_HISTORICAL_25_EXCLUSION_V1` inside
    /// a retained writer or operation-lock directory also survives. Existing
    /// SDK generations create none of these layouts;
    /// [`Self::reset_strict_exclusive_workload_graph`] also removes them when
    /// the caller can make its additional ownership assertions.
    ///
    /// # Environment and interruption
    /// Requires `CAP_NET_ADMIN` for tc and `CAP_SYS_ADMIN` for global program
    /// enumeration whenever a map or retired program is inspected; `CAP_BPF`
    /// alone is insufficient. bpffs, procfs, netlink, `bpf`, `openat2` and filesystem
    /// operations must be accessible, with enough file descriptors to hold the
    /// inventory. The root and retained lock directories require the effective
    /// uid/gid and mode `0700`.
    ///
    /// Root/lock directories may be created before inspection. After interruption,
    /// complete the next **exclusive** reset: conservative reset and ordinary
    /// attach may refuse an unfinished exclusion marker until it succeeds.
    ///
    /// # Errors
    /// - A busy writer/operation lock returns `RetryRequired` with
    ///   `ebpf_workload_cleanup_writer_busy`; it ends when the holder releases
    ///   the lock or exits.
    /// - `StateIndeterminate` with `ebpf_exclusive_workload_external_program_reference`
    ///   means a program this reset did not detach still references a scope map
    ///   after the bounded wait. Both reference errors may be retried with
    ///   back-off: delayed kernel teardown from an earlier call can settle, but
    ///   a live external namespace, program/link pin or descriptor must retire.
    ///   Repeated reset does not force that holder away. Referenced maps stay pinned.
    /// - `StateIndeterminate` with `ebpf_exclusive_workload_detached_program_reference`
    ///   means a retired program still references a map after the 250 ms wait.
    ///   Delayed kernel release may settle by itself; an external holder must
    ///   release its reference. Retrying has no guarantee of convergence.
    /// - Selector-authority, decommission and legacy selector-terminal markers,
    ///   or a pending terminal admission on this backend, return `UnsupportedFeature`.
    ///   They require their separate lifecycle and never end through repeated reset.
    /// - Wrong root/invalid interface and locally managed devices require caller
    ///   correction. Identity changes may settle after a concurrent operation ends.
    ///   Inspection failures never grant deletion authority; denied permissions,
    ///   symlinks, nested mounts, invalid lock metadata or unavailable kernel
    ///   facilities require fixing the environment, not unbounded retries.
    ///
    /// Keep ingress isolated and do not attach or serve after any error.
    pub async fn reset_exclusive_workload_graph(
        &self,
        scope: EbpfWorkloadScope,
        interface: &str,
    ) -> Result<(), GtpuError> {
        self.reset_workload(scope, interface, WorkloadReset::Exclusive)
            .await
            .map(|_| ())
    }

    /// Reset an exclusively owned scope that has never provisioned a selector.
    ///
    /// Calling this method asserts all ownership and quiescence requirements of
    /// [`Self::reset_exclusive_workload_graph`] and, additionally, that:
    ///
    /// - **No selector namespace has ever been provisioned in this scope.**
    ///   Selector-authority, decommission and legacy selector-terminal markers
    ///   protect no valid history here and may be removed with their contents.
    /// - **The configured tc priority on the named interface belongs to the
    ///   caller in every chain.** Every clsact ingress/egress filter at that
    ///   priority may be detached, of any origin, classifier kind, protocol or
    ///   handle. At every other priority on that interface, SDK hooks and filters
    ///   whose programs reference the product's own scope maps are removed
    ///   individually, preserving foreign filters sharing their classifier.
    ///   An old priority therefore cannot strand the next ordinary attach,
    ///   including when the predecessor's map pins are already gone.
    ///
    /// Declared interfaces are the name passed to this call and interface-shaped
    /// scope-root entry names. Alternative names resolve to the same kernel
    /// index. On other interfaces in the calling network namespace, SDK hooks
    /// found through those entries or scope-map references are removed, as are
    /// filters whose programs reference recognized product maps. These removals
    /// use individual handles; non-SDK filters count as foreign. Other namespace
    /// references, outside program/link pins, live descriptors, non-tc
    /// attachments and references on interfaces whose filter dumps are skipped
    /// during discovery keep the ordinary reference refusals. All direct tc
    /// operations stay in the calling network namespace.
    ///
    /// A map is the product's when this build recognizes its pin name, kernel
    /// name and definition. An unrecognized map is treated as foreign and
    /// unpinned without an external-reference wait, even if it is a product map
    /// whose pin was renamed or whose generation is unknown after a rollback.
    /// Another SDK workload's recognized map pinned into this scope counts as
    /// this product's, as in ordinary reset; recognition does not prove workload
    /// ownership. Foreign-map references only locate filters matching the SDK
    /// attach predicate, which are removed as the product's own hooks. They
    /// confer no authority over other filters and do not block map unpinning.
    /// A link pinned in the scope is released when the reset removes its pin,
    /// wherever it is attached, regardless of who created it. Scope-wide pin
    /// cleanup otherwise follows the ordinary exclusive reset contract.
    ///
    /// Misplaced exclusion-marker directories are removed throughout the root.
    /// Inside retained lock directories the ordinary preservation rule remains,
    /// except for operation locks and writer locks of interfaces known to this
    /// call. Valid ordinary exclusions therefore retain their inodes, including
    /// those of absent interfaces; unfinished exclusions of known interfaces are
    /// completed before success. Lock inodes stay held and unchanged.
    /// The ordinary reference guards apply to recognized product maps;
    /// interruption rules remain those of the ordinary exclusive reset. Repeat
    /// this strict reset after an interrupted call, before ordinary attachment.
    /// No sessions survive; callers must drain or transfer emergency sessions
    /// before voluntary teardown.
    ///
    /// A false assertion can erase permanent selector fencing/retirement history,
    /// permit reuse of a retired namespace, or detach another owner's forwarding
    /// or security policy. A writer/reference scan cannot prove the assertion.
    /// This operation is outside RFC 016's selector lifecycle. Do not use it in
    /// a scope that ever provisioned a selector, even after decommission.
    ///
    /// # Errors
    /// Preserves the distinct writer-busy and program-reference reasons of
    /// [`Self::reset_exclusive_workload_graph`], as well as its root, interface,
    /// inspection and pending-terminal-admission guards. Selector marker names
    /// alone no longer refuse. After confirmed foreign removals, an error is
    /// [`GtpuError::StrictWorkloadResetIncomplete`], carrying this attempt's
    /// counts and the original failure as its source. Other failures retain
    /// their original variant. Retain reports across retries: a later successful
    /// call cannot recount objects already removed. Failed-attempt counts are
    /// lower bounds; an ACK-uncertain removal remains unknown, so a zero retry
    /// report does not prove the whole sequence found nothing foreign.
    /// Keep ingress isolated and do not attach or serve until reset succeeds.
    pub async fn reset_strict_exclusive_workload_graph(
        &self,
        scope: EbpfWorkloadScope,
        interface: &str,
    ) -> Result<EbpfStrictWorkloadResetReport, GtpuError> {
        self.reset_workload(scope, interface, WorkloadReset::StrictExclusive)
            .await
    }

    async fn reset_workload(
        &self,
        scope: EbpfWorkloadScope,
        interface: &str,
        mode: WorkloadReset,
    ) -> Result<EbpfStrictWorkloadResetReport, GtpuError> {
        if self.inner.config.bpffs_pin_root != scope.bpffs_pin_root() {
            return Err(GtpuError::invalid_config(
                "ebpf.workload_scope",
                "backend must use the exact workload pin root",
            ));
        }
        let interface = interface.to_owned();
        self.run_blocking("ebpf_workload_cleanup", move |backend| {
            let _operation = backend.operation_guard()?;
            super::validate_interface_name(&interface)?;
            if !backend.devices()?.is_empty() {
                return Err(GtpuError::AlreadyExists);
            }
            let ifindex = match backend.inner.runtime.ifindex_by_name(&interface) {
                Ok(index) => Some(index),
                Err(GtpuError::NotFound) => None,
                Err(error) => return Err(error),
            };
            if mode != WorkloadReset::Conservative {
                if backend
                    .terminal_admissions()?
                    .keys()
                    .any(|path| path.starts_with(scope.bpffs_pin_root()))
                {
                    return Err(GtpuError::UnsupportedFeature {
                        feature: "exclusive_workload_cleanup_pending_terminal_admission",
                    });
                }
                if mode == WorkloadReset::StrictExclusive {
                    backend.inner.runtime.reset_strict_exclusive_workload_graph(
                        ifindex,
                        &backend.pin_dir(&interface),
                        backend.inner.config.tc_priority,
                    )
                } else {
                    backend
                        .inner
                        .runtime
                        .reset_exclusive_workload_graph(
                            ifindex,
                            &backend.pin_dir(&interface),
                            backend.inner.config.tc_priority,
                        )
                        .map(|()| EbpfStrictWorkloadResetReport::default())
                }
            } else {
                backend
                    .inner
                    .runtime
                    .reset_workload_graph(
                        ifindex,
                        &backend.pin_dir(&interface),
                        backend.inner.config.tc_priority,
                    )
                    .map(|()| EbpfStrictWorkloadResetReport::default())
            }
        })
        .await
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct CleanupInventory {
    pub(super) pins: Vec<usize>,
    pub(super) selector_bound: bool,
}

/// The kernel adapter retains the writer lock and inspected object descriptors
/// throughout this sequence. The small port makes interruption at each effect
/// boundary testable without substituting a second cleanup implementation.
#[cfg(any(target_os = "linux", test))]
pub(super) trait WorkloadCleanup {
    fn inventory(&mut self) -> Result<CleanupInventory, GtpuError>;
    fn detach_owned_hooks(&mut self) -> Result<(), GtpuError>;
    fn unpin(&mut self, index: usize) -> Result<(), GtpuError>;
    fn finish(&mut self) -> Result<(), GtpuError>;
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn cleanup(port: &mut impl WorkloadCleanup) -> Result<(), GtpuError> {
    let inventory = port.inventory()?;
    if inventory.selector_bound {
        return Err(GtpuError::UnsupportedFeature {
            feature: "workload_cleanup_bound_selector_namespace",
        });
    }
    port.detach_owned_hooks()?;
    for index in inventory.pins {
        port.unpin(index)?;
    }
    port.finish()
}

#[cfg(any(target_os = "linux", test))]
pub(super) struct ExclusiveCleanupInventory {
    pub(super) interfaces: Vec<usize>,
    pub(super) object_pins: Vec<usize>,
    pub(super) pins: Vec<usize>,
    pub(super) selector_bound: bool,
}

/// The exclusive adapter inventories every leaf before effects. Program and
/// link pins must retire before the bounded release wait and map-reference scan.
#[cfg(any(target_os = "linux", test))]
pub(super) trait ExclusiveWorkloadCleanup {
    fn inventory(&mut self) -> Result<ExclusiveCleanupInventory, GtpuError>;
    fn detach_interface(&mut self, interface: usize) -> Result<(), GtpuError>;
    fn unpin(&mut self, index: usize) -> Result<(), GtpuError>;
    fn wait_for_detached_programs(&mut self) -> Result<(), GtpuError>;
    fn finish(&mut self) -> Result<(), GtpuError>;
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn cleanup_exclusive(port: &mut impl ExclusiveWorkloadCleanup) -> Result<(), GtpuError> {
    let inventory = port.inventory()?;
    if inventory.selector_bound {
        return Err(GtpuError::UnsupportedFeature {
            feature: "workload_cleanup_bound_selector_namespace",
        });
    }
    for interface in inventory.interfaces {
        port.detach_interface(interface)?;
    }
    for pin in inventory.object_pins {
        port.unpin(pin)?;
    }
    port.wait_for_detached_programs()?;
    for pin in inventory.pins {
        port.unpin(pin)?;
    }
    port.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    struct FakeCleanup {
        pins: BTreeSet<usize>,
        selector_bound: bool,
        hooks: bool,
        foreign: bool,
        fail_after: Option<usize>,
        effects: usize,
        finished: bool,
    }

    impl FakeCleanup {
        fn fresh() -> Self {
            Self {
                pins: (0..super::super::CURRENT_EBPF_GRAPH_PIN_COUNT).collect(),
                selector_bound: false,
                hooks: true,
                foreign: false,
                fail_after: None,
                effects: 0,
                finished: false,
            }
        }

        fn effect(&mut self) -> Result<(), GtpuError> {
            self.effects += 1;
            if self.fail_after == Some(self.effects) {
                Err(GtpuError::StateIndeterminate {
                    operation: "injected_interruption",
                })
            } else {
                Ok(())
            }
        }
    }

    impl WorkloadCleanup for FakeCleanup {
        fn inventory(&mut self) -> Result<CleanupInventory, GtpuError> {
            if self.foreign {
                return Err(GtpuError::AlreadyExists);
            }
            Ok(CleanupInventory {
                pins: self.pins.iter().copied().collect(),
                selector_bound: self.selector_bound,
            })
        }
        fn detach_owned_hooks(&mut self) -> Result<(), GtpuError> {
            self.hooks = false;
            self.effect()
        }
        fn unpin(&mut self, index: usize) -> Result<(), GtpuError> {
            assert!(!self.hooks, "pins must outlive forwarding hooks");
            self.pins.remove(&index);
            self.effect()
        }
        fn finish(&mut self) -> Result<(), GtpuError> {
            assert!(self.pins.is_empty() && !self.selector_bound && !self.hooks);
            self.finished = true;
            self.effect()
        }
    }

    #[test]
    fn workload_scopes_are_stable_disjoint_and_redacted() {
        let first = EbpfWorkloadScope::new([1; 32]).unwrap();
        let second = EbpfWorkloadScope::new([2; 32]).unwrap();
        assert_eq!(
            first.bpffs_pin_root(),
            EbpfWorkloadScope::new([1; 32]).unwrap().bpffs_pin_root()
        );
        assert_ne!(first.bpffs_pin_root(), second.bpffs_pin_root());
        assert_ne!(
            first.bpffs_pin_root(),
            PathBuf::from(super::super::DEFAULT_BPFFS_PIN_ROOT)
        );
        assert_eq!(format!("{first:?}"), "EbpfWorkloadScope { .. }");
        assert!(EbpfWorkloadScope::new([0; 32]).is_err());
    }

    #[test]
    fn workload_cleanup_resumes_after_every_effect_and_repeats() {
        let effects = super::super::CURRENT_EBPF_GRAPH_PIN_COUNT + 2;
        for cut in 1..=effects {
            let mut port = FakeCleanup::fresh();
            port.fail_after = Some(cut);
            assert!(cleanup(&mut port).is_err());
            assert_eq!(port.effects, cut);
            port.fail_after = None;
            cleanup(&mut port).unwrap();
            assert!(port.finished);
            cleanup(&mut port).unwrap();
        }
    }

    #[test]
    fn workload_cleanup_accepts_interrupted_creation_and_absence() {
        for present in 0..=super::super::CURRENT_EBPF_GRAPH_PIN_COUNT {
            let mut port = FakeCleanup::fresh();
            port.hooks = false;
            port.pins.retain(|index| *index < present);
            cleanup(&mut port).unwrap();
            assert!(port.finished);
        }
    }

    #[test]
    fn workload_cleanup_inspection_refusal_has_no_effects() {
        let mut port = FakeCleanup::fresh();
        port.foreign = true;
        assert!(cleanup(&mut port).is_err());
        assert_eq!(port.effects, 0);
        assert!(port.hooks);
        assert_eq!(port.pins.len(), super::super::CURRENT_EBPF_GRAPH_PIN_COUNT);
    }

    #[test]
    fn workload_cleanup_never_retires_permanent_selector_history() {
        let mut port = FakeCleanup::fresh();
        port.selector_bound = true;
        assert!(cleanup(&mut port).is_err());
        assert!(port.selector_bound && port.hooks);
        assert_eq!(port.effects, 0);
        assert_eq!(port.pins.len(), super::super::CURRENT_EBPF_GRAPH_PIN_COUNT);
    }

    #[test]
    fn exclusive_cleanup_orders_every_interface_and_object_before_map_removal() {
        struct Scope {
            hooks: [[bool; 2]; 3],
            object_pins: BTreeSet<usize>,
            map_pins: BTreeSet<usize>,
            released: bool,
            cut: Option<usize>,
            effects: usize,
        }
        impl Scope {
            fn effect(&mut self) -> Result<(), GtpuError> {
                self.effects += 1;
                if self.cut == Some(self.effects) {
                    Err(GtpuError::StateIndeterminate {
                        operation: "injected_cut",
                    })
                } else {
                    Ok(())
                }
            }
        }
        impl ExclusiveWorkloadCleanup for Scope {
            fn inventory(&mut self) -> Result<ExclusiveCleanupInventory, GtpuError> {
                self.released = false;
                self.effect()?;
                Ok(ExclusiveCleanupInventory {
                    interfaces: vec![0, 1, 2],
                    object_pins: self.object_pins.iter().copied().collect(),
                    pins: self.map_pins.iter().copied().collect(),
                    selector_bound: false,
                })
            }
            fn detach_interface(&mut self, interface: usize) -> Result<(), GtpuError> {
                for direction in 0..2 {
                    self.hooks[interface][direction] = false;
                    self.effect()?;
                }
                Ok(())
            }
            fn unpin(&mut self, pin: usize) -> Result<(), GtpuError> {
                assert_eq!(self.hooks, [[false; 2]; 3], "all leaves must detach first");
                if !self.object_pins.remove(&pin) {
                    assert!(
                        self.object_pins.is_empty(),
                        "links and programs retire first"
                    );
                    assert!(
                        self.released,
                        "wait for detached programs before map removal"
                    );
                    assert!(self.map_pins.remove(&pin));
                }
                self.effect()
            }
            fn wait_for_detached_programs(&mut self) -> Result<(), GtpuError> {
                assert_eq!(self.hooks, [[false; 2]; 3]);
                assert!(self.object_pins.is_empty());
                self.released = true;
                self.effect()
            }
            fn finish(&mut self) -> Result<(), GtpuError> {
                assert!(self.map_pins.is_empty());
                assert!(self.released);
                self.effect()
            }
        }
        // 1 complete inventory, 6 hook detaches across 3 interfaces, 2 object
        // pins, 1 wait, 5 map/directory removals, 1 finish. Include a cut inside
        // each interface's detach, between directions, as well as driver steps.
        for cut in 1..=16 {
            let mut port = Scope {
                hooks: [[true; 2]; 3],
                object_pins: [0, 1].into_iter().collect(),
                map_pins: (2..7).collect(),
                released: false,
                cut: Some(cut),
                effects: 0,
            };
            assert!(cleanup_exclusive(&mut port).is_err(), "cut {cut}");
            assert_eq!(port.effects, cut);
            port.cut = None;
            cleanup_exclusive(&mut port).unwrap();
            cleanup_exclusive(&mut port).unwrap();
            assert!(port.map_pins.is_empty());
            assert!(port.object_pins.is_empty());
        }
    }
}
