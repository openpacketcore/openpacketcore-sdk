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
            backend.inner.runtime.reset_workload_graph(
                ifindex,
                &backend.pin_dir(&interface),
                backend.inner.config.tc_priority,
            )
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
}
