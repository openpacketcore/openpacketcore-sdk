//! Current-image graph inspection for the held local kernel lifecycle.

use crate::GtpuError;
use opc_linux_gtpu_sys::tc::{ArtifactInventory, ArtifactSpec, LocalKernelScope};
use opc_local_kernel_lifecycle::{LocalArtifact, LocalGraphBinding, LocalLifecycleError};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
pub(super) mod session_effect;

/// Process-local publication of one grouped GTP-U session. A receipt cannot
/// be transplanted to another actor or reset epoch; dropping it preserves
/// forwarding. It contains no authority to create a new session.
#[derive(Clone)]
pub struct ScopedGtpuReceipt {
    #[cfg(target_os = "linux")]
    pub(super) binding: std::sync::Arc<ScopedGtpuBinding>,
    #[cfg(not(target_os = "linux"))]
    _unsupported: std::convert::Infallible,
}
#[cfg(target_os = "linux")]
pub(super) struct ScopedGtpuBinding {
    pub(super) graph: opc_local_kernel_lifecycle::LocalInstalledGraph,
    pub(super) retired: std::sync::atomic::AtomicBool,
}
impl std::fmt::Debug for ScopedGtpuReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedGtpuReceipt")
    }
}

impl super::EbpfGtpuDataplaneBackend {
    /// Install one exact group under real committed activation. Capacity waits
    /// for actor admission; a dropped unpublished operation is undone by its
    /// owner. Exact published retries require only fresh local readback.
    pub async fn install_scoped(
        &self,
        graph: &opc_local_kernel_lifecycle::LocalInstalledGraph,
        effect: opc_local_kernel_lifecycle::CommittedScopeEffect,
        request: crate::GtpuSessionGroup,
    ) -> Result<ScopedGtpuReceipt, GtpuError> {
        #[cfg(target_os = "linux")]
        {
            self.scoped_runtime()?.install(graph, effect, request).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (graph, effect, request);
            Err(GtpuError::UnsupportedPlatform)
        }
    }
    /// Read this actor's exact published group and selectors without store
    /// authority, repairing nothing and refusing changed object identities.
    pub async fn read_scoped(&self, receipt: &ScopedGtpuReceipt) -> Result<bool, GtpuError> {
        #[cfg(target_os = "linux")]
        {
            self.scoped_runtime()?.read(receipt).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = receipt;
            Err(GtpuError::UnsupportedPlatform)
        }
    }
    /// Retire only this receipt's group, drain kernel readers and then remove
    /// its exact selectors. Cleanup bypasses install admission and needs no
    /// current store authority, including after the caller is dropped.
    pub async fn remove_scoped(&self, receipt: &ScopedGtpuReceipt) -> Result<(), GtpuError> {
        #[cfg(target_os = "linux")]
        {
            self.scoped_runtime()?.remove(receipt).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = receipt;
            Err(GtpuError::UnsupportedPlatform)
        }
    }
    /// Fixed progress for pending actor-owned work; clocks only pace retries.
    pub async fn scoped_cleanup_progress(
        &self,
    ) -> Result<Vec<opc_local_kernel_lifecycle::CleanupProgress>, GtpuError> {
        #[cfg(target_os = "linux")]
        {
            self.scoped_runtime()?.progress().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(GtpuError::UnsupportedPlatform)
        }
    }
    #[cfg(target_os = "linux")]
    fn scoped_runtime(
        &self,
    ) -> Result<&std::sync::Arc<super::aya_runtime::local_scope::Runtime>, GtpuError> {
        self.inner
            .local_runtime
            .as_ref()
            .ok_or(GtpuError::UnsupportedFeature {
                feature: "local_scope_requires_scoped_operation",
            })
    }
    /// Build the current GTP-U image and empty grouped-session configuration
    /// under a completed contained reset. This grants no session activation.
    pub async fn rebuild_local_graph(
        &self,
        reset: &opc_local_kernel_lifecycle::LocalScopeResetReceipt,
        request: crate::CreateGtpDeviceEndpointSetRequest,
    ) -> Result<opc_local_kernel_lifecycle::LocalInstalledGraph, GtpuError> {
        #[cfg(target_os = "linux")]
        {
            let binding = self
                .inner
                .local_scope
                .as_ref()
                .ok_or(GtpuError::UnsupportedFeature {
                    feature: "local_scope_requires_scoped_operation",
                })?;
            let runtime = self
                .inner
                .local_runtime
                .as_ref()
                .ok_or(GtpuError::UnsupportedPlatform)?;
            runtime.rebuild(binding, reset, request).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (reset, request);
            Err(GtpuError::UnsupportedPlatform)
        }
    }
    /// Create a backend bound to one catalog in the shared contained lifecycle.
    /// Legacy workload resets and unscoped mutation entry points are unavailable
    /// on this backend. The shared coordinator retains its local writer guard.
    pub fn for_local_scope(binding: LocalGraphBinding) -> Result<Self, GtpuError> {
        #[cfg(target_os = "linux")]
        {
            let spec = binding.artifact();
            let slot = spec.slots().next().ok_or_else(|| {
                GtpuError::invalid_config("ebpf.local_scope", "missing graph slot")
            })?;
            let expected =
                EbpfLocalGraph::new(spec.directory().to_owned(), slot.ifindex(), slot.priority())?;
            if expected.artifact() != spec {
                return Err(GtpuError::invalid_config(
                    "ebpf.local_scope",
                    "binding is not the current GTP-U graph",
                ));
            }
            binding
                .local_scope()
                .verify()
                .map_err(|_| GtpuError::StateIndeterminate {
                    operation: "ebpf_local_scope",
                })?;
            let parent = spec.directory().parent().ok_or_else(|| {
                GtpuError::invalid_config("ebpf.local_scope", "missing graph parent")
            })?;
            let mut backend = Self::with_config(super::EbpfGtpuDataplaneBackendConfig {
                bpffs_pin_root: binding.local_scope().spec().pin_root().join(parent),
                tc_priority: slot.priority(),
            });
            let registration =
                binding
                    .register_actor()
                    .map_err(|_| GtpuError::StateIndeterminate {
                        operation: "ebpf_local_scope_actor_busy",
                    })?;
            let inner = std::sync::Arc::get_mut(&mut backend.inner).ok_or(
                GtpuError::StateIndeterminate {
                    operation: "ebpf_local_scope",
                },
            )?;
            inner.local_runtime = Some(std::sync::Arc::new(
                super::aya_runtime::local_scope::Runtime::new(registration)?,
            ));
            inner.local_scope = Some(binding);
            Ok(backend)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = binding;
            Err(GtpuError::UnsupportedPlatform)
        }
    }
}

/// Current GTP-U image catalog at two exact tc slots and one private pin leaf.
///
/// Construction derives all program tags, map definitions and graph relations
/// from the shipped image. Inspection neither adopts a retained graph nor
/// installs forwarding. A predecessor is retired under shared containment.
#[derive(Clone, Debug)]
pub struct EbpfLocalGraph {
    spec: ArtifactSpec,
}

impl LocalArtifact for EbpfLocalGraph {
    fn artifact(&self) -> &ArtifactSpec {
        &self.spec
    }
    fn preserved_empty_directories(&self) -> Vec<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            super::aya_runtime::local_scope::preserved_directories(&self.spec)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }
    fn inspect(&self, scope: &LocalKernelScope) -> Result<ArtifactInventory, LocalLifecycleError> {
        EbpfLocalGraph::inspect(self, scope).map_err(Into::into)
    }
}
impl EbpfLocalGraph {
    /// Bind this image to one interface and relative directory in a local scope.
    pub fn new(
        relative_pin_directory: PathBuf,
        ifindex: u32,
        tc_priority: u16,
    ) -> Result<Self, GtpuError> {
        #[cfg(target_os = "linux")]
        {
            super::aya_runtime::local_scope::artifact_spec(
                relative_pin_directory,
                ifindex,
                tc_priority,
            )
            .map(|spec| Self { spec })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (relative_pin_directory, ifindex, tc_priority);
            Err(GtpuError::UnsupportedPlatform)
        }
    }
    /// Retain a complete current-image graph under the given local writer guard.
    pub fn inspect(
        &self,
        scope: &LocalKernelScope,
    ) -> Result<ArtifactInventory, opc_linux_gtpu_sys::tc::ScopeError> {
        let inventory = ArtifactInventory::inspect(scope, &self.spec)?;
        #[cfg(target_os = "linux")]
        super::aya_runtime::local_scope::require_no_selector_history(
            scope, &self.spec, &inventory,
        )?;
        Ok(inventory)
    }
    /// Exact low-level catalog derived from the embedded object.
    pub fn artifact(&self) -> &ArtifactSpec {
        &self.spec
    }
}
