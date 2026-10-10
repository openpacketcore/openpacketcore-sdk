//! Namespace actor participation in one contained local reset.

#[cfg(feature = "scope-store")]
pub(crate) mod effect;
#[cfg(feature = "scope-store")]
pub(crate) mod operations;
pub(crate) mod profile;
#[cfg(feature = "scope-store")]
mod registry;
#[cfg(feature = "scope-store")]
pub(crate) mod request;
#[cfg(feature = "scope-store")]
pub use operations::ScopedXfrmReceipt;
#[cfg(feature = "scope-store")]
pub use request::ScopedXfrmRequest;

use crate::{
    ExclusiveNamespaceResetAcknowledgement, LinuxXfrmBackend, LinuxXfrmBackendConfig,
    LinuxXfrmDscpMarkingConfig, NamespaceBoundLinuxXfrmBackend, XfrmError,
};
use opc_local_kernel_lifecycle::{
    LocalKernelLifecycle, LocalLifecycleError, LocalXfrmReset, ResetPhase,
};
use std::sync::Arc;

/// Opaque, actor-local admission of the restricted XFRM producer profile.
/// This reports full key-readback capability under an exact reset epoch. It
/// does not authorize a session or grant committed activation authority.
#[derive(Clone)]
pub struct LocalXfrmProfile {
    binding: Arc<ProfileBinding>,
}
struct ProfileBinding {
    epoch: opc_local_kernel_lifecycle::LocalScopeEpoch,
}
impl std::fmt::Debug for LocalXfrmProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalXfrmProfile")
    }
}
impl LocalXfrmProfile {
    #[cfg(feature = "scope-store")]
    pub(crate) async fn begin(
        &self,
    ) -> Result<opc_local_kernel_lifecycle::LocalOperation, XfrmError> {
        self.binding
            .epoch
            .begin_operation()
            .await
            .map_err(|_| XfrmError::StateMismatch {
                operation: "local_scope_profile_epoch",
            })
    }
    /// Recheck that no subsequent reset invalidated this local profile.
    pub fn recheck(&self) -> Result<(), XfrmError> {
        self.binding
            .epoch
            .recheck()
            .map_err(|_| XfrmError::StateMismatch {
                operation: "local_scope_profile_epoch",
            })
    }
}

#[derive(Default)]
pub(crate) struct LocalXfrmState {
    epoch: Option<opc_local_kernel_lifecycle::LocalScopeEpoch>,
    probe: Option<crate::linux::LocalAdmissionProbe>,
    profile: Option<LocalXfrmProfile>,
    refused: bool,
    admission: Option<ProfileAdmission>,
}
struct ProfileAdmission {
    guard: opc_local_kernel_lifecycle::LocalContainedOperation,
    reply: tokio::sync::oneshot::Sender<Result<LocalXfrmProfile, XfrmError>>,
    schedule: opc_local_kernel_lifecycle::CleanupSchedule,
}
impl LocalXfrmState {
    #[cfg(feature = "scope-store")]
    pub(crate) fn profile(&self) -> Option<LocalXfrmProfile> {
        self.profile.clone()
    }
    pub(crate) fn next_attempt(&self) -> Option<tokio::time::Instant> {
        self.admission
            .as_ref()
            .map(|admission| admission.schedule.next_attempt())
    }
    #[cfg(feature = "scope-store")]
    pub(crate) fn progress(&self) -> Option<opc_local_kernel_lifecycle::CleanupProgress> {
        self.admission
            .as_ref()
            .map(|admission| admission.schedule.progress())
    }
    pub(crate) fn admit(
        &mut self,
        guard: opc_local_kernel_lifecycle::LocalContainedOperation,
        reply: tokio::sync::oneshot::Sender<Result<LocalXfrmProfile, XfrmError>>,
    ) {
        if guard.recheck().is_err() {
            let _ = reply.send(Err(XfrmError::StateMismatch {
                operation: "local_scope_profile_epoch",
            }));
            return;
        }
        let epoch = guard.epoch();
        if !self.epoch.as_ref().is_some_and(|old| old.is_same(&epoch)) {
            *self = Self {
                epoch: Some(epoch.clone()),
                ..Self::default()
            };
        }
        if let Some(profile) = &self.profile {
            let _ = reply.send(profile.recheck().map(|()| profile.clone()));
        } else if self.refused {
            let _ = reply.send(Err(XfrmError::UnsupportedFeature {
                feature: "local_scope_full_key_readback",
            }));
        } else if let Some(admission) = &mut self.admission {
            if admission.reply.is_closed() {
                admission.reply = reply;
            } else {
                let _ = reply.send(Err(XfrmError::StateIndeterminate {
                    operation: "local_scope_profile_admission",
                }));
            }
        } else {
            match crate::linux::LocalAdmissionProbe::new() {
                Ok(probe) => {
                    self.probe = Some(probe);
                    self.admission = Some(ProfileAdmission {
                        guard,
                        reply,
                        schedule: Default::default(),
                    });
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            }
        }
    }
    pub(crate) async fn step(&mut self, backend: &LinuxXfrmBackend) {
        use futures_util::FutureExt;
        let Some(admission) = self.admission.as_mut() else {
            return;
        };
        let Some(attempt) = admission.schedule.begin() else {
            return;
        };
        let Some(probe) = self.probe.as_mut() else {
            return;
        };
        let work = probe.run(backend, &admission.guard, attempt);
        let result = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            std::panic::AssertUnwindSafe(work).catch_unwind(),
        )
        .await
        {
            Ok(Ok(result)) => result,
            _ => Err(XfrmError::StateIndeterminate {
                operation: "local_scope_profile_admission",
            }),
        };
        if result.is_err() && probe.has_uncertain_effects() {
            admission.schedule.failed(rand::random());
            return;
        }
        let Some(admission) = self.admission.take() else {
            return;
        };
        self.probe = None;
        if matches!(
            result,
            Err(XfrmError::UnsupportedFeature {
                feature: "local_scope_full_key_readback"
            })
        ) {
            self.refused = true;
        }
        let result = result.map(|()| {
            let profile = LocalXfrmProfile {
                binding: Arc::new(ProfileBinding {
                    epoch: admission.guard.epoch(),
                }),
            };
            self.profile = Some(profile.clone());
            profile
        });
        let _ = admission.reply.send(result);
    }
}

impl NamespaceBoundLinuxXfrmBackend {
    /// Qualify the sole producer after contained whole-scope reset. The private
    /// probe is removed and the full SPD/SAD (including socket policies) is
    /// freshly empty before success or a typed key-readback refusal. An
    /// uncertain probe remains owned by the actor for exact retry or reset.
    pub async fn admit_scoped_profile(
        &self,
        receipt: &opc_local_kernel_lifecycle::LocalScopeResetReceipt,
    ) -> Result<LocalXfrmProfile, XfrmError> {
        let lifecycle = self
            .local_lifecycle()
            .ok_or(XfrmError::UnsupportedFeature {
                feature: "local_scope_requires_scoped_operation",
            })?;
        let guard = receipt
            .begin_contained_operation(lifecycle)
            .await
            .map_err(|_| XfrmError::StateMismatch {
                operation: "local_scope_profile_epoch",
            })?;
        self.admit_local_profile(guard).await
    }
    /// Create a fresh namespace actor in the local writer domain. Construction
    /// is effect-free, including DSCP. The ownership acknowledgement has the
    /// same stopped-namespace and no-predecessor-retention requirements as the
    /// existing exclusive reset. Legacy mutation entry points are unavailable.
    pub fn for_local_scope(
        lifecycle: LocalKernelLifecycle,
        config: LinuxXfrmBackendConfig,
        dscp: Option<LinuxXfrmDscpMarkingConfig>,
        _ownership: ExclusiveNamespaceResetAcknowledgement,
    ) -> Result<Self, XfrmError> {
        if config.receive_attempts == 0
            || config
                .retry_delay
                .checked_mul(u32::from(config.receive_attempts))
                .is_none_or(|duration| duration > std::time::Duration::from_secs(1))
        {
            return Err(XfrmError::invalid_config(
                "local_scope.netlink",
                "exchanges require a nonzero attempt count and at most one second of retry delay",
            ));
        }
        lifecycle.local_scope().verify().map_err(scope_error)?;
        if let Some(dscp) = &dscp {
            dscp.validate()?;
            let relative = dscp
                .bpffs_pin_root
                .strip_prefix(lifecycle.local_scope().spec().pin_root())
                .map_err(|_| {
                    XfrmError::invalid_config(
                        "dscp.local_scope",
                        "pin root is outside the held scope",
                    )
                })?;
            for interface in &dscp.egress_interfaces {
                let ifindex = opc_linux_gtpu_sys::ifindex_by_name(interface)
                    .map_err(|error| XfrmError::io("local_scope_interface", error))?;
                let graph = crate::XfrmDscpLocalGraph::new(
                    relative.join(interface),
                    ifindex,
                    dscp.tc_priority,
                )?;
                lifecycle.bind_graph(graph.artifact()).map_err(|_| {
                    XfrmError::invalid_config(
                        "dscp.local_scope",
                        "DSCP graph is absent from the shared plan",
                    )
                })?;
            }
        }
        let backend = match dscp {
            Some(config_dscp) => {
                LinuxXfrmBackend::with_config_and_deferred_dscp_marking(config, config_dscp)?
            }
            None => LinuxXfrmBackend::with_config(config),
        };
        backend
            .with_local_lifecycle(lifecycle)?
            .bind_current_network_namespace()
    }

    /// Obtain the reset port backed by this actor's fresh SPD/SAD readback.
    /// An ordinary unbound actor cannot be used as a local reset participant.
    pub fn local_reset_participant(&self) -> Result<Arc<dyn LocalXfrmReset>, XfrmError> {
        let lifecycle = self
            .local_lifecycle()
            .ok_or(XfrmError::UnsupportedFeature {
                feature: "local_scope_requires_scoped_operation",
            })?
            .clone();
        Ok(Arc::new(XfrmResetParticipant {
            backend: self.clone(),
            lifecycle,
        }))
    }
}

pub(crate) fn scope_error(_: opc_linux_gtpu_sys::tc::ScopeError) -> XfrmError {
    XfrmError::StateIndeterminate {
        operation: "local_scope_containment",
    }
}

struct XfrmResetParticipant {
    backend: NamespaceBoundLinuxXfrmBackend,
    lifecycle: LocalKernelLifecycle,
}
#[async_trait::async_trait]
impl LocalXfrmReset for XfrmResetParticipant {
    fn local_scope(&self) -> &opc_linux_gtpu_sys::tc::LocalKernelScope {
        self.lifecycle.local_scope()
    }
    async fn is_empty(&self) -> Result<bool, LocalLifecycleError> {
        self.backend
            .local_namespace_empty()
            .await
            .map_err(|_| LocalLifecycleError::Incomplete(ResetPhase::Xfrm))
    }
    async fn reset_contained(
        &self,
        contained: &opc_linux_gtpu_sys::tc::ContainedScope,
    ) -> Result<(), LocalLifecycleError> {
        if !self.local_scope().is_same_instance(contained.scope()) {
            return Err(LocalLifecycleError::InvalidPlan);
        }
        self.backend
            .reset_local_namespace(contained.clone())
            .await
            .map_err(|_| LocalLifecycleError::Incomplete(ResetPhase::Xfrm))
    }
}

#[cfg(all(test, target_os = "linux", feature = "scope-store"))]
mod tests;
