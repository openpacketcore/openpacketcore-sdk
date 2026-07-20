//! Safe GTP-U dataplane backend trait.

use async_trait::async_trait;
use std::io;

use crate::model::{
    CreateGtpDeviceRequest, DrainedV2TeardownOutcome, DrainedV2TeardownRequest, GtpDevice,
    GtpPdpContext, GtpuProbe, PdpContextInstallOutcome, PdpContextReadback,
    PdpContextReconciliationCapabilities, PdpContextRemovalOutcome, PdpContextSelector,
    RemovePdpContextRequest,
};
use crate::GtpuError;

/// Backend that can mutate Linux GTP-U dataplane state.
///
/// Implementations are async because real adapters perform netlink I/O and
/// privilege checks. The mock and unsupported adapters keep operations cheap
/// and deterministic.
#[async_trait]
pub trait GtpuDataplaneBackend: Send + Sync + std::fmt::Debug {
    /// Create a Linux `gtp` netdevice.
    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError>;

    /// Resolve an existing Linux `gtp` netdevice by interface name.
    async fn resolve_device(&self, name: &str) -> Result<GtpDevice, GtpuError>;

    /// Remove a Linux `gtp` netdevice.
    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError>;

    /// Remove a positively identified, drained legacy-v2 eBPF pin graph.
    ///
    /// This maintenance-only operation is deliberately separate from normal
    /// device resolution/removal. Implementations must independently prove
    /// the complete old program/map/hook identity and empty forwarding state,
    /// then preserve retry evidence across partial cleanup. Existing backend
    /// implementations inherit an explicit unsupported result.
    async fn teardown_drained_v2(
        &self,
        _request: DrainedV2TeardownRequest,
    ) -> Result<DrainedV2TeardownOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "drained_v2_teardown",
        })
    }

    /// Install a GTP-U PDP context.
    ///
    /// [`GtpuError::RetryRequired`] means the backend completed a safe
    /// prerequisite recovery step but did not install this request. Callers
    /// must not treat that result as already present; resubmit the desired
    /// context as a new operation.
    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError>;

    /// Remove a GTP-U PDP context.
    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError>;

    /// Read one complete PDP context by a typed selector.
    ///
    /// The default is explicitly unsupported so existing third-party trait
    /// implementations remain source-compatible without accidentally claiming
    /// that absence or equality was proven.
    async fn read_pdp_context(
        &self,
        _selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_context_readback",
        })
    }

    /// Install a context only after classifying both its local-TEID and uplink
    /// selector axes.
    ///
    /// Unlike [`Self::install_pdp_context`], this strict convergence method
    /// never treats an uninspected `AlreadyExists` result as idempotent and
    /// never silently relocates an existing context. Cancellation does not
    /// prove that a backend's blocking kernel operation stopped; callers must
    /// use readback before retrying after dropping an in-flight future.
    async fn install_pdp_context_classified(
        &self,
        _request: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_context_classified_install",
        })
    }

    /// Remove only state that both selector axes prove exactly matches
    /// `expected` under the backend's mutation-authority boundary.
    ///
    /// Backends without compare-delete or an equivalent exclusive writer must
    /// leave this unsupported. Consumer-orchestrated stale removal followed by
    /// desired installation has a bounded forwarding gap between the two
    /// successful calls; this API does not claim atomic replacement.
    async fn remove_pdp_context_exact(
        &self,
        _expected: GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_context_exact_removal",
        })
    }

    /// Report support for the additive PDP reconciliation contract.
    ///
    /// This is intentionally separate from packet-processing capabilities in
    /// [`GtpuProbe`].
    fn pdp_context_reconciliation_capabilities(&self) -> PdpContextReconciliationCapabilities {
        PdpContextReconciliationCapabilities::unsupported()
    }

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<GtpuProbe, GtpuError>;
}

/// Return true only for errors whose contract proves the requested mutation
/// did not execute. Other transport/runtime errors may represent ACK loss or a
/// partial multi-resource update and must be reconciled from authoritative
/// readback rather than propagated as proof of absence.
pub(crate) fn error_proves_no_requested_mutation(error: &GtpuError) -> bool {
    matches!(
        error,
        GtpuError::UnsupportedPlatform
            | GtpuError::UnsupportedFeature { .. }
            | GtpuError::NotFound
            | GtpuError::RetryRequired { .. }
            | GtpuError::InvalidConfig { .. }
            | GtpuError::Io {
                kind: io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported,
                ..
            }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct LegacyExternalBackend;

    #[async_trait]
    impl GtpuDataplaneBackend for LegacyExternalBackend {
        async fn create_device(
            &self,
            _request: CreateGtpDeviceRequest,
        ) -> Result<GtpDevice, GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn resolve_device(&self, _name: &str) -> Result<GtpDevice, GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn remove_device(&self, _device: &GtpDevice) -> Result<(), GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn install_pdp_context(&self, _request: GtpPdpContext) -> Result<(), GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn remove_pdp_context(
            &self,
            _request: RemovePdpContextRequest,
        ) -> Result<(), GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
            Ok(GtpuProbe::unsupported())
        }
    }

    #[tokio::test]
    async fn legacy_external_implementer_gets_fail_closed_defaults() {
        let backend: Box<dyn GtpuDataplaneBackend> = Box::new(LegacyExternalBackend);
        assert_eq!(
            backend.pdp_context_reconciliation_capabilities(),
            PdpContextReconciliationCapabilities::unsupported()
        );
        let selector = PdpContextSelector::LocalTeid(
            crate::PdpContextLocalTeidSelector::new(
                7,
                crate::GtpVersion::V1,
                crate::GtpAddressFamily::Ipv4,
                crate::Teid::new(1).unwrap(),
            )
            .unwrap(),
        );
        assert!(matches!(
            backend.read_pdp_context(selector).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "pdp_context_readback"
            })
        ));
        let request = crate::DrainedV2TeardownRequest::new(
            crate::GtpDevice {
                name: String::from("gtp0"),
                ifindex: 7,
            },
            crate::GtpuV2DrainProof::sessions_and_traffic_drained(),
        );
        assert!(matches!(
            backend.teardown_drained_v2(request).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "drained_v2_teardown"
            })
        ));
    }
}
