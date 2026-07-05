//! Unsupported-platform GTP-U dataplane backend.

use async_trait::async_trait;

use crate::backend::GtpuDataplaneBackend;
use crate::error::GtpuError;
use crate::model::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpuProbe, RemovePdpContextRequest,
};

/// GTP-U backend that reports [`GtpuError::UnsupportedPlatform`] for every
/// mutating operation and a probe with `platform_supported = false`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedGtpuDataplaneBackend;

impl UnsupportedGtpuDataplaneBackend {
    /// Create a new unsupported backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl GtpuDataplaneBackend for UnsupportedGtpuDataplaneBackend {
    async fn create_device(
        &self,
        _request: CreateGtpDeviceRequest,
    ) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn remove_device(&self, _device: &GtpDevice) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn install_pdp_context(&self, _request: GtpPdpContext) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn remove_pdp_context(&self, _request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        Ok(GtpuProbe::unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GtpuBackendKind;

    #[tokio::test]
    async fn unsupported_backend_returns_unsupported_platform_for_mutation() {
        let backend = UnsupportedGtpuDataplaneBackend::new();
        let err = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap_err();
        assert!(matches!(err, GtpuError::UnsupportedPlatform));
    }

    #[tokio::test]
    async fn unsupported_probe_reports_unsupported() {
        let backend = UnsupportedGtpuDataplaneBackend::new();
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::Unsupported);
        assert!(!probe.platform_supported);
        assert!(!probe.kernel_reachable);
        assert!(!probe.net_admin_capable);
        assert!(!probe.mutation_ready);
    }
}
