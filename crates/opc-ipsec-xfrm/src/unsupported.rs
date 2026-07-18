//! Unsupported-platform XFRM backend.

use async_trait::async_trait;

use crate::backend::XfrmBackend;
use crate::error::XfrmError;
use crate::model::{
    AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, QuerySaRequest, RekeyPolicyRequest,
    RekeySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest, SaRelocationIdentity,
    SaState, SpiAllocation, XfrmProbe,
};

/// XFRM backend that reports [`XfrmError::UnsupportedPlatform`] for every
/// mutating operation and a probe with `platform_supported = false`.
///
/// Use this backend on non-Linux targets or in any build where real XFRM
/// netlink access is intentionally disabled.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedXfrmBackend;

impl UnsupportedXfrmBackend {
    /// Create a new unsupported backend.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl XfrmBackend for UnsupportedXfrmBackend {
    async fn allocate_spi(&self, _request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn install_sa(&self, _request: InstallSaRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn query_sa(&self, _request: QuerySaRequest) -> Result<SaState, XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn query_sa_relocation_identity(
        &self,
        _request: QuerySaRequest,
    ) -> Result<SaRelocationIdentity, XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn relocate_sa(&self, _request: RelocateSaRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn remove_sa(&self, _request: RemoveSaRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn install_policy(&self, _request: InstallPolicyRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn remove_policy(&self, _request: RemovePolicyRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
        Ok(XfrmProbe::unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IpAddress, XfrmBackendKind, XfrmCapability};

    #[tokio::test]
    async fn unsupported_backend_returns_unsupported_platform_for_all_ops() {
        let backend = UnsupportedXfrmBackend::new();
        let request = RemoveSaRequest {
            destination: IpAddress::Ipv4([10, 0, 0, 2]),
            protocol: 50,
            spi: 0x1234_5678,
            mark: None,
        };
        let err = backend.remove_sa(request).await.unwrap_err();
        assert!(matches!(err, XfrmError::UnsupportedPlatform));
    }

    #[tokio::test]
    async fn unsupported_probe_reports_unsupported() {
        let backend = UnsupportedXfrmBackend::new();
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, XfrmBackendKind::Unsupported);
        assert!(!probe.platform_supported);
        assert!(!probe.kernel_reachable);
        assert!(!probe.net_admin_capable);
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Missing
        );
    }
}
