//! Safe GTP-U dataplane backend trait.

use async_trait::async_trait;

use crate::model::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpuProbe, RemovePdpContextRequest,
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

    /// Remove a Linux `gtp` netdevice.
    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError>;

    /// Install a GTP-U PDP context.
    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError>;

    /// Remove a GTP-U PDP context.
    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError>;

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<GtpuProbe, GtpuError>;
}
