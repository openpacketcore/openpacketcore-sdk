//! Safe XFRM backend trait.

use async_trait::async_trait;

use crate::model::{
    AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, QuerySaRequest, RekeyPolicyRequest,
    RekeySaRequest, RemovePolicyRequest, RemoveSaRequest, SaState, SpiAllocation, XfrmProbe,
};
use crate::XfrmError;

/// Backend that can mutate Linux XFRM IPsec state.
///
/// Implementations are async because real adapters may perform blocking netlink
/// I/O or privilege checks, and the SDK's callers are async. The mock and
/// unsupported adapters keep operations cheap and deterministic.
#[async_trait]
pub trait XfrmBackend: Send + Sync + std::fmt::Debug {
    /// Allocate an SPI for an inbound SA.
    async fn allocate_spi(&self, request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError>;

    /// Install a new Security Association.
    async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError>;

    /// Query an existing Security Association.
    async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError>;

    /// Rekey (update) an existing Security Association.
    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError>;

    /// Remove a Security Association.
    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError>;

    /// Install a new Security Policy.
    async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError>;

    /// Rekey (update) an existing Security Policy.
    async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError>;

    /// Remove a Security Policy.
    async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError>;

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<XfrmProbe, XfrmError>;
}
