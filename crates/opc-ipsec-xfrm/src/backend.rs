//! Safe XFRM backend trait.

use async_trait::async_trait;

use crate::model::{
    validate_exact_remove_policy_request, AllocateSpiRequest, ExactRemovePolicyRequest,
    InstallPolicyRequest, InstallSaRequest, QuerySaRequest, RekeyPolicyRequest, RekeySaRequest,
    RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest, SaRelocationIdentity, SaState,
    SpiAllocation, XfrmCapability, XfrmProbe,
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

    /// Query the exact current-state snapshot needed to authorize one SA
    /// relocation.
    ///
    /// This is separate from [`Self::query_sa`] so the established public
    /// `SaState` shape remains source compatible. Backends that cannot prove
    /// the complete raw selector, lookup mark, zero-original-address NAT-T
    /// template, and interface identifier fail closed.
    async fn query_sa_relocation_identity(
        &self,
        _request: QuerySaRequest,
    ) -> Result<SaRelocationIdentity, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "sa_relocation",
        })
    }

    /// Rekey (update) an existing Security Association.
    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError>;

    /// Relocate one exactly identified SA's outer endpoints and optionally
    /// preserve, set, or remove its NAT-T encapsulation.
    ///
    /// Outgoing callers must install the upstream-required block policy before
    /// selecting `OutboundBlockPolicyInstalled` and retain it until the
    /// replacement allow policy is active. Incoming relocation does not need
    /// that block. See [`crate::SaRelocationDirection`].
    ///
    /// Backends without an exact single-SA primitive fail closed. The default
    /// keeps third-party adapters source-compatible while making lack of this
    /// optional capability explicit.
    ///
    /// # Cancel safety
    ///
    /// This operation is not cancellation-safe once polled. A backend may
    /// continue its kernel mutation and readback after the returned future is
    /// dropped. Callers must supervise and poll the future to completion rather
    /// than wrap it in an aborting timeout. Cancellation, disconnection, or
    /// process loss is operationally [`XfrmError::StateIndeterminate`]: retain
    /// the outbound block policy and namespace-wide writer exclusion until the
    /// worker completes and exact old/new tuple readback reconciles the state.
    /// After process loss, reconcile before retrying; relocation is not blindly
    /// idempotent.
    async fn relocate_sa(&self, _request: RelocateSaRequest) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "sa_relocation",
        })
    }

    /// Report exact single-SA relocation support without changing the
    /// source-compatible [`XfrmProbe`] structure.
    ///
    /// Linux uses the upstream non-mutating missing-SA probe. `ESRCH` proves
    /// support, while `EINVAL` identifies a kernel predating the message and
    /// `ENOPROTOOPT` identifies a kernel built without migration support.
    async fn sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
        Ok(XfrmCapability::Missing)
    }

    /// Remove a Security Association.
    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError>;

    /// Install a new Security Policy.
    async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError>;

    /// Rekey (update) an existing Security Policy.
    async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError>;

    /// Remove a Security Policy.
    async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError>;

    /// Remove one exactly interface-scoped Security Policy.
    ///
    /// The default keeps existing backend implementations source-compatible.
    /// It delegates an unscoped request to [`Self::remove_policy`] and fails
    /// closed for a scoped request because the established method cannot carry
    /// `XFRMA_IF_ID`. Backends must override this method to advertise and
    /// implement scoped deletion. A scoped implementation must prove through
    /// exact policy readback that the platform recognized the requested
    /// interface ID before issuing an unconditional delete; older Linux
    /// kernels silently ignore unknown netlink attributes.
    ///
    /// Linux has no owner- or generation-conditional policy deletion. Callers
    /// must therefore hold namespace-wide XFRM writer exclusion across the
    /// complete readback-and-delete future. The namespace actor serializes SDK
    /// operations on that actor, but it cannot exclude unrelated writers.
    async fn remove_policy_exact(
        &self,
        request: ExactRemovePolicyRequest,
    ) -> Result<(), XfrmError> {
        validate_exact_remove_policy_request(&request)?;
        if request.if_id().is_some() {
            return Err(XfrmError::UnsupportedFeature {
                feature: "exact_scoped_policy_removal",
            });
        }
        self.remove_policy(request.into_request()).await
    }

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<XfrmProbe, XfrmError>;
}
