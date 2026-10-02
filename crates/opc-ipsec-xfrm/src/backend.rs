//! Safe XFRM backend trait.

use async_trait::async_trait;

use crate::model::{
    authorize_exact_sa_removal, validate_exact_remove_policy_request,
    validate_exact_remove_sa_request, AllocateSpiRequest, ExactRemovePolicyRequest,
    ExactRemoveSaRequest, InstallPolicyRequest, InstallSaRequest, PolicyParameters,
    QueryPolicyRequest, QuerySaRequest, RekeyPolicyRequest, RekeySaRequest, RelocateSaRequest,
    RemovePolicyRequest, RemoveSaRequest, SaKeySnapshot, SaLookupKey, SaRelocationIdentity,
    SaState, SpiAllocation, XfrmCapability, XfrmProbe,
};
use crate::XfrmError;

/// Backend that can mutate Linux XFRM IPsec state.
///
/// Implementations are async because real adapters may perform blocking netlink
/// I/O or privilege checks, and the SDK's callers are async. The mock and
/// unsupported adapters keep operations cheap and deterministic.
#[async_trait]
pub trait XfrmBackend: Send + Sync + std::fmt::Debug {
    /// Report support for the optional authenticated complete-roster profile.
    /// Raw, mock and custom adapters default to Missing. Available still
    /// requires a valid bounded intent and a bound durable namespace actor.
    #[cfg(all(unix, feature = "ikev2"))]
    async fn child_sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
        Ok(XfrmCapability::Missing)
    }

    /// Acquire an affine ticket for installed Child-SA roster publication.
    ///
    /// Only a namespace-bound actor with whole-roster readback and writer
    /// fencing implements this optional profile. Raw Linux, mock and custom
    /// backends fail closed by default. Install/adopt resources before this call.
    async fn begin_child_sa_roster_update(&self) -> Result<crate::ChildSaRosterUpdate, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "installed_child_sa_roster",
        })
    }

    /// Consume a current ticket, read back every declared SA/policy and publish
    /// one key-free generation. A failed readback retires the predecessor.
    ///
    /// The actor continues an admitted call after caller cancellation. Lost
    /// replies require a fresh ticket and full readback; they do not authorize
    /// use of an older generation. This call makes no kernel mutations and
    /// grants no packet-provenance or endpoint-migration authority.
    async fn publish_child_sa_roster(
        &self,
        _update: crate::ChildSaRosterUpdate,
        _request: crate::ChildSaInstalledRosterRequest,
    ) -> Result<crate::InstalledChildSaRoster, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "installed_child_sa_roster",
        })
    }

    /// Select an exact outbound pair after fresh whole-roster readback.
    ///
    /// Caller classification chooses a class or the explicit default. This is
    /// a point-in-time observation under namespace writer exclusion, not a
    /// lock across later packet sends. Any admitted actor mutation invalidates
    /// the publication, even if that mutation later fails or is indeterminate.
    async fn select_installed_child_sa(
        &self,
        _roster: &crate::InstalledChildSaRoster,
        _selection: crate::child_sa::ChildSaOutboundSelection,
    ) -> Result<crate::InstalledChildSaSelection, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "installed_child_sa_roster",
        })
    }

    /// Allocate an SPI for an inbound SA.
    async fn allocate_spi(&self, request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError>;

    /// Install a new Security Association.
    async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError>;

    /// Query an existing Security Association.
    async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError>;

    /// Query one exactly identified Security Policy.
    ///
    /// This is the policy counterpart of [`Self::query_sa`]: an observation
    /// authority that reports the current kernel parameters of the exact
    /// selector/direction/mark/interface identity, or [`XfrmError::NotFound`]
    /// when no such policy exists. It never authorizes a mutation. Backends
    /// without an exact single-policy readback fail closed with
    /// [`XfrmError::UnsupportedFeature`].
    async fn query_policy(
        &self,
        _request: QueryPolicyRequest,
    ) -> Result<PolicyParameters, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "exact_policy_query",
        })
    }

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

    /// Read every SA state at one lookup key, whatever its lookup mark.
    ///
    /// Linux GETSA, DELSA, UPDSA, and MIGRATE_STATE all select their state
    /// with `__xfrm_state_lookup`: the first state in an SPI hash chain whose
    /// stored mark satisfies `(lookup & mask) == value`. An unmarked state
    /// satisfies every lookup, new states go to the chain head, and a hash
    /// resize can reverse the chain. When two states at one key match a
    /// lookup, no point query can prove which one the next lookup selects.
    /// This read does not depend on chain order. Apply the predicate with
    /// [`SaKeySnapshot::lookup_candidates`].
    ///
    /// The snapshot never reports a partial read as complete. Every state
    /// present at the key for the whole read is reported. A state added at
    /// the key or removed from it while the read runs may or may not be. So
    /// the snapshot equals the key's states only while no other writer
    /// changes them; excluding other writers at the key is a caller
    /// precondition, as for [`Self::remove_policy_exact`]. Expiry can still
    /// remove a state, which only shrinks the set.
    ///
    /// A finished Linux dump is not proof of a complete one: Linux ends a
    /// state dump with a successful `NLMSG_DONE` after silently dropping a
    /// state too large for a dump batch, together with every older state.
    /// The Linux backend therefore dumps every state in the namespace and
    /// accepts the dump only when it returned as many states as the kernel's
    /// SAD count read just before and just after it. An oversized state fails
    /// the read instead of hiding others. The count could be offset only if,
    /// within one read, the namespace both gained a state before the dump
    /// started and lost one the dump had already returned; with other writers
    /// excluded, only a kernel ACQUIRE state and a lifetime expiry together
    /// could do that.
    ///
    /// This is a read and changes no kernel state. Through the namespace
    /// actor a lost reply is `Unavailable`, as for other reads. Backends
    /// without a complete key read fail closed with
    /// [`XfrmError::UnsupportedFeature`].
    ///
    /// # Errors
    ///
    /// [`XfrmError::InvalidConfig`] for a zero SPI or a protocol other than
    /// AH, ESP, or IPComp. A Linux read whose dump the kernel flags as
    /// interrupted, or whose state count disagrees with the SAD count, is
    /// repeated a bounded number of times, then reported as
    /// [`XfrmError::StateIndeterminate`]. A state at the key that the SDK
    /// cannot represent, such as one with an unaddressable lookup mark, fails
    /// the read instead of being left out.
    async fn query_sa_key_snapshot(&self, _key: SaLookupKey) -> Result<SaKeySnapshot, XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "sa_key_snapshot",
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

    /// Remove one SA only when a fresh key snapshot proves that the
    /// deletion's own lookup can select nothing else.
    ///
    /// [`Self::remove_sa`] deletes whatever state the kernel lookup selects
    /// first, which need not be the caller's state when another state at the
    /// key also matches the lookup mark (for example an unmarked state, which
    /// matches every mark). This method first reads the key with
    /// [`Self::query_sa_key_snapshot`]. It sends the deletion only when
    /// exactly one state is a lookup candidate for the expected lookup mark
    /// and that state equals the expected identity on every field of
    /// [`SaRelocationIdentity`]. With a single candidate, chain order cannot
    /// change which state the deletion selects.
    ///
    /// Linux has no conditional SA deletion. Excluding other writers at the
    /// key across the read and the deletion is a caller precondition, as for
    /// [`Self::remove_policy_exact`]. The namespace actor runs both steps as
    /// one command, which excludes the SDK's own operations on that actor but
    /// not other processes.
    ///
    /// The default implementation composes [`Self::query_sa_key_snapshot`]
    /// and [`Self::remove_sa`], so a backend without key snapshots fails
    /// closed with [`XfrmError::UnsupportedFeature`] and sends no deletion.
    ///
    /// # Errors
    ///
    /// No deletion is sent for any of these refusals:
    ///
    /// - [`XfrmError::StateIndeterminate`] when two or more states are lookup
    ///   candidates;
    /// - [`XfrmError::StateMismatch`] when the only candidate differs from
    ///   the expected identity;
    /// - [`XfrmError::NotFound`] when no state is a candidate;
    /// - [`XfrmError::InvalidConfig`] for an invalid key or a zero interface
    ///   identifier;
    /// - any error of [`Self::query_sa_key_snapshot`], including
    ///   [`XfrmError::StateIndeterminate`] when the read cannot be proven
    ///   complete.
    ///
    /// After an authorized deletion is sent, errors are those of
    /// [`Self::remove_sa`].
    async fn remove_sa_exact(&self, request: ExactRemoveSaRequest) -> Result<(), XfrmError> {
        validate_exact_remove_sa_request(&request)?;
        let snapshot = self.query_sa_key_snapshot(request.key()).await?;
        authorize_exact_sa_removal(&snapshot, request.expected())?;
        self.remove_sa(request.removal()).await
    }

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
