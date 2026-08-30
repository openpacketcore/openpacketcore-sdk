//! Safe GTP-U dataplane backend trait.

use async_trait::async_trait;
use std::io;

use crate::model::{
    CreateGtpDeviceEndpointSetRequest, CreateGtpDeviceRequest,
    CurrentEbpfGraphRecoveryAuthorizedRequest, CurrentEbpfGraphRecoveryOutcome,
    CurrentEbpfGraphRecoveryReceipt, CurrentEbpfGraphRecoveryRefusal,
    CurrentEbpfGraphRecoveryRequest, CurrentEbpfGraphRecoveryTerminalTransferRequest,
    DrainedV2TeardownOutcome, DrainedV2TeardownRequest, GtpDevice, GtpPdpContext, GtpuCapability,
    GtpuIpFamilyCapabilities, GtpuProbe, GtpuSessionAttachmentSelector, GtpuSessionGroup,
    GtpuSessionGroupReadback, GtpuSessionGroupReconcileOutcome, GtpuSessionGroupReconcileRequest,
    GtpuSessionGroupRemovalOutcome, GtpuSessionGroupSelector,
    HistoricalEbpfGraphRecoveryInspectionOutcome, HistoricalEbpfGraphRecoveryInspectionRequest,
    HistoricalEbpfGraphRecoveryReceipt, HistoricalEbpfGraphRecoveryRequest,
    PdpContextInstallOutcome, PdpContextReadback, PdpContextReconciliationCapabilities,
    PdpContextRemovalOutcome, PdpContextSelector, PdpLiveWriterProof, PdpLiveWriterRemovalRequest,
    PdpRestartRecoveryRequest, RemovePdpContextRequest,
};
use crate::tft_classifier::{
    TftUplinkClassifier, TftUplinkClassifierReadback, TftUplinkClassifierReconcileOutcome,
    TftUplinkClassifierRemovalOutcome,
};
use crate::traffic_observation::{
    GtpuTrafficProof, GtpuTrafficProofAuthority, GtpuTrafficProofAuthorityLease,
    GtpuTrafficProofAuthorityStore, GtpuTrafficProofDispatchError, GtpuTrafficProofDispatchPort,
    GtpuTrafficProofDispatchReceipt, GtpuTrafficProofPoll, GtpuTrafficProofSession,
    GtpuTrafficProofValidation,
};
use crate::{GtpAddressFamily, GtpuError};

/// Exact no-effect evidence for recovery of a durable Installing intent.
///
/// This is intentionally distinct from grouped authorized readback. Ordinary
/// readback may report `Absent` only for an exact terminal-retired stamp;
/// returning this value requires the backend to hold the namespace binding
/// and inventory lock while it proves no authority, journal, index, or stamp
/// exists for the precise pending group.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSessionSelectorInstallRecovery {
    /// The exact pending group has no dataplane effect and no selector stamp.
    NoEffect,
}

/// Exact restart evidence for a durable Installing coordinate whose backend
/// supervisor has already been started.
///
/// The no-effect variant covers a process loss after the durable handoff but
/// before its first map write. The pending variant permits only the exact
/// journal and pending selector-operation stamp for the same opaque
/// coordinate; malformed, partial, or unstamped state is never resumable.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSessionSelectorInstallResume {
    /// No dataplane effect has appeared for the exact started coordinate.
    NoEffect,
    /// The exact pending-install journal and selector-operation stamp remain.
    ExactPendingInstall,
}

/// Exact restart evidence for a durable Retiring coordinate whose backend
/// supervisor has already been started.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSessionSelectorRetiringResume {
    /// The exact prior Active terminal remains intact before any remove write.
    NoEffect,
    /// The exact pending-remove journal and selector-operation stamp remain.
    ExactPendingRemove,
}

/// Exact no-effect evidence for recovery of a durable Retiring intent.
///
/// This does not mean the group is absent: a `Retiring(false)` row was
/// precommitted from one exact Active terminal. Returning this value proves
/// that predecessor's complete active graph and terminal stamp remain exact,
/// while no removal journal, pending-remove stamp, or terminal-retired stamp
/// has appeared. It is deliberately distinct from ordinary Active readback.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSessionSelectorRetiringRecovery {
    /// The exact previous Active terminal remains intact and no removal
    /// dataplane effect has started.
    ExactPreviousActive,
}

/// Backend that can mutate Linux GTP-U dataplane state.
///
/// Implementations are async because real adapters perform netlink I/O and
/// privilege checks. The mock and unsupported adapters keep operations cheap
/// and deterministic.
#[async_trait]
pub trait GtpuDataplaneBackend: Send + Sync + std::fmt::Debug {
    /// Report whether this backend can issue a trusted production GTP-U
    /// traffic-continuity proof.
    ///
    /// Reconcile, install, readback, and mock success do not issue a proof.
    /// Only an adapter that independently authenticates observations, reads
    /// back the exact current dataplane generation, and revalidates revocation
    /// authority may override this fail-closed default.
    fn gtpu_traffic_proof_capability(&self) -> GtpuCapability {
        GtpuCapability::Missing
    }

    /// Register the sole canonical product-authority store for one session group.
    ///
    /// A trusted adapter mints and retains an opaque store identity bound to
    /// its backend incarnation. This is deliberately not a public store
    /// constructor: independently recreating a store from a stale authority
    /// snapshot must not create a usable lease. Exact session-group removal
    /// retires the backend's store and revokes every outstanding attempt;
    /// orphaned store clones cannot register themselves again. Existing
    /// backends fail closed.
    async fn register_gtpu_traffic_proof_authority(
        &self,
        _authority: GtpuTrafficProofAuthority,
    ) -> Result<GtpuTrafficProofAuthorityStore, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_traffic_proof",
        })
    }

    /// Authenticate one store and affine lease as this backend's canonical authority.
    ///
    /// The fail-closed default cannot establish ownership. Trusted adapters
    /// bind this check to their private backend incarnation and canonical
    /// store registry; wrappers that delegate production proof operations
    /// must delegate this check as well. Returning `true` permits the inherited
    /// rebind default to terminally revoke the supplied authority, but it can
    /// never grant access to the crate-private publication transaction.
    fn owns_gtpu_traffic_proof_authority(
        &self,
        _store: &GtpuTrafficProofAuthorityStore,
        _authority: &GtpuTrafficProofAuthorityLease,
    ) -> bool {
        false
    }

    /// Atomically rebind one canonical proof authority to an exact changed desired group.
    ///
    /// The caller first reconciles the candidate group through the normal
    /// grouped-dataplane contract. Consuming the old store's affine lease then
    /// closes its authority gate immediately, before this method waits for any
    /// other old lease. A trusted adapter must clean every old proof artifact,
    /// verify the exact new active readback under its mutation boundary, and
    /// only then publish the new authority. Failure or cancellation leaves the
    /// old authority revoked and does not mint a new usable lease. The default
    /// implementation begins terminal revocation only when the backend first
    /// authenticates the store and lease as its own. An adapter that cannot
    /// establish ownership reports unsupported without mutating a potentially
    /// foreign authority.
    ///
    /// Completion is intentionally restricted to SDK-owned trusted adapters:
    /// it requires the crate-private transaction that binds the final exact
    /// readback to publication. External trait implementations remain useful
    /// for non-proof dataplane operations, but cannot mint a production proof.
    ///
    /// ```compile_fail
    /// use opc_gtpu_dataplane::{GtpuTrafficProofAuthorityLease, GtpuTrafficProofAuthorityStore};
    ///
    /// fn external_backend_cannot_publish_changed_desired_authority(
    ///     store: &GtpuTrafficProofAuthorityStore,
    ///     lease: GtpuTrafficProofAuthorityLease,
    /// ) {
    ///     let _ = store.begin_rebind(lease);
    /// }
    /// ```
    async fn rebind_gtpu_traffic_proof_authority(
        &self,
        store: &GtpuTrafficProofAuthorityStore,
        old_authority: GtpuTrafficProofAuthorityLease,
        _replacement: GtpuTrafficProofAuthority,
    ) -> Result<GtpuTrafficProofAuthorityStore, GtpuError> {
        if !self.owns_gtpu_traffic_proof_authority(store, &old_authority) {
            return Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_traffic_proof",
            });
        }
        // Preserve the old authority's terminal state even when an adapter has
        // not opted into rebind completion. Dropping this transaction releases
        // writer contention but deliberately never reopens its dispatch gate.
        let _rebind =
            store
                .begin_rebind(old_authority)
                .map_err(|_| GtpuError::StateIndeterminate {
                    operation: "gtpu_traffic_authority_rebind",
                })?;
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_traffic_proof",
        })
    }

    /// Start one trusted traffic-proof attempt for an exact current authority.
    ///
    /// The non-cloneable lease is consumed and retained by the adapter's
    /// complete begin operation, including any uncancellable blocking work, so
    /// reconciliation cannot replace the authority after the caller cancels
    /// this future. A trusted adapter obtains the dataplane generation from
    /// authoritative live readback before accepting observations. Existing
    /// backends fail closed.
    ///
    /// ```compile_fail
    /// use opc_gtpu_dataplane::{GtpuDataplaneBackend, GtpuTrafficProofAuthority};
    ///
    /// async fn legacy_request_cannot_begin(
    ///     backend: impl GtpuDataplaneBackend,
    ///     authority: GtpuTrafficProofAuthority,
    /// ) {
    ///     let _ = backend.begin_gtpu_traffic_proof(authority).await;
    /// }
    /// ```
    async fn begin_gtpu_traffic_proof(
        &self,
        _authority: GtpuTrafficProofAuthorityLease,
    ) -> Result<GtpuTrafficProofSession, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_traffic_proof",
        })
    }

    /// Construct and hand off one exact challenge for this backend's live attempt.
    ///
    /// After SDK route resolution and packet construction, the backend
    /// revalidates its exact incarnation, canonical authority store, attempt
    /// token, live dataplane readback, and observation source before any
    /// transport effect. Reconciliation, removal, restart, proof issuance, or
    /// close revokes the applicable monotonic handoff gate and cancels a
    /// cooperative pending transport. Source loss or external drift observed
    /// before handoff prevents the port call; if it races an irreversible
    /// transport send, subsequent poll/validation invalidates its proof state.
    /// Callers can select only an inner family and a fresh nonzero sample; no
    /// PAA, TEID, generation, authentication value, or packet bytes are
    /// accepted. Existing backends fail closed.
    ///
    /// ```compile_fail
    /// use opc_gtpu_dataplane::{
    ///     GtpAddressFamily, GtpuDataplaneBackend, GtpuTrafficProofDispatchPort,
    ///     GtpuTrafficProofSession,
    /// };
    ///
    /// async fn caller_cannot_supply_packet_identity(
    ///     backend: &impl GtpuDataplaneBackend,
    ///     session: &mut GtpuTrafficProofSession,
    ///     port: &(dyn GtpuTrafficProofDispatchPort + Send + Sync),
    /// ) {
    ///     let _ = backend
    ///         .dispatch_gtpu_traffic_proof_challenge(
    ///             session,
    ///             port,
    ///             GtpAddressFamily::Ipv4,
    ///             1,
    ///             0xfeed_beef_u32,
    ///             [10_u8, 0, 0, 1],
    ///             vec![0x30, 0xff],
    ///         )
    ///         .await;
    /// }
    /// ```
    async fn dispatch_gtpu_traffic_proof_challenge(
        &self,
        _session: &mut GtpuTrafficProofSession,
        _port: &(dyn GtpuTrafficProofDispatchPort + Send + Sync),
        _family: GtpAddressFamily,
        _sample_id: u32,
    ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError> {
        Err(GtpuTrafficProofDispatchError::TransportUnavailable)
    }

    /// Poll one trusted traffic-proof attempt.
    ///
    /// A `Proven` result is possible only from a trusted adapter override;
    /// successful reconcile, install, readback, or mock operations alone are
    /// insufficient evidence. The trusted backend acquires and retains a lease
    /// from its canonical registered store across all uncancellable work, so a
    /// canceled caller cannot lose an affine proof or race authority
    /// replacement. Existing backends fail closed.
    async fn poll_gtpu_traffic_proof(
        &self,
        _session: &mut GtpuTrafficProofSession,
    ) -> Result<GtpuTrafficProofPoll, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_traffic_proof",
        })
    }

    /// Revalidate a final trusted proof against the product's exact current
    /// authority-store lease before use.
    ///
    /// A trusted adapter checks exact generation, product authority, and
    /// revocation state here. Callers must serialize this check with the
    /// authority update and the protected use. The non-cloneable lease holds
    /// the store read guard for this entire critical section, so a retained
    /// authority snapshot cannot be used after reconciliation replaces the
    /// store. Existing backends fail closed.
    async fn validate_gtpu_traffic_proof(
        &self,
        _proof: &GtpuTrafficProof,
        _authority: &GtpuTrafficProofAuthorityLease,
    ) -> Result<GtpuTrafficProofValidation, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_traffic_proof",
        })
    }

    /// Close one trusted traffic-proof attempt and release its adapter-owned
    /// observation authority. Existing backends fail closed.
    async fn close_gtpu_traffic_proof(
        &self,
        _session: GtpuTrafficProofSession,
    ) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_traffic_proof",
        })
    }

    /// Report whether this backend can classify an unmarked shared-SA uplink
    /// packet by a canonical TFT before its existing bearer-mark lookup.
    ///
    /// This is deliberately separate from [`GtpuProbe::per_bearer_marking`]:
    /// the latter consumes an already assigned mark. Backends must report
    /// `Missing` until their live program and readback ABI can prove an exact
    /// classifier snapshot as one unit.
    fn tft_uplink_classification_capability(&self) -> GtpuCapability {
        GtpuCapability::Missing
    }

    /// Validate whether one complete TFT classifier can be represented by this
    /// backend without changing runtime state.
    ///
    /// Backends that do not explicitly implement this additive contract fail
    /// closed, even when they implement other TFT classifier operations.
    fn validate_tft_uplink_classifier(
        &self,
        _desired: &TftUplinkClassifier,
    ) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "tft_uplink_classification",
        })
    }

    /// Read the exact desired/observed TFT classifier for one attachment/PAA.
    ///
    /// `Present` proves one complete classifier under this backend's authority.
    /// Partial, mixed, stale, or otherwise unprovable state is `Indeterminate`,
    /// never `Absent`.
    async fn read_tft_uplink_classifier(
        &self,
        _link_ifindex: u32,
        _paa: std::net::IpAddr,
    ) -> Result<TftUplinkClassifierReadback, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "tft_uplink_classification",
        })
    }

    /// Reconcile one complete TFT classifier snapshot under this backend's
    /// authority.
    ///
    /// An absent classifier is installed and an exact classifier is idempotently
    /// already present. A different complete classifier already owned by this
    /// backend/authority is atomically replaced. A complete classifier owned by
    /// another authority is `Conflict`; partial, mixed, stale, or otherwise
    /// unprovable state is `Indeterminate`. Implementations must never publish a
    /// transient absent classifier, partial ownership, or wrong-bearer
    /// classifier during replacement.
    async fn reconcile_tft_uplink_classifier(
        &self,
        _desired: TftUplinkClassifier,
    ) -> Result<TftUplinkClassifierReconcileOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "tft_uplink_classification",
        })
    }

    /// Remove a TFT classifier only when the complete observed object equals
    /// `expected` under this backend's authority.
    ///
    /// Absence is idempotent, foreign complete ownership is `Conflict`, and
    /// partial, mixed, stale, or otherwise unprovable state is `Indeterminate`.
    async fn remove_tft_uplink_classifier_exact(
        &self,
        _expected: TftUplinkClassifier,
    ) -> Result<TftUplinkClassifierRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "tft_uplink_classification",
        })
    }
    /// Create a Linux `gtp` netdevice.
    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError>;

    /// Create or adopt a device with exact one- or two-family endpoint authority.
    ///
    /// This additive boundary never falls back to
    /// [`CreateGtpDeviceRequest::bind_address`]. Implementations persist the
    /// stable device ID independently of ifindex and must prove any
    /// replacement interface and existing pin namespace before rebinding.
    /// After restart, a grouped-session consumer adopts retained state by
    /// calling this method again with the exact stable device ID and endpoint
    /// set; the name-only [`Self::resolve_device`] boundary is not a substitute
    /// for that identity proof.
    async fn create_device_with_endpoints(
        &self,
        _request: CreateGtpDeviceEndpointSetRequest,
    ) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_device_endpoint_set",
        })
    }

    /// Resolve an existing legacy Linux `gtp` or single-context eBPF device by name.
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

    /// Recover one orphaned current-schema eBPF graph by its stable pin
    /// namespace.
    ///
    /// Implementations must fence the canonical persistent namespace
    /// independently of a mutable interface index, validate the replacement
    /// interface separately, prove that no live program references the graph,
    /// and preserve retry evidence across committed cleanup. Existing backend
    /// implementations inherit an explicit unsupported result.
    async fn recover_orphaned_current_ebpf_graph(
        &self,
        _request: CurrentEbpfGraphRecoveryRequest,
    ) -> Result<CurrentEbpfGraphRecoveryOutcome, GtpuError> {
        Ok(CurrentEbpfGraphRecoveryOutcome::Refused(
            CurrentEbpfGraphRecoveryRefusal::AuthorityRequired,
        ))
    }

    /// Recover one orphaned current-schema eBPF graph under a freshly live
    /// external node-fence authority.
    ///
    /// The request is affine: retry only the cloneable intent with a newly
    /// acquired authority/guard. Implementations must persist the complete
    /// binding in the proof record and invoke its asynchronous currentness
    /// guard around every irreversible proof, pin, and directory effect.
    async fn recover_orphaned_current_ebpf_graph_with_authority(
        &self,
        _request: CurrentEbpfGraphRecoveryAuthorizedRequest,
    ) -> Result<CurrentEbpfGraphRecoveryOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "current_ebpf_graph_recovery_authority",
        })
    }

    /// Recover one current graph and return a typed terminal receipt.
    ///
    /// Adapters that do not implement a durable current-terminal WAL inherit
    /// a deliberately nonterminal receipt: callers must never infer terminal
    /// absence from the legacy outcome alone.
    async fn recover_orphaned_current_ebpf_graph_with_authority_receipt(
        &self,
        request: CurrentEbpfGraphRecoveryAuthorizedRequest,
    ) -> Result<CurrentEbpfGraphRecoveryReceipt, GtpuError> {
        let authority = request.authority_binding();
        let outcome = self
            .recover_orphaned_current_ebpf_graph_with_authority(request)
            .await?;
        Ok(CurrentEbpfGraphRecoveryReceipt::nonterminal(
            authority, outcome,
        ))
    }

    /// Authenticate and transfer a retained current-terminal WAL to a new
    /// affine authority without deleting the WAL.
    ///
    /// The request carries an exact prior binding and receipt commitment from
    /// the external retired-state broker. Implementations must refuse a
    /// missing, malformed, graph-present, wrong-target, or mismatched WAL;
    /// neither a legacy `Removed` outcome nor a pristine observation can be
    /// converted into a transferable terminal.
    async fn transfer_current_ebpf_graph_terminal(
        &self,
        _request: CurrentEbpfGraphRecoveryTerminalTransferRequest,
    ) -> Result<CurrentEbpfGraphRecoveryReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "current_ebpf_graph_terminal_transfer",
        })
    }

    /// Recover one positively identified orphaned historical eBPF graph.
    ///
    /// This maintenance-only contract is separate from ordinary startup and
    /// current-schema recovery. Implementations must authenticate the named
    /// frozen graph and its legacy authority layout, acquire the legacy and
    /// current host-global authority domains in their fixed order, and retain
    /// durable recovery proof until both graph and legacy authority retirement
    /// are terminal. Existing implementations fail closed.
    async fn recover_orphaned_historical_ebpf_graph(
        &self,
        _request: HistoricalEbpfGraphRecoveryRequest,
    ) -> Result<HistoricalEbpfGraphRecoveryReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "historical_ebpf_graph_recovery",
        })
    }

    /// Inspect one exact detached shipped-25 graph without mutating bpffs,
    /// maps, hooks, roots, or authority leaves.
    ///
    /// The returned commitment is computed by the SDK from the locked live
    /// graph and is intended to be bound into a freshly acquired external
    /// provenance attestation before the affine recovery authority is built.
    /// A different graph, map-ID set, graph inode, replacement identity, or
    /// attachment state must not produce a reusable inspection result.
    async fn inspect_orphaned_historical_ebpf_graph(
        &self,
        _request: HistoricalEbpfGraphRecoveryInspectionRequest,
    ) -> Result<HistoricalEbpfGraphRecoveryInspectionOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "historical_ebpf_graph_inspection",
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

    /// Reconcile one durable PDP descriptor after its previous writer stops.
    ///
    /// Unlike [`Self::remove_pdp_context_exact`], this request carries the
    /// expected device identity, a non-reusable device incarnation, and the
    /// prior-writer stop attestation required to acquire restart authority.
    /// Implementations that cannot prove those values against authoritative
    /// live state under an exclusive writer boundary remain unsupported.
    async fn recover_pdp_context_exact(
        &self,
        _request: PdpRestartRecoveryRequest,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_restart_recovery_authority",
        })
    }

    /// Acquire an affine attestation for the current cooperating live writer.
    ///
    /// Calling this method explicitly attests that the caller is the current
    /// cooperating writer and owns the live mutation namespace; it never
    /// asserts that a previous writer stopped. Implementations bind that
    /// assertion to authority they can revalidate before mutation.
    ///
    /// The returned proof is bound to this backend's exact recovery root and
    /// the network namespace in which the attestation executes. Callers must
    /// move it into one [`PdpLiveWriterRemovalRequest`]; proofs cannot be
    /// cloned or constructed through the public API. Backends that cannot
    /// establish this authority return an explicit unsupported error.
    async fn acquire_pdp_live_writer_proof(&self) -> Result<PdpLiveWriterProof, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_live_writer_exact_removal",
        })
    }

    /// Remove only state that both selector axes prove exactly matches the
    /// request under the current cooperating live writer's authority.
    ///
    /// This is the same-process replacement companion of
    /// [`Self::recover_pdp_context_exact`]: the caller is the live writer
    /// and remains live, so the request carries a live-writer ownership proof
    /// instead of the prior-writer stop attestation, which would be false.
    /// The restart-recovery contract stays strict and distinct; neither
    /// authority substitutes for the other. Like
    /// [`Self::recover_pdp_context_exact`], the request binds the expected
    /// device identity, a non-reusable device incarnation, and the complete
    /// expected context, and implementations must serialize under the
    /// topology and per-device writer gates. Cancellation does not prove
    /// that a backend's blocking kernel operation stopped; the blocking
    /// mutation is owned to a terminal classified result even if the caller
    /// future is dropped.
    async fn remove_pdp_context_exact_live_writer(
        &self,
        _request: PdpLiveWriterRemovalRequest,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_live_writer_exact_removal",
        })
    }

    /// Read one complete grouped session by stable group and device identity.
    ///
    /// Implementations revalidate the full selector/index graph, group
    /// generation and phase, exact managed endpoint-set membership, stable pin
    /// identity, live attachment, schema/map identities, program hooks, and
    /// held exclusive lease on every call. Extra or missing indexes, duplicate
    /// family authority, and a group ID bound to another device are never
    /// collapsed into `Absent` or `Active`.
    ///
    /// This is a legacy diagnostic port only. A production backend MUST refuse
    /// it whenever the attachment has an immutable durable selector namespace
    /// binding. Bound lifecycle settlement uses
    /// [`Self::read_pdp_context_group_with_lease`]; structural readback cannot
    /// satisfy protected-ledger recovery.
    async fn read_pdp_context_group(
        &self,
        _selector: GtpuSessionGroupSelector,
    ) -> Result<GtpuSessionGroupReadback, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_readback",
        })
    }

    /// Read one exact grouped session through the durable selector authority.
    ///
    /// The affine admission is consumed so an adapter can verify the opaque
    /// stamp before inspecting kernel state without leaving replayable
    /// authority. This is deliberately a separate
    /// authority-bearing port: falling back to a structural semantic lookup
    /// after an in-memory admission check would let an unauthenticated
    /// readback settle durable recovery. Adapters that do not implement the
    /// exact binding-and-stamp proof must fail closed.
    async fn read_pdp_context_group_authorized(
        &self,
        _expected: &GtpuSessionGroup,
        _admission: crate::GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionGroupReadback, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_authorized_readback",
        })
    }

    /// Provision one previously absent selector namespace while the dataplane
    /// is stopped. Implementations must prove the full control-map inventory
    /// empty, create an immutable marker for this exact opaque binding, and
    /// read it back before returning. Existing adapters fail closed.
    async fn provision_selector_namespace(
        &self,
        _binding: crate::GtpuSessionSelectorBackendBinding,
    ) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_provision",
        })
    }

    /// Verify the exact immutable selector namespace binding before an
    /// authorized readback, recovery, or mutation. A binding created for one
    /// backend may not be rebound by passing another backend here.
    async fn ensure_selector_namespace_binding(
        &self,
        _binding: crate::GtpuSessionSelectorBackendBinding,
    ) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_binding",
        })
    }

    /// Consume a pending Installing no-effect inspection request under the
    /// exact namespace binding and the backend's inventory lock.
    ///
    /// This port exists solely to decide the documented no-effect recovery
    /// branch. It must not reinterpret a terminal-retired stamp as virgin or
    /// use a generationless semantic lookup. Backends that cannot prove the
    /// full negative fact fail closed. The request's currentness fence must be
    /// checked immediately before and after the exact negative inspection
    /// while the host lock is retained. Only then may the backend consume it
    /// into the returned coordinate-bound receipt.
    async fn inspect_installing_selector_no_effect(
        &self,
        _request: crate::GtpuSessionSelectorInstallingNoEffectRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_installing_no_effect_recovery",
        })
    }

    /// Inspect a started Installing coordinate before resuming its backend
    /// effect after process loss.
    ///
    /// This is not usable by a worker that lost the false-to-true handoff
    /// race. It may report only exact no-effect or the one exact pending
    /// install journal/stamp for the supplied admission; any partial,
    /// malformed, terminal, or differently bound state fails closed.
    async fn inspect_installing_selector_resume(
        &self,
        _expected: &GtpuSessionGroup,
        _admission: &crate::GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorInstallResume, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_installing_started_recovery",
        })
    }

    /// Consume a pending Retiring no-effect inspection request before its
    /// first backend removal effect.
    ///
    /// This port may return [`GtpuSessionSelectorRetiringRecovery::ExactPreviousActive`]
    /// only under the immutable namespace binding and exclusive inventory
    /// lock, after proving the exact prior Active terminal graph and stamp and
    /// the absence of any removal journal, pending-remove stamp, or terminal
    /// remove stamp. It is consumed only while durable state is
    /// `Retiring(false)`; an adapter that cannot prove that negative fact must
    /// fail closed rather than treating structural Active readback as enough.
    /// The request's currentness fence must be checked immediately before and
    /// after the complete negative proof under the host lock, then consumed
    /// into the returned coordinate-bound receipt.
    async fn inspect_retiring_selector_no_effect(
        &self,
        _request: crate::GtpuSessionSelectorRetiringNoEffectRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_retiring_no_effect_recovery",
        })
    }

    /// Inspect a started Retiring coordinate before resuming its backend
    /// removal after process loss. Implementations may classify only exact
    /// prior Active/no-effect or the one exact pending-remove journal/stamp.
    async fn inspect_retiring_selector_resume(
        &self,
        _expected: &GtpuSessionGroup,
        _admission: &crate::GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorRetiringResume, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_retiring_started_recovery",
        })
    }

    /// Prove backend quiescence for one SDK-issued retired selector source
    /// before the exact requested successor may reuse its selectors.
    ///
    /// The request carries the opaque terminal-retired coordinate. An
    /// implementation must verify its exact terminal-retired stamp and
    /// authoritative absence, then complete a trusted traffic drain or RCU
    /// barrier before consuming the request into its receipt. Backends without
    /// that proof remain unsupported; callers can never mint a receipt from a
    /// public evidence enum alone.
    async fn authorize_selector_reuse(
        &self,
        _request: crate::GtpuSessionSelectorReuseRequest,
    ) -> Result<crate::GtpuSessionSelectorReuseReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_reuse_quiescence",
        })
    }

    /// Qualify one complete retired selector source for RFC 017 reuse.
    ///
    /// This is deliberately distinct from [`Self::authorize_selector_reuse`]:
    /// it accepts no v1 reuse request, proof, or receipt. A qualified backend
    /// must bind its drain result to the opaque namespace, group, selector-set,
    /// desired-graph, generation, nonce, and epoch coordinate. Until the RFC
    /// 017 coordinator and adapter codec are complete, all implementations
    /// inherit this fail-closed result.
    ///
    /// ```compile_fail
    /// use opc_gtpu_dataplane::GtpuSessionSelectorRetiredDrainRequest;
    ///
    /// fn cannot_clone(
    ///     request: GtpuSessionSelectorRetiredDrainRequest,
    /// ) -> GtpuSessionSelectorRetiredDrainRequest {
    ///     request.clone()
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use std::fmt::Debug;
    /// use opc_gtpu_dataplane::GtpuSessionSelectorRetiredDrainRequest;
    ///
    /// fn cannot_format(request: GtpuSessionSelectorRetiredDrainRequest) {
    ///     let _ = format!("{request:?}");
    /// }
    /// ```
    async fn qualify_retired_selector_drain(
        &self,
        _request: crate::GtpuSessionSelectorRetiredDrainRequest,
    ) -> Result<crate::GtpuSessionSelectorRetiredDrainReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_retired_drain_qualification",
        })
    }

    /// Inspect one selector namespace for qualified complete mutable loss.
    ///
    /// A missing map, an empty readback, retained exact state, or traffic
    /// observation cannot satisfy this port. The returned opaque observation
    /// is for the matching SDK supervisor alone and cannot create restore
    /// authority through a public API. Existing implementations fail closed.
    async fn inspect_selector_namespace_loss(
        &self,
        _request: crate::GtpuSessionSelectorNamespaceLossInspectionRequest,
    ) -> Result<crate::GtpuSessionSelectorNamespaceLossObservation, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_loss_inspection",
        })
    }

    /// Restore one complete selector namespace after separately qualified loss.
    ///
    /// The opaque request is not a generic reconcile request and does not
    /// accept any v1 selector-reuse surface. A backend must reject altered,
    /// stale, cross-namespace, cross-generation, cross-nonce, or cross-epoch
    /// coordinates before mutation. Existing implementations fail closed.
    async fn restore_selector_namespace(
        &self,
        _request: crate::GtpuSessionSelectorNamespaceRestoreRequest,
    ) -> Result<crate::GtpuSessionSelectorNamespaceRestoreReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_restore",
        })
    }

    /// Read back one completed selector-namespace restore exactly.
    ///
    /// This remains a separate operation so a successful restore effect can
    /// never stand in for exact readback. Existing implementations fail closed.
    async fn readback_selector_namespace_restore(
        &self,
        _request: crate::GtpuSessionSelectorNamespaceRestoreReadbackRequest,
    ) -> Result<crate::GtpuSessionSelectorNamespaceRestoreReadbackReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_restore_readback",
        })
    }

    /// Acquire one opaque selector namespace binding lease. This is the
    /// backend-neutral authority port used by production selector workers;
    /// implementations must not fall back to a raw semantic lookup.
    async fn acquire_selector_namespace_lease(
        &self,
        _lease: crate::GtpuSessionSelectorBindingLease,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_binding_lease",
        })
    }

    /// Perform the stopped-installation selector provisioning effect through
    /// its opaque SDK request and return its consumed receipt.
    async fn provision_selector_namespace_authorized(
        &self,
        _request: crate::GtpuSessionSelectorProvisionRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_authorized_provision",
        })
    }

    /// Inspect the durable terminal-fence capsule before or after a selector
    /// namespace decommission precommit.
    ///
    /// An absence request may succeed only when no capsule exists. A recovery
    /// request may succeed only when the one retained capsule is byte-for-byte
    /// equal to its opaque expected payload. Existing adapters fail closed.
    async fn inspect_selector_namespace_decommission_fence(
        &self,
        _request: crate::GtpuSessionSelectorDecommissionInspectRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_decommission_fence_inspect",
        })
    }

    /// Create and exactly read back the durable terminal-fence capsule for a
    /// selector namespace decommission.
    ///
    /// The opaque request carries the authenticated precommitted coordinate.
    /// A binding-only marker is insufficient because a recovery worker must
    /// never invent the coordinate it converges.
    async fn create_selector_namespace_decommission_fence(
        &self,
        _request: crate::GtpuSessionSelectorDecommissionRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_decommission_fence_create",
        })
    }

    /// Compatibility alias for the original terminal-fence creation port.
    /// New implementations should implement
    /// [`Self::create_selector_namespace_decommission_fence`] together with
    /// the required inspect and exact-readback ports.
    async fn decommission_selector_namespace_authorized(
        &self,
        request: crate::GtpuSessionSelectorDecommissionRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        self.create_selector_namespace_decommission_fence(request)
            .await
    }

    /// Read back the one exact durable terminal-fence capsule after creation
    /// or recovery. A missing, extra, malformed, or different capsule must
    /// not be collapsed into success.
    async fn read_selector_namespace_decommission_fence(
        &self,
        _request: crate::GtpuSessionSelectorDecommissionReadbackRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_selector_namespace_decommission_fence_readback",
        })
    }

    /// Execute an opaque selector install/reconcile effect. The request owns
    /// the affine admission and must be retained by the backend until it has
    /// a terminal classified receipt.
    async fn reconcile_pdp_context_group_authorized(
        &self,
        _request: crate::GtpuSessionSelectorEffectRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_authorized_reconcile",
        })
    }

    /// Read an exact group through the opaque SDK authority request.
    async fn read_pdp_context_group_with_lease(
        &self,
        _request: crate::GtpuSessionSelectorReadbackRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_leased_readback",
        })
    }

    /// Execute an opaque selector removal effect for one exact Retiring
    /// coordinate. Backends must retain and consume the request rather than
    /// treating an absent marker as authorization for raw removal.
    async fn remove_pdp_context_group_with_lease(
        &self,
        _request: crate::GtpuSessionSelectorRemovalRequest,
    ) -> Result<crate::GtpuSessionSelectorBackendReceipt, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_leased_removal",
        })
    }

    /// Converge one one- or two-family session through a single authority
    /// cutover.
    ///
    /// The required state machine uses an ordinary non-per-CPU HASH authority
    /// updated only by whole-element replacement. It journals exact base and
    /// desired graphs plus an operation token before mutation. Fresh creation
    /// publishes Pending generation 1, stages exact `NOEXIST` candidates, then
    /// commits Active once. Updates retain Active N while staging N/N+1
    /// dual-candidate selector values, replace the authority Active N→Active
    /// N+1 once, read it back, then remove exact N candidates. tc must retain
    /// index first, authority second, generation-match, and never re-read the
    /// index. Packets already holding an old RCU value may complete.
    ///
    /// Exact Active is the only idempotent success. An exact Pending journal is
    /// resumed. Removing is finished and returns [`GtpuError::RetryRequired`]
    /// without resurrecting the request. Missing/mismatched journals, foreign
    /// components, generation overflow, endpoint-authority loss, or uncertain
    /// ACK state produce conflict/indeterminate with no guessed cleanup.
    /// Cross-group selector transfer is always forbidden while the source is
    /// live. Reuse after exact removal requires an opaque, source-bound SDK
    /// authorization carried by [`GtpuSessionGroupReconcileRequest`]; fresh
    /// ownership is admitted only by the protected selector-ledger
    /// coordinator.
    async fn reconcile_pdp_context_group(
        &self,
        _request: GtpuSessionGroupReconcileRequest,
    ) -> Result<GtpuSessionGroupReconcileOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_reconcile",
        })
    }

    /// Remove only one byte-exact grouped session.
    ///
    /// Removal journals the exact Active base, replaces authority with
    /// Removing first, deletes only byte-exact owned candidates, deletes the
    /// authority last, proves absence, and then clears the bounded in-flight
    /// journal. The caller permanently retires the group ID; the dataplane
    /// does not retain an unbounded tombstone. Pending/Removing adoption may
    /// mutate only absent or byte-exact owned components.
    ///
    /// This is a legacy compatibility port only. A production backend MUST
    /// refuse it whenever the attachment has an immutable durable selector
    /// namespace binding, even if the caller supplies a byte-exact group.
    /// Selector-owned removal requires the affine Retiring request accepted by
    /// [`Self::remove_pdp_context_group_with_lease`]; otherwise a caller could
    /// bypass durable retirement and permanently published-atom history.
    async fn remove_pdp_context_group_exact(
        &self,
        _expected: GtpuSessionGroup,
    ) -> Result<GtpuSessionGroupRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_exact_removal",
        })
    }

    /// Remove one exact grouped session by consuming the affine selector
    /// authority that created it. The default preserves third-party source
    /// compatibility while refusing an effect it cannot bind to a durable
    /// namespace ledger.
    async fn remove_pdp_context_group_authorized(
        &self,
        _expected: GtpuSessionGroup,
        _admission: crate::GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionGroupRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_authorized_removal",
        })
    }

    /// Report support for the additive PDP reconciliation contract.
    ///
    /// This is intentionally separate from packet-processing capabilities in
    /// [`GtpuProbe`].
    fn pdp_context_reconciliation_capabilities(&self) -> PdpContextReconciliationCapabilities {
        PdpContextReconciliationCapabilities::unsupported()
    }

    /// Report support for the authority-bearing durable restart-recovery
    /// request independently of generationless exact removal.
    fn pdp_restart_recovery_capability(&self) -> GtpuCapability {
        GtpuCapability::Missing
    }

    /// Report support for the authority-bearing live-writer exact-removal
    /// request independently of restart recovery and generationless exact
    /// removal.
    fn pdp_live_writer_removal_capability(&self) -> GtpuCapability {
        GtpuCapability::Missing
    }

    /// Inspect independently qualified grouped address-family capabilities for
    /// one exact attachment.
    ///
    /// The default is explicitly Missing/Unsupported. A backend may report
    /// Available only after exact named-map identity is repeated around schema,
    /// configuration, and live-hook inspection, with canonical endpoint
    /// configuration and exclusive lease ownership proven. Create and adoption
    /// separately preflight the pin namespace and both tc slots. Ordinary
    /// `probe()` must not mutate live state to manufacture this evidence.
    ///
    /// This query is async and attachment-scoped because qualification may
    /// require kernel inventory, and one backend can manage multiple
    /// attachments with different live evidence. A returned report is a
    /// point-in-time observation; every mutation revalidates authority.
    async fn gtpu_ip_family_capabilities(
        &self,
        _attachment: GtpuSessionAttachmentSelector,
    ) -> Result<GtpuIpFamilyCapabilities, GtpuError> {
        Ok(GtpuIpFamilyCapabilities::unsupported())
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
        assert_eq!(
            backend.pdp_restart_recovery_capability(),
            GtpuCapability::Missing
        );
        assert_eq!(
            backend.pdp_live_writer_removal_capability(),
            GtpuCapability::Missing
        );
        let group_id = crate::GtpuSessionGroupId::new([1; 16]).unwrap();
        let device_id = crate::GtpuSessionDeviceId::new([2; 16]).unwrap();
        let local_outer = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let endpoints = crate::GtpuLocalEndpointSet::new(local_outer, None).unwrap();
        let attachment = GtpuSessionAttachmentSelector::new(
            device_id,
            GtpDevice {
                name: String::from("gtp0"),
                ifindex: 7,
            },
            endpoints,
        )
        .unwrap();
        assert_eq!(
            backend
                .gtpu_ip_family_capabilities(attachment)
                .await
                .unwrap(),
            GtpuIpFamilyCapabilities::unsupported()
        );
        let device_request = CreateGtpDeviceEndpointSetRequest::new(
            CreateGtpDeviceRequest::new("gtp0"),
            device_id,
            endpoints,
        )
        .unwrap();
        assert!(matches!(
            backend.create_device_with_endpoints(device_request).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_device_endpoint_set"
            })
        ));
        let group_selector = GtpuSessionGroupSelector::new(group_id, device_id);
        assert!(matches!(
            backend.read_pdp_context_group(group_selector).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_session_group_readback"
            })
        ));
        let context = GtpPdpContext {
            local_teid: crate::Teid::new(1).unwrap(),
            peer_teid: crate::Teid::new(2).unwrap(),
            ms_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            peer_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
            link_ifindex: 7,
            downlink_source_port_policy: crate::GtpuSourcePortPolicy::Any,
            gtp_version: crate::GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        assert!(matches!(
            backend.acquire_pdp_live_writer_proof().await,
            Err(GtpuError::UnsupportedFeature {
                feature: "pdp_live_writer_exact_removal"
            })
        ));
        let entry = crate::GtpuSessionEntry::new(context, local_outer).unwrap();
        let group = GtpuSessionGroup::new(group_id, device_id, vec![entry]).unwrap();
        let namespace = crate::selector_namespace::TestGtpuSessionSelectorNamespaceAuthority::new(
            crate::InMemoryGtpuSessionSelectorNamespaceStore::default(),
            [0x53; 32],
            32,
        );
        let admission = namespace.claim(&group, None).unwrap();
        let reconcile_request =
            GtpuSessionGroupReconcileRequest::new(group.clone(), admission).unwrap();
        assert!(matches!(
            backend.reconcile_pdp_context_group(reconcile_request).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_session_group_reconcile"
            })
        ));
        assert!(matches!(
            backend.remove_pdp_context_group_exact(group).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_session_group_exact_removal"
            })
        ));
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
        let request = crate::CurrentEbpfGraphRecoveryRequest::new(
            "gtp0",
            crate::CurrentEbpfGraphWriterProof::previous_writer_stopped(),
        );
        assert!(matches!(
            backend.recover_orphaned_current_ebpf_graph(request).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "current_ebpf_graph_recovery"
            })
        ));

        let retired_drain_request =
            crate::selector_namespace_v2::GtpuSessionSelectorRetiredDrainRequest::for_test();
        assert!(matches!(
            backend
                .qualify_retired_selector_drain(retired_drain_request)
                .await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_selector_retired_drain_qualification"
            })
        ));
        let loss_inspection_request =
            crate::selector_namespace_v2::GtpuSessionSelectorNamespaceLossInspectionRequest::for_test();
        assert!(matches!(
            backend
                .inspect_selector_namespace_loss(loss_inspection_request)
                .await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_selector_namespace_loss_inspection"
            })
        ));
        let restore_request =
            crate::selector_namespace_v2::GtpuSessionSelectorNamespaceRestoreRequest::for_test();
        assert!(matches!(
            backend.restore_selector_namespace(restore_request).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_selector_namespace_restore"
            })
        ));
        let restore_readback_request =
            crate::selector_namespace_v2::GtpuSessionSelectorNamespaceRestoreReadbackRequest::for_test();
        assert!(matches!(
            backend
                .readback_selector_namespace_restore(restore_readback_request)
                .await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_selector_namespace_restore_readback"
            })
        ));
    }
}
