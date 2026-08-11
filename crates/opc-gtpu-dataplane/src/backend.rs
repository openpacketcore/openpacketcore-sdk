//! Safe GTP-U dataplane backend trait.

use async_trait::async_trait;
use std::io;

use crate::model::{
    CreateGtpDeviceEndpointSetRequest, CreateGtpDeviceRequest, CurrentEbpfGraphRecoveryOutcome,
    CurrentEbpfGraphRecoveryRequest, DrainedV2TeardownOutcome, DrainedV2TeardownRequest, GtpDevice,
    GtpPdpContext, GtpuCapability, GtpuIpFamilyCapabilities, GtpuProbe,
    GtpuSessionAttachmentSelector, GtpuSessionGroup, GtpuSessionGroupReadback,
    GtpuSessionGroupReconcileOutcome, GtpuSessionGroupReconcileRequest,
    GtpuSessionGroupRemovalOutcome, GtpuSessionGroupSelector, PdpContextInstallOutcome,
    PdpContextReadback, PdpContextReconciliationCapabilities, PdpContextRemovalOutcome,
    PdpContextSelector, PdpLiveWriterProof, PdpLiveWriterRemovalRequest, PdpRestartRecoveryRequest,
    RemovePdpContextRequest,
};
use crate::tft_classifier::{
    TftUplinkClassifier, TftUplinkClassifierReadback, TftUplinkClassifierReconcileOutcome,
    TftUplinkClassifierRemovalOutcome,
};
use crate::GtpuError;

/// Backend that can mutate Linux GTP-U dataplane state.
///
/// Implementations are async because real adapters perform netlink I/O and
/// privilege checks. The mock and unsupported adapters keep operations cheap
/// and deterministic.
#[async_trait]
pub trait GtpuDataplaneBackend: Send + Sync + std::fmt::Debug {
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
        Err(GtpuError::UnsupportedFeature {
            feature: "current_ebpf_graph_recovery",
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
    async fn read_pdp_context_group(
        &self,
        _selector: GtpuSessionGroupSelector,
    ) -> Result<GtpuSessionGroupReadback, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_readback",
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
    /// live. Reuse after exact removal requires the source-bound drain/grace
    /// evidence carried by [`GtpuSessionGroupReconcileRequest`]; a fresh claim
    /// is checked against the caller's durable selector registry.
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
    async fn remove_pdp_context_group_exact(
        &self,
        _expected: GtpuSessionGroup,
    ) -> Result<GtpuSessionGroupRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "gtpu_session_group_exact_removal",
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
        let reconcile_request = GtpuSessionGroupReconcileRequest::new(
            group.clone(),
            crate::GtpuSessionSelectorProvenance::Fresh,
        )
        .unwrap();
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
    }
}
