//! Safe Linux GTP-U dataplane backend model for OpenPacketCore.
//!
//! This crate provides a backend trait for GTP-U dataplane device and
//! PDP-context lifecycle operations, a deterministic mock backend for tests,
//! an unsupported-platform backend, a Linux `gtp`-netdevice kernel adapter, an
//! eBPF tc datapath adapter for access-gateway (uplink-capable) roles, and
//! redaction-safe error types. It deliberately does not implement the
//! GTP-C/PFCP control plane, route steering, XFRM policy, namespace
//! management, or deployment policy; GTP-U packet handling itself lives in
//! the committed eBPF datapath object and `opc-gtpu-ebpf-common`.
//!
//! The additive reconciliation contract provides typed lookup by local TEID or
//! uplink identity, dual-selector classified install, and capability-gated
//! exact removal. Existing backend implementations inherit fail-closed
//! unsupported defaults. The eBPF adapter proves complete pinned-map state and
//! held mutation authority; the Linux adapter provides strict double-read
//! `GETPDP` inspection and, once a durable recovery root is bound, exact
//! restart-recovery authority: a cross-process per-device lease plus the
//! authoritative dual-axis readback that together compensate for the kernel's
//! missing compare-delete primitive. A distinct live-writer authority removes
//! one exact PDP context while the cooperating writer remains live for
//! same-process session replacement, without weakening the strict
//! prior-writer-stopped restart contract. Linux callers acquire an affine,
//! opaque `PdpLiveWriterProof` through
//! `GtpuDataplaneBackend::acquire_pdp_live_writer_proof`; the proof binds the
//! exact configured recovery root and current network-namespace identity and
//! is consumed by the removal request. It cannot be cloned or statically
//! constructed, and a wrong-root or wrong-namespace proof is rejected before
//! any netlink access. A separate identity-bearing,
//! mutation-free retained-device acquisition classifies a durable Linux
//! kernel-GTP device record after process loss — exact retained identity,
//! authoritative absence, conflicting replacement identity, structural
//! repair, or retryable authority unavailability — without reading,
//! installing, or deleting any PDP context.
//!
//! A separate maintenance-only drained-v2 teardown accepts an explicit typed
//! drain attestation, proves the complete frozen legacy program/map identity,
//! and retains durable identity evidence until partial hook/pin cleanup is
//! complete. Normal startup and adoption continue to reject endpoint-unbound
//! v2 state.
//!
//! Current-schema eBPF graphs orphaned after process and interface-namespace
//! loss have a separate typed recovery boundary. It leases the stable
//! canonical pin namespace independently of ifindex, validates the exact
//! current map and program graph, rejects live or foreign references, and
//! requires explicit prior-writer and populated-state drain attestations.
//! Durable proof-last cleanup is idempotently retryable; product code never
//! receives raw pin-deletion authority.
//!
//! Raw Linux netlink and socket syscalls stay in [`opc_linux_gtpu_sys`]; this
//! crate is safe Rust and never performs `unsafe` operations.

#![forbid(unsafe_code)]

pub mod backend;
pub mod ebpf;
pub mod error;
pub mod icmp;
pub mod linux;
pub mod mock;
pub mod model;
pub mod reassembly;
pub mod unsupported;

pub use backend::GtpuDataplaneBackend;
pub use ebpf::{
    probe_committed_classifier_load, ClassifierLoadBlocker, ClassifierLoadCapability,
    EbpfGtpuDatapathCounters, EbpfGtpuDatapathSnapshot, EbpfGtpuDataplaneBackend,
    EbpfGtpuDataplaneBackendConfig, EbpfManagedDeviceIdentity, EbpfManagedDeviceInventory,
    EbpfManagedDeviceInventoryCompleteness, DEFAULT_BPFFS_PIN_ROOT, DEFAULT_TC_PRIORITY,
    MAX_EBPF_MANAGED_DEVICE_IDENTITIES,
};
pub use error::{GtpuError, ProgramLoadRefusal};
pub use icmp::{build_icmpv4_packet_too_big, build_icmpv6_packet_too_big};
pub use linux::{LinuxGtpuDataplaneBackend, LinuxGtpuDataplaneBackendConfig};
pub use mock::{
    MockGtpuDataplaneBackend, MockOperation, MockPdpContextFault,
    MockPdpContextReconciliationOperation,
};
pub use model::{
    CreateGtpDeviceEndpointSetRequest, CreateGtpDeviceRequest, CurrentEbpfGraphDrainProof,
    CurrentEbpfGraphRecoveryOutcome, CurrentEbpfGraphRecoveryProgress,
    CurrentEbpfGraphRecoveryRefusal, CurrentEbpfGraphRecoveryRequest, CurrentEbpfGraphWriterProof,
    DrainedV2TeardownOutcome, DrainedV2TeardownProgress, DrainedV2TeardownRefusal,
    DrainedV2TeardownRequest, EbpfDatapathGeneration, EbpfHistoricalDatapathGeneration,
    GtpAddressFamily, GtpBearerMark, GtpDevice, GtpPdpContext, GtpRole, GtpVersion,
    GtpuBackendKind, GtpuCapability, GtpuDownlinkEndpoint, GtpuDownlinkFragmentContract,
    GtpuIpFamilyCapabilities, GtpuLocalEndpointSet, GtpuOuterFragmentPolicy, GtpuProbe,
    GtpuReassemblyBounds, GtpuSessionAttachmentSelector, GtpuSessionDeviceId, GtpuSessionEntry,
    GtpuSessionGroup, GtpuSessionGroupConflict, GtpuSessionGroupId,
    GtpuSessionGroupIndeterminateReason, GtpuSessionGroupReadback,
    GtpuSessionGroupReconcileOutcome, GtpuSessionGroupReconcileRequest,
    GtpuSessionGroupRemovalOutcome, GtpuSessionGroupSelector, GtpuSessionModelError,
    GtpuSessionPaa, GtpuSessionSelectorProvenance, GtpuSessionSelectorReuseEvidence,
    GtpuSessionSelectorReuseProof, GtpuSourcePortPolicy, GtpuSourcePortRange,
    GtpuUplinkChecksumOffloadContract, GtpuUplinkMtuPolicy, GtpuUplinkSourcePortPolicy,
    GtpuV2DrainProof, PdpContextConflict, PdpContextIndeterminateReason, PdpContextInstallOutcome,
    PdpContextLocalTeidSelector, PdpContextMismatchField, PdpContextReadback,
    PdpContextReconciliationCapabilities, PdpContextRemovalOutcome, PdpContextRepairReason,
    PdpContextSelector, PdpContextSelectorOccupancy, PdpContextUplinkIdentity,
    PdpContextUplinkSelector, PdpDeviceIncarnation, PdpLiveWriterProof,
    PdpLiveWriterRemovalRequest, PdpRestartRecoveryProof, PdpRestartRecoveryRequest,
    RemovePdpContextRequest, RetainedDeviceConflictReason, RetainedDeviceIdentityAcquisition,
    RetainedDeviceIdentityOutcome, RetainedDeviceIdentityRequest,
    RetainedDeviceIndeterminateReason, RetainedDeviceRepairReason,
    RetainedGraphCleanupClassification, RetainedGraphCleanupRefusal, RetainedGraphCleanupRequest,
    Teid, GTPU_PORT,
};
pub use opc_types::DscpCodepoint;
#[cfg(target_os = "linux")]
pub use reassembly::{
    linux_reassembly_bounds, read_linux_ipv4_reassembly_stats, GtpuKernelIpv4ReassemblyStats,
    GtpuKernelReassemblyStatsError, GtpuReassemblySocket,
};
pub use reassembly::{
    reassembly_commit_authorizes_graph, DownlinkOuterProvenance, GtpuReassemblyConsumer,
    GtpuReassemblyCounters, GtpuReassemblyDrop, GtpuReassemblyGraphIdentity, GtpuReassemblyOutcome,
    GtpuReassemblyPdr, GtpuReassemblySelector,
};
pub use unsupported::UnsupportedGtpuDataplaneBackend;

#[cfg(test)]
mod integration_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(0x1000_0001),
            peer_teid: teid(0x2000_0001),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        }
    }

    #[tokio::test]
    async fn mock_backend_lifecycle_round_trip() {
        let backend = MockGtpuDataplaneBackend::new();
        let dev = backend
            .create_device(CreateGtpDeviceRequest::new("gtp-test"))
            .await
            .unwrap();
        assert_eq!(dev.name, "gtp-test");
        assert_ne!(dev.ifindex, 0);

        let pdp = context();
        backend.install_pdp_context(pdp.clone()).await.unwrap();
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&pdp))
            .await
            .unwrap();
        backend.remove_device(&dev).await.unwrap();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::Mock);
        assert!(probe.platform_supported);
        assert!(!probe.kernel_reachable);
        assert!(!probe.net_admin_capable);
        assert_eq!(backend.operations().len(), 5);
    }

    #[tokio::test]
    async fn unsupported_backend_is_trait_object_safe() {
        let backend: Box<dyn GtpuDataplaneBackend> =
            Box::new(UnsupportedGtpuDataplaneBackend::new());
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe, GtpuProbe::unsupported());
    }
}
