//! Public-surface assertions for the Linux live-writer exact PDP removal
//! authority.
//!
//! These compile-time checks pin the exported live-writer types and method
//! shapes so accidental signature drift is caught at build time, mirroring
//! the restart-recovery surface test. The live-writer authority is a
//! distinct request family: its proof type cannot be constructed from, or
//! substituted for, the restart-recovery prior-writer stop attestation.

use std::path::PathBuf;

use opc_gtpu_dataplane::{
    GtpDevice, GtpPdpContext, GtpuCapability, GtpuDataplaneBackend, GtpuError,
    LinuxGtpuDataplaneBackend, PdpContextIndeterminateReason, PdpContextRemovalOutcome,
    PdpContextRepairReason, PdpDeviceIncarnation, PdpLiveWriterProof, PdpLiveWriterRemovalRequest,
};

fn assert_send_sync<T: Send + Sync>() {}

fn assert_live_writer_request_accessors(request: &PdpLiveWriterRemovalRequest) {
    let _: &GtpDevice = request.device();
    let _: PdpDeviceIncarnation = request.incarnation();
    let _: &GtpPdpContext = request.expected();
    let _: PdpLiveWriterProof = request.writer_proof();
}

// Compile-time proof that the live-writer entry point exists with the
// documented async shape and returns the classified removal outcome.
#[allow(dead_code)]
async fn live_writer_removal_returns_classified_outcome(
    backend: &LinuxGtpuDataplaneBackend,
    request: PdpLiveWriterRemovalRequest,
) -> Result<PdpContextRemovalOutcome, GtpuError> {
    backend.remove_pdp_context_exact_live_writer(request).await
}

#[allow(dead_code)]
async fn trait_object_live_writer_removal_carries_live_authority(
    backend: &dyn GtpuDataplaneBackend,
    request: PdpLiveWriterRemovalRequest,
) -> Result<PdpContextRemovalOutcome, GtpuError> {
    backend.remove_pdp_context_exact_live_writer(request).await
}

#[allow(dead_code)]
fn trait_object_live_writer_capability_is_queryable(
    backend: &dyn GtpuDataplaneBackend,
) -> GtpuCapability {
    backend.pdp_live_writer_removal_capability()
}

#[test]
fn linux_live_writer_removal_surface_is_public_and_typed() {
    assert_send_sync::<PdpLiveWriterRemovalRequest>();
    assert_send_sync::<PdpLiveWriterProof>();
    assert_send_sync::<PdpDeviceIncarnation>();
    assert_send_sync::<LinuxGtpuDataplaneBackend>();

    // Repair reasons and removal outcomes are typed, value-free, and copyable
    // through the live-writer boundary exactly as through restart recovery.
    let reason = PdpContextRepairReason::DeviceIdentityChanged;
    let copied = reason;
    assert_eq!(reason, copied);
    let _ = format!("{reason:?}");

    // Structural repair and retryable indeterminate remain distinct outcomes.
    let repair = PdpContextRemovalOutcome::RepairRequired(reason);
    let indeterminate = PdpContextRemovalOutcome::Indeterminate(
        PdpContextIndeterminateReason::AuthorityUnavailable,
    );
    assert_ne!(repair, indeterminate);
    let _ = format!("{repair:?} {indeterminate:?}");

    // The live-writer proof is a value-free capability distinct from the
    // restart-recovery prior-writer stop attestation.
    let proof = PdpLiveWriterProof::current_writer_owns_live_namespace();
    assert_eq!(
        proof,
        PdpLiveWriterProof::current_writer_owns_live_namespace()
    );
    let _ = format!("{proof:?}");

    // Construction-time recovery-root binding is public.
    let _bind: fn(
        LinuxGtpuDataplaneBackend,
        PathBuf,
    ) -> Result<LinuxGtpuDataplaneBackend, GtpuError> =
        |backend, root| backend.with_pdp_recovery_root(root);

    let _accessors: fn(&PdpLiveWriterRemovalRequest) = assert_live_writer_request_accessors;
}

#[test]
fn linux_live_writer_removal_request_is_redaction_safe() {
    let request = PdpLiveWriterRemovalRequest::new(
        GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 7,
        },
        PdpDeviceIncarnation::from_bytes([0xa5; 16]).unwrap(),
        GtpPdpContext {
            local_teid: opc_gtpu_dataplane::Teid::new(0x1122_3344).unwrap(),
            peer_teid: opc_gtpu_dataplane::Teid::new(0x5566_7788).unwrap(),
            ms_address: "10.23.0.2".parse().unwrap(),
            peer_address: "192.0.2.10".parse().unwrap(),
            link_ifindex: 7,
            downlink_source_port_policy: opc_gtpu_dataplane::GtpuSourcePortPolicy::Any,
            gtp_version: opc_gtpu_dataplane::GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy:
                opc_gtpu_dataplane::GtpuUplinkSourcePortPolicy::LegacyServicePort,
        },
        PdpLiveWriterProof::current_writer_owns_live_namespace(),
    );
    let rendered = format!("{request:?}");
    for secret in ["11223344", "55667788", "10.23.0.2", "192.0.2.10", "gtp0"] {
        assert!(
            !rendered.contains(secret),
            "live-writer removal request debug leaked {secret}: {rendered}"
        );
    }
}
