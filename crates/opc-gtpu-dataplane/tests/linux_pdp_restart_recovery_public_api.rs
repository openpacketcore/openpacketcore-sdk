//! Public-surface assertions for the Linux PDP restart-recovery authority.
//!
//! These compile-time checks pin the exported recovery types and method shapes
//! so accidental signature drift is caught at build time, mirroring the
//! managed-device inventory surface test.

use std::path::PathBuf;

use opc_gtpu_dataplane::{
    GtpDevice, GtpPdpContext, GtpuDataplaneBackend, GtpuError, LinuxGtpuDataplaneBackend,
    PdpContextIndeterminateReason, PdpContextRemovalOutcome, PdpContextRepairReason,
    PdpDeviceIncarnation, PdpRestartRecoveryProof, PdpRestartRecoveryRequest,
};

fn assert_send_sync<T: Send + Sync>() {}

fn assert_recovery_request_accessors(request: &PdpRestartRecoveryRequest) {
    let _: &GtpDevice = request.device();
    let _: PdpDeviceIncarnation = request.incarnation();
    let _: &GtpPdpContext = request.expected();
    let _: PdpRestartRecoveryProof = request.writer_proof();
}

// Compile-time proof that the recovery entry point exists with the documented
// async shape and returns the classified removal outcome.
#[allow(dead_code)]
async fn recover_returns_classified_removal_outcome(
    backend: &LinuxGtpuDataplaneBackend,
    request: PdpRestartRecoveryRequest,
) -> Result<PdpContextRemovalOutcome, GtpuError> {
    backend.recover_pdp_context_exact(request).await
}

#[allow(dead_code)]
async fn trait_object_recovery_carries_incarnation_authority(
    backend: &dyn GtpuDataplaneBackend,
    request: PdpRestartRecoveryRequest,
) -> Result<PdpContextRemovalOutcome, GtpuError> {
    backend.recover_pdp_context_exact(request).await
}

#[test]
fn linux_pdp_restart_recovery_surface_is_public_and_typed() {
    assert_send_sync::<PdpRestartRecoveryRequest>();
    assert_send_sync::<PdpRestartRecoveryProof>();
    assert_send_sync::<PdpDeviceIncarnation>();
    assert_send_sync::<LinuxGtpuDataplaneBackend>();

    // Repair reasons and removal outcomes are typed, value-free, and copyable.
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

    // Construction-time recovery-root binding is public.
    let _bind: fn(
        LinuxGtpuDataplaneBackend,
        PathBuf,
    ) -> Result<LinuxGtpuDataplaneBackend, GtpuError> =
        |backend, root| backend.with_pdp_recovery_root(root);

    let _accessors: fn(&PdpRestartRecoveryRequest) = assert_recovery_request_accessors;
}

#[test]
fn linux_pdp_restart_recovery_request_is_redaction_safe() {
    let request = PdpRestartRecoveryRequest::new(
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
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    let rendered = format!("{request:?}");
    for secret in ["11223344", "55667788", "10.23.0.2", "192.0.2.10", "gtp0"] {
        assert!(
            !rendered.contains(secret),
            "recovery request debug leaked {secret}: {rendered}"
        );
    }
}
