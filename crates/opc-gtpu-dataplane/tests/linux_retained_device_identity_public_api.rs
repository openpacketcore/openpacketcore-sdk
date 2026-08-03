//! Public-surface assertions for the retained Linux GTP device identity
//! acquisition boundary.
//!
//! These compile-time checks pin the exported acquisition types and method
//! shapes so accidental signature drift is caught at build time, mirroring
//! the Linux PDP restart-recovery surface test.

use std::path::PathBuf;

use opc_gtpu_dataplane::{
    GtpDevice, GtpuError, LinuxGtpuDataplaneBackend, PdpDeviceIncarnation, PdpRestartRecoveryProof,
    RetainedDeviceConflictReason, RetainedDeviceIdentityOutcome, RetainedDeviceIdentityRequest,
    RetainedDeviceIndeterminateReason, RetainedDeviceRepairReason,
};

fn assert_send_sync<T: Send + Sync>() {}

fn assert_identity_request_accessors(request: &RetainedDeviceIdentityRequest) {
    let _: &GtpDevice = request.device();
    let _: PdpDeviceIncarnation = request.incarnation();
    let _: PdpRestartRecoveryProof = request.writer_proof();
}

// Compile-time proof that the acquisition entry point exists with the
// documented async shape and returns the classified identity outcome.
#[allow(dead_code)]
async fn acquire_returns_classified_identity_outcome(
    backend: &LinuxGtpuDataplaneBackend,
    request: RetainedDeviceIdentityRequest,
) -> Result<RetainedDeviceIdentityOutcome, GtpuError> {
    backend.acquire_retained_device_identity(request).await
}

#[test]
fn linux_retained_device_identity_surface_is_public_and_typed() {
    assert_send_sync::<RetainedDeviceIdentityRequest>();
    assert_send_sync::<RetainedDeviceIdentityOutcome>();
    assert_send_sync::<RetainedDeviceConflictReason>();
    assert_send_sync::<RetainedDeviceIndeterminateReason>();
    assert_send_sync::<RetainedDeviceRepairReason>();
    assert_send_sync::<LinuxGtpuDataplaneBackend>();

    // Conflict, indeterminate, and repair reasons are typed, value-free, and
    // copyable.
    let conflict = RetainedDeviceConflictReason::ReplacementIdentity;
    let indeterminate = RetainedDeviceIndeterminateReason::AuthorityUnavailable;
    let repair = RetainedDeviceRepairReason::Unstamped;
    let (copied_conflict, copied_indeterminate, copied_repair) = (conflict, indeterminate, repair);
    assert_eq!(conflict, copied_conflict);
    assert_eq!(indeterminate, copied_indeterminate);
    assert_eq!(repair, copied_repair);
    let _ = format!("{conflict:?} {indeterminate:?} {repair:?}");

    // Structural and conflicting states remain distinct from retryable
    // authority unavailability and from the retained/absent identities.
    let retained = RetainedDeviceIdentityOutcome::Retained;
    let absent = RetainedDeviceIdentityOutcome::Absent;
    let conflict_outcome = RetainedDeviceIdentityOutcome::Conflict(conflict);
    let indeterminate_outcome = RetainedDeviceIdentityOutcome::Indeterminate(indeterminate);
    let repair_outcome = RetainedDeviceIdentityOutcome::RepairRequired(repair);
    for lhs in [
        &retained,
        &absent,
        &conflict_outcome,
        &indeterminate_outcome,
        &repair_outcome,
    ] {
        for rhs in [
            &retained,
            &absent,
            &conflict_outcome,
            &indeterminate_outcome,
            &repair_outcome,
        ] {
            if !std::ptr::eq(lhs, rhs) {
                assert_ne!(lhs, rhs);
            }
        }
    }
    let _ = format!(
        "{retained:?} {absent:?} {conflict_outcome:?} {indeterminate_outcome:?} {repair_outcome:?}"
    );

    // Construction-time recovery-root binding remains the authority gate.
    let _bind: fn(
        LinuxGtpuDataplaneBackend,
        PathBuf,
    ) -> Result<LinuxGtpuDataplaneBackend, GtpuError> =
        |backend, root| backend.with_pdp_recovery_root(root);

    let _accessors: fn(&RetainedDeviceIdentityRequest) = assert_identity_request_accessors;
}

#[test]
fn linux_retained_device_identity_request_is_redaction_safe() {
    let request = RetainedDeviceIdentityRequest::new(
        GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 7,
        },
        PdpDeviceIncarnation::from_bytes([0xa5; 16]).unwrap(),
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    let rendered = format!("{request:?}");
    for secret in ["gtp0", "a5a5", "[165, 165"] {
        assert!(
            !rendered.contains(secret),
            "identity request debug leaked {secret}: {rendered}"
        );
    }
}
