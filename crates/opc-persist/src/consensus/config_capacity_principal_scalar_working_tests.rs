//! Necessary live-allocation lower bound for rejected reserved scalar strings.
//! This does not measure parser scratch, allocator overhead or the whole request.

use super::{fixture, AuditKey, CryptoEnvelopeRef, ObservationGuard, PreparedConfigCommit};
use super::{OPERATION_BYTES, PROFILE};

fn rejected_scalar_wrapper(field: &str) -> String {
    let scalar = "x".repeat(8192);
    match field {
        "principal" => {
            format!(r#"{{"principal":"{scalar}","recovery_required":false,"unknown":null}}"#)
        }
        "recovery_required" => {
            format!(r#"{{"principal":"synthetic","recovery_required":"{scalar}"}}"#)
        }
        "replay_lookup_digest" | "rollback_label" => {
            format!(r#"{{"principal":"synthetic","recovery_required":false,"{field}":"{scalar}"}}"#,)
        }
        _ => panic!("unsupported synthetic field"),
    }
}

fn rejected_scalar_case(field: &str, nonce_byte: u8) {
    let key = AuditKey::new([0xA5; 32]).expect("synthetic audit key");
    let (record, audit) = fixture(nonce_byte);
    let compact = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE)
        .expect("compact genuine record is preparable");
    compact.validate().expect("compact record structure");
    drop(compact);

    let (mut record, audit) = fixture(nonce_byte + 1);
    record.principal = rejected_scalar_wrapper(field);
    assert!(record.principal.len() < 16_384);
    assert!(!record.principal.chars().any(char::is_control));
    let (header_bytes, aad_bytes) =
        CryptoEnvelopeRef::encoded_metadata_lengths(&record.encrypted_blob)
            .expect("unchanged genuine envelope framing");
    assert!(header_bytes + aad_bytes < 1024);
    let other_input_bytes = std::mem::size_of::<PreparedConfigCommit>()
        + record.plaintext_digest.capacity()
        + record.principal.capacity();
    let target = OPERATION_BYTES
        .checked_sub(1024)
        .and_then(|bytes| bytes.checked_sub(other_input_bytes))
        .expect("positive spare-capacity target");
    let before = record.encrypted_blob.clone();
    record
        .encrypted_blob
        .try_reserve_exact(target - record.encrypted_blob.len())
        .expect("capacity-only fixture allocation");
    assert!(
        record.encrypted_blob == before,
        "preserved authenticated bytes"
    );
    drop(before);
    let input_capacity = other_input_bytes + record.encrypted_blob.capacity();
    assert_eq!(input_capacity, OPERATION_BYTES - 1024);
    let input_pair_bytes = record.encrypted_blob.capacity() + record.principal.capacity();
    let guard = ObservationGuard::start(input_pair_bytes);
    let result = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE);
    let observed = guard.finish();
    assert!(
        matches!(result, Err(ref error)
        if matches!(error.kind(), crate::PersistErrorKind::ConstraintViolation(_))),
        "invalid reserved scalar must be rejected"
    );
    eprintln!(
        "CONFIG_CAPACITY_PRINCIPAL_SCALAR_WORKING input_capacity={input_capacity} input_pair_bytes={input_pair_bytes} value_bytes={} observed_calls={} live_lower_bound={} proposed_operation_bound={OPERATION_BYTES}",
        observed.value_bytes, observed.calls, observed.maximum_lower_bound,
    );
    assert!(
        observed.maximum_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_PRINCIPAL_SCALAR_WORKING: scalar metadata exceeded the entire proposed operation bound before rejection"
    );
}

#[test]
fn config_capacity_957_preparation_counts_rejected_principal_scalar() {
    rejected_scalar_case("principal", 0x41);
}

#[test]
fn config_capacity_957_preparation_counts_rejected_replay_scalar() {
    rejected_scalar_case("replay_lookup_digest", 0x43);
}

#[test]
fn config_capacity_957_preparation_counts_rejected_recovery_scalar() {
    rejected_scalar_case("recovery_required", 0x45);
}

#[test]
fn config_capacity_957_preparation_counts_rejected_rollback_scalar() {
    rejected_scalar_case("rollback_label", 0x47);
}
