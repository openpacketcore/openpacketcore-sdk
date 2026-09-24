//! Observe real rejected-principal storage while the original owners are live.
//! This lower bound omits parser scratch, map nodes, allocator overhead and
//! other phases. It does not qualify the whole operation or open BoundedV1.

use std::cell::Cell;

use super::{AttestedConfigCommit, AuditKey, AuditRecord, CommitRecord, CommitSource};
use crate::consensus::PreparedConfigCommit;
use opc_crypto::{ConfigCapacityProfile, CryptoEnvelopeRef};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

const OPERATION_BYTES: usize = 33_554_432;
const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

#[derive(Clone, Copy)]
struct Observation {
    input_pair_bytes: usize,
    value_bytes: usize,
    maximum_lower_bound: usize,
    calls: usize,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

fn value_heap_lower_bound(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::String(value) => value.capacity(),
        serde_json::Value::Array(values) => values.iter().fold(
            values
                .capacity()
                .checked_mul(std::mem::size_of::<serde_json::Value>())
                .expect("finite fixture array capacity"),
            |bytes, value| {
                bytes
                    .checked_add(value_heap_lower_bound(value))
                    .expect("finite fixture descendant capacity")
            },
        ),
        // Map nodes are not measured. Owned keys and descendants still form
        // a valid lower bound independent of the map's implementation.
        serde_json::Value::Object(values) => values.iter().fold(0usize, |bytes, (key, value)| {
            bytes
                .checked_add(key.capacity())
                .and_then(|bytes| bytes.checked_add(value_heap_lower_bound(value)))
                .expect("finite fixture map payload capacity")
        }),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => 0,
    }
}

// The production parser calls this after next_value returns and before its
// Value is classified or dropped. The observer itself makes no heap allocation.
pub(super) fn observe_reserved_value(value: &serde_json::Value) {
    OBSERVATION.with(|slot| {
        if let Some(mut observation) = slot.get() {
            let bytes = value_heap_lower_bound(value);
            observation.calls += 1;
            observation.value_bytes = observation.value_bytes.max(bytes);
            observation.maximum_lower_bound = observation.maximum_lower_bound.max(
                observation
                    .input_pair_bytes
                    .checked_add(bytes)
                    .expect("finite fixture live lower bound"),
            );
            slot.set(Some(observation));
        }
    });
}

struct ObservationGuard;

impl ObservationGuard {
    fn start(input_pair_bytes: usize) -> Self {
        OBSERVATION.with(|slot| {
            assert!(slot.get().is_none(), "one observation per test thread");
            slot.set(Some(Observation {
                input_pair_bytes,
                value_bytes: 0,
                maximum_lower_bound: input_pair_bytes,
                calls: 0,
            }));
        });
        Self
    }

    fn finish(self) -> Observation {
        OBSERVATION.with(|slot| slot.take().expect("active observation"))
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| slot.set(None));
    }
}

fn fixture(nonce_byte: u8) -> (CommitRecord, Vec<AuditRecord>) {
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let principal = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config".to_owned();
    let schema_digest = SchemaDigest::from_bytes([0xA3; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            &principal,
            schema_digest,
            "running",
        )
        .expect("synthetic config AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("principal-phase-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xA4; 32]),
    );
    let plaintext = br#"{"phase":"principal"}"#;
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        plaintext,
        [nonce_byte; 12],
    )
    .expect("genuine bounded encryption");
    let readback = opc_crypto::decrypt_envelope_with_handle(&handle, &aad, envelope.encoded())
        .expect("authenticated compact readback");
    assert!(readback.as_slice() == plaintext, "exact synthetic readback");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version,
        committed_at,
        principal,
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let attested = AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        envelope.claim().expect("one-shot encryption evidence"),
    )
    .expect("exact encrypted record and digest");
    let (record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    assert_eq!(audit.capacity(), 0);
    (record, audit)
}

fn rejected_array_wrapper(field: &str) -> String {
    let array = format!("[{}0]", "0,".repeat(4095));
    match field {
        "principal" => format!(r#"{{"principal":{array},"recovery_required":false}}"#),
        "recovery_required" => {
            format!(r#"{{"principal":"synthetic","recovery_required":{array}}}"#)
        }
        "replay_lookup_digest" | "rollback_label" => {
            format!(r#"{{"principal":"synthetic","recovery_required":false,"{field}":{array}}}"#,)
        }
        _ => panic!("unsupported synthetic field"),
    }
}

fn rejected_value_case(field: &str, nonce_byte: u8) {
    let key = AuditKey::new([0xA5; 32]).expect("synthetic audit key");
    let (record, audit) = fixture(nonce_byte);
    let compact = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE)
        .expect("compact genuine record is preparable");
    compact.validate().expect("compact record structure");
    drop(compact);

    let (mut record, audit) = fixture(nonce_byte + 1);
    record.principal = rejected_array_wrapper(field);
    assert!(record.principal.len() < 16_384);
    assert!(!record.principal.chars().any(char::is_control));
    let (header_bytes, aad_bytes) =
        CryptoEnvelopeRef::encoded_metadata_lengths(&record.encrypted_blob)
            .expect("unchanged genuine envelope framing");
    assert!(
        header_bytes + aad_bytes < 1024,
        "metadata floor leaves this fixture admissible"
    );
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
        "invalid reserved array must be rejected"
    );
    eprintln!(
        "CONFIG_CAPACITY_PRINCIPAL_WORKING input_capacity={input_capacity} input_pair_bytes={input_pair_bytes} value_bytes={} observed_calls={} live_lower_bound={} proposed_operation_bound={OPERATION_BYTES}",
        observed.value_bytes, observed.calls, observed.maximum_lower_bound,
    );
    assert!(observed.maximum_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_PRINCIPAL_WORKING: rejected metadata exceeded the entire proposed operation bound before rejection");
}

#[test]
fn config_capacity_957_preparation_counts_rejected_principal_array() {
    rejected_value_case("principal", 0x31);
}

#[test]
fn config_capacity_957_preparation_counts_rejected_replay_array() {
    rejected_value_case("replay_lookup_digest", 0x33);
}

#[test]
fn config_capacity_957_preparation_counts_rejected_recovery_array() {
    rejected_value_case("recovery_required", 0x35);
}

#[test]
fn config_capacity_957_preparation_counts_rejected_rollback_array() {
    rejected_value_case("rollback_label", 0x37);
}
