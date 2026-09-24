//! Measure tenant JSON storage during actual encrypted-record preparation.
//! The oracle omits map nodes, parser scratch, decoded AAD and wrapped-owner
//! storage. This is a necessary live lower bound, not a complete memory proof.

use std::cell::Cell;

use super::{
    value_heap_lower_bound, AttestedConfigCommit, AuditKey, AuditRecord, CommitRecord,
    CommitSource, ConfigCapacityProfile, ConfigVersion, CryptoEnvelopeRef, Digest,
    PreparedConfigCommit, SchemaDigest, Sha256, TenantId, Timestamp, TxId,
};

const OPERATION_BYTES: usize = 33_554_432;
const INPUT_HEADROOM_BYTES: usize = 32_768;
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

// Called inside the existing tenant Value closure before any field is copied
// or dropped. The original configuration record is still owned by preparation.
// Observation uses only stack arithmetic and the existing Value's capacities.
pub(crate) fn observe_value(value: &serde_json::Value) {
    OBSERVATION.with(|slot| {
        if let Some(mut observation) = slot.get() {
            let bytes = value_heap_lower_bound(value);
            observation.calls += 1;
            observation.value_bytes = observation.value_bytes.max(bytes);
            observation.maximum_lower_bound = observation.maximum_lower_bound.max(
                observation
                    .input_pair_bytes
                    .checked_add(bytes)
                    .expect("finite tenant fixture live lower bound"),
            );
            slot.set(Some(observation));
        }
    });
}

struct ObservationGuard;

impl ObservationGuard {
    fn start(input_pair_bytes: usize) -> Self {
        OBSERVATION.with(|slot| {
            assert!(
                slot.get().is_none(),
                "one tenant observation per test thread"
            );
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
        OBSERVATION.with(|slot| slot.take().expect("active tenant observation"))
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| slot.set(None));
    }
}

fn fixture(wrapped: bool, nonce_byte: u8) -> (CommitRecord, Vec<AuditRecord>) {
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let raw_principal = format!(r#"{{"tenant":"test","data":[{}0]}}"#, "0,".repeat(4095));
    let schema_digest = SchemaDigest::from_bytes([0xB3; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            raw_principal.as_str(),
            schema_digest,
            "running",
        )
        .expect("synthetic tenant AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("tenant-phase-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xB4; 32]),
    );
    let plaintext = br#"{"phase":"tenant"}"#;
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
    let principal = if wrapped {
        serde_json::to_string(&serde_json::json!({
            "principal": raw_principal,
            "recovery_required": false,
        }))
        .expect("synthetic wrapper")
    } else {
        raw_principal
    };
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
    assert_eq!(crate::types::extract_tenant(&record.principal), "test");
    (record, audit)
}

fn tenant_value_case(wrapped: bool, nonce_byte: u8) {
    let key = AuditKey::new([0xB5; 32]).expect("synthetic audit key");
    let (record, audit) = fixture(wrapped, nonce_byte);
    let compact = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE)
        .expect("compact genuine tenant record is preparable");
    compact.validate().expect("compact tenant record structure");
    drop(compact);

    let (mut record, audit) = fixture(wrapped, nonce_byte + 1);
    assert!(record.principal.len() < 16_384);
    assert!(!record.principal.chars().any(char::is_control));
    let (header_bytes, aad_bytes) =
        CryptoEnvelopeRef::encoded_metadata_lengths(&record.encrypted_blob)
            .expect("unchanged genuine envelope framing");
    assert!(
        header_bytes + aad_bytes + record.principal.len() < INPUT_HEADROOM_BYTES,
        "existing encoded-metadata and scalar floors leave this fixture admissible"
    );
    let other_input_bytes = std::mem::size_of::<PreparedConfigCommit>()
        + record.plaintext_digest.capacity()
        + record.principal.capacity();
    let target = OPERATION_BYTES
        .checked_sub(INPUT_HEADROOM_BYTES)
        .and_then(|bytes| bytes.checked_sub(other_input_bytes))
        .expect("positive tenant fixture spare-capacity target");
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
    assert_eq!(input_capacity, OPERATION_BYTES - INPUT_HEADROOM_BYTES);
    let input_pair_bytes = record.encrypted_blob.capacity() + record.principal.capacity();
    let guard = ObservationGuard::start(input_pair_bytes);
    let result = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE);
    let observed = guard.finish();
    let accepted = result.is_ok();
    if let Err(error) = result {
        assert!(
            matches!(error.kind(), crate::PersistErrorKind::ConstraintViolation(message)
                if message == "config preparation allocation exceeds working limit"),
            "valid tenant fixture may only be refused by capacity admission"
        );
    }
    eprintln!(
        "CONFIG_CAPACITY_TENANT_WORKING wrapped={wrapped} accepted={accepted} input_capacity={input_capacity} input_pair_bytes={input_pair_bytes} value_bytes={} observed_calls={} live_lower_bound={} proposed_operation_bound={OPERATION_BYTES}",
        observed.value_bytes, observed.calls, observed.maximum_lower_bound,
    );
    assert!(
        observed.maximum_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_TENANT_WORKING: tenant metadata exceeded the entire proposed operation bound during preparation"
    );
}

#[test]
fn config_capacity_957_preparation_counts_unwrapped_tenant_value() {
    tenant_value_case(false, 0x43);
}

#[test]
fn config_capacity_957_preparation_counts_wrapped_tenant_value() {
    tenant_value_case(true, 0x45);
}

#[path = "config_capacity_tenant_compatibility_tests.rs"]
mod compatibility;
