//! Necessary transferred-allocation controls for the proposed bounded profile.
//! Pure preparation evidence only: no public store, reservation, native WAL,
//! transport, allocator-wide peak or whole-operation qualification.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::types::{AuditOpType, CommitSource};
use opc_crypto::ConfigCapacityProfile;
use opc_types::{ConfigVersion, SchemaDigest, TenantId};

// Independently state the proposed entire-operation allowance. Any one
// transferred allocation exceeding it cannot fit, even before counting the
// remaining live buffers. This is not a per-field share or an inclusive
// positive boundary for the whole operation.
const OPERATION_BYTES: usize = 33_554_432;
const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

#[derive(Clone, Copy, Debug)]
enum InputField {
    Ciphertext,
    Digest,
    Principal,
    AuditVector,
    AuditPath,
    PreviousValue,
    NewValue,
}

fn key() -> crate::AuditKey {
    crate::AuditKey::new([0xD4; 32]).expect("synthetic audit key")
}

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xD5; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xD6; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    )
}

fn fixture() -> (CommitRecord, Vec<AuditRecord>, CapacityRecordBinding) {
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
    let schema_digest = SchemaDigest::from_bytes([0xD7; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-input-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xD8; 32]),
    );
    let plaintext = br#"{"capacity":"input"}"#;
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle, &aad, plaintext, [0xD9; 12],
    )
    .expect("genuine bounded encryption");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version,
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let audit = vec![AuditRecord {
        tx_id,
        sequence: 0,
        yang_path: "/fixture:capacity".to_owned(),
        op_type: AuditOpType::Update,
        previous_value: Some("synthetic-before".to_owned()),
        new_value: Some("synthetic-after".to_owned()),
        redaction_applied: false,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    }];
    let attested = crate::AttestedConfigCommit::try_new(
        record,
        audit,
        envelope.claim().expect("one-shot encryption evidence"),
    )
    .expect("exact authenticated record");
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE)
        .expect("genuine scoped size proof");
    let (record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    binding
        .verify(&record, identity(), &key(), PROFILE)
        .expect("exact record proof before changing only allocation capacity");
    (record, audit, binding)
}

fn reserve_bytes(bytes: &mut Vec<u8>) -> usize {
    let requested = OPERATION_BYTES.checked_add(1).expect("finite input bound");
    bytes
        .try_reserve_exact(requested - bytes.len())
        .expect("capacity fixture allocation");
    bytes.capacity()
}

fn reserve_string(value: &mut String) -> usize {
    let requested = OPERATION_BYTES.checked_add(1).expect("finite input bound");
    value
        .try_reserve_exact(requested - value.len())
        .expect("capacity fixture allocation");
    value.capacity()
}

fn inflate(field: InputField, record: &mut CommitRecord, audit: &mut Vec<AuditRecord>) -> usize {
    match field {
        InputField::Ciphertext => reserve_bytes(&mut record.encrypted_blob),
        InputField::Digest => reserve_bytes(&mut record.plaintext_digest),
        InputField::Principal => reserve_string(&mut record.principal),
        InputField::AuditVector => {
            let element_bytes = std::mem::size_of::<AuditRecord>();
            assert!(element_bytes > 0);
            let requested = OPERATION_BYTES / element_bytes + 1;
            audit
                .try_reserve_exact(requested - audit.len())
                .expect("capacity fixture allocation");
            audit
                .capacity()
                .checked_mul(element_bytes)
                .expect("actual allocation byte count")
        }
        InputField::AuditPath => reserve_string(&mut audit[0].yang_path),
        InputField::PreviousValue => {
            reserve_string(audit[0].previous_value.as_mut().expect("synthetic value"))
        }
        InputField::NewValue => {
            reserve_string(audit[0].new_value.as_mut().expect("synthetic value"))
        }
    }
}

fn assert_transferred_input_boundary(field: InputField) {
    // A compact, genuinely encrypted positive control must reach the complete
    // preparation and authenticated finalized chain before the negative case.
    let (record, audit, binding) = fixture();
    let prepared = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE)
        .expect("compact valid input is preparable");
    prepared.validate().expect("valid finalized structure");
    binding
        .verify(&prepared.record, identity(), &key(), PROFILE)
        .expect("preparation preserves exact encryption and size proof");
    crate::StoredConfig {
        record: prepared.record,
        audit: prepared.audit,
    }
    .verify_audit_chain(&key())
    .expect("compact finalized chain authenticates");

    let (mut record, mut audit, _binding) = fixture();
    let before = serde_json::to_vec(&(&record, &audit)).expect("small exact content oracle");
    assert!(before.len() < 4096, "size fences cannot mask this detector");
    let allocated = inflate(field, &mut record, &mut audit);
    assert!(
        allocated > OPERATION_BYTES,
        "check capacity, not requested length"
    );
    assert!(
        serde_json::to_vec(&(&record, &audit)).expect("unchanged content oracle") == before,
        "inflation changes no encrypted, digest, principal or audit bytes",
    );
    eprintln!(
        "CONFIG_CAPACITY_TRANSFERRED_INPUT field={field:?} allocated_capacity={allocated} proposed_operation_bound={OPERATION_BYTES}"
    );
    // Move the original allocations directly into the real helper. Do not
    // clone, encode/decode, shrink, redact or replace them before admission.
    let result = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE);
    assert!(
        result.is_err(),
        "CONFIG_CAPACITY_TRANSFERRED_INPUT: one transferred allocation exceeds the entire proposed operation bound",
    );
}

macro_rules! input_case {
    ($name:ident, $field:ident) => {
        #[test]
        fn $name() {
            assert_transferred_input_boundary(InputField::$field);
        }
    };
}

input_case!(config_capacity_957_input_ciphertext_capacity, Ciphertext);
input_case!(config_capacity_957_input_digest_capacity, Digest);
input_case!(config_capacity_957_input_principal_capacity, Principal);
input_case!(config_capacity_957_input_audit_vector_capacity, AuditVector);
input_case!(config_capacity_957_input_audit_path_capacity, AuditPath);
input_case!(
    config_capacity_957_input_previous_value_capacity,
    PreviousValue
);
input_case!(config_capacity_957_input_new_value_capacity, NewValue);

#[test]
fn config_capacity_957_input_combined_capacities() {
    // The compact positive must finish authentic preparation first. This is
    // not an at-limit success for the whole-operation memory contract.
    let (record, audit, binding) = fixture();
    let prepared = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE)
        .expect("compact valid input is preparable");
    prepared.validate().expect("valid finalized structure");
    binding
        .verify(&prepared.record, identity(), &key(), PROFILE)
        .expect("exact compact record proof");
    crate::StoredConfig {
        record: prepared.record,
        audit: prepared.audit,
    }
    .verify_audit_chain(&key())
    .expect("compact finalized chain authenticates");

    let (mut record, audit, _binding) = fixture();
    let before = serde_json::to_vec(&(&record, &audit)).expect("small exact content oracle");
    assert!(before.len() < 4096, "size fences cannot mask this detector");
    let requested = OPERATION_BYTES / 2 + 1;
    record
        .plaintext_digest
        .try_reserve_exact(requested - record.plaintext_digest.len())
        .expect("first capacity fixture allocation");
    record
        .principal
        .try_reserve_exact(requested - record.principal.len())
        .expect("second capacity fixture allocation");
    let digest_capacity = record.plaintext_digest.capacity();
    let principal_capacity = record.principal.capacity();
    assert!(digest_capacity <= OPERATION_BYTES);
    assert!(principal_capacity <= OPERATION_BYTES);
    let combined = digest_capacity
        .checked_add(principal_capacity)
        .expect("combined allocation byte count");
    assert!(
        combined > OPERATION_BYTES,
        "each field alone stays below the bound"
    );
    assert!(
        serde_json::to_vec(&(&record, &audit)).expect("unchanged content oracle") == before,
        "capacity changes preserve every serialized byte",
    );
    eprintln!(
        "CONFIG_CAPACITY_TRANSFERRED_INPUT combined_digest_capacity={digest_capacity} combined_principal_capacity={principal_capacity} summed_capacity={combined} proposed_operation_bound={OPERATION_BYTES}"
    );
    // Both original allocations coexist and transfer directly to the helper.
    let result = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE);
    assert!(
        result.is_err(),
        "CONFIG_CAPACITY_TRANSFERRED_INPUT: combined transferred allocations exceed the entire proposed operation bound",
    );
}
