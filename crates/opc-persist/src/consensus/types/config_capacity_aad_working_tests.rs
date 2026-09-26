//! Necessary live-allocation evidence during real AAD validation.
//! This private preparation fixture neither opens BoundedV1 nor measures RSS,
//! allocator overhead, all temporary allocations or aggregate store resources.

use std::cell::Cell;

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::types::CommitSource;
use opc_crypto::ConfigCapacityProfile;
use opc_types::{ConfigVersion, SchemaDigest, TenantId};

const OPERATION_BYTES: usize = 33_554_432;
const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

#[derive(Clone, Copy)]
struct Observation {
    input_pair_bytes: usize,
    decoded_principal_bytes: usize,
    maximum_lower_bound: usize,
    calls: usize,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

// Called only after the real decoder returns owned ConfigAad metadata, while
// the borrowed input record and decoded principal are simultaneously live.
// ConfigAad owns a String, so its byte length is a lower bound on its heap
// capacity. No allocation is introduced by this observer.
pub(super) fn observe_decoded_principal(principal_bytes: usize) {
    OBSERVATION.with(|slot| {
        if let Some(mut value) = slot.get() {
            value.calls += 1;
            value.decoded_principal_bytes = value.decoded_principal_bytes.max(principal_bytes);
            value.maximum_lower_bound = value.maximum_lower_bound.max(
                value
                    .input_pair_bytes
                    .checked_add(principal_bytes)
                    .expect("finite fixture lower bound"),
            );
            slot.set(Some(value));
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
                decoded_principal_bytes: 0,
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

fn key() -> crate::AuditKey {
    crate::AuditKey::new([0xE1; 32]).expect("synthetic audit key")
}

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xE2; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xE3; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    )
}

fn fixture(nonce_byte: u8) -> (CommitRecord, Vec<AuditRecord>, CapacityRecordBinding) {
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let principal = format!(
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/{}",
        "a".repeat(8192)
    );
    assert!(principal.len() < 16_384);
    let schema_digest = SchemaDigest::from_bytes([0xE4; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            principal.as_str(),
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-aad-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xE5; 32]),
    );
    let plaintext = br#"{"allocation":"aad"}"#;
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        plaintext,
        [nonce_byte; 12],
    )
    .expect("genuine bounded encryption");
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
    let attested = crate::AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        envelope.claim().expect("one-shot encryption evidence"),
    )
    .expect("exact authenticated record");
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE)
        .expect("genuine scoped capacity proof");
    let (record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    assert_eq!(audit.capacity(), 0);
    (record, audit, binding)
}

#[test]
fn config_capacity_957_preparation_counts_live_decoded_aad_principal() {
    let (record, audit, binding) = fixture(0xE6);
    let compact = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE)
        .expect("compact genuine record is preparable");
    compact.validate().expect("compact record structure");
    binding
        .verify(&compact.record, identity(), &key(), PROFILE)
        .expect("compact scoped encryption proof");
    drop(compact);

    let (mut record, audit, binding) = fixture(0xE7);
    let before = serde_json::to_vec(&(&record, &audit)).expect("exact content oracle");
    assert!(
        before.len() < 128 * 1024,
        "encoded size fences cannot mask this detector"
    );
    // Setup accounts all original owners. The oracle below uses only three
    // coexisting heap allocations, not the production aggregate formula.
    let other_input_bytes = std::mem::size_of::<PreparedConfigCommit>()
        .checked_add(record.plaintext_digest.capacity())
        .and_then(|bytes| bytes.checked_add(record.principal.capacity()))
        .expect("finite fixture input accounting");
    let target = OPERATION_BYTES
        .checked_sub(1024)
        .and_then(|bytes| bytes.checked_sub(other_input_bytes))
        .expect("positive envelope spare-capacity target");
    record
        .encrypted_blob
        .try_reserve_exact(target - record.encrypted_blob.len())
        .expect("capacity fixture allocation");
    let input_capacity = record.encrypted_blob.capacity() + other_input_bytes;
    assert_eq!(input_capacity, OPERATION_BYTES - 1024);
    assert!(
        serde_json::to_vec(&(&record, &audit)).expect("unchanged content oracle") == before,
        "spare capacity changes no encrypted or metadata bytes",
    );
    drop(before);
    binding
        .verify(&record, identity(), &key(), PROFILE)
        .expect("capacity-only change preserves authentic record proof");
    let input_pair_bytes = record.encrypted_blob.capacity() + record.principal.capacity();
    let guard = ObservationGuard::start(input_pair_bytes);
    // Move the original owners directly. Rejection is valid only if it occurs
    // before this necessary live-allocation lower bound is exceeded.
    let result = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE);
    let observed = guard.finish();
    if result.is_ok() {
        assert_eq!(
            observed.calls, 1,
            "actual successful validation must be observed"
        );
        assert!(observed.decoded_principal_bytes >= 8192);
    }
    eprintln!(
        "CONFIG_CAPACITY_AAD_WORKING input_capacity={input_capacity} input_pair_bytes={input_pair_bytes} decoded_principal_bytes={} observed_calls={} live_lower_bound={} proposed_operation_bound={OPERATION_BYTES}",
        observed.decoded_principal_bytes, observed.calls, observed.maximum_lower_bound,
    );
    assert!(
        observed.maximum_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_AAD_WORKING: live original buffers and decoded principal exceed the entire proposed operation bound",
    );
}
