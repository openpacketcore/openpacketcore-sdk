//! Necessary live heap evidence at one actual preparation checkpoint.
//! Original input buffers, decoded AAD/key strings and the tenant projection
//! coexist here. Separate phase maxima are never added. Wrapper storage, map
//! nodes, parser scratch, allocator overhead and other phases remain omitted;
//! passing this detector does not establish a peak or open BoundedV1.

use std::cell::Cell;
use std::marker::PhantomData;

use super::PreparedConfigCommit;
use crate::{AttestedConfigCommit, AuditKey, AuditRecord, CommitRecord, CommitSource};
use opc_crypto::ConfigCapacityProfile;
use opc_key::{EnvelopeAad, EnvelopeMetadata, KeyId};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

#[path = "tests/config_capacity_957_ledger_observation.rs"]
pub(crate) mod ledger;

const OPERATION_BYTES: usize = 33_554_432;
const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

#[derive(Clone, Copy, Default)]
struct Sample {
    input_bytes: usize,
    decoded_bytes: usize,
    tenant_bytes: usize,
    total: usize,
}

#[derive(Clone, Copy)]
struct Observation {
    input_bytes: usize,
    aad_live: bool,
    decoded_bytes: usize,
    overlap_calls: usize,
    after_aad_calls: usize,
    peak: Sample,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

// Borrow real decoded owners across the tenant call. The strings are owned by
// these concrete types; their lengths are lower bounds on their capacities.
// The AAD tenant representation is deliberately omitted, as it may be inline.
pub(crate) fn decoded_owners<'a>(
    aad: &'a EnvelopeAad,
    envelope_key: &'a KeyId,
    bound_key: &'a KeyId,
) -> DecodedOwnersGuard<'a> {
    let active = OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return false;
        };
        assert!(
            !observation.aad_live,
            "one decoded AAD lifetime per validation"
        );
        let EnvelopeMetadata::Config(metadata) = aad.metadata() else {
            panic!("config preparation checkpoint requires config AAD");
        };
        observation.aad_live = true;
        observation.decoded_bytes = metadata.principal().len()
            + metadata.store_kind().len()
            + envelope_key.as_str().len()
            + bound_key.as_str().len();
        slot.set(Some(observation));
        true
    });
    DecodedOwnersGuard {
        active,
        owners: PhantomData,
    }
}

pub(crate) struct DecodedOwnersGuard<'a> {
    active: bool,
    owners: PhantomData<(&'a EnvelopeAad, &'a KeyId, &'a KeyId)>,
}

impl Drop for DecodedOwnersGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            OBSERVATION.with(|slot| {
                if let Some(mut observation) = slot.get() {
                    observation.aad_live = false;
                    observation.decoded_bytes = 0;
                    slot.set(Some(observation));
                }
            });
        }
    }
}

// Called by the existing tenant observer while its actual Value is borrowed.
// Stack arithmetic records one instant; this callback allocates no heap data.
pub(crate) fn observe_tenant(tenant_bytes: usize) {
    OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return;
        };
        if observation.aad_live {
            observation.overlap_calls += 1;
        } else {
            observation.after_aad_calls += 1;
        }
        let sample = Sample {
            input_bytes: observation.input_bytes,
            decoded_bytes: observation.decoded_bytes,
            tenant_bytes,
            total: observation
                .input_bytes
                .checked_add(observation.decoded_bytes)
                .and_then(|bytes| bytes.checked_add(tenant_bytes))
                .expect("finite simultaneous fixture lower bound"),
        };
        if sample.total > observation.peak.total {
            observation.peak = sample;
        }
        slot.set(Some(observation));
    });
}

struct ObservationGuard;

impl ObservationGuard {
    fn start(record: &CommitRecord) -> Self {
        let input_bytes = record.encrypted_blob.capacity()
            + record.principal.capacity()
            + record.plaintext_digest.capacity();
        OBSERVATION.with(|slot| {
            assert!(slot.get().is_none(), "one observation per test thread");
            slot.set(Some(Observation {
                input_bytes,
                aad_live: false,
                decoded_bytes: 0,
                overlap_calls: 0,
                after_aad_calls: 0,
                peak: Sample {
                    input_bytes,
                    total: input_bytes,
                    ..Sample::default()
                },
            }));
        });
        Self
    }

    fn finish(self) -> Observation {
        OBSERVATION.with(|slot| {
            let observation = slot.take().expect("active observation");
            assert!(!observation.aad_live, "decoded AAD dropped before return");
            observation
        })
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| slot.set(None));
    }
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    Unwrapped,
    Wrapped,
    EscapedDuplicates,
    NestedRaw,
}

fn fixture(shape: Shape, nonce_byte: u8) -> (CommitRecord, Vec<AuditRecord>) {
    let raw_principal = match shape {
        Shape::Unwrapped | Shape::Wrapped => {
            format!(r#"{{"tenant":"test","data":[{}0]}}"#, "0,".repeat(4095))
        }
        Shape::EscapedDuplicates => format!(
            r#"{{"tenant":"unused","ten\u0061nt":"test","{}":"{}"}}"#,
            "k\\u0061".repeat(300),
            "\\u0062".repeat(600),
        ),
        Shape::NestedRaw => {
            let mut raw = format!("[{}0]", "0,".repeat(127));
            for _ in 0..4 {
                raw = serde_json::to_string(&serde_json::json!({
                    "$serde_json::private::RawValue": raw,
                }))
                .expect("synthetic raw wrapper");
            }
            format!(r#"{{"tenant":"test","data":{raw}}}"#)
        }
    };
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let schema_digest = SchemaDigest::from_bytes([0xC3; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            &raw_principal,
            schema_digest,
            "running",
        )
        .expect("synthetic simultaneous-owner AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        KeyId::new("simultaneous-preparation-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xC4; 32]),
    );
    let plaintext = br#"{"phase":"simultaneous"}"#;
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
    let principal = if matches!(shape, Shape::Wrapped) {
        serde_json::to_string(&serde_json::json!({
            "principal": raw_principal,
            "recovery_required": false,
        }))
        .expect("synthetic principal wrapper")
    } else {
        raw_principal
    };
    assert!(principal.len() < 16_384);
    assert!(!principal.chars().any(char::is_control));
    assert_eq!(crate::types::extract_tenant(&principal), "test");
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
    .expect("exact authenticated record");
    let (record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    assert_eq!(audit.capacity(), 0);
    (record, audit)
}

fn simultaneous_case(shape: Shape, nonce_start: u8) {
    let key = AuditKey::new([0xC5; 32]).expect("synthetic audit key");
    let (record, audit) = fixture(shape, nonce_start);
    let guard = ObservationGuard::start(&record);
    let compact = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE)
        .expect("compact genuine record must be preparable");
    let observed = guard.finish();
    assert_eq!(observed.overlap_calls, 1, "actual simultaneous checkpoint");
    assert_eq!(
        observed.after_aad_calls, 1,
        "AAD guard must end at validation"
    );
    assert!(observed.peak.decoded_bytes > 0 && observed.peak.tenant_bytes > 0);
    assert!(observed.peak.total <= OPERATION_BYTES);
    compact.validate().expect("compact record structure");
    drop(compact);

    for (index, headroom) in [131_072usize, 32_768, 16_384, 4096, 1024]
        .into_iter()
        .enumerate()
    {
        let (mut record, audit) = fixture(shape, nonce_start + 1 + index as u8);
        let other = std::mem::size_of::<PreparedConfigCommit>()
            + record.plaintext_digest.capacity()
            + record.principal.capacity();
        let target = OPERATION_BYTES - headroom - other;
        let before = record.encrypted_blob.clone();
        record
            .encrypted_blob
            .try_reserve_exact(target - record.encrypted_blob.len())
            .expect("capacity-only fixture allocation");
        assert!(
            record.encrypted_blob == before,
            "unchanged authenticated bytes"
        );
        drop(before);
        assert_eq!(
            record.encrypted_blob.capacity() + other,
            OPERATION_BYTES - headroom
        );
        let guard = ObservationGuard::start(&record);
        let result = PreparedConfigCommit::prepare_for_profile(record, audit, &key, PROFILE);
        let observed = guard.finish();
        let accepted = result.is_ok();
        if let Err(ref error) = result {
            assert!(
                matches!(error.kind(), crate::PersistErrorKind::ConstraintViolation(message)
                    if message == "config preparation allocation exceeds working limit"),
                "valid capacity fixture may only be refused by capacity admission"
            );
        } else {
            assert_eq!(observed.overlap_calls, 1);
            assert_eq!(observed.after_aad_calls, 1);
        }
        eprintln!(
            "CONFIG_CAPACITY_SIMULTANEOUS shape={shape:?} headroom={headroom} accepted={accepted} overlap_calls={} after_aad_calls={} input_bytes={} decoded_bytes={} tenant_bytes={} live_lower_bound={} proposed_operation_bound={OPERATION_BYTES}",
            observed.overlap_calls, observed.after_aad_calls, observed.peak.input_bytes,
            observed.peak.decoded_bytes, observed.peak.tenant_bytes, observed.peak.total,
        );
        assert!(
            observed.peak.total <= OPERATION_BYTES,
            "CONFIG_CAPACITY_SIMULTANEOUS: coexisting preparation owners exceeded the entire proposed operation bound"
        );
    }
}

#[test]
fn config_capacity_957_simultaneous_unwrapped_preparation_owners() {
    simultaneous_case(Shape::Unwrapped, 0x61);
}

#[test]
fn config_capacity_957_simultaneous_wrapped_preparation_owners() {
    simultaneous_case(Shape::Wrapped, 0x71);
}

#[test]
fn config_capacity_957_simultaneous_escaped_duplicate_preparation_owners() {
    simultaneous_case(Shape::EscapedDuplicates, 0x81);
}

#[test]
fn config_capacity_957_simultaneous_nested_raw_preparation_owners() {
    simultaneous_case(Shape::NestedRaw, 0x91);
}
