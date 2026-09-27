//! Canonical validation allocation and compatibility evidence for config capacity.
//! The observed heap capacities are a necessary phase bound, not total RSS,
//! parser scratch, all returned owners or a complete operation reservation.

use super::*;
use crate::{EncryptedPayload, KeyHandle, Zeroizing};
use std::cell::Cell;
use std::str::FromStr;

const PROPOSED_OPERATION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Observation {
    input_bytes: usize,
    parsed_bytes: usize,
    canonical_capacity: usize,
    maximum_lower_bound: usize,
    calls: usize,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

// Observe at the actual canonical-comparison phase, before parsed owners and
// the old canonical Vec can drop. The streamed path has no canonical Vec.
pub(super) fn observe_live_bytes(aad: &EnvelopeAad, key_id: &KeyId, canonical_capacity: usize) {
    OBSERVATION.with(|slot| {
        if let Some(mut observed) = slot.get() {
            let EnvelopeMetadata::Config(metadata) = aad.metadata() else {
                panic!("configuration fixture must reach config comparison");
            };
            let parsed_bytes = metadata.principal.capacity()
                + metadata.store_kind.capacity()
                + key_id.0.capacity();
            let lower_bound = observed
                .input_bytes
                .checked_add(parsed_bytes)
                .and_then(|bytes| bytes.checked_add(canonical_capacity))
                .expect("finite phase lower bound");
            observed.calls += 1;
            observed.parsed_bytes = observed.parsed_bytes.max(parsed_bytes);
            observed.canonical_capacity = observed.canonical_capacity.max(canonical_capacity);
            observed.maximum_lower_bound = observed.maximum_lower_bound.max(lower_bound);
            slot.set(Some(observed));
        }
    });
}

struct ObservationGuard;

impl ObservationGuard {
    fn start(input_bytes: usize) -> Self {
        OBSERVATION.with(|slot| {
            assert!(slot.get().is_none(), "one observation per thread");
            slot.set(Some(Observation {
                input_bytes,
                parsed_bytes: 0,
                canonical_capacity: 0,
                maximum_lower_bound: input_bytes,
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

fn config_aad(principal: &str, parent: bool) -> EnvelopeAad {
    EnvelopeAad::config(
        TenantId::from_static("test"),
        u64::MAX,
        ConfigAad::new(
            TxId::from_str("11111111-1111-4111-8111-111111111111").expect("synthetic transaction"),
            parent.then(|| {
                TxId::from_str("22222222-2222-4222-8222-222222222222").expect("synthetic parent")
            }),
            Timestamp::from_str("2026-09-22T00:00:00Z").expect("synthetic timestamp"),
            principal,
            SchemaDigest::from_bytes([0xA1; 32]),
            "synthetic-custom-store",
        )
        .expect("supported nonblank metadata"),
    )
}

fn encrypted_fixture() -> EncryptedPayload {
    let aad = config_aad(&"a".repeat(8192), false);
    let handle = KeyHandle::new(
        KeyId::new("canonical-capacity-test").expect("synthetic key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xA2; 32]),
    );
    let nonce = [0xA3; 12];
    let plaintext = br#"{"allocation":"canonical-aad"}"#;
    let encrypted = handle
        .encrypt_payload(&aad, plaintext, nonce)
        .expect("genuine encryption");
    assert_eq!(
        handle
            .decrypt_payload(&aad, &encrypted.aad, &encrypted.ciphertext_and_tag, nonce)
            .expect("genuine authenticated readback"),
        plaintext,
    );
    let (decoded, key_id) = decode_bound_aad(&encrypted.aad).expect("compact canonical positive");
    assert_eq!(decoded, aad);
    assert_eq!(&key_id, handle.key_id());
    encrypted
}

#[test]
fn config_capacity_957_canonical_comparison_counts_actual_live_buffers() {
    let mut encrypted = encrypted_fixture();
    assert!(encrypted.aad.len() < 65_536);
    let original_bytes = encrypted.aad.clone();
    // Give the metadata floor enough room for its exact encoded bytes. A
    // second canonical Vec and decoded Strings must not silently exceed it.
    let metadata_floor = encrypted.aad.len() + "canonical-capacity-test".len();
    let other_inputs =
        std::mem::size_of::<EncryptedPayload>() + encrypted.ciphertext_and_tag.capacity();
    let target = PROPOSED_OPERATION_BYTES
        .checked_sub(metadata_floor)
        .and_then(|bytes| bytes.checked_sub(other_inputs))
        .expect("positive spare-capacity target");
    encrypted
        .aad
        .try_reserve_exact(target - encrypted.aad.len())
        .expect("synthetic capacity allocation");
    assert_eq!(encrypted.aad.capacity(), target);
    assert_eq!(
        encrypted.aad, original_bytes,
        "encoded authenticated bytes unchanged"
    );
    drop(original_bytes);
    let input_bytes = encrypted.aad.capacity() + other_inputs;
    assert_eq!(input_bytes + metadata_floor, PROPOSED_OPERATION_BYTES);
    let guard = ObservationGuard::start(input_bytes);
    let decoded = decode_bound_aad(&encrypted.aad).expect("unchanged canonical input");
    let observed = guard.finish();
    std::hint::black_box((&encrypted, &decoded));
    assert_eq!(observed.calls, 1, "real canonical phase was observed");
    assert!(observed.parsed_bytes >= 8192);
    eprintln!(
        "CONFIG_CAPACITY_CANONICAL_WORKING input_bytes={} parsed_bytes={} canonical_capacity={} live_lower_bound={} proposed_operation_bound={PROPOSED_OPERATION_BYTES}",
        observed.input_bytes, observed.parsed_bytes, observed.canonical_capacity,
        observed.maximum_lower_bound,
    );
    assert!(
        observed.maximum_lower_bound <= PROPOSED_OPERATION_BYTES,
        "CONFIG_CAPACITY_CANONICAL_WORKING: live original buffers, parsed metadata and canonical output exceed the proposed operation bound",
    );
}

// Frozen decoder body from the original SDK source. Its complete canonical
// Vec remains the compatibility oracle; no new streaming implementation is
// called here. Keep this body identical while correcting the production path.
fn original_decode_bound_aad(bound_aad: &[u8]) -> Result<(EnvelopeAad, KeyId), KeyError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BoundEnvelopeAadOwned {
        tenant: TenantId,
        purpose: KeyPurpose,
        version: u64,
        key_id: KeyId,
        metadata: EnvelopeMetadata,
    }

    let parsed: BoundEnvelopeAadOwned = serde_json::from_slice(bound_aad)
        .map_err(|_| KeyError::invalid_metadata("aad", "failed to deserialize"))?;
    let aad = EnvelopeAad {
        tenant: parsed.tenant,
        purpose: parsed.purpose,
        version: parsed.version,
        metadata: parsed.metadata,
    };
    aad.validate()?;
    let canonical = serialize_bound_aad(&aad, &parsed.key_id)?;
    if canonical.as_slice() != bound_aad {
        return Err(KeyError::invalid_metadata("aad", "must be canonical"));
    }
    Ok((aad, parsed.key_id))
}

fn all_domains() -> Vec<EnvelopeAad> {
    vec![
        config_aad("synthetic-\"quoted\"-\\-\n-\u{3b1}", false),
        config_aad("synthetic-principal", true),
        EnvelopeAad::session(
            TenantId::from_static("test"),
            u64::MAX,
            SessionAad::new(
                "synthetic-nf",
                "synthetic-digest",
                "\u{3b1}-state",
                u64::MAX,
                u64::MAX,
                "\\\"namespace",
            )
            .expect("session fixture"),
        ),
        EnvelopeAad::consumer_checkpoint(
            TenantId::from_static("test"),
            u64::MAX,
            ConsumerCheckpointAad::new([0xA4; 32], [0xA5; 32]).expect("checkpoint fixture"),
        ),
        EnvelopeAad::shadow_security(
            TenantId::from_static("test"),
            u64::MAX,
            ShadowSecurityAad::new(u64::MAX),
        ),
    ]
}

#[test]
fn config_capacity_957_canonical_decoder_preserves_all_domain_results() {
    for aad in all_domains() {
        for id in ["k".to_owned(), "k".repeat(512)] {
            let key_id = KeyId::new(id).expect("inclusive key-ID boundary");
            let canonical = serialize_bound_aad(&aad, &key_id).expect("canonical fixture");
            assert_eq!(decode_bound_aad(&canonical), Ok((aad.clone(), key_id)));
            assert_eq!(
                decode_bound_aad(&canonical),
                original_decode_bound_aad(&canonical)
            );
        }
    }
}

#[test]
fn config_capacity_957_canonical_decoder_preserves_exact_rejections() {
    for aad in all_domains() {
        let key_id = KeyId::new("canonical-key").expect("synthetic key ID");
        let canonical = serialize_bound_aad(&aad, &key_id).expect("canonical fixture");
        let text = String::from_utf8(canonical.clone()).expect("UTF-8 fixture");
        let value: serde_json::Value = serde_json::from_slice(&canonical).expect("JSON fixture");
        let mut cases = vec![
            format!("{text}\n").into_bytes(),
            format!(" {text}").into_bytes(),
            format!("{text}{{}}").into_bytes(),
            canonical[..canonical.len() - 1].to_vec(),
            serde_json::to_vec_pretty(&value).expect("reformatted fixture"),
            text.replacen(
                "\"tenant\":\"test\"",
                "\"tenant\":\"test\",\"tenant\":\"test\"",
                1,
            )
            .into_bytes(),
            text.replacen(
                "\"tenant\":\"test\"",
                "\"tenant\":\"test\",\"unknown\":null",
                1,
            )
            .into_bytes(),
            text.replacen("\"key_id\":\"canonical-key\"", "\"key_id\":\"\"", 1)
                .into_bytes(),
            text.replacen(
                "\"key_id\":\"canonical-key\"",
                &format!("\"key_id\":\"{}\"", "k".repeat(513)),
                1,
            )
            .into_bytes(),
            text.replacen("\"key_id\":\"canonical-key\"", "\"key_id\":17", 1)
                .into_bytes(),
            text.replacen("\"tenant\":\"test\"", "\"tenant\":\"\\u0074est\"", 1)
                .into_bytes(),
        ];
        cases.push(
            format!(
                "{{\"purpose\":{},\"tenant\":{},\"version\":{},\"key_id\":{},\"metadata\":{}}}",
                value["purpose"],
                value["tenant"],
                value["version"],
                value["key_id"],
                value["metadata"],
            )
            .into_bytes(),
        );
        let mut wrong_purpose = value.clone();
        wrong_purpose["purpose"] = "audit".into();
        cases.push(serde_json::to_vec(&wrong_purpose).expect("wrong-purpose fixture"));
        let mut unknown_metadata = value.clone();
        unknown_metadata["metadata"]["unknown"] = true.into();
        cases.push(serde_json::to_vec(&unknown_metadata).expect("unknown-metadata fixture"));
        for input in cases {
            let original = original_decode_bound_aad(&input);
            assert!(original.is_err(), "negative fixture must reject originally");
            assert_eq!(
                decode_bound_aad(&input),
                original,
                "preserve exact error classification"
            );
        }
    }
}
