//! Compare observer receipts with independently borrowed original encoding owners.

use super::*;
use crate::capacity_observation::{
    capture_current, scope, AllocationIdentity, BufferEvent, BufferKind, BufferObservation,
};
use opc_key::{ConfigAad, KeyPurpose, MemoryKeyProvider};
use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};
use std::str::FromStr;
use std::sync::Mutex;

#[derive(Default)]
struct Checks {
    encodings: usize,
    mismatch: bool,
    before_tag: Option<(usize, usize)>,
    after_tag: Option<(usize, usize)>,
    kdf_salt: bool,
    kdf_info: bool,
}

tokio::task_local! {
    static CHECKS: Arc<Mutex<Checks>>;
}

pub(super) fn inspect_encoding(envelope: &CryptoEnvelopeV1, out: &Vec<u8>) {
    let _ = CHECKS.try_with(|checks| {
        // These are the exact encode() owners, never a test copy, receipt cache,
        // logical-length estimate, or assumed allocator growth factor.
        let originals = [
            (BufferKind::BoundAad, &envelope.aad),
            (BufferKind::Ciphertext, &envelope.ciphertext_and_tag),
            (BufferKind::EnvelopeNonce, &envelope.nonce),
            (BufferKind::EncodedEnvelope, out),
        ];
        let matches = capture_current(|snapshot| {
            originals.into_iter().all(|(kind, original)| {
                snapshot.buffers.iter().flatten().any(|row| {
                    row.kind == kind
                        && row.identity == AllocationIdentity::of(original)
                        && row.length == original.len()
                        && row.capacity == original.capacity()
                })
            }) && !snapshot.overflowed
        })
        .unwrap_or(false);
        let mut checks = checks.lock().unwrap();
        checks.encodings += 1;
        checks.mismatch |= !matches;
    });
}

#[tokio::test]
async fn at_limit_encryption_temporaries_and_arc_aliases_are_original_allocations() {
    let checks = Arc::new(Mutex::new(Checks::default()));
    let callback_checks = Arc::clone(&checks);
    let observer = Arc::new(BufferObservation::new(move |event, snapshot| {
        let mut checks = callback_checks.lock().unwrap();
        for row in snapshot.buffers.iter().flatten() {
            checks.kdf_salt |= row.kind == BufferKind::KdfSalt;
            checks.kdf_info |= row.kind == BufferKind::KdfInfo;
            if row.kind == BufferKind::Ciphertext {
                if event == BufferEvent::Checkpoint("ciphertext-before-seal") {
                    checks.before_tag = Some((row.length, row.capacity));
                }
                if event == BufferEvent::Checkpoint("ciphertext-with-tag") {
                    checks.after_tag = Some((row.length, row.capacity));
                }
            }
        }
    }));
    let provider = MemoryKeyProvider::new();
    let tenant = TenantId::from_static("capacity-test");
    provider
        .insert_active_key(
            KeyId::new("capacity-test-key").unwrap(),
            KeyPurpose::Config,
            tenant.clone(),
            Zeroizing::new([0x43; 32]),
        )
        .unwrap();
    let aad = EnvelopeAad::config(
        tenant,
        1,
        ConfigAad::new(
            TxId::new(),
            None,
            Timestamp::from_str("2026-09-01T00:00:00Z").unwrap(),
            "synthetic-principal",
            SchemaDigest::from_bytes([0x5A; 32]),
            "running",
        )
        .unwrap(),
    );
    let pool = ConfigPreparationPool::bounded_v1();
    let mut plaintext = vec![b'q'; CONFIG_CAPACITY_V1_LOGICAL_BYTES];
    plaintext[0] = b'"';
    *plaintext.last_mut().unwrap() = b'"';
    let envelope = CHECKS
        .scope(
            Arc::clone(&checks),
            scope(
                Arc::clone(&observer),
                42,
                encrypt_reserved_bounded_config_envelope(
                    pool.try_reserve().unwrap(),
                    &provider,
                    &aad,
                    &plaintext,
                ),
            ),
        )
        .await
        .unwrap();
    let actual_address = AllocationIdentity::of(&envelope.encoded);
    let alias = envelope.clone();
    let claim = alias.claim().unwrap();
    let same_original = actual_address == AllocationIdentity::of(&alias.encoded)
        && actual_address == AllocationIdentity::of(&claim.encoded);
    let aliases = observer.capture(|snapshot| {
        snapshot.allocations() == 1
            && snapshot.buffers.iter().flatten().any(|row| {
                row.identity == actual_address
                    && row.aliases == 3
                    && row.capacity == envelope.encoded.len()
            })
    });
    let readback = decrypt_envelope(&provider, &aad, envelope.encoded())
        .await
        .unwrap();
    let plaintext_matches = readback.as_slice() == plaintext.as_slice();
    drop(readback);
    drop(envelope);
    drop(alias);
    let claim_retains_original = observer.capture(|snapshot| {
        snapshot.allocations() == 1
            && snapshot.buffers.iter().flatten().any(|row| {
                row.identity == AllocationIdentity::of(&claim.encoded) && row.aliases == 1
            })
    });
    let (_, reservation) = claim.into_capacity_parts();
    let drained = observer.capture(|snapshot| snapshot.allocations() == 0);
    drop(reservation);
    drop(plaintext);
    let reservations: Vec<_> = (0..8).map(|_| pool.try_reserve().unwrap()).collect();
    drop(reservations);
    let checks = checks.lock().unwrap();
    println!("CONFIG_CAPACITY_CRYPTO_LIFECYCLE drained={drained} original_aliases={same_original} plaintext_roundtrip={plaintext_matches}");
    assert!(drained && plaintext_matches && aliases && same_original && claim_retains_original);
    assert!(
        checks.encodings == 1 && !checks.mismatch && checks.kdf_salt && checks.kdf_info,
        "CONFIG_CAPACITY_CRYPTO_EXACT_ORIGINALS: compare every encode owner after actual cleanup"
    );
    let (before_length, before_capacity) = checks.before_tag.unwrap();
    let (after_length, after_capacity) = checks.after_tag.unwrap();
    assert_eq!(before_length, CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    assert_eq!(after_length, before_length + AEAD_TAG_LEN);
    assert!(before_capacity >= before_length && after_capacity >= after_length);
    assert!(
        after_capacity > before_capacity,
        "exercise actual ciphertext tag reallocation and spare capacity"
    );
}
