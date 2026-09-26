//! The production consumed-attestation path must admit capacity before issuing
//! a record proof. These are component controls, not store/transport evidence.

use super::*;

fn attested(expanded: bool, resolution_kind: usize) -> AttestedConfigCommit {
    let (mut record, audit, _) = fixture(32, 64, true).into_parts();
    let envelope = CryptoEnvelopeRef::decode(&record.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-record-proof").unwrap(),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xA7; 32]),
    );
    let fresh = encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        &plaintext(32, 64),
        [0xA8; 12],
    )
    .unwrap();
    assert_eq!(fresh.encoded(), record.encrypted_blob);
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&handle, &aad, fresh.encoded())
            .unwrap()
            .as_slice(),
        plaintext(32, 64),
    );
    if expanded {
        record
            .encrypted_blob
            .try_reserve_exact(32 * 1024 * 1024 + 1 - record.encrypted_blob.len())
            .unwrap();
        assert!(record.encrypted_blob.capacity() > 32 * 1024 * 1024);
        assert_eq!(fresh.encoded(), record.encrypted_blob);
    }
    let pending_tx_id = record.parent_tx_id.unwrap();
    let resolution = match resolution_kind {
        0 => None,
        1 => Some(crate::ConfirmedCommitResolution::Confirm { pending_tx_id }),
        2 => Some(crate::ConfirmedCommitResolution::Rollback { pending_tx_id }),
        _ => panic!("fixed fixture variants"),
    };
    match resolution {
        None => AttestedConfigCommit::try_new(record, audit, fresh.claim().unwrap()),
        Some(resolution) => AttestedConfigCommit::try_new_resolving(
            record,
            audit,
            fresh.claim().unwrap(),
            resolution,
        ),
    }
    .expect("genuine paired claim after capacity-only growth")
}

#[test]
fn config_capacity_preparation_preserves_paired_evidence_and_resolution() {
    for resolution in 0..3 {
        let input = attested(false, resolution);
        let expected = CapacityRecordBinding::issue(&input, scope(), &key(), PROFILE).unwrap();
        let expected_resolution = input.confirmed_resolution();
        let expected_evidence = input.capacity_evidence();
        RECORD_ISSUES.set(0);
        let prepared = PreparedCapacityCommit::prepare(input, scope(), &key(), PROFILE).unwrap();
        assert_eq!(RECORD_ISSUES.get(), 1);
        assert_eq!(prepared.binding, Some(expected));
        assert_eq!(prepared.resolution, expected_resolution);
        assert_eq!(prepared.evidence, expected_evidence);
        expected
            .verify(&prepared.commit.record, scope(), &key(), PROFILE)
            .unwrap();
        prepared.commit.validate().unwrap();
    }
    RECORD_ISSUES.set(0);
    let legacy = PreparedCapacityCommit::prepare(
        fixture(32, 0, false),
        scope(),
        &key(),
        ConfigCapacityProfile::Legacy,
    )
    .unwrap();
    assert!(legacy.binding.is_none());
    assert_eq!(RECORD_ISSUES.get(), 0);
}

#[test]
fn config_capacity_preparation_rejects_before_record_proof_work() {
    let compact = attested(false, 0);
    RECORD_ISSUES.set(0);
    PreparedCapacityCommit::prepare(compact, scope(), &key(), PROFILE).unwrap();
    assert_eq!(
        RECORD_ISSUES.get(),
        1,
        "positive control reaches real issuer"
    );
    let expanded = attested(true, 0);
    RECORD_ISSUES.set(0);
    let error = match PreparedCapacityCommit::prepare(expanded, scope(), &key(), PROFILE) {
        Ok(_) => panic!("oversized transferred capacity must reject"),
        Err(error) => error,
    };
    assert!(
        matches!(error.kind(), crate::PersistErrorKind::ConstraintViolation(message)
        if message == "config preparation allocation exceeds working limit")
    );
    assert_eq!(
        RECORD_ISSUES.get(),
        0,
        "capacity rejection precedes proof validation and MAC"
    );
}
