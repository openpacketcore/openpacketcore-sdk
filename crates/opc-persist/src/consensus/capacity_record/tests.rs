use super::*;
use crate::consensus::capacity_tests::support::*;
use opc_crypto::{AuthenticatedEnvelope, ConfigCapacityError};
use opc_types::{ConfigVersion, SchemaDigest};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

fn proof(attested: &AttestedConfigCommit) -> CapacityRecordBinding {
    CapacityRecordBinding::issue(attested, identity(), &key()).unwrap()
}

fn signed_counts(record: &CommitRecord, logical: usize, replay: usize) -> CapacityRecordBinding {
    // White-box adversarial input: a valid MAC must not override byte limits.
    // Production cannot call the private issuer with arbitrary lengths.
    let mut proof = CapacityRecordBinding {
        header: [0; HEADER_BYTES],
        tag: [0; 32],
    };
    proof.header[..4].copy_from_slice(&[0, 1, 0, 1]);
    proof.header[4..8].copy_from_slice(&(logical as u32).to_be_bytes());
    proof.header[8..12].copy_from_slice(&(replay as u32).to_be_bytes());
    proof.tag = proof
        .mac(record, identity(), &key())
        .unwrap()
        .finalize()
        .into_bytes()
        .into();
    proof
}

fn unchecked_record(logical: usize, replay: usize) -> CommitRecord {
    let bytes = plaintext(logical, replay);
    let mut record = record();
    record.encrypted_blob = opc_crypto::encrypt_envelope_with_handle_and_nonce(
        &handle_key(),
        &aad(&record, "running"),
        &bytes,
        [0x35; 12],
    )
    .unwrap();
    record.plaintext_digest = Sha256::digest(&bytes).to_vec();
    record
}

#[test]
fn fixed_proof_bytes_and_digest_have_an_independent_transcript() {
    let attested = bounded_attested(32, 64);
    let record = attested.record();
    let proof = proof(&attested);
    let header = [0, 1, 0, 1, 0, 0, 0, 32, 0, 0, 0, 64];
    // Independent oracle: an explicit byte transcript, not the implementation's
    // issue/mac helper, including each scope and exact ciphertext digest.
    let mut transcript = b"openpacketcore/config-capacity/record/v1\0".to_vec();
    transcript.extend_from_slice(&header);
    transcript.extend_from_slice(&1_u64.to_be_bytes());
    transcript.extend_from_slice(identity().cluster_id().as_bytes());
    transcript.extend_from_slice(&[3; 32]);
    transcript.extend_from_slice(&1_u64.to_be_bytes());
    transcript.extend_from_slice(tx().as_uuid().as_bytes());
    transcript.extend_from_slice(&2_u64.to_be_bytes());
    transcript.extend_from_slice(&(record.encrypted_blob.len() as u64).to_be_bytes());
    transcript.extend_from_slice(&Sha256::digest(&record.encrypted_blob));
    transcript.extend_from_slice(&record.plaintext_digest);
    let mut mac = Hmac::<Sha256>::new_from_slice(&[4; 32]).unwrap();
    mac.update(&transcript);
    let mut expected = header.to_vec();
    expected.extend_from_slice(&mac.finalize().into_bytes());
    assert_eq!(proof.encode().as_slice(), expected);
    assert_eq!(opc_consensus::encode_bounded(&proof).unwrap(), expected);
    let wire: CapacityRecordBinding = opc_consensus::decode_bounded(&expected).unwrap();
    assert_eq!(wire, proof);
    assert_eq!(CapacityRecordBinding::decode(&expected).unwrap(), proof);
    let json = serde_json::to_vec(&proof).unwrap();
    assert_eq!(
        serde_json::from_slice::<CapacityRecordBinding>(&json).unwrap(),
        proof
    );
    assert_eq!(format!("{proof:?}"), "CapacityRecordBinding(<redacted>)");
    proof.verify(record, identity(), &key(), PROFILE).unwrap();
    for size in [0, 12, 32, 43, 45, 64] {
        assert!(CapacityRecordBinding::decode(&vec![0; size]).is_err());
    }
    expected.push(0);
    assert!(opc_consensus::decode_bounded::<CapacityRecordBinding>(&expected).is_err());
}

#[test]
fn every_proof_byte_and_independent_scope_is_authenticated() {
    let attested = bounded_attested(32, 64);
    let proof = proof(&attested);
    for offset in 0..RECORD_CAPACITY_BYTES {
        let mut encoded = proof.encode();
        encoded[offset] ^= 1;
        let changed = CapacityRecordBinding::decode(&encoded).unwrap();
        assert!(
            changed
                .verify(attested.record(), identity(), &key(), PROFILE)
                .is_err(),
            "offset {offset}"
        );
    }
    for scope in [
        ConfigConsensusIdentity::new(
            crate::ConfigConsensusClusterId::from_bytes([20; 32]),
            identity().configuration_id(),
            identity().configuration_epoch(),
        ),
        ConfigConsensusIdentity::new(
            identity().cluster_id(),
            crate::ConfigConsensusConfigurationId::from_bytes([21; 32]),
            identity().configuration_epoch(),
        ),
        ConfigConsensusIdentity::new(
            identity().cluster_id(),
            identity().configuration_id(),
            crate::ConfigConsensusConfigurationEpoch::new(2).unwrap(),
        ),
    ] {
        assert!(proof
            .verify(attested.record(), scope, &key(), PROFILE)
            .is_err());
    }
    for other in [
        AuditKey::new([22; 32]).unwrap(),
        AuditKey::new_with_epoch([4; 32], 2).unwrap(),
    ] {
        assert!(proof
            .verify(attested.record(), identity(), &other, PROFILE)
            .is_err());
    }
    assert!(proof
        .verify(
            attested.record(),
            identity(),
            &key(),
            ConfigCapacityProfile::Legacy
        )
        .is_err());
}

#[test]
fn every_immutable_record_field_is_bound_and_mutable_projections_are_separate() {
    let attested = bounded_attested(32, 64);
    let proof = proof(&attested);
    let changes: [fn(&mut CommitRecord); 11] = [
        |r| r.tx_id = parent(),
        |r| r.parent_tx_id = None,
        |r| r.version = ConfigVersion::new(3),
        |r| r.committed_at = "2026-01-02T00:00:00Z".parse().unwrap(),
        |r| r.principal.push('x'),
        |r| r.schema_digest = SchemaDigest::from_bytes([99; 32]),
        |r| r.plaintext_digest[0] ^= 1,
        |r| {
            r.plaintext_digest.pop();
        },
        |r| *r.encrypted_blob.last_mut().unwrap() ^= 1,
        |r| r.encrypted_blob.push(0),
        |r| r.encrypted_blob.clear(),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut changed = attested.record().clone();
        change(&mut changed);
        assert!(
            proof.verify(&changed, identity(), &key(), PROFILE).is_err(),
            "field {index}"
        );
    }
    let mut record = attested.record().clone();
    record.rollback_point = !record.rollback_point;
    record.confirmed_deadline = Some(timestamp());
    record.source = crate::CommitSource::Rollback;
    proof.verify(&record, identity(), &key(), PROFILE).unwrap();
    // These fields belong to the complete command's digest and audit MAC; this
    // record proof intentionally binds immutable encrypted identity only.
}

#[test]
fn logical_replay_and_joint_plaintext_limits_use_real_encryption() {
    for (logical, replay) in [
        (1, 0),
        (CONFIG_CAPACITY_V1_LOGICAL_BYTES, 0),
        (1, CONFIG_CAPACITY_V1_REPLAY_BYTES),
        (
            CONFIG_CAPACITY_V1_LOGICAL_BYTES,
            CONFIG_CAPACITY_V1_REPLAY_BYTES,
        ),
    ] {
        let attested = bounded_attested(logical, replay);
        proof(&attested)
            .verify(attested.record(), identity(), &key(), PROFILE)
            .unwrap();
        assert_eq!(
            attested.capacity_evidence().unwrap().logical_bytes(),
            logical
        );
        assert_eq!(attested.capacity_evidence().unwrap().replay_bytes(), replay);
    }
    for (logical, replay) in [
        (CONFIG_CAPACITY_V1_LOGICAL_BYTES + 1, 0),
        (1, CONFIG_CAPACITY_V1_REPLAY_BYTES + 1),
        (
            CONFIG_CAPACITY_V1_LOGICAL_BYTES,
            CONFIG_CAPACITY_V1_REPLAY_BYTES + 1,
        ),
    ] {
        let record = unchecked_record(logical, replay);
        assert!(signed_counts(&record, logical, replay)
            .verify(&record, identity(), &key(), PROFILE)
            .is_err());
    }
    let attested = bounded_attested(32, 64);
    for (logical, replay) in [(0, 96), (31, 64), (33, 64), (32, 63), (32, 65)] {
        assert!(signed_counts(attested.record(), logical, replay)
            .verify(attested.record(), identity(), &key(), PROFILE)
            .is_err());
    }
}

#[test]
fn declared_envelope_extents_have_inclusive_limits() {
    // This isolates the extent preflight itself, not its ordering relative to
    // decoding. Each rejected input changes one admitted extent or total size.
    let mut header: [u8; 16] = record().encrypted_blob[..16].try_into().unwrap();
    header[8..10].copy_from_slice(&512_u16.to_be_bytes());
    header[10..12].copy_from_slice(&12_u16.to_be_bytes());
    header[12..16].copy_from_slice(&65_536_u32.to_be_bytes());
    preflight_envelope_lengths(&header).unwrap();
    for (range, replacement) in [
        (8..10, 513_u16.to_be_bytes().to_vec()),
        (10..12, 13_u16.to_be_bytes().to_vec()),
        (12..16, 65_537_u32.to_be_bytes().to_vec()),
    ] {
        let mut invalid = header;
        invalid[range].copy_from_slice(&replacement);
        assert!(preflight_envelope_lengths(&invalid).is_err());
    }
    for length in 0..16 {
        assert!(preflight_envelope_lengths(&header[..length]).is_err());
    }
    for nonce in [0_u16, 11, 13, u16::MAX] {
        let mut changed = header;
        changed[10..12].copy_from_slice(&nonce.to_be_bytes());
        assert!(preflight_envelope_lengths(&changed).is_err());
    }
    // This header-only test isolates the inclusive defensive total-length
    // check. The real maximum envelope is covered below with actual encryption.
    let mut encoded = vec![0; CONFIG_CAPACITY_V1_ENVELOPE_BYTES];
    encoded[..16].copy_from_slice(&header);
    preflight_envelope_lengths(&encoded).unwrap();
    encoded.push(0);
    assert!(preflight_envelope_lengths(&encoded).is_err());
}

#[test]
fn maximum_actual_envelope_and_aad_bindings_fit() {
    let mut record = record();
    let key_handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("k".repeat(512)).unwrap(),
        opc_key::KeyPurpose::Config,
        opc_types::TenantId::from_static("default"),
        opc_key::Zeroizing::new([0x36; 32]),
    );
    let base = opc_key::serialize_bound_aad(&aad(&record, "s"), key_handle.key_id())
        .unwrap()
        .len();
    let store = "s".repeat(CONFIG_CAPACITY_V1_AAD_BYTES - base + 1);
    let bytes = plaintext(
        CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        CONFIG_CAPACITY_V1_REPLAY_BYTES,
    );
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &key_handle,
        &aad(&record, &store),
        &bytes,
        [0x37; 12],
    )
    .unwrap();
    assert_eq!(envelope.encoded().len(), CONFIG_CAPACITY_V1_ENVELOPE_BYTES);
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&bytes).to_vec();
    let attested =
        AttestedConfigCommit::try_new(record.clone(), vec![], envelope.claim().unwrap()).unwrap();
    proof(&attested)
        .verify(&record, identity(), &key(), PROFILE)
        .unwrap();
    let mut over = opc_crypto::CryptoEnvelopeV1::decode(&record.encrypted_blob).unwrap();
    over.aad =
        opc_key::serialize_bound_aad(&aad(&record, &(store + "s")), key_handle.key_id()).unwrap();
    record.encrypted_blob = over.encode().unwrap();
    assert_eq!(
        record.encrypted_blob.len(),
        CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1
    );
    assert!(signed_counts(
        &record,
        CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        CONFIG_CAPACITY_V1_REPLAY_BYTES
    )
    .verify(&record, identity(), &key(), PROFILE)
    .is_err());
}

struct Provider;
#[async_trait::async_trait]
impl opc_key::KeyProvider for Provider {
    async fn get_active_key(
        &self,
        _: opc_key::KeyPurpose,
        _: &opc_types::TenantId,
    ) -> Result<opc_key::KeyHandle, opc_key::KeyError> {
        Ok(handle_key())
    }
    async fn get_key_by_id(
        &self,
        _: &opc_key::KeyId,
    ) -> Result<opc_key::KeyHandle, opc_key::KeyError> {
        panic!("unexpected lookup")
    }
    async fn rotate_key(
        &self,
        _: opc_key::KeyPurpose,
        _: &opc_types::TenantId,
    ) -> Result<opc_key::KeyId, opc_key::KeyError> {
        panic!("unexpected rotation")
    }
}

async fn reserved(pool: &ConfigPreparationPool) -> (CommitRecord, AuthenticatedEnvelope) {
    let mut record = record();
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().unwrap(),
        &Provider,
        &aad(&record, "running"),
        b"null",
    )
    .await
    .unwrap();
    record.encrypted_blob = envelope.encoded().to_vec();
    (record, envelope)
}

#[tokio::test]
async fn consumed_preparation_keeps_exact_pool_claim_and_alias_ownership() {
    let pool = ConfigPreparationPool::bounded_v1();
    let other = ConfigPreparationPool::bounded_v1();
    assert!(
        PreparedCapacityCommit::prepare(bounded_attested(32, 64), identity(), &key(), &pool,)
            .is_err()
    );
    let (record, envelope) = reserved(&pool).await;
    let attested = AttestedConfigCommit::try_new(
        record.clone(),
        audit(),
        envelope.claim_reserved(&pool).unwrap(),
    )
    .unwrap();
    assert!(PreparedCapacityCommit::prepare(attested, identity(), &key(), &other).is_err());
    drop(envelope);
    let (record, envelope) = reserved(&pool).await;
    let alias = envelope.clone();
    let attested = AttestedConfigCommit::try_new_resolving(
        record,
        audit(),
        envelope.claim_reserved(&pool).unwrap(),
        ConfirmedCommitResolution::Confirm {
            pending_tx_id: parent(),
        },
    )
    .unwrap();
    let prepared = PreparedCapacityCommit::prepare(attested, identity(), &key(), &pool).unwrap();
    assert!(pool.owns(&prepared.reservation));
    assert_eq!(
        prepared.resolution,
        Some(ConfirmedCommitResolution::Confirm {
            pending_tx_id: parent()
        })
    );
    prepared
        .binding
        .verify(&prepared.commit.record, identity(), &key(), PROFILE)
        .unwrap();
    drop(envelope);
    let held: Vec<_> = (0..7).map(|_| pool.try_reserve().unwrap()).collect();
    assert_eq!(
        pool.try_reserve().unwrap_err(),
        ConfigCapacityError::ResourceAdmission
    );
    drop(prepared);
    assert_eq!(
        pool.try_reserve().unwrap_err(),
        ConfigCapacityError::ResourceAdmission
    );
    drop(alias);
    pool.try_reserve().unwrap();
    drop(held);
}

#[test]
fn record_binding_rejects_ciphertext_or_plaintext_digest_substitution() {
    let attested = bounded_attested(32, 64);
    let binding = proof(&attested);
    binding
        .verify(attested.record(), identity(), &key(), PROFILE)
        .unwrap();
    for change_digest in [false, true] {
        let mut record = attested.record().clone();
        if change_digest {
            record.plaintext_digest[0] ^= 1;
        } else {
            *record.encrypted_blob.last_mut().unwrap() ^= 1;
        }
        // No claim constructor is involved: all structural checks pass and
        // only the C2 proof's MAC can reject the single substituted field.
        binding.validate(&record, PROFILE).unwrap();
        assert!(binding
            .verify(&record, identity(), &key(), PROFILE)
            .is_err());
    }
}

#[test]
fn legacy_attestation_cannot_issue_a_bounded_binding() {
    let mut record = record();
    let envelope = opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
        &handle_key(),
        &aad(&record, "running"),
        b"null",
        [0x38; 12],
    )
    .unwrap();
    record.encrypted_blob = envelope.encoded().to_vec();
    let attested =
        AttestedConfigCommit::try_new(record, audit(), envelope.claim().unwrap()).unwrap();
    assert!(CapacityRecordBinding::issue(&attested, identity(), &key()).is_err());
}

#[tokio::test]
async fn both_command_forms_retain_the_record_from_consumed_reserved_encryption() {
    use crate::consensus::audit_mutation::AuditedConfigEffect;
    use crate::consensus::{ConfigMutationIntent, PreparedAuditedMutation};
    let pool = ConfigPreparationPool::bounded_v1();
    for audited in [false, true] {
        let (record, envelope) = reserved(&pool).await;
        let expected = record.clone();
        let attested =
            AttestedConfigCommit::try_new(record, audit(), envelope.claim_reserved(&pool).unwrap())
                .unwrap();
        let PreparedCapacityCommit {
            commit,
            binding,
            resolution,
            reservation,
        } = PreparedCapacityCommit::prepare(attested, identity(), &key(), &pool).unwrap();
        assert_eq!(commit.record, expected);
        let intent = if audited {
            let effect = AuditedConfigEffect::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution,
            };
            ConfigMutationIntent::AuditedMutation(PreparedAuditedMutation {
                handle: handle(Some(&effect)),
                effect,
            })
        } else {
            ConfigMutationIntent::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution,
            }
        };
        let mut command = command(intent);
        command.schema_version = 8;
        command
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .unwrap();
        opc_consensus::encode_bounded(&command).unwrap();
        command.payload_digest().unwrap();
        assert!(pool.owns(&reservation));
        assert!(command.validate(identity()).is_err());
        // Submission ownership is deliberately not inferred from serialization.
        // The consumed preparation still retains its original process-local lease.
    }
}

#[test]
fn record_metadata_and_its_aad_binding_have_exact_boundaries() {
    for (principal, version, accepted) in [
        (
            "p".repeat(super::super::types::CONFIG_PRINCIPAL_MAX_BYTES),
            i64::MAX as u64,
            true,
        ),
        (
            "p".repeat(super::super::types::CONFIG_PRINCIPAL_MAX_BYTES + 1),
            2,
            false,
        ),
        ("writer".into(), i64::MAX as u64 + 1, false),
    ] {
        let mut record = record();
        record.principal = principal;
        record.version = ConfigVersion::new(version);
        let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
            &handle_key(),
            &aad(&record, "running"),
            b"null",
            [0x39; 12],
        )
        .unwrap();
        record.encrypted_blob = envelope.encoded().to_vec();
        let attested =
            AttestedConfigCommit::try_new(record, vec![], envelope.claim().unwrap()).unwrap();
        assert_eq!(
            CapacityRecordBinding::issue(&attested, identity(), &key()).is_ok(),
            accepted
        );
    }
    let attested = bounded_attested(32, 64);
    for mutation in [0, 1, 2] {
        let mut record = attested.record().clone();
        let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(&record.encrypted_blob).unwrap();
        if mutation == 0 {
            envelope.key_id = opc_key::KeyId::new("another-key").unwrap();
        }
        if mutation == 1 {
            envelope.nonce.push(0);
        }
        if mutation == 2 {
            envelope.ciphertext_and_tag.push(0);
        }
        // The general encoder may itself refuse a malformed nonce. Otherwise a
        // correctly signed proof must still reject the contradictory envelope.
        if let Ok(encoded) = envelope.encode() {
            record.encrypted_blob = encoded;
            assert!(signed_counts(&record, 32, 64)
                .verify(&record, identity(), &key(), PROFILE)
                .is_err());
        }
    }
}
