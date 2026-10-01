//! Payload/codec controls only. No joint retained store can be opened by these
//! tests; native admission, apply, history and snapshot qualification is separate.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{AuditOperationBinding, AuditPrivacyKey, ProjectedAuditEvent};
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::{TargetAuditCommandV1, TargetEncryptedBlobV1};
use crate::consensus::types::{ConfigConsensusCommand, ConfigMutationIntent};
use async_trait::async_trait;
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusRequestId,
};
use opc_key::{ConfigAad, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose};
use opc_types::TenantId;
use serde_json::json;
use sha2::{Digest, Sha256};

struct Provider;
#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyHandle, KeyError> {
        Ok(KeyHandle::new(
            KeyId::new("joint-payload-test").unwrap(),
            KeyPurpose::Config,
            TenantId::from_static("synthetic"),
            opc_key::Zeroizing::new([0x71; 32]),
        ))
    }
    async fn get_key_by_id(&self, _: &KeyId) -> Result<KeyHandle, KeyError> {
        Err(KeyError::Unavailable)
    }
    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        Err(KeyError::Unavailable)
    }
}

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x72; 32]),
        ConsensusConfigurationId::from_bytes([0x73; 32]),
        ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}
fn key() -> AuditKey {
    AuditKey::new([0x74; 32]).unwrap()
}
fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x75; 32]).unwrap()
}
fn event() -> ProjectedAuditEvent {
    let event = crate::ManagementAuditEventRecord::try_new(
        [0x76; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .unwrap(),
        "synthetic",
        "synthetic-principal",
        crate::ManagementAuditTransportCode::NetconfSsh,
        crate::ManagementAuditOperationCode::Replace,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("joint-payload"),
    )
    .unwrap();
    ProjectedAuditEvent::project(&privacy(), &event).unwrap()
}

async fn payload(
    pool: &ConfigPreparationPool,
    plaintext: &[u8],
) -> (BoundedRunningPayload, Arc<PreparationOwnership>) {
    payload_for(pool, plaintext, identity(), &key()).await
}

async fn payload_for(
    pool: &ConfigPreparationPool,
    plaintext: &[u8],
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
) -> (BoundedRunningPayload, Arc<PreparationOwnership>) {
    let tx_id: TxId = "72727272-7272-4272-8272-727272727272".parse().unwrap();
    let committed_at = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
    let schema_digest = SchemaDigest::from_bytes([0x77; 32]);
    let principal =
        "spiffe://fixture.invalid/tenant/synthetic/ns/test/sa/config/nf/test/instance/0";
    let aad = EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        ConfigAad::new(
            tx_id,
            None,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .unwrap(),
    );
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        pool.try_reserve().unwrap(),
        &Provider,
        &aad,
        plaintext,
    )
    .await
    .unwrap();
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at,
        principal: principal.to_owned(),
        source: crate::CommitSource::Netconf,
        schema_digest,
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let attested =
        crate::AttestedConfigCommit::try_new(record, Vec::new(), envelope.claim().unwrap())
            .unwrap();
    assert!(envelope.claim().is_err(), "one real encryption claim");
    assert!(pool.owns(attested.preparation().unwrap()));
    let prepared =
        PreparedCapacityCommit::prepare(attested, identity, key, ConfigCapacityProfile::BoundedV1)
            .unwrap();
    let payload = BoundedRunningPayload::from_prepared(prepared).unwrap();
    drop(envelope);
    payload
}

fn signed(parts: (BoundedRunningPayload, Arc<PreparationOwnership>)) -> PreparedTargetMutation {
    signed_for(parts, identity(), &key())
}

fn signed_for(
    (payload, owner): (BoundedRunningPayload, Arc<PreparationOwnership>),
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
) -> PreparedTargetMutation {
    let event = event();
    let effect = TargetEffectV1 {
        format: 1,
        authority: identity,
        profile_incarnation: [0x78; 16],
        device_incarnation: [0x79; 16],
        caller: event.caller,
        request: event.request,
        action: 16.try_into().unwrap(),
        destination: TargetExpectationV1::Running { version: 0 },
        source: None,
        lock: Some(TargetLockExpectationV1 {
            datastore: 0,
            incarnation: 1,
            session: Some([0x7a; 16]),
            requester: [0x7a; 16],
        }),
        expires_at: 160,
        encrypted_payload: Some(TargetPayloadV1::BoundedRunning(payload)),
        resolution: None,
    };
    let digest = effect.digest(key).unwrap();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity,
            binding: AuditOperationBinding::project(&privacy(), &event, 0, &digest).unwrap(),
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0x7b; 16],
            key_epoch: key.epoch(),
            mutation: Some(digest),
        },
        key,
    )
    .unwrap();
    PreparedTargetMutation::new(handle, effect, Some(owner))
}

fn resign(prepared: &mut PreparedTargetMutation) {
    let digest = prepared.command().effect.digest(&key()).unwrap();
    let mut body = prepared.command().handle.body.clone();
    body.mutation = Some(digest);
    body.binding = AuditOperationBinding::project(&privacy(), &body.event, 0, &digest).unwrap();
    prepared.command_mut().handle = AuditOperationHandle::issue(body, &key()).unwrap();
}

fn input(bytes: &[u8]) -> PreparedTargetMutation {
    serde_json::from_slice::<Received>(bytes)
        .unwrap()
        .into_prepared()
        .unwrap()
}
fn all_slots_available(pool: &ConfigPreparationPool) {
    let slots: Vec<_> = (0..8)
        .map(|_| pool.try_reserve().expect("all eight released"))
        .collect();
    assert!(pool.try_reserve().is_err());
    drop(slots);
}
fn intent(prepared: PreparedTargetMutation) -> ConfigMutationIntent {
    ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::NetconfTarget(Box::new(
        TargetAuditCommandV1::Apply(prepared.command().clone()),
    ))))
}

#[tokio::test]
async fn joint_payload_original_reservation_and_ciphertext_survive_clones() {
    let pool = ConfigPreparationPool::bounded_v1();
    let other: Vec<_> = (0..7).map(|_| pool.try_reserve().unwrap()).collect();
    let prepared = signed(payload(&pool, br#"{"enabled":true}"#).await);
    assert!(pool.try_reserve().is_err(), "JOINT_ORIGINAL_RESERVATION");
    let aliases = vec![prepared.clone(); 16];
    for alias in &aliases {
        assert!(Arc::ptr_eq(
            &alias.bounded_running().unwrap().fields,
            &prepared.bounded_running().unwrap().fields
        ));
        assert!(Arc::ptr_eq(
            alias.preparation.as_ref().unwrap(),
            prepared.preparation.as_ref().unwrap()
        ));
    }
    let owner = prepared.preparation.as_ref().unwrap();
    assert!(owner.belongs_to(&pool, ConfigCapacityProfile::BoundedV1, true));
    let foreign = ConfigPreparationPool::bounded_v1();
    assert!(!owner.belongs_to(&foreign, ConfigCapacityProfile::BoundedV1, true));
    let guard = prepared.preparation.as_ref().unwrap().try_encode().unwrap();
    assert!(
        aliases[0].encode().is_err(),
        "one encoding per original owner"
    );
    drop(guard);
    let bytes = prepared.encode().unwrap();
    assert!(!std::str::from_utf8(&bytes).unwrap().contains("preparation"));
    prepared
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    drop(prepared);
    assert!(
        pool.try_reserve().is_err(),
        "aliases preserve original ownership"
    );
    drop(aliases);
    let slot = pool.try_reserve().unwrap();
    drop(slot);
    drop(other);
    all_slots_available(&pool);
}

#[tokio::test]
async fn joint_payload_recovery_authenticates_exact_original_scope_and_proof() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let encoded = prepared.encode().unwrap();
    let decoded = input(&encoded);
    assert!(
        decoded.encode().is_err(),
        "representation mints no reservation"
    );
    assert!(
        decoded.verify_effect(&key()).is_err(),
        "target9 cannot authorize joint"
    );
    let destination = ConfigPreparationPool::bounded_v1();
    let foreign = ConfigPreparationPool::bounded_v1();
    assert!(
        recover(
            &encoded,
            foreign.try_reserve().unwrap(),
            &destination,
            identity(),
            &key(),
            event().caller
        )
        .is_err(),
        "JOINT_DESTINATION_POOL"
    );
    all_slots_available(&foreign);
    let recovered = recover(
        &encoded,
        destination.try_reserve().unwrap(),
        &destination,
        identity(),
        &key(),
        event().caller,
    )
    .unwrap();
    assert_eq!(
        recovered.encode().unwrap(),
        encoded,
        "same fixed original, no re-encryption or expiry change"
    );
    assert_eq!(recovered.handle(), prepared.handle());
    assert_eq!(recovered.command().handle.body.expires_at, 160);
    drop(recovered);
    all_slots_available(&destination);

    let mut changed = input(&encoded);
    changed
        .command_mut()
        .effect
        .lock
        .as_mut()
        .unwrap()
        .incarnation += 1;
    let bytes = serde_json::to_vec(&changed).unwrap();
    assert!(
        recover(
            &bytes,
            destination.try_reserve().unwrap(),
            &destination,
            identity(),
            &key(),
            event().caller
        )
        .is_err(),
        "JOINT_ORIGINAL_MAC"
    );
    all_slots_available(&destination);

    // Independently re-sign the operation after a corrupted size proof. A valid
    // original-operation MAC cannot stand in for the actual record-size MAC.
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["effect"]["encrypted_payload"]["bounded-running"]["binding"]["tag"][0] = json!(0);
    let old_tag = prepared.bounded_running().unwrap().binding().encode()[12];
    value["effect"]["encrypted_payload"]["bounded-running"]["binding"]["tag"][0] =
        json!(old_tag ^ 1);
    let mut changed = input(&serde_json::to_vec(&value).unwrap());
    resign(&mut changed);
    let bytes = serde_json::to_vec(&changed).unwrap();
    assert!(
        recover(
            &bytes,
            destination.try_reserve().unwrap(),
            &destination,
            identity(),
            &key(),
            event().caller
        )
        .is_err(),
        "JOINT_RECORD_PROOF"
    );
    all_slots_available(&destination);
    let foreign_identity = ConfigConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x7c; 32]),
        identity().configuration_id(),
        identity().configuration_epoch(),
    );
    assert!(recover(
        &encoded,
        destination.try_reserve().unwrap(),
        &destination,
        foreign_identity,
        &key(),
        event().caller
    )
    .is_err());
    let foreign_caller = AuditCaller::project(&privacy(), "synthetic", "other-principal").unwrap();
    assert!(recover(
        &encoded,
        destination.try_reserve().unwrap(),
        &destination,
        identity(),
        &key(),
        foreign_caller
    )
    .is_err());
    all_slots_available(&destination);
}

#[tokio::test]
async fn joint_payload_strict_received_and_retained_inputs_are_closed() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let bytes = prepared.encode().unwrap();
    let binary = opc_consensus::encode_bounded(&prepared).unwrap();
    let decoded = opc_consensus::decode_bounded::<Received>(&binary)
        .unwrap()
        .into_prepared()
        .unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    assert!(decoded.preparation.is_none());
    for end in 0..binary.len() {
        assert!(opc_consensus::decode_bounded::<Received>(&binary[..end]).is_err());
    }
    let mut trailing = binary;
    trailing.push(0);
    assert!(opc_consensus::decode_bounded::<Received>(&trailing).is_err());
    for path in [
        "",
        "/handle",
        "/effect",
        "/effect/lock",
        "/effect/encrypted_payload/bounded-running",
        "/effect/encrypted_payload/bounded-running/commit",
        "/effect/encrypted_payload/bounded-running/commit/record",
        "/effect/encrypted_payload/bounded-running/binding",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(0));
        assert!(
            serde_json::from_value::<Received>(value).is_err(),
            "JOINT_STRICT_INPUT: {path}"
        );
    }
    let duplicate = std::str::from_utf8(&bytes).unwrap().replace(
        "\"rollback_point\":false",
        "\"rollback_point\":false,\"rollback_point\":false",
    );
    assert!(serde_json::from_str::<Received>(&duplicate).is_err());
    // The old decoder rejects the tag itself, before visiting an invalid or
    // attacker-sized record body; the control makes that visit observable.
    let error = serde_json::from_str::<TargetPayloadV1>(r#"{"bounded-running": {"unparsed": ["#)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("unknown variant"),
        "JOINT_OLD_TAG_EARLY_REFUSAL: {error}"
    );
    assert!(serde_json::from_slice::<TargetPayloadV1>(
        &serde_json::to_vec(
            prepared
                .command()
                .effect
                .encrypted_payload
                .as_ref()
                .unwrap()
        )
        .unwrap()
    )
    .is_err());
    assert!(PreparedTargetMutation::decode(&bytes).is_err());
}

#[tokio::test]
async fn joint_payload_variable_owners_reject_one_over_and_declared_hints() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let bytes = prepared.encode().unwrap();
    for (field, value) in [
        (
            "principal",
            json!("x".repeat(CONFIG_PRINCIPAL_MAX_BYTES + 1)),
        ),
        ("schema_digest", json!("0".repeat(65))),
        ("plaintext_digest", json!(vec![0u8; 33])),
        (
            "encrypted_blob",
            json!(vec![0u8; CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1]),
        ),
    ] {
        let mut source: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        source["effect"]["encrypted_payload"]["bounded-running"]["commit"]["record"][field] = value;
        assert!(
            serde_json::from_value::<Received>(source).is_err(),
            "JOINT_INPUT_BOUND: {field}"
        );
    }
    // Exercise the shared bounded visitor on a declared length with no payload.
    assert!(
        opc_consensus::decode_bounded::<Bytes<CONFIG_CAPACITY_V1_ENVELOPE_BYTES>>(&[
            0xff, 0xff, 0xff, 0xff, 0x0f
        ])
        .is_err()
    );
    let escaped = format!("\"{}\"", "\\u0000".repeat(CONFIG_PRINCIPAL_MAX_BYTES + 1));
    assert!(json_string_preflight(escaped.as_bytes()).is_err());
    let entry = AuditRecord {
        tx_id: prepared.bounded_running().unwrap().commit().record.tx_id,
        sequence: 0,
        yang_path: "/fixture:config".to_owned(),
        op_type: crate::AuditOpType::Replace,
        previous_value: None,
        new_value: None,
        redaction_applied: false,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    };
    for entries in [
        vec![entry.clone(); CONFIG_CAPACITY_V1_METADATA_BYTES / 64 + 1],
        vec![
            AuditRecord {
                yang_path: format!("/{}", "x".repeat(CONFIG_AUDIT_PATH_MAX_BYTES - 1)),
                ..entry
            };
            25
        ],
    ] {
        let json = serde_json::to_vec(&entries).unwrap();
        assert!(
            serde_json::from_slice::<AuditInputList>(&json).is_err(),
            "JOINT_AUDIT_AGGREGATE"
        );
        let wire = opc_consensus::encode_bounded(&entries).unwrap();
        assert!(opc_consensus::decode_bounded::<AuditInputList>(&wire).is_err());
    }
}

fn command(prepared: PreparedTargetMutation, revision: u16) -> ConfigConsensusCommand {
    ConfigConsensusCommand {
        schema_version: revision,
        identity: identity(),
        request_id: ConsensusRequestId::from_bytes([0x7e; 16]),
        logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
        intent: intent(prepared),
    }
}

#[tokio::test]
async fn joint_payload_existing_profiles_refuse_new_representation() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    for revision in [7, 8, 9, 10] {
        let command = command(prepared.clone(), revision);
        assert_eq!(
            command.intent.minimum_command_version(),
            10,
            "JOINT_SEMANTIC_REVISION"
        );
        for mode in [
            crate::retained::RetainedConfigMode::Legacy,
            crate::retained::RetainedConfigMode::BoundedV1,
            crate::retained::RetainedConfigMode::NetconfTargetsV1,
        ] {
            assert!(
                command
                    .validate_for_profile(identity(), &key(), mode)
                    .is_err(),
                "joint opening/apply remains closed"
            );
        }
        assert!(serde_json::from_slice::<ConfigConsensusCommand>(
            &serde_json::to_vec(&command).unwrap()
        )
        .is_err());
    }
}

#[tokio::test]
async fn joint_payload_metadata_charges_every_field_except_proved_envelope_content() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, br#"{"data":[]}"#).await);
    prepared
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    crate::consensus::store::preflight_joint_target_payload(&prepared).unwrap();
    let envelope = prepared
        .bounded_running()
        .unwrap()
        .commit()
        .record
        .encrypted_blob
        .len();
    let value = intent(prepared.clone());
    assert!(value.metadata_fits_profile(
        envelope + CONFIG_CAPACITY_V1_METADATA_BYTES,
        ConfigCapacityProfile::BoundedV1
    ));
    assert!(
        !value.metadata_fits_profile(
            envelope + CONFIG_CAPACITY_V1_METADATA_BYTES + 1,
            ConfigCapacityProfile::BoundedV1
        ),
        "JOINT_EXACT_METADATA"
    );
    assert!(!value.metadata_fits_profile(envelope - 1, ConfigCapacityProfile::BoundedV1));

    // A valid record proof authenticates no audit-size exemption. Grow genuine
    // encoded audit metadata beyond the complete command allowance, preserving
    // the exact record/proof and signing the altered original operation.
    let mut changed = input(&prepared.encode().unwrap());
    let Some(TargetPayloadV1::BoundedRunning(payload)) =
        &mut changed.command_mut().effect.encrypted_payload
    else {
        panic!("bounded fixture")
    };
    let fields = Arc::get_mut(&mut payload.fields).unwrap();
    let tx_id = fields.commit.record.tx_id;
    for sequence in 0..25 {
        fields.commit.audit.push(AuditRecord {
            tx_id,
            sequence,
            yang_path: format!("/{}", "x".repeat(CONFIG_AUDIT_PATH_MAX_BYTES - 1)),
            op_type: crate::AuditOpType::Replace,
            previous_value: None,
            new_value: None,
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        });
    }
    resign(&mut changed);
    changed
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    assert!(
        crate::consensus::store::preflight_joint_target_payload(&changed).is_err(),
        "JOINT_FULL_METADATA"
    );
    let source = serde_json::to_vec(&changed).unwrap();
    let recovered_pool = ConfigPreparationPool::bounded_v1();
    assert!(recover(
        &source,
        recovered_pool.try_reserve().unwrap(),
        &recovered_pool,
        identity(),
        &key(),
        event().caller
    )
    .is_err());
    all_slots_available(&recovered_pool);
}

#[tokio::test]
async fn joint_payload_old_tags_and_encoded_fields_stay_identical() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let commit = prepared.bounded_running().unwrap().commit().clone();
    let blob = TargetEncryptedBlobV1 {
        schema: commit.record.schema_digest,
        plaintext_digest: commit
            .record
            .plaintext_digest
            .as_slice()
            .try_into()
            .unwrap(),
        encrypted_blob: commit.record.encrypted_blob.clone(),
    };
    let binding: crate::consensus::audit_mutation::target_copy::TargetCopyBindingV1 = serde_json::from_value(json!({
        "source_ciphertext_digest": vec![1u8; 32], "source_plaintext_digest": vec![2u8; 32],
        "destination_ciphertext_digest": vec![3u8; 32], "destination_plaintext_digest": vec![4u8; 32], "schema": commit.record.schema_digest
    })).unwrap();
    #[derive(Serialize)]
    #[serde(rename = "TargetPayloadV1", rename_all = "kebab-case")]
    enum Old<'a> {
        Target(&'a TargetEncryptedBlobV1),
        Running {
            commit: &'a PreparedConfigCommit,
            confirmation_ownership: Option<&'a TargetEncryptedBlobV1>,
        },
        ProviderCopy {
            commit: &'a PreparedConfigCommit,
            confirmation_ownership: Option<&'a TargetEncryptedBlobV1>,
            binding: &'a crate::consensus::audit_mutation::target_copy::TargetCopyBindingV1,
        },
    }
    for (ordinal, actual, old) in [
        (0, TargetPayloadV1::Target(blob.clone()), Old::Target(&blob)),
        (
            1,
            TargetPayloadV1::Running {
                commit: Box::new(commit.clone()),
                confirmation_ownership: None,
            },
            Old::Running {
                commit: &commit,
                confirmation_ownership: None,
            },
        ),
        (
            2,
            TargetPayloadV1::ProviderCopy {
                commit: Box::new(commit.clone()),
                confirmation_ownership: Some(blob.clone()),
                binding: binding.clone(),
            },
            Old::ProviderCopy {
                commit: &commit,
                confirmation_ownership: Some(&blob),
                binding: &binding,
            },
        ),
    ] {
        let bytes = opc_consensus::encode_bounded(&actual).unwrap();
        assert_eq!(bytes[0], ordinal);
        assert_eq!(
            bytes,
            opc_consensus::encode_bounded(&old).unwrap(),
            "old postcard bytes"
        );
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&old).unwrap(),
            "old JSON bytes"
        );
        assert!(opc_consensus::decode_bounded::<TargetPayloadV1>(&bytes).unwrap() == actual);
    }
    let bytes = opc_consensus::encode_bounded(
        prepared
            .command()
            .effect
            .encrypted_payload
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bytes[0], 3, "new payload appended after old tags");
}

#[tokio::test]
async fn joint_payload_at_logical_limit_preflights_real_encodings() {
    let pool = ConfigPreparationPool::bounded_v1();
    let mut plaintext = vec![b'x'; opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES];
    plaintext[0] = b'"';
    *plaintext.last_mut().unwrap() = b'"';
    let prepared = signed(payload(&pool, &plaintext).await);
    prepared
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    crate::consensus::store::preflight_joint_target_payload(&prepared)
        .expect("JOINT_LIMIT_REAL_ENCODING");
    let bytes = prepared.encode().unwrap();
    let destination = ConfigPreparationPool::bounded_v1();
    let recovered = recover(
        &bytes,
        destination.try_reserve().unwrap(),
        &destination,
        identity(),
        &key(),
        event().caller,
    )
    .unwrap();
    assert_eq!(recovered.encode().unwrap(), bytes);
    assert_eq!(
        recovered
            .bounded_running()
            .unwrap()
            .commit()
            .record
            .plaintext_digest,
        Sha256::digest(&plaintext).to_vec()
    );
    drop(recovered);
    all_slots_available(&destination);
}

#[test]
fn joint_payload_tag_zero_keeps_fixed_postcard_vector() {
    let payload = TargetPayloadV1::Target(TargetEncryptedBlobV1 {
        schema: SchemaDigest::from_bytes([0x11; 32]),
        plaintext_digest: [0x22; 32],
        encrypted_blob: vec![0x33, 0x44],
    });
    let mut expected = vec![0, 64];
    expected.extend_from_slice("11".repeat(32).as_bytes());
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(&[2, 0x33, 0x44]);
    assert_eq!(
        opc_consensus::encode_bounded(&payload).unwrap(),
        expected,
        "old tag/schema-string/digest/envelope framing vector"
    );
}

// These observations sit immediately before the actual allocating record
// decoders in types.rs. They neither replace parsing nor count invented bytes.
// Recovery is synchronous, so a scope never crosses an async suspension point.
#[derive(Clone, Copy, Default)]
struct RecordDecodeEntries {
    envelope: usize,
    aad: usize,
}

thread_local! {
    static RECORD_DECODE_ENTRIES: std::cell::Cell<Option<RecordDecodeEntries>> =
        const { std::cell::Cell::new(None) };
}

pub(in crate::consensus) fn observe_record_envelope_decode() {
    RECORD_DECODE_ENTRIES.with(|slot| {
        if let Some(mut entries) = slot.get() {
            entries.envelope += 1;
            slot.set(Some(entries));
        }
    });
}

pub(in crate::consensus) fn observe_record_aad_decode() {
    RECORD_DECODE_ENTRIES.with(|slot| {
        if let Some(mut entries) = slot.get() {
            entries.aad += 1;
            slot.set(Some(entries));
        }
    });
}

struct RecordDecodeScope;

impl RecordDecodeScope {
    fn start() -> Self {
        RECORD_DECODE_ENTRIES.with(|slot| {
            assert!(slot.replace(Some(RecordDecodeEntries::default())).is_none());
        });
        Self
    }

    fn finish(self) -> RecordDecodeEntries {
        RECORD_DECODE_ENTRIES.with(|slot| slot.take().expect("active record decode scope"))
    }
}

impl Drop for RecordDecodeScope {
    fn drop(&mut self) {
        RECORD_DECODE_ENTRIES.with(|slot| slot.set(None));
    }
}

fn original_envelope(prepared: &PreparedTargetMutation) -> opc_crypto::CryptoEnvelopeV1 {
    opc_crypto::CryptoEnvelopeV1::decode(
        &prepared
            .bounded_running()
            .unwrap()
            .commit()
            .record
            .encrypted_blob,
    )
    .unwrap()
}

fn assert_recovery_refuses_before_record_decoding(
    original: &PreparedTargetMutation,
    envelope: Vec<u8>,
    case: &str,
) {
    assert!(envelope.len() <= CONFIG_CAPACITY_V1_ENVELOPE_BYTES);
    opc_crypto::CryptoEnvelopeRef::encoded_metadata_lengths(&envelope)
        .expect("malformed metadata still has complete envelope framing");
    let encoded = original.encode().unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    changed["effect"]["encrypted_payload"]["bounded-running"]["commit"]["record"]
        ["encrypted_blob"] = json!(envelope);
    let received = serde_json::to_vec(&changed).unwrap();
    assert!(received.len() < crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES);
    // Exercise the actual typed DTO first, so a framing/visitor refusal cannot
    // masquerade as validation-order evidence. No operation or proof is re-signed.
    assert!(serde_json::from_slice::<Received>(&received).is_ok());

    let destination = ConfigPreparationPool::bounded_v1();
    let other: Vec<_> = (0..7).map(|_| destination.try_reserve().unwrap()).collect();
    let original_reservation = destination.try_reserve().unwrap();
    assert!(destination.try_reserve().is_err());
    let scope = RecordDecodeScope::start();
    let rejected = recover(
        &received,
        original_reservation,
        &destination,
        identity(),
        &key(),
        event().caller,
    );
    let malformed_entries = scope.finish();
    assert!(rejected.is_err(), "JOINT_AAD_REFUSAL: {case}");
    drop(rejected);
    // The seven unrelated leases remain held. The consumed original lease is
    // the only one recover can release, and the next lease must use that slot.
    let released = destination
        .try_reserve()
        .expect("original recovery slot released");
    assert!(destination.try_reserve().is_err());
    drop(released);
    drop(other);
    all_slots_available(&destination);

    // Positive calibration: the same real recovery boundary still enters both
    // decoders for an authentic original. A disconnected counter cannot pass.
    let scope = RecordDecodeScope::start();
    let recovered = recover(
        &encoded,
        destination.try_reserve().unwrap(),
        &destination,
        identity(),
        &key(),
        event().caller,
    )
    .expect("unchanged genuine original recovers");
    let original_entries = scope.finish();
    assert!(original_entries.envelope > 0 && original_entries.aad > 0);
    assert_eq!(recovered.encode().unwrap(), encoded);
    assert_eq!(recovered.handle(), original.handle());
    assert_eq!(
        recovered.command().handle.body.expires_at,
        original.command().handle.body.expires_at
    );
    drop(recovered);
    all_slots_available(&destination);
    eprintln!(
        "JOINT_AAD_PREFLIGHT_ORDER case={case} malformed_envelope_entries={} malformed_aad_entries={} original_envelope_entries={} original_aad_entries={} slots_released=8",
        malformed_entries.envelope,
        malformed_entries.aad,
        original_entries.envelope,
        original_entries.aad,
    );
    // Both versions return Err. These actual boundary observations distinguish
    // refusal before the allocating parsers from their eventual rejection.
    assert_eq!(
        malformed_entries.aad, 0,
        "JOINT_AAD_PREFLIGHT_ORDER: {case}: generic AAD decoder entered"
    );
    assert_eq!(
        malformed_entries.envelope, 0,
        "JOINT_AAD_PREFLIGHT_ORDER: {case}: generic envelope decoder entered"
    );
}

#[tokio::test]
async fn joint_payload_nested_aad_refuses_before_general_decode() {
    let pool = ConfigPreparationPool::bounded_v1();
    let original = signed(payload(&pool, b"null").await);
    let mut envelope = original_envelope(&original);
    let mut aad: serde_json::Value = serde_json::from_slice(&envelope.aad).unwrap();
    aad["metadata"]["principal"] = json!({"nested": [0, 1, 2]});
    envelope.aad = serde_json::to_vec(&aad).unwrap();
    assert!(envelope.aad.len() < opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES);
    let encoded = envelope.encode().unwrap();
    assert_eq!(
        opc_crypto::CryptoEnvelopeRef::encoded_metadata_lengths(&encoded).unwrap(),
        (envelope.key_id.as_str().len(), envelope.aad.len())
    );
    assert_recovery_refuses_before_record_decoding(&original, encoded, "nested-metadata");
}

#[tokio::test]
async fn joint_payload_oversize_aad_refuses_before_general_decode() {
    let pool = ConfigPreparationPool::bounded_v1();
    let original = signed(payload(&pool, b"null").await);
    let mut envelope = original_envelope(&original);
    let mut aad: serde_json::Value = serde_json::from_slice(&envelope.aad).unwrap();
    aad["metadata"]["store_kind"] = json!("x");
    let one_byte_size = serde_json::to_vec(&aad).unwrap().len();
    let extent = opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES + 1;
    aad["metadata"]["store_kind"] = json!("x".repeat(extent - one_byte_size + 1));
    envelope.aad = serde_json::to_vec(&aad).unwrap();
    assert_eq!(envelope.aad.len(), extent);
    let encoded = envelope.encode().unwrap();
    assert_eq!(
        opc_crypto::CryptoEnvelopeRef::encoded_metadata_lengths(&encoded)
            .unwrap()
            .1,
        extent,
        "the header declares the actual one-over AAD extent"
    );
    assert_recovery_refuses_before_record_decoding(&original, encoded, "aad-one-over");
}

#[tokio::test]
async fn joint_payload_oversize_header_refuses_before_general_decode() {
    let pool = ConfigPreparationPool::bounded_v1();
    let original = signed(payload(&pool, b"null").await);
    let original_bytes = &original
        .bounded_running()
        .unwrap()
        .commit()
        .record
        .encrypted_blob;
    let (key_bytes, aad_bytes) =
        opc_crypto::CryptoEnvelopeRef::encoded_metadata_lengths(original_bytes).unwrap();
    // A public KeyId cannot construct this deliberately rejected length. Retain
    // the original nonce/AAD/ciphertext and change only framed header-key bytes.
    let mut encoded = original_bytes[..16].to_vec();
    encoded[8..10].copy_from_slice(&513u16.to_be_bytes());
    encoded.extend_from_slice(&[b'k'; 513]);
    encoded.extend_from_slice(&original_bytes[16 + key_bytes..]);
    assert_eq!(
        opc_crypto::CryptoEnvelopeRef::encoded_metadata_lengths(&encoded).unwrap(),
        (513, aad_bytes)
    );
    assert_recovery_refuses_before_record_decoding(&original, encoded, "header-key-one-over");
}

// The native ownership detector uses the same real preparation, with the
// destination's independently selected identity/key. It does not open joint mode.
#[cfg(target_os = "linux")]
pub(in crate::consensus) async fn prepared_for_store(
    pool: &ConfigPreparationPool,
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
) -> PreparedTargetMutation {
    signed_for(
        payload_for(pool, br#"{"enabled":true}"#, identity, key).await,
        identity,
        key,
    )
}

// Real bounded encryption with independently supplied identity/key and size.
#[cfg(target_os = "linux")]
pub(in crate::consensus) async fn prepared_for_history_gate(
    pool: &ConfigPreparationPool,
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
    plaintext: &[u8],
) -> PreparedTargetMutation {
    signed_for(
        payload_for(pool, plaintext, identity, key).await,
        identity,
        key,
    )
}

#[path = "joint_target_submission_tests.rs"]
mod submission;

#[path = "joint_target_retained_recovery_tests.rs"]
pub(in crate::consensus) mod retained_recovery;

#[path = "joint_native_cost_tests.rs"]
mod native_cost;

#[path = "joint_native_route_tests.rs"]
pub(in crate::consensus) mod native_route;
