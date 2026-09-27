//! Real codec equivalence and inclusive encoding boundaries. These tests do
//! not open a larger-profile store or qualify native cluster/storage behavior.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::{ConfigConsensusCommand, ConfigRaftTypeConfig, PreparedConfigCommit};
use opc_consensus::engine::raft::AppendEntriesRequest;
use opc_consensus::engine::{Entry, EntryPayload};
use opc_consensus::{decode_bounded, encode_bounded, ConsensusIdentity, ConsensusRequestId};
use sha2::{Digest, Sha256};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

#[path = "config_capacity_decoding_tests.rs"]
mod decoding;

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0x31; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x32; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).expect("epoch"),
    )
}

fn key() -> crate::AuditKey {
    crate::AuditKey::new([0x33; 32]).expect("synthetic key")
}

fn command(logical_bytes: usize) -> ConfigConsensusCommand {
    let (mut record, _, _) = super::super::tests::sized_attested_commit(32).into_parts();
    let mut plaintext = vec![b'x'; logical_bytes];
    plaintext[0] = b'"';
    plaintext[logical_bytes - 1] = b'"';
    let aad = opc_key::EnvelopeAad::config(
        opc_types::TenantId::from_static("test"),
        record.version.get(),
        opc_key::ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("config-capacity-encoding").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        opc_types::TenantId::from_static("test"),
        opc_key::Zeroizing::new([0x34; 32]),
    );
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle, &aad, &plaintext, [0x35; 12],
    )
    .expect("genuine bounded encryption");
    let decoded = opc_crypto::decrypt_envelope_with_handle(&handle, &aad, envelope.encoded())
        .expect("authenticated plaintext readback");
    assert_eq!(decoded.as_slice(), plaintext);
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let attested = crate::AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        envelope
            .claim()
            .expect("one-shot exact encryption evidence"),
    )
    .expect("paired attestation");
    assert_eq!(
        attested
            .capacity_evidence()
            .expect("bounded evidence")
            .logical_bytes(),
        logical_bytes
    );
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE)
        .expect("genuine retained capacity proof");
    let (record, audit, resolution) = attested.into_parts();
    let commit = PreparedConfigCommit::prepare(record, audit, &key()).expect("prepared commit");
    ConfigConsensusCommand {
        schema_version: 8,
        identity: identity(),
        request_id: ConsensusRequestId::from_bytes([0x36; 16]),
        logical_time: super::super::maximum_encoded_config_timestamp().expect("longest timestamp"),
        intent: ConfigMutationIntent::prepared_append(commit, resolution, Some(binding)),
    }
}

fn probe(command: &ConfigConsensusCommand) -> ConfigConsensusCommandSizeProbe<'_> {
    ConfigConsensusCommandSizeProbe {
        schema_version: command.schema_version,
        identity: command.identity,
        request_id: command.request_id,
        logical_time: command.logical_time,
        intent: &command.intent,
    }
}

#[test]
fn capacity_borrowed_shapes_match_owned_engine_and_forwarding_encoders() {
    let command = command(128);
    let probe = probe(&command);
    assert_eq!(
        encode_bounded(&probe).unwrap(),
        encode_bounded(&command).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&probe).unwrap(),
        serde_json::to_vec(&command).unwrap()
    );
    let node = ConsensusNodeId::new(CONSENSUS_NODE_ID_MAX).unwrap();
    let log_id = LogId::new(CommittedLeaderId::new(u64::MAX, node), u64::MAX);
    let vote = Vote::new_committed(u64::MAX, node);
    let owned = Entry::<ConfigRaftTypeConfig> {
        log_id,
        payload: EntryPayload::Normal(command.clone()),
    };
    let borrowed = BorrowedEntry {
        log_id,
        payload: BorrowedNormal(&probe),
    };
    let json = serde_json::to_vec(&owned).unwrap();
    assert_eq!(serde_json::to_vec(&borrowed).unwrap(), json);
    assert_eq!(json_size(&borrowed, json.len()), Ok(json.len()));
    assert_eq!(
        encode_bounded(&borrowed).unwrap(),
        encode_bounded(&owned).unwrap()
    );
    let entries = [borrowed];
    let borrowed_append = BorrowedAppend {
        vote,
        prev_log_id: Some(log_id),
        entries: &entries,
        leader_commit: Some(log_id),
    };
    let owned_append = AppendEntriesRequest::<ConfigRaftTypeConfig> {
        vote,
        prev_log_id: Some(log_id),
        entries: vec![owned],
        leader_commit: Some(log_id),
    };
    let compatibility = ConfigPeerCompatibility {
        wire_version: config_wire_revision(PROFILE),
        command_version: 8,
        audit_key_epoch: u64::MAX,
        audit_key_fingerprint: [u8::MAX; 32],
    };
    let budget = ForwardedBudget {
        remaining_nanos: 60_000_000_000,
    };
    let borrowed_forward = BorrowedForward {
        request_id: command.request_id,
        intent: &command.intent,
        compatibility,
        budget,
    };
    let owned_forward = super::super::ForwardMutationRequest {
        request_id: command.request_id,
        intent: command.intent.clone(),
        compatibility,
        budget,
    };
    for profile in [ConfigCapacityProfile::Legacy, PROFILE] {
        assert_eq!(
            encode_bounded(&BorrowedWire {
                revision: config_wire_revision(profile),
                value: &borrowed_append
            })
            .unwrap(),
            crate::consensus::types::encode_config_wire_for_profile(profile, &owned_append)
                .unwrap()
        );
        assert_eq!(
            encode_bounded(&BorrowedWire {
                revision: config_wire_revision(profile),
                value: &borrowed_forward
            })
            .unwrap(),
            crate::consensus::types::encode_config_wire_for_profile(profile, &owned_forward)
                .unwrap()
        );
    }
    let actual = preflight(&probe, PROFILE).expect("complete preflight");
    assert_eq!(actual.command, encode_bounded(&command).unwrap().len());
    assert_eq!(actual.durable_json, json.len());
    assert_eq!(
        actual.forwarded,
        crate::consensus::types::encode_config_wire_for_profile(PROFILE, &owned_forward)
            .unwrap()
            .len()
    );
    assert_eq!(
        actual.singleton,
        crate::consensus::types::encode_config_wire_for_profile(PROFILE, &owned_append)
            .unwrap()
            .len()
    );
}

#[test]
fn capacity_at_logical_limit_fits_all_real_encodings_with_maximum_engine_framing() {
    // This exercises an actual encrypted, attested and decoded command. It
    // proves only encoding admission, not store enablement or cluster success.
    let command = command(1_572_864);
    let encoded = encode_bounded(&command).expect("real large command encoding");
    assert!(encoded.len() > 1_048_576);
    let decoded: ConfigConsensusCommand = decode_bounded(&encoded).expect("real command decoding");
    decoded
        .validate_for_profile(identity(), &key(), PROFILE)
        .expect("received preflight and proof");
    let sizes = preflight(&probe(&decoded), PROFILE).expect("all encoding budgets");
    assert!(sizes.command <= 1_966_080);
    assert!(sizes.forwarded <= 2_097_152);
    assert!(sizes.singleton <= 2_097_152);
    assert!(sizes.durable_json <= 16_777_216);
    assert_eq!(sizes.command, encoded.len());
    assert!(
        super::super::preflight_config_command_replication_budget(
            identity(),
            command.request_id,
            &command.intent,
            ConfigCapacityProfile::Legacy
        )
        .is_err(),
        "legacy command fence remains one MiB"
    );
    assert!(!super::super::config_command_fits_replication_budget(
        &command,
        ConfigCapacityProfile::Legacy
    ));
    eprintln!(
        "CAPACITY_ENCODING_BYTES command={} forwarded={} singleton={} durable_json={}",
        sizes.command, sizes.forwarded, sizes.singleton, sizes.durable_json
    );
}

#[test]
fn capacity_encoding_ceilings_are_inclusive_and_do_not_depend_on_component_reachability() {
    // The independent component ceilings reject before the full command/JSON
    // ceilings become reachable. Exercise those encoders directly as required
    // by the RFC, without calling the synthetic payload a valid configuration.
    for limit in [1_966_080, 2_097_152] {
        let mut bytes = vec![u8::MAX; limit - 3];
        assert_eq!(postcard_size(&bytes, limit), Ok(limit));
        assert_eq!(encode_bounded(&bytes).unwrap().len(), limit);
        bytes.push(u8::MAX);
        assert_eq!(
            postcard_size(&bytes, limit),
            Err(ForwardMutationRejection::CommandTooLarge)
        );
    }
    let mut json_text = "x".repeat(16_777_216 - 2);
    assert_eq!(json_size(&json_text, 16_777_216), Ok(16_777_216));
    json_text.push('x');
    assert_eq!(
        json_size(&json_text, 16_777_216),
        Err(ForwardMutationRejection::CommandTooLarge)
    );
    let escaping = "\0\n\"\\\u{0001}".repeat(1024);
    let actual = serde_json::to_vec(&escaping).unwrap();
    assert_eq!(json_size(&escaping, actual.len()), Ok(actual.len()));
    assert_eq!(
        json_size(&escaping, actual.len() - 1),
        Err(ForwardMutationRejection::CommandTooLarge)
    );
    let mut overflow = JsonSize {
        bytes: usize::MAX,
        limit: usize::MAX,
        exceeded: false,
    };
    assert!(overflow.write(&[0]).is_err());
    assert!(overflow.exceeded);
}

#[test]
fn capacity_streamed_effect_mac_matches_original_for_every_variant_and_rejects_tampering() {
    use crate::audit_authority::ledger::{authenticate, verify};
    use crate::audit_authority::AuditAuthorityError;
    use crate::consensus::audit_mutation::AuditedConfigEffect;
    use crate::consensus::types::ValidatedRollbackLabel;
    use crate::ConfirmedCommitResolution;

    const DOMAIN: &[u8] = b"openpacketcore/management-audit/config-mutation/v1\0";
    let command = command(1_572_864);
    let ConfigMutationIntent::BoundedAppend {
        commit, binding, ..
    } = command.intent
    else {
        panic!("genuine bounded append fixture");
    };
    let tx_id = commit.record.tx_id;
    let mut effects = vec![
        AuditedConfigEffect::Confirm { tx_id },
        AuditedConfigEffect::RollbackPoint { tx_id, label: None },
        AuditedConfigEffect::RollbackPoint {
            tx_id,
            label: Some(ValidatedRollbackLabel::try_new("capacity-label".to_owned()).unwrap()),
        },
    ];
    // These are MAC transcript compatibility cases, including every optional
    // resolution representation; they grant no mutation or parent authority.
    for resolution in [
        None,
        Some(ConfirmedCommitResolution::Confirm {
            pending_tx_id: tx_id,
        }),
        Some(ConfirmedCommitResolution::Rollback {
            pending_tx_id: tx_id,
        }),
    ] {
        effects.push(AuditedConfigEffect::Append {
            commit: commit.clone(),
            resolution,
        });
        effects.push(AuditedConfigEffect::BoundedAppend {
            commit: commit.clone(),
            binding,
            resolution,
        });
    }
    let wrong_key = crate::AuditKey::new([0x47; 32]).unwrap();
    for effect in &effects {
        let original = authenticate(&key(), DOMAIN, effect).unwrap();
        let streamed = effect.digest(&key()).unwrap();
        assert_eq!(streamed, original, "unchanged authenticated transcript");
        effect.verify(&key(), &original).unwrap();
        verify(&key(), DOMAIN, effect, &streamed).unwrap();
        assert_eq!(
            effect.verify(&wrong_key, &original),
            Err(AuditAuthorityError::BindingMismatch)
        );
        let mut altered_mac = original;
        altered_mac[31] ^= 1;
        assert_eq!(
            effect.verify(&key(), &altered_mac),
            Err(AuditAuthorityError::BindingMismatch)
        );
        let other = if matches!(effect, AuditedConfigEffect::Confirm { .. }) {
            &effects[1]
        } else {
            &effects[0]
        };
        assert_eq!(
            other.verify(&key(), &original),
            Err(AuditAuthorityError::BindingMismatch)
        );
    }
}

#[path = "config_capacity_command_buffer_tests.rs"]
mod command_buffers;

#[path = "config_capacity_engine_decoding_tests.rs"]
mod engine_decoding;

#[test]
fn capacity_final_command_admission_uses_the_independent_store_profile() {
    let command = command(opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    command
        .validate_for_profile(identity(), &key(), PROFILE)
        .unwrap();
    let actual = encode_bounded(&command).expect("real complete command");
    assert!(actual.len() > opc_consensus::DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
    assert!(actual.len() <= CONFIG_CAPACITY_V1_COMMAND_BYTES);
    assert!(super::super::config_command_fits_replication_budget(
        &command, PROFILE
    ));
    assert!(!super::super::config_command_fits_replication_budget(
        &command,
        ConfigCapacityProfile::Legacy,
    ));
}
