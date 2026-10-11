use super::support::*;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::types::*;
use crate::consensus::PreparedAuditedMutation;
use crate::*;
use hmac::{Hmac, KeyInit, Mac};
use opc_crypto::{
    ConfigCapacityProfile, CONFIG_CAPACITY_V1_LOGICAL_BYTES, CONFIG_CAPACITY_V1_REPLAY_BYTES,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

fn fields(
    command: &ConfigConsensusCommand,
) -> (
    &PreparedConfigCommit,
    CapacityRecordBinding,
    Option<ConfirmedCommitResolution>,
) {
    match &command.intent {
        ConfigMutationIntent::BoundedAppend {
            commit,
            binding,
            resolution,
        } => (commit, *binding, *resolution),
        ConfigMutationIntent::AuditedMutation(prepared) => {
            let AuditedConfigEffect::BoundedAppend {
                commit,
                binding,
                resolution,
            } = &prepared.effect
            else {
                panic!("bounded effect")
            };
            (commit, *binding, *resolution)
        }
        _ => panic!("bounded intent"),
    }
}

fn replace(
    command: &mut ConfigConsensusCommand,
    commit: PreparedConfigCommit,
    binding: CapacityRecordBinding,
) {
    match &mut command.intent {
        ConfigMutationIntent::BoundedAppend {
            commit: old,
            binding: proof,
            ..
        } => {
            **old = commit;
            *proof = binding;
        }
        ConfigMutationIntent::AuditedMutation(prepared) => {
            let AuditedConfigEffect::BoundedAppend {
                commit: old,
                binding: proof,
                ..
            } = &mut prepared.effect
            else {
                panic!("bounded effect")
            };
            **old = commit;
            *proof = binding;
            prepared.handle = handle(Some(&prepared.effect));
        }
        _ => panic!("bounded intent"),
    }
}

// An independent borrowing wire encoder fixes tags and field order explicitly.
// There are no duplicate accepting enum variants or production decode routes.
struct ReferenceIntent<'a>(&'a ConfigConsensusCommand);
impl Serialize for ReferenceIntent<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        let (commit, binding, resolution) = fields(self.0);
        if let ConfigMutationIntent::AuditedMutation(prepared) = &self.0.intent {
            #[derive(Serialize)]
            #[serde(rename = "PreparedAuditedMutation")]
            struct Prepared<'a> {
                handle: &'a crate::audit_authority::AuditOperationHandle,
                effect: ReferenceEffect<'a>,
            }
            s.serialize_newtype_variant(
                "ConfigMutationIntent",
                7,
                "AuditedMutation",
                &Prepared {
                    handle: &prepared.handle,
                    effect: ReferenceEffect {
                        commit,
                        binding,
                        resolution,
                    },
                },
            )
        } else {
            let mut fields =
                s.serialize_struct_variant("ConfigMutationIntent", 8, "BoundedAppend", 3)?;
            fields.serialize_field("commit", commit)?;
            fields.serialize_field("binding", &binding)?;
            fields.serialize_field("resolution", &resolution)?;
            fields.end()
        }
    }
}

struct ReferenceEffect<'a> {
    commit: &'a PreparedConfigCommit,
    binding: CapacityRecordBinding,
    resolution: Option<ConfirmedCommitResolution>,
}
impl Serialize for ReferenceEffect<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        let mut fields =
            s.serialize_struct_variant("AuditedConfigEffect", 3, "BoundedAppend", 3)?;
        fields.serialize_field("commit", self.commit)?;
        fields.serialize_field("binding", &self.binding)?;
        fields.serialize_field("resolution", &self.resolution)?;
        fields.end()
    }
}

#[derive(Serialize)]
#[serde(rename = "ConfigConsensusCommand")]
struct ReferenceCommand<'a> {
    schema_version: u16,
    identity: ConfigConsensusIdentity,
    request_id: ConfigConsensusRequestId,
    logical_time: opc_types::Timestamp,
    intent: ReferenceIntent<'a>,
}

#[test]
fn ordinary_and_audited_bytes_tags_and_digests_are_exact() {
    for audited in [false, true] {
        for resolution in [
            None,
            Some(ConfirmedCommitResolution::Confirm {
                pending_tx_id: parent(),
            }),
            Some(ConfirmedCommitResolution::Rollback {
                pending_tx_id: parent(),
            }),
        ] {
            let command = bounded_command(audited, resolution);
            command
                .validate_bounded_representation(identity(), &key(), PROFILE)
                .unwrap();
            let reference = ReferenceCommand {
                schema_version: 8,
                identity: identity(),
                request_id: command.request_id,
                logical_time: timestamp(),
                intent: ReferenceIntent(&command),
            };
            let binary = opc_consensus::encode_bounded(&command).unwrap();
            assert_eq!(binary, opc_consensus::encode_bounded(&reference).unwrap());
            assert_eq!(
                serde_json::to_vec(&command).unwrap(),
                serde_json::to_vec(&reference).unwrap()
            );
            let mut hash = Sha256::new();
            hash.update(b"openpacketcore/config-consensus/outcome/v1\0");
            hash.update(
                serde_json::to_vec(&(8_u16, identity(), ReferenceIntent(&command))).unwrap(),
            );
            assert_eq!(
                command.payload_digest().unwrap().as_slice(),
                hash.finalize().as_slice()
            );
            let previous = ConfigConsensusEntryDigest::from_bytes([16; 32]);
            let mut hash = Sha256::new();
            hash.update(b"openpacketcore/config-consensus/command/v1\0");
            hash.update(serde_json::to_vec(&(17_u64, previous, timestamp(), &reference)).unwrap());
            assert_eq!(
                command
                    .calculate_applied_digest(17, previous, timestamp())
                    .unwrap()
                    .as_bytes(),
                hash.finalize().as_slice()
            );
            if let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent {
                let (commit, binding, resolution) = fields(&command);
                let effect = serde_json::to_vec(&ReferenceEffect {
                    commit,
                    binding,
                    resolution,
                })
                .unwrap();
                let mut mac = Hmac::<Sha256>::new_from_slice(key().as_bytes()).unwrap();
                mac.update(b"openpacketcore/management-audit/config-mutation/v1\0");
                mac.update(&(effect.len() as u64).to_be_bytes());
                mac.update(&effect);
                assert_eq!(
                    prepared.effect.digest(&key()).unwrap().as_slice(),
                    mac.finalize().into_bytes().as_slice()
                );
                assert_eq!(
                    prepared.encode().unwrap(),
                    serde_json::to_vec(prepared).unwrap()
                );
            }
        }
    }
}

#[test]
fn legacy_decoders_and_validation_refuse_both_new_tags() {
    use opc_consensus::ConsensusCodecError;
    for audited in [false, true] {
        let command = bounded_command(audited, None);
        let binary = opc_consensus::encode_bounded(&command).unwrap();
        assert_eq!(
            opc_consensus::decode_bounded::<ConfigConsensusCommand>(&binary),
            Err(ConsensusCodecError::Decode)
        );
        let wire = encode_config_wire(&command).unwrap();
        assert_eq!(
            decode_config_wire::<ConfigConsensusCommand>(&wire),
            Err(ConsensusCodecError::Decode)
        );
        let json = serde_json::to_vec(&command).unwrap();
        let error = serde_json::from_slice::<ConfigConsensusCommand>(&json).unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown variant `BoundedAppend`"));
        for revision in 1..=8 {
            let changed = ConfigConsensusCommand {
                schema_version: revision,
                ..command.clone()
            };
            assert_eq!(
                changed.validate(identity()).unwrap_err().to_string(),
                PersistError::inconsistent_state(
                    "config consensus command scope or revision mismatch"
                )
                .to_string()
            );
        }
        if let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent {
            assert_eq!(
                PreparedAuditedMutation::decode(&prepared.encode().unwrap()).unwrap_err(),
                crate::audit_authority::AuditAuthorityError::InvalidInput
            );
        }
    }
    assert_eq!(
        (
            CONFIG_CONSENSUS_COMMAND_VERSION,
            CONFIG_CONSENSUS_WIRE_VERSION,
            CONFIG_CONSENSUS_STORAGE_VERSION,
            CONFIG_CONSENSUS_SNAPSHOT_VERSION
        ),
        (7, 7, 6, 6)
    );
}

#[test]
fn bounded_command_rejects_scope_profile_key_proof_and_resolution_substitution() {
    for audited in [false, true] {
        let command = bounded_command(audited, None);
        assert!(command
            .validate_bounded_representation(identity(), &key(), ConfigCapacityProfile::Legacy)
            .is_err());
        assert!(command
            .validate_bounded_representation(identity(), &AuditKey::new([99; 32]).unwrap(), PROFILE)
            .is_err());
        let foreign = ConfigConsensusIdentity::new(
            identity().cluster_id(),
            ConfigConsensusConfigurationId::from_bytes([99; 32]),
            identity().configuration_epoch(),
        );
        assert!(command
            .validate_bounded_representation(foreign, &key(), PROFILE)
            .is_err());
        for revision in [0, 7, 9, 10, u16::MAX] {
            let changed = ConfigConsensusCommand {
                schema_version: revision,
                ..command.clone()
            };
            assert!(changed
                .validate_bounded_representation(identity(), &key(), PROFILE)
                .is_err());
        }
        let other = bounded_attested(33, 64);
        let wrong_proof = CapacityRecordBinding::issue(&other, identity(), &key()).unwrap();
        let mut changed = command.clone();
        replace(&mut changed, fields(&command).0.clone(), wrong_proof);
        assert!(changed
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .is_err());
        let invalid_resolution = bounded_command(
            audited,
            Some(ConfirmedCommitResolution::Confirm {
                pending_tx_id: tx(),
            }),
        );
        assert!(invalid_resolution
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .is_err());
    }
    let legacy = command(ConfigMutationIntent::AppendCommit(Box::new(prepared())));
    assert!(ConfigConsensusCommand {
        schema_version: 8,
        ..legacy
    }
    .validate_bounded_representation(identity(), &key(), PROFILE)
    .is_err());
}

#[test]
fn bounded_command_rejects_a_signed_handle_for_another_effect() {
    let mut command = bounded_command(true, None);
    command
        .validate_bounded_representation(identity(), &key(), PROFILE)
        .unwrap();
    let ConfigMutationIntent::AuditedMutation(prepared) = &mut command.intent else {
        unreachable!()
    };
    let mut body = prepared.handle.body.clone();
    body.mutation = Some([99; 32]);
    prepared.handle = crate::audit_authority::AuditOperationHandle::issue(body, &key()).unwrap();
    // Re-sign the handle so its own authentication cannot mask a wrong effect
    // digest. No record, scope, profile or command metadata changes.
    prepared
        .handle
        .verify(&key(), identity(), prepared.handle.body.binding.caller)
        .unwrap();
    assert_eq!(
        prepared.verify_effect(&key()),
        Err(crate::audit_authority::AuditAuthorityError::BindingMismatch)
    );
    assert!(command
        .validate_bounded_representation(identity(), &key(), PROFILE)
        .is_err());
}

#[test]
fn complete_metadata_limit_counts_real_ordinary_and_audited_commands() {
    for audited in [false, true] {
        let mut command = bounded_command(audited, None);
        let (base, binding, _) = fields(&command);
        let mut commit = base.clone();
        // Use real finalized audit entries. Grow their already-safe paths to
        // place the actual complete postcard command exactly on the boundary.
        let entry = commit.audit[0].clone();
        commit.audit = (0..25)
            .map(|sequence| {
                let mut entry = entry.clone();
                entry.sequence = sequence;
                entry.yang_path = "/".to_owned() + &"p".repeat(7000);
                entry.previous_hash = [0; 32];
                entry.entry_hmac = [0; 32];
                entry
            })
            .collect();
        replace(&mut command, commit.clone(), binding);
        let envelope_length = commit.record.encrypted_blob.len();
        let current = opc_consensus::encode_bounded(&command).unwrap().len() - envelope_length;
        let remaining = CONFIG_CAPACITY_V1_METADATA_BYTES - current;
        let mut left = remaining;
        for entry in &mut commit.audit {
            let extra = left.min(8000 - entry.yang_path.len());
            entry.yang_path.push_str(&"p".repeat(extra));
            left -= extra;
        }
        assert_eq!(left, 0);
        commit = PreparedConfigCommit::prepare(commit.record, commit.audit, &key()).unwrap();
        replace(&mut command, commit.clone(), binding);
        assert_eq!(
            opc_consensus::encode_bounded(&command).unwrap().len() - envelope_length,
            CONFIG_CAPACITY_V1_METADATA_BYTES
        );
        command
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .unwrap();
        // The final entry still has room within the independent path bound.
        commit.audit.last_mut().unwrap().yang_path.push('p');
        commit = PreparedConfigCommit::prepare(commit.record, commit.audit, &key()).unwrap();
        replace(&mut command, commit, binding);
        assert_eq!(
            opc_consensus::encode_bounded(&command).unwrap().len() - envelope_length,
            CONFIG_CAPACITY_V1_METADATA_BYTES + 1
        );
        assert!(command
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .is_err());
    }
}

#[test]
fn maximum_plaintext_flows_through_each_real_command_kind() {
    let attested = bounded_attested(
        CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        CONFIG_CAPACITY_V1_REPLAY_BYTES,
    );
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key()).unwrap();
    let commit = PreparedConfigCommit::prepare(attested.record().clone(), audit(), &key()).unwrap();
    for audited in [false, true] {
        let mut command = bounded_command(audited, None);
        replace(&mut command, commit.clone(), binding);
        command
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .unwrap();
        let bytes = opc_consensus::encode_bounded(&command).unwrap();
        assert!(bytes.len() > opc_consensus::DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
        assert!(bytes.len() <= opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/config-consensus/outcome/v1\0");
        hash.update(serde_json::to_vec(&(8_u16, identity(), &command.intent)).unwrap());
        assert_eq!(
            command.payload_digest().unwrap().as_slice(),
            hash.finalize().as_slice()
        );
    }
}

#[test]
fn audit_handle_authenticates_mutable_projections_and_exact_effect() {
    for field in 0..5 {
        let mut command = bounded_command(true, None);
        let ConfigMutationIntent::AuditedMutation(prepared) = &mut command.intent else {
            unreachable!()
        };
        let AuditedConfigEffect::BoundedAppend {
            commit,
            binding,
            resolution,
        } = &mut prepared.effect
        else {
            unreachable!()
        };
        match field {
            0 => commit.record.source = CommitSource::Rollback,
            1 => commit.record.rollback_point = !commit.record.rollback_point,
            2 => commit.record.confirmed_deadline = Some(timestamp()),
            3 => commit.audit[0].yang_path = "/changed:path".into(),
            4 => {
                *resolution = Some(ConfirmedCommitResolution::Rollback {
                    pending_tx_id: parent(),
                })
            }
            _ => unreachable!(),
        }
        // All independent structure, record-proof and handle checks still pass;
        // only the binding of this handle to these exact effect bytes can reject.
        binding
            .verify(&commit.record, identity(), &key(), PROFILE)
            .unwrap();
        commit.validate().unwrap();
        prepared
            .handle
            .verify(&key(), identity(), prepared.handle.body.binding.caller)
            .unwrap();
        assert!(prepared.verify_effect(&key()).is_err());
        assert!(command
            .validate_bounded_representation(identity(), &key(), PROFILE)
            .is_err());
    }
}
