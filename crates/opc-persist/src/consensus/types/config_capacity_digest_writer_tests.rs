//! Independent compact-JSON/SHA oracles for the two existing command domains.
//! Native lifecycle cost assertions live with the real request observations.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::types::CommitSource;
use crate::{AttestedConfigCommit, AuditKey};
use opc_crypto::ConfigCapacityProfile;
use opc_types::{ConfigVersion, SchemaDigest, TenantId};
use std::io::Write as _;
use std::str::FromStr;

fn original_digest<T: Serialize>(domain: &[u8], value: &T) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(serde_json::to_vec(value).expect("independent compact JSON"));
    hasher.finalize().into()
}

fn require_original_transcripts(command: &ConfigConsensusCommand, semantic_revision: u16) {
    require_original_transcripts_at(
        command,
        semantic_revision,
        17,
        ConfigConsensusEntryDigest::from_bytes([0xA1; 32]),
        Timestamp::from_str("2026-01-01T00:00:02Z").expect("synthetic time"),
    );
}

fn require_original_transcripts_at(
    command: &ConfigConsensusCommand,
    semantic_revision: u16,
    sequence: u64,
    previous: ConfigConsensusEntryDigest,
    effective_time: Timestamp,
) {
    // Literal domains and independently selected semantic revision prevent the
    // oracle from accepting a changed domain or replay-version policy.
    assert_eq!(
        command.payload_digest().expect("real outcome digest"),
        original_digest(
            b"openpacketcore/config-consensus/outcome/v1\0",
            &(semantic_revision, command.identity, &command.intent),
        ),
        "CONFIG_CAPACITY_COMMAND_DIGEST_BYTES_RED: exact outcome transcript"
    );
    assert_eq!(
        command
            .calculate_applied_digest(sequence, previous, effective_time)
            .expect("real applied digest"),
        ConfigConsensusEntryDigest::from_bytes(original_digest(
            b"openpacketcore/config-consensus/command/v1\0",
            &(sequence, previous, effective_time, command),
        )),
        "CONFIG_CAPACITY_COMMAND_DIGEST_BYTES_RED: exact applied transcript"
    );
    let expected_outcome =
        serde_json::to_vec(&(semantic_revision, command.identity, &command.intent))
            .expect("independent outcome transcript");
    let expected_applied = serde_json::to_vec(&(sequence, previous, effective_time, command))
        .expect("independent applied transcript");
    let mut outcome = Vec::new();
    let mut applied = Vec::new();
    config_capacity_joint_digest::write_transcripts(
        command,
        sequence,
        previous,
        effective_time,
        &mut outcome,
        &mut applied,
    )
    .expect("real paired transcript writer");
    assert_eq!(outcome, expected_outcome, "exact shared outcome JSON bytes");
    assert_eq!(applied, expected_applied, "exact shared applied JSON bytes");
    let (outcome, applied) = command
        .payload_and_applied_digests(sequence, previous, effective_time)
        .expect("real paired digests");
    assert_eq!(
        outcome,
        original_digest(
            b"openpacketcore/config-consensus/outcome/v1\0",
            &(semantic_revision, command.identity, &command.intent),
        )
    );
    assert_eq!(
        applied,
        ConfigConsensusEntryDigest::from_bytes(original_digest(
            b"openpacketcore/config-consensus/command/v1\0",
            &(sequence, previous, effective_time, command),
        ))
    );
}

#[test]
fn config_capacity_command_digest_writer_preserves_bytes_and_batches_actual_sha_updates() {
    for length in [0, 1, 255, 4095, 4096, 4097, 8192, 8193] {
        let bytes: Vec<u8> = (0..=255).cycle().take(length).collect();
        for chunk_size in [1, 3, 257, 4096, 6000] {
            let mut hasher = Sha256::new();
            let (observed_bytes, updates) = {
                let mut writer = ConfigDigestWriter::new(&mut hasher);
                assert_eq!(writer.write(&[]).expect("empty write"), 0);
                for chunk in bytes.chunks(chunk_size) {
                    writer.write_all(chunk).expect("synthetic chunk");
                }
                writer.flush().expect("last partial chunk");
                writer.flush().expect("idempotent flush");
                (writer.sink.bytes, writer.sink.updates)
            };
            let actual: [u8; 32] = hasher.finalize().into();
            let expected: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(actual, expected, "exact bytes for every caller split");
            assert_eq!(observed_bytes, length, "every input byte reaches SHA once");
            assert_eq!(
                updates,
                length.div_ceil(4096),
                "CONFIG_CAPACITY_COMMAND_DIGEST_DISPATCH_RED: actual SHA updates, after byte equality; length={length} chunk_size={chunk_size}"
            );
        }
    }
    let mut hasher = Sha256::new();
    {
        let mut writer = ConfigDigestWriter::new(&mut hasher);
        writer.write_all(b"before").expect("first partial chunk");
        writer.flush().expect("midstream flush");
        writer.write_all(b"after").expect("new partial chunk");
        writer.flush().expect("last flush");
        assert_eq!(writer.sink.bytes, 11);
        assert_eq!(writer.sink.updates, 2);
    }
    assert_eq!(hasher.finalize(), Sha256::digest(b"beforeafter"));
}

struct Fixture {
    command: ConfigConsensusCommand,
    audit_key: AuditKey,
    key: opc_key::KeyHandle,
    aad: opc_key::EnvelopeAad,
    plaintext: Vec<u8>,
}

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xA2; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xA3; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    )
}

fn fixture(profile: ConfigCapacityProfile) -> Fixture {
    fixture_with_parent(profile, None)
}

fn fixture_with_parent(profile: ConfigCapacityProfile, parent: Option<TxId>) -> Fixture {
    let bounded = profile == ConfigCapacityProfile::BoundedV1;
    let version = if parent.is_some() { 2 } else { 1 };
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0xA4));
    let committed_at = Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time");
    let principal = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config";
    let schema_digest = SchemaDigest::from_bytes([0xA5; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        opc_key::ConfigAad::new(
            tx_id,
            parent,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let key = opc_key::KeyHandle::new(
        opc_key::KeyId::new("command-digest-fixture").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([if bounded { 0xA6 } else { 0xA7 }; 32]),
    );
    let plaintext = serde_json::to_vec(&"\0\n\"\\é🦀".repeat(1024)).expect("synthetic JSON");
    let envelope = if bounded {
        opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
            &key, &aad, &plaintext, [0xA8; 12],
        )
        .expect("genuine bounded encryption")
    } else {
        opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
            &key, &aad, &plaintext, [0xA9; 12],
        )
        .expect("genuine legacy encryption")
    };
    let record = CommitRecord {
        tx_id,
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
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
    let audit_key = AuditKey::new([0xAA; 32]).expect("synthetic audit key");
    let binding = bounded.then(|| {
        CapacityRecordBinding::issue(&attested, identity(), &audit_key, profile)
            .expect("genuine scoped retained proof")
    });
    let (record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    let prepared = PreparedConfigCommit::prepare_for_profile(record, audit, &audit_key, profile)
        .expect("real preparation");
    Fixture {
        command: ConfigConsensusCommand {
            schema_version: if bounded { 8 } else { 1 },
            identity: identity(),
            request_id: ConfigConsensusRequestId::from_bytes([0xAB; 16]),
            logical_time: committed_at,
            intent: ConfigMutationIntent::prepared_append(prepared, None, binding),
        },
        audit_key,
        key,
        aad,
        plaintext,
    }
}

#[test]
fn config_capacity_command_digests_match_original_json_for_valid_and_tampered_records() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let fixture = fixture(profile);
        let command = &fixture.command;
        command
            .validate_for_profile(command.identity, &fixture.audit_key, profile)
            .expect("independently validated genuine command");
        let semantic_revision = if profile == ConfigCapacityProfile::Legacy {
            1
        } else {
            8
        };
        require_original_transcripts(command, semantic_revision);
        let mut changed = command.clone();
        let encrypted_blob = match &mut changed.intent {
            ConfigMutationIntent::AppendCommit(commit)
            | ConfigMutationIntent::BoundedAppend { commit, .. } => {
                &mut commit.record.encrypted_blob
            }
            _ => unreachable!("fixture is an ordinary append"),
        };
        assert_eq!(
            opc_crypto::decrypt_envelope_with_handle(&fixture.key, &fixture.aad, encrypted_blob)
                .expect("positive AEAD control")
                .as_slice(),
            fixture.plaintext.as_slice(),
        );
        *encrypted_blob
            .last_mut()
            .expect("nonempty ciphertext and tag") ^= 1;
        assert!(
            opc_crypto::decrypt_envelope_with_handle(&fixture.key, &fixture.aad, encrypted_blob)
                .is_err(),
            "buffered command hashing grants no AEAD authenticity"
        );
        require_original_transcripts(&changed, semantic_revision);
        assert_ne!(
            command.payload_digest().expect("original payload"),
            changed.payload_digest().expect("changed payload"),
            "tampered bytes still participate in the exact digest"
        );
        if profile == ConfigCapacityProfile::BoundedV1 {
            assert!(
                changed
                    .validate_for_profile(command.identity, &fixture.audit_key, profile)
                    .is_err(),
                "independent native-sized record authentication still rejects tampering"
            );
        }
        let foreign = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xAC; 32]),
            command.identity.configuration_id(),
            command.identity.configuration_epoch(),
        );
        assert!(command
            .validate_for_profile(foreign, &fixture.audit_key, profile)
            .is_err());
    }
}

#[test]
fn config_capacity_command_digests_preserve_legacy_replay_and_bind_applied_metadata() {
    let command = ConfigConsensusCommand {
        schema_version: 1,
        identity: identity(),
        request_id: ConfigConsensusRequestId::from_bytes([0xB1; 16]),
        logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time"),
        intent: ConfigMutationIntent::MarkConfirmed { tx_id: TxId::new() },
    };
    command
        .validate(command.identity)
        .expect("valid legacy command");
    require_original_transcripts(&command, 1);
    let original_payload = command.payload_digest().expect("legacy outcome");
    let previous = ConfigConsensusEntryDigest::from_bytes([0xAD; 32]);
    let effective_time = Timestamp::from_str("2026-01-01T00:00:02Z").expect("synthetic time");
    let applied = command
        .calculate_applied_digest(17, previous, effective_time)
        .expect("legacy applied digest");
    for field in 0..4 {
        let mut changed = command.clone();
        match field {
            0 => changed.schema_version = CONFIG_CONSENSUS_COMMAND_VERSION,
            1 => changed.request_id = ConfigConsensusRequestId::from_bytes([0xAE; 16]),
            2 => changed.logical_time = effective_time,
            _ => {
                changed.identity = ConfigConsensusIdentity::new(
                    ConfigConsensusClusterId::from_bytes([0xAF; 32]),
                    changed.identity.configuration_id(),
                    changed.identity.configuration_epoch(),
                );
            }
        }
        require_original_transcripts(&changed, 1);
        if field != 3 {
            assert_eq!(
                original_payload,
                changed.payload_digest().expect("same semantic retry"),
                "outcome replay excludes schema, request ID and selected time"
            );
        } else {
            assert_ne!(
                original_payload,
                changed.payload_digest().expect("foreign scope")
            );
        }
        assert_ne!(
            applied,
            changed
                .calculate_applied_digest(17, previous, effective_time)
                .expect("changed applied command"),
            "applied chain binds complete command metadata"
        );
    }
    for (sequence, prior, time) in [
        (18, previous, effective_time),
        (
            17,
            ConfigConsensusEntryDigest::from_bytes([0xB0; 32]),
            effective_time,
        ),
        (17, previous, command.logical_time),
    ] {
        assert_ne!(
            applied,
            command
                .calculate_applied_digest(sequence, prior, time)
                .expect("changed chain framing"),
            "applied chain retains sequence, predecessor and deterministic time"
        );
        let (joint_outcome, joint_applied) = command
            .payload_and_applied_digests(sequence, prior, time)
            .expect("paired changed chain framing");
        assert_eq!(
            joint_outcome, original_payload,
            "chain framing leaves semantic replay unchanged"
        );
        assert_eq!(
            joint_applied,
            ConfigConsensusEntryDigest::from_bytes(original_digest(
                b"openpacketcore/config-consensus/command/v1\0",
                &(sequence, prior, time, &command),
            ))
        );
        assert_ne!(
            joint_applied, applied,
            "paired digest retains every applied chain field"
        );
    }
}

#[test]
fn config_capacity_joint_digests_emit_one_intent_and_preserve_transcripts() {
    let mut emissions = Vec::new();
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let fixture = fixture(profile);
        let command = &fixture.command;
        command
            .validate_for_profile(command.identity, &fixture.audit_key, profile)
            .expect("existing authenticated ordinary command");
        let ciphertext = match &command.intent {
            ConfigMutationIntent::AppendCommit(commit)
            | ConfigMutationIntent::BoundedAppend { commit, .. } => &commit.record.encrypted_blob,
            _ => unreachable!("ordinary fixture"),
        };
        let semantic_revision = if profile == ConfigCapacityProfile::Legacy {
            1
        } else {
            8
        };
        require_original_transcripts(command, semantic_revision);
        let expected_emission = serde_json::to_vec(ciphertext)
            .expect("independent numeric byte array")
            .len()
            - 2;
        let previous = ConfigConsensusEntryDigest::from_bytes([0xB2; 32]);
        let effective_time = Timestamp::from_str("2026-01-01T00:00:02Z").expect("synthetic time");
        let (result, emitted) =
            crate::consensus::config_capacity_json::tests::observe_emission(|| {
                command.payload_and_applied_digests(17, previous, effective_time)
            });
        let (outcome, applied) = result.expect("paired real digests");
        assert_eq!(
            outcome,
            original_digest(
                b"openpacketcore/config-consensus/outcome/v1\0",
                &(semantic_revision, command.identity, &command.intent),
            )
        );
        assert_eq!(
            applied,
            ConfigConsensusEntryDigest::from_bytes(original_digest(
                b"openpacketcore/config-consensus/command/v1\0",
                &(17_u64, previous, effective_time, command),
            ))
        );
        emissions.push((profile, emitted, expected_emission));
    }
    assert!(
        emissions.iter().all(|(_, emitted, expected)| emitted == expected),
        "CONFIG_CAPACITY_JOINT_DIGEST_EMISSION_RED: all family transcript and hash oracles completed before emission comparison; observations={emissions:?}"
    );
}

#[path = "config_capacity_digest_coverage_tests.rs"]
mod coverage;
