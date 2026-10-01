//! Joint valid component maxima, distinct from native-cluster qualification.

use super::*;
use opc_crypto::{
    CryptoEnvelopeRef, CONFIG_CAPACITY_V1_AAD_BYTES, CONFIG_CAPACITY_V1_ENVELOPE_BYTES,
    CONFIG_CAPACITY_V1_LOGICAL_BYTES, CONFIG_CAPACITY_V1_PLAINTEXT_BYTES,
    CONFIG_CAPACITY_V1_REPLAY_BYTES,
};
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::TenantId;

const LOGICAL_BYTES: usize = 1_572_864;
const REPLAY_BYTES: usize = 65_536;
const AAD_BYTES: usize = 65_536;
const PRINCIPAL_BYTES: usize = 16_384;
const ENVELOPE_BYTES: usize = 1_704_492;

fn framed_plaintext() -> Vec<u8> {
    let mut bytes = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    bytes.extend(std::iter::repeat_n(b'x', LOGICAL_BYTES - 2));
    bytes.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    bytes.resize(LOGICAL_BYTES + REPLAY_BYTES - 2, b'r');
    bytes.extend_from_slice(b"\"}");
    assert_eq!(bytes.len(), CONFIG_CAPACITY_V1_PLAINTEXT_BYTES);
    bytes
}

fn maximum_parts(path_bytes: usize) -> (PreparedConfigCommit, CapacityRecordBinding) {
    assert_eq!(CONFIG_CAPACITY_V1_LOGICAL_BYTES, LOGICAL_BYTES);
    assert_eq!(CONFIG_CAPACITY_V1_REPLAY_BYTES, REPLAY_BYTES);
    assert_eq!(CONFIG_CAPACITY_V1_AAD_BYTES, AAD_BYTES);
    assert_eq!(CONFIG_CAPACITY_V1_ENVELOPE_BYTES, ENVELOPE_BYTES);

    // Reuse the original valid parent/record/audit fixture, then re-encrypt and
    // re-attest after every metadata change. The original small cases remain.
    let (base, _) = parts(128);
    let mut record = base.record;
    let mut audit = base.audit;
    audit.truncate(22);
    assert_eq!(audit.len(), 22);
    let prefix = "/fixture:";
    audit.last_mut().expect("last audit path").yang_path =
        format!("{prefix}{}", "x".repeat(path_bytes - prefix.len()));
    let prefix = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/";
    record.principal = format!("{prefix}{}", "p".repeat(PRINCIPAL_BYTES - prefix.len()));
    assert_eq!(record.principal.len(), PRINCIPAL_BYTES);

    let key_handle = KeyHandle::new(
        KeyId::new("k".repeat(512)).expect("maximum valid key identifier"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xD2; 32]),
    );
    let make_aad = |store: &str| {
        EnvelopeAad::config(
            TenantId::from_static("test"),
            record.version.get(),
            ConfigAad::new(
                record.tx_id,
                record.parent_tx_id,
                record.committed_at,
                &record.principal,
                record.schema_digest,
                store,
            )
            .expect("existing valid scalar metadata"),
        )
    };
    // Include real escaped and UTF-8 text; ASCII padding has one-byte growth.
    let mut store = String::from("synthetic-\"\\é-");
    let base_aad = opc_key::serialize_bound_aad(&make_aad(&store), key_handle.key_id())
        .expect("canonical base AAD")
        .len();
    store.extend(std::iter::repeat_n(
        's',
        AAD_BYTES.checked_sub(base_aad).expect("AAD padding room"),
    ));
    let aad = make_aad(&store);
    assert_eq!(
        opc_key::serialize_bound_aad(&aad, key_handle.key_id())
            .expect("canonical maximum AAD")
            .len(),
        AAD_BYTES
    );
    let plaintext = framed_plaintext();
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &key_handle,
        &aad,
        &plaintext,
        [0xD3; 12],
    )
    .expect("genuine joint-maximum encryption");
    let decoded = CryptoEnvelopeRef::decode(envelope.encoded()).expect("real envelope framing");
    assert_eq!(decoded.key_id.as_str().len(), 512);
    assert_eq!(decoded.aad.len(), AAD_BYTES);
    assert_eq!(decoded.nonce.len(), 12);
    assert_eq!(decoded.ciphertext_and_tag.len(), plaintext.len() + 16);
    assert_eq!(envelope.encoded().len(), ENVELOPE_BYTES);
    assert!(
        opc_crypto::decrypt_envelope_with_handle(&key_handle, &aad, envelope.encoded())
            .expect("authenticate and decrypt maximum envelope")
            .as_slice()
            == plaintext
    );
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    record.encrypted_blob = envelope.encoded().to_vec();
    let attested = AttestedConfigCommit::try_new(
        record,
        audit,
        envelope.claim().expect("fresh exact envelope claim"),
    )
    .expect("exact maximum plaintext attestation");
    let evidence = attested
        .capacity_evidence()
        .expect("real capacity evidence");
    assert_eq!(evidence.logical_bytes(), LOGICAL_BYTES);
    assert_eq!(evidence.replay_bytes(), REPLAY_BYTES);
    let binding = CapacityRecordBinding::issue(&attested, identity(), &key(), PROFILE)
        .expect("maximum envelope and principal fit real retained binding");
    let (record, audit, _) = attested.into_parts();
    let commit = PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE)
        .expect("real bounded preparation and finalized audit");
    StoredConfig {
        record: commit.record.clone(),
        audit: commit.audit.clone(),
    }
    .verify_audit_chain(&key())
    .expect("complete real audit-chain authentication");
    (commit, binding)
}

fn maximum_command(
    audit: bool,
    resolution: Option<bool>,
    path_bytes: usize,
) -> ConfigConsensusCommand {
    let (commit, binding) = maximum_parts(path_bytes);
    let resolution = resolution.map(|confirm| {
        if confirm {
            ConfirmedCommitResolution::Confirm {
                pending_tx_id: parent(),
            }
        } else {
            ConfirmedCommitResolution::Rollback {
                pending_tx_id: parent(),
            }
        }
    });
    ConfigConsensusCommand {
        schema_version: 8,
        identity: identity(),
        request_id: opc_consensus::ConsensusRequestId::from_bytes([0xD4; 16]),
        logical_time: maximum_encoded_config_timestamp().expect("maximum command timestamp"),
        intent: if audit {
            audited(AuditedConfigEffect::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution,
            })
        } else {
            ConfigMutationIntent::prepared_append(commit, resolution, Some(binding))
        },
    }
}

fn joint_metadata(command: &ConfigConsensusCommand) -> usize {
    let wire = encode_bounded(command).expect("actual joint command fits unchanged RPC cap");
    assert_eq!(config_command_encoded_size(command).unwrap(), wire.len());
    assert!(wire.len() > DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
    wire.len()
        .checked_sub(ENVELOPE_BYTES)
        .expect("exactly one maximum envelope")
}

fn assert_joint_boundary(audit: bool) {
    for resolution in [None, Some(true), Some(false)] {
        let baseline_path = 128;
        let baseline = joint_metadata(&maximum_command(audit, resolution, baseline_path));
        let at_limit_path = baseline_path
            + METADATA_LIMIT
                .checked_sub(baseline)
                .expect("all other maxima leave valid last-path room");
        assert!((baseline_path..CONFIG_AUDIT_PATH_MAX_BYTES).contains(&at_limit_path));
        for extra in [0, 1] {
            let value = maximum_command(audit, resolution, at_limit_path + extra);
            value
                .validate(identity())
                .expect("structurally valid maximum command");
            assert_eq!(joint_metadata(&value), METADATA_LIMIT + extra);
            let wire = encode_bounded(&value).expect("unchanged full RPC encoder");
            let decoded: ConfigConsensusCommand =
                opc_consensus::decode_bounded(&wire).expect("actual command decoding");
            assert_eq!(
                decoded
                    .validate_for_profile(identity(), &key(), PROFILE)
                    .is_ok(),
                extra == 0,
                "joint maximum envelope must preserve exact metadata admission"
            );
            let probe = ConfigConsensusCommandSizeProbe {
                schema_version: value.schema_version,
                identity: value.identity,
                request_id: value.request_id,
                logical_time: value.logical_time,
                intent: &value.intent,
            };
            let result = super::super::super::config_capacity_admission::preflight(&probe, PROFILE);
            if extra == 0 {
                result.expect("joint maxima fit every independent encoding and output bound");
                assert_eq!(wire.len(), 1_901_100);
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    ForwardMutationRejection::CommandTooLarge
                );
            }
            assert_eq!(
                preflight_config_command_replication_budget(
                    identity(),
                    value.request_id,
                    &value.intent,
                    PROFILE,
                ),
                if extra == 0 {
                    Ok(())
                } else {
                    Err(ForwardMutationRejection::CommandTooLarge)
                },
                "real store preflight must retain the exact independent metadata boundary"
            );
        }
    }
    eprintln!(
        "CONFIG_CAPACITY_JOINT logical=1572864 replay=65536 aad=65536 key_id=512 principal=16384 metadata=196608 command=1901100 audited={audit} one_over=rejected"
    );
}

#[test]
fn config_capacity_957_joint_maxima_ordinary_metadata_boundary() {
    assert_joint_boundary(false);
}

#[test]
fn config_capacity_957_joint_maxima_audited_metadata_boundary() {
    assert_joint_boundary(true);
}
