//! Encoder/digest compatibility controls, not larger-profile admission proof.

use super::*;

fn command(intent: ConfigMutationIntent) -> crate::consensus::ConfigConsensusCommand {
    crate::consensus::ConfigConsensusCommand {
        schema_version: crate::consensus::CONFIG_CONSENSUS_COMMAND_VERSION,
        identity: opc_consensus::ConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x81; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x82; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
        ),
        request_id: opc_consensus::ConsensusRequestId::from_bytes([0x83; 16]),
        logical_time: maximum_encoded_config_timestamp().expect("maximum encoded time"),
        intent,
    }
}

fn encrypted_intent(bytes: usize) -> ConfigMutationIntent {
    let (record, audit, resolution) = sized_attested_commit(bytes).into_parts();
    assert!(resolution.is_none());
    ConfigMutationIntent::AppendCommit(Box::new(
        PreparedConfigCommit::prepare(
            record,
            audit,
            &crate::AuditKey::new([0x84; 32]).expect("synthetic key"),
        )
        .expect("prepare real encrypted format control"),
    ))
}

#[test]
fn config_capacity_957_counted_command_sizes_keep_exact_legacy_rejection() {
    for bytes in [16, 512, 524_288, 1_048_000, 1_572_864] {
        let command = command(encrypted_intent(bytes));
        command
            .validate(command.identity)
            .expect("valid command format");
        let encoded = encode_bounded(&command).expect("format control fits hard RPC encoder");
        assert_eq!(
            config_command_encoded_size(&command).expect("counted size"),
            encoded.len()
        );
        let expected = encoded.len() <= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES;
        assert_eq!(config_command_fits_replication_budget(&command), expected);
        assert_eq!(
            preflight_config_command_replication_budget(
                command.identity,
                command.request_id,
                &command.intent
            )
            .is_ok(),
            expected,
            "counting must preserve the original command rejection"
        );
    }

    // Locate the complete encoded command boundary using the unchanged
    // encoder. The encrypted bytes have fixed-width postcard elements here;
    // keep the same varint length range when adding the remaining capacity.
    let baseline_plaintext = 1_000_000;
    let baseline = command(encrypted_intent(baseline_plaintext));
    let baseline_bytes = encode_bounded(&baseline).expect("boundary sizing control");
    let at_limit_plaintext =
        baseline_plaintext + DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES - baseline_bytes.len();
    for extra in [0, 1] {
        let command = command(encrypted_intent(at_limit_plaintext + extra));
        let encoded = encode_bounded(&command).expect("command boundary is below hard RPC limit");
        assert_eq!(
            encoded.len(),
            DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + extra,
            "fixture must reach the exact complete-command boundary"
        );
        assert_eq!(config_command_fits_replication_budget(&command), extra == 0);
        let expected = if extra == 0 {
            Ok(())
        } else {
            Err(ForwardMutationRejection::CommandTooLarge)
        };
        assert_eq!(
            preflight_config_command_replication_budget(
                command.identity,
                command.request_id,
                &command.intent
            ),
            expected
        );
    }
}

#[test]
fn config_capacity_957_streamed_digests_match_original_canonical_json() {
    let tx_id = opc_types::TxId::new();
    let intents = [
        (1_u16, encrypted_intent(1_572_864)),
        (1, ConfigMutationIntent::MarkConfirmed { tx_id }),
        (2, ConfigMutationIntent::ClearRecoveryRequired { tx_id }),
        (
            1,
            ConfigMutationIntent::CreateRollbackPoint {
                tx_id,
                label: Some(
                    ValidatedRollbackLabel::try_new("capacity-λ-\\\"".into())
                        .expect("escaped label"),
                ),
            },
        ),
    ];
    for (semantic_revision, intent) in intents {
        let command = command(intent);
        command
            .validate(command.identity)
            .expect("valid command format");
        // Retain the pre-change algorithms, including literal domains, as
        // independent compatibility oracles for durable history and outcomes.
        let mut old_payload = Sha256::new();
        old_payload.update(b"openpacketcore/config-consensus/outcome/v1\0");
        old_payload.update(
            serde_json::to_vec(&(semantic_revision, command.identity, &command.intent))
                .expect("original payload JSON"),
        );
        let expected: [u8; 32] = old_payload.finalize().into();
        assert!(
            command.payload_digest().expect("streamed payload") == expected,
            "outcome digest compatibility"
        );

        let sequence = i64::MAX as u64;
        let previous = opc_consensus::ConsensusEntryDigest::from_bytes([0x85; 32]);
        let effective_time = size_test_timestamp();
        let mut old_applied = Sha256::new();
        old_applied.update(b"openpacketcore/config-consensus/command/v1\0");
        old_applied.update(
            serde_json::to_vec(&(sequence, previous, effective_time, &command))
                .expect("original applied JSON"),
        );
        let expected: [u8; 32] = old_applied.finalize().into();
        assert!(
            command
                .calculate_applied_digest(sequence, previous, effective_time)
                .expect("streamed applied")
                .as_bytes()
                == &expected,
            "applied-chain digest compatibility"
        );
    }
}
