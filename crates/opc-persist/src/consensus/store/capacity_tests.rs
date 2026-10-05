use super::*;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::capacity_tests::support::*;
use crate::consensus::PreparedAuditedMutation;

fn legacy_command(
    audited: bool,
    resolving: bool,
    ciphertext: usize,
) -> super::super::ConfigConsensusCommand {
    let mut record = record();
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(&record.encrypted_blob).unwrap();
    envelope.ciphertext_and_tag.resize(ciphertext, 0xA5);
    record.encrypted_blob = envelope.encode().unwrap();
    let prepared = Box::new(PreparedConfigCommit::prepare(record, audit(), &key()).unwrap());
    let resolution = resolving.then(|| crate::ConfirmedCommitResolution::Confirm {
        pending_tx_id: parent(),
    });
    let intent = if audited {
        let effect = AuditedConfigEffect::Append {
            commit: prepared,
            resolution,
        };
        ConfigMutationIntent::AuditedMutation(PreparedAuditedMutation {
            handle: handle(Some(&effect)),
            effect,
        })
    } else if let Some(resolution) = resolution {
        ConfigMutationIntent::ResolveConfirmedAndAppend {
            commit: prepared,
            resolution,
        }
    } else {
        ConfigMutationIntent::AppendCommit(prepared)
    };
    let mut command = command(intent);
    command.logical_time = maximum_encoded_config_timestamp().unwrap();
    command
}

#[test]
fn legacy_command_ceiling_is_exactly_one_mebibyte_for_both_append_paths() {
    for audited in [false, true] {
        for resolving in [false, true] {
            let probe_size = 900_000;
            let probe = legacy_command(audited, resolving, probe_size);
            let overhead = encode_bounded(&probe).unwrap().len() - probe_size;
            let at_size = 1_048_576 - overhead;
            let at = legacy_command(audited, resolving, at_size);
            at.validate(identity()).unwrap();
            assert_eq!(encode_bounded(&at).unwrap().len(), 1_048_576);
            assert!(config_command_fits_replication_budget(&at));
            assert_eq!(
                preflight_config_command_replication_budget(identity(), at.request_id, &at.intent),
                Ok(())
            );
            let over = legacy_command(audited, resolving, at_size + 1);
            over.validate(identity()).unwrap();
            assert_eq!(encode_bounded(&over).unwrap().len(), 1_048_577);
            assert!(!config_command_fits_replication_budget(&over));
            assert_eq!(
                preflight_config_command_replication_budget(
                    identity(),
                    over.request_id,
                    &over.intent
                ),
                Err(ForwardMutationRejection::CommandTooLarge)
            );
        }
    }
}
