pub(crate) use super::legacy_support::*;

use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::types::*;
use crate::{AttestedConfigCommit, ConfirmedCommitResolution};
use sha2::{Digest, Sha256};

pub(crate) fn plaintext(logical: usize, replay: usize) -> Vec<u8> {
    let mut value = vec![b'q'; logical];
    if logical == 1 {
        value[0] = b'0';
    } else {
        value[0] = b'"';
        value[logical - 1] = b'"';
    }
    if replay == 0 {
        return value;
    }
    let mut result = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":".to_vec();
    result.extend_from_slice(&value);
    result.extend_from_slice(b",\"idempotency_key\":\"");
    result.resize(result.len() + replay - (result.len() - logical + 2), b'r');
    result.extend_from_slice(b"\"}");
    assert_eq!(result.len(), logical + replay);
    result
}

pub(crate) fn bounded_attested(logical: usize, replay: usize) -> AttestedConfigCommit {
    let bytes = plaintext(logical, replay);
    let mut record = record();
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle_key(),
        &aad(&record, "running"),
        &bytes,
        [0x34; 12],
    )
    .unwrap();
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&bytes).to_vec();
    AttestedConfigCommit::try_new(record, audit(), envelope.claim().unwrap()).unwrap()
}

pub(crate) fn bounded_command(
    audited: bool,
    resolution: Option<ConfirmedCommitResolution>,
) -> ConfigConsensusCommand {
    let attested = bounded_attested(32, 64);
    let binding = crate::consensus::capacity_record::CapacityRecordBinding::issue(
        &attested,
        identity(),
        &key(),
    )
    .unwrap();
    let commit = Box::new(
        PreparedConfigCommit::prepare(attested.record().clone(), audit(), &key()).unwrap(),
    );
    let intent = if audited {
        let effect = AuditedConfigEffect::BoundedAppend {
            commit,
            binding,
            resolution,
        };
        ConfigMutationIntent::AuditedMutation(crate::consensus::PreparedAuditedMutation {
            handle: handle(Some(&effect)),
            effect,
        })
    } else {
        ConfigMutationIntent::BoundedAppend {
            commit,
            binding,
            resolution,
        }
    };
    ConfigConsensusCommand {
        schema_version: 8,
        ..command(intent)
    }
}
