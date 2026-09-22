//! Exact encryption evidence must survive both public commit constructors.

use super::AttestedConfigCommit;
use crate::types::{CommitRecord, ConfirmedCommitResolution};
use opc_crypto::{
    encrypt_bounded_config_envelope_with_handle_and_nonce, AuthenticatedEnvelope,
    ConfigCapacityProfile,
};
use sha2::{Digest, Sha256};

fn fixture(parent: Option<opc_types::TxId>) -> (CommitRecord, AuthenticatedEnvelope) {
    let (mut record, _, _) = super::tests::sized_attested_commit(32).into_parts();
    record.parent_tx_id = parent;
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
        opc_key::KeyId::new("config-capacity-evidence").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        opc_types::TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xD1; 32]),
    );
    let plaintext = br#"{"synthetic":true}"#;
    let envelope =
        encrypt_bounded_config_envelope_with_handle_and_nonce(&handle, &aad, plaintext, [0xD2; 12])
            .expect("fresh bounded envelope");
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(plaintext).to_vec();
    (record, envelope)
}

#[test]
fn capacity_evidence_survives_normal_confirm_and_rollback_constructors() {
    let pending_tx_id = opc_types::TxId::new();
    for resolution in [
        None,
        Some(ConfirmedCommitResolution::Confirm { pending_tx_id }),
        Some(ConfirmedCommitResolution::Rollback { pending_tx_id }),
    ] {
        let (record, envelope) = fixture(resolution.map(ConfirmedCommitResolution::pending_tx_id));
        let claim = envelope.claim().expect("one-shot claim");
        let expected = claim.capacity_evidence().expect("bounded evidence");
        let commit = match resolution {
            None => AttestedConfigCommit::try_new(record, Vec::new(), claim),
            Some(resolution) => {
                AttestedConfigCommit::try_new_resolving(record, Vec::new(), claim, resolution)
            }
        }
        .expect("exact authenticated record");
        assert_eq!(commit.capacity_evidence(), Some(expected));
        assert_eq!(expected.profile(), ConfigCapacityProfile::BoundedV1);
        assert_eq!(expected.logical_bytes(), br#"{"synthetic":true}"#.len());
        assert_eq!(expected.replay_bytes(), 0);
        assert_eq!(commit.confirmed_resolution(), resolution);
    }
    assert!(
        super::tests::sized_attested_commit(32)
            .capacity_evidence()
            .is_none(),
        "legacy claim cannot acquire bounded evidence at transfer"
    );
}

#[test]
fn capacity_evidence_cannot_authorize_changed_ciphertext_or_digest() {
    for resolving in [false, true] {
        for change_ciphertext in [false, true] {
            let pending_tx_id = opc_types::TxId::new();
            let (mut record, envelope) = fixture(resolving.then_some(pending_tx_id));
            if change_ciphertext {
                *record.encrypted_blob.last_mut().expect("ciphertext") ^= 1;
            } else {
                record.plaintext_digest[0] ^= 1;
            }
            let claim = envelope.claim().expect("one-shot evidence");
            assert!(claim.capacity_evidence().is_some());
            let result = if resolving {
                AttestedConfigCommit::try_new_resolving(
                    record,
                    Vec::new(),
                    claim,
                    ConfirmedCommitResolution::Confirm { pending_tx_id },
                )
            } else {
                AttestedConfigCommit::try_new(record, Vec::new(), claim)
            };
            assert!(
                result.is_err(),
                "capacity evidence never bypasses the exact encryption binding"
            );
        }
    }
}
