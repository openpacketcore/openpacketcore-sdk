//! Opt-in private checkpoint custody; tests never print private or shared bytes.

use opc_crypto_provider::{
    CryptoCapability, CryptoModule, CryptoOperationErrorCode as Code, IkeDhGroup as Group,
    IkeDiffieHellmanOperations,
};
use opc_proto_ikev2::{Ikev2SoftwareCryptoModule, Ikev2SoftwareCryptoOperations};

const GROUPS: [Group; 6] = [
    Group::Modp768,
    Group::Modp1024,
    Group::Modp2048,
    Group::Ecp256,
    Group::Ecp384,
    Group::Ecp521,
];
const OPERATIONS: Ikev2SoftwareCryptoOperations = Ikev2SoftwareCryptoOperations::new();

#[test]
fn software_checkpoint_support_is_explicit_for_each_group() {
    let module = Ikev2SoftwareCryptoModule::new().unwrap();
    assert!(module
        .advertised_capabilities()
        .contains(CryptoCapability::IkeDhCheckpoint));
    assert!(!module
        .advertised_capabilities()
        .contains(CryptoCapability::SealedKeyStorage));
    for group in GROUPS {
        assert!(OPERATIONS.supports_dh_checkpoint(group));
    }
}

#[test]
fn checkpoint_survives_loss_of_original_private_handle_for_every_group() {
    for group in GROUPS {
        let mut original = OPERATIONS.generate_keypair(group).unwrap();
        let peer = OPERATIONS.generate_keypair(group).unwrap();
        let expected_public = original.public_value().to_vec();
        let expected_secret = peer.agree(&expected_public).unwrap();
        let checkpoint = original.export_private_checkpoint().unwrap();
        assert_eq!(checkpoint.len(), group.checkpoint_len());
        // Inspect public framing only; assertion diagnostics never contain the scalar.
        assert_eq!(checkpoint[0], 1);
        assert_eq!(
            u16::from_be_bytes([checkpoint[1], checkpoint[2]]),
            group.transform_id()
        );
        assert_eq!(
            original.export_private_checkpoint().err().unwrap().code(),
            Code::CheckpointAlreadyExported
        );
        drop(original);
        let mut restored = OPERATIONS
            .import_keypair_checkpoint(group, &checkpoint, &expected_public)
            .unwrap();
        drop(checkpoint);
        assert!(restored.public_value() == expected_public);
        let actual = restored.agree(peer.public_value()).unwrap();
        assert!(
            actual.as_slice() == expected_secret.as_slice(),
            "agreement changed after checkpoint import"
        );
        assert_eq!(
            restored.export_private_checkpoint().err().unwrap().code(),
            Code::CheckpointAlreadyExported
        );
    }
}

#[test]
fn checkpoint_refuses_version_group_length_and_invalid_private_values() {
    for group in GROUPS {
        let mut original = OPERATIONS.generate_keypair(group).unwrap();
        let public = original.public_value().to_vec();
        let checkpoint = original.export_private_checkpoint().unwrap();
        drop(original);
        for mutation in 0..7 {
            let mut invalid = checkpoint.clone();
            match mutation {
                0 => invalid[0] = 2,
                1 => invalid[2] ^= 1,
                2 => {
                    invalid.pop();
                }
                3 => invalid.push(0),
                4 => invalid[3..].fill(0),
                5 => invalid[3..].fill(0xff),
                6 => invalid.clear(),
                _ => unreachable!(),
            }
            let error = OPERATIONS
                .import_keypair_checkpoint(group, &invalid, &public)
                .err()
                .unwrap();
            assert_eq!(
                error.code(),
                Code::InvalidCheckpoint,
                "case {mutation}, group {group}"
            );
        }
    }
}

#[test]
fn checkpoint_import_recomputes_and_checks_the_committed_public_value() {
    for group in GROUPS {
        let mut original = OPERATIONS.generate_keypair(group).unwrap();
        let mut public = original.public_value().to_vec();
        let checkpoint = original.export_private_checkpoint().unwrap();
        drop(original);
        public[0] ^= 1;
        let error = OPERATIONS
            .import_keypair_checkpoint(group, &checkpoint, &public)
            .err()
            .unwrap();
        assert_eq!(error.code(), Code::CheckpointPublicValueMismatch);
        assert_eq!(
            error.to_string(),
            "crypto_op_checkpoint_public_value_mismatch"
        );
        assert_eq!(
            format!("{error:?}"),
            "CryptoOperationError { code: \"crypto_op_checkpoint_public_value_mismatch\" }"
        );
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[derive(Debug)]
struct LegacyKey;
impl opc_crypto_provider::IkeDhKeyPair for LegacyKey {
    fn group(&self) -> Group {
        Group::Ecp256
    }
    fn public_value(&self) -> &[u8] {
        &[]
    }
    fn agree(
        &self,
        _: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, opc_crypto_provider::CryptoOperationError> {
        Err(opc_crypto_provider::CryptoOperationError::new(
            Code::UnsupportedAlgorithm,
        ))
    }
}
struct LegacyOperations;
impl IkeDiffieHellmanOperations for LegacyOperations {
    fn supports_dh_group(&self, _: Group) -> bool {
        false
    }
    fn generate_keypair(
        &self,
        _: Group,
    ) -> Result<Box<dyn opc_crypto_provider::IkeDhKeyPair>, opc_crypto_provider::CryptoOperationError>
    {
        Ok(Box::new(LegacyKey))
    }
}

#[test]
fn providers_without_checkpoint_methods_default_to_refusal() {
    let operations = LegacyOperations;
    assert!(!operations.supports_dh_checkpoint(Group::Ecp256));
    assert_eq!(
        operations
            .import_keypair_checkpoint(Group::Ecp256, &[], &[])
            .err()
            .unwrap()
            .code(),
        Code::UnsupportedAlgorithm
    );
    assert_eq!(
        operations
            .generate_keypair(Group::Ecp256)
            .unwrap()
            .export_private_checkpoint()
            .err()
            .unwrap()
            .code(),
        Code::UnsupportedAlgorithm
    );
}
