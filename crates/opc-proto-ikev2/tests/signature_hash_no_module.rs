//! Process-isolated fail-closed proof before crypto-module installation.

use opc_proto_ikev2::{
    Ikev2CryptoModuleErrorCode, Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalOffer,
    Ikev2SignatureHashNegotiationError,
};

#[test]
fn local_offer_requires_installed_admitted_verification_support() {
    let error = Ikev2SignatureHashLocalOffer::new(&[Ikev2SignatureHashAlgorithm::Sha2_256])
        .expect_err("offer must not rely on compile-time support alone");
    assert!(matches!(
        error,
        Ikev2SignatureHashNegotiationError::CryptoModuleFailure(module)
            if module.code() == Ikev2CryptoModuleErrorCode::NotInstalled
    ));
    assert_eq!(error.as_str(), "ike_signature_hash_crypto_module_failure");
    assert_eq!(
        error.to_string(),
        "ike_signature_hash_crypto_module_failure"
    );
}
