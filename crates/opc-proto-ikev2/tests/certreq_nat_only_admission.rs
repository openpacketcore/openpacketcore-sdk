//! Process-isolated proof that NAT-D admission does not authorize CERTREQ.

use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::{
    ikev2_certreq_authority_key_hash, ikev2_nat_detection_hash,
    install_ikev2_software_crypto_module, Ikev2CertReqSubjectPublicKeyInfo,
    Ikev2CryptoModuleErrorCode, Ikev2CryptoRequirements,
};

const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");

#[test]
fn nat_detection_only_does_not_authorize_certreq_hashing() {
    let mut requirements = Ikev2CryptoRequirements::new();
    requirements.require_nat_detection();
    let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
    let _report = install_ikev2_software_crypto_module(policy, requirements)
        .expect("NAT-D-only software module admission succeeds");

    ikev2_nat_detection_hash(1, 2, "192.0.2.10:500".parse().expect("synthetic endpoint"))
        .expect("NAT-D remains executable");

    let spki =
        Ikev2CertReqSubjectPublicKeyInfo::from_der(P256_SPKI_DER).expect("synthetic SPKI is valid");
    let error = ikev2_certreq_authority_key_hash(spki)
        .expect_err("NAT-D-only admission must not authorize CERTREQ hashing");
    assert_eq!(
        error.code(),
        Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted
    );
}
