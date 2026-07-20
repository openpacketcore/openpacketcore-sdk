//! Process-isolated proof that CERTREQ admission does not authorize NAT-D.

use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::{
    ikev2_certreq_authority_key_hash, ikev2_nat_detection_hash,
    install_ikev2_software_crypto_module, Ikev2CertReqSubjectPublicKeyInfo,
    Ikev2CryptoModuleErrorCode, Ikev2CryptoRequirements,
};

const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
// Independently computed with OpenSSL 3:
// `openssl dgst -sha1 tests/data/p256_spki.der`.
const P256_SPKI_SHA1: [u8; 20] = [
    0xa2, 0x37, 0x81, 0xbb, 0x75, 0xce, 0x80, 0xc8, 0xfb, 0xf0, 0x6f, 0xcc, 0xcf, 0x4a, 0x6f, 0xc3,
    0xdb, 0x45, 0x95, 0x72,
];

#[test]
fn certreq_only_hashes_the_exact_spki_but_does_not_authorize_nat_detection() {
    let mut requirements = Ikev2CryptoRequirements::new();
    requirements.require_certreq_authority_hash();
    let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
    let _report = install_ikev2_software_crypto_module(policy, requirements)
        .expect("CERTREQ-only software module admission succeeds");

    let spki =
        Ikev2CertReqSubjectPublicKeyInfo::from_der(P256_SPKI_DER).expect("synthetic SPKI is valid");
    let hash = ikev2_certreq_authority_key_hash(spki).expect("CERTREQ hashing executes");
    assert_eq!(hash.as_bytes(), &P256_SPKI_SHA1);

    let error =
        ikev2_nat_detection_hash(1, 2, "192.0.2.10:500".parse().expect("synthetic endpoint"))
            .expect_err("CERTREQ-only admission must not authorize NAT-D");
    assert_eq!(
        error.code(),
        Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted
    );
}
