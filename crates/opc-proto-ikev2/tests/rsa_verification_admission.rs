//! Default-feature regression for directional RSA signature admission.

#![cfg(not(feature = "rsa-signing"))]

use opc_crypto_provider::{
    IkePrfAlgorithm, IkePrfOperations, IkeSignatureAlgorithm, ProviderPolicy,
};
use opc_proto_ikev2::{
    derive_ike_sa_init_key_material, install_ikev2_software_crypto_module,
    verify_ike_auth_signature, Ikev2AuthenticationPayload, Ikev2CryptoModuleInstallError,
    Ikev2CryptoRequirements, Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SignaturePublicKey,
    Ikev2SoftwareCryptoOperations, IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE,
};
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

const RSA_PKCS8_DER: &[u8] = include_bytes!("data/rsa2048_pkcs8.der");
const RSA_SPKI_DER: &[u8] = include_bytes!("data/rsa2048_spki.der");

fn policy(requirements: &Ikev2CryptoRequirements) -> ProviderPolicy {
    ProviderPolicy::new().require_all(requirements.required_capabilities())
}

#[test]
fn default_build_admits_rsa_verification_but_rejects_private_rsa_signing() {
    let mut signing = Ikev2CryptoRequirements::new();
    signing.require_signature_generation(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256);
    let error = install_ikev2_software_crypto_module(policy(&signing), signing)
        .expect_err("default build must not admit RSA private signing");
    assert!(matches!(
        error,
        Ikev2CryptoModuleInstallError::AlgorithmUnsupported {
            algorithm: "rsa_pkcs1_v1_5_sha2_256"
        }
    ));

    let profile = Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("executable test profile");
    let mut verification = Ikev2CryptoRequirements::new();
    verification
        .require_ike_sa_profile(profile)
        .expect("profile requirements");
    verification.require_signature_verification(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256);
    let _report = install_ikev2_software_crypto_module(policy(&verification), verification)
        .expect("RSA verification-only configuration admits");

    let material = derive_ike_sa_init_key_material(
        profile,
        1_u64.to_be_bytes(),
        2_u64.to_be_bytes(),
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        None,
    )
    .expect("test key material");
    let ike_sa_init_message = [0x44; 32];
    let peer_nonce = [0x55; 32];
    let identity_payload_body = [0x66; 16];
    let signed_octets = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: &ike_sa_init_message,
        peer_nonce: &peer_nonce,
        identity_payload_body: &identity_payload_body,
    };

    let macked_identity = Ikev2SoftwareCryptoOperations::new()
        .prf(
            IkePrfAlgorithm::HmacSha2_256,
            material.sk_pr(),
            &identity_payload_body,
        )
        .expect("independent transcript PRF");
    let mut signed = Vec::new();
    signed.extend_from_slice(&ike_sa_init_message);
    signed.extend_from_slice(&peer_nonce);
    signed.extend_from_slice(&macked_identity);
    let digest = Sha256::digest(&signed);
    let private = RsaPrivateKey::from_pkcs8_der(RSA_PKCS8_DER).expect("test RSA key");
    let signature = private
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .expect("test-only independent RSA signature");
    let public = Ikev2SignaturePublicKey::from_spki_der(RSA_SPKI_DER).expect("RSA SPKI");

    verify_ike_auth_signature(
        profile,
        &material,
        signed_octets,
        &public,
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE,
            auth_data: &signature,
        },
        None,
    )
    .expect("admitted RSA public-key verification succeeds");
}
