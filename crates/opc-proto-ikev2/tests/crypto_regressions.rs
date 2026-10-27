//! Regression vectors for initial XCBC derivation and signature/AEAD admission.
use opc_proto_ikev2::*;
use opc_protocol::DecodeContext;
mod support;

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn initial_xcbc_skeyseed_and_complete_key_stream_match_independent_vector() {
    support::ensure_ike_crypto();
    let profile = Ikev2SaInitCryptoProfile::from_transform_ids(4, 19, 20, Some(128), None).unwrap();
    let keys = derive_ike_sa_init_key_material(
        Ikev2NonceLocalRole::Initiator,
        profile,
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )
    .unwrap();
    // Independent AES-ECB XCBC implementation, RFC 7296 section 2.14 and RFC 4434.
    // Only SKEYSEED takes Ni[0..8] || Nr[0..8]; PRF+ retains both complete nonces.
    assert_eq!(keys.skeyseed(), hex("c05cd52f3c70e22b1ad97281d05fb308"));
    assert_eq!(
        [
            keys.sk_d(),
            keys.sk_ei(),
            keys.sk_er(),
            keys.sk_pi(),
            keys.sk_pr()
        ]
        .concat(),
        hex(
            "80578ae4ed2bb176460e4f209a8c98c7497fda1a21747d481cee092e3b67cbdaecf77692136ccb5fca618782d776e60b3a5349f239ed92ae346ae7bc0c29db2630e2a22c9dd0a5e0fcdca11fa5570056caf43b3a5ba96365"
        )
    );
    assert!(keys.sk_ai().is_empty());
    assert!(keys.sk_ar().is_empty());
}

#[test]
fn chacha20_poly1305_and_all_ccm8_key_sizes_are_executable_ike_suites() {
    for (id, bits) in [
        (28, None),
        (14, Some(128)),
        (14, Some(192)),
        (14, Some(256)),
    ] {
        assert!(
            Ikev2SaInitCryptoProfile::from_transform_ids(5, 19, id, bits, None).is_ok(),
            "AEAD transform {id}, key bits {bits:?}"
        );
    }
}

#[test]
fn pure_ed25519_and_ed448_public_keys_are_admitted() {
    for encoded in [
        "302a300506032b6570032100db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d",
        "3043300506032b6571033a002601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00",
    ] {
        assert!(Ikev2SignaturePublicKey::from_spki_der(&hex(encoded)).is_ok());
    }
}

#[cfg(feature = "rsa-signing")]
#[test]
fn rsa_constructor_refuses_each_ecdsa_auth_method() {
    support::ensure_ike_crypto();
    for method in [
        Ikev2SignatureAuthMethod::EcdsaSha2_256,
        Ikev2SignatureAuthMethod::EcdsaSha2_384,
        Ikev2SignatureAuthMethod::EcdsaSha2_512,
    ] {
        assert!(
            Ikev2SignatureAuthKey::rsa_pkcs8_der(method, include_bytes!("data/rsa2048_pkcs8.der"))
                .is_err()
        );
    }
}

#[cfg(feature = "rsa-signing")]
fn local_pss(
    hash: Ikev2SignatureHashAlgorithm,
    constructor: fn(&[u8]) -> Result<Ikev2SignatureAuthKey, Ikev2SignatureKeyError>,
) {
    support::ensure_ike_crypto();
    let profile = Ikev2SaInitCryptoProfile::from_transform_ids(5, 19, 20, Some(128), None).unwrap();
    let keys = Ikev2SaInitKeyMaterial::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &[0x22; 20],
        &[0x33; 20],
        &[0x44; 32],
        &[0x55; 32],
    )
    .unwrap();
    let hashes = [hash];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .unwrap()
    .into_authorities();
    let octets = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: &response,
        peer_nonce: support::TEST_INITIATOR_NONCE,
        identity_payload_body: b"\x02\0\0\0peer.example",
    };
    let key = constructor(include_bytes!("data/rsa2048_pkcs8.der")).unwrap();
    let public =
        Ikev2SignaturePublicKey::from_spki_der(include_bytes!("data/rsa2048_spki.der")).unwrap();
    let signature = compute_ike_auth_signature(
        profile,
        &keys,
        octets,
        &key,
        Some(
            authorities
                .signing()
                .for_exchange(&request, &response)
                .unwrap(),
        ),
    )
    .unwrap();
    let authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(&request, &response, octets, hash, &public)
        .unwrap();
    verify_local_ike_auth_signature(
        profile,
        &keys,
        &Ikev2AuthenticationPayload {
            auth_method: 14,
            auth_data: &signature,
        },
        authorization,
    )
    .unwrap();
}
#[cfg(feature = "rsa-signing")]
#[test]
fn rsa_pss_sha256_auth_self_verifies_with_the_actual_signing_scheme() {
    local_pss(
        Ikev2SignatureHashAlgorithm::Sha2_256,
        Ikev2SignatureAuthKey::rsa_pss_sha256_pkcs8_der,
    );
}
#[cfg(feature = "rsa-signing")]
#[test]
fn rsa_pss_sha384_auth_self_verifies_with_the_actual_signing_scheme() {
    local_pss(
        Ikev2SignatureHashAlgorithm::Sha2_384,
        Ikev2SignatureAuthKey::rsa_pss_sha384_pkcs8_der,
    );
}
#[cfg(feature = "rsa-signing")]
#[test]
fn rsa_pss_sha512_auth_self_verifies_with_the_actual_signing_scheme() {
    local_pss(
        Ikev2SignatureHashAlgorithm::Sha2_512,
        Ikev2SignatureAuthKey::rsa_pss_sha512_pkcs8_der,
    );
}
