use opc_proto_ikev2::{
    build_ike_auth_identification_payload, compute_ike_auth_signature,
    derive_ike_sa_init_key_material, verify_ike_auth_signature, Ikev2AuthenticationPayload,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IdentificationPayloadBuild, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError, Ikev2PrfAlgorithm,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SignatureAuthKey,
    Ikev2SignatureAuthMethod, Ikev2SignatureKeyError, Ikev2SignaturePublicKey,
    IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE,
    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256,
    RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384, RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256,
};

const RSA_SPKI_DER: &[u8] = include_bytes!("data/rsa2048_spki.der");
const P256_PKCS8_DER: &[u8] = include_bytes!("data/p256_pkcs8.der");
const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
const P256_CERT_DER: &[u8] = include_bytes!("data/p256_cert.der");
const P384_PKCS8_DER: &[u8] = include_bytes!("data/p384_pkcs8.der");
const P384_SPKI_DER: &[u8] = include_bytes!("data/p384_spki.der");

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid AES-GCM IKE profile")
}

fn key_material() -> Ikev2SaInitKeyMaterial {
    derive_ike_sa_init_key_material(
        profile(),
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )
    .expect("key material")
}

fn identity_payload_body() -> Vec<u8> {
    build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"epdg.test.openpacketcore".to_vec(),
    })
    .expect("IDr body")
}

fn signed_octets<'a>(
    ike_sa_init_message: &'a [u8],
    peer_nonce: &'a [u8],
    identity: &'a [u8],
) -> Ikev2IkeAuthSignedOctets<'a> {
    Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message,
        peer_nonce,
        identity_payload_body: identity,
    }
}

const SA_INIT_RESPONSE: &[u8] = &[0x5a; 96];
const PEER_NONCE: &[u8] = &[0x66; 32];

fn auth_payload(auth_method: u8, auth_data: &[u8]) -> Ikev2AuthenticationPayload<'_> {
    Ikev2AuthenticationPayload {
        auth_method,
        auth_data,
    }
}

#[test]
fn ecdsa_p256_method_14_signature_round_trips() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    assert_eq!(key.method().as_u8(), IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE);

    let auth_data =
        compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");
    assert_eq!(
        usize::from(auth_data[0]),
        RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256.len()
    );
    assert_eq!(
        &auth_data[1..1 + RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256.len()],
        RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256
    );

    for public in [
        Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI"),
        Ikev2SignaturePublicKey::from_x509_certificate_der(P256_CERT_DER).expect("P-256 cert"),
    ] {
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &auth_data),
        )
        .expect("method 14 ECDSA P-256 verifies");
    }
}

#[test]
fn ecdsa_p384_method_14_signature_round_trips() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let key = Ikev2SignatureAuthKey::ecdsa_p384_pkcs8_der(P384_PKCS8_DER).expect("P-384 key");

    let auth_data =
        compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");
    assert_eq!(
        &auth_data[1..1 + RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384.len()],
        RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384
    );

    let public = Ikev2SignaturePublicKey::from_spki_der(P384_SPKI_DER).expect("P-384 SPKI");
    verify_ike_auth_signature(
        profile(),
        &key_material(),
        octets,
        &public,
        &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &auth_data),
    )
    .expect("method 14 ECDSA P-384 verifies");
}

#[test]
fn tampered_transcript_fails_verification() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let auth_data =
        compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");

    let tampered_nonce = [0x67; 32];
    let tampered = signed_octets(SA_INIT_RESPONSE, &tampered_nonce, &identity);
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            tampered,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &auth_data),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
    );
}

#[test]
fn wrong_key_type_fails_closed() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let auth_data =
        compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");

    // ECDSA-signed AUTH data presented against an RSA trust anchor.
    let rsa_public = Ikev2SignaturePublicKey::from_spki_der(RSA_SPKI_DER).expect("RSA SPKI");
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &rsa_public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &auth_data),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch)
    );

    // Flipping a signature bit against the right key fails as a bad signature.
    let ec_public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let mut corrupted = auth_data.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &ec_public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &corrupted),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
    );
}

#[test]
fn malformed_rfc7427_framing_fails_closed() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let public = Ikev2SignaturePublicKey::from_spki_der(RSA_SPKI_DER).expect("RSA SPKI");

    // Length byte runs past the AUTH data.
    let bad_length = [0xff_u8, 0x30, 0x0d];
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &bad_length),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
    );

    // AlgorithmIdentifier present but no signature bytes follow.
    let mut no_signature = vec![
        u8::try_from(RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256.len())
            .expect("algid length fits u8"),
    ];
    no_signature.extend_from_slice(&RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256);
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &no_signature),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
    );

    // Unknown AlgorithmIdentifier OID.
    let unknown_algid: &[u8] = &[
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x7f,
    ];
    let mut unknown = vec![u8::try_from(unknown_algid.len()).expect("algid length fits u8")];
    unknown.extend_from_slice(unknown_algid);
    unknown.extend_from_slice(&[0u8; 64]);
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &unknown),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported)
    );
}

#[test]
fn non_signature_auth_methods_are_rejected() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let public = Ikev2SignaturePublicKey::from_spki_der(RSA_SPKI_DER).expect("RSA SPKI");

    for method in [IKEV2_AUTH_METHOD_SHARED_KEY_MIC, 9, 255] {
        assert_eq!(
            verify_ike_auth_signature(
                profile(),
                &key_material(),
                octets,
                &public,
                &auth_payload(method, &[0u8; 32]),
            ),
            Err(Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod { method })
        );
    }
}

#[test]
fn method_1_payload_with_ec_key_fails_closed() {
    let identity = identity_payload_body();
    let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    // EC constructors pin the method to Digital Signature (14).
    assert_eq!(key.method(), Ikev2SignatureAuthMethod::DigitalSignature);

    // A method-1 payload can only be verified against an RSA key; an ECDSA
    // trust anchor fails closed.
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let auth_data =
        compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE, &auth_data),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch)
    );
}

#[test]
fn key_parsing_fails_closed_on_garbage() {
    assert_eq!(
        Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(&[0u8; 16]).expect_err("garbage EC key"),
        Ikev2SignatureKeyError::EcdsaPrivateKeyParse
    );
    assert_eq!(
        Ikev2SignaturePublicKey::from_spki_der(&[0u8; 16]).expect_err("garbage SPKI"),
        Ikev2SignatureKeyError::SpkiParse
    );
    assert_eq!(
        Ikev2SignaturePublicKey::from_x509_certificate_der(&[0u8; 16])
            .expect_err("garbage certificate"),
        Ikev2SignatureKeyError::CertificateParse
    );
    // A P-384 key handed to the P-256 parser fails as an EC parse error.
    assert_eq!(
        Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P384_PKCS8_DER).expect_err("P-384 into P-256"),
        Ikev2SignatureKeyError::EcdsaPrivateKeyParse
    );
}

#[test]
fn public_key_der_parsers_require_exact_input() {
    Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("exact P-256 SPKI");
    Ikev2SignaturePublicKey::from_x509_certificate_der(P256_CERT_DER)
        .expect("exact P-256 certificate");

    let mut spki_with_trailing_data = P256_SPKI_DER.to_vec();
    spki_with_trailing_data.push(0xaa);
    let spki_error = Ikev2SignaturePublicKey::from_spki_der(&spki_with_trailing_data)
        .expect_err("SPKI trailing data must fail closed");
    assert_eq!(spki_error, Ikev2SignatureKeyError::SpkiTrailingData);
    assert_eq!(spki_error.as_str(), "ike_auth_signature_spki_trailing_data");
    assert_eq!(format!("{spki_error:?}"), "SpkiTrailingData");
    assert_eq!(
        spki_error.to_string(),
        "ike_auth_signature_spki_trailing_data"
    );
    assert!(std::error::Error::source(&spki_error).is_none());

    let mut certificate_with_trailing_data = P256_CERT_DER.to_vec();
    certificate_with_trailing_data.push(0xbb);
    let certificate_error =
        Ikev2SignaturePublicKey::from_x509_certificate_der(&certificate_with_trailing_data)
            .expect_err("certificate trailing data must fail closed");
    assert_eq!(
        certificate_error,
        Ikev2SignatureKeyError::CertificateTrailingData
    );
    assert_eq!(
        certificate_error.as_str(),
        "ike_auth_signature_certificate_trailing_data"
    );
    assert_eq!(format!("{certificate_error:?}"), "CertificateTrailingData");
    assert_eq!(
        certificate_error.to_string(),
        "ike_auth_signature_certificate_trailing_data"
    );
    assert!(std::error::Error::source(&certificate_error).is_none());
}

#[test]
fn exact_der_enforcement_preserves_existing_error_classes() {
    assert_eq!(
        Ikev2SignaturePublicKey::from_spki_der(&P256_SPKI_DER[..P256_SPKI_DER.len() - 1])
            .expect_err("truncated SPKI"),
        Ikev2SignatureKeyError::SpkiParse
    );
    assert_eq!(
        Ikev2SignaturePublicKey::from_x509_certificate_der(
            &P256_CERT_DER[..P256_CERT_DER.len() - 1],
        )
        .expect_err("truncated certificate"),
        Ikev2SignatureKeyError::CertificateParse
    );

    // Change only the final arc of id-ecPublicKey to another well-formed OID.
    // The DER remains structurally valid and must retain the typed algorithm
    // classification instead of being mistaken for a trailing-data failure.
    const EC_PUBLIC_KEY_OID_DER: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let mut unsupported_algorithm = P256_SPKI_DER.to_vec();
    let oid_offset = unsupported_algorithm
        .windows(EC_PUBLIC_KEY_OID_DER.len())
        .position(|window| window == EC_PUBLIC_KEY_OID_DER)
        .expect("fixture contains id-ecPublicKey OID");
    unsupported_algorithm[oid_offset + EC_PUBLIC_KEY_OID_DER.len() - 1] = 0x02;
    assert_eq!(
        Ikev2SignaturePublicKey::from_spki_der(&unsupported_algorithm)
            .expect_err("unsupported public-key algorithm"),
        Ikev2SignatureKeyError::UnsupportedPublicKeyAlgorithm
    );
}

#[test]
fn debug_output_redacts_key_material() {
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let debug = format!("{key:?}");
    assert!(debug.contains("key_kind"));
    assert!(debug.len() < 128);

    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let debug = format!("{public:?}");
    assert!(debug.contains("ecdsa_p256"));
    assert!(debug.len() < 128);
}

/// RSA signing coverage, compiled only with the opt-in `rsa-signing` feature.
#[cfg(feature = "rsa-signing")]
mod rsa_signing {
    use super::*;
    use opc_proto_ikev2::{build_ike_auth_authentication_payload, Ikev2AuthenticationPayloadBuild};

    const RSA_PKCS8_DER: &[u8] = include_bytes!("data/rsa2048_pkcs8.der");
    const RSA_CERT_DER: &[u8] = include_bytes!("data/rsa2048_cert.der");

    #[test]
    fn rsa_method_1_signature_round_trips() {
        let identity = identity_payload_body();
        let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
        let key = Ikev2SignatureAuthKey::rsa_pkcs8_der(
            Ikev2SignatureAuthMethod::RsaDigitalSignature,
            RSA_PKCS8_DER,
        )
        .expect("RSA key");
        assert_eq!(
            key.method().as_u8(),
            IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE
        );

        let auth_data =
            compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");
        assert_eq!(auth_data.len(), 256);

        let auth_body = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
            auth_method: key.method().as_u8(),
            auth_data: auth_data.clone(),
        })
        .expect("AUTH body");
        assert_eq!(auth_body[0], IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE);

        let public = Ikev2SignaturePublicKey::from_spki_der(RSA_SPKI_DER).expect("RSA SPKI");
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE, &auth_data),
        )
        .expect("method 1 verifies");
    }

    #[test]
    fn rsa_method_14_signature_round_trips_with_certificate_key() {
        let identity = identity_payload_body();
        let octets = signed_octets(SA_INIT_RESPONSE, PEER_NONCE, &identity);
        let key = Ikev2SignatureAuthKey::rsa_pkcs8_der(
            Ikev2SignatureAuthMethod::DigitalSignature,
            RSA_PKCS8_DER,
        )
        .expect("RSA key");

        let auth_data =
            compute_ike_auth_signature(profile(), &key_material(), octets, &key).expect("sign");

        // RFC 7427 framing: length octet, AlgorithmIdentifier DER, raw signature.
        assert_eq!(
            usize::from(auth_data[0]),
            RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256.len()
        );
        assert_eq!(
            &auth_data[1..1 + RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256.len()],
            RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256
        );
        assert_eq!(
            auth_data.len(),
            1 + RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256.len() + 256
        );

        let public =
            Ikev2SignaturePublicKey::from_x509_certificate_der(RSA_CERT_DER).expect("cert SPKI");
        verify_ike_auth_signature(
            profile(),
            &key_material(),
            octets,
            &public,
            &auth_payload(IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, &auth_data),
        )
        .expect("method 14 RSA verifies");
    }

    #[test]
    fn rsa_key_parsing_fails_closed_on_garbage() {
        assert_eq!(
            Ikev2SignatureAuthKey::rsa_pkcs8_der(
                Ikev2SignatureAuthMethod::RsaDigitalSignature,
                &[0u8; 16]
            )
            .expect_err("garbage RSA key"),
            Ikev2SignatureKeyError::RsaPrivateKeyParse
        );
        // An EC key handed to the RSA parser fails as an RSA parse error.
        assert_eq!(
            Ikev2SignatureAuthKey::rsa_pkcs8_der(
                Ikev2SignatureAuthMethod::DigitalSignature,
                P256_PKCS8_DER
            )
            .expect_err("EC into RSA"),
            Ikev2SignatureKeyError::RsaPrivateKeyParse
        );
    }

    #[test]
    fn rsa_debug_output_redacts_key_material() {
        let key = Ikev2SignatureAuthKey::rsa_pkcs8_der(
            Ikev2SignatureAuthMethod::DigitalSignature,
            RSA_PKCS8_DER,
        )
        .expect("RSA key");
        let debug = format!("{key:?}");
        assert!(debug.contains("key_kind"));
        assert!(debug.len() < 128);
    }
}
