#[cfg(feature = "rsa-signing")]
use opc_proto_ikev2::Ikev2SignatureAuthMethod;
use opc_proto_ikev2::{
    build_ike_auth_identification_payload, compute_ike_auth_signature,
    derive_ike_sa_init_key_material, negotiate_ikev2_signature_hash_algorithms,
    verify_ike_auth_signature, verify_local_ike_auth_signature, Ikev2AuthenticationPayload,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IdentificationPayloadBuild, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError, Ikev2PrfAlgorithm,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SignatureAuthKey,
    Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalRole, Ikev2SignaturePublicKey,
    IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
};
use opc_protocol::DecodeContext;

mod support;

const P256_PKCS8_DER: &[u8] = include_bytes!("data/p256_pkcs8.der");
const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
const P384_PKCS8_DER: &[u8] = include_bytes!("data/p384_pkcs8.der");
const P384_SPKI_DER: &[u8] = include_bytes!("data/p384_spki.der");
#[cfg(feature = "rsa-signing")]
const RSA_PKCS8_DER: &[u8] = include_bytes!("data/rsa2048_pkcs8.der");
#[cfg(feature = "rsa-signing")]
const RSA_SPKI_DER: &[u8] = include_bytes!("data/rsa2048_spki.der");

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid synthetic profile")
}

fn key_material(seed: u8) -> Ikev2SaInitKeyMaterial {
    support::ensure_ike_crypto();
    derive_ike_sa_init_key_material(
        profile(),
        [seed; 8],
        [seed.wrapping_add(1); 8],
        &[seed.wrapping_add(2); 32],
        &[seed.wrapping_add(3); 32],
        &[seed.wrapping_add(4); 32],
        None,
    )
    .expect("synthetic key material")
}

fn identity_body(label: &[u8]) -> Vec<u8> {
    build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: label.to_vec(),
    })
    .expect("synthetic identity")
}

fn signed_octets<'a>(
    role: Ikev2IkeAuthPeer,
    request: &'a [u8],
    response: &'a [u8],
    identity_payload_body: &'a [u8],
) -> Ikev2IkeAuthSignedOctets<'a> {
    match role {
        Ikev2IkeAuthPeer::Initiator => Ikev2IkeAuthSignedOctets {
            peer: role,
            ike_sa_init_message: request,
            peer_nonce: support::TEST_RESPONDER_NONCE,
            identity_payload_body,
        },
        Ikev2IkeAuthPeer::Responder => Ikev2IkeAuthSignedOctets {
            peer: role,
            ike_sa_init_message: response,
            peer_nonce: support::TEST_INITIATOR_NONCE,
            identity_payload_body,
        },
    }
}

#[test]
fn responder_p256_auth_self_verifies_but_peer_authority_rejects_local_direction() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder negotiation")
    .into_authorities();
    let identity = identity_body(b"synthetic-responder.example");
    let signed_octets = signed_octets(Ikev2IkeAuthPeer::Responder, &request, &response, &identity);
    let material = key_material(0x10);
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let auth_data = compute_ike_auth_signature(
        profile(),
        &material,
        signed_octets,
        &key,
        Some(
            authorities
                .signing()
                .for_exchange(&request, &response)
                .expect("exact signing exchange"),
        ),
    )
    .expect("local responder signature");
    let authentication = Ikev2AuthenticationPayload {
        auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
        auth_data: &auth_data,
    };

    let local_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            signed_octets,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local responder authorization");
    verify_local_ike_auth_signature(profile(), &material, &authentication, local_authorization)
        .expect("local responder AUTH self-verifies");

    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &material,
            signed_octets,
            &public,
            &authentication,
            Some(
                authorities
                    .verification()
                    .for_exchange(&request, &response)
                    .expect("exact peer-verification exchange"),
            ),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)
    );
}

#[test]
fn initiator_p384_sha384_auth_self_verifies() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_384];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("initiator negotiation")
    .into_authorities();
    let identity = identity_body(b"synthetic-initiator.example");
    let signed_octets = signed_octets(Ikev2IkeAuthPeer::Initiator, &request, &response, &identity);
    let material = key_material(0x20);
    let key = Ikev2SignatureAuthKey::ecdsa_p384_pkcs8_der(P384_PKCS8_DER).expect("P-384 key");
    let public = Ikev2SignaturePublicKey::from_spki_der(P384_SPKI_DER).expect("P-384 SPKI");
    let auth_data = compute_ike_auth_signature(
        profile(),
        &material,
        signed_octets,
        &key,
        Some(
            authorities
                .signing()
                .for_exchange(&request, &response)
                .expect("exact signing exchange"),
        ),
    )
    .expect("local initiator signature");
    let authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            signed_octets,
            Ikev2SignatureHashAlgorithm::Sha2_384,
            &public,
        )
        .expect("exact local initiator authorization");

    verify_local_ike_auth_signature(
        profile(),
        &material,
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
            auth_data: &auth_data,
        },
        authorization,
    )
    .expect("local initiator AUTH self-verifies");
}

#[test]
fn local_authorization_rejects_transcript_role_nonce_and_invalid_identity() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder negotiation")
    .into_authorities();
    let identity = identity_body(b"synthetic-boundary.example");
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let exact = signed_octets(Ikev2IkeAuthPeer::Responder, &request, &response, &identity);

    let mut changed_request = request.clone();
    changed_request[8] ^= 1;
    let mut changed_response = response.clone();
    changed_response[8] ^= 1;
    for result in [
        authorities
            .signing()
            .authorize_local_auth_self_verification(
                &changed_request,
                &response,
                exact,
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            ),
        authorities
            .signing()
            .authorize_local_auth_self_verification(
                &request,
                &changed_response,
                exact,
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            ),
        authorities
            .signing()
            .authorize_local_auth_self_verification(
                &request,
                &response,
                Ikev2IkeAuthSignedOctets {
                    peer: Ikev2IkeAuthPeer::Initiator,
                    ..exact
                },
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            ),
        authorities
            .signing()
            .authorize_local_auth_self_verification(
                &request,
                &response,
                Ikev2IkeAuthSignedOctets {
                    ike_sa_init_message: &request,
                    ..exact
                },
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            ),
        authorities
            .signing()
            .authorize_local_auth_self_verification(
                &request,
                &response,
                Ikev2IkeAuthSignedOctets {
                    peer_nonce: support::TEST_RESPONDER_NONCE,
                    ..exact
                },
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            ),
    ] {
        assert_eq!(
            result.expect_err("substitution must fail before authorization"),
            Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch
        );
    }

    assert_eq!(
        authorities
            .signing()
            .authorize_local_auth_self_verification(
                &request,
                &response,
                Ikev2IkeAuthSignedOctets {
                    identity_payload_body: &[2, 0, 0],
                    ..exact
                },
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            )
            .expect_err("truncated identity must fail before authorization"),
        Ikev2IkeAuthVerificationError::IdentityPayloadTooShort
    );
}

#[test]
fn local_verification_rejects_identity_method_signature_key_and_credential_substitution() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder negotiation")
    .into_authorities();
    let identity = identity_body(b"synthetic-original.example");
    let exact = signed_octets(Ikev2IkeAuthPeer::Responder, &request, &response, &identity);
    let material = key_material(0x30);
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let auth_data = compute_ike_auth_signature(
        profile(),
        &material,
        exact,
        &key,
        Some(
            authorities
                .signing()
                .for_exchange(&request, &response)
                .expect("exact signing exchange"),
        ),
    )
    .expect("local signature");

    let changed_identity = identity_body(b"synthetic-substituted.example");
    let changed_identity_octets = Ikev2IkeAuthSignedOctets {
        identity_payload_body: &changed_identity,
        ..exact
    };
    let identity_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            changed_identity_octets,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("substituted identity is structurally valid and bound");
    assert_eq!(
        verify_local_ike_auth_signature(
            profile(),
            &material,
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &auth_data,
            },
            identity_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
    );

    let method_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local authorization");
    assert_eq!(
        verify_local_ike_auth_signature(
            profile(),
            &material,
            &Ikev2AuthenticationPayload {
                auth_method: 1,
                auth_data: &auth_data,
            },
            method_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod { method: 1 })
    );

    let mut changed_signature = auth_data.clone();
    let signature_start = 1 + usize::from(changed_signature[0]);
    changed_signature[signature_start + 8] ^= 1;
    let signature_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local authorization");
    assert_eq!(
        verify_local_ike_auth_signature(
            profile(),
            &material,
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &changed_signature,
            },
            signature_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
    );

    let key_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local authorization");
    assert_eq!(
        verify_local_ike_auth_signature(
            profile(),
            &key_material(0x40),
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &auth_data,
            },
            key_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
    );

    let alternate_signing_key =
        p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).expect("valid alternate P-256 scalar");
    let alternate_public =
        Ikev2SignaturePublicKey::EcdsaP256(alternate_signing_key.verifying_key().to_owned());
    let credential_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &alternate_public,
        )
        .expect("alternate credential is executable");
    assert_eq!(
        verify_local_ike_auth_signature(
            profile(),
            &material,
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &auth_data,
            },
            credential_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
    );
}

#[test]
fn local_verification_rejects_selected_hash_substitution_before_crypto() {
    support::ensure_ike_crypto();
    let hashes = [
        Ikev2SignatureHashAlgorithm::Sha2_384,
        Ikev2SignatureHashAlgorithm::Sha2_256,
    ];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder negotiation")
    .into_authorities();
    let identity = identity_body(b"synthetic-hash.example");
    let exact = signed_octets(Ikev2IkeAuthPeer::Responder, &request, &response, &identity);
    let material = key_material(0x50);
    let key = Ikev2SignatureAuthKey::ecdsa_p384_pkcs8_der(P384_PKCS8_DER).expect("P-384 key");
    let public = Ikev2SignaturePublicKey::from_spki_der(P384_SPKI_DER).expect("P-384 SPKI");
    let auth_data = compute_ike_auth_signature(
        profile(),
        &material,
        exact,
        &key,
        Some(
            authorities
                .signing()
                .for_exchange(&request, &response)
                .expect("exact signing exchange"),
        ),
    )
    .expect("SHA2-384 signature");
    let wrong_hash_authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("P-384 can execute the separately authorized SHA2-256");

    assert_eq!(
        verify_local_ike_auth_signature(
            profile(),
            &material,
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &auth_data,
            },
            wrong_hash_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashNotAuthorized)
    );
}

#[test]
fn local_authorization_and_errors_are_redaction_safe() {
    support::ensure_ike_crypto();
    const IDENTITY_MARKER: &[u8] = b"credential-and-identity-must-not-appear";
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder negotiation")
    .into_authorities();
    let identity = identity_body(IDENTITY_MARKER);
    let exact = signed_octets(Ikev2IkeAuthPeer::Responder, &request, &response, &identity);
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI");
    let authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local authorization");
    let debug = format!("{authorization:?}");
    assert!(!debug.contains(std::str::from_utf8(IDENTITY_MARKER).expect("ASCII marker")));
    assert!(!debug.contains("nonce"));
    assert!(!debug.contains("credential"));
    assert!(!debug.contains("ike_sa_init"));

    let mut wrong_response = response.clone();
    wrong_response[8] ^= 1;
    let error = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &wrong_response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect_err("wrong transcript");
    for rendered in [format!("{error:?}"), error.to_string()] {
        assert!(!rendered.contains(std::str::from_utf8(IDENTITY_MARKER).expect("ASCII marker")));
        assert!(!rendered.contains("66"));
        assert!(!rendered.contains("77"));
        assert!(!rendered.contains("BEGIN"));
    }
}

#[cfg(feature = "rsa-signing")]
#[test]
fn responder_rsa_method14_auth_self_verifies() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder negotiation")
    .into_authorities();
    let identity = identity_body(b"synthetic-rsa-responder.example");
    let exact = signed_octets(Ikev2IkeAuthPeer::Responder, &request, &response, &identity);
    let material = key_material(0x60);
    let key = Ikev2SignatureAuthKey::rsa_pkcs8_der(
        Ikev2SignatureAuthMethod::DigitalSignature,
        RSA_PKCS8_DER,
    )
    .expect("RSA method-14 key");
    let public = Ikev2SignaturePublicKey::from_spki_der(RSA_SPKI_DER).expect("RSA SPKI");
    let auth_data = compute_ike_auth_signature(
        profile(),
        &material,
        exact,
        &key,
        Some(
            authorities
                .signing()
                .for_exchange(&request, &response)
                .expect("exact signing exchange"),
        ),
    )
    .expect("RSA method-14 signature");
    let authorization = authorities
        .signing()
        .authorize_local_auth_self_verification(
            &request,
            &response,
            exact,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local RSA authorization");

    verify_local_ike_auth_signature(
        profile(),
        &material,
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
            auth_data: &auth_data,
        },
        authorization,
    )
    .expect("local RSA method-14 AUTH self-verifies");
}
