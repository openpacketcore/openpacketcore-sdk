use opc_proto_ikev2::{
    build_ike_auth_identification_payload, build_ike_auth_notify_payload,
    compute_ike_auth_signature, decode_ikev2_signature_hash_algorithms_notify,
    derive_ike_sa_init_key_material, negotiate_ikev2_signature_hash_algorithms,
    verify_ike_auth_signature, Ikev2AuthenticationPayload, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2IdentificationPayloadBuild, Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets,
    Ikev2IkeAuthVerificationError, Ikev2NotifyPayload, Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile,
    Ikev2SignatureAuthKey, Ikev2SignatureHashAlgorithm, Ikev2SignatureHashBindingError,
    Ikev2SignatureHashLocalOffer, Ikev2SignatureHashLocalRole, Ikev2SignatureHashNegotiationError,
    Ikev2SignaturePublicKey, IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
    IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS,
    IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT,
};
use opc_protocol::DecodeContext;

mod support;

const P256_PKCS8_DER: &[u8] = include_bytes!("data/p256_pkcs8.der");
const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
const P384_PKCS8_DER: &[u8] = include_bytes!("data/p384_pkcs8.der");
const P384_SPKI_DER: &[u8] = include_bytes!("data/p384_spki.der");

fn notify(data: &[u8]) -> Ikev2NotifyPayload<'_> {
    Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS,
        spi: &[],
        notification_data: data,
    }
}

fn local_both() -> Ikev2SignatureHashLocalOffer {
    support::ensure_ike_crypto();
    Ikev2SignatureHashLocalOffer::new(&[
        Ikev2SignatureHashAlgorithm::Sha2_384,
        Ikev2SignatureHashAlgorithm::Sha2_256,
    ])
    .expect("admitted local offer")
}

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid test profile")
}

fn key_material() -> opc_proto_ikev2::Ikev2SaInitKeyMaterial {
    support::ensure_ike_crypto();
    derive_ike_sa_init_key_material(
        profile(),
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )
    .expect("test key material")
}

fn identity_payload_body() -> Vec<u8> {
    build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"synthetic.epdg.example".to_vec(),
    })
    .expect("synthetic identity payload")
}

fn signed_octets<'a>(
    peer: Ikev2IkeAuthPeer,
    sa_init_message: &'a [u8],
    identity: &'a [u8],
) -> Ikev2IkeAuthSignedOctets<'a> {
    Ikev2IkeAuthSignedOctets {
        peer,
        ike_sa_init_message: sa_init_message,
        peer_nonce: &[0x77; 32],
        identity_payload_body: identity,
    }
}

#[test]
fn canonical_offer_encoding_and_typed_decoding_preserve_wire_order() {
    let local = local_both();
    assert_eq!(
        local.algorithms(),
        &[
            Ikev2SignatureHashAlgorithm::Sha2_384,
            Ikev2SignatureHashAlgorithm::Sha2_256,
        ]
    );
    let encoded = local.to_notify_payload();
    assert_eq!(encoded.protocol_id, 0);
    assert!(encoded.spi.is_empty());
    assert_eq!(
        encoded.notify_message_type,
        IKEV2_NOTIFY_SIGNATURE_HASH_ALGORITHMS
    );
    assert_eq!(encoded.notification_data, [0x00, 0x03, 0x00, 0x02]);
    let body = build_ike_auth_notify_payload(&encoded).expect("generic Notify body encoder");
    assert_eq!(body, [0x00, 0x00, 0x40, 0x2f, 0x00, 0x03, 0x00, 0x02]);
    let decoded_body = Ikev2NotifyPayload::decode_body(&body).expect("generic Notify body decode");
    assert_eq!(
        decode_ikev2_signature_hash_algorithms_notify(decoded_body)
            .expect("typed Notify decode")
            .expect("matching type")
            .algorithms(),
        local.algorithms()
    );

    let peer_data = [
        0x04, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00,
        0x07, 0x00, 0x08,
    ];
    let peer = decode_ikev2_signature_hash_algorithms_notify(notify(&peer_data))
        .expect("valid peer offer")
        .expect("matching Notify");
    assert_eq!(
        peer.algorithms(),
        &[
            Ikev2SignatureHashAlgorithm::PrivateUse(1024),
            Ikev2SignatureHashAlgorithm::Sha2_256,
            Ikev2SignatureHashAlgorithm::Sha2_384,
            Ikev2SignatureHashAlgorithm::Sha1,
            Ikev2SignatureHashAlgorithm::Sha2_512,
            Ikev2SignatureHashAlgorithm::Identity,
            Ikev2SignatureHashAlgorithm::Streebog256,
            Ikev2SignatureHashAlgorithm::Streebog512,
            Ikev2SignatureHashAlgorithm::Unassigned(8),
        ]
    );
}

#[test]
fn rfc7427_directional_offers_do_not_require_a_common_hash() {
    support::ensure_ike_crypto();
    let (request, response) = support::signature_hash_exchange(
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_256]),
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_384]),
    );

    let responder = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder directional negotiation");
    assert_eq!(
        responder.signing_algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_256]
    );
    assert_eq!(
        responder.verification_algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_384]
    );

    let initiator = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("initiator directional negotiation");
    assert_eq!(
        initiator.signing_algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_384]
    );
    assert_eq!(
        initiator.verification_algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_256]
    );

    let (responder_signing, responder_verification) = responder.into_authorities().into_parts();
    let (initiator_signing, initiator_verification) = initiator.into_authorities().into_parts();
    let identity = identity_payload_body();
    let material = key_material();

    let responder_octets = signed_octets(Ikev2IkeAuthPeer::Responder, &response, &identity);
    let responder_key =
        Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let responder_auth = compute_ike_auth_signature(
        profile(),
        &material,
        responder_octets,
        &responder_key,
        Some(
            responder_signing
                .for_exchange(&request, &response)
                .expect("responder signing authority matches exchange"),
        ),
    )
    .expect("responder signs with hash offered by initiator");
    verify_ike_auth_signature(
        profile(),
        &material,
        responder_octets,
        &Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 SPKI"),
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
            auth_data: &responder_auth,
        },
        Some(
            initiator_verification
                .for_exchange(&request, &response)
                .expect("initiator verification authority matches exchange"),
        ),
    )
    .expect("initiator verifies its offered SHA2-256");

    let initiator_octets = signed_octets(Ikev2IkeAuthPeer::Initiator, &request, &identity);
    let initiator_key =
        Ikev2SignatureAuthKey::ecdsa_p384_pkcs8_der(P384_PKCS8_DER).expect("P-384 key");
    let initiator_auth = compute_ike_auth_signature(
        profile(),
        &material,
        initiator_octets,
        &initiator_key,
        Some(
            initiator_signing
                .for_exchange(&request, &response)
                .expect("initiator signing authority matches exchange"),
        ),
    )
    .expect("initiator signs with hash offered by responder");
    verify_ike_auth_signature(
        profile(),
        &material,
        initiator_octets,
        &Ikev2SignaturePublicKey::from_spki_der(P384_SPKI_DER).expect("P-384 SPKI"),
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
            auth_data: &initiator_auth,
        },
        Some(
            responder_verification
                .for_exchange(&request, &response)
                .expect("responder verification authority matches exchange"),
        ),
    )
    .expect("responder verifies its offered SHA2-384");
}

#[test]
fn omission_and_unsupported_directional_states_fail_closed() {
    support::ensure_ike_crypto();
    let sha256 = [Ikev2SignatureHashAlgorithm::Sha2_256];

    let (request, response) = support::signature_hash_exchange(None, Some(&sha256));
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::LocalOfferMissing)
    );
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Responder,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::PeerOfferMissing)
    );

    let (request, response) = support::signature_hash_exchange(Some(&sha256), None);
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::PeerOfferMissing)
    );
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Responder,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::LocalOfferMissing)
    );

    let (request, response) =
        support::signature_hash_exchange(Some(&[Ikev2SignatureHashAlgorithm::Sha1]), Some(&sha256));
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Responder,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::UnsupportedOnly)
    );

    let (request, response) =
        support::signature_hash_exchange(Some(&sha256), Some(&[Ikev2SignatureHashAlgorithm::Sha1]));
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Responder,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::UnsupportedLocalAlgorithm)
    );
}

#[test]
fn malformed_duplicate_and_oversized_notifies_fail_closed() {
    support::ensure_ike_crypto();
    let wrong_protocol = Ikev2NotifyPayload {
        protocol_id: 1,
        ..notify(&[0, 2])
    };
    let wrong_spi_size = Ikev2NotifyPayload {
        spi_size: 1,
        spi: &[0xaa],
        ..notify(&[0, 2])
    };
    let inconsistent_spi = Ikev2NotifyPayload {
        spi: &[0xaa],
        ..notify(&[0, 2])
    };
    let cases = [
        (
            wrong_protocol,
            Ikev2SignatureHashNegotiationError::ProtocolIdNonzero,
        ),
        (
            wrong_spi_size,
            Ikev2SignatureHashNegotiationError::SpiSizeNonzero,
        ),
        (
            inconsistent_spi,
            Ikev2SignatureHashNegotiationError::SpiNonempty,
        ),
        (notify(&[]), Ikev2SignatureHashNegotiationError::EmptyOffer),
        (
            notify(&[0x00]),
            Ikev2SignatureHashNegotiationError::MalformedDataLength,
        ),
        (
            notify(&[0x00, 0x00]),
            Ikev2SignatureHashNegotiationError::ReservedAlgorithm,
        ),
        (
            notify(&[0x00, 0x02, 0x00, 0x02]),
            Ikev2SignatureHashNegotiationError::DuplicateAlgorithm,
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(
            decode_ikev2_signature_hash_algorithms_notify(input),
            Err(expected)
        );
    }

    let mut at_limit = Vec::new();
    for value in 8..8 + IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT {
        at_limit.extend_from_slice(
            &u16::try_from(value)
                .expect("bounded test identifier")
                .to_be_bytes(),
        );
    }
    assert_eq!(
        decode_ikev2_signature_hash_algorithms_notify(notify(&at_limit))
            .expect("exact resource bound accepts")
            .expect("matching Notify")
            .algorithms()
            .len(),
        IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT
    );
    let oversized = vec![0x00; (IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT + 1) * 2];
    assert_eq!(
        decode_ikev2_signature_hash_algorithms_notify(notify(&oversized)),
        Err(Ikev2SignatureHashNegotiationError::TooManyAlgorithms)
    );

    assert_eq!(
        Ikev2SignatureHashLocalOffer::new(&[]),
        Err(Ikev2SignatureHashNegotiationError::EmptyOffer)
    );
    assert_eq!(
        Ikev2SignatureHashLocalOffer::new(&[
            Ikev2SignatureHashAlgorithm::Sha2_256,
            Ikev2SignatureHashAlgorithm::Sha2_256,
        ]),
        Err(Ikev2SignatureHashNegotiationError::DuplicateAlgorithm)
    );
    assert_eq!(
        Ikev2SignatureHashLocalOffer::new(&[Ikev2SignatureHashAlgorithm::Sha1]),
        Err(Ikev2SignatureHashNegotiationError::UnsupportedLocalAlgorithm)
    );
    let oversized_local =
        vec![Ikev2SignatureHashAlgorithm::Sha2_256; IKEV2_SIGNATURE_HASH_ALGORITHMS_MAX_COUNT + 1];
    assert_eq!(
        Ikev2SignatureHashLocalOffer::new(&oversized_local),
        Err(Ikev2SignatureHashNegotiationError::TooManyAlgorithms)
    );

    let (request, mut response) = support::signature_hash_exchange(
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_256]),
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_256]),
    );
    append_duplicate_last_notify(&mut response);
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::DuplicateNotify)
    );
}

#[test]
fn authority_is_bound_to_exact_exchange_and_peer_before_crypto() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response, signing, verification) =
        support::responder_signature_hash_authorities(&hashes);
    let identity = identity_payload_body();
    let material = key_material();
    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER).expect("P-256 key");
    let octets = signed_octets(Ikev2IkeAuthPeer::Responder, &response, &identity);

    assert_eq!(
        compute_ike_auth_signature(profile(), &material, octets, &key, None),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityMissing)
    );
    let auth_data = compute_ike_auth_signature(
        profile(),
        &material,
        octets,
        &key,
        Some(
            signing
                .for_exchange(&request, &response)
                .expect("signing authority matches exchange"),
        ),
    )
    .expect("exchange-bound signature");
    let authentication = Ikev2AuthenticationPayload {
        auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
        auth_data: &auth_data,
    };
    let public = Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("P-256 public key");
    verify_ike_auth_signature(
        profile(),
        &material,
        octets,
        &public,
        &authentication,
        Some(
            verification
                .for_exchange(&request, &response)
                .expect("verification authority matches exchange"),
        ),
    )
    .expect("matching exchange verifies");

    let mut other_response = response.clone();
    other_response[8] ^= 0x01;
    let wrong_exchange = signed_octets(Ikev2IkeAuthPeer::Responder, &other_response, &identity);
    assert!(matches!(
        signing.for_exchange(&request, &other_response),
        Err(Ikev2SignatureHashBindingError::ExchangeMismatch)
    ));
    assert!(matches!(
        verification.for_exchange(&request, &other_response),
        Err(Ikev2SignatureHashBindingError::ExchangeMismatch)
    ));
    assert_eq!(
        compute_ike_auth_signature(
            profile(),
            &material,
            wrong_exchange,
            &key,
            Some(
                signing
                    .for_exchange(&request, &response)
                    .expect("signing authority matches original exchange"),
            ),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)
    );
    assert_eq!(
        verify_ike_auth_signature(
            profile(),
            &material,
            wrong_exchange,
            &public,
            &authentication,
            Some(
                verification
                    .for_exchange(&request, &response)
                    .expect("verification authority matches original exchange"),
            ),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)
    );
    let wrong_peer = signed_octets(Ikev2IkeAuthPeer::Initiator, &response, &identity);
    assert_eq!(
        compute_ike_auth_signature(
            profile(),
            &material,
            wrong_peer,
            &key,
            Some(
                signing
                    .for_exchange(&request, &response)
                    .expect("signing authority matches original exchange"),
            ),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)
    );
}

#[test]
fn authority_rejects_exchange_when_only_opposite_sa_init_message_changes() {
    support::ensure_ike_crypto();
    let sha256 = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let sha384 = [Ikev2SignatureHashAlgorithm::Sha2_384];

    let (request, response_a) = support::signature_hash_exchange(Some(&sha256), Some(&sha384));
    let (same_request, response_b) = support::signature_hash_exchange(Some(&sha256), Some(&sha256));
    assert_eq!(request, same_request);

    let initiator_authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request,
        &response_a,
        DecodeContext::default(),
    )
    .expect("exchange A initiator negotiation")
    .into_authorities();
    let responder_authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response_a,
        DecodeContext::default(),
    )
    .expect("exchange A responder negotiation")
    .into_authorities();
    assert!(matches!(
        initiator_authorities
            .signing()
            .for_exchange(&request, &response_b),
        Err(Ikev2SignatureHashBindingError::ExchangeMismatch)
    ));
    assert!(matches!(
        responder_authorities
            .verification()
            .for_exchange(&request, &response_b),
        Err(Ikev2SignatureHashBindingError::ExchangeMismatch)
    ));

    let (request_a, response) = support::signature_hash_exchange(Some(&sha384), Some(&sha256));
    let (request_b, same_response) = support::signature_hash_exchange(Some(&sha256), Some(&sha256));
    assert_eq!(response, same_response);

    let responder_authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request_a,
        &response,
        DecodeContext::default(),
    )
    .expect("exchange A responder negotiation")
    .into_authorities();
    let initiator_authorities = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request_a,
        &response,
        DecodeContext::default(),
    )
    .expect("exchange A initiator negotiation")
    .into_authorities();
    assert!(matches!(
        responder_authorities
            .signing()
            .for_exchange(&request_b, &response),
        Err(Ikev2SignatureHashBindingError::ExchangeMismatch)
    ));
    assert!(matches!(
        initiator_authorities
            .verification()
            .for_exchange(&request_b, &response),
        Err(Ikev2SignatureHashBindingError::ExchangeMismatch)
    ));
}

#[test]
fn complete_exchange_correlation_and_trailing_bytes_fail_closed() {
    support::ensure_ike_crypto();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));

    let mut wrong_spi = response.clone();
    wrong_spi[0] ^= 0x01;
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &request,
            &wrong_spi,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::InvalidResponseMessage)
    );

    let mut trailing_request = request.clone();
    trailing_request.push(0xaa);
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &trailing_request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::RequestTrailingBytes)
    );
    let mut trailing_response = response;
    trailing_response.push(0xbb);
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &request,
            &trailing_response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::ResponseTrailingBytes)
    );
}

#[test]
fn unrelated_notify_remains_unconsumed() {
    let unrelated_data = [0x10; 20];
    let unrelated = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
        spi: &[],
        notification_data: &unrelated_data,
    };
    assert_eq!(
        decode_ikev2_signature_hash_algorithms_notify(unrelated),
        Ok(None)
    );
    assert_eq!(unrelated.notification_data, &unrelated_data);
}

#[test]
fn diagnostics_are_stable_and_transcript_free() {
    let marker = "peer-identity-and-packet-marker";
    let binding_error = Ikev2SignatureHashBindingError::ExchangeMismatch;
    assert_eq!(
        binding_error.as_str(),
        "ike_signature_hash_authority_exchange_mismatch"
    );
    assert_eq!(binding_error.to_string(), binding_error.as_str());
    assert!(std::error::Error::source(&binding_error).is_none());
    assert!(!format!("{binding_error:?}").contains(marker));

    let errors = [
        (
            Ikev2SignatureHashNegotiationError::ProtocolIdNonzero,
            "ike_signature_hash_protocol_id_nonzero",
        ),
        (
            Ikev2SignatureHashNegotiationError::SpiSizeNonzero,
            "ike_signature_hash_spi_size_nonzero",
        ),
        (
            Ikev2SignatureHashNegotiationError::SpiNonempty,
            "ike_signature_hash_spi_nonempty",
        ),
        (
            Ikev2SignatureHashNegotiationError::EmptyOffer,
            "ike_signature_hash_empty_offer",
        ),
        (
            Ikev2SignatureHashNegotiationError::MalformedDataLength,
            "ike_signature_hash_malformed_data_length",
        ),
        (
            Ikev2SignatureHashNegotiationError::TooManyAlgorithms,
            "ike_signature_hash_too_many_algorithms",
        ),
        (
            Ikev2SignatureHashNegotiationError::ReservedAlgorithm,
            "ike_signature_hash_reserved_algorithm",
        ),
        (
            Ikev2SignatureHashNegotiationError::DuplicateAlgorithm,
            "ike_signature_hash_duplicate_algorithm",
        ),
        (
            Ikev2SignatureHashNegotiationError::DuplicateNotify,
            "ike_signature_hash_duplicate_notify",
        ),
        (
            Ikev2SignatureHashNegotiationError::LocalOfferMissing,
            "ike_signature_hash_local_offer_missing",
        ),
        (
            Ikev2SignatureHashNegotiationError::PeerOfferMissing,
            "ike_signature_hash_peer_offer_missing",
        ),
        (
            Ikev2SignatureHashNegotiationError::InvalidRequestMessage,
            "ike_signature_hash_invalid_request_message",
        ),
        (
            Ikev2SignatureHashNegotiationError::InvalidResponseMessage,
            "ike_signature_hash_invalid_response_message",
        ),
        (
            Ikev2SignatureHashNegotiationError::RequestTrailingBytes,
            "ike_signature_hash_request_trailing_bytes",
        ),
        (
            Ikev2SignatureHashNegotiationError::ResponseTrailingBytes,
            "ike_signature_hash_response_trailing_bytes",
        ),
        (
            Ikev2SignatureHashNegotiationError::UnsupportedLocalAlgorithm,
            "ike_signature_hash_unsupported_local_algorithm",
        ),
        (
            Ikev2SignatureHashNegotiationError::UnsupportedOnly,
            "ike_signature_hash_unsupported_only",
        ),
    ];
    for (error, code) in errors {
        assert_eq!(error.as_str(), code);
        assert_eq!(error.to_string(), code);
        assert!(!format!("{error:?}").contains(marker));
        assert!(std::error::Error::source(&error).is_none());
    }

    support::ensure_ike_crypto();
    let local = local_both();
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, mut response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    append_noncritical_vendor_id(&mut response, marker.as_bytes());
    let negotiation = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("valid negotiation");
    let authorities = negotiation.into_authorities();
    let signing_authorization = authorities
        .signing()
        .for_exchange(&request, &response)
        .expect("signing authorization");
    let verification_authorization = authorities
        .verification()
        .for_exchange(&request, &response)
        .expect("verification authorization");
    for debug in [
        format!("{local:?}"),
        format!("{authorities:?}"),
        format!("{:?}", authorities.signing()),
        format!("{:?}", authorities.verification()),
        format!("{signing_authorization:?}"),
        format!("{verification_authorization:?}"),
    ] {
        assert!(!debug.contains(marker));
        assert!(!debug.contains("0102030405060708"));
        assert!(debug.len() < 256);
    }
}

fn append_duplicate_last_notify(message: &mut Vec<u8>) {
    let payload_len = 10usize;
    let notify_offset = message
        .len()
        .checked_sub(payload_len)
        .expect("test message contains final Notify");
    let duplicate = message[notify_offset..].to_vec();
    message[notify_offset] = 41;
    message.extend_from_slice(&duplicate);
    let new_len = u32::try_from(message.len()).expect("test message fits IKE length");
    message[24..28].copy_from_slice(&new_len.to_be_bytes());
}

fn append_noncritical_vendor_id(message: &mut Vec<u8>, value: &[u8]) {
    let final_notify_len = 10usize;
    let notify_offset = message
        .len()
        .checked_sub(final_notify_len)
        .expect("test message contains final Notify");
    message[notify_offset] = 43;
    let payload_len = u16::try_from(
        4usize
            .checked_add(value.len())
            .expect("test Vendor ID length"),
    )
    .expect("test Vendor ID fits u16");
    message.push(0);
    message.push(0);
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(value);
    let new_len = u32::try_from(message.len()).expect("test message fits IKE length");
    message[24..28].copy_from_slice(&new_len.to_be_bytes());
}
