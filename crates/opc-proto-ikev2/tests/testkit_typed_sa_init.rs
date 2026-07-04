use opc_proto_ikev2::testkit::{
    ike_sa_init_request_datagram, ike_sa_init_request_datagram_typed,
    ike_sa_init_request_datagram_typed_default, Ikev2FixtureBuildError, Ikev2FixtureTransport,
    Ikev2TypedSaInitProfile,
};
use opc_proto_ikev2::{
    classify_ike_nat_traversal_datagram, decode_ike_sa_init_request_payloads, Ikev2DhGroup,
    Ikev2NoncePayloadBuild, Ikev2SaInitBuildError, Ikev2TransformAttributeValue,
    NatTraversalClassification, NatTraversalIkeTransport, PayloadType, EXCHANGE_TYPE_IKE_SA_INIT,
    IKE_UDP_PORT,
};
use opc_protocol::DecodeContext;

const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;

#[test]
fn typed_default_fixture_round_trips_through_sa_init_decode() {
    let datagram = match ike_sa_init_request_datagram_typed_default(
        Ikev2FixtureTransport::Udp500,
        INITIATOR_SPI,
    ) {
        Ok(value) => value,
        Err(error) => panic!("typed SA_INIT fixture build failed: {error:?}"),
    };

    let message = match classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram) {
        NatTraversalClassification::Ike(message) => message,
        other => panic!("unexpected typed SA_INIT classification: {other:?}"),
    };

    // Mirror the header/classification checks the placeholder fixture test runs.
    assert_eq!(message.transport(), NatTraversalIkeTransport::Udp500);
    assert_eq!(message.message().header.initiator_spi, INITIATOR_SPI);
    assert_eq!(message.message().header.responder_spi, 0);
    assert_eq!(
        message.message().header.exchange_type,
        EXCHANGE_TYPE_IKE_SA_INIT
    );
    assert_eq!(message.message().header.message_id, 0);
    assert_eq!(
        message.message().payloads.first_payload(),
        PayloadType::SecurityAssociation
    );

    let decoded =
        match decode_ike_sa_init_request_payloads(message.message(), DecodeContext::default()) {
            Ok(value) => value,
            Err(error) => panic!("typed SA_INIT payload decode failed: {error:?}"),
        };

    // Exactly one SA, one KE, one Nonce projected.
    assert_eq!(decoded.security_association.proposals.len(), 1);
    let proposal = &decoded.security_association.proposals[0];
    assert_eq!(proposal.transforms.len(), 4);

    // ENCR transform with the 256-bit key-length attribute.
    let encr = &proposal.transforms[0];
    assert_eq!(encr.transform_type, 1);
    assert_eq!(encr.transform_id, 12);
    assert_eq!(encr.attributes.len(), 1);
    assert_eq!(encr.attributes[0].attribute_type, 14);
    assert_eq!(
        encr.attributes[0].value,
        Ikev2TransformAttributeValue::Tv(256)
    );

    // DH transform group matches the KE payload group.
    let dh = &proposal.transforms[3];
    assert_eq!(dh.transform_type, 4);
    assert_eq!(dh.transform_id, Ikev2DhGroup::Ecp256.transform_id());

    assert_eq!(
        decoded.key_exchange.dh_group,
        Ikev2DhGroup::Ecp256.transform_id()
    );
    assert_eq!(
        decoded.key_exchange.key_exchange_data.len(),
        Ikev2DhGroup::Ecp256.public_value_len()
    );
    assert!(decoded.nonce.nonce.len() >= 16);
    assert_eq!(decoded.nonce.nonce.len(), 32);
}

#[test]
fn typed_default_fixture_is_deterministic_and_distinct_from_placeholder() {
    let typed_a =
        ike_sa_init_request_datagram_typed_default(Ikev2FixtureTransport::Udp500, INITIATOR_SPI);
    let typed_b =
        ike_sa_init_request_datagram_typed_default(Ikev2FixtureTransport::Udp500, INITIATOR_SPI);
    let (typed_a, typed_b) = match (typed_a, typed_b) {
        (Ok(a), Ok(b)) => (a, b),
        other => panic!("typed fixture build failed: {other:?}"),
    };
    assert_eq!(typed_a, typed_b, "typed fixture must be byte-deterministic");

    let placeholder =
        match ike_sa_init_request_datagram(Ikev2FixtureTransport::Udp500, INITIATOR_SPI) {
            Ok(value) => value,
            Err(error) => panic!("placeholder fixture build failed: {error:?}"),
        };
    assert_ne!(
        typed_a, placeholder,
        "typed fixture must carry different bodies than the placeholder fixture"
    );
}

#[test]
fn typed_fixture_supports_nat_t_transport() {
    let datagram = match ike_sa_init_request_datagram_typed_default(
        Ikev2FixtureTransport::Udp4500NatTraversal,
        INITIATOR_SPI,
    ) {
        Ok(value) => value,
        Err(error) => panic!("typed NAT-T SA_INIT fixture build failed: {error:?}"),
    };
    assert!(
        datagram.starts_with(&[0, 0, 0, 0]),
        "NAT-T non-ESP marker prefix"
    );
}

#[test]
fn typed_fixture_rejects_short_nonce_override_with_stable_error() {
    let mut profile = Ikev2TypedSaInitProfile::default_profile();
    // 8 octets is below the RFC 7296 16-octet nonce minimum.
    profile.nonce = Ikev2NoncePayloadBuild {
        nonce: vec![0u8; 8],
    };

    let error = match ike_sa_init_request_datagram_typed(
        Ikev2FixtureTransport::Udp500,
        INITIATOR_SPI,
        &profile,
    ) {
        Ok(value) => panic!("short nonce override unexpectedly built fixture: {value:?}"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        Ikev2FixtureBuildError::TypedPayload(Ikev2SaInitBuildError::NonceTooShort)
    ));
    assert_eq!(error.as_str(), "ikev2_fixture_typed_payload_invalid");

    // Redaction: the error surfaces stable codes, never nonce bytes.
    let rendered = format!("{error} {error:?}");
    assert!(rendered.contains("ikev2_fixture_typed_payload_invalid"));
    assert!(rendered.contains("ike_sa_init_build_nonce_too_short"));
}

#[test]
fn typed_fixture_rejects_empty_key_exchange_override_with_stable_error() {
    let mut profile = Ikev2TypedSaInitProfile::default_profile();
    profile.key_exchange.key_exchange_data.clear();

    let error = match ike_sa_init_request_datagram_typed(
        Ikev2FixtureTransport::Udp500,
        INITIATOR_SPI,
        &profile,
    ) {
        Ok(value) => panic!("empty KE override unexpectedly built fixture: {value:?}"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        Ikev2FixtureBuildError::TypedPayload(Ikev2SaInitBuildError::EmptyKeyExchangeData)
    ));
    assert_eq!(error.as_str(), "ikev2_fixture_typed_payload_invalid");
}
