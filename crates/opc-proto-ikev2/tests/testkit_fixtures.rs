use opc_proto_ikev2::testkit::{
    build_fixture_datagram, ike_sa_init_request_datagram, ike_sa_init_response_datagram,
    ike_sa_init_retransmission_datagram, malformed_truncated_payload_datagram,
    nat_t_keepalive_datagram, nat_t_non_esp_marker_only_datagram,
    protected_ike_auth_request_datagram, Ikev2FixtureBuildError, Ikev2FixtureMessagePlan,
    Ikev2FixturePayload, Ikev2FixtureTransport,
};
use opc_proto_ikev2::{
    classify_ike_nat_traversal_datagram, HeaderFlags, NatTraversalClassification,
    NatTraversalIkeDecodeErrorCode, NatTraversalIkeTransport, NatTraversalRejection, PayloadType,
    EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT, IKE_NAT_TRAVERSAL_UDP_PORT, IKE_UDP_PORT,
};

#[test]
fn testkit_builds_udp500_ike_sa_init_and_retransmission_fixtures() {
    let initiator_spi = 0x0102_0304_0506_0708;
    let datagram = match ike_sa_init_request_datagram(Ikev2FixtureTransport::Udp500, initiator_spi)
    {
        Ok(value) => value,
        Err(error) => panic!("IKE_SA_INIT fixture build failed: {error:?}"),
    };
    let retransmission =
        match ike_sa_init_retransmission_datagram(Ikev2FixtureTransport::Udp500, initiator_spi) {
            Ok(value) => value,
            Err(error) => panic!("IKE_SA_INIT retransmission fixture build failed: {error:?}"),
        };

    assert_eq!(datagram, retransmission);
    let classification = classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram);
    match classification {
        NatTraversalClassification::Ike(message) => {
            assert_eq!(message.transport(), NatTraversalIkeTransport::Udp500);
            assert_eq!(message.message().header.initiator_spi, initiator_spi);
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
        }
        other => panic!("unexpected IKE_SA_INIT fixture classification: {other:?}"),
    }
}

#[test]
fn testkit_builds_nat_t_response_and_protected_ike_auth_fixtures() {
    let initiator_spi = 0x0102_0304_0506_0708;
    let responder_spi = 0x8877_6655_4433_2211;
    let response = match ike_sa_init_response_datagram(
        Ikev2FixtureTransport::Udp4500NatTraversal,
        initiator_spi,
        responder_spi,
    ) {
        Ok(value) => value,
        Err(error) => panic!("IKE_SA_INIT response fixture build failed: {error:?}"),
    };
    assert!(response.starts_with(&[0, 0, 0, 0]));
    match classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &response) {
        NatTraversalClassification::Ike(message) => {
            assert_eq!(
                message.transport(),
                NatTraversalIkeTransport::Udp4500NonEspMarker
            );
            assert!(message.message().header.flags.response());
            assert_eq!(message.message().header.responder_spi, responder_spi);
        }
        other => panic!("unexpected IKE_SA_INIT response classification: {other:?}"),
    }

    let auth = match protected_ike_auth_request_datagram(
        Ikev2FixtureTransport::Udp4500NatTraversal,
        initiator_spi,
        responder_spi,
    ) {
        Ok(value) => value,
        Err(error) => panic!("protected IKE_AUTH fixture build failed: {error:?}"),
    };
    match classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &auth) {
        NatTraversalClassification::Ike(message) => {
            assert_eq!(
                message.message().header.exchange_type,
                EXCHANGE_TYPE_IKE_AUTH
            );
            assert_eq!(message.message().header.message_id, 1);
            let mut payloads = message.message().payloads();
            let payload = match payloads.next() {
                Some(Ok(value)) => value,
                other => panic!("unexpected protected payload fixture: {other:?}"),
            };
            assert_eq!(payload.payload_type, PayloadType::Encrypted);
            assert_eq!(payload.next_payload, PayloadType::ExtensibleAuthentication);
            assert!(payload.is_protected());
        }
        other => panic!("unexpected protected IKE_AUTH classification: {other:?}"),
    }
}

#[test]
fn testkit_builds_malformed_and_nat_t_marker_fixtures() {
    let malformed = match malformed_truncated_payload_datagram(
        Ikev2FixtureTransport::Udp4500NatTraversal,
        0x0102_0304_0506_0708,
    ) {
        Ok(value) => value,
        Err(error) => panic!("malformed fixture build failed: {error:?}"),
    };
    match classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &malformed) {
        NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
            decode_code,
            ..
        }) => {
            assert_eq!(decode_code, NatTraversalIkeDecodeErrorCode::Truncated);
        }
        other => panic!("unexpected malformed fixture classification: {other:?}"),
    }

    let keepalive = nat_t_keepalive_datagram();
    assert_eq!(
        classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &keepalive).code(),
        "natt_keepalive"
    );

    let marker_only = nat_t_non_esp_marker_only_datagram();
    assert_eq!(
        classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &marker_only).code(),
        "ike_truncated"
    );
}

#[test]
fn testkit_returns_stable_errors_for_invalid_fixture_input() {
    let long_body = vec![0u8; usize::from(u16::MAX)];
    let payload = [Ikev2FixturePayload::new(
        PayloadType::SecurityAssociation,
        &long_body,
    )];
    let error = match build_fixture_datagram(
        Ikev2FixtureTransport::Udp500,
        Ikev2FixtureMessagePlan {
            initiator_spi: 1,
            responder_spi: 0,
            exchange_type: EXCHANGE_TYPE_IKE_SA_INIT,
            flags: HeaderFlags::from_bits(true, false, false),
            message_id: 0,
            payloads: &payload,
        },
    ) {
        Ok(value) => panic!("oversized payload unexpectedly built fixture: {value:?}"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Ikev2FixtureBuildError::PayloadTooLong { .. }
    ));
    assert_eq!(error.as_str(), "ikev2_fixture_payload_too_long");

    assert_eq!(
        Ikev2FixtureTransport::Udp4500NatTraversal.udp_destination_port(),
        IKE_NAT_TRAVERSAL_UDP_PORT
    );
    assert_eq!(Ikev2FixtureTransport::Udp500.as_str(), "udp_500");
}
