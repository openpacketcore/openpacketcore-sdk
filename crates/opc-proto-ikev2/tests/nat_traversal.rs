use opc_proto_ikev2::{
    classify_ike_nat_traversal_datagram, NatTraversalClassification,
    NatTraversalIkeDecodeErrorCode, NatTraversalIkeTransport, NatTraversalRejection,
    EXCHANGE_TYPE_IKE_SA_INIT, HEADER_LEN, IKE_NAT_TRAVERSAL_UDP_PORT, IKE_UDP_PORT,
    NAT_TRAVERSAL_KEEPALIVE,
};

fn header_only_ike_message() -> [u8; HEADER_LEN] {
    [
        0x01,                      // Initiator SPI byte 0.
        0x02,                      // Initiator SPI byte 1.
        0x03,                      // Initiator SPI byte 2.
        0x04,                      // Initiator SPI byte 3.
        0x05,                      // Initiator SPI byte 4.
        0x06,                      // Initiator SPI byte 5.
        0x07,                      // Initiator SPI byte 6.
        0x08,                      // Initiator SPI byte 7.
        0x00,                      // Responder SPI byte 0.
        0x00,                      // Responder SPI byte 1.
        0x00,                      // Responder SPI byte 2.
        0x00,                      // Responder SPI byte 3.
        0x00,                      // Responder SPI byte 4.
        0x00,                      // Responder SPI byte 5.
        0x00,                      // Responder SPI byte 6.
        0x00,                      // Responder SPI byte 7.
        0x00,                      // No Next Payload.
        0x20,                      // IKEv2 version 2.0.
        EXCHANGE_TYPE_IKE_SA_INIT, // IKE_SA_INIT.
        0x08,                      // Initiator flag set.
        0x00,                      // Message ID byte 0.
        0x00,                      // Message ID byte 1.
        0x00,                      // Message ID byte 2.
        0x00,                      // Message ID byte 3.
        0x00,                      // Length byte 0.
        0x00,                      // Length byte 1.
        0x00,                      // Length byte 2.
        HEADER_LEN as u8,          // Length byte 3.
    ]
}

#[test]
fn classifies_udp_500_ike_without_copying() {
    let datagram = header_only_ike_message();

    let classification = classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram);

    let NatTraversalClassification::Ike(message) = classification else {
        panic!("unexpected classification: {classification:?}");
    };
    assert_eq!(message.transport(), NatTraversalIkeTransport::Udp500);
    assert_eq!(message.udp_destination_port(), IKE_UDP_PORT);
    assert_eq!(message.datagram().as_ptr(), datagram.as_ptr());
    assert_eq!(message.ike_bytes().as_ptr(), datagram.as_ptr());
    assert_eq!(
        message.message().header.exchange_type,
        EXCHANGE_TYPE_IKE_SA_INIT
    );
    assert_eq!(message.message().payloads.bytes().len(), 0);
}

#[test]
fn classifies_udp_4500_non_esp_marker_ike_without_copying() {
    let ike = header_only_ike_message();
    let mut datagram = Vec::from([0x00, 0x00, 0x00, 0x00]);
    datagram.extend_from_slice(&ike);

    let classification = classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &datagram);

    let NatTraversalClassification::Ike(message) = classification else {
        panic!("unexpected classification: {classification:?}");
    };
    assert_eq!(
        message.transport(),
        NatTraversalIkeTransport::Udp4500NonEspMarker
    );
    assert_eq!(message.code(), "natt_ike_non_esp_marker");
    assert_eq!(message.datagram().as_ptr(), datagram.as_ptr());
    assert_eq!(message.ike_bytes().as_ptr(), datagram[4..].as_ptr());
    assert_eq!(message.message().header.length, HEADER_LEN as u32);
}

#[test]
fn classifies_udp_4500_keepalive() {
    let datagram = [NAT_TRAVERSAL_KEEPALIVE];

    let classification = classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &datagram);

    assert_eq!(classification.code(), "natt_keepalive");
    assert!(classification.is_accepted());
    let NatTraversalClassification::NatKeepalive(keepalive) = classification else {
        panic!("unexpected classification: {classification:?}");
    };
    assert_eq!(keepalive.datagram(), datagram);
}

#[test]
fn classifies_udp_4500_esp_candidate() {
    let datagram = [0x01, 0x02, 0x03, 0x04, 0xa0, 0xa1, 0xa2, 0xa3, 0xff];

    let classification = classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &datagram);

    assert_eq!(classification.code(), "natt_esp_candidate");
    assert!(classification.is_accepted());
    let NatTraversalClassification::EspCandidate(candidate) = classification else {
        panic!("unexpected classification: {classification:?}");
    };
    assert_eq!(candidate.datagram(), datagram);
    assert_eq!(candidate.spi(), 0x0102_0304);
    assert_eq!(candidate.sequence_number(), 0xa0a1_a2a3);
}

#[test]
fn rejects_unsupported_port_with_stable_code() {
    let datagram = header_only_ike_message();

    let classification = classify_ike_nat_traversal_datagram(1701, &datagram);

    assert!(!classification.is_accepted());
    assert_eq!(classification.code(), "natt_unsupported_udp_port");
    assert!(matches!(
        classification,
        NatTraversalClassification::Rejected(NatTraversalRejection::UnsupportedPort {
            udp_destination_port: 1701
        })
    ));
}

#[test]
fn rejects_trailing_ike_bytes_with_stable_code() {
    let mut datagram = header_only_ike_message().to_vec();
    datagram.extend_from_slice(&[0xaa, 0xbb]);

    let classification = classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram);

    assert_eq!(classification.code(), "ike_trailing_bytes");
    assert!(matches!(
        classification,
        NatTraversalClassification::Rejected(NatTraversalRejection::TrailingIkeBytes {
            transport: NatTraversalIkeTransport::Udp500,
            declared_len: HEADER_LEN,
            actual_len
        }) if actual_len == HEADER_LEN + 2
    ));
}

#[test]
fn rejects_malformed_ike_with_mapped_decode_code() {
    let datagram = [0x00, 0x00, 0x00, 0x00, 0x20];

    let classification = classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &datagram);

    assert_eq!(classification.code(), "ike_truncated");
    assert!(matches!(
        classification,
        NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
            transport: NatTraversalIkeTransport::Udp500,
            decode_code: NatTraversalIkeDecodeErrorCode::Truncated
        })
    ));
}

#[test]
fn rejects_udp_4500_marker_malformed_ike() {
    let datagram = [0x00, 0x00, 0x00, 0x00, 0x20];

    let classification = classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &datagram);

    assert_eq!(classification.code(), "ike_truncated");
    assert!(matches!(
        classification,
        NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
            transport: NatTraversalIkeTransport::Udp4500NonEspMarker,
            decode_code: NatTraversalIkeDecodeErrorCode::Truncated
        })
    ));
}

#[test]
fn rejects_udp_4500_runt_esp_candidate() {
    let datagram = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    let classification = classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &datagram);

    assert_eq!(classification.code(), "natt_esp_runt");
    assert!(matches!(
        classification,
        NatTraversalClassification::Rejected(NatTraversalRejection::RuntEspCandidate {
            datagram: rejected
        }) if rejected == datagram
    ));
}

#[test]
fn debug_output_redacts_packet_bytes_and_spi_values() {
    let esp_datagram = [0x01, 0x02, 0x03, 0x04, 0xa0, 0xa1, 0xa2, 0xa3, 0xff, 0xee];
    let esp = classify_ike_nat_traversal_datagram(IKE_NAT_TRAVERSAL_UDP_PORT, &esp_datagram);
    let esp_debug = format!("{esp:?}");
    assert!(!esp_debug.contains("16909060"));
    assert!(!esp_debug.contains("2694947491"));
    assert!(!esp_debug.contains("[1, 2, 3, 4"));

    let ike = header_only_ike_message();
    let ike_classification = classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &ike);
    let ike_debug = format!("{ike_classification:?}");
    assert!(!ike_debug.contains("72623859790382856"));
    assert!(!ike_debug.contains("[1, 2, 3, 4"));
    assert!(ike_debug.contains("exchange_type"));
}
