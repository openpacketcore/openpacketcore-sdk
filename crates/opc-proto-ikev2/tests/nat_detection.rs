use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

mod support;

use opc_proto_ikev2::{
    evaluate_ikev2_nat_detection, ikev2_nat_detection_hash as sdk_nat_detection_hash,
    Ikev2NatDetectionEndpointStatus, Ikev2NatDetectionObservedEndpoint, Ikev2NatDetectionOutcome,
    Ikev2NatDetectionPayloadError, Ikev2NatDetectionPayloads, Ikev2NotifyPayload,
    IKEV2_NAT_DETECTION_HASH_LEN, IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
    IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, IKEV2_NOTIFY_PROTOCOL_ID_NONE,
};

const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
const IPV4_SOURCE_HASH: [u8; IKEV2_NAT_DETECTION_HASH_LEN] = [
    0x44, 0x1d, 0x37, 0x7f, 0x16, 0x13, 0x13, 0x01, 0x42, 0x83, 0x7a, 0xc1, 0xd5, 0xad, 0x09, 0x9c,
    0xad, 0xa6, 0xff, 0x2d,
];
const IPV4_DESTINATION_HASH: [u8; IKEV2_NAT_DETECTION_HASH_LEN] = [
    0xb1, 0x58, 0x05, 0x14, 0xa5, 0xe2, 0x78, 0x54, 0xcb, 0x5b, 0x5d, 0x72, 0x48, 0x53, 0xa9, 0x79,
    0xd4, 0xb1, 0xd8, 0x5c,
];
const IPV6_SOURCE_HASH: [u8; IKEV2_NAT_DETECTION_HASH_LEN] = [
    0x05, 0xce, 0x03, 0xdc, 0x8b, 0x67, 0x13, 0xbc, 0x8d, 0x43, 0xfd, 0xa9, 0xc7, 0x20, 0x64, 0xdb,
    0x36, 0x7e, 0x11, 0x6e,
];
const IPV6_DESTINATION_HASH: [u8; IKEV2_NAT_DETECTION_HASH_LEN] = [
    0xfb, 0x92, 0xcb, 0x1d, 0xc1, 0x0a, 0x16, 0xc4, 0xd1, 0xea, 0x26, 0x6d, 0x95, 0xfc, 0x9c, 0x43,
    0x02, 0x4c, 0xa2, 0x17,
];

fn ipv4_source() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 500)
}

fn ipv4_destination() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 500)
}

fn ipv6_source() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010)),
        4500,
    )
}

fn ipv6_destination() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0020)),
        4500,
    )
}

fn alternate_source() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 33)), 4500)
}

fn alternate_destination() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44)), 4500)
}

fn ikev2_nat_detection_hash(
    initiator_spi: u64,
    responder_spi: u64,
    endpoint: SocketAddr,
) -> [u8; IKEV2_NAT_DETECTION_HASH_LEN] {
    support::ensure_ike_crypto();
    sdk_nat_detection_hash(initiator_spi, responder_spi, endpoint)
        .expect("explicitly admitted NAT-D hash computes")
}

fn natd_notify<'a>(
    notify_message_type: u16,
    notification_data: &'a [u8],
) -> Ikev2NotifyPayload<'a> {
    Ikev2NotifyPayload {
        protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        spi_size: 0,
        notify_message_type,
        spi: &[],
        notification_data,
    }
}

fn evaluate<'a>(
    source_hashes: impl IntoIterator<Item = &'a [u8]>,
    destination_hash: Option<&'a [u8]>,
    source: SocketAddr,
    destination: SocketAddr,
) -> opc_proto_ikev2::Ikev2NatDetectionEvaluation {
    support::ensure_ike_crypto();
    let mut payloads = Ikev2NatDetectionPayloads::new();
    for source_hash in source_hashes {
        payloads
            .push_notify(natd_notify(
                IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
                source_hash,
            ))
            .unwrap();
    }
    if let Some(destination_hash) = destination_hash {
        payloads
            .push_notify(natd_notify(
                IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
                destination_hash,
            ))
            .unwrap();
    }

    evaluate_ikev2_nat_detection(
        &payloads,
        INITIATOR_SPI,
        RESPONDER_SPI,
        source.into(),
        destination.into(),
    )
    .expect("explicitly admitted NAT-D evaluation computes")
}

#[test]
fn nat_detection_hash_matches_ipv4_and_ipv6_vectors() {
    assert_eq!(
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, ipv4_source()),
        IPV4_SOURCE_HASH
    );
    assert_eq!(
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, ipv4_destination()),
        IPV4_DESTINATION_HASH
    );
    assert_eq!(
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, ipv6_source()),
        IPV6_SOURCE_HASH
    );
    assert_eq!(
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, ipv6_destination()),
        IPV6_DESTINATION_HASH
    );
}

#[test]
fn no_nat_detection_payloads_are_unknown() {
    support::ensure_ike_crypto();
    let payloads = Ikev2NatDetectionPayloads::new();

    let evaluation = evaluate_ikev2_nat_detection(
        &payloads,
        INITIATOR_SPI,
        RESPONDER_SPI,
        ipv4_source().into(),
        ipv4_destination().into(),
    )
    .expect("explicitly admitted NAT-D evaluation computes");

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::Unknown);
    assert_eq!(evaluation.code(), "ike_nat_detection_unknown");
    assert_eq!(evaluation.source_hash_count(), 0);
    assert!(!evaluation.has_destination_hash());
    assert_eq!(evaluation.source_hash_matched(), None);
    assert_eq!(evaluation.destination_hash_matched(), None);
}

#[test]
fn matching_source_and_destination_hashes_report_no_nat() {
    let evaluation = evaluate(
        [&IPV4_SOURCE_HASH[..]],
        Some(&IPV4_DESTINATION_HASH),
        ipv4_source(),
        ipv4_destination(),
    );

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::NoNat);
    assert_eq!(evaluation.source_hash_matched(), Some(true));
    assert_eq!(evaluation.destination_hash_matched(), Some(true));
}

#[test]
fn source_mismatch_only_reports_source_nat() {
    let alternate_source_hash =
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, alternate_source());

    let evaluation = evaluate(
        [&alternate_source_hash[..]],
        Some(&IPV4_DESTINATION_HASH),
        ipv4_source(),
        ipv4_destination(),
    );

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::SourceNat);
    assert_eq!(evaluation.source_hash_matched(), Some(false));
    assert_eq!(evaluation.destination_hash_matched(), Some(true));
}

#[test]
fn destination_mismatch_only_reports_destination_nat() {
    let alternate_destination_hash =
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, alternate_destination());

    let evaluation = evaluate(
        [&IPV4_SOURCE_HASH[..]],
        Some(&alternate_destination_hash),
        ipv4_source(),
        ipv4_destination(),
    );

    assert_eq!(
        evaluation.outcome(),
        Ikev2NatDetectionOutcome::DestinationNat
    );
    assert_eq!(evaluation.source_hash_matched(), Some(true));
    assert_eq!(evaluation.destination_hash_matched(), Some(false));
}

#[test]
fn both_mismatch_reports_both_nat() {
    let alternate_source_hash =
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, alternate_source());
    let alternate_destination_hash =
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, alternate_destination());

    let evaluation = evaluate(
        [&alternate_source_hash[..]],
        Some(&alternate_destination_hash),
        ipv4_source(),
        ipv4_destination(),
    );

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::Both);
    assert_eq!(evaluation.source_hash_matched(), Some(false));
    assert_eq!(evaluation.destination_hash_matched(), Some(false));
}

#[test]
fn multiple_source_hashes_match_as_or_set() {
    let alternate_source_hash =
        ikev2_nat_detection_hash(INITIATOR_SPI, RESPONDER_SPI, alternate_source());

    let evaluation = evaluate(
        [&alternate_source_hash[..], &IPV4_SOURCE_HASH[..]],
        Some(&IPV4_DESTINATION_HASH),
        ipv4_source(),
        ipv4_destination(),
    );

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::NoNat);
    assert_eq!(evaluation.source_hash_count(), 2);
    assert_eq!(evaluation.source_hash_matched(), Some(true));
}

#[test]
fn missing_destination_hash_is_unknown() {
    let evaluation = evaluate(
        [&IPV4_SOURCE_HASH[..]],
        None,
        ipv4_source(),
        ipv4_destination(),
    );

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::Unknown);
    assert_eq!(evaluation.source_hash_matched(), None);
    assert_eq!(evaluation.destination_hash_matched(), None);
}

#[test]
fn wildcard_local_endpoint_is_unknown() {
    support::ensure_ike_crypto();
    let evaluation = evaluate_ikev2_nat_detection(
        &Ikev2NatDetectionPayloads::from_notifies([
            natd_notify(IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, &IPV4_SOURCE_HASH),
            natd_notify(
                IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
                &IPV4_DESTINATION_HASH,
            ),
        ])
        .unwrap(),
        INITIATOR_SPI,
        RESPONDER_SPI,
        ipv4_source().into(),
        Ikev2NatDetectionObservedEndpoint::socket_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            500,
        )),
    )
    .expect("explicitly admitted NAT-D evaluation computes");

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::Unknown);
    assert_eq!(
        evaluation.destination_endpoint_status(),
        Ikev2NatDetectionEndpointStatus::UnspecifiedAddress
    );
    assert_eq!(evaluation.source_hash_matched(), None);
    assert_eq!(evaluation.destination_hash_matched(), None);
}

#[test]
fn missing_local_endpoint_is_unknown() {
    support::ensure_ike_crypto();
    let payloads = Ikev2NatDetectionPayloads::from_notifies([
        natd_notify(IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, &IPV4_SOURCE_HASH),
        natd_notify(
            IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
            &IPV4_DESTINATION_HASH,
        ),
    ])
    .unwrap();

    let evaluation = evaluate_ikev2_nat_detection(
        &payloads,
        INITIATOR_SPI,
        RESPONDER_SPI,
        ipv4_source().into(),
        Ikev2NatDetectionObservedEndpoint::Missing,
    )
    .expect("explicitly admitted NAT-D evaluation computes");

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::Unknown);
    assert_eq!(
        evaluation.destination_endpoint_status(),
        Ikev2NatDetectionEndpointStatus::Missing
    );
}

#[test]
fn ipv6_hashes_evaluate_successfully() {
    let evaluation = evaluate(
        [&IPV6_SOURCE_HASH[..]],
        Some(&IPV6_DESTINATION_HASH),
        ipv6_source(),
        ipv6_destination(),
    );

    assert_eq!(evaluation.outcome(), Ikev2NatDetectionOutcome::NoNat);
    assert_eq!(
        evaluation.source_endpoint_status(),
        Ikev2NatDetectionEndpointStatus::Concrete
    );
    assert_eq!(
        evaluation.destination_endpoint_status(),
        Ikev2NatDetectionEndpointStatus::Concrete
    );
}

#[test]
fn collector_ignores_unrelated_notify_and_rejects_duplicate_destination() {
    let unrelated = natd_notify(16_390, b"cookie");
    let destination = natd_notify(
        IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
        &IPV4_DESTINATION_HASH,
    );

    let mut payloads = Ikev2NatDetectionPayloads::new();

    assert!(!payloads.push_notify(unrelated).unwrap());
    assert!(payloads.push_notify(destination).unwrap());
    let error = payloads.push_notify(destination).unwrap_err();

    assert_eq!(
        error,
        Ikev2NatDetectionPayloadError::DuplicateDestinationHash
    );
    assert_eq!(
        error.as_str(),
        "ike_nat_detection_duplicate_destination_hash"
    );
}

#[test]
fn collector_rejects_invalid_shape_and_hash_length() {
    let invalid_shape = Ikev2NotifyPayload {
        protocol_id: 1,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
        spi: &[],
        notification_data: &IPV4_SOURCE_HASH,
    };
    let short_hash = natd_notify(IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP, b"leaky-secret");

    let mut payloads = Ikev2NatDetectionPayloads::new();

    assert!(matches!(
        payloads.push_notify(invalid_shape),
        Err(Ikev2NatDetectionPayloadError::InvalidNotifyShape {
            notify_message_type: IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP
        })
    ));
    let error = payloads.push_notify(short_hash).unwrap_err();
    assert!(matches!(
        error,
        Ikev2NatDetectionPayloadError::InvalidHashLength {
            notify_message_type: IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
            len: 12
        }
    ));
    assert_eq!(error.as_str(), "ike_nat_detection_invalid_hash_length");
    assert_eq!(error.to_string(), error.as_str());
    assert!(!format!("{error:?}").contains("leaky-secret"));
    assert!(!format!("{error}").contains("leaky-secret"));
}

#[test]
fn debug_output_redacts_nat_detection_hashes_and_endpoints() {
    support::ensure_ike_crypto();
    let payloads = Ikev2NatDetectionPayloads::from_notifies([
        natd_notify(IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, &IPV4_SOURCE_HASH),
        natd_notify(
            IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
            &IPV4_DESTINATION_HASH,
        ),
    ])
    .unwrap();
    let evaluation = evaluate_ikev2_nat_detection(
        &payloads,
        INITIATOR_SPI,
        RESPONDER_SPI,
        ipv4_source().into(),
        ipv4_destination().into(),
    )
    .expect("explicitly admitted NAT-D evaluation computes");
    let payloads_debug = format!("{payloads:?}");
    let evaluation_debug = format!("{evaluation:?}");
    let endpoint_debug = format!(
        "{:?}",
        Ikev2NatDetectionObservedEndpoint::socket_addr(ipv4_destination())
    );

    for output in [payloads_debug, evaluation_debug, endpoint_debug] {
        assert!(!output.contains("192.0.2.10"));
        assert!(!output.contains("198.51.100.20"));
        assert!(!output.contains("[68, 29, 55"));
        assert!(!output.contains("[177, 88, 5"));
        assert!(!output.contains("441d377f"));
        assert!(!output.contains("b1580514"));
    }
}
