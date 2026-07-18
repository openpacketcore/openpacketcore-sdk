use opc_ipsec_lb::{
    classify_keyless_ingress_packet, EspEncapsulationKind, IngressEncapsulationKind,
    IngressIdentityProvenance, IngressPacketIdentity, IngressUnclassifiableReason, IpAddress,
    KeylessIngressClassification, OwnershipKeyKind, RoutingDomainTag, SessionOwnershipKey,
};
use proptest::prelude::*;

const SERVICE_A: [u8; 4] = [192, 0, 2, 10];
const SERVICE_B: [u8; 4] = [192, 0, 2, 11];
const PEER_A: [u8; 4] = [198, 51, 100, 20];
const ROUTER_A: [u8; 4] = [203, 0, 113, 1];
const SERVICE_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10];
const PEER_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20];
const ROUTER_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const ROUTING_DOMAIN: RoutingDomainTag = RoutingDomainTag::new(7);
const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
const ESP_SPI: u32 = 0x2122_2324;

fn ike_header(
    initiator_spi: u64,
    responder_spi: u64,
    exchange_type: u8,
    next_payload: u8,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 28];
    bytes[0..8].copy_from_slice(&initiator_spi.to_be_bytes());
    bytes[8..16].copy_from_slice(&responder_spi.to_be_bytes());
    bytes[16] = next_payload;
    bytes[17] = 0x20;
    bytes[18] = exchange_type;
    bytes[24..28].copy_from_slice(&28_u32.to_be_bytes());
    bytes
}

fn esp_prefix(spi: u32) -> Vec<u8> {
    let mut bytes = Vec::from(spi.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes
}

fn udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(8 + payload.len()).expect("test UDP length fits");
    let mut bytes = Vec::with_capacity(usize::from(length));
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&destination_port.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv4_with_fragment(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    fragment: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = u16::try_from(20 + payload.len()).expect("test IPv4 length fits");
    let mut bytes = vec![0_u8; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
    bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&source);
    bytes[16..20].copy_from_slice(&destination);
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv4(source: [u8; 4], destination: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_with_fragment(source, destination, protocol, 0, payload)
}

fn ipv6(source: [u8; 16], destination: [u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = u16::try_from(payload.len()).expect("test IPv6 payload length fits");
    let mut bytes = vec![0_u8; 40];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&payload_len.to_be_bytes());
    bytes[6] = next_header;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&source);
    bytes[24..40].copy_from_slice(&destination);
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv6_first_fragment(
    source: [u8; 16],
    destination: [u8; 16],
    next_header: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut fragment = vec![next_header, 0, 0, 1, 0, 0, 0, 1];
    fragment.extend_from_slice(payload);
    ipv6(source, destination, 44, &fragment)
}

fn natt_ike(ike: &[u8]) -> Vec<u8> {
    let mut payload = vec![0, 0, 0, 0];
    payload.extend_from_slice(ike);
    payload
}

fn icmp_error(icmp_type: u8, code: u8, quote: &[u8]) -> Vec<u8> {
    let mut bytes = vec![icmp_type, code, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(quote);
    bytes
}

fn outer_destination(packet: &[u8]) -> Option<IpAddress> {
    match packet.first().map(|first| first >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddress::V4([
            packet[16], packet[17], packet[18], packet[19],
        ])),
        Some(6) if packet.len() >= 40 => Some(IpAddress::V6([
            packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30],
            packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37],
            packet[38], packet[39],
        ])),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum Expected {
    Ownership {
        kind: OwnershipKeyKind,
        encapsulation: IngressEncapsulationKind,
        provenance: IngressIdentityProvenance,
        source_port: Option<u16>,
    },
    QuotedEsp {
        encapsulation: IngressEncapsulationKind,
        esp_encapsulation: EspEncapsulationKind,
        provenance: IngressIdentityProvenance,
    },
    Unclassifiable(IngressUnclassifiableReason),
}

#[test]
fn required_raw_packet_vectors_extract_destination_scoped_identities() {
    let initial_ike = ike_header(INITIATOR_SPI, 0, 34, 33);
    let established_ike = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46);
    let skf_ike = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 53);
    let esp = esp_prefix(ESP_SPI);
    let quoted_esp = ipv4(SERVICE_A, PEER_A, 50, &esp);

    let cases = vec![
        (
            "UDP/500 IKE_SA_INIT",
            ipv4(PEER_A, SERVICE_A, 17, &udp(40_000, 500, &initial_ike)),
            Expected::Ownership {
                kind: OwnershipKeyKind::InitialIke,
                encapsulation: IngressEncapsulationKind::IkeUdp500,
                provenance: IngressIdentityProvenance::Direct,
                source_port: Some(40_000),
            },
        ),
        (
            "UDP/500 established IKE",
            ipv4(PEER_A, SERVICE_A, 17, &udp(40_001, 500, &established_ike)),
            Expected::Ownership {
                kind: OwnershipKeyKind::EstablishedIke,
                encapsulation: IngressEncapsulationKind::IkeUdp500,
                provenance: IngressIdentityProvenance::Direct,
                source_port: Some(40_001),
            },
        ),
        (
            "UDP/4500 established IKE",
            ipv4(
                PEER_A,
                SERVICE_A,
                17,
                &udp(45_000, 4500, &natt_ike(&established_ike)),
            ),
            Expected::Ownership {
                kind: OwnershipKeyKind::EstablishedIke,
                encapsulation: IngressEncapsulationKind::IkeUdp4500,
                provenance: IngressIdentityProvenance::Direct,
                source_port: Some(45_000),
            },
        ),
        (
            "UDP/4500 ESP",
            ipv4(PEER_A, SERVICE_A, 17, &udp(45_000, 4500, &esp)),
            Expected::Ownership {
                kind: OwnershipKeyKind::Esp,
                encapsulation: IngressEncapsulationKind::EspUdp4500,
                provenance: IngressIdentityProvenance::Direct,
                source_port: Some(45_000),
            },
        ),
        (
            "native ESP",
            ipv4(PEER_A, SERVICE_A, 50, &esp),
            Expected::Ownership {
                kind: OwnershipKeyKind::Esp,
                encapsulation: IngressEncapsulationKind::NativeEsp,
                provenance: IngressIdentityProvenance::Direct,
                source_port: None,
            },
        ),
        (
            "RFC 7383 SKF",
            ipv4(
                PEER_A,
                SERVICE_A,
                17,
                &udp(45_000, 4500, &natt_ike(&skf_ike)),
            ),
            Expected::Ownership {
                kind: OwnershipKeyKind::EstablishedIke,
                encapsulation: IngressEncapsulationKind::IkeUdp4500,
                provenance: IngressIdentityProvenance::Direct,
                source_port: Some(45_000),
            },
        ),
        (
            "non-initial IPv4 fragment",
            ipv4_with_fragment(PEER_A, SERVICE_A, 50, 1, &esp),
            Expected::Unclassifiable(IngressUnclassifiableReason::NonInitialIpFragment),
        ),
        (
            "ICMP PTB quoting native ESP",
            ipv4(ROUTER_A, SERVICE_A, 1, &icmp_error(3, 4, &quoted_esp)),
            Expected::QuotedEsp {
                encapsulation: IngressEncapsulationKind::NativeEsp,
                esp_encapsulation: EspEncapsulationKind::Native,
                provenance: IngressIdentityProvenance::IcmpV4Quote,
            },
        ),
    ];

    for (name, packet, expected) in cases {
        let classification = classify_keyless_ingress_packet(&packet, ROUTING_DOMAIN);
        match expected {
            Expected::Ownership {
                kind,
                encapsulation,
                provenance,
                source_port,
            } => {
                let matched = classification
                    .matched()
                    .unwrap_or_else(|| panic!("{name}: expected a classified packet"));
                let key = matched
                    .ownership_key()
                    .unwrap_or_else(|| panic!("{name}: expected an ownership key"));
                assert_eq!(key.kind(), kind, "{name}");
                assert_eq!(
                    key.destination().address(),
                    IpAddress::V4(SERVICE_A),
                    "{name}"
                );
                assert_eq!(key.destination().routing_domain(), ROUTING_DOMAIN, "{name}");
                assert_eq!(matched.encapsulation(), encapsulation, "{name}");
                assert_eq!(matched.provenance(), provenance, "{name}");
                assert_eq!(matched.outer_source().udp_port(), source_port, "{name}");
                match key {
                    SessionOwnershipKey::InitialIke(key) => {
                        assert_eq!(key.initiator_spi().get(), INITIATOR_SPI, "{name}");
                        assert_eq!(
                            key.outer_source().address(),
                            IpAddress::V4(PEER_A),
                            "{name}"
                        );
                        assert_eq!(
                            key.outer_source().port(),
                            source_port.expect("initial IKE is UDP")
                        );
                    }
                    SessionOwnershipKey::EstablishedIke(key) => {
                        assert_eq!(key.initiator_spi().get(), INITIATOR_SPI, "{name}");
                        assert_eq!(key.responder_spi().get(), RESPONDER_SPI, "{name}");
                    }
                    SessionOwnershipKey::Esp(key) => {
                        assert_eq!(key.inbound_spi().get(), ESP_SPI, "{name}");
                        let expected = match encapsulation {
                            IngressEncapsulationKind::EspUdp4500 => {
                                EspEncapsulationKind::UdpEncapsulated
                            }
                            IngressEncapsulationKind::NativeEsp => EspEncapsulationKind::Native,
                            _ => panic!("{name}: ESP key carried by an IKE encapsulation"),
                        };
                        assert_eq!(key.encapsulation(), expected, "{name}");
                    }
                }
            }
            Expected::QuotedEsp {
                encapsulation,
                esp_encapsulation,
                provenance,
            } => {
                let matched = classification
                    .matched()
                    .unwrap_or_else(|| panic!("{name}: expected a quoted match"));
                assert_eq!(matched.encapsulation(), encapsulation, "{name}");
                assert_eq!(matched.provenance(), provenance, "{name}");
                assert_eq!(matched.outer_source().address(), IpAddress::V4(ROUTER_A));
                assert_eq!(matched.outer_source().udp_port(), None);
                assert_eq!(matched.ownership_key(), None, "{name}");
                let IngressPacketIdentity::QuotedEsp(identity) = matched.identity() else {
                    panic!("{name}: expected direction-safe quoted ESP identity");
                };
                assert_eq!(identity.destination().address(), IpAddress::V4(SERVICE_A));
                assert_eq!(identity.destination().routing_domain(), ROUTING_DOMAIN);
                assert_eq!(identity.encapsulation(), esp_encapsulation);
                assert_eq!(identity.spi().get(), ESP_SPI);
            }
            Expected::Unclassifiable(reason) => {
                assert_eq!(
                    classification.unclassifiable_reason(),
                    Some(reason),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn skf_and_unfragmented_ike_have_the_same_session_identity() {
    let normal = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(
            45_000,
            4500,
            &natt_ike(&ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46)),
        ),
    );
    let skf = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(
            45_000,
            4500,
            &natt_ike(&ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 53)),
        ),
    );

    let normal = classify_keyless_ingress_packet(&normal, ROUTING_DOMAIN)
        .matched()
        .expect("ordinary IKE matches");
    let skf = classify_keyless_ingress_packet(&skf, ROUTING_DOMAIN)
        .matched()
        .expect("SKF IKE matches");
    assert_eq!(normal.identity(), skf.identity());
}

#[test]
fn first_ip_fragment_can_use_a_complete_fixed_ike_header() {
    let mut ike = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46);
    ike[24..28].copy_from_slice(&64_u32.to_be_bytes());
    let mut datagram = udp(40_000, 500, &ike);
    datagram[4..6].copy_from_slice(&72_u16.to_be_bytes());
    let packets = [
        ipv4_with_fragment(PEER_A, SERVICE_A, 17, 0x2000, &datagram),
        ipv6_first_fragment(PEER_V6, SERVICE_V6, 17, &datagram),
    ];

    for packet in packets {
        let matched = classify_keyless_ingress_packet(&packet, ROUTING_DOMAIN)
            .matched()
            .expect("first fragment with the complete fixed IKE header classifies");
        assert_eq!(matched.encapsulation(), IngressEncapsulationKind::IkeUdp500);
        assert_eq!(
            matched
                .ownership_key()
                .expect("established IKE has an ownership key")
                .kind(),
            OwnershipKeyKind::EstablishedIke
        );
    }
}

#[test]
fn udp_and_ike_declared_lengths_must_describe_one_consistent_envelope() {
    let mut complete_ike_mismatch = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46);
    complete_ike_mismatch[24..28].copy_from_slice(&64_u32.to_be_bytes());
    let complete_ike_mismatch = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(40_000, 500, &complete_ike_mismatch),
    );

    let mut fragment_ike_mismatch = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46);
    fragment_ike_mismatch[24..28].copy_from_slice(&80_u32.to_be_bytes());
    let mut fragment_udp_mismatch = udp(40_000, 500, &fragment_ike_mismatch);
    fragment_udp_mismatch[4..6].copy_from_slice(&72_u16.to_be_bytes());
    let fragment_ike_mismatch =
        ipv4_with_fragment(PEER_A, SERVICE_A, 17, 0x2000, &fragment_udp_mismatch);

    let mut complete_quoted_udp = udp(
        500,
        40_000,
        &ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46),
    );
    complete_quoted_udp[4..6].copy_from_slice(&72_u16.to_be_bytes());
    let complete_quoted_udp = ipv4(
        ROUTER_A,
        SERVICE_A,
        1,
        &icmp_error(3, 4, &ipv4(SERVICE_A, PEER_A, 17, &complete_quoted_udp)),
    );

    let mut natt_fragment = udp(
        45_000,
        4500,
        &natt_ike(&ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46)),
    );
    natt_fragment[4..6].copy_from_slice(&48_u16.to_be_bytes());
    let natt_fragment = ipv4_with_fragment(PEER_A, SERVICE_A, 17, 0x2000, &natt_fragment);

    let marker_only = ipv4(PEER_A, SERVICE_A, 17, &udp(45_000, 4500, &[0, 0, 0, 0]));

    let mut truncated_quoted_ip = ipv4(
        SERVICE_A,
        PEER_A,
        17,
        &udp(4500, 40_000, &esp_prefix(ESP_SPI)),
    );
    truncated_quoted_ip[2..4].copy_from_slice(&100_u16.to_be_bytes());
    let truncated_quote_with_short_udp = ipv4(
        ROUTER_A,
        SERVICE_A,
        1,
        &icmp_error(3, 4, &truncated_quoted_ip),
    );

    let exact_fragment_ike_udp = udp(
        40_000,
        500,
        &ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46),
    );
    let exact_ipv4_fragment_ike =
        ipv4_with_fragment(PEER_A, SERVICE_A, 17, 0x2000, &exact_fragment_ike_udp);
    let exact_ipv6_fragment_ike =
        ipv6_first_fragment(PEER_V6, SERVICE_V6, 17, &exact_fragment_ike_udp);
    let exact_ipv4_fragment_keepalive =
        ipv4_with_fragment(PEER_A, SERVICE_A, 17, 0x2000, &udp(45_000, 4500, &[0xff]));
    let exact_ipv6_fragment_keepalive =
        ipv6_first_fragment(PEER_V6, SERVICE_V6, 17, &udp(45_000, 4500, &[0xff]));

    let cases = [
        (
            complete_ike_mismatch,
            IngressUnclassifiableReason::MalformedIkeHeader,
        ),
        (
            fragment_ike_mismatch,
            IngressUnclassifiableReason::MalformedIkeHeader,
        ),
        (
            complete_quoted_udp,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            natt_fragment,
            IngressUnclassifiableReason::MalformedIkeHeader,
        ),
        (
            marker_only,
            IngressUnclassifiableReason::TruncatedNatTraversalIke,
        ),
        (
            truncated_quote_with_short_udp,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            exact_ipv4_fragment_ike,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            exact_ipv6_fragment_ike,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            exact_ipv4_fragment_keepalive,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            exact_ipv6_fragment_keepalive,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
    ];

    for (packet, reason) in cases {
        assert_eq!(
            classify_keyless_ingress_packet(&packet, ROUTING_DOMAIN).unclassifiable_reason(),
            Some(reason)
        );
    }
}

#[test]
fn direct_and_quoted_udp_use_destination_and_source_ports_respectively() {
    let ike = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46);
    let direct_wrong_direction = ipv4(PEER_A, SERVICE_A, 17, &udp(500, 40_000, &ike));
    assert_eq!(
        classify_keyless_ingress_packet(&direct_wrong_direction, ROUTING_DOMAIN)
            .unclassifiable_reason(),
        Some(IngressUnclassifiableReason::UnsupportedUdpPort)
    );

    let quoted_wrong_direction = ipv4(
        ROUTER_A,
        SERVICE_A,
        1,
        &icmp_error(3, 4, &ipv4(SERVICE_A, PEER_A, 17, &udp(40_000, 500, &ike))),
    );
    assert_eq!(
        classify_keyless_ingress_packet(&quoted_wrong_direction, ROUTING_DOMAIN)
            .unclassifiable_reason(),
        Some(IngressUnclassifiableReason::UnsupportedIcmpQuotedProtocol)
    );
}

#[test]
fn identical_esp_spi_on_two_destinations_produces_distinct_ownership_keys() {
    let esp = esp_prefix(ESP_SPI);
    let first = ipv4(PEER_A, SERVICE_A, 50, &esp);
    let second = ipv4(PEER_A, SERVICE_B, 50, &esp);
    let first = classify_keyless_ingress_packet(&first, ROUTING_DOMAIN)
        .matched()
        .expect("first destination classifies")
        .ownership_key()
        .expect("direct ESP has an ownership key");
    let second = classify_keyless_ingress_packet(&second, ROUTING_DOMAIN)
        .matched()
        .expect("second destination classifies")
        .ownership_key()
        .expect("direct ESP has an ownership key");

    assert_ne!(first, second);
    let (SessionOwnershipKey::Esp(first), SessionOwnershipKey::Esp(second)) = (first, second)
    else {
        panic!("both packets must produce ESP ownership keys");
    };
    assert_eq!(first.inbound_spi(), second.inbound_spi());
    assert_ne!(first.destination(), second.destination());
}

#[test]
fn icmpv6_ptb_and_udp_encapsulated_quote_preserve_direction() {
    let quoted = ipv6(
        SERVICE_V6,
        PEER_V6,
        17,
        &udp(4500, 45_000, &esp_prefix(ESP_SPI)),
    );
    let outer = ipv6(ROUTER_V6, SERVICE_V6, 58, &icmp_error(2, 0, &quoted));
    let matched = classify_keyless_ingress_packet(&outer, ROUTING_DOMAIN)
        .matched()
        .expect("ICMPv6 PTB quote classifies");
    assert_eq!(matched.provenance(), IngressIdentityProvenance::IcmpV6Quote);
    assert_eq!(
        matched.encapsulation(),
        IngressEncapsulationKind::EspUdp4500
    );
    assert_eq!(matched.destination().address(), IpAddress::V6(SERVICE_V6));
    assert_eq!(matched.ownership_key(), None);
    let IngressPacketIdentity::QuotedEsp(identity) = matched.identity() else {
        panic!("quoted UDP ESP must stay direction-sensitive");
    };
    assert_eq!(
        identity.encapsulation(),
        EspEncapsulationKind::UdpEncapsulated
    );
    assert_eq!(identity.spi().get(), ESP_SPI);
}

#[test]
fn established_ike_in_an_icmp_quote_can_use_the_direction_neutral_key() {
    let quoted = ipv4(
        SERVICE_A,
        PEER_A,
        17,
        &udp(
            500,
            40_000,
            &ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46),
        ),
    );
    let outer = ipv4(ROUTER_A, SERVICE_A, 1, &icmp_error(3, 4, &quoted));
    let matched = classify_keyless_ingress_packet(&outer, ROUTING_DOMAIN)
        .matched()
        .expect("quoted established IKE classifies");
    assert_eq!(matched.provenance(), IngressIdentityProvenance::IcmpV4Quote);
    let key = matched
        .ownership_key()
        .expect("established IKE SPI pair is direction-neutral");
    assert_eq!(key.kind(), OwnershipKeyKind::EstablishedIke);
}

#[test]
fn keepalive_is_explicit_and_carries_redacted_observation() {
    let packet = ipv4(PEER_A, SERVICE_A, 17, &udp(45_000, 4500, &[0xff]));
    let classification = classify_keyless_ingress_packet(&packet, ROUTING_DOMAIN);
    let KeylessIngressClassification::NatTraversalKeepalive {
        destination,
        outer_source,
    } = classification
    else {
        panic!("one-octet NAT-T keepalive must be explicit");
    };
    assert_eq!(destination.address(), IpAddress::V4(SERVICE_A));
    assert_eq!(outer_source.address(), IpAddress::V4(PEER_A));
    assert_eq!(outer_source.udp_port(), Some(45_000));
}

#[test]
fn malformed_fragments_lengths_and_quotes_fail_closed_with_typed_reasons() {
    let mut malformed_udp = udp(40_000, 500, &ike_header(INITIATOR_SPI, 0, 34, 33));
    malformed_udp[4..6].copy_from_slice(&7_u16.to_be_bytes());
    let malformed_udp = ipv4(PEER_A, SERVICE_A, 17, &malformed_udp);

    let mut malformed_ike = ike_header(INITIATOR_SPI, 0, 34, 33);
    malformed_ike[24..28].copy_from_slice(&27_u32.to_be_bytes());
    let malformed_ike = ipv4(PEER_A, SERVICE_A, 17, &udp(40_000, 500, &malformed_ike));

    let reserved_esp = ipv4(PEER_A, SERVICE_A, 50, &esp_prefix(255));

    let mismatched_quote = ipv4(
        ROUTER_A,
        SERVICE_A,
        1,
        &icmp_error(3, 4, &ipv4(SERVICE_B, PEER_A, 50, &esp_prefix(ESP_SPI))),
    );

    let quoted_initial = ipv4(
        ROUTER_A,
        SERVICE_A,
        1,
        &icmp_error(
            3,
            4,
            &ipv4(
                SERVICE_A,
                PEER_A,
                17,
                &udp(500, 40_000, &ike_header(INITIATOR_SPI, 0, 34, 33)),
            ),
        ),
    );

    let cases = [
        (
            malformed_udp,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            malformed_ike,
            IngressUnclassifiableReason::MalformedIkeHeader,
        ),
        (reserved_esp, IngressUnclassifiableReason::InvalidEspSpi),
        (
            mismatched_quote,
            IngressUnclassifiableReason::IcmpQuoteAddressMismatch,
        ),
        (
            quoted_initial,
            IngressUnclassifiableReason::QuotedInitialIke,
        ),
    ];

    for (packet, reason) in cases {
        assert_eq!(
            classify_keyless_ingress_packet(&packet, ROUTING_DOMAIN).unclassifiable_reason(),
            Some(reason)
        );
    }
}

#[test]
fn fixed_header_mutations_never_produce_a_guessed_identity() {
    let mut invalid_ihl = ipv4(PEER_A, SERVICE_A, 50, &esp_prefix(ESP_SPI));
    invalid_ihl[0] = 0x44;

    let mut invalid_ipv4_total = ipv4(PEER_A, SERVICE_A, 50, &esp_prefix(ESP_SPI));
    invalid_ipv4_total[2..4].copy_from_slice(&19_u16.to_be_bytes());

    let mut truncated_ipv6_payload = ipv6(PEER_V6, SERVICE_V6, 50, &esp_prefix(ESP_SPI));
    truncated_ipv6_payload[4..6].copy_from_slice(&64_u16.to_be_bytes());

    let mut oversized_udp = udp(
        40_000,
        500,
        &ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46),
    );
    oversized_udp[4..6].copy_from_slice(&72_u16.to_be_bytes());
    let oversized_udp = ipv4(PEER_A, SERVICE_A, 17, &oversized_udp);

    let mut wrong_ike_version = ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46);
    wrong_ike_version[17] = 0x10;
    let wrong_ike_version = ipv4(PEER_A, SERVICE_A, 17, &udp(40_000, 500, &wrong_ike_version));

    let zero_initiator = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(40_000, 500, &ike_header(0, RESPONDER_SPI, 35, 46)),
    );
    let zero_responder_wrong_exchange = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(40_000, 500, &ike_header(INITIATOR_SPI, 0, 35, 46)),
    );
    let esp_runt = ipv4(PEER_A, SERVICE_A, 50, &[1, 2, 3, 4, 0, 0, 1]);
    let marker_mutated_to_reserved_esp = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(45_000, 4500, &[0, 0, 0, 1, 0, 0, 0, 1]),
    );
    let nested_icmp = ipv4(
        ROUTER_A,
        SERVICE_A,
        1,
        &icmp_error(3, 4, &ipv4(SERVICE_A, PEER_A, 1, &icmp_error(3, 4, &[]))),
    );

    let cases = [
        (invalid_ihl, IngressUnclassifiableReason::MalformedIpHeader),
        (
            invalid_ipv4_total,
            IngressUnclassifiableReason::MalformedIpHeader,
        ),
        (
            truncated_ipv6_payload,
            IngressUnclassifiableReason::TruncatedIpPacket,
        ),
        (
            oversized_udp,
            IngressUnclassifiableReason::MalformedUdpLength,
        ),
        (
            wrong_ike_version,
            IngressUnclassifiableReason::UnsupportedIkeVersion,
        ),
        (zero_initiator, IngressUnclassifiableReason::InvalidIkeSpi),
        (
            zero_responder_wrong_exchange,
            IngressUnclassifiableReason::InvalidInitialIkeExchange,
        ),
        (esp_runt, IngressUnclassifiableReason::TruncatedEspHeader),
        (
            marker_mutated_to_reserved_esp,
            IngressUnclassifiableReason::InvalidEspSpi,
        ),
        (
            nested_icmp,
            IngressUnclassifiableReason::UnsupportedIcmpQuotedProtocol,
        ),
    ];

    for (packet, reason) in cases {
        assert_eq!(
            classify_keyless_ingress_packet(&packet, ROUTING_DOMAIN).unclassifiable_reason(),
            Some(reason)
        );
    }

    let extended_keepalive_is_esp = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(45_000, 4500, &[0xff, 0, 0, 0, 0, 0, 0, 1]),
    );
    let matched = classify_keyless_ingress_packet(&extended_keepalive_is_esp, ROUTING_DOMAIN)
        .matched()
        .expect("only the exact one-octet value is a NAT-T keepalive");
    assert_eq!(
        matched.encapsulation(),
        IngressEncapsulationKind::EspUdp4500
    );
}

#[test]
fn ipv6_extension_order_and_authentication_header_lengths_fail_closed() {
    let esp = esp_prefix(ESP_SPI);

    let mut short_ah = vec![50, 0, 0, 0, 0, 0, 0, 0];
    short_ah.extend_from_slice(&esp);
    let short_ah = ipv6(PEER_V6, SERVICE_V6, 51, &short_ah);
    assert_eq!(
        classify_keyless_ingress_packet(&short_ah, ROUTING_DOMAIN).unclassifiable_reason(),
        Some(IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader)
    );

    let truncated_minimum_ah = ipv6(PEER_V6, SERVICE_V6, 51, &[50, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        classify_keyless_ingress_packet(&truncated_minimum_ah, ROUTING_DOMAIN)
            .unclassifiable_reason(),
        Some(IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader)
    );

    let mut unaligned_ah = vec![50, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    unaligned_ah.extend_from_slice(&esp);
    let unaligned_ah = ipv6(PEER_V6, SERVICE_V6, 51, &unaligned_ah);
    assert_eq!(
        classify_keyless_ingress_packet(&unaligned_ah, ROUTING_DOMAIN).unclassifiable_reason(),
        Some(IngressUnclassifiableReason::MalformedIpv6AuthenticationHeader)
    );

    let mut aligned_ah = vec![50, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    aligned_ah.extend_from_slice(&esp);
    let aligned_ah = ipv6(PEER_V6, SERVICE_V6, 51, &aligned_ah);
    let aligned = classify_keyless_ingress_packet(&aligned_ah, ROUTING_DOMAIN)
        .matched()
        .expect("minimum aligned 16-byte AH followed by ESP classifies");
    assert_eq!(aligned.encapsulation(), IngressEncapsulationKind::NativeEsp);

    let mut longer_aligned_ah = vec![50, 4, 0, 0, 0, 0, 0, 0];
    longer_aligned_ah.extend_from_slice(&[0; 16]);
    longer_aligned_ah.extend_from_slice(&esp);
    let longer_aligned_ah = ipv6(PEER_V6, SERVICE_V6, 51, &longer_aligned_ah);
    let longer_aligned = classify_keyless_ingress_packet(&longer_aligned_ah, ROUTING_DOMAIN)
        .matched()
        .expect("aligned 24-byte AH followed by ESP classifies");
    assert_eq!(
        longer_aligned.encapsulation(),
        IngressEncapsulationKind::NativeEsp
    );

    let mut hop_then_destination = vec![60, 0, 0, 0, 0, 0, 0, 0];
    hop_then_destination.extend_from_slice(&[50, 0, 0, 0, 0, 0, 0, 0]);
    hop_then_destination.extend_from_slice(&esp);
    let hop_then_destination = ipv6(PEER_V6, SERVICE_V6, 0, &hop_then_destination);
    assert!(
        classify_keyless_ingress_packet(&hop_then_destination, ROUTING_DOMAIN)
            .matched()
            .is_some()
    );

    let mut destination_then_hop = vec![0, 0, 0, 0, 0, 0, 0, 0];
    destination_then_hop.extend_from_slice(&[50, 0, 0, 0, 0, 0, 0, 0]);
    destination_then_hop.extend_from_slice(&esp);
    let destination_then_hop = ipv6(PEER_V6, SERVICE_V6, 60, &destination_then_hop);
    assert_eq!(
        classify_keyless_ingress_packet(&destination_then_hop, ROUTING_DOMAIN)
            .unclassifiable_reason(),
        Some(IngressUnclassifiableReason::InvalidIpv6ExtensionChain)
    );

    let mut duplicate_routing = vec![43, 0, 0, 0, 0, 0, 0, 0];
    duplicate_routing.extend_from_slice(&[50, 0, 0, 0, 0, 0, 0, 0]);
    duplicate_routing.extend_from_slice(&esp);
    let duplicate_routing = ipv6(PEER_V6, SERVICE_V6, 43, &duplicate_routing);
    assert_eq!(
        classify_keyless_ingress_packet(&duplicate_routing, ROUTING_DOMAIN).unclassifiable_reason(),
        Some(IngressUnclassifiableReason::InvalidIpv6ExtensionChain)
    );

    let mut fragment_then_routing = vec![43, 0, 0, 0, 0, 0, 0, 1];
    fragment_then_routing.extend_from_slice(&[50, 0, 0, 0, 0, 0, 0, 0]);
    fragment_then_routing.extend_from_slice(&esp);
    let fragment_then_routing = ipv6(PEER_V6, SERVICE_V6, 44, &fragment_then_routing);
    assert_eq!(
        classify_keyless_ingress_packet(&fragment_then_routing, ROUTING_DOMAIN)
            .unclassifiable_reason(),
        Some(IngressUnclassifiableReason::InvalidIpv6ExtensionChain)
    );
}

#[test]
fn ipv6_fragment_offset_reserved_bits_and_more_flag_are_distinct() {
    let mut non_initial = vec![50, 0, 0, 8, 0, 0, 0, 1];
    non_initial.extend_from_slice(&esp_prefix(ESP_SPI));
    let non_initial = ipv6(PEER_V6, SERVICE_V6, 44, &non_initial);
    assert_eq!(
        classify_keyless_ingress_packet(&non_initial, ROUTING_DOMAIN).unclassifiable_reason(),
        Some(IngressUnclassifiableReason::NonInitialIpFragment)
    );

    let mut reserved_bits = vec![50, 0, 0, 2, 0, 0, 0, 1];
    reserved_bits.extend_from_slice(&esp_prefix(ESP_SPI));
    let reserved_bits = ipv6(PEER_V6, SERVICE_V6, 44, &reserved_bits);
    assert_eq!(
        classify_keyless_ingress_packet(&reserved_bits, ROUTING_DOMAIN).unclassifiable_reason(),
        Some(IngressUnclassifiableReason::MalformedIpHeader)
    );

    let mut first_with_more = vec![50, 0, 0, 1, 0, 0, 0, 1];
    first_with_more.extend_from_slice(&esp_prefix(ESP_SPI));
    let first_with_more = ipv6(PEER_V6, SERVICE_V6, 44, &first_with_more);
    assert!(
        classify_keyless_ingress_packet(&first_with_more, ROUTING_DOMAIN)
            .matched()
            .is_some()
    );
}

#[test]
fn every_truncation_and_deterministic_hostile_input_is_panic_free() {
    let valid_packets = [
        ipv4(
            PEER_A,
            SERVICE_A,
            17,
            &udp(
                45_000,
                4500,
                &natt_ike(&ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 53)),
            ),
        ),
        ipv4(PEER_A, SERVICE_A, 50, &esp_prefix(ESP_SPI)),
        ipv4(
            ROUTER_A,
            SERVICE_A,
            1,
            &icmp_error(3, 4, &ipv4(SERVICE_A, PEER_A, 50, &esp_prefix(ESP_SPI))),
        ),
    ];

    for packet in &valid_packets {
        for end in 0..packet.len() {
            let classification = classify_keyless_ingress_packet(&packet[..end], ROUTING_DOMAIN);
            assert!(
                classification.unclassifiable_reason().is_some(),
                "truncated prefix at {end} bytes must fail closed"
            );
        }
    }

    let mut state = 0x9e37_79b9_u32;
    for length in 0..=512usize {
        let mut input = vec![0_u8; length];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let _ = classify_keyless_ingress_packet(&input, ROUTING_DOMAIN);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bounded_packets_are_panic_free_deterministic_and_structural(
        packet in prop::collection::vec(any::<u8>(), 0..2049),
        routing_value in any::<u64>(),
    ) {
        let routing_domain = RoutingDomainTag::new(routing_value);
        let first = classify_keyless_ingress_packet(&packet, routing_domain);
        let second = classify_keyless_ingress_packet(&packet, routing_domain);
        prop_assert_eq!(first, second);

        match first {
            KeylessIngressClassification::Classified(matched) => {
                prop_assert_eq!(matched.destination().routing_domain(), routing_domain);
                prop_assert_eq!(
                    Some(matched.destination().address()),
                    outer_destination(&packet),
                );
                match matched.identity() {
                    IngressPacketIdentity::Ownership(key) => {
                        prop_assert_eq!(matched.ownership_key(), Some(key));
                        match key {
                            SessionOwnershipKey::InitialIke(key) => {
                                prop_assert_ne!(key.initiator_spi().get(), 0);
                                prop_assert_eq!(key.exchange().get(), 34);
                                prop_assert_eq!(
                                    matched.outer_source().udp_tuple(),
                                    Some(key.outer_source()),
                                );
                                prop_assert!(matches!(
                                    matched.encapsulation(),
                                    IngressEncapsulationKind::IkeUdp500
                                        | IngressEncapsulationKind::IkeUdp4500
                                ));
                            }
                            SessionOwnershipKey::EstablishedIke(key) => {
                                prop_assert_ne!(key.initiator_spi().get(), 0);
                                prop_assert_ne!(key.responder_spi().get(), 0);
                                prop_assert!(matches!(
                                    matched.encapsulation(),
                                    IngressEncapsulationKind::IkeUdp500
                                        | IngressEncapsulationKind::IkeUdp4500
                                ));
                            }
                            SessionOwnershipKey::Esp(key) => {
                                prop_assert!(key.inbound_spi().get() >= 256);
                                prop_assert!(matches!(
                                    (matched.encapsulation(), key.encapsulation()),
                                    (
                                        IngressEncapsulationKind::NativeEsp,
                                        EspEncapsulationKind::Native,
                                    ) | (
                                        IngressEncapsulationKind::EspUdp4500,
                                        EspEncapsulationKind::UdpEncapsulated,
                                    )
                                ));
                            }
                        }
                    }
                    IngressPacketIdentity::QuotedEsp(identity) => {
                        prop_assert_eq!(matched.ownership_key(), None);
                        prop_assert!(identity.spi().get() >= 256);
                        prop_assert!(matches!(
                            matched.provenance(),
                            IngressIdentityProvenance::IcmpV4Quote
                                | IngressIdentityProvenance::IcmpV6Quote
                        ));
                    }
                    _ => prop_assert!(false, "unknown classified identity variant"),
                }
            }
            KeylessIngressClassification::NatTraversalKeepalive { destination, .. } => {
                prop_assert_eq!(destination.routing_domain(), routing_domain);
                prop_assert_eq!(Some(destination.address()), outer_destination(&packet));
            }
            KeylessIngressClassification::Unclassifiable { .. } => {}
            _ => prop_assert!(false, "unknown classifier verdict variant"),
        }
    }

    #[test]
    fn arbitrary_valid_native_esp_preserves_exact_public_metadata(
        source in any::<[u8; 4]>(),
        destination in any::<[u8; 4]>(),
        spi in 256_u32..=u32::MAX,
        routing_value in any::<u64>(),
    ) {
        let routing_domain = RoutingDomainTag::new(routing_value);
        let packet = ipv4(source, destination, 50, &esp_prefix(spi));
        let matched = classify_keyless_ingress_packet(&packet, routing_domain)
            .matched()
            .expect("valid generated native ESP packet classifies");
        prop_assert_eq!(matched.destination().address(), IpAddress::V4(destination));
        prop_assert_eq!(matched.destination().routing_domain(), routing_domain);
        prop_assert_eq!(matched.outer_source().address(), IpAddress::V4(source));
        let Some(SessionOwnershipKey::Esp(key)) = matched.ownership_key() else {
            return Err(TestCaseError::fail("native ESP did not yield an ESP ownership key"));
        };
        prop_assert_eq!(key.inbound_spi().get(), spi);
        prop_assert_eq!(key.encapsulation(), EspEncapsulationKind::Native);
    }
}

#[test]
fn diagnostics_do_not_expose_addresses_ports_or_spis() {
    let esp_packet = ipv4(PEER_A, SERVICE_A, 50, &esp_prefix(ESP_SPI));
    let ike_packet = ipv4(
        PEER_A,
        SERVICE_A,
        17,
        &udp(
            45_000,
            4500,
            &natt_ike(&ike_header(INITIATOR_SPI, RESPONDER_SPI, 35, 46)),
        ),
    );
    let esp_classification = classify_keyless_ingress_packet(&esp_packet, ROUTING_DOMAIN);
    let ike_classification = classify_keyless_ingress_packet(&ike_packet, ROUTING_DOMAIN);
    let debug = format!("{esp_classification:?} {ike_classification:?}");
    assert!(!debug.contains("192, 0, 2, 10"));
    assert!(!debug.contains("198, 51, 100, 20"));
    assert!(!debug.contains("192.0.2.10"));
    assert!(!debug.contains("198.51.100.20"));
    assert!(!debug.contains("555885348"));
    assert!(!debug.contains("21222324"));
    assert!(!debug.contains("0x21222324"));
    assert!(!debug.contains("72623859790382856"));
    assert!(!debug.contains("0102030405060708"));
    assert!(!debug.contains("1230066625199609624"));
    assert!(!debug.contains("1112131415161718"));
    assert!(!debug.contains("45000"));

    let truncated = classify_keyless_ingress_packet(&esp_packet[..7], ROUTING_DOMAIN);
    assert_eq!(truncated.code(), "ingress_truncated_ip_packet");
    assert_eq!(
        truncated
            .unclassifiable_reason()
            .expect("typed reason is present")
            .to_string(),
        "truncated IP packet"
    );
}
