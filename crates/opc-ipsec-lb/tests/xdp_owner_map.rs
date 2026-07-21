//! Kernel-independent, fixture-driven parity tests for the XDP owner-map ABI.
//!
//! These tests prove, without a kernel, that the shared classification
//! decision procedure and owner-map key derivation used by the eBPF program
//! (`opc-ipsec-lb-ebpf-common::xdp`) produce exactly the canonical
//! destination-scoped ownership keys that the userspace classifier (#304) and
//! ownership model (#305) produce for the same packets. The verdict decision
//! (#306 fence execution) is covered by the shared `decide_owner_verdict`
//! table here and by the backend unit tests in `src/xdp.rs`.
//!
//! `simulate_xdp` mirrors the eBPF program's fixed-header path, including its
//! fail-closed rule that every IPv6 extension-bearing packet goes to the
//! userspace slow path. Deliberate, documented divergences from the userspace
//! classifier — IP fragmentation and IPv6 extension handling — have fixtures
//! asserting the expected disagreement, always in the fail-closed direction.

use opc_ipsec_lb::ownership::{RoutingDomainTag, SessionOwnershipKey};
use opc_ipsec_lb::{
    classify_keyless_ingress_packet, IngressEncapsulationKind, KeylessIngressClassification,
};
use opc_ipsec_lb_ebpf_common::{
    classify_transport, decide_owner_verdict, is_ipv6_extension_header_kind, ownership_map_key,
    XdpDatapathConfig, XdpFenceMode, XdpIpAddress, XdpOwnerValue, XdpTransportClass, XdpVerdict,
    IP_PROTOCOL_ESP, IP_PROTOCOL_UDP, OWNERSHIP_ESP_NATIVE, OWNERSHIP_ESP_UDP_ENCAPSULATED,
    OWNER_KEY_LEN, UDP_PORT_IKE, UDP_PORT_IKE_NATT,
};

const DOMAIN: u64 = 7;

/// Outcome of the host-side mirror of the XDP program's IP-header walk.
#[derive(Debug, PartialEq, Eq)]
enum SimOutcome {
    Identity {
        class: XdpTransportClass,
        source: XdpIpAddress,
        source_port: u16,
        destination: XdpIpAddress,
    },
    NonSwu,
    Keepalive,
    Unclassifiable,
}

/// Mirror of the eBPF program's header walk for the fixture packets, feeding
/// the SHARED `classify_transport` / `ownership_map_key` decision logic.
fn simulate_xdp(packet: &[u8]) -> SimOutcome {
    match packet[0] >> 4 {
        4 => simulate_ipv4(packet),
        6 => simulate_ipv6(packet),
        _ => SimOutcome::Unclassifiable,
    }
}

fn simulate_ipv4(packet: &[u8]) -> SimOutcome {
    if packet.len() < 20 || packet[0] & 0x0f != 5 {
        return SimOutcome::Unclassifiable;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < 20 || total_len > packet.len() {
        return SimOutcome::Unclassifiable;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return SimOutcome::Unclassifiable;
    }
    let protocol = packet[9];
    if protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_ESP {
        return SimOutcome::NonSwu;
    }
    finish(
        packet,
        protocol,
        20,
        total_len - 20,
        XdpIpAddress::V4([packet[12], packet[13], packet[14], packet[15]]),
        XdpIpAddress::V4([packet[16], packet[17], packet[18], packet[19]]),
    )
}

fn simulate_ipv6(packet: &[u8]) -> SimOutcome {
    if packet.len() < 40 {
        return SimOutcome::Unclassifiable;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if 40 + payload_len > packet.len() {
        return SimOutcome::Unclassifiable;
    }
    let protocol = packet[6];
    if protocol != IP_PROTOCOL_ESP && is_ipv6_extension_header_kind(protocol) {
        return SimOutcome::Unclassifiable;
    }
    if protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_ESP {
        return SimOutcome::NonSwu;
    }
    let mut source = [0_u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0_u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    finish(
        packet,
        protocol,
        40,
        payload_len,
        XdpIpAddress::V6(source),
        XdpIpAddress::V6(destination),
    )
}

fn finish(
    packet: &[u8],
    protocol: u8,
    transport_offset: usize,
    declared_transport_len: usize,
    source: XdpIpAddress,
    destination: XdpIpAddress,
) -> SimOutcome {
    let available = packet.len() - transport_offset;
    let class = classify_transport(
        protocol,
        &packet[transport_offset..],
        available,
        declared_transport_len,
    );
    match class {
        XdpTransportClass::NonSwu => SimOutcome::NonSwu,
        XdpTransportClass::NatKeepalive => SimOutcome::Keepalive,
        XdpTransportClass::Unclassifiable => SimOutcome::Unclassifiable,
        identity => SimOutcome::Identity {
            class: identity,
            source,
            source_port: u16::from_be_bytes([
                packet[transport_offset],
                packet[transport_offset + 1],
            ]),
            destination,
        },
    }
}

/// Assert the XDP decision procedure and key derivation agree with the
/// userspace classifier and ownership model for one packet.
fn assert_parity(packet: &[u8], expected_encapsulation: IngressEncapsulationKind) {
    let classification = classify_keyless_ingress_packet(packet, RoutingDomainTag::new(DOMAIN));
    let simulated = simulate_xdp(packet);

    let KeylessIngressClassification::Classified(matched) = classification else {
        panic!("userspace classifier rejected a parity fixture: {classification:?}");
    };
    assert_eq!(matched.encapsulation(), expected_encapsulation);
    let ownership_key = matched
        .ownership_key()
        .expect("direct classification must carry an ownership key");

    let SimOutcome::Identity {
        class,
        source,
        source_port,
        destination,
    } = simulated
    else {
        panic!("XDP simulation rejected a parity fixture: {simulated:?}");
    };

    // The XDP encapsulation class matches the userspace encapsulation kind.
    match (expected_encapsulation, class) {
        (
            IngressEncapsulationKind::IkeUdp500 | IngressEncapsulationKind::IkeUdp4500,
            XdpTransportClass::IkeEstablished { .. } | XdpTransportClass::IkeInitial { .. },
        )
        | (
            IngressEncapsulationKind::EspUdp4500,
            XdpTransportClass::Esp {
                encapsulation: OWNERSHIP_ESP_UDP_ENCAPSULATED,
                ..
            },
        )
        | (
            IngressEncapsulationKind::NativeEsp,
            XdpTransportClass::Esp {
                encapsulation: OWNERSHIP_ESP_NATIVE,
                ..
            },
        ) => {}
        (expected, class) => panic!("encapsulation mismatch: {expected:?} vs {class:?}"),
    }

    // The owner-map key the XDP program looks up is byte-identical to the
    // canonical ownership key userspace installs.
    let canonical = ownership_key.to_canonical_bytes();
    let map_key = ownership_map_key(&class, source, source_port, destination, DOMAIN)
        .expect("identity must map to a key");
    assert_eq!(usize::from(map_key[0]), canonical.len());
    assert_eq!(
        &map_key[1..1 + canonical.len()],
        canonical.as_slice(),
        "XDP owner-map key diverges from the canonical ownership key"
    );
    assert!(map_key[1 + canonical.len()..].iter().all(|byte| *byte == 0));
    assert_eq!(map_key.len(), OWNER_KEY_LEN);
}

fn ike_header(initiator: u64, responder: u64, exchange: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&initiator.to_be_bytes());
    header.extend_from_slice(&responder.to_be_bytes());
    header.push(0x20); // next payload: SA
    header.push(0x20); // IKEv2
    header.push(exchange);
    header.push(0x08); // initiator flag
    header.extend_from_slice(&[0, 0, 0, 0]); // message id
    header.extend_from_slice(&((28 + payload.len()) as u32).to_be_bytes());
    header.extend_from_slice(payload);
    header
}

fn udp_datagram(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    datagram
}

fn ipv4_packet(protocol: u8, source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let header_len = 20;
    let mut packet = vec![0x45, 0, 0, 0];
    packet[2..4].copy_from_slice(&((header_len + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 1, 0, 0, 64, protocol, 0, 0]);
    packet.extend_from_slice(&source);
    packet.extend_from_slice(&destination);
    packet.extend_from_slice(payload);
    packet
}

fn ipv6_packet(
    next_header: u8,
    source: [u8; 16],
    destination: [u8; 16],
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(next_header);
    packet.push(64);
    packet.extend_from_slice(&source);
    packet.extend_from_slice(&destination);
    packet.extend_from_slice(payload);
    packet
}

const VIP4: [u8; 4] = [203, 0, 113, 7];
const PEER4: [u8; 4] = [198, 51, 100, 9];
const VIP6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const PEER6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

#[test]
fn udp_500_established_ike_v4_and_v6_parity() {
    let ike = ike_header(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        35,
        &[0xaa; 12],
    );
    assert_parity(
        &ipv4_packet(
            IP_PROTOCOL_UDP,
            PEER4,
            VIP4,
            &udp_datagram(45000, UDP_PORT_IKE, &ike),
        ),
        IngressEncapsulationKind::IkeUdp500,
    );
    assert_parity(
        &ipv6_packet(
            IP_PROTOCOL_UDP,
            PEER6,
            VIP6,
            &udp_datagram(45000, UDP_PORT_IKE, &ike),
        ),
        IngressEncapsulationKind::IkeUdp500,
    );
}

#[test]
fn udp_500_initial_ike_sa_init_parity() {
    let ike = ike_header(0x0102_0304_0506_0708, 0, 34, &[0xbb; 40]);
    assert_parity(
        &ipv4_packet(
            IP_PROTOCOL_UDP,
            PEER4,
            VIP4,
            &udp_datagram(45000, UDP_PORT_IKE, &ike),
        ),
        IngressEncapsulationKind::IkeUdp500,
    );
}

#[test]
fn udp_4500_zero_marker_ike_parity() {
    let mut payload = vec![0, 0, 0, 0];
    payload.extend_from_slice(&ike_header(
        0xaaaa_bbbb_cccc_dddd,
        0x9999_8888_7777_6666,
        35,
        &[],
    ));
    assert_parity(
        &ipv4_packet(
            IP_PROTOCOL_UDP,
            PEER4,
            VIP4,
            &udp_datagram(45000, UDP_PORT_IKE_NATT, &payload),
        ),
        IngressEncapsulationKind::IkeUdp4500,
    );
    assert_parity(
        &ipv6_packet(
            IP_PROTOCOL_UDP,
            PEER6,
            VIP6,
            &udp_datagram(45000, UDP_PORT_IKE_NATT, &payload),
        ),
        IngressEncapsulationKind::IkeUdp4500,
    );
}

#[test]
fn udp_4500_esp_in_udp_parity() {
    let mut esp = 0x00ca_fe00_u32.to_be_bytes().to_vec();
    esp.extend_from_slice(&[0, 0, 0, 7]); // sequence
    esp.extend_from_slice(&[0x55; 24]); // protected payload + ICV
    assert_parity(
        &ipv4_packet(
            IP_PROTOCOL_UDP,
            PEER4,
            VIP4,
            &udp_datagram(45000, UDP_PORT_IKE_NATT, &esp),
        ),
        IngressEncapsulationKind::EspUdp4500,
    );
    assert_parity(
        &ipv6_packet(
            IP_PROTOCOL_UDP,
            PEER6,
            VIP6,
            &udp_datagram(45000, UDP_PORT_IKE_NATT, &esp),
        ),
        IngressEncapsulationKind::EspUdp4500,
    );
}

#[test]
fn native_esp_v4_and_v6_parity() {
    let mut esp = 0x00ca_fe01_u32.to_be_bytes().to_vec();
    esp.extend_from_slice(&[0, 0, 0, 9]);
    esp.extend_from_slice(&[0x77; 24]);
    assert_parity(
        &ipv4_packet(IP_PROTOCOL_ESP, PEER4, VIP4, &esp),
        IngressEncapsulationKind::NativeEsp,
    );
    assert_parity(
        &ipv6_packet(IP_PROTOCOL_ESP, PEER6, VIP6, &esp),
        IngressEncapsulationKind::NativeEsp,
    );
}

#[test]
fn native_esp_padding_beyond_the_ip_length_is_unclassifiable() {
    let mut esp = 0x00ca_fe01_u32.to_be_bytes().to_vec();
    esp.extend_from_slice(&[0, 0, 0, 9]);

    let mut ipv4 = ipv4_packet(IP_PROTOCOL_ESP, PEER4, VIP4, &esp);
    ipv4[2..4].copy_from_slice(&(24_u16).to_be_bytes());
    assert_eq!(simulate_xdp(&ipv4), SimOutcome::Unclassifiable);

    let mut ipv6 = ipv6_packet(IP_PROTOCOL_ESP, PEER6, VIP6, &esp);
    ipv6[4..6].copy_from_slice(&(4_u16).to_be_bytes());
    assert_eq!(simulate_xdp(&ipv6), SimOutcome::Unclassifiable);
}

#[test]
fn natt_keepalive_agrees_with_userspace_classifier() {
    let packet = ipv4_packet(
        IP_PROTOCOL_UDP,
        PEER4,
        VIP4,
        &udp_datagram(45000, UDP_PORT_IKE_NATT, &[0xff]),
    );
    let classification = classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN));
    assert!(matches!(
        classification,
        KeylessIngressClassification::NatTraversalKeepalive { .. }
    ));
    assert_eq!(simulate_xdp(&packet), SimOutcome::Keepalive);
}

#[test]
fn initial_fragments_diverge_deliberately() {
    // The userspace classifier accepts an initial fragment (MF=1, offset=0)
    // that still carries the complete discriminator. The XDP fast path
    // deliberately hands ANY fragment to the slow path: the packet reaches
    // the same userspace classifier there, never a contradictory verdict.
    let ike = ike_header(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        35,
        &[0xaa; 12],
    );
    let udp = udp_datagram(45000, UDP_PORT_IKE, &ike);
    let fragment_payload = &udp[..8 + 32];
    let mut packet = ipv4_packet(IP_PROTOCOL_UDP, PEER4, VIP4, fragment_payload);
    packet[6] = 0x20; // more-fragments flag, offset 0

    let classification = classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN));
    assert!(
        matches!(classification, KeylessIngressClassification::Classified(_)),
        "userspace classifies a complete-discriminator initial fragment: {classification:?}"
    );
    assert_eq!(
        simulate_xdp(&packet),
        SimOutcome::Unclassifiable,
        "the XDP fast path deliberately slow-paths any fragment"
    );
}

#[test]
fn ipv6_extension_bearing_swu_is_always_slow_pathed_by_xdp() {
    let ike = ike_header(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        35,
        &[0xaa; 12],
    );
    let udp = udp_datagram(45000, UDP_PORT_IKE, &ike);
    // Hop-by-Hop Options, Hdr Ext Len 0, six Pad1 octets.
    let mut payload = vec![IP_PROTOCOL_UDP, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&udp);
    let packet = ipv6_packet(0, PEER6, VIP6, &payload);

    let classification = classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN));
    assert!(
        matches!(classification, KeylessIngressClassification::Classified(_)),
        "userspace validates and classifies the extension-bearing fixture: {classification:?}"
    );
    assert_eq!(
        simulate_xdp(&packet),
        SimOutcome::Unclassifiable,
        "XDP must never fast-path an IPv6 extension chain it does not validate"
    );
}

#[test]
fn every_registered_ipv6_extension_kind_is_slow_pathed_except_direct_esp() {
    for extension_kind in [0, 43, 44, 51, 60, 135, 139, 140, 253, 254] {
        let packet = ipv6_packet(extension_kind, PEER6, VIP6, &[]);
        assert!(matches!(
            classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN)),
            KeylessIngressClassification::Unclassifiable { .. }
        ));
        assert_eq!(
            simulate_xdp(&packet),
            SimOutcome::Unclassifiable,
            "IANA IPv6 extension kind {extension_kind} must reach the slow path"
        );
    }

    // Protocol 50 is also marked as an IPv6 extension kind by IANA, but a
    // base header that directly names ESP is a supported SWu transport.
    let mut esp = 0x00ca_fe01_u32.to_be_bytes().to_vec();
    esp.extend_from_slice(&[0, 0, 0, 9]);
    assert!(matches!(
        simulate_xdp(&ipv6_packet(IP_PROTOCOL_ESP, PEER6, VIP6, &esp)),
        SimOutcome::Identity {
            class: XdpTransportClass::Esp {
                encapsulation: OWNERSHIP_ESP_NATIVE,
                spi: 0x00ca_fe01,
            },
            ..
        }
    ));
}

#[test]
fn shim6_cannot_conceal_swu_transport_from_xdp() {
    let ike = ike_header(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        35,
        &[0xaa; 12],
    );
    let udp = udp_datagram(45000, UDP_PORT_IKE, &ike);
    // Shim6 uses the IPv6 extension-header convention: Next Header followed
    // by Hdr Ext Len. The XDP contract must slow-path it before interpreting
    // the concealed UDP/500 bytes.
    let mut payload = vec![IP_PROTOCOL_UDP, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&udp);
    let packet = ipv6_packet(140, PEER6, VIP6, &payload);

    assert!(matches!(
        classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN)),
        KeylessIngressClassification::Unclassifiable { .. }
    ));
    assert_eq!(simulate_xdp(&packet), SimOutcome::Unclassifiable);
}

#[test]
fn malformed_swu_candidates_fail_closed_on_both_paths() {
    // Reserved ESP SPI in UDP/4500.
    let mut esp = 0x0000_00ff_u32.to_be_bytes().to_vec();
    esp.extend_from_slice(&[0, 0, 0, 1, 2, 3, 4, 5]);
    let packet = ipv4_packet(
        IP_PROTOCOL_UDP,
        PEER4,
        VIP4,
        &udp_datagram(45000, UDP_PORT_IKE_NATT, &esp),
    );
    assert!(matches!(
        classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN)),
        KeylessIngressClassification::Unclassifiable { .. }
    ));
    assert_eq!(simulate_xdp(&packet), SimOutcome::Unclassifiable);

    // Truncated IKE header.
    let packet = ipv4_packet(
        IP_PROTOCOL_UDP,
        PEER4,
        VIP4,
        &udp_datagram(45000, UDP_PORT_IKE, &ike_header(1, 2, 35, &[])[..20]),
    );
    assert!(matches!(
        classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN)),
        KeylessIngressClassification::Unclassifiable { .. }
    ));
    // UDP length is consistent but the IKE header is short: both paths agree.
    assert_eq!(simulate_xdp(&packet), SimOutcome::Unclassifiable);

    // Non-initial fragment.
    let mut packet = ipv4_packet(
        IP_PROTOCOL_UDP,
        PEER4,
        VIP4,
        &udp_datagram(45000, UDP_PORT_IKE, &[]),
    );
    packet[7] = 0x08; // fragment offset 64
    assert!(matches!(
        classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN)),
        KeylessIngressClassification::Unclassifiable { .. }
    ));
    assert_eq!(simulate_xdp(&packet), SimOutcome::Unclassifiable);
}

#[test]
fn non_swu_traffic_passes_untouched() {
    // The XDP fast path passes non-IKE/ESP traffic to the normal stack
    // untouched; the userspace classifier (which exists to find SWu
    // identities) reports it as unsupported. The verdicts differ by design:
    // the fast path's "pass untouched" is exactly what hands such traffic to
    // the same stack the userspace path would see it on.
    let packet = ipv4_packet(
        IP_PROTOCOL_UDP,
        PEER4,
        VIP4,
        &udp_datagram(53000, 443, &[0x16; 16]),
    );
    assert_eq!(simulate_xdp(&packet), SimOutcome::NonSwu);

    let packet = ipv4_packet(6, PEER4, VIP4, &[0; 20]);
    assert_eq!(simulate_xdp(&packet), SimOutcome::NonSwu);
}

#[test]
fn verdict_table_executes_fenced_ownership_decisions() {
    let config = XdpDatapathConfig {
        fence_mode: XdpFenceMode::Global,
        self_shard: 1,
        routing_domain: DOMAIN,
        handoff_ifindex: 42,
    };
    let fence_generation = 10_u64;
    let fresh_self = XdpOwnerValue {
        owner_shard: 1,
        generation: 10,
    }
    .encode();
    let fresh_remote = XdpOwnerValue {
        owner_shard: 2,
        generation: 11,
    }
    .encode();
    let fenced_out = XdpOwnerValue {
        owner_shard: 1,
        generation: 9,
    }
    .encode();

    assert_eq!(
        decide_owner_verdict(Some(fresh_self), &config, fence_generation),
        XdpVerdict::Local
    );
    assert_eq!(
        decide_owner_verdict(Some(fresh_remote), &config, fence_generation),
        XdpVerdict::RedirectHandoff
    );
    assert_eq!(
        decide_owner_verdict(Some(fenced_out), &config, fence_generation),
        XdpVerdict::SlowPathStale
    );
    assert_eq!(
        decide_owner_verdict(None, &config, fence_generation),
        XdpVerdict::SlowPathMiss
    );
}

#[test]
fn owner_map_key_round_trips_through_canonical_decode() {
    // A key the XDP program derives from a packet decodes back to the exact
    // ownership key userspace classified, for every fixture class.
    let fixtures: [(Vec<u8>, IngressEncapsulationKind); 3] = [
        (
            ipv4_packet(
                IP_PROTOCOL_UDP,
                PEER4,
                VIP4,
                &udp_datagram(45000, UDP_PORT_IKE, &ike_header(7, 8, 35, &[])),
            ),
            IngressEncapsulationKind::IkeUdp500,
        ),
        (
            ipv4_packet(
                IP_PROTOCOL_UDP,
                PEER4,
                VIP4,
                &udp_datagram(45000, UDP_PORT_IKE_NATT, &{
                    let mut esp = 0x00ca_fe02_u32.to_be_bytes().to_vec();
                    esp.extend_from_slice(&[0; 12]);
                    esp
                }),
            ),
            IngressEncapsulationKind::EspUdp4500,
        ),
        (
            ipv4_packet(IP_PROTOCOL_ESP, PEER4, VIP4, &{
                let mut esp = 0x00ca_fe03_u32.to_be_bytes().to_vec();
                esp.extend_from_slice(&[0; 12]);
                esp
            }),
            IngressEncapsulationKind::NativeEsp,
        ),
    ];
    for (packet, _) in fixtures {
        let classification =
            classify_keyless_ingress_packet(&packet, RoutingDomainTag::new(DOMAIN));
        let KeylessIngressClassification::Classified(matched) = classification else {
            panic!("fixture must classify");
        };
        let ownership_key: SessionOwnershipKey =
            matched.ownership_key().expect("ownership key present");
        let SimOutcome::Identity {
            class,
            source,
            source_port,
            destination,
        } = simulate_xdp(&packet)
        else {
            panic!("fixture must produce an XDP identity");
        };
        let map_key = ownership_map_key(&class, source, source_port, destination, DOMAIN)
            .expect("key present");
        let decoded =
            SessionOwnershipKey::from_canonical_bytes(&map_key[1..1 + usize::from(map_key[0])])
                .expect("canonical key in map key must decode");
        assert_eq!(decoded, ownership_key);
    }
}
