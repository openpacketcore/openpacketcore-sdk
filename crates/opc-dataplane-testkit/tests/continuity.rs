use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use opc_dataplane_testkit::{
    build_measurement_tpdu, decode_gtpu, encode_echo_request, encode_gpdu,
    encode_gpdu_with_extensions, ContinuityObserver, GtpuReflector, GtpuReturnDatagramOutcome,
    InnerIpFlow, PacketContinuityBudget, ReflectorAction, ReflectorConfig, ReflectorPolicy,
    ReflectorSendReason, RouteTarget, TrafficEngine, TrafficPlan, GTPU_EXT_PDU_SESSION_CONTAINER,
    GTPU_MSG_ECHO_RESPONSE, GTPU_MSG_ERROR_INDICATION, GTPU_MSG_GPDU,
};

const REFLECTOR_TEID: u32 = 0x1000_0001;
const ENGINE_TEID: u32 = 0x2000_0001;

fn engine_addr() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 10], 2152))
}

fn reflector_addr() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 20], 2152))
}

fn ipv4_flow() -> InnerIpFlow {
    InnerIpFlow::Ipv4 {
        src: Ipv4Addr::new(198, 51, 100, 10),
        dst: Ipv4Addr::new(203, 0, 113, 20),
        src_port: 49152,
        dst_port: 9,
    }
}

fn ipv6_flow() -> InnerIpFlow {
    InnerIpFlow::Ipv6 {
        src: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10),
        dst: Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 20),
        src_port: 49153,
        dst_port: 9,
    }
}

fn echo_reflector() -> GtpuReflector {
    GtpuReflector::new(ReflectorConfig {
        local_teid: REFLECTOR_TEID,
        peer_teid: ENGINE_TEID,
        peer_addr: engine_addr(),
        recovery_counter: 7,
        policy: ReflectorPolicy::Echo,
    })
}

#[test]
fn loopback_continuity_report_validates_schema_and_snapshot() {
    let mut engine = TrafficEngine::new();
    let mut observer = ContinuityObserver::new();
    let packets = engine
        .generate(
            ipv4_flow(),
            TrafficPlan {
                packet_count: 4,
                target_rate_pps: 1_000,
                first_send_timestamp_ns: 10_000,
            },
        )
        .expect("generate packets");
    let mut reflector = echo_reflector();

    for packet in &packets {
        observer.record_sent(packet);
        let request = encode_gpdu(REFLECTOR_TEID, &packet.tpdu).expect("encode G-PDU");
        let action = reflector
            .handle_datagram(engine_addr(), &request)
            .expect("reflect packet");
        let ReflectorAction::Send {
            destination,
            packet: response,
            reason,
        } = action
        else {
            panic!("expected reflected G-PDU");
        };
        assert_eq!(destination, engine_addr());
        assert_eq!(reason, ReflectorSendReason::ReflectedGpdu);
        let outcome = observer
            .record_return_gtpu_datagram(packet.send_timestamp_ns + 500, &response)
            .expect("record return GTP-U packet");
        assert_eq!(outcome, GtpuReturnDatagramOutcome::MeasurementTpdu);
    }

    let report = observer.report(
        "flow-redacted-loopback",
        10_000,
        20_000,
        PacketContinuityBudget::zero_loss(),
    );
    assert_eq!(report.sent_packets, 4);
    assert_eq!(report.received_packets, 4);
    assert_eq!(report.gtpu_error_indications, 0);
    assert!(report.forwarding_proven);
    assert!(report.packet_continuity_proven);
    report.validate_redaction().expect("redaction-safe report");
    let debug = format!("{report:?}");
    assert!(!debug.contains("198.51.100.10"));
    assert!(!debug.contains("203.0.113.20"));

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/packet-continuity-report.schema.json"
    ))
    .expect("schema parses");
    let instance = serde_json::to_value(&report).expect("report serializes");
    opc_schema_validate::validate(&schema, &instance).expect("report validates against schema");

    let snapshot = report.to_dataplane_snapshot(true);
    snapshot
        .validate_packet_continuity_claim()
        .expect("report maps to packet-continuity evidence");
}

#[test]
fn injected_loss_below_and_above_budget_sets_continuity() {
    let mut engine = TrafficEngine::new();
    let packets = engine
        .generate(
            ipv6_flow(),
            TrafficPlan {
                packet_count: 5,
                target_rate_pps: 1_000,
                first_send_timestamp_ns: 0,
            },
        )
        .expect("generate packets");

    let mut below = ContinuityObserver::new();
    for packet in &packets {
        below.record_sent(packet);
    }
    for packet in packets.iter().filter(|packet| packet.sequence != 2) {
        below
            .record_received_tpdu(packet.send_timestamp_ns + 100, &packet.tpdu)
            .expect("record received packet");
    }
    let budget = PacketContinuityBudget {
        max_lost_packets: 1,
        max_consecutive_lost_packets: 1,
        outage_budget_ns: 1_000_000,
    };
    let below_report = below.report("flow-redacted-loss-budget", 0, 5_000_000, budget);
    assert_eq!(below_report.lost_packets, 1);
    assert!(below_report.packet_continuity_proven);

    let mut above = ContinuityObserver::new();
    for packet in &packets {
        above.record_sent(packet);
    }
    for packet in packets
        .iter()
        .filter(|packet| packet.sequence != 2 && packet.sequence != 3)
    {
        above
            .record_received_tpdu(packet.send_timestamp_ns + 100, &packet.tpdu)
            .expect("record received packet");
    }
    let above_report = above.report("flow-redacted-loss-budget", 0, 5_000_000, budget);
    assert_eq!(above_report.lost_packets, 2);
    assert_eq!(above_report.max_consecutive_lost_packets, 2);
    assert_eq!(above_report.max_gap_duration_ns, 2_000_000);
    assert!(!above_report.packet_continuity_proven);
}

#[test]
fn observer_counts_duplicates_out_of_order_and_latency() {
    let mut engine = TrafficEngine::new();
    let packets = engine
        .generate(
            ipv4_flow(),
            TrafficPlan {
                packet_count: 3,
                target_rate_pps: 1_000,
                first_send_timestamp_ns: 1_000,
            },
        )
        .expect("generate packets");
    let mut observer = ContinuityObserver::new();
    for packet in &packets {
        observer.record_sent(packet);
    }

    observer
        .record_received_tpdu(2_003_000, &packets[2].tpdu)
        .expect("record first packet");
    observer
        .record_received_tpdu(1_001_500, &packets[1].tpdu)
        .expect("record out-of-order packet");
    observer
        .record_received_tpdu(1_001_600, &packets[1].tpdu)
        .expect("record duplicate packet");

    let report = observer.report(
        "flow-redacted-reordering",
        1_000,
        3_001_000,
        PacketContinuityBudget {
            max_lost_packets: 1,
            max_consecutive_lost_packets: 1,
            outage_budget_ns: 1_000_000,
        },
    );
    assert_eq!(report.received_packets, 2);
    assert_eq!(report.duplicate_packets, 1);
    assert_eq!(report.out_of_order_packets, 1);
    assert_eq!(report.max_consecutive_lost_packets, 1);
    assert_eq!(report.max_gap_duration_ns, 1_000_000);
    let latency = report.latency.expect("latency summary");
    assert_eq!(latency.min_ns, 500);
    assert_eq!(latency.max_ns, 2_000);
    assert_eq!(latency.avg_ns, 1_250);
    assert!(report.packet_continuity_proven);
}

#[test]
fn reflector_handles_echo_request_and_unknown_teid_error_indication() {
    let mut reflector = echo_reflector();
    let echo_request = encode_echo_request(77).expect("encode echo request");
    let ReflectorAction::Send {
        destination,
        packet,
        reason,
    } = reflector
        .handle_datagram(engine_addr(), &echo_request)
        .expect("handle echo request")
    else {
        panic!("expected echo response");
    };
    assert_eq!(destination, engine_addr());
    assert_eq!(reason, ReflectorSendReason::EchoResponse);
    let response = decode_gtpu(&packet).expect("decode echo response");
    assert_eq!(response.header.message_type, GTPU_MSG_ECHO_RESPONSE);
    assert_eq!(response.header.teid, 0);
    assert_eq!(response.header.sequence_number, Some(77));
    assert_eq!(response.payload.as_ref(), &[14, 7]);

    let tpdu = build_measurement_tpdu(ipv4_flow(), 1, 0).expect("build T-PDU");
    let unknown = encode_gpdu(0x9999_9999, &tpdu).expect("encode unknown TEID G-PDU");
    let ReflectorAction::Send { packet, reason, .. } = reflector
        .handle_datagram(engine_addr(), &unknown)
        .expect("unknown TEID emits Error Indication")
    else {
        panic!("expected error indication");
    };
    assert_eq!(reason, ReflectorSendReason::ErrorIndication);
    let error = decode_gtpu(&packet).expect("decode error indication");
    assert_eq!(error.header.message_type, GTPU_MSG_ERROR_INDICATION);
    assert_eq!(error.header.teid, 0);
    assert_eq!(&error.payload.as_ref()[..5], &[16, 0x99, 0x99, 0x99, 0x99]);
    assert_eq!(
        &error.payload.as_ref()[5..],
        &[133, 0x00, 0x04, 192, 0, 2, 10]
    );
    assert_eq!(reflector.stats().error_indications_sent, 1);

    let mut observer = ContinuityObserver::new();
    let outcome = observer
        .record_return_gtpu_datagram(10, &packet)
        .expect("record error indication");
    assert_eq!(outcome, GtpuReturnDatagramOutcome::ErrorIndication);
    let report = observer.report(
        "flow-redacted-error-indication",
        0,
        10,
        PacketContinuityBudget {
            max_lost_packets: 10,
            max_consecutive_lost_packets: 10,
            outage_budget_ns: 10,
        },
    );
    assert_eq!(report.gtpu_error_indications, 1);
    assert!(!report.packet_continuity_proven);
}

#[test]
fn reflector_route_and_sink_policies_are_teid_scoped() {
    let tpdu = build_measurement_tpdu(ipv4_flow(), 7, 1_000).expect("build T-PDU");

    let route_target = RouteTarget {
        destination: SocketAddr::from(([192, 0, 2, 30], 2152)),
        teid: 0x3000_0001,
    };
    let mut router = GtpuReflector::new(ReflectorConfig {
        local_teid: REFLECTOR_TEID,
        peer_teid: ENGINE_TEID,
        peer_addr: engine_addr(),
        recovery_counter: 1,
        policy: ReflectorPolicy::Route(route_target),
    });
    let routed_request = encode_gpdu(REFLECTOR_TEID, &tpdu).expect("encode routed request");
    let ReflectorAction::Send {
        destination,
        packet,
        reason,
    } = router
        .handle_datagram(engine_addr(), &routed_request)
        .expect("route G-PDU")
    else {
        panic!("expected routed G-PDU");
    };
    assert_eq!(destination, route_target.destination);
    assert_eq!(reason, ReflectorSendReason::RoutedGpdu);
    let routed = decode_gtpu(&packet).expect("decode routed packet");
    assert_eq!(routed.header.teid, route_target.teid);
    assert_eq!(routed.payload.as_ref(), tpdu.as_slice());
    assert_eq!(router.stats().gpdu_forwarded, 1);

    let mut sink = GtpuReflector::new(ReflectorConfig {
        local_teid: REFLECTOR_TEID,
        peer_teid: ENGINE_TEID,
        peer_addr: engine_addr(),
        recovery_counter: 1,
        policy: ReflectorPolicy::SinkAndCount,
    });
    let sunk_request = encode_gpdu(REFLECTOR_TEID, &tpdu).expect("encode sunk request");
    let ReflectorAction::Noop { reason } = sink
        .handle_datagram(engine_addr(), &sunk_request)
        .expect("sink G-PDU")
    else {
        panic!("expected sink noop");
    };
    assert_eq!(reason, "G-PDU sunk");
    assert_eq!(sink.stats().gpdu_sunk, 1);
}

#[test]
fn reflector_roundtrip_accepts_pdu_session_container_extension() {
    let mut reflector = echo_reflector();
    let tpdu = build_measurement_tpdu(ipv4_flow(), 42, 100).expect("build T-PDU");
    let request = encode_gpdu_with_extensions(
        REFLECTOR_TEID,
        GTPU_EXT_PDU_SESSION_CONTAINER,
        &[0x01, 0x00, 0x09, 0x00],
        &tpdu,
    )
    .expect("encode G-PDU with extension");

    let ReflectorAction::Send { packet, .. } = reflector
        .handle_datagram(engine_addr(), &request)
        .expect("reflect extension-bearing G-PDU")
    else {
        panic!("expected reflected G-PDU");
    };
    let response = decode_gtpu(&packet).expect("decode reflected packet");
    assert_eq!(response.header.message_type, GTPU_MSG_GPDU);
    assert_eq!(response.header.teid, ENGINE_TEID);
}

#[test]
fn reflector_roundtrip_skips_unknown_extension_header() {
    let mut reflector = echo_reflector();
    let tpdu = build_measurement_tpdu(ipv4_flow(), 43, 100).expect("build T-PDU");
    let request =
        encode_gpdu_with_extensions(REFLECTOR_TEID, 0xee, &[0x01, 0xaa, 0xbb, 0x00], &tpdu)
            .expect("encode G-PDU with unknown extension");

    let ReflectorAction::Send { packet, .. } = reflector
        .handle_datagram(engine_addr(), &request)
        .expect("reflect unknown-extension G-PDU")
    else {
        panic!("expected reflected G-PDU");
    };
    let response = decode_gtpu(&packet).expect("decode reflected packet");
    assert_eq!(response.header.message_type, GTPU_MSG_GPDU);
    assert_eq!(response.header.teid, ENGINE_TEID);
}

#[test]
fn malformed_gtpu_header_is_rejected() {
    let mut reflector = echo_reflector();
    let err = reflector
        .handle_datagram(reflector_addr(), &[0x30, 0xff, 0x00])
        .expect_err("truncated GTP-U must be rejected");
    assert!(format!("{err}").contains("GTP-U decode failed"));
    assert_eq!(reflector.stats().malformed_rejected, 1);
}
