//! RFC 6083 DTLS-over-SCTP integration regressions.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, KeyingMaterial, Output};

#[derive(Default)]
struct Rfc6083Trace {
    packets: Vec<Vec<u8>>,
    connected: bool,
    application_data: Vec<Vec<u8>>,
    close_notify: bool,
    exporter_material: Vec<KeyingMaterial>,
    srtp_exporter_events: usize,
    prepare_ccs_events: usize,
    prepare_epoch_events: usize,
    prepare_close_events: usize,
}

fn assert_single_dtls_record(packet: &[u8]) {
    assert!(
        packet.len() >= 13,
        "RFC 6083 packet must contain a complete DTLS record header"
    );
    let fragment_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    assert_eq!(
        packet.len(),
        13 + fragment_len,
        "RFC 6083 requires exactly one DTLS record per SCTP message"
    );
}

fn drain_rfc6083(endpoint: &mut Dtls) -> Rfc6083Trace {
    let mut trace = Rfc6083Trace::default();
    let mut buffer = vec![0_u8; 65_536];
    loop {
        match endpoint.poll_output(&mut buffer) {
            Output::Packet(packet) => {
                assert_single_dtls_record(packet);
                trace.packets.push(packet.to_vec());
            }
            Output::Connected => trace.connected = true,
            Output::ApplicationData(data) => trace.application_data.push(data.to_vec()),
            Output::CloseNotify => trace.close_notify = true,
            Output::Rfc6083KeyingMaterial(material) => {
                trace.exporter_material.push(material);
            }
            Output::KeyingMaterial(_, _) => trace.srtp_exporter_events += 1,
            Output::Rfc6083PrepareChangeCipherSpec => trace.prepare_ccs_events += 1,
            Output::Rfc6083PrepareEpoch => trace.prepare_epoch_events += 1,
            Output::Rfc6083PrepareCloseNotify => trace.prepare_close_events += 1,
            Output::PeerCert(_) | Output::PeerCertChain(_) => {}
            Output::BufferTooSmall { needed } => {
                panic!("65 KiB RFC 6083 output buffer was too small: needed {needed}")
            }
            Output::Timeout(_) => break,
            other => panic!("unexpected RFC 6083 output: {other:?}"),
        }
    }
    trace
}

fn deliver(packets: &[Vec<u8>], destination: &mut Dtls) {
    for packet in packets {
        destination
            .handle_packet(packet)
            .expect("RFC 6083 peer accepts record");
    }
}

#[cfg(feature = "rcgen")]
fn connected_pair(now: Instant) -> (Dtls, Dtls, Rfc6083Trace, Rfc6083Trace) {
    use dimpl::certificate::generate_self_signed_certificate;

    let config = Arc::new(
        Config::builder()
            .rfc6083_sctp()
            .dtls13_cipher_suites(&[])
            .build()
            .expect("RFC 6083 DTLS 1.2 config"),
    );
    let client_certificate =
        generate_self_signed_certificate().expect("generate client certificate");
    let server_certificate =
        generate_self_signed_certificate().expect("generate server certificate");
    let mut client = Dtls::new_12(Arc::clone(&config), client_certificate, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_certificate, now);
    server.set_active(false);

    let mut client_trace = Rfc6083Trace::default();
    let mut server_trace = Rfc6083Trace::default();
    let mut current = now;
    for _ in 0..80 {
        client
            .handle_timeout(current)
            .expect("advance RFC 6083 client");
        server
            .handle_timeout(current)
            .expect("advance RFC 6083 server");

        let client_round = drain_rfc6083(&mut client);
        let server_round = drain_rfc6083(&mut server);
        client_trace.connected |= client_round.connected;
        server_trace.connected |= server_round.connected;
        client_trace
            .exporter_material
            .extend(client_round.exporter_material);
        server_trace
            .exporter_material
            .extend(server_round.exporter_material);
        client_trace.srtp_exporter_events += client_round.srtp_exporter_events;
        server_trace.srtp_exporter_events += server_round.srtp_exporter_events;
        client_trace.prepare_ccs_events += client_round.prepare_ccs_events;
        server_trace.prepare_ccs_events += server_round.prepare_ccs_events;
        client_trace.prepare_epoch_events += client_round.prepare_epoch_events;
        server_trace.prepare_epoch_events += server_round.prepare_epoch_events;

        deliver(&client_round.packets, &mut server);
        deliver(&server_round.packets, &mut client);

        if client_trace.connected && server_trace.connected {
            break;
        }
        current += Duration::from_millis(10);
    }

    assert!(client_trace.connected, "RFC 6083 client must connect");
    assert!(server_trace.connected, "RFC 6083 server must connect");
    (client, server, client_trace, server_trace)
}

#[test]
#[cfg(feature = "rcgen")]
fn rfc6083_handshake_uses_only_rfc6083_exporter_and_one_record_messages() {
    let (_client, _server, client_trace, server_trace) = connected_pair(Instant::now());

    assert_eq!(client_trace.srtp_exporter_events, 0);
    assert_eq!(server_trace.srtp_exporter_events, 0);
    assert_eq!(client_trace.exporter_material.len(), 1);
    assert_eq!(server_trace.exporter_material.len(), 1);
    assert_eq!(client_trace.exporter_material[0].len(), 64);
    assert_eq!(server_trace.exporter_material[0].len(), 64);
    assert_eq!(
        client_trace.exporter_material[0].as_ref(),
        server_trace.exporter_material[0].as_ref(),
        "both roles must derive the same endpoint-pair shared secret"
    );
    assert_eq!(client_trace.prepare_ccs_events, 1);
    assert_eq!(server_trace.prepare_ccs_events, 1);
    assert_eq!(client_trace.prepare_epoch_events, 1);
    assert_eq!(server_trace.prepare_epoch_events, 1);
}

fn assert_local_close_order(endpoint: &mut Dtls) -> Vec<Vec<u8>> {
    endpoint
        .send_application_data(b"first queued write")
        .expect("queue first write");
    endpoint
        .send_application_data(b"second queued write")
        .expect("queue second write");
    endpoint.close().expect("initiate local close");

    let mut output = vec![0_u8; 65_536];
    let mut packets = Vec::new();
    for expected_content_type in [23_u8, 23, 21] {
        if expected_content_type == 21 {
            assert!(matches!(
                endpoint.poll_output(&mut output),
                Output::Rfc6083PrepareCloseNotify
            ));
        }
        match endpoint.poll_output(&mut output) {
            Output::Packet(packet) => {
                assert_single_dtls_record(packet);
                assert_eq!(packet[0], expected_content_type);
                packets.push(packet.to_vec());
            }
            other => panic!("expected RFC 6083 packet, got {other:?}"),
        }
    }
    assert!(matches!(
        endpoint.poll_output(&mut output),
        Output::Timeout(_)
    ));
    packets
}

#[test]
#[cfg(feature = "rcgen")]
fn rfc6083_sender_dry_close_order_is_symmetric_and_reciprocal_discards_writes() {
    for client_initiates in [true, false] {
        let (mut client, mut server, _, _) = connected_pair(Instant::now());
        let (initiator, receiver) = if client_initiates {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };

        receiver
            .send_application_data(b"must be discarded on reciprocal close")
            .expect("queue peer write");
        let initiator_packets = assert_local_close_order(initiator);
        deliver(&initiator_packets, receiver);

        let mut output = vec![0_u8; 65_536];
        for expected in [b"first queued write".as_slice(), b"second queued write"] {
            assert!(matches!(
                receiver.poll_output(&mut output),
                Output::ApplicationData(data) if data == expected
            ));
        }
        assert!(matches!(
            receiver.poll_output(&mut output),
            Output::Rfc6083PrepareCloseNotify
        ));
        let reciprocal = match receiver.poll_output(&mut output) {
            Output::Packet(packet) => {
                assert_single_dtls_record(packet);
                assert_eq!(packet[0], 21, "pending application write must be discarded");
                packet.to_vec()
            }
            other => panic!("expected reciprocal close_notify packet, got {other:?}"),
        };
        assert!(matches!(
            receiver.poll_output(&mut output),
            Output::CloseNotify
        ));
        assert!(matches!(
            receiver.poll_output(&mut output),
            Output::Timeout(_)
        ));

        initiator
            .handle_packet(&reciprocal)
            .expect("accept reciprocal close_notify");
        assert!(matches!(
            initiator.poll_output(&mut output),
            Output::CloseNotify
        ));
    }
}
