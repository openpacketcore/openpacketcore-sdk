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
        let (output, identity) = endpoint.poll_output_with_record(&mut buffer);
        if matches!(output, Output::ApplicationData(_)) {
            assert!(
                identity.is_some(),
                "RFC 6083 plaintext has a record identity"
            );
        } else {
            assert_eq!(
                identity, None,
                "control output never carries a stale record"
            );
        }
        match output {
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

// These PSK pairs exercise the record API under both retained provider builds.
// They do not assert certificate policy or NGAP protected readiness.
struct RecordTestPsk;

impl dimpl::PskResolver for RecordTestPsk {
    fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
        (identity == b"synthetic-record-test").then(|| vec![0x6b; 32])
    }
}

fn record_pair(rfc6083: bool) -> (Dtls, Dtls) {
    fn builder(rfc6083: bool) -> dimpl::ConfigBuilder {
        let builder = Config::builder()
            .dtls13_cipher_suites(&[])
            .dtls12_cipher_suites(&[dimpl::crypto::Dtls12CipherSuite::PSK_AES128_CCM_8]);
        if rfc6083 {
            builder.rfc6083_sctp()
        } else {
            builder
        }
    }
    let client_config = builder(rfc6083)
        .with_psk_client(b"synthetic-record-test".to_vec(), Arc::new(RecordTestPsk))
        .build()
        .expect("record test client config");
    let server_config = builder(rfc6083)
        .with_psk_server(None, Arc::new(RecordTestPsk))
        .build()
        .expect("record test server config");
    let mut now = Instant::now();
    let mut client = Dtls::new_12_psk(Arc::new(client_config), now);
    let mut server = Dtls::new_12_psk(Arc::new(server_config), now);
    client.set_active(true);
    let mut connected = [false; 2];
    let mut buffer = [0_u8; 18445];
    for _ in 0..80 {
        for (side, connected_side) in connected.iter_mut().enumerate() {
            let (source, destination) = if side == 0 {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            source.handle_timeout(now).expect("advance handshake");
            loop {
                let (output, record) = source.poll_output_with_record(&mut buffer);
                assert_eq!(
                    record, None,
                    "handshake output cannot supply application metadata"
                );
                match output {
                    Output::Packet(packet) => {
                        destination.handle_packet(packet).expect("handshake packet")
                    }
                    Output::Connected => *connected_side = true,
                    Output::Timeout(_) => break,
                    Output::Rfc6083KeyingMaterial(_)
                    | Output::Rfc6083PrepareChangeCipherSpec
                    | Output::Rfc6083PrepareEpoch => {}
                    Output::KeyingMaterial(_, _) if !rfc6083 => {}
                    other => panic!("unexpected synthetic handshake event: {other:?}"),
                }
            }
        }
        if connected == [true, true] {
            return (client, server);
        }
        now += Duration::from_millis(10);
    }
    panic!("synthetic record test handshake did not complete");
}

fn wire_number(packet: &[u8]) -> (u16, u64) {
    assert_single_dtls_record(packet);
    let epoch = u16::from_be_bytes([packet[3], packet[4]]);
    let sequence = packet[5..11]
        .iter()
        .fold(0_u64, |number, byte| (number << 8) | u64::from(*byte));
    (epoch, sequence)
}

#[test]
fn rfc6083_public_record_identity_correlates_both_roles_and_out_of_order_streams() {
    let (mut client, mut server) = record_pair(true);
    for side in 0..2 {
        let (sender, receiver) = if side == 0 {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        let mut expected = Vec::new();
        for index in 0_u8..4 {
            let plaintext = [index; 32];
            sender
                .send_application_data(&plaintext)
                .expect("send protected record");
            let packets = drain_rfc6083(sender).packets;
            assert_eq!(packets.len(), 1);
            expected.push((wire_number(&packets[0]), plaintext, packets[0].clone()));
        }
        for index in [3, 1, 2, 0] {
            receiver
                .handle_packet(&expected[index].2)
                .expect("reordered record");
        }
        let mut buffer = [0_u8; 64];
        for (number, plaintext, _) in expected {
            let (output, record) = receiver.poll_output_with_record(&mut buffer);
            assert!(matches!(output, Output::ApplicationData(data) if data == plaintext));
            let record = record.expect("paired application record");
            assert_eq!((record.epoch(), record.sequence_number()), number);
        }
        let (output, record) = receiver.poll_output_with_record(&mut buffer);
        assert!(matches!(output, Output::Timeout(_)));
        assert_eq!(record, None);
    }
}

#[test]
fn rfc6083_public_record_identity_survives_retry_and_alternating_legacy_polls() {
    let (mut client, mut server) = record_pair(true);
    let mut expected = Vec::new();
    for index in 1_u8..=3 {
        client
            .send_application_data(&[index; 32])
            .expect("queue protected record");
        let packets = drain_rfc6083(&mut client).packets;
        assert_eq!(packets.len(), 1);
        expected.push(wire_number(&packets[0]));
        deliver(&packets, &mut server);
    }
    for _ in 0..2 {
        let mut short = [0; 31];
        let (output, record) = server.poll_output_with_record(&mut short);
        assert!(matches!(output, Output::BufferTooSmall { needed: 32 }));
        assert_eq!(record, None);
    }
    let mut buffer = [0_u8; 32];
    assert!(
        matches!(server.poll_output(&mut buffer), Output::ApplicationData(data) if data == [1; 32])
    );
    let (output, record) = server.poll_output_with_record(&mut buffer);
    assert!(matches!(output, Output::ApplicationData(data) if data == [2; 32]));
    let record = record.expect("second record after legacy polling");
    assert_eq!((record.epoch(), record.sequence_number()), expected[1]);
    assert!(
        matches!(server.poll_output(&mut buffer), Output::ApplicationData(data) if data == [3; 32])
    );
    let (_, record) = server.poll_output_with_record(&mut buffer);
    assert_eq!(record, None);
}

#[test]
fn rfc6083_public_record_identity_is_absent_for_ordinary_dtls() {
    let (mut client, mut server) = record_pair(false);
    client
        .send_application_data(b"ordinary transport")
        .expect("ordinary application data");
    let mut buffer = [0_u8; 18445];
    loop {
        let (output, record) = client.poll_output_with_record(&mut buffer);
        assert_eq!(record, None);
        match output {
            Output::Packet(packet) => server.handle_packet(packet).expect("ordinary packet"),
            Output::Timeout(_) => break,
            other => panic!("unexpected ordinary send: {other:?}"),
        }
    }
    let (output, record) = server.poll_output_with_record(&mut buffer);
    assert!(matches!(output, Output::ApplicationData(data) if data == b"ordinary transport"));
    assert_eq!(record, None);
}

#[test]
fn rfc6083_public_record_identity_is_absent_for_pending_dtls13() {
    let config = Arc::new(Config::builder().build().expect("ordinary DTLS config"));
    let certificate = dimpl::DtlsCertificate {
        certificate: Vec::new(),
        intermediates: Vec::new(),
        private_key: Vec::new(),
    };
    let mut endpoint = Dtls::new_13(config, certificate, Instant::now());
    let mut buffer = [0_u8; 32];
    let (output, record) = endpoint.poll_output_with_record(&mut buffer);
    assert!(matches!(output, Output::Timeout(_)));
    assert_eq!(record, None);
}

#[test]
#[cfg(feature = "rcgen")]
fn rfc6083_public_record_identity_is_absent_for_dtls13_application_data() {
    use dimpl::certificate::generate_self_signed_certificate;
    let config = Arc::new(
        Config::builder()
            .dtls12_cipher_suites(&[])
            .build()
            .expect("DTLS 1.3 config"),
    );
    let mut now = Instant::now();
    let mut client = Dtls::new_13(
        Arc::clone(&config),
        generate_self_signed_certificate().expect("client certificate"),
        now,
    );
    let mut server = Dtls::new_13(
        config,
        generate_self_signed_certificate().expect("server certificate"),
        now,
    );
    client.set_active(true);
    let mut connected = [false; 2];
    let mut buffer = [0_u8; 18445];
    for _ in 0..80 {
        for (side, connected_side) in connected.iter_mut().enumerate() {
            let (source, destination) = if side == 0 {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            source
                .handle_timeout(now)
                .expect("advance DTLS 1.3 handshake");
            loop {
                let (output, record) = source.poll_output_with_record(&mut buffer);
                assert_eq!(record, None, "DTLS 1.3 does not expose RFC 6083 metadata");
                match output {
                    Output::Packet(packet) => {
                        destination.handle_packet(packet).expect("DTLS 1.3 packet")
                    }
                    Output::Connected => *connected_side = true,
                    Output::Timeout(_) => break,
                    Output::PeerCert(_)
                    | Output::PeerCertChain(_)
                    | Output::KeyingMaterial(_, _) => {}
                    other => panic!("unexpected DTLS 1.3 output: {other:?}"),
                }
            }
        }
        if connected == [true, true] {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert_eq!(connected, [true, true]);
    for side in 0..2 {
        let (source, destination) = if side == 0 {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        source
            .send_application_data(b"DTLS 1.3 payload")
            .expect("DTLS 1.3 application data");
        loop {
            let (output, record) = source.poll_output_with_record(&mut buffer);
            assert_eq!(record, None);
            match output {
                Output::Packet(packet) => destination
                    .handle_packet(packet)
                    .expect("DTLS 1.3 application packet"),
                Output::Timeout(_) => break,
                other => panic!("unexpected DTLS 1.3 send output: {other:?}"),
            }
        }
        let (output, record) = destination.poll_output_with_record(&mut buffer);
        assert!(matches!(output, Output::ApplicationData(data) if data == b"DTLS 1.3 payload"));
        assert_eq!(record, None);
    }
}
