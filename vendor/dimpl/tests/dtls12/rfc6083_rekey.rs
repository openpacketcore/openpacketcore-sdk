//! Epoch transitions are exercised in both crypto-provider feature profiles.

use super::*;
use crate::ossl_helper::{DtlsCertOptions, OsslDtlsCert};
use dimpl::crypto::Dtls12CipherSuite;

fn certificate() -> dimpl::DtlsCertificate {
    let cert = OsslDtlsCert::new(DtlsCertOptions::default());
    dimpl::DtlsCertificate {
        certificate: cert.x509.to_der().expect("test certificate"),
        intermediates: Vec::new(),
        private_key: cert.pkey.private_key_to_der().expect("test private key"),
    }
}

fn endpoints(suite: Dtls12CipherSuite, now: Instant) -> (Dtls, Dtls) {
    let config = Arc::new(
        Config::builder()
            .rfc6083_sctp()
            .require_server_certificate_request(true)
            .dtls12_cipher_suites(&[suite])
            .dtls13_cipher_suites(&[])
            .build()
            .expect("mutual SCTP profile")
            .with_rfc6083_rekey()
            .expect("explicit secure renegotiation"),
    );
    let mut client = Dtls::new_12(Arc::clone(&config), certificate(), now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, certificate(), now);
    server.set_active(false);
    (client, server)
}

fn append(trace: &mut Rfc6083Trace, round: Rfc6083Trace) {
    assert!(round.application_data.is_empty() || trace.connected || round.connected);
    trace.connected |= round.connected;
    trace.application_data.extend(round.application_data);
    trace.exporter_material.extend(round.exporter_material);
    trace.srtp_exporter_events += round.srtp_exporter_events;
    trace.prepare_ccs_events += round.prepare_ccs_events;
    trace.prepare_epoch_events += round.prepare_epoch_events;
    trace.packets.extend(round.packets);
}

fn handshake(client: &mut Dtls, server: &mut Dtls, now: &mut Instant) -> [Rfc6083Trace; 2] {
    let mut traces = [Rfc6083Trace::default(), Rfc6083Trace::default()];
    for _ in 0..80 {
        client.handle_timeout(*now).expect("client progress");
        server.handle_timeout(*now).expect("server progress");
        let c = drain_rfc6083(client);
        let s = drain_rfc6083(server);
        deliver(&c.packets, server);
        deliver(&s.packets, client);
        append(&mut traces[0], c);
        append(&mut traces[1], s);
        if traces.iter().all(|v| v.connected) {
            break;
        }
        *now += Duration::from_millis(1);
    }
    for trace in &traces {
        assert!(trace.connected, "both endpoints complete this handshake");
        assert_eq!(trace.exporter_material.len(), 1);
        assert_eq!(trace.exporter_material[0].len(), 64);
        assert_eq!(trace.srtp_exporter_events, 0);
        assert_eq!(trace.prepare_ccs_events, 1);
        assert_eq!(trace.prepare_epoch_events, 1);
    }
    assert_eq!(
        traces[0].exporter_material[0].as_ref(),
        traces[1].exporter_material[0].as_ref()
    );
    traces
}

#[test]
fn rfc6083_rekey_preserves_queued_plaintext_and_changes_real_record_keys() {
    for suite in [
        Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
        Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
        Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
    ] {
        let mut now = Instant::now();
        let (mut client, mut server) = endpoints(suite, now);
        let initial = handshake(&mut client, &mut server, &mut now);
        let mut previous = initial[0].exporter_material[0].as_ref().to_vec();
        for epoch in 2..=4_u16 {
            client
                .send_application_data(b"queued client record")
                .expect("old epoch write");
            server
                .send_application_data(b"queued server record")
                .expect("old epoch write");
            let client_packets = drain_rfc6083(&mut client).packets;
            let server_packets = drain_rfc6083(&mut server).packets;
            deliver(&client_packets, &mut server);
            deliver(&server_packets, &mut client);
            client.begin_rfc6083_rekey().expect("arm client");
            server.begin_rfc6083_rekey().expect("arm server");
            let traces = handshake(&mut client, &mut server, &mut now);
            assert_eq!(client.rfc6083_epoch(), Some(epoch));
            assert_eq!(server.rfc6083_epoch(), Some(epoch));
            assert_ne!(traces[0].exporter_material[0].as_ref(), previous);
            previous = traces[0].exporter_material[0].as_ref().to_vec();
            assert_eq!(
                traces[0].application_data,
                [b"queued server record".to_vec()]
            );
            assert_eq!(
                traces[1].application_data,
                [b"queued client record".to_vec()]
            );
            deliver(&client_packets, &mut server);
            deliver(&server_packets, &mut client);
            assert!(
                drain_rfc6083(&mut client).application_data.is_empty(),
                "old epoch is retired"
            );
            assert!(
                drain_rfc6083(&mut server).application_data.is_empty(),
                "old epoch is retired"
            );
            for trace in &traces {
                assert!(trace.packets.iter().any(|v| v[0] == 20));
                for packet in &trace.packets {
                    let wire_epoch = u16::from_be_bytes([packet[3], packet[4]]);
                    assert!(wire_epoch == epoch - 1 || wire_epoch == epoch);
                    if packet[0] == 20 {
                        assert_eq!(wire_epoch, epoch - 1, "CCS uses previous keys");
                    }
                }
            }
            let exchange = |sender: &mut Dtls, receiver: &mut Dtls| {
                sender
                    .send_application_data(b"new epoch plaintext")
                    .expect("new epoch write");
                let packets = drain_rfc6083(sender).packets;
                assert_eq!(packets.len(), 1);
                assert_eq!(u16::from_be_bytes([packets[0][3], packets[0][4]]), epoch);
                deliver(&packets, receiver);
                assert_eq!(
                    drain_rfc6083(receiver).application_data,
                    [b"new epoch plaintext".to_vec()]
                );
            };
            exchange(&mut client, &mut server);
            exchange(&mut server, &mut client);
        }
    }
}

#[test]
fn rekey_future_application_waits_for_peer_finished_after_cross_stream_reordering() {
    for suite in [
        Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
        Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
        Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
    ] {
        let mut now = Instant::now();
        let (mut client, mut server) = endpoints(suite, now);
        handshake(&mut client, &mut server, &mut now);
        client.begin_rfc6083_rekey().expect("client arm");
        server.begin_rfc6083_rekey().expect("server arm");
        let mut reordered = false;
        for _ in 0..80 {
            client.handle_timeout(now).expect("client progress");
            server.handle_timeout(now).expect("server progress");
            let c = drain_rfc6083(&mut client);
            let s = drain_rfc6083(&mut server);
            assert!(!c.connected, "client has not received the final flight");
            deliver(&c.packets, &mut server);
            if s.connected {
                assert!(s.packets.iter().any(|v| v[0] == 20), "held CCS");
                server
                    .send_application_data(b"future ciphertext")
                    .expect("new epoch write");
                let app = drain_rfc6083(&mut server);
                assert_eq!(app.packets.len(), 1);
                deliver(&app.packets, &mut client);
                let early = drain_rfc6083(&mut client);
                assert!(!early.connected);
                assert!(
                    early.application_data.is_empty(),
                    "nothing before peer Finished"
                );
                deliver(&s.packets, &mut client);
                let completed = drain_rfc6083(&mut client);
                assert!(completed.connected);
                assert_eq!(completed.application_data, [b"future ciphertext".to_vec()]);
                reordered = true;
                break;
            }
            deliver(&s.packets, &mut client);
            now += Duration::from_millis(1);
        }
        assert!(
            reordered,
            "real new-epoch ciphertext was held behind Finished"
        );
    }
}
