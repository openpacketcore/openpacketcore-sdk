//! In-place epoch transitions preserve the authenticated association contract.

use super::*;

#[tokio::test(start_paused = true)]
async fn rekey_never_renews_the_absolute_association_lifetime() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap)
        .with_rekey()
        .with_maximum_connection_age(Duration::from_secs(10))
        .expect("age");
    let (mut client, mut server, _) = generic_pair(&material, policy, policy).await;
    tokio::time::advance(Duration::from_secs(6)).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    let (c, s) = tokio::join!(client.rekey(deadline), server.rekey(deadline));
    c.expect("client rekey before expiration");
    s.expect("server rekey before expiration");
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(client.readback().err(), Some(Error::Retired));
    assert_eq!(server.readback().err(), Some(Error::Retired));
}

#[tokio::test]
async fn credential_withdrawal_interrupts_a_pending_rekey_in_both_roles() {
    for client_role in [true, false] {
        let material = dtls_material();
        let policy = generic_policy(PayloadProtocol::Ngap).with_rekey();
        let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
        log.set_dtls_send_blocked(true, true);
        let (local, remote, source) = if client_role {
            (&mut client, &mut server, &material.client_source)
        } else {
            (&mut server, &mut client, &material._server_source)
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut rekey = Box::pin(local.rekey(deadline));
        std::future::poll_fn(|cx| {
            assert!(rekey.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        source.send(None).expect("withdraw credentials");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rekey)
                .await
                .expect("prompt retirement"),
            Err(Error::Retired)
        );
        assert_eq!(local.readback().err(), Some(Error::Retired));
        assert_eq!(remote.readback().err(), Some(Error::ConnectionClosed));
    }
}

#[tokio::test]
async fn coordinated_rekey_preserves_queued_streams_and_rotates_each_auth_boundary() {
    let material = dtls_material();
    for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 32)
            .expect("streams")
            .with_allowed_ciphers(&[cipher])
            .expect("cipher")
            .with_rekey();
        let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
        let original_material = client
            .readback()
            .expect("initial evidence")
            .material_epoch();
        for epoch in 2..=4_u16 {
            let deadline = Instant::now() + Duration::from_secs(5);
            for stream in [1, 15, 0] {
                client
                    .send_on_stream(stream, &[stream as u8], deadline)
                    .await
                    .expect("old client write");
                server
                    .send_on_stream(stream, &[stream as u8, 42], deadline)
                    .await
                    .expect("old server write");
            }
            let start = log.records().len();
            let (c, s) = tokio::join!(client.rekey(deadline), server.rekey(deadline));
            c.expect("client rekey");
            s.expect("server rekey");
            for connection in [&client, &server] {
                let evidence = connection.readback().expect("completed rekey evidence");
                assert!(evidence.allows_rekey());
                assert_eq!(evidence.record_epoch(), epoch);
                assert_eq!(evidence.cipher(), cipher);
            }
            assert_eq!(
                client
                    .readback()
                    .expect("credential epoch")
                    .material_epoch(),
                original_material
            );
            for stream in [1, 15, 0] {
                let c = client
                    .receive(deadline)
                    .await
                    .expect("queued server record");
                let s = server
                    .receive(deadline)
                    .await
                    .expect("queued client record");
                assert_eq!(
                    (c.stream_id(), c.as_bytes()),
                    (stream, [stream as u8, 42].as_slice())
                );
                assert_eq!(
                    (s.stream_id(), s.as_bytes()),
                    (stream, [stream as u8].as_slice())
                );
            }
            let records = log.records();
            for direction in [true, false] {
                let sent: Vec<_> = records[start..]
                    .iter()
                    .filter(|r| r.a_to_b == direction)
                    .collect();
                assert!(sent
                    .iter()
                    .any(|r| r.record_header.is_some_and(|h| h[0] == 20)));
                assert!(sent.iter().any(|r| r.auth_key_id == epoch));
                for record in sent {
                    let header = record.record_header.expect("whole record");
                    let wire_epoch = u16::from_be_bytes([header[3], header[4]]);
                    assert_eq!(record.stream_id, 0, "all handshake controls use zero");
                    assert_eq!(record.auth_key_id, wire_epoch);
                    assert!(wire_epoch == epoch - 1 || wire_epoch == epoch);
                    if header[0] == 20 {
                        assert_eq!(wire_epoch, epoch - 1);
                    }
                }
            }
            let (sent, received) = tokio::join!(
                client.send_on_stream(2, b"fresh", deadline),
                server.receive(deadline)
            );
            sent.expect("new epoch send");
            assert_eq!(received.expect("new epoch receive").as_bytes(), b"fresh");
        }
    }
}

#[tokio::test]
async fn rekey_requires_opt_in_and_cancellation_closes_the_association() {
    let material = dtls_material();
    let ordinary = generic_policy(PayloadProtocol::Ngap);
    let (mut client, server, _) = generic_pair(&material, ordinary, ordinary).await;
    assert!(!client.readback().expect("ordinary evidence").allows_rekey());
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(client.rekey(deadline).await, Err(Error::PolicyRejected));
    assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
    assert_eq!(server.readback().err(), Some(Error::ConnectionClosed));
    let enabled = ordinary.with_rekey();
    for client_role in [true, false] {
        let (mut client, mut server, log) = generic_pair(&material, enabled, enabled).await;
        log.set_dtls_send_blocked(true, true);
        let (cancelled, peer) = if client_role {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        let mut rekey = Box::pin(cancelled.rekey(deadline));
        std::future::poll_fn(|context| {
            assert!(rekey.as_mut().poll(context).is_pending(), "held handshake");
            Poll::Ready(())
        })
        .await;
        drop(rekey);
        assert_eq!(cancelled.readback().err(), Some(Error::ConnectionClosed));
        assert_eq!(peer.readback().err(), Some(Error::ConnectionClosed));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_rekey_preserves_multistream_records_and_rotates_keys() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").expect("current network namespace"),
        std::fs::read_link("/proc/1/ns/net").expect("initial network namespace"),
        "requires a private network namespace"
    );
    let material = dtls_material();
    let deadline = Instant::now() + Duration::from_secs(40);
    for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
        let (client, server) =
            kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline).await;
        let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 32)
            .expect("streams")
            .with_allowed_ciphers(&[cipher])
            .expect("cipher")
            .with_rekey();
        let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
            .expect("connector");
        let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
            .expect("acceptor");
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::from_sctp(client, PayloadProtocol::Ngap, 64).expect("carrier"),
                deadline
            ),
            acceptor.accept(
                Transport::from_sctp(server, PayloadProtocol::Ngap, 64).expect("carrier"),
                deadline
            ),
        );
        let (mut client, mut server) = (client.expect("client"), server.expect("server"));
        for epoch in 2..=4_u16 {
            let mut expected = std::collections::BTreeMap::<u16, Vec<Vec<u8>>>::new();
            for stream in [15, 0, 1, 15, 0, 1] {
                let payload = vec![epoch as u8, stream as u8, expected.len() as u8];
                client
                    .send_on_stream(stream, &payload, deadline)
                    .await
                    .expect("old client send");
                server
                    .send_on_stream(stream, &payload, deadline)
                    .await
                    .expect("old server send");
                expected.entry(stream).or_default().push(payload);
            }
            // Leave every old application record unread across the key transition.
            let (c, s) = tokio::join!(client.rekey(deadline), server.rekey(deadline));
            c.expect("native client rekey");
            s.expect("native server rekey");
            for connection in [&mut client, &mut server] {
                let evidence = connection.readback().expect("completed native transition");
                assert_eq!(evidence.record_epoch(), epoch);
                assert_eq!(evidence.cipher(), cipher);
                let mut actual = std::collections::BTreeMap::<u16, Vec<Vec<u8>>>::new();
                for _ in 0..6 {
                    let received = connection
                        .receive(deadline)
                        .await
                        .expect("retained old record");
                    actual
                        .entry(received.stream_id())
                        .or_default()
                        .push(received.as_bytes().to_vec());
                }
                assert_eq!(actual, expected, "retain ordering within each SCTP stream");
            }
            for reverse in [false, true] {
                let (sender, receiver) = if reverse {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };
                let (sent, received) = tokio::join!(
                    sender.send_on_stream(2, b"new native epoch", deadline),
                    receiver.receive(deadline)
                );
                sent.expect("new key send");
                let received = received.expect("new key receive");
                assert_eq!(
                    (received.stream_id(), received.as_bytes()),
                    (2, b"new native epoch".as_slice())
                );
            }
        }
        let (closed, peer) = tokio::join!(client.close(deadline), server.receive(deadline));
        closed.expect("reciprocal native close after rekey");
        assert_eq!(peer.err(), Some(Error::PeerClosed));
    }
    println!("native protected SCTP rekey assertions completed: 3 ciphers, 9 transitions per peer");
}
