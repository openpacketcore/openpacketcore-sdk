//! Exact association-local correlation between encrypted records and streams.
use super::*;
use crate::dtls::{SctpDeliveryOrder, SctpUserMessage};

#[tokio::test]
async fn generic_stream_runtime_gap_detector() {
    let material = dtls_material();
    let policy =
        Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 64).expect("stream policy");
    let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
    log.set_next_dtls_metadata(
        true,
        SctpUserMessage::new(
            Bytes::new(),
            66,
            1,
            SctpDeliveryOrder::Ordered,
            false,
            false,
            false,
        ),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    client
        .send(b"synthetic-ue-stream", deadline)
        .await
        .expect("encrypted send");
    let received = server
        .receive(deadline)
        .await
        .expect("nonzero application stream");
    assert_eq!(received.as_bytes(), b"synthetic-ue-stream");
    assert_eq!(received.stream_id(), 1);
}

#[test]
fn stream_policy_bounds_are_explicit_and_redacted() {
    for count in [0, 1] {
        assert_eq!(
            Policy::ordered_streams(PayloadProtocol::Ngap, 4096, count, 1).err(),
            Some(Error::PolicyRejected)
        );
    }
    for capacity in [
        0,
        crate::MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES + 1,
        usize::MAX,
    ] {
        assert_eq!(
            Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 2, capacity).err(),
            Some(Error::PolicyRejected)
        );
    }
    for count in [2, 16, u16::MAX] {
        for capacity in [1, crate::MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES] {
            let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, count, capacity)
                .expect("inclusive bounds");
            assert_eq!(policy.application_stream_count(), count);
            assert_eq!(policy.pending_record_capacity(), capacity);
            assert_eq!(format!("{policy:?}"), "Policy([redacted])");
        }
    }
    let legacy = generic_policy(PayloadProtocol::Ngap);
    assert_eq!(legacy.application_stream_count(), 1);
    assert_eq!(legacy.pending_record_capacity(), 0);
}

#[tokio::test]
async fn multistream_profile_rejects_nonzero_handshake_and_alert_streams() {
    let material = dtls_material();
    let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 8).expect("policy");
    for reverse in [false, true] {
        let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
            .expect("connector");
        let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
            .expect("acceptor");
        let (client, server, log) = in_memory_sctp_link(64);
        log.set_next_dtls_metadata(
            !reverse,
            SctpUserMessage::new(
                Bytes::new(),
                66,
                1,
                SctpDeliveryOrder::Ordered,
                false,
                false,
                false,
            ),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::in_memory(client, PayloadProtocol::Ngap),
                deadline
            ),
            acceptor.accept(
                Transport::in_memory(server, PayloadProtocol::Ngap),
                deadline
            ),
        );
        assert_eq!(
            if reverse { client.err() } else { server.err() },
            Some(Error::Transport)
        );
        assert!(log
            .records()
            .iter()
            .all(|v| v.record_header.is_none_or(|h| h[0] != 23)));
        let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
        log.set_next_dtls_metadata(
            !reverse,
            SctpUserMessage::new(
                Bytes::new(),
                66,
                1,
                SctpDeliveryOrder::Ordered,
                false,
                false,
                false,
            ),
        );
        let (_closed, peer_closed) = if reverse {
            tokio::join!(server.close(deadline), client.receive(deadline))
        } else {
            tokio::join!(client.close(deadline), server.receive(deadline))
        };
        assert_eq!(peer_closed.err(), Some(Error::Transport));
    }
}

#[tokio::test]
async fn ordered_streams_work_in_both_roles_and_keep_control_on_zero() {
    let material = dtls_material();
    for protocol in [PayloadProtocol::Ngap, PayloadProtocol::Diameter] {
        for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
            let policy =
                Policy::ordered_streams(protocol, MAX_DTLS_SCTP_MESSAGE_BYTES, u16::MAX, 8)
                    .expect("policy")
                    .with_allowed_ciphers(&[cipher])
                    .expect("cipher");
            let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
            assert_eq!(
                client
                    .readback()
                    .expect("readback")
                    .application_stream_count(),
                u16::MAX
            );
            assert_eq!(
                server
                    .readback()
                    .expect("readback")
                    .pending_record_capacity(),
                8
            );
            let mut expected = Vec::new();
            for reverse in [false, true] {
                let (sender, receiver) = if reverse {
                    (&mut server, &mut client)
                } else {
                    (&mut client, &mut server)
                };
                for stream in [0, 1, 2, 15, u16::MAX - 1] {
                    for length in [0, 1, 37, MAX_DTLS_SCTP_MESSAGE_BYTES] {
                        let payload: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
                        let deadline = Instant::now() + Duration::from_secs(5);
                        sender
                            .send_on_stream(stream, &payload, deadline)
                            .await
                            .expect("stream send");
                        let received = receiver.receive(deadline).await.expect("stream receive");
                        assert_eq!(received.stream_id(), stream);
                        assert_eq!(received.as_bytes(), payload);
                        assert_eq!(format!("{received:#?}"), "ApplicationMessage([redacted])");
                        expected.push((!reverse, stream));
                    }
                }
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            let (closed, peer_closed) =
                tokio::join!(client.close(deadline), server.receive(deadline));
            closed.expect("sender-drained reciprocal close");
            assert_eq!(peer_closed.err(), Some(Error::PeerClosed));
            let records = log.records();
            assert!(records.iter().all(|v| v.ppid == protocol.ppid()));
            assert!(records
                .iter()
                .filter(|v| v.record_header.is_some_and(|h| h[0] != 23))
                .all(|v| v.stream_id == 0));
            let actual: Vec<_> = records
                .iter()
                .filter(|v| v.record_header.is_some_and(|h| h[0] == 23))
                .map(|v| {
                    assert_eq!(v.auth_key_id, 1);
                    (v.a_to_b, v.stream_id)
                })
                .collect();
            assert_eq!(actual, expected);
            assert_rfc6083_auth_epoch_boundary(&log);
        }
    }
}

#[tokio::test]
async fn stream_metadata_failures_and_local_bounds_retire_before_delivery() {
    let material = dtls_material();
    let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 8).expect("policy");
    for reverse in [false, true] {
        for fault in [
            "stream-limit",
            "stream-max",
            "unordered",
            "payload",
            "control",
            "notification",
            "cleartext",
            "foreign-protected",
        ] {
            let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
            log.set_next_dtls_metadata(
                !reverse,
                SctpUserMessage::new(
                    Bytes::new(),
                    match fault {
                        "cleartext" => 60,
                        "foreign-protected" => 47,
                        _ => 66,
                    },
                    match fault {
                        "stream-limit" => 16,
                        "stream-max" => u16::MAX,
                        _ => 1,
                    },
                    if fault == "unordered" {
                        SctpDeliveryOrder::Unordered
                    } else {
                        SctpDeliveryOrder::Ordered
                    },
                    fault == "payload",
                    fault == "control",
                    fault == "notification",
                ),
            );
            let (sender, receiver) = if reverse {
                (&mut server, &mut client)
            } else {
                (&mut client, &mut server)
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            sender
                .send_on_stream(1, b"synthetic", deadline)
                .await
                .expect("real encrypted record");
            let error = receiver
                .receive(deadline)
                .await
                .expect_err("invalid metadata");
            assert_eq!(
                error,
                if matches!(fault, "cleartext" | "foreign-protected") {
                    Error::CleartextRejected
                } else {
                    Error::Transport
                }
            );
            assert_eq!(receiver.readback().err(), Some(Error::ConnectionClosed));
        }
    }
    for stream in [16, u16::MAX] {
        let (mut client, _server, log) = generic_pair(&material, policy, policy).await;
        let before = log.records().len();
        assert_eq!(
            client
                .send_on_stream(
                    stream,
                    b"synthetic",
                    Instant::now() + Duration::from_secs(5)
                )
                .await,
            Err(Error::Transport)
        );
        assert_eq!(log.records().len(), before);
        assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
    }
}

#[tokio::test]
async fn stream_send_cancellation_and_material_retirement_keep_exact_fences() {
    let material = dtls_material();
    let policy = Policy::ordered_streams(PayloadProtocol::Ngap, 4096, 16, 8).expect("policy");
    let (mut client, _server, log) = generic_pair(&material, policy, policy).await;
    log.set_dtls_send_blocked(true, true);
    let mut send =
        Box::pin(client.send_on_stream(3, b"synthetic", Instant::now() + Duration::from_secs(5)));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(send);
    assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
    let (mut client, mut server, _) = generic_pair(&material, policy, policy).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    server
        .send_on_stream(7, b"queued", deadline)
        .await
        .expect("queued real record");
    material
        .client_source
        .send(None)
        .expect("withdraw material");
    assert_eq!(client.receive(deadline).await.err(), Some(Error::Retired));
    assert_eq!(client.readback().err(), Some(Error::Retired));
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_multistream_preserves_payload_streams_and_close() {
    let material = dtls_material();
    let deadline = Instant::now() + Duration::from_secs(20);
    let (client, server) =
        kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline).await;
    let policy =
        Policy::ordered_streams(PayloadProtocol::Ngap, MAX_DTLS_SCTP_MESSAGE_BYTES, 16, 16)
            .expect("policy");
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
    for reverse in [false, true] {
        let (sender, receiver) = if reverse {
            (&mut server, &mut client)
        } else {
            (&mut client, &mut server)
        };
        let mut expected = std::collections::BTreeMap::<u16, Vec<Vec<u8>>>::new();
        for stream in [1, 0, 15, 2, 1, 0, 15, 2] {
            let payload = vec![
                stream as u8;
                if expected.contains_key(&stream) {
                    MAX_DTLS_SCTP_MESSAGE_BYTES
                } else {
                    0
                }
            ];
            sender
                .send_on_stream(stream, &payload, deadline)
                .await
                .expect("kernel stream send");
            expected.entry(stream).or_default().push(payload);
        }
        let mut actual = std::collections::BTreeMap::<u16, Vec<Vec<u8>>>::new();
        for _ in 0..8 {
            let received = receiver
                .receive(deadline)
                .await
                .expect("kernel stream receive");
            actual
                .entry(received.stream_id())
                .or_default()
                .push(received.into_bytes().to_vec());
        }
        assert_eq!(
            actual, expected,
            "ordered within each stream; no cross-stream ordering assumption"
        );
        assert_eq!(
            sender
                .readback()
                .expect("retained")
                .application_stream_count(),
            16
        );
    }
    let (closed, peer_closed) = tokio::join!(client.close(deadline), server.receive(deadline));
    closed.expect("sender-drained close across every stream");
    assert_eq!(peer_closed.err(), Some(Error::PeerClosed));
}
