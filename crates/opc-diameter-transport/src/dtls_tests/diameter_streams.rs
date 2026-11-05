//! RFC 6733 section 2.1.1 admits application messages on any SCTP stream.
use super::*;
use crate::dtls::{SctpDeliveryOrder, SctpUserMessage};

#[tokio::test]
async fn diameter_accepts_peer_application_streams_in_both_roles_and_runtimes() {
    for reverse in [false, true] {
        for concurrent in [false, true] {
            for (stream, order) in [
                (1, SctpDeliveryOrder::Ordered),
                (u16::MAX - 1, SctpDeliveryOrder::Ordered),
                (0, SctpDeliveryOrder::Unordered),
                (7, SctpDeliveryOrder::Unordered),
            ] {
                let material = dtls_material();
                let (mut client, mut server, log) = establish_pair(
                    &material,
                    DtlsSctpPolicy::default(),
                    DtlsSctpPolicy::default(),
                )
                .await
                .expect("protected association");
                let deadline = Instant::now() + Duration::from_secs(5);
                negotiate_capabilities(&mut client, &mut server, deadline).await;
                let (mut sender, mut receiver) = if reverse {
                    (server, client)
                } else {
                    (client, server)
                };
                log.set_next_dtls_metadata(
                    !reverse,
                    SctpUserMessage::new(
                        Bytes::new(),
                        DIAMETER_DTLS_SCTP_PPID,
                        stream,
                        order,
                        false,
                        false,
                        false,
                    ),
                );
                let request = application_request();
                sender
                    .send_message(&request, deadline)
                    .await
                    .expect("send protected message");
                if concurrent {
                    let capacity = NonZeroUsize::new(2).expect("capacity");
                    let config = DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, None)
                        .expect("runtime bounds");
                    let (_handle, mut incoming) = receiver
                        .into_peer_runtime(config)
                        .expect("peer runtime")
                        .into_parts();
                    let received = tokio::time::timeout_at(deadline, incoming.receive())
                        .await
                        .expect("bounded receive")
                        .expect("application stream");
                    assert_eq!(received.into_message(), request);
                } else {
                    let (received, admission) = receiver
                        .receive_message(deadline)
                        .await
                        .expect("application stream");
                    assert_eq!(received, request);
                    assert!(admission.is_protected());
                }
                assert!(log.records().iter().all(|record| {
                    record.record_header.is_some_and(|header| header[0] == 23)
                        || record.stream_id == 0
                }));
            }
        }
    }
}

#[tokio::test]
async fn diameter_selected_streams_keep_protection_and_reserved_stream_fails_closed() {
    let material = dtls_material();
    for reverse in [false, true] {
        let (mut client, mut server, log) = establish_pair(
            &material,
            DtlsSctpPolicy::default(),
            DtlsSctpPolicy::default(),
        )
        .await
        .expect("protected association");
        let deadline = Instant::now() + Duration::from_secs(5);
        negotiate_capabilities(&mut client, &mut server, deadline).await;
        let (mut sender, mut receiver) = if reverse {
            (server, client)
        } else {
            (client, server)
        };
        for stream in [0, 1, 7, u16::MAX - 1] {
            let request = application_request();
            let admission = sender
                .send_message_on_stream(&request, stream, deadline)
                .await
                .expect("selected application stream");
            assert!(admission.is_protected());
            let sent = log.records().last().copied().expect("wire record");
            assert_eq!(sent.stream_id, stream);
            assert_eq!(sent.ppid, DIAMETER_DTLS_SCTP_PPID);
            assert_eq!(sent.auth_key_id, 1);
            let (received, admission) = receiver.receive_message(deadline).await.expect("receive");
            assert_eq!(received, request);
            assert!(admission.is_protected());
        }
        let sent = log.records().len();
        assert_eq!(
            sender
                .send_message_on_stream(&application_request(), u16::MAX, deadline)
                .await
                .err(),
            Some(DiameterTlsError::Transport)
        );
        assert_eq!(
            log.records().len(),
            sent,
            "reserved stream never reaches the carrier"
        );
        assert!(sender.protection_readiness().is_err());
    }
}

#[tokio::test]
async fn diameter_application_streams_retain_metadata_and_control_refusals() {
    for invalid in [
        (DIAMETER_DTLS_SCTP_PPID, u16::MAX, false, false, false),
        (DIAMETER_DTLS_SCTP_PPID, 7, true, false, false),
        (DIAMETER_DTLS_SCTP_PPID, 7, false, true, false),
        (DIAMETER_DTLS_SCTP_PPID, 7, false, false, true),
        (46, 7, false, false, false),
    ] {
        let material = dtls_material();
        let (mut sender, mut receiver, log) = establish_pair(
            &material,
            DtlsSctpPolicy::default(),
            DtlsSctpPolicy::default(),
        )
        .await
        .expect("protected association");
        let deadline = Instant::now() + Duration::from_secs(5);
        negotiate_capabilities(&mut sender, &mut receiver, deadline).await;
        log.set_next_dtls_metadata(
            true,
            SctpUserMessage::new(
                Bytes::new(),
                invalid.0,
                invalid.1,
                SctpDeliveryOrder::Unordered,
                invalid.2,
                invalid.3,
                invalid.4,
            ),
        );
        sender
            .send_message(&application_request(), deadline)
            .await
            .expect("send");
        assert!(matches!(
            receiver.receive_message(deadline).await,
            Err(DiameterTlsError::Transport | DiameterTlsError::CleartextInput)
        ));
        assert!(receiver.protection_readiness().is_err());
    }
    for (stream, order) in [
        (1, SctpDeliveryOrder::Ordered),
        (0, SctpDeliveryOrder::Unordered),
    ] {
        let material = dtls_material();
        let (mut sender, mut receiver, log) = establish_pair(
            &material,
            DtlsSctpPolicy::default(),
            DtlsSctpPolicy::default(),
        )
        .await
        .expect("protected association");
        let deadline = Instant::now() + Duration::from_secs(5);
        negotiate_capabilities(&mut sender, &mut receiver, deadline).await;
        log.set_next_dtls_metadata(
            true,
            SctpUserMessage::new(
                Bytes::new(),
                DIAMETER_DTLS_SCTP_PPID,
                stream,
                order,
                false,
                false,
                false,
            ),
        );
        let (_, received) =
            tokio::join!(sender.close(deadline), receiver.receive_message(deadline));
        assert_eq!(received.err(), Some(DiameterTlsError::Transport));
        assert!(receiver.protection_readiness().is_err());
    }
}
