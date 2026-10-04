use super::*;
use crate::PayloadProtocolIdentifier;

const UNPROTECTED_VECTOR: &str =
    include_str!("../../../opc-n3iwf-fixtures/fixtures/n2-sctp/wire/positive-ppid60-port.hex");
const PROTECTED_VECTOR: &str =
    include_str!("../../../opc-n3iwf-fixtures/fixtures/n2-sctp/wire/unknown-ppid66.hex");

fn hex_bytes(source: &str) -> Vec<u8> {
    let source: String = source.split_whitespace().collect();
    assert!(source.len().is_multiple_of(2), "invalid synthetic fixture");
    source
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn profile() -> UnprotectedN2Profile {
    UnprotectedN2Profile::new(3).unwrap()
}

fn data(ppid: u32) -> InboundMessage {
    InboundMessage {
        payload: Bytes::from_static(b"nas"),
        stream_id: 7,
        ppid: PayloadProtocolIdentifier::new(ppid),
        order: DeliveryOrder::Ordered,
        assoc_id: 41,
        notification: false,
        event: None,
        truncated: false,
        control_truncated: false,
    }
}

#[test]
fn published_numeric_vectors_match_iana_bytes_independently() {
    let plain = hex_bytes(UNPROTECTED_VECTOR);
    let protected = hex_bytes(PROTECTED_VECTOR);
    assert!(plain == [0, 0, 0, 60, 0x96, 0x0c], "NGAP fixture drift");
    assert!(protected == [0, 0, 0, 66, 0x96, 0x0c], "DTLS fixture drift");
    assert!(NGAP_PPID.to_network_order().to_ne_bytes() == plain[..4]);
    assert!(NGAP_DEFAULT_PORT.to_be_bytes() == plain[4..]);
    let address = default_destination("192.0.2.60".parse().unwrap());
    assert!(address.port() == u16::from_be_bytes([plain[4], plain[5]]));
    let v6 = default_destination("2001:db8::60".parse().unwrap());
    assert!(v6.port() == 38412 && v6.is_ipv6());
}

#[test]
fn strict_inbound_ppid_rejects_protected_and_non_ngap_data() {
    let protected = hex_bytes(PROTECTED_VECTOR);
    let protected_ppid = u32::from_be_bytes(protected[..4].try_into().unwrap());
    for ppid in [0, 46, protected_ppid, 60_u32.swap_bytes(), u32::MAX] {
        assert!(
            matches!(profile().admit(data(ppid)), Err(N2Error::WrongPpid)),
            "non-NGAP DATA crossed the strict admission boundary"
        );
    }
    for bit in 0..32 {
        assert!(
            matches!(
                profile().admit(data(60 ^ (1 << bit))),
                Err(N2Error::WrongPpid)
            ),
            "mutated PPID crossed the strict admission boundary"
        );
    }
}

#[test]
fn accepted_record_keeps_payload_stream_and_association_exactly() {
    let original = data(60);
    let N2Inbound::Payload(admitted) = profile().admit(original.clone()).unwrap() else {
        panic!("DATA became a notification");
    };
    assert!(admitted.payload() == &original.payload, "payload changed");
    assert!(admitted.stream_id() == original.stream_id, "stream changed");
    assert!(
        admitted.association_id() == original.assoc_id,
        "association changed"
    );
    assert!(
        admitted.into_payload() == original.payload,
        "payload changed"
    );
}

#[test]
fn outbound_record_is_ordered_ppid60_on_the_selected_stream() {
    for stream_id in [0, 1, 17, u16::MAX] {
        let outbound = profile()
            .outbound_message(Bytes::from_static(b"nas"), stream_id)
            .unwrap();
        assert!(format!("{outbound:?}") == "N2OutboundMessage { .. }");
        let raw = outbound.into_sctp_message();
        assert!(raw.payload.as_ref() == b"nas", "payload changed");
        assert!(raw.stream_id == stream_id, "stream changed");
        assert!(raw.order == DeliveryOrder::Ordered);
        assert!(raw.ppid.get() == 60 && raw.assoc_id == 0);
    }
}

#[test]
fn empty_and_oversized_data_fail_at_both_boundaries() {
    assert!(matches!(
        UnprotectedN2Profile::new(0),
        Err(N2Error::InvalidLimit)
    ));
    assert!(profile().max_message_bytes() == 3);
    for (payload, expected) in [
        (Bytes::new(), N2Error::EmptyPayload),
        (Bytes::from_static(b"over"), N2Error::MessageTooLarge),
    ] {
        let mut inbound = data(60);
        inbound.payload = payload.clone();
        assert!(matches!(profile().admit(inbound), Err(error) if error == expected));
        assert!(matches!(profile().outbound_message(payload, 0), Err(error) if error == expected));
    }
    assert!(profile().admit(data(60)).is_ok());
}

#[test]
fn truncated_and_unordered_data_cannot_become_payload() {
    let mut payload = data(60);
    payload.truncated = true;
    assert!(matches!(
        profile().admit(payload),
        Err(N2Error::TruncatedPayload)
    ));
    let mut metadata = data(60);
    metadata.control_truncated = true;
    assert!(matches!(
        profile().admit(metadata),
        Err(N2Error::TruncatedMetadata)
    ));
    let mut unordered = data(60);
    unordered.order = DeliveryOrder::Unordered;
    assert!(matches!(
        profile().admit(unordered),
        Err(N2Error::UnorderedData)
    ));
}

#[test]
fn notification_bytes_never_become_ngap_and_do_not_use_the_data_cap_or_ppid() {
    let event = SctpEvent::Shutdown { assoc_id: 41 };
    let mut notification = data(66);
    notification.notification = true;
    notification.event = Some(event);
    notification.payload = Bytes::from_static(b"synthetic notification beyond DATA cap");
    let admitted = profile().admit(notification.clone()).unwrap();
    assert!(matches!(admitted, N2Inbound::Notification(actual) if actual == event));
    assert!(format!("{admitted:?}") == "N2Inbound::Notification { .. }");
    notification.truncated = true;
    assert!(matches!(
        profile().admit(notification.clone()),
        Err(N2Error::TruncatedPayload)
    ));
    notification.truncated = false;
    notification.control_truncated = true;
    assert!(matches!(
        profile().admit(notification),
        Err(N2Error::TruncatedMetadata)
    ));
}

#[test]
fn inconsistent_notification_flags_fail_closed() {
    let mut missing_event = data(60);
    missing_event.notification = true;
    assert!(matches!(
        profile().admit(missing_event),
        Err(N2Error::InvalidNotification)
    ));
    let mut unflagged = data(60);
    unflagged.event = Some(SctpEvent::Shutdown { assoc_id: 41 });
    assert!(matches!(
        profile().admit(unflagged),
        Err(N2Error::InvalidNotification)
    ));
    let mut unknown = data(60);
    unknown.notification = true;
    unknown.event = Some(SctpEvent::Unknown {
        notification_type: u16::MAX,
    });
    assert!(matches!(
        profile().admit(unknown),
        Ok(N2Inbound::Notification(SctpEvent::Unknown { .. }))
    ));
}

#[test]
fn diagnostics_drop_payload_and_transport_details() {
    assert!(format!("{:?}", profile()) == "UnprotectedN2Profile { .. }");
    let received = profile().admit(data(60)).unwrap();
    assert!(format!("{received:?}") == "N2Inbound::Payload { .. }");
    let N2Inbound::Payload(payload) = received else {
        unreachable!()
    };
    assert!(format!("{payload:?}") == "N2Payload { .. }");
    let error = transport_error(
        SctpError::InvalidConfig {
            field: "synthetic-sensitive-field",
            reason: "synthetic-sensitive-reason",
        },
        N2Error::ConnectFailed,
    );
    assert!(error.to_string() == "n2_invalid_configuration");
    assert!(format!("{error:?}") == "InvalidConfiguration");
    assert!(std::error::Error::source(&error).is_none());
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use crate::{SctpEndpoint, SctpEndpointConfig};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const GUARD: Duration = Duration::from_secs(5);

    async fn pair(max_message_bytes: usize) -> (UnprotectedN2Association, SctpAssociation) {
        let mut bind = SctpEndpointConfig::one_to_one(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        bind.max_message_bytes = max_message_bytes;
        let endpoint = SctpEndpoint::bind(bind).unwrap();
        let address = endpoint.local_addresses().unwrap()[0];
        let mut config = SctpConnectConfig::new(address);
        config.max_message_bytes = max_message_bytes;
        let client = tokio::time::timeout(GUARD, UnprotectedN2Association::connect(config))
            .await
            .expect("N2 connect timed out")
            .unwrap();
        let accepted = tokio::time::timeout(GUARD, endpoint.accept())
            .await
            .expect("N2 accept timed out")
            .unwrap();
        assert!(client.profile().max_message_bytes() == max_message_bytes);
        assert!(client.peer_addresses().unwrap() == accepted.local_addresses().unwrap());
        assert!(client.local_addresses().unwrap() == accepted.peer_addresses().unwrap());
        assert!(client.peer_path_health().len() == 1);
        assert!(format!("{client:?}") == "UnprotectedN2Association { .. }");
        (client, accepted)
    }

    async fn receive_raw(association: &SctpAssociation) -> InboundMessage {
        tokio::time::timeout(GUARD, async {
            for _ in 0..16 {
                let message = association.recv().await.unwrap();
                if !message.notification {
                    return message;
                }
            }
            panic!("too many synthetic transport notifications");
        })
        .await
        .expect("raw N2 receive timed out")
    }

    async fn receive_payload(association: &UnprotectedN2Association) -> Result<N2Payload, N2Error> {
        tokio::time::timeout(GUARD, async {
            for _ in 0..16 {
                match association.recv().await? {
                    N2Inbound::Payload(payload) => return Ok(payload),
                    N2Inbound::Notification(_) => {}
                }
            }
            panic!("too many synthetic transport notifications");
        })
        .await
        .expect("profiled N2 receive timed out")
    }

    async fn send_raw(association: &SctpAssociation, message: OutboundMessage) {
        tokio::time::timeout(GUARD, association.send(message))
            .await
            .expect("synthetic N2 send timed out")
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support; executed by the required SCTP CI lane"]
    async fn unprotected_n2_profile() {
        let (client, server) = pair(4).await;
        assert!(matches!(
            client.send(Bytes::from_static(b"large"), 7).await,
            Err(N2Error::MessageTooLarge)
        ));
        let mut streams = std::collections::BTreeMap::<u16, Vec<Bytes>>::new();
        for (stream, bytes) in [(7, b"one"), (2, b"two"), (7, b"end")] {
            tokio::time::timeout(GUARD, client.send(Bytes::from_static(bytes), stream))
                .await
                .expect("N2 send timed out")
                .unwrap();
        }
        for _ in 0..3 {
            let message = receive_raw(&server).await;
            assert!(message.ppid.get() == 60 && message.order == DeliveryOrder::Ordered);
            assert!(!message.truncated && !message.control_truncated);
            streams
                .entry(message.stream_id)
                .or_default()
                .push(message.payload);
        }
        assert!(
            streams.get(&7).unwrap() == &[Bytes::from_static(b"one"), Bytes::from_static(b"end")]
        );
        assert!(streams.get(&2).unwrap() == &[Bytes::from_static(b"two")]);
        assert!(streams.len() == 2);
        send_raw(
            &server,
            OutboundMessage::ordered(Bytes::from_static(b"back"), 9, NGAP_PPID),
        )
        .await;
        let payload = receive_payload(&client).await.unwrap();
        assert!(payload.payload().as_ref() == b"back" && payload.stream_id() == 9);
        drop(client);
        drop(server);

        // Live wrong-PPID admission is terminal; it cannot leave a send-capable
        // connection behind after rejecting a protected or unclassified record.
        for ppid in [66, 0] {
            let (client, server) = pair(4).await;
            send_raw(
                &server,
                OutboundMessage::ordered(
                    Bytes::from_static(b"bad"),
                    7,
                    PayloadProtocolIdentifier::new(ppid),
                ),
            )
            .await;
            send_raw(
                &server,
                OutboundMessage::ordered(Bytes::from_static(b"end"), 7, NGAP_PPID),
            )
            .await;
            let received = tokio::join!(receive_payload(&client), receive_payload(&client));
            assert!(matches!(
                received,
                (Err(N2Error::WrongPpid), Err(N2Error::ReceiveFailed))
                    | (Err(N2Error::ReceiveFailed), Err(N2Error::WrongPpid))
            ));
            assert!(client.send(Bytes::from_static(b"end"), 7).await.is_err());
            assert!(matches!(client.recv().await, Err(N2Error::ReceiveFailed)));
        }

        let (client, server) = pair(4).await;
        send_raw(
            &server,
            OutboundMessage::ordered(Bytes::from_static(b"large"), 7, NGAP_PPID),
        )
        .await;
        assert!(matches!(
            receive_payload(&client).await,
            Err(N2Error::MessageTooLarge)
        ));
        assert!(client.send(Bytes::from_static(b"end"), 7).await.is_err());
        drop(client);
        drop(server);

        let (client, server) = pair(200_000).await;
        let cancelled = tokio::time::timeout(Duration::from_millis(10), async {
            loop {
                match client.recv().await.unwrap() {
                    N2Inbound::Notification(_) => {}
                    N2Inbound::Payload(_) => panic!("unexpected DATA before synthetic sender"),
                }
            }
        })
        .await;
        assert!(
            cancelled.is_err(),
            "idle receive did not remain cancellable"
        );
        let large = Bytes::from(vec![0x41; 100_000]);
        send_raw(
            &server,
            OutboundMessage::ordered(large.clone(), 11, NGAP_PPID),
        )
        .await;
        let received = receive_payload(&client).await.unwrap();
        assert!(
            received.payload() == &large && received.stream_id() == 11,
            "record boundary changed"
        );
        let abort_handle = client.abort_handle();
        drop(client);
        tokio::time::timeout(GUARD, async {
            for _ in 0..16 {
                match server.recv().await {
                    Err(_) => return,
                    Ok(message) if message.notification => {}
                    Ok(_) => panic!("DATA appeared after N2 owner drop"),
                }
            }
            panic!("N2 owner drop did not terminate its transport");
        })
        .await
        .expect("peer did not observe N2 owner drop");
        // Retaining this handle must not have kept the dropped owner alive.
        abort_handle.abort();

        // Accepted associations use the same actual transport bound.
        let (client, server) = pair(4).await;
        let accepted = UnprotectedN2Association::from_association(server).unwrap();
        client.send(Bytes::from_static(b"end"), 5).await.unwrap();
        let received = receive_payload(&accepted).await.unwrap();
        assert!(received.payload().as_ref() == b"end" && received.stream_id() == 5);
        assert!(accepted.profile().max_message_bytes() == 4);
        println!("native N2 framing assertions completed");
    }
}
