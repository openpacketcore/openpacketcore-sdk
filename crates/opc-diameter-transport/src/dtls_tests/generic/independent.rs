//! Authored lifecycle obligations, real DTLS and the existing in-memory carrier.
use super::*;
use crate::dtls::{SctpDeliveryOrder, SctpUserMessage};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/rfc6083/lifecycle.tsv"
));

fn initial_auth_epoch(log: &SctpWireLog) {
    let records = log.records();
    assert!(records.iter().all(|record| record.ppid == 66));
    for direction in [false, true] {
        let records: Vec<_> = records
            .iter()
            .filter(|record| record.a_to_b == direction)
            .collect();
        let transition = records
            .iter()
            .position(|record| record.auth_key_id == 1)
            .expect("exporter-key transition in each direction");
        assert!(transition > 0);
        assert!(records[..transition]
            .iter()
            .all(|record| record.auth_key_id == 0));
        assert!(records[..transition]
            .iter()
            .any(|record| { record.record_header.is_some_and(|header| header[0] == 20) }));
        let first = records[transition].record_header.expect("Finished header");
        assert!(first[0] == 22 && u16::from_be_bytes([first[3], first[4]]) == 1);
        assert!(records[transition..]
            .iter()
            .all(|record| record.auth_key_id == 1));
    }
}

fn readback(connection: &Connection) -> String {
    match connection.readback() {
        Ok(evidence) => {
            assert_eq!(format!("{evidence:?}"), "Evidence([redacted])");
            assert_eq!(evidence.payload_protocol(), PayloadProtocol::Ngap);
            "active".to_owned()
        }
        Err(error) => error.to_string(),
    }
}

async fn metadata_case(side: &str, family: &str, argument: &str) -> String {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
        .expect("connector");
    let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
        .expect("acceptor");
    let (client_io, server_io, log) = in_memory_sctp_link(64);
    let (stage, fault) = argument.split_once(':').expect("stage and fault");
    let message = SctpUserMessage::new(
        Bytes::new(),
        if family == "cleartext" {
            fault.parse().expect("numeric PPID")
        } else {
            66
        },
        match fault {
            "stream-one" => 1,
            "stream-max" => u16::MAX,
            _ => 0,
        },
        if fault == "unordered" {
            SctpDeliveryOrder::Unordered
        } else {
            SctpDeliveryOrder::Ordered
        },
        fault == "payload-truncated",
        fault == "control-truncated",
        fault == "notification",
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let error = if stage == "before" {
        log.set_next_dtls_metadata(side != "connector", message);
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::in_memory(client_io, PayloadProtocol::Ngap),
                deadline
            ),
            acceptor.accept(
                Transport::in_memory(server_io, PayloadProtocol::Ngap),
                deadline
            ),
        );
        let local = if side == "connector" { client } else { server };
        let error = local.expect_err("no protected connection with invalid metadata");
        assert!(
            log.records()
                .iter()
                .all(|record| { record.record_header.is_none_or(|header| header[0] != 23) }),
            "no application before protected admission"
        );
        error
    } else {
        assert_eq!(stage, "after");
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::in_memory(client_io, PayloadProtocol::Ngap),
                deadline
            ),
            acceptor.accept(
                Transport::in_memory(server_io, PayloadProtocol::Ngap),
                deadline
            ),
        );
        let mut client = client.expect("client admitted");
        let mut server = server.expect("server admitted");
        initial_auth_epoch(&log);
        log.set_next_dtls_metadata(side != "connector", message);
        let (local, remote) = if side == "connector" {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        let before = log.records().len();
        remote
            .send(b"synthetic-valid-encrypted-record", deadline)
            .await
            .expect("authentic record with altered carrier metadata");
        assert_eq!(log.records().len(), before + 1);
        let error = local
            .receive(deadline)
            .await
            .expect_err("metadata refused before plaintext delivery");
        assert_eq!(readback(local), "rfc6083_connection_closed");
        assert_eq!(
            log.records().len(),
            before + 1,
            "rejection emits no further record"
        );
        error
    };
    error.to_string()
}

#[tokio::test]
async fn independent_ngap_dtls_lifecycle_schedules_match_public_contract() {
    let mut names = std::collections::BTreeSet::new();
    for row in REFERENCE.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 5);
        let (name, family, side, argument, expected) =
            (fields[0], fields[1], fields[2], fields[3], fields[4]);
        assert!(names.insert(name), "unique independent schedule");
        assert!(matches!(side, "connector" | "acceptor"));
        if matches!(family, "metadata" | "cleartext") {
            assert_eq!(
                metadata_case(side, family, argument).await,
                expected,
                "{name}"
            );
            continue;
        }
        let material = dtls_material();
        let policy = generic_policy(PayloadProtocol::Ngap);
        let local_policy = if family == "limits" && argument == "receive" {
            Policy::ordered_stream_zero(PayloadProtocol::Ngap, 1).expect("finite receiver bound")
        } else {
            policy
        };
        let (client_policy, server_policy) = if side == "connector" {
            (local_policy, policy)
        } else {
            (policy, local_policy)
        };
        let (client, server, log) = generic_pair(&material, client_policy, server_policy).await;
        initial_auth_epoch(&log);
        let (mut local, mut remote) = if side == "connector" {
            (client, server)
        } else {
            (server, client)
        };
        assert_eq!(readback(&local), "active");
        let deadline = Instant::now() + Duration::from_secs(5);
        let outcome = match family {
            "records" => {
                let size: usize = argument.parse().expect("synthetic length");
                let payload = vec![0x5a; size];
                let before = log.records().len();
                let (sent, received) =
                    tokio::join!(local.send(&payload, deadline), remote.receive(deadline));
                sent.expect("bounded send");
                let received = received.expect("authenticated receive");
                assert!(
                    received.as_bytes() == payload,
                    "opaque record equality: {name}"
                );
                assert_eq!(format!("{received:?}"), "ApplicationMessage([redacted])");
                let records = log.records();
                assert_eq!(records.len(), before + 1, "one record per SCTP message");
                assert!(records[before..]
                    .iter()
                    .all(|record| record.auth_key_id == 1 && record.ppid == 66));
                assert_eq!(readback(&local), "active");
                assert_eq!(readback(&remote), "active");
                "delivered".to_owned()
            }
            "limits" => {
                let error = if argument == "send" {
                    let before = log.records().len();
                    let error = local
                        .send(&vec![0; MAX_DTLS_SCTP_MESSAGE_BYTES + 1], deadline)
                        .await
                        .unwrap_err();
                    assert_eq!(log.records().len(), before, "oversize send emits nothing");
                    error
                } else {
                    assert_eq!(argument, "receive");
                    remote
                        .send(b"xx", deadline)
                        .await
                        .expect("sender budget allows record");
                    local
                        .receive(deadline)
                        .await
                        .expect_err("receiver bound enforced")
                };
                assert_eq!(readback(&local), "rfc6083_connection_closed");
                assert_eq!(readback(&remote), "rfc6083_connection_closed");
                error.to_string()
            }
            "cancellation" => {
                let (poll, operation) = argument.split_once('-').expect("poll and operation");
                let before = log.records().len();
                let mut future: std::pin::Pin<Box<dyn Future<Output = ()> + '_>> = match operation {
                    "send" => {
                        log.set_dtls_send_blocked(side == "connector", true);
                        Box::pin(async {
                            let _ = local.send(b"opaque", deadline).await;
                        })
                    }
                    "receive" => Box::pin(async {
                        let _ = local.receive(deadline).await;
                    }),
                    "close" => {
                        log.set_dtls_send_blocked(side == "connector", true);
                        // Consuming close is handled below because it owns the connection.
                        let mut future = Box::pin(local.close(deadline));
                        assert!(
                            std::future::poll_fn(|cx| Poll::Ready(
                                future.as_mut().poll(cx).is_pending()
                            ))
                            .await
                        );
                        drop(future);
                        assert_eq!(log.records().len(), before);
                        assert_eq!(readback(&remote), expected, "{name}");
                        continue;
                    }
                    _ => panic!("unknown cancellation operation"),
                };
                if poll == "polled" {
                    assert!(
                        std::future::poll_fn(|cx| Poll::Ready(
                            future.as_mut().poll(cx).is_pending()
                        ))
                        .await
                    );
                } else {
                    assert_eq!(poll, "unpolled");
                }
                drop(future);
                assert_eq!(
                    log.records().len(),
                    before,
                    "cancelled operation emits nothing"
                );
                assert_eq!(
                    readback(&remote),
                    expected,
                    "peer cancellation boundary: {name}"
                );
                readback(&local)
            }
            "deadline" => {
                if argument == "receive" {
                    remote
                        .send(b"queued", deadline)
                        .await
                        .expect("queue before expiration");
                }
                let before = log.records().len();
                let error = if argument == "send" {
                    local.send(b"expired", Instant::now()).await.unwrap_err()
                } else {
                    assert_eq!(argument, "receive");
                    local
                        .receive(Instant::now())
                        .await
                        .expect_err("expired receive")
                };
                assert_eq!(log.records().len(), before);
                assert_eq!(readback(&local), "rfc6083_connection_closed");
                error.to_string()
            }
            "retirement" => {
                let admitted = local.readback().unwrap().material_epoch();
                remote
                    .send(b"queued-before-retirement", deadline)
                    .await
                    .expect("queue record");
                let (source, controller, identity) = if side == "connector" {
                    (
                        &material.client_source,
                        &material.client_controller,
                        CLIENT_ID,
                    )
                } else {
                    (
                        &material._server_source,
                        &material.server_controller,
                        SERVER_ID,
                    )
                };
                let replacement = match argument {
                    "replacement" => Some(identity_state(identity, &material._ca)),
                    "withdrawal" => None,
                    "trust" => {
                        let mut state = source.borrow().as_ref().expect("admitted state").clone();
                        let additional = test_ca();
                        state.trust_bundles.insert(TrustBundle {
                            trust_domain: TrustDomain::new("example.test").unwrap(),
                            certificates: vec![
                                material._ca.der().clone(),
                                additional.der().clone(),
                            ],
                        });
                        Some(state)
                    }
                    _ => panic!("unknown material transition"),
                };
                source
                    .send(replacement)
                    .expect("publish read-only material input");
                tokio::time::timeout_at(deadline, async {
                    while local.readback().err() != Some(Error::Retired) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("bounded epoch retirement");
                if argument != "withdrawal" {
                    assert_ne!(controller.status().epoch(), admitted);
                }
                assert_eq!(readback(&remote), "rfc6083_connection_closed");
                assert_eq!(
                    local.send(b"after-retirement", deadline).await,
                    Err(Error::Retired)
                );
                local
                    .receive(deadline)
                    .await
                    .expect_err("queued plaintext never delivered")
                    .to_string()
            }
            "carrier" => {
                if argument == "queued-abort" {
                    remote
                        .send(b"queued-before-abort", deadline)
                        .await
                        .expect("queue record");
                } else {
                    assert_eq!(argument, "abort");
                }
                drop(remote);
                assert_eq!(readback(&local), expected, "terminal readback: {name}");
                local
                    .receive(deadline)
                    .await
                    .expect_err("no delivery after abort")
                    .to_string()
            }
            "close" => match argument {
                "reciprocal" => {
                    let (closed, peer_closed) =
                        tokio::join!(local.close(deadline), remote.receive(deadline));
                    closed.expect("sender-drained reciprocal close");
                    peer_closed.expect_err("explicit peer close").to_string()
                }
                "silent" => local
                    .close(Instant::now() + Duration::from_millis(25))
                    .await
                    .unwrap_err()
                    .to_string(),
                "pending" => {
                    remote
                        .send(b"pending", deadline)
                        .await
                        .expect("undelivered record");
                    local.close(deadline).await.unwrap_err().to_string()
                }
                _ => panic!("unknown close operation"),
            },
            _ => panic!("unknown lifecycle family"),
        };
        assert_eq!(outcome, expected, "{name}");
    }
    assert_eq!(names.len(), 78);
}
