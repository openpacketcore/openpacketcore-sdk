//! Exercise the public generic boundary without constructing a Diameter session.

mod independent;

use super::*;
use crate::rfc6083::{
    Acceptor, Connection, Connector, Error, ExpectedPeer, PayloadProtocol, Policy, Role, Transport,
};
use std::future::Future;
use std::task::Poll;

fn generic_policy(protocol: PayloadProtocol) -> Policy {
    Policy::ordered_stream_zero(protocol, MAX_DTLS_SCTP_MESSAGE_BYTES).expect("bounded policy")
}

fn peer(value: &str) -> ExpectedPeer {
    ExpectedPeer::spiffe(SpiffeId::new(value).expect("synthetic SPIFFE identity"))
}

async fn generic_pair(
    material: &TestMaterial,
    client_policy: Policy,
    server_policy: Policy,
) -> (Connection, Connection, SctpWireLog) {
    let connector = Connector::new(
        material.client_controller.clone(),
        peer(SERVER_ID),
        client_policy,
    )
    .expect("generic connector");
    let acceptor = Acceptor::new(
        material.server_controller.clone(),
        peer(CLIENT_ID),
        server_policy,
    )
    .expect("generic acceptor");
    let (client, server, log) = in_memory_sctp_link(64);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (client, server) = tokio::join!(
        connector.connect(
            Transport::in_memory(client, client_policy.payload_protocol()),
            deadline
        ),
        acceptor.accept(
            Transport::in_memory(server, server_policy.payload_protocol()),
            deadline
        ),
    );
    (
        client.expect("client authenticated"),
        server.expect("server authenticated"),
        log,
    )
}

#[tokio::test]
async fn generic_mutual_connection_carries_opaque_records_on_both_protected_ppids() {
    let material = dtls_material();
    for protocol in [PayloadProtocol::Ngap, PayloadProtocol::Diameter] {
        for cipher in DtlsSctpPolicy::default().allowed_ciphers() {
            let policy = generic_policy(protocol)
                .with_allowed_ciphers(&[cipher])
                .expect("cipher policy");
            let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
            let client_readback = client.readback().expect("active readback");
            assert_eq!(client_readback.role(), Role::Connector);
            assert_eq!(client_readback.version(), DtlsSctpVersion::Dtls12);
            assert_eq!(client_readback.cipher(), cipher);
            assert_eq!(client_readback.payload_protocol(), protocol);
            assert_eq!(client_readback.expected_peer(), &peer(SERVER_ID));
            assert_eq!(
                client_readback.material_epoch(),
                material.client_controller.status().epoch()
            );
            assert_eq!(
                server.readback().expect("server readback").role(),
                Role::Acceptor
            );
            assert_eq!(format!("{client_readback:?}"), "Evidence([redacted])");
            assert_rfc6083_auth_epoch_boundary(&log);
            assert!(log
                .records()
                .iter()
                .all(|record| record.ppid == protocol.ppid()));
            assert!(
                !log.records()
                    .iter()
                    .any(|record| record.record_header.is_some_and(|h| h[0] == 23)),
                "no application before explicit send"
            );
            for size in [0, 1, 19, MAX_DTLS_SCTP_MESSAGE_BYTES] {
                let payload: Vec<_> = (0..size).map(|i| ((i * 37 + 19) % 256) as u8).collect();
                let deadline = Instant::now() + Duration::from_secs(5);
                let (sent, received) =
                    tokio::join!(client.send(&payload, deadline), server.receive(deadline));
                sent.expect("opaque send without CER/CEA");
                let received = received.expect("opaque receive without Diameter decoding");
                assert_eq!(received.as_bytes(), payload);
                assert_eq!(format!("{received:#?}"), "ApplicationMessage([redacted])");
                assert_eq!(received.into_bytes().len(), size);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            let (sent, received) =
                tokio::join!(server.send(b"reverse", deadline), client.receive(deadline));
            sent.expect("reverse send");
            assert_eq!(received.expect("reverse receive").as_bytes(), b"reverse");
            let records = log.records();
            assert!(records.iter().all(|record| record.ppid == protocol.ppid()));
            assert!(records
                .iter()
                .filter(|record| record.record_header.is_some_and(|h| h[0] == 23))
                .all(|record| record.auth_key_id == 1));
            let (closed, peer_closed) =
                tokio::join!(client.close(deadline), server.receive(deadline));
            closed.expect("reciprocal close");
            assert_eq!(peer_closed.err(), Some(Error::PeerClosed));
        }
    }
}

#[test]
fn generic_policy_bounds_and_diagnostics_are_value_free() {
    for invalid in [0, MAX_DTLS_SCTP_MESSAGE_BYTES + 1, usize::MAX] {
        assert_eq!(
            Policy::ordered_stream_zero(PayloadProtocol::Ngap, invalid).err(),
            Some(Error::PolicyRejected)
        );
    }
    for size in [1, MAX_DTLS_SCTP_MESSAGE_BYTES] {
        let policy =
            Policy::ordered_stream_zero(PayloadProtocol::Ngap, size).expect("inclusive limit");
        assert_eq!(policy.maximum_plaintext_bytes(), size);
        assert_eq!(
            policy.with_allowed_ciphers(&[]).err(),
            Some(Error::PolicyRejected)
        );
        assert_eq!(
            policy.with_maximum_connection_age(Duration::ZERO).err(),
            Some(Error::PolicyRejected)
        );
        assert_eq!(
            policy.with_maximum_connection_age(Duration::MAX).err(),
            Some(Error::PolicyRejected)
        );
        assert_eq!(format!("{policy:#?}"), "Policy([redacted])");
    }
    assert_eq!(format!("{:?}", peer(SERVER_ID)), "ExpectedPeer([redacted])");
    assert_eq!(PayloadProtocol::Ngap.ppid().to_be_bytes(), [0, 0, 0, 66]);
    assert_eq!(
        PayloadProtocol::Diameter.ppid().to_be_bytes(),
        [0, 0, 0, 47]
    );
}

#[tokio::test]
async fn generic_profile_mismatch_cannot_start_a_handshake() {
    let material = dtls_material();
    let connector = Connector::new(
        material.client_controller,
        peer(SERVER_ID),
        generic_policy(PayloadProtocol::Ngap),
    )
    .expect("connector");
    let (client, server, log) = in_memory_sctp_link(64);
    let result = connector
        .connect(
            Transport::in_memory(client, PayloadProtocol::Diameter),
            Instant::now() + Duration::from_secs(5),
        )
        .await;
    assert_eq!(result.err(), Some(Error::PolicyRejected));
    assert!(log.records().is_empty());
    assert_eq!(
        server.injector().send_raw_message(66, Bytes::new()).await,
        Err(DiameterTlsError::Transport)
    );
}

#[tokio::test]
async fn generic_wrong_peer_identity_fails_in_each_endpoint_role() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    for wrong_client in [false, true] {
        let connector = Connector::new(
            material.client_controller.clone(),
            peer(if wrong_client {
                SERVER_ID
            } else {
                OTHER_SERVER_ID
            }),
            policy,
        )
        .expect("connector");
        let acceptor = Acceptor::new(
            material.server_controller.clone(),
            peer(if wrong_client {
                OTHER_CLIENT_ID
            } else {
                CLIENT_ID
            }),
            policy,
        )
        .expect("acceptor");
        let (client, server, _log) = in_memory_sctp_link(64);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::in_memory(client, PayloadProtocol::Ngap),
                deadline
            ),
            acceptor.accept(
                Transport::in_memory(server, PayloadProtocol::Ngap),
                deadline
            )
        );
        if wrong_client {
            assert_eq!(server.err(), Some(Error::PeerIdentityMismatch));
            assert!(client.is_err());
        } else {
            assert_eq!(client.err(), Some(Error::PeerIdentityMismatch));
            assert!(server.is_err());
        }
    }
}

#[tokio::test]
async fn generic_untrusted_certificate_fails_closed() {
    let material = dtls_material();
    let foreign = test_ca();
    let (_source, rx) = watch::channel(Some(identity_state_with_trust(
        SERVER_ID,
        &foreign,
        vec![foreign.der().clone(), material._ca.der().clone()],
    )));
    let policy = generic_policy(PayloadProtocol::Ngap);
    let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
        .expect("connector");
    let acceptor = Acceptor::new(material_controller(&rx, SERVER_ID), peer(CLIENT_ID), policy)
        .expect("acceptor");
    let (client, server, _log) = in_memory_sctp_link(64);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (client, server) = tokio::join!(
        connector.connect(
            Transport::in_memory(client, PayloadProtocol::Ngap),
            deadline
        ),
        acceptor.accept(
            Transport::in_memory(server, PayloadProtocol::Ngap),
            deadline
        )
    );
    assert_eq!(client.err(), Some(Error::Authentication));
    assert!(server.is_err());
}

#[tokio::test]
async fn generic_foreign_and_plaintext_ppids_fail_before_and_after_handshake() {
    for ppid in [0, 46, 47, 60, u32::MAX] {
        let material = dtls_material();
        let policy = generic_policy(PayloadProtocol::Ngap);
        let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
            .expect("acceptor");
        let (client, server, log) = in_memory_sctp_link(64);
        client
            .injector()
            .send_raw_message(ppid, Bytes::from_static(b"synthetic-cleartext"))
            .await
            .expect("inject before handshake");
        assert_eq!(
            acceptor
                .accept(
                    Transport::in_memory(server, PayloadProtocol::Ngap),
                    Instant::now() + Duration::from_secs(5)
                )
                .await
                .err(),
            Some(Error::CleartextRejected)
        );
        assert_eq!(log.records().len(), 1, "no protected output manufactured");

        let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
            .expect("connector");
        let (client, server, _log) = in_memory_sctp_link(64);
        let injector = client.injector();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (client, server) = tokio::join!(
            connector.connect(
                Transport::in_memory(client, PayloadProtocol::Ngap),
                deadline
            ),
            acceptor.accept(
                Transport::in_memory(server, PayloadProtocol::Ngap),
                deadline
            )
        );
        let _client = client.expect("authenticated client");
        let mut server = server.expect("authenticated server");
        injector
            .send_raw_message(ppid, Bytes::from_static(b"synthetic-cleartext"))
            .await
            .expect("inject after handshake");
        assert_eq!(
            server.receive(deadline).await.err(),
            Some(Error::CleartextRejected)
        );
        assert_eq!(server.readback().err(), Some(Error::ConnectionClosed));
    }
}

#[tokio::test]
async fn generic_cancelling_unpolled_and_blocked_handshakes_closes_carrier() {
    let material = dtls_material();
    let connector = Connector::new(
        material.client_controller.clone(),
        peer(SERVER_ID),
        generic_policy(PayloadProtocol::Ngap),
    )
    .expect("connector");
    for poll_once in [false, true] {
        let (client, server, log) = in_memory_sctp_link(64);
        log.set_dtls_send_blocked(true, true);
        let mut future = Box::pin(connector.connect(
            Transport::in_memory(client, PayloadProtocol::Ngap),
            Instant::now() + Duration::from_secs(30),
        ));
        if poll_once {
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await
            );
        }
        drop(future);
        assert_eq!(
            server.injector().send_raw_message(66, Bytes::new()).await,
            Err(DiameterTlsError::Transport)
        );
        assert!(log.records().is_empty());
    }
}

#[tokio::test]
async fn generic_handshake_budget_and_blocked_send_obey_one_deadline() {
    let material = dtls_material();
    let connector = Connector::new(
        material.client_controller.clone(),
        peer(SERVER_ID),
        generic_policy(PayloadProtocol::Ngap),
    )
    .expect("connector");
    for saturated in [false, true] {
        let mut permits = Vec::new();
        if saturated {
            for _ in 0..opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES {
                permits.push(
                    material
                        .client_controller
                        .begin_external_handshake()
                        .await
                        .expect("saturate budget"),
                );
            }
        }
        let (client, server, log) = in_memory_sctp_link(64);
        if !saturated {
            log.set_dtls_send_blocked(true, true);
        }
        assert_eq!(
            connector
                .connect(
                    Transport::in_memory(client, PayloadProtocol::Ngap),
                    Instant::now() + Duration::from_millis(25)
                )
                .await
                .err(),
            Some(Error::DeadlineExceeded)
        );
        assert_eq!(
            server.injector().send_raw_message(66, Bytes::new()).await,
            Err(DiameterTlsError::Transport)
        );
        assert!(log.records().is_empty());
    }
}

#[tokio::test]
async fn generic_cancelling_established_send_receive_and_close_is_terminal() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    for operation in 0..3 {
        let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        match operation {
            0 => {
                log.set_dtls_send_blocked(true, true);
                let mut future = Box::pin(client.send(b"opaque", deadline));
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending()))
                        .await
                );
                drop(future);
                assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
            }
            1 => {
                let mut future = Box::pin(client.receive(deadline));
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending()))
                        .await
                );
                drop(future);
                assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
            }
            _ => {
                log.set_dtls_send_blocked(true, true);
                let mut future = Box::pin(client.close(deadline));
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending()))
                        .await
                );
                drop(future);
            }
        }
        assert_eq!(
            server.receive(deadline).await.err(),
            Some(Error::ConnectionClosed)
        );
    }
}

#[tokio::test]
async fn generic_plaintext_limits_apply_independently_in_both_directions() {
    let material = dtls_material();
    let small = Policy::ordered_stream_zero(PayloadProtocol::Ngap, 1).expect("small policy");
    let large = generic_policy(PayloadProtocol::Ngap);
    let (mut client, mut server, log) = generic_pair(&material, small, large).await;
    let count = log.records().len();
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(client.send(b"xx", deadline).await, Err(Error::MessageLimit));
    assert_eq!(
        log.records().len(),
        count,
        "oversize local plaintext never reaches wire"
    );
    assert_eq!(
        server.receive(deadline).await.err(),
        Some(Error::ConnectionClosed)
    );
    let (mut client, mut server, _) = generic_pair(&material, large, small).await;
    let (sent, received) = tokio::join!(client.send(b"xx", deadline), server.receive(deadline));
    sent.expect("sender's admitted budget");
    assert_eq!(received.err(), Some(Error::MessageLimit));
    assert_eq!(server.readback().err(), Some(Error::ConnectionClosed));
}

#[tokio::test]
async fn generic_rotation_and_explicit_withdrawal_retire_exact_admitted_epoch() {
    for withdraw in [false, true] {
        let material = dtls_material();
        let policy = generic_policy(PayloadProtocol::Ngap);
        let (client, mut server, _) = generic_pair(&material, policy, policy).await;
        let admitted = client
            .readback()
            .expect("admitted evidence")
            .material_epoch();
        material
            .client_source
            .send(if withdraw {
                None
            } else {
                Some(identity_state(CLIENT_ID, &material._ca))
            })
            .expect("publish material change");
        let deadline = Instant::now() + Duration::from_secs(5);
        tokio::time::timeout_at(deadline, async {
            loop {
                if client.readback().err() == Some(Error::Retired) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded retirement");
        if withdraw {
            assert_eq!(
                material.client_controller.status().reason(),
                Some(opc_tls::TlsMaterialReloadReason::MaterialUnavailable)
            );
        } else {
            assert_ne!(material.client_controller.status().epoch(), admitted);
        }
        assert_eq!(
            server.receive(deadline).await.err(),
            Some(Error::ConnectionClosed)
        );
    }
}

#[tokio::test]
async fn generic_expired_deadline_never_emits_or_delivers_application_data() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    for receive in [false, true] {
        let (mut client, mut server, log) = generic_pair(&material, policy, policy).await;
        if receive {
            server
                .send(b"queued", Instant::now() + Duration::from_secs(5))
                .await
                .expect("queue record");
        }
        let count = log.records().len();
        let error = if receive {
            client.receive(Instant::now()).await.err()
        } else {
            client.send(b"late", Instant::now()).await.err()
        };
        assert_eq!(error, Some(Error::DeadlineExceeded));
        assert_eq!(log.records().len(), count);
        assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
    }
}

#[tokio::test]
async fn generic_close_rejects_undelivered_records_and_unresponsive_peer() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let (client, mut server, _) = generic_pair(&material, policy, policy).await;
    server
        .send(b"pending", Instant::now() + Duration::from_secs(5))
        .await
        .expect("pending record");
    assert_eq!(
        client.close(Instant::now() + Duration::from_secs(5)).await,
        Err(Error::Transport)
    );
    let (client, _server, _) = generic_pair(&material, policy, policy).await;
    assert_eq!(
        client
            .close(Instant::now() + Duration::from_millis(25))
            .await,
        Err(Error::DeadlineExceeded)
    );
}

#[tokio::test]
async fn generic_raw_peer_validity_failures_use_shared_certificate_verifier() {
    let material = dtls_material();
    let now = time::OffsetDateTime::now_utc();
    for (before, after) in [
        (
            now - time::Duration::hours(2),
            now - time::Duration::hours(1),
        ),
        (
            now + time::Duration::hours(1),
            now + time::Duration::hours(2),
        ),
    ] {
        let certificate = raw_certificate_with_validity(CLIENT_ID, &material._ca, before, after);
        let acceptor = Acceptor::new(
            material.server_controller.clone(),
            peer(CLIENT_ID),
            generic_policy(PayloadProtocol::Diameter),
        )
        .expect("acceptor");
        let (client, server, _) = in_memory_sctp_link(64);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut engine =
            dimpl::Dtls::new_12(raw_rfc6083_config(), certificate, std::time::Instant::now());
        engine.set_active(true);
        let (result, _) = tokio::join!(
            acceptor.accept(
                Transport::in_memory(server, PayloadProtocol::Diameter),
                deadline
            ),
            drive_raw_engine(engine, client, deadline)
        );
        assert_eq!(result.err(), Some(Error::Authentication));
    }
}

#[cfg(target_os = "linux")]
async fn kernel_associations(
    authenticated: bool,
    receive_budget: usize,
    deadline: Instant,
) -> (opc_sctp::SctpAssociation, opc_sctp::SctpAssociation) {
    let auth = opc_sctp::SctpAuthenticationConfig::data();
    let mut server_config =
        opc_sctp::SctpEndpointConfig::one_to_one("127.0.0.1:0".parse().expect("loopback"));
    server_config.max_message_bytes = receive_budget;
    let endpoint = if authenticated {
        opc_sctp::SctpEndpoint::bind_with_authentication(server_config, auth)
    } else {
        opc_sctp::SctpEndpoint::bind(server_config)
    }
    .expect("SCTP listener");
    let mut client_config =
        opc_sctp::SctpConnectConfig::new(endpoint.local_addresses().expect("listener address")[0]);
    client_config.max_message_bytes = receive_budget;
    let client = tokio::time::timeout_at(deadline, async {
        if authenticated {
            opc_sctp::SctpAssociation::connect_with_authentication(client_config, auth).await
        } else {
            opc_sctp::SctpAssociation::connect(client_config).await
        }
    })
    .await
    .expect("connect bound")
    .expect("SCTP connect");
    let server = tokio::time::timeout_at(deadline, endpoint.accept())
        .await
        .expect("accept bound")
        .expect("SCTP accept");
    (client, server)
}

#[cfg(target_os = "linux")]
async fn kernel_generic_pair(
    material: &TestMaterial,
    deadline: Instant,
) -> (Connection, Connection) {
    let (client, server) =
        kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline).await;
    let client = Transport::from_sctp(client, PayloadProtocol::Ngap, 64).expect("generic carrier");
    let server = Transport::from_sctp(server, PayloadProtocol::Ngap, 64).expect("generic carrier");
    let policy = generic_policy(PayloadProtocol::Ngap);
    let connector = Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
        .expect("connector");
    let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
        .expect("acceptor");
    let (client, server) = tokio::join!(
        connector.connect(client, deadline),
        acceptor.accept(server, deadline)
    );
    (
        client.expect("mutual connector"),
        server.expect("mutual acceptor"),
    )
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_ppid66_handshake_opaque_delivery_and_reciprocal_close() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let material = dtls_material();
    let (mut client, mut server) = kernel_generic_pair(&material, deadline).await;
    assert_eq!(
        client.readback().expect("readback").payload_protocol(),
        PayloadProtocol::Ngap
    );
    let (sent, received) = tokio::join!(
        client.send(b"synthetic-opaque-application", deadline),
        server.receive(deadline)
    );
    sent.expect("protected send");
    assert_eq!(
        received.expect("protected receive").as_bytes(),
        b"synthetic-opaque-application"
    );
    let (closed, peer) = tokio::join!(client.close(deadline), server.receive(deadline));
    closed.expect("reciprocal close");
    assert_eq!(peer.err(), Some(Error::PeerClosed));
}

#[tokio::test(start_paused = true)]
async fn generic_age_bound_retires_without_new_peer_traffic() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap)
        .with_maximum_connection_age(Duration::from_secs(1))
        .expect("age policy");
    let (client, server, _) = generic_pair(&material, policy, policy).await;
    assert!(client.readback().is_ok());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(client.readback().err(), Some(Error::Retired));
    assert_eq!(server.readback().err(), Some(Error::Retired));
}

#[tokio::test]
async fn generic_missing_material_never_publishes_protection() {
    let (_source, rx) = watch::channel(None::<IdentityState>);
    let controller = material_controller(&rx, CLIENT_ID);
    let connector = Connector::new(
        controller,
        peer(SERVER_ID),
        generic_policy(PayloadProtocol::Ngap),
    )
    .expect("policy construction");
    let (client, server, log) = in_memory_sctp_link(64);
    assert_eq!(
        connector
            .connect(
                Transport::in_memory(client, PayloadProtocol::Ngap),
                Instant::now() + Duration::from_secs(5)
            )
            .await
            .err(),
        Some(Error::MaterialNotAdmitted)
    );
    assert!(log.records().is_empty());
    assert_eq!(
        server.injector().send_raw_message(66, Bytes::new()).await,
        Err(DiameterTlsError::Transport)
    );
}

#[tokio::test]
async fn generic_one_way_server_never_publishes_mutual_protection() {
    let material = dtls_material();
    let connector = Connector::new(
        material.client_controller.clone(),
        peer(SERVER_ID),
        generic_policy(PayloadProtocol::Diameter),
    )
    .expect("connector");
    let config = std::sync::Arc::new(
        dimpl::Config::builder()
            .with_crypto_provider(dimpl::crypto::rust_crypto::default_provider())
            .require_client_certificate(false)
            .dtls13_cipher_suites(&[])
            .rfc6083_sctp()
            .build()
            .expect("raw non-mutual server"),
    );
    let mut engine = dimpl::Dtls::new_12(
        config,
        raw_certificate(SERVER_ID, &material._ca),
        std::time::Instant::now(),
    );
    engine.set_active(false);
    let (client, server, _) = in_memory_sctp_link(64);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (client, raw) = tokio::join!(
        connector.connect(
            Transport::in_memory(client, PayloadProtocol::Diameter),
            deadline
        ),
        drive_raw_engine(engine, server, deadline)
    );
    assert_eq!(client.err(), Some(Error::Handshake));
    assert!(raw.is_err());
}

fn reviewed_wire(name: &str) -> Bytes {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../opc-n3iwf-fixtures/fixtures/n2-dtls/wire");
    std::fs::read_to_string(root.join(format!("{name}.hex")))
        .expect("reviewed synthetic wire")
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).expect("hex octet"))
        .collect::<Vec<_>>()
        .into()
}

#[tokio::test]
async fn generic_reviewed_headers_cannot_manufacture_a_protected_connection() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
        .expect("acceptor");
    let ppid = reviewed_wire("positive-ppid66");
    assert_eq!(ppid.as_ref(), PayloadProtocol::Ngap.ppid().to_be_bytes());
    let foreign_ppid = reviewed_wire("unknown-ppid60");
    let foreign_ppid =
        u32::from_be_bytes(foreign_ppid.as_ref().try_into().expect("independent PPID"));
    for (ppid, record, expected) in [
        (
            foreign_ppid,
            reviewed_wire("positive-handshake-header"),
            Error::CleartextRejected,
        ),
        (
            66,
            reviewed_wire("malformed-tls-version"),
            Error::DeadlineExceeded,
        ),
        (66, reviewed_wire("truncated-record"), Error::Transport),
        (
            66,
            reviewed_wire("bounded-record-overflow"),
            Error::Transport,
        ),
    ] {
        let (client, server, _) = in_memory_sctp_link(64);
        client
            .injector()
            .send_raw_message(ppid, record)
            .await
            .expect("inject independent record");
        let result = acceptor
            .accept(
                Transport::in_memory(server, PayloadProtocol::Ngap),
                Instant::now() + Duration::from_millis(100),
            )
            .await;
        assert_eq!(result.err(), Some(expected));
    }
}

#[tokio::test]
async fn generic_nonzero_unordered_and_truncated_metadata_fail_closed() {
    use crate::dtls::{SctpDeliveryOrder, SctpUserMessage};
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let acceptor = Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy)
        .expect("acceptor");
    for established in [false, true] {
        for metadata_case in 0..6 {
            let (client_io, server_io, _) = in_memory_sctp_link(64);
            let injector = client_io.injector();
            let payload = reviewed_wire("positive-handshake-header");
            let message = SctpUserMessage::new(
                payload,
                66,
                match metadata_case {
                    0 => 1,
                    1 => u16::MAX,
                    _ => 0,
                },
                if metadata_case == 2 {
                    SctpDeliveryOrder::Unordered
                } else {
                    SctpDeliveryOrder::Ordered
                },
                metadata_case == 3,
                metadata_case == 4,
                metadata_case == 5,
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            if established {
                let connector =
                    Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy)
                        .expect("connector");
                let (client, server) = tokio::join!(
                    connector.connect(
                        Transport::in_memory(client_io, PayloadProtocol::Ngap),
                        deadline
                    ),
                    acceptor.accept(
                        Transport::in_memory(server_io, PayloadProtocol::Ngap),
                        deadline
                    )
                );
                let _client = client.expect("client authenticated");
                let mut server = server.expect("server authenticated");
                injector
                    .send_message(message)
                    .await
                    .expect("inject metadata");
                assert_eq!(server.receive(deadline).await.err(), Some(Error::Transport));
                assert_eq!(server.readback().err(), Some(Error::ConnectionClosed));
            } else {
                injector
                    .send_message(message)
                    .await
                    .expect("inject metadata");
                assert_eq!(
                    acceptor
                        .accept(
                            Transport::in_memory(server_io, PayloadProtocol::Ngap),
                            deadline
                        )
                        .await
                        .err(),
                    Some(Error::Transport)
                );
            }
        }
    }
}

#[tokio::test]
async fn generic_terminal_carrier_cannot_retain_active_readback_or_deliver_queued_plaintext() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let (mut client, mut server, _) = generic_pair(&material, policy, policy).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    server
        .send(b"queued-before-terminal", deadline)
        .await
        .expect("queue application");
    drop(server);
    assert_eq!(client.readback().err(), Some(Error::ConnectionClosed));
    assert_eq!(
        client.receive(deadline).await.err(),
        Some(Error::ConnectionClosed)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_terminal_carrier_revokes_readback_before_queued_delivery() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let material = dtls_material();
    let (mut client, mut server) = kernel_generic_pair(&material, deadline).await;
    server
        .send(b"synthetic-queued-before-abort", deadline)
        .await
        .expect("queue record");
    drop(server);
    // The independent receive task must observe peer termination even while
    // the application never calls receive. This tests abort, not SCTP restart
    // or multihoming path recovery.
    tokio::time::timeout_at(deadline, async {
        loop {
            match client.readback() {
                Ok(_) => tokio::task::yield_now().await,
                Err(error) => {
                    assert_eq!(error, Error::ConnectionClosed);
                    break;
                }
            }
        }
    })
    .await
    .expect("terminal signal bound");
    assert_eq!(
        client.receive(deadline).await.err(),
        Some(Error::ConnectionClosed)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires isolated Linux SCTP-AUTH and sender-dry support"]
async fn generic_kernel_constructor_rejects_unprotected_or_nonpristine_carriers() {
    for scenario in 0..5 {
        let deadline = Instant::now() + Duration::from_secs(15);
        let budget = crate::MAX_DTLS_SCTP_RECORD_BYTES - usize::from(scenario == 1);
        let (client, server) = kernel_associations(scenario != 0, budget, deadline).await;
        if scenario == 2 {
            let key = opc_sctp::SctpAuthKey::for_rfc6083(
                opc_sctp::SctpAuthKeyId::new(7).expect("nonzero id"),
                vec![0x5a; 64],
            )
            .expect("synthetic key");
            client
                .install_auth_key(key)
                .await
                .expect("prior auth mutation");
        }
        if scenario == 3 {
            client
                .send(opc_sctp::OutboundMessage::ordered(
                    Bytes::from_static(b"synthetic-cleartext-before-sealing"),
                    0,
                    opc_sctp::PayloadProtocolIdentifier::new(60),
                ))
                .await
                .expect("prior DATA mutation");
        }
        let capacity = if scenario == 4 {
            crate::MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES - 1
        } else {
            64
        };
        assert_eq!(
            Transport::from_sctp(client, PayloadProtocol::Ngap, capacity).err(),
            Some(Error::PolicyRejected),
            "public generic constructor must reject scenario {scenario}",
        );
        server.abort_handle().abort();
    }
}

fn independent_der(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "complete independent DER octets");
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("independent hex octet")
        })
        .collect()
}

#[tokio::test]
async fn generic_independent_certificate_vectors_enforce_signature_identity_time_trust_and_role() {
    let vectors = include_str!("../../tests/fixtures/rfc6083/certificates.tsv");
    let rows: Vec<_> = vectors
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), 8);
    for protocol in [PayloadProtocol::Ngap, PayloadProtocol::Diameter] {
        for row in &rows {
            let columns: Vec<_> = row.split('\t').collect();
            assert_eq!(columns.len(), 6);
            let local_ca = test_ca();
            let state = identity_state_with_trust(
                SERVER_ID,
                &local_ca,
                vec![
                    local_ca.der().clone(),
                    CertificateDer::from(independent_der(columns[5])),
                ],
            );
            let (_source, rx) = watch::channel(Some(state));
            let controller = material_controller(&rx, SERVER_ID);
            let acceptor = Acceptor::new(controller, peer(CLIENT_ID), generic_policy(protocol))
                .expect("independent-vector acceptor");
            let certificate = dimpl::DtlsCertificate {
                certificate: independent_der(columns[2]),
                private_key: independent_der(columns[3]),
                intermediates: vec![independent_der(columns[4])],
            };
            let mut engine =
                dimpl::Dtls::new_12(raw_rfc6083_config(), certificate, std::time::Instant::now());
            engine.set_active(true);
            let (client, server, log) = in_memory_sctp_link(64);
            let deadline = Instant::now() + Duration::from_secs(5);
            let raw = tokio::spawn(drive_raw_engine_with_ppid(
                engine,
                client,
                deadline,
                protocol.ppid(),
            ));
            let connection = acceptor
                .accept(Transport::in_memory(server, protocol), deadline)
                .await;
            match columns[1] {
                "admit" => {
                    let connection =
                        connection.expect("independently signed valid client admitted");
                    assert_eq!(
                        connection
                            .readback()
                            .expect("active readback")
                            .expected_peer(),
                        &peer(CLIENT_ID)
                    );
                    drop(connection);
                }
                "identity" => assert_eq!(
                    connection.err(),
                    Some(Error::PeerIdentityMismatch),
                    "{}",
                    columns[0]
                ),
                "authentication" => assert_eq!(
                    connection.err(),
                    Some(Error::Authentication),
                    "{}",
                    columns[0]
                ),
                _ => panic!("unknown independent expectation"),
            }
            assert!(raw.await.expect("raw client joined").is_err());
            assert!(log
                .records()
                .iter()
                .all(|record| record.ppid == protocol.ppid()));
        }
    }
}

#[tokio::test]
async fn generic_disjoint_cipher_policies_never_publish_protection() {
    let material = dtls_material();
    let policy = generic_policy(PayloadProtocol::Ngap);
    let ciphers: Vec<_> = DtlsSctpPolicy::default().allowed_ciphers().collect();
    let connector = Connector::new(
        material.client_controller.clone(),
        peer(SERVER_ID),
        policy
            .with_allowed_ciphers(&ciphers[..1])
            .expect("client policy"),
    )
    .expect("connector");
    let acceptor = Acceptor::new(
        material.server_controller.clone(),
        peer(CLIENT_ID),
        policy
            .with_allowed_ciphers(&ciphers[1..])
            .expect("server policy"),
    )
    .expect("acceptor");
    let (client, server, log) = in_memory_sctp_link(64);
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
    assert!(client.is_err());
    assert_eq!(server.err(), Some(Error::Handshake));
    assert!(log
        .records()
        .iter()
        .all(|record| record.record_header.is_none_or(|header| header[0] != 23)));
}
