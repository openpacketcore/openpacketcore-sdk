//! RFC 6733 section 2.1: malformed protected frames require SCTP ABORT.
use super::*;
use crate::rfc6083::{Connector, ExpectedPeer, PayloadProtocol, Policy, Transport};

#[tokio::test]
#[ignore = "requires Linux kernel SCTP-AUTH and sender-dry support"]
async fn kernel_malformed_diameter_frames_abort_sequential_and_runtime_associations() {
    let material = dtls_material();
    let valid = encoded_bytes(&application_request(), DiameterFrameLimits::default())
        .expect("application wire");
    let mut mismatched = valid.to_vec();
    mismatched.pop();
    let mut reserved_header = valid.to_vec();
    reserved_header[4] |= 1;
    for concurrent in [false, true] {
        for malformed in [b"bad".to_vec(), mismatched.clone(), reserved_header.clone()] {
            let deadline = Instant::now() + Duration::from_secs(15);
            let (client, server) =
                generic::kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline)
                    .await;
            let server_abort = server.abort_handle();
            let connector = Connector::new(
                material.client_controller.clone(),
                ExpectedPeer::spiffe(SpiffeId::new(SERVER_ID).expect("identity")),
                Policy::ordered_stream_zero(PayloadProtocol::Diameter, MAX_DTLS_SCTP_MESSAGE_BYTES)
                    .expect("generic policy"),
            )
            .expect("generic connector");
            let acceptor = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default());
            let (client, server) = tokio::join!(
                connector.connect(
                    Transport::from_sctp(client, PayloadProtocol::Diameter, 64)
                        .expect("client carrier"),
                    deadline
                ),
                acceptor.accept_direct(
                    Box::new(crate::KernelSctpMessageIo::new(server, 64).expect("server carrier"))
                        as Box<dyn SctpMessageIo>,
                    direct_session("server.example.test"),
                    deadline,
                ),
            );
            let mut client = client.expect("authenticated generic peer");
            let mut server = server.expect("authenticated Diameter peer");
            let cer = build_capabilities_exchange_request(
                &capabilities("client.example.test"),
                0x111,
                0x222,
                EncodeContext::default(),
            )
            .expect("CER");
            let cer = encoded_bytes(&cer, DiameterFrameLimits::default()).expect("CER wire");
            client.send(&cer, deadline).await.expect("send CER");
            assert_eq!(
                server
                    .receive_capabilities_request(deadline)
                    .await
                    .expect("receive CER"),
                capabilities("client.example.test")
            );
            let answer = CapabilitiesExchangeAnswer {
                result_code: RESULT_CODE_DIAMETER_SUCCESS,
                capabilities: capabilities("server.example.test"),
                diagnostics: AnswerDiagnostics::default(),
            };
            assert!(server
                .send_capabilities_answer(&answer, deadline)
                .await
                .expect("send CEA")
                .is_negotiated());
            client.receive(deadline).await.expect("receive CEA");
            client
                .send(&malformed, deadline)
                .await
                .expect("authenticated malformed plaintext");
            if concurrent {
                let capacity = NonZeroUsize::new(2).expect("capacity");
                let config = DiameterPeerRuntimeConfig::new(capacity, capacity, capacity, None)
                    .expect("runtime limits");
                let (_handle, mut incoming) = server
                    .into_peer_runtime(config)
                    .expect("runtime")
                    .into_parts();
                assert_eq!(
                    tokio::time::timeout_at(deadline, incoming.receive())
                        .await
                        .expect("bounded invalid receive")
                        .err(),
                    Some(crate::DiameterPeerRuntimeError::Transport(
                        DiameterTlsError::InvalidFrame
                    ))
                );
                assert!(
                    client.receive(deadline).await.is_err(),
                    "peer observes terminal carrier"
                );
            } else {
                assert_eq!(
                    server.receive_message(deadline).await.err(),
                    Some(DiameterTlsError::InvalidFrame)
                );
                assert!(server.protection_readiness().is_err());
                assert!(
                    client.receive(deadline).await.is_err(),
                    "peer observes terminal carrier"
                );
            }
            server_abort
                .abort_on_wire()
                .expect("idempotent after framing failure");
        }
    }

    // The cleartext CER/CEA prelude has the same abort obligation in both roles.
    for responder in [true, false] {
        for malformed in [b"bad".to_vec(), mismatched.clone(), reserved_header.clone()] {
            let deadline = Instant::now() + Duration::from_secs(15);
            let (peer, local) =
                generic::kernel_associations(true, crate::MAX_DTLS_SCTP_RECORD_BYTES, deadline)
                    .await;
            let local = crate::KernelSctpMessageIo::new(local, 64).expect("prelude carrier");
            let local = Box::new(local) as Box<dyn SctpMessageIo>;
            let error = if responder {
                let server = acceptor(&material, expected(CLIENT_ID), DtlsSctpPolicy::default())
                    .begin_inband(
                        local,
                        inband_capabilities("server.example.test"),
                        peer_policy(),
                    )
                    .unwrap();
                peer.send(opc_sctp::OutboundMessage::ordered(
                    Bytes::from(malformed),
                    0,
                    opc_sctp::DIAMETER_SCTP_PPID,
                ))
                .await
                .expect("malformed CER");
                server.receive_capabilities_request(deadline).await.err()
            } else {
                let client = connector(&material, expected(SERVER_ID), DtlsSctpPolicy::default())
                    .begin_inband(
                        local,
                        inband_capabilities("client.example.test"),
                        peer_policy(),
                    )
                    .unwrap()
                    .send_capabilities_request(0x1234, 0x5678, deadline)
                    .await
                    .unwrap();
                peer.send(opc_sctp::OutboundMessage::ordered(
                    Bytes::from(malformed),
                    0,
                    opc_sctp::DIAMETER_SCTP_PPID,
                ))
                .await
                .expect("malformed CEA");
                client
                    .receive_capabilities_answer_and_upgrade(deadline)
                    .await
                    .err()
            };
            assert_eq!(error, Some(DiameterTlsError::InvalidFrame));
            let event = tokio::time::timeout_at(deadline, async {
                loop {
                    let message = peer.recv().await.expect("peer observes prelude abort");
                    if matches!(message.event, Some(opc_sctp::SctpEvent::AssociationChange { state, .. }) if state != 0)
                        || matches!(message.event, Some(opc_sctp::SctpEvent::Shutdown { .. }))
                    {
                        break message.event;
                    }
                }
            })
            .await
            .expect("bounded prelude terminal notification");
            assert!(
                matches!(
                    event,
                    Some(opc_sctp::SctpEvent::AssociationChange { state: 1, .. })
                ),
                "malformed prelude must produce COMM_LOST: {event:?}"
            );
        }
    }
}
