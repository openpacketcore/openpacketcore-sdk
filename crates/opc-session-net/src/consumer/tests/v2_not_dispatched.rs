use super::*;

#[tokio::test]
async fn v2_complete_pre_dispatch_refusal_is_not_transmitted_without_transport_replay() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let client_identity = material_spiffe("v2-not-dispatched-client");
    let server_identity = material_spiffe("v2-not-dispatched-server");
    let material = RotatableClientMaterial::new(client_identity.as_str());
    let calls = Arc::new(AtomicUsize::new(0));
    let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
        scope(),
        [client_identity],
        std::iter::empty(),
    )
    .expect("authorizer");
    let (server, address) = SessionQuorumConsumerServer::new(
        Arc::new(CountingV2RejectingTestConsumer {
            calls: Arc::clone(&calls),
        }),
        material.trusted_server_config(server_identity.as_str()),
        authorizer,
    )
    .listen("127.0.0.1:0".parse().expect("loopback address"))
    .await
    .expect("listen");
    let stateless = StatelessSessionConsumerClient::new_unattested_for_test(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        server_identity,
        scope(),
        material.config(),
    );
    let persistent = PersistentSessionConsumerClient::from_stateless(stateless.clone())
        .expect("persistent client");
    for (index, request) in [
        v2_effectful_request(0x61).await,
        v2_effectful_batch_request(&[0x62, 0x63]).await,
    ]
    .into_iter()
    .enumerate()
    {
        let expected = Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        });
        assert_eq!(
            stateless.execute_v2(&request).await,
            expected,
            "the complete matching refusal proves no dispatch"
        );
        assert_eq!(
            persistent.execute_v2(&request).await,
            expected,
            "the pooled call preserves the same proof"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            (index + 1) * 2,
            "a received refusal does not re-enter the transport setup retry loop"
        );
    }
    assert_eq!(
        persistent
            .execute_v2(&SessionConsumerV2Request::new(
                scope(),
                SessionConsumerV2Operation::FencedTransitionV2Capability,
            ))
            .await,
        Ok(SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::Unavailable
        )),
        "read-only rejections preserve their existing response"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let _ = persistent.shutdown().await;
    server.abort_and_wait().await;
}

#[derive(Clone, Copy, Debug)]
enum UnprovedRefusal {
    WrongCorrelation,
    WrongNonce,
    WrongCommitment,
    Partial,
    Disconnected,
    Rejected(SessionConsumerRejection),
    MayHaveProposed,
}

async fn assert_unproved_v2_refusal_stays_unknown(pooled: bool, refusal: UnprovedRefusal) {
    let client_identity = material_spiffe("v2-unproved-refusal-client");
    let server_identity = material_spiffe("v2-unproved-refusal-server");
    let material = RotatableClientMaterial::new(client_identity.as_str());
    let server_material = material.trusted_server_config(server_identity.as_str());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let address = listener.local_addr().expect("address");
    let request = v2_effectful_request(0x69).await;
    let SessionConsumerV2Operation::FencedTransitionV2 {
        request: transition,
    } = request.operation()
    else {
        panic!("effectful request");
    };
    let request_id = transition.request_id();
    let expected_request = request.clone();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let handshake = server_material.begin_handshake().expect("handshake");
        let acceptor = tokio_rustls::TlsAcceptor::from(super::super::consumer_server_tls_config(
            handshake.rustls_config(),
        ));
        let mut tls = acceptor.accept(tcp).await.expect("TLS");
        handshake.admit().expect("admit");
        assert!(matches!(
            super::super::read_consumer_frame::<_, ConsumerV2WireRequest>(
                &mut tls,
                MAX_NEGOTIATED_FRAME_SIZE,
            )
            .await
            .expect("Hello"),
            ConsumerV2WireRequest::Hello(_)
        ));
        super::super::write_frame_bounded_until(
            &mut tls,
            &v2_hello_ack(MAX_NEGOTIATED_FRAME_SIZE),
            MAX_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("HelloAck");
        let ConsumerV2WireRequest::Call(ConsumerV2Call {
            mut correlation,
            mut attempt_nonce,
            mut request_commitment,
            request,
        }) = super::super::read_consumer_frame::<_, ConsumerV2WireRequest>(
            &mut tls,
            MAX_NEGOTIATED_FRAME_SIZE,
        )
        .await
        .expect("complete Call")
        else {
            panic!("expected a Call");
        };
        assert_eq!(*request, expected_request);
        let response = match refusal {
            UnprovedRefusal::Disconnected => return,
            UnprovedRefusal::WrongCorrelation => {
                correlation = NonZeroU32::new(2).expect("different correlation");
                SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
            }
            UnprovedRefusal::WrongNonce => {
                attempt_nonce[0] ^= 1;
                SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
            }
            UnprovedRefusal::WrongCommitment => {
                request_commitment[0] ^= 1;
                SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
            }
            UnprovedRefusal::Rejected(rejection) => SessionConsumerV2Response::Rejected(rejection),
            UnprovedRefusal::MayHaveProposed => SessionConsumerV2Response::FencedTransitionV2(Err(
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::Unavailable,
                ),
            )),
            UnprovedRefusal::Partial => {
                SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
            }
        };
        let response = ConsumerV2WireResponse::Response(ConsumerV2CallResponse {
            correlation,
            attempt_nonce,
            request_commitment,
            response: Box::new(response),
        });
        if matches!(refusal, UnprovedRefusal::Partial) {
            let body = serde_json::to_vec(&response).expect("encoded refusal");
            let length = u32::try_from(body.len()).expect("bounded frame");
            tls.write_all(&length.to_be_bytes()).await.expect("length");
            tls.write_all(&body[..body.len() / 2])
                .await
                .expect("partial body");
            tls.flush().await.expect("flush partial refusal");
        } else {
            super::super::write_frame_bounded_until(
                &mut tls,
                &response,
                MAX_NEGOTIATED_FRAME_SIZE,
                tokio::time::Instant::now() + Duration::from_secs(2),
            )
            .await
            .expect("write response");
        }
    });
    let stateless = StatelessSessionConsumerClient::new_unattested_for_test(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        server_identity,
        scope(),
        material.config(),
    )
    .with_operation_timeout(Duration::from_secs(2));
    let result = if pooled {
        let persistent =
            PersistentSessionConsumerClient::from_stateless(stateless).expect("persistent client");
        let result = persistent.execute_v2(&request).await;
        let _ = persistent.shutdown().await;
        result
    } else {
        stateless.execute_v2(&request).await
    };
    peer.await.expect("join peer");
    assert_eq!(
        result,
        Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }),
        "{refusal:?}, pooled={pooled}: an unproved refusal retains the exact recovery identity"
    );
}

#[tokio::test]
async fn v2_ambiguous_or_uncorrelated_refusals_remain_unknown() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for pooled in [false, true] {
        for refusal in [
            UnprovedRefusal::WrongCorrelation,
            UnprovedRefusal::WrongNonce,
            UnprovedRefusal::WrongCommitment,
            UnprovedRefusal::Partial,
            UnprovedRefusal::Disconnected,
            UnprovedRefusal::Rejected(SessionConsumerRejection::ScopeMismatch),
            UnprovedRefusal::Rejected(SessionConsumerRejection::TopologyMismatch),
            UnprovedRefusal::Rejected(SessionConsumerRejection::MalformedRequest),
            UnprovedRefusal::Rejected(SessionConsumerRejection::Unauthorized),
            UnprovedRefusal::MayHaveProposed,
        ] {
            assert_unproved_v2_refusal_stays_unknown(pooled, refusal).await;
        }
    }
}
