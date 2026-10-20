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
