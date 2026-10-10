//! Actual mTLS calls use independent class pools and listener execution credits.
use super::*;
use opc_session_store::scope_scheduler::ScopeWorkClass;

#[derive(Debug)]
struct HeldMaintenance {
    entered: Semaphore,
    release: Semaphore,
}
#[async_trait]
impl SessionConsensusRpcHandler for HeldMaintenance {
    async fn handle(
        &self,
        _sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::InstallSnapshot {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[tokio::test]
async fn actual_mtls_control_progresses_with_both_maintenance_lanes_and_handlers_held() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let descriptors = (1..=2)
        .map(|i| {
            QuorumReplicaDescriptor::new(
                ReplicaId::new(format!("replica-{i}")).unwrap(),
                ReplicaEndpoint::new(format!("replica-{i}.invalid"), 7443).unwrap(),
                ReplicaTlsIdentity::new(format!(
                    "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/{i}"
                ))
                .unwrap(),
                ReplicaFailureDomain::new(format!("zone-{i}")).unwrap(),
                ReplicaBackingIdentity::new(format!("disk-{i}")).unwrap(),
            )
        })
        .collect();
    let manifest = Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("class-network").unwrap(),
            SessionConfigurationGeneration::new("1").unwrap(),
            SessionConfigurationEpoch::new(1).unwrap(),
            descriptors,
        )
        .unwrap(),
    );
    let server_binding = manifest
        .bind_local(ReplicaId::new("replica-2").unwrap())
        .unwrap();
    let binding = manifest
        .bind_local(ReplicaId::new("replica-1").unwrap())
        .unwrap()
        .bind_remote(ReplicaId::new("replica-2").unwrap())
        .unwrap();
    let material = crate::test_support::RotatableServerMaterial::new(
        "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/2",
    );
    let tls = material.trusted_client_config(
        "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/1",
    );
    let handler = Arc::new(HeldMaintenance {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let server = SessionConsensusServer::new(handler.clone(), material.config(), server_binding)
        .with_max_connections(2)
        .listen_classified([SocketAddr::from(([127, 0, 0, 1], 0)); 5])
        .await
        .unwrap();
    let addresses = server.addresses();
    let resolvers = std::array::from_fn(|index| {
        let address = addresses[index];
        Arc::new(
            move || -> futures_util::future::BoxFuture<'static, io::Result<SocketAddr>> {
                Box::pin(async move { Ok(address) })
            },
        ) as RemoteAddrResolver
    });
    let peer =
        RemoteSessionConsensusPeer::new(binding.clone(), tls.clone(), Some(Duration::from_secs(5)))
            .with_class_resolvers(resolvers);
    let request = |family| {
        SessionConsensusWireRequest::try_new(
            binding.consensus_identity(),
            binding.local_consensus_node_id(),
            family,
            vec![0xA5],
        )
        .unwrap()
    };
    let mut held = Vec::new();
    for _ in 0..2 {
        let peer = peer.clone();
        let request = request(SessionConsensusRpcFamily::InstallSnapshot);
        held.push(tokio::spawn(async move { peer.call(request).await }));
    }
    tokio::time::timeout(Duration::from_secs(2), handler.entered.acquire_many(2))
        .await
        .unwrap()
        .unwrap()
        .forget();
    // Fill the ordinary material-controller budgets at both ends. Reserved
    // transport classes must retain cold-handshake capacity on that same epoch.
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let mut handshake_holders = Vec::new();
    for _ in 0..opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES {
        let source = material.config();
        let entered = entered.clone();
        let release = release.clone();
        handshake_holders.push(tokio::spawn(async move {
            source
                .run_handshake(|_| {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.add_permits(1);
                        release.acquire().await.unwrap().forget();
                        Ok::<_, ()>(())
                    }
                })
                .await
                .unwrap();
        }));
    }
    for _ in 0..opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES {
        let source = tls.clone();
        let entered = entered.clone();
        let release = release.clone();
        handshake_holders.push(tokio::spawn(async move {
            source
                .run_handshake(|_| {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.add_permits(1);
                        release.acquire().await.unwrap().forget();
                        Ok::<_, ()>(())
                    }
                })
                .await
                .unwrap();
        }));
    }
    tokio::time::timeout(
        Duration::from_secs(2),
        entered.acquire_many((2 * opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES) as u32),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
    let control = tokio::time::timeout(
        Duration::from_secs(1),
        peer.call(request(SessionConsensusRpcFamily::Vote)),
    )
    .await
    .expect("reserved cold handshake capacity")
    .unwrap();
    assert_eq!(control.result, Ok(vec![0xA5]));
    release.add_permits(2 * opc_tls::MAX_TLS_CONCURRENT_HANDSHAKES);
    for task in handshake_holders {
        task.await.unwrap();
    }
    let wrong: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(addresses[0]) }));
    let wrong = RemoteSessionConsensusPeer::new_with_resolver(
        binding.clone(),
        wrong,
        tls,
        Some(Duration::from_secs(2)),
    );
    assert_eq!(
        wrong
            .call(request(SessionConsensusRpcFamily::InstallSnapshot))
            .await
            .unwrap()
            .result,
        Err(SessionConsensusPeerError::Protocol),
        "an endpoint number cannot promote a maintenance RPC"
    );
    handler.release.add_permits(2);
    for task in held {
        assert_eq!(task.await.unwrap().unwrap().result, Ok(vec![0xA5]));
    }
    drop(peer);
    drop(wrong);
    server.abort_and_wait().await;
}

#[tokio::test]
async fn class_local_builders_do_not_share_incompatible_cold_or_cached_state() {
    let (_, binding) = bindings();
    let resolvers = std::array::from_fn(|_| {
        Arc::new(
            || -> futures_util::future::BoxFuture<'static, io::Result<SocketAddr>> {
                Box::pin(async { Ok(SocketAddr::from(([127, 0, 0, 1], 1))) })
            },
        ) as RemoteAddrResolver
    });
    let peer = RemoteSessionConsensusPeer::from_transport(
        ConsensusTarget::configured(&binding),
        None,
        binding,
        None,
    )
    .with_class_resolvers(resolvers);
    let shared = peer.clone();
    assert!(Arc::ptr_eq(
        peer.class_transports.as_ref().unwrap(),
        shared.class_transports.as_ref().unwrap()
    ));
    let changed = peer
        .clone()
        .with_max_frame_size(MIN_SESSION_CONSENSUS_FRAME_SIZE);
    for i in 0..5 {
        assert!(!Arc::ptr_eq(
            &peer.class_transports.as_ref().unwrap()[i].pool,
            &changed.class_transports.as_ref().unwrap()[i].pool
        ));
        for j in 0..i {
            assert!(!Arc::ptr_eq(
                &peer.class_transports.as_ref().unwrap()[i].pool,
                &peer.class_transports.as_ref().unwrap()[j].pool
            ));
        }
    }
    let normal = &peer.class_transports.as_ref().unwrap()
        [super::super::classified::class_index(ScopeWorkClass::Normal).unwrap()]
    .pool;
    let _one = normal.acquire().await;
    let _two = normal.acquire().await;
    let control = &peer.class_transports.as_ref().unwrap()[0].pool;
    let _control = tokio::time::timeout(Duration::from_millis(100), control.acquire())
        .await
        .unwrap();
}
