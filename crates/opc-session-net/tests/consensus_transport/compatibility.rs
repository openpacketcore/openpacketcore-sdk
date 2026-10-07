use super::*;
use opc_consensus::{ConsensusCompatibility, ConsensusNodeId};

#[derive(Debug)]
struct ProfileHandler {
    profile: Option<ConsensusCompatibility>,
    received: StdMutex<Vec<Option<ConsensusCompatibility>>>,
}

#[async_trait]
impl SessionConsensusRpcHandler for ProfileHandler {
    fn compatibility(&self) -> Option<ConsensusCompatibility> {
        self.profile
    }

    async fn handle(
        &self,
        sender: ConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.handle_with_compatibility(sender, request, None).await
    }

    async fn handle_with_compatibility(
        &self,
        _: ConsensusNodeId,
        request: SessionConsensusWireRequest,
        proof: Option<ConsensusCompatibility>,
    ) -> SessionConsensusWireResponse {
        self.received.lock().unwrap().push(proof);
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

async fn serve_profile(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
    profile: Option<ConsensusCompatibility>,
) -> (
    opc_session_net::SessionConsensusServerHandle,
    SocketAddr,
    Arc<ProfileHandler>,
) {
    let handler = Arc::new(ProfileHandler {
        profile,
        received: StdMutex::new(Vec::new()),
    });
    let (server, address) = SessionConsensusServer::new(
        handler.clone(),
        pki.server_config(SERVER_REPLICA),
        manifest.bind_local(replica_id(SERVER_REPLICA)).unwrap(),
    )
    .listen("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();
    (server, address, handler)
}

#[tokio::test]
async fn connection_compatibility_is_mutual_and_bound_to_dispatch() {
    let pki = TestPki::new();
    let manifest = manifest("connection-compatibility", 1, 1);
    let (server, address, handler) = serve_profile(&pki, &manifest, Some([0x41; 32])).await;
    let peer = peer(
        &manifest,
        1,
        SERVER_REPLICA,
        address,
        pki.client_config(1),
        Duration::from_secs(5),
    )
    .with_compatibility([0x41; 32])
    .unwrap();
    for required in [None, Some([0x41; 32])] {
        let response = peer
            .call_with_compatibility(
                request(&manifest, 1, vec![7]),
                required,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(response.compatibility, Some([0x41; 32]));
        assert_eq!(response.response.result, Ok(vec![7]));
    }
    assert_eq!(*handler.received.lock().unwrap(), vec![Some([0x41; 32]); 2]);
    let mismatch = peer
        .call_with_compatibility(
            request(&manifest, 1, vec![8]),
            Some([0x42; 32]),
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(mismatch, Err(SessionConsensusPeerError::ScopeMismatch));
    assert_eq!(
        handler.received.lock().unwrap().len(),
        2,
        "a call requiring another profile never reaches the handler"
    );
    server.abort_and_wait().await;
}

#[tokio::test]
async fn legacy_handshakes_work_in_both_directions_without_verification_credit() {
    let pki = TestPki::new();
    let manifest = manifest("legacy-compatibility", 1, 1);
    for (client_profile, server_profile) in [(Some([0x41; 32]), None), (None, Some([0x41; 32]))] {
        let (server, address, handler) = serve_profile(&pki, &manifest, server_profile).await;
        let original = peer(
            &manifest,
            1,
            SERVER_REPLICA,
            address,
            pki.client_config(1),
            Duration::from_secs(5),
        );
        let peer: Arc<dyn SessionConsensusPeer> = match client_profile {
            Some(profile) => original.with_compatibility(profile).unwrap(),
            None => Arc::new(original),
        };
        let response = peer
            .call_with_compatibility(request(&manifest, 1, vec![7]), None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(response.compatibility, None);
        assert_eq!(response.response.result, Ok(vec![7]));
        let required = peer
            .call_with_compatibility(
                request(&manifest, 1, vec![8]),
                Some([0x41; 32]),
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(required, Err(SessionConsensusPeerError::ScopeMismatch));
        assert_eq!(
            *handler.received.lock().unwrap(),
            vec![None],
            "legacy transport is usable but cannot authorize a verified call"
        );
        server.abort_and_wait().await;
    }
}

#[tokio::test]
async fn reconnect_cannot_reuse_a_predecessors_compatibility_proof() {
    let pki = TestPki::new();
    let manifest = manifest("reconnect-compatibility", 1, 1);
    let (server, address, _) = serve_profile(&pki, &manifest, Some([0x41; 32])).await;
    let route = Arc::new(StdRwLock::new(Some(address)));
    let original = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        manifest
            .bind_local(replica_id(1))
            .unwrap()
            .bind_remote(replica_id(SERVER_REPLICA))
            .unwrap(),
        deferred_resolver(route.clone(), Arc::new(AtomicBool::new(true))),
        pki.client_config(1),
    );
    let peer = original.with_compatibility([0x41; 32]).unwrap();
    let first = peer
        .call_with_compatibility(
            request(&manifest, 1, vec![7]),
            Some([0x41; 32]),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(first.compatibility, Some([0x41; 32]));
    server.abort_and_wait().await;
    let (replacement, address, handler) = serve_profile(&pki, &manifest, Some([0x42; 32])).await;
    *route.write().unwrap() = Some(address);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match peer
                .call_with_compatibility(
                    request(&manifest, 1, vec![8]),
                    Some([0x41; 32]),
                    Duration::from_secs(5),
                )
                .await
            {
                Err(SessionConsensusPeerError::ScopeMismatch) => break,
                Err(
                    SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                ) => tokio::task::yield_now().await,
                other => {
                    panic!("incompatible replacement must never receive an engine call: {other:?}")
                }
            }
        }
    })
    .await
    .expect("incompatible handshake terminates");
    assert!(handler.received.lock().unwrap().is_empty());
    replacement.abort_and_wait().await;
}
