//! Read-only callers expose the same bounded revision signals as workers.
use super::*;
use crate::scope::{
    scope_transport_revision_diagnostics, ScopeReadClient, ScopeReadClientConfig,
    ScopeTransportDirection, ScopeTransportPurpose, ScopeTransportRole,
};

#[test]
fn observer_revision_mismatch_is_typed_counted_and_cleared_by_a_fresh_handshake() {
    const CHILD: &str = "OPC_OBSERVER_REVISION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scope::rpc_client::batch_tests::read_revision::observer_revision_mismatch_is_typed_counted_and_cleared_by_a_fresh_handshake", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        timeout(Duration::from_secs(15), async {
            let identity = SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([1; 32]),
                SessionConsensusConfigurationId::from_bytes([2; 32]),
                SessionConsensusConfigurationEpoch::new(1).unwrap(),
            );
            let scope = ScopeId::new(identity, TenantId::new("test").unwrap(), NetworkFunctionKind::new("smf").unwrap(), [81; 32]).unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let mut parameters = rcgen::CertificateParams::default();
            parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = rcgen::CertifiedIssuer::self_signed(parameters, rcgen::KeyPair::generate().unwrap()).unwrap();
            let (_client_source, receive) = tokio::sync::watch::channel(Some(material(WORKER, &ca)));
            let tls = TlsConfigBuilder::new(receive).with_policy(PeerPolicy {
                allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])), ..Default::default()
            }).build_authenticated_client_config().unwrap();
            let (_server_source, receive) = tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
            let server = TlsConfigBuilder::new(receive).with_policy(PeerPolicy {
                allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])), ..Default::default()
            }).build_authenticated_server_config().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let owner = ScopeSchedulerOwner::default();
            let client = ScopeReadClient::new(ScopeReadClientConfig {
                scope: scope.clone(), tls, server: SpiffeId::new(ISSUER).unwrap(),
                addresses: [listener.local_addr().unwrap(); 5], clock: Arc::new(Clock), scheduler: owner.scheduler(),
            }).unwrap();
            let diagnostic = |purpose| scope_transport_revision_diagnostics().into_iter().find(|entry|
                entry.role == ScopeTransportRole::Observer && entry.purpose == purpose && entry.direction == ScopeTransportDirection::Outbound
            ).unwrap();
            assert!(scope_transport_revision_diagnostics().iter().all(|entry| entry.total == 0));
            let (result, peer) = tokio::join!(client.current(Duration::from_secs(2)), async {
                let (socket, _) = listener.accept().await.unwrap();
                let handshake = server.begin_handshake().unwrap();
                let mut config = (*handshake.rustls_config()).clone();
                config.alpn_protocols = vec![b"opc-scope/1".to_vec()];
                tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await
            });
            assert!(peer.is_err());
            assert_eq!(result.err(), Some(ScopeRpcError::TransportRevisionMismatch));
            let alert = diagnostic(ScopeTransportPurpose::Handshake);
            assert_eq!((alert.total, alert.authenticated, alert.active), (1, 0, true));
            for old in [true, false] {
                let (result, peer) = tokio::join!(client.current(Duration::from_secs(2)), async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut stream = server.begin_handshake().unwrap().accept_scope(socket, binding.tls_domain().unwrap()).await.unwrap();
                    let mut fixed = [0; HEADER_BYTES];
                    stream.read_exact(&mut fixed).await.unwrap();
                    let call = Header::decode(&fixed).unwrap();
                    assert_eq!(call.method, Method::Current);
                    let mut body = vec![0; call.payload_len];
                    stream.read_exact(&mut body).await.unwrap();
                    let request = CallPayload::decode(call.method, &body).unwrap();
                    let view: ScopeAuthorityView = serde_json::from_value(json!({
                        "scope": scope, "revision": 0, "retired_through": 0,
                        "admission_generation_floor": 0, "stamp": null, "active": false, "closed_digest": null
                    })).unwrap();
                    let payload = ResultPayload::new(request.nonce, ResultStatus::CurrentView, [0; 32], view.encode_canonical().unwrap()).unwrap().encode().unwrap();
                    let mut response = call.response(FrameKind::Result, payload.len()).unwrap().encode().unwrap();
                    if old { response[4..6].copy_from_slice(&1u16.to_be_bytes()); }
                    stream.write_all(&response).await.unwrap();
                    if !old { stream.write_all(&payload).await.unwrap(); }
                    stream.flush().await.unwrap();
                    stream
                });
                let alert = diagnostic(ScopeTransportPurpose::Handshake);
                assert_eq!((alert.total, alert.authenticated, alert.active), (1, 0, false), "the authenticated revision-two handshake clears the alert condition without erasing counters");
                let frame = diagnostic(ScopeTransportPurpose::ScopeResponse);
                if old {
                    assert_eq!(result.err(), Some(ScopeRpcError::TransportRevisionMismatch), "a complete old fixed header is rejected before waiting for a body");
                    assert_eq!((frame.total, frame.authenticated, frame.active), (1, 1, true));
                } else {
                    assert_eq!(result.unwrap().scope(), &scope);
                    assert_eq!((frame.total, frame.authenticated, frame.active), (1, 1, false));
                }
                assert_eq!(owner.scheduler().snapshot().class(ScopeWorkClass::SafetyControl).resident, 0);
                drop(peer);
            }
        }).await.expect("bounded observer revision fixture");
    });
}
