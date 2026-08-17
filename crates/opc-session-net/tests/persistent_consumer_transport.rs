//! Live contract tests for the bounded persistent consumer transport.
//!
//! These exercise only the typed consumer port.  They deliberately do not
//! reach through to consensus, replication, or backend implementation APIs.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt};
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    ConnectionLifecyclePolicy, PersistentSessionConsumerClient, PersistentSessionConsumerConfig,
    PersistentSessionConsumerDiagnostics, PersistentSessionConsumerExecuteError,
    RemoteAddrResolver, SessionConsumerAuthorizer, SessionConsumerClientError,
    SessionQuorumConsumerServer, SessionReauthenticationControl, StatelessSessionConsumerClient,
};
use opc_session_store::{
    BackendCapabilities, ConsensusSessionStore, QuorumReplicaDescriptor, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, SessionConsensusIdentity,
    SessionConsumerChange, SessionConsumerIdentity, SessionConsumerOperation,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError, SessionKey,
    SessionKeyType, SessionQuorumConsumer, SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::net::TcpListener;
use tokio::sync::Notify;

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "persistent consumer test CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, key).expect("test CA certificate"),
        }
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client TLS config")
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server TLS config")
    }

    fn identity_state(&self, spiffe_id: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("test leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("test leaf certificate");
        let certificates =
            parse_certs_pem(&(certificate.pem() + &self.ca.pem())).expect("test certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("test private key");
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test.example").expect("trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles).expect("test identity state")
    }
}

#[derive(Default)]
struct ControlledConsumer {
    calls: AtomicUsize,
    block: AtomicBool,
    blocked_remaining: AtomicUsize,
    entered: Notify,
    released: Notify,
    request_order: Mutex<Vec<opc_session_store::SessionConsumerRequestId>>,
    watch_entry: Mutex<Option<SessionConsumerChange>>,
    watch_entry_limit: AtomicUsize,
    watch_emitted: Arc<AtomicUsize>,
}

impl ControlledConsumer {
    fn arm_blocks(&self, count: usize) {
        self.blocked_remaining.store(count, Ordering::SeqCst);
        self.block.store(count != 0, Ordering::SeqCst);
    }

    async fn wait_until_entered(&self, expected: usize) {
        while self.calls.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    }

    fn release(&self) {
        self.block.store(false, Ordering::SeqCst);
        self.released.notify_waiters();
    }

    fn request_order(&self) -> Vec<opc_session_store::SessionConsumerRequestId> {
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn repeat_watch_entry(&self, entry: SessionConsumerChange) {
        self.watch_entry_limit.store(0, Ordering::SeqCst);
        *self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
    }

    fn emit_watch_entries_then_close(&self, entry: SessionConsumerChange, count: usize) {
        assert!(
            count > 0,
            "finite watch fixture must emit at least one entry"
        );
        self.watch_entry_limit.store(count, Ordering::SeqCst);
        *self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
    }
}

#[async_trait]
impl SessionQuorumConsumer for ControlledConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerIdentity,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.request_id());
        self.entered.notify_waiters();
        if self
            .blocked_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            while self.block.load(Ordering::SeqCst) {
                self.released.notified().await;
            }
        }
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            SessionConsumerResponse::WatchOpened
        } else {
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled())
        }
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerIdentity,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        let entry = self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(entry) = entry else {
            return Ok(stream::pending().boxed());
        };
        let entry_limit = self.watch_entry_limit.load(Ordering::SeqCst);
        let emitted = Arc::clone(&self.watch_emitted);
        let entries = stream::repeat(entry).map(move |entry| {
            emitted.fetch_add(1, Ordering::SeqCst);
            Ok::<_, SessionConsumerStoreError>(entry)
        });
        if entry_limit == 0 {
            Ok(entries.boxed())
        } else {
            Ok(entries.take(entry_limit).boxed())
        }
    }
}

fn large_watch_change() -> SessionConsumerChange {
    let key = SessionKey {
        tenant: TenantId::new("watch-pressure").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![7_u8; 64])
            .try_into()
            .expect("maximum bounded stable ID"),
    };
    let item = serde_json::json!({
        "key": serde_json::to_value(key).expect("watch key encodes"),
        "kind": "RecordWritten",
    });
    let change: SessionConsumerChange = serde_json::from_value(serde_json::json!({
        "sequence": 1,
        "changes": vec![item; 1_700],
    }))
    .expect("synthetic bounded watch change decodes");
    let encoded = serde_json::to_vec(&change).expect("watch change encodes");
    assert!(
        (256 * 1024..512 * 1024).contains(&encoded.len()),
        "fixture must consume over half of the fixed byte queue without exceeding it: {}",
        encoded.len()
    );
    change
}

fn small_watch_change() -> SessionConsumerChange {
    let key = SessionKey {
        tenant: TenantId::new("watch-queue").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"opaque-watch-queue")
            .try_into()
            .expect("bounded stable ID"),
    };
    serde_json::from_value(serde_json::json!({
        "sequence": 1,
        "changes": [{
            "key": serde_json::to_value(key).expect("watch key encodes"),
            "kind": "RecordWritten",
        }],
    }))
    .expect("small synthetic watch change decodes")
}

fn assert_fixed_zero_diagnostics(diagnostics: PersistentSessionConsumerDiagnostics) {
    // Keep this exhaustive literal: adding an identifier-bearing field to the
    // public snapshot must be a deliberate compatibility decision, rather
    // than silently inheriting `Default` in this boundary test.
    assert_eq!(
        diagnostics,
        PersistentSessionConsumerDiagnostics {
            setup_attempts: 0,
            setup_failures: 0,
            setup_successes: 0,
            resolve_attempts: 0,
            resolve_failures: 0,
            tcp_attempts: 0,
            tcp_failures: 0,
            tls_attempts: 0,
            tls_failures: 0,
            hello_attempts: 0,
            hello_failures: 0,
            pool_wait_current: 0,
            pool_wait_max: 0,
            pool_wait_count: 0,
            pool_wait_max_duration_millis: 0,
            pool_wait_oldest_age_millis: 0,
            active: 0,
            max_active: 0,
            idle: 0,
            reused: 0,
            reconnects: 0,
            failures: 0,
            queued: 0,
            inflight: 0,
            max_inflight: 0,
            watch_active: 0,
            max_watch_active: 0,
            successes: 0,
            not_transmitted: 0,
            outcome_unknown: 0,
            overload: 0,
            shutdown: 0,
            authentication: 0,
            scope: 0,
            protocol: 0,
            deadline: 0,
        }
    );
}

fn spiffe(name: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{name}")
}

async fn authorizer_and_scope(
    client_spiffe: &str,
) -> (SessionConsumerAuthorizer, SessionConsumerScope) {
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let replica_id = ReplicaId::new("persistent-consumer-test").expect("replica ID");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("persistent-consumer.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(spiffe("member")).expect("member TLS identity"),
        ReplicaFailureDomain::new("persistent-consumer-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("persistent-consumer-disk").expect("backing identity"),
    );
    let cluster = ConsensusClusterId::new("persistent-consumer-test").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let configuration =
        derive_configuration_id(cluster, epoch, &[descriptor.configuration_fingerprint()]);
    let topology = ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        replica_id,
        vec![descriptor],
        SessionConsensusIdentity::new(cluster, configuration, epoch),
    )
    .expect("singleton topology");
    let store = ConsensusSessionStore::open(
        topology,
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
        snapshots.path(),
        Default::default(),
    )
    .await
    .expect("open store");
    store.initialize_cluster().await.expect("initialize store");
    let manifest = store
        .consumer_authorization_manifest()
        .await
        .expect("consumer authorization manifest");
    let scope = manifest.scope();
    let authorizer = SessionConsumerAuthorizer::try_new(
        manifest,
        [SpiffeId::new(client_spiffe).expect("client SPIFFE")],
    )
    .expect("consumer authorizer");
    (authorizer, scope)
}

fn config(
    request_connections: usize,
    pending_calls: usize,
    watch_connections: usize,
) -> PersistentSessionConsumerConfig {
    PersistentSessionConsumerConfig::try_new(
        request_connections,
        pending_calls,
        Duration::from_millis(250),
        watch_connections,
        Duration::from_millis(1_500),
        2,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("bounded persistent config")
}

fn persistent_client(
    pki: &TestPki,
    resolver: RemoteAddrResolver,
    server_name: rustls_pki_types::ServerName<'static>,
    server_spiffe: &str,
    client_spiffe: &str,
    scope: SessionConsumerScope,
    config: PersistentSessionConsumerConfig,
) -> PersistentSessionConsumerClient {
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        server_name,
        SpiffeId::new(server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    PersistentSessionConsumerClient::try_from_stateless(stateless, config)
        .expect("persistent client")
}

#[tokio::test]
async fn prewarm_opens_fixed_lanes_reuses_them_and_keeps_diagnostics_redacted() {
    const LANES: usize = 3;
    let pki = TestPki::new();
    let server_spiffe = spiffe("prewarm-server");
    let client_spiffe = spiffe("prewarm-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let proxy = listener.local_addr().expect("proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept client");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    else {
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                });
            }
        })
    };
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(LANES, 8, 1),
    );
    let request_id_canary = SessionConsumerRequestId::from_bytes([0xa5; 16]);
    let scope_debug_canary = format!("{scope:?}");
    let scope_wire_canary = serde_json::to_string(&scope).expect("scope canary encodes");
    let request_id_debug_canary = format!("{request_id_canary:?}");
    let request_id_wire_canary = serde_json::to_string(&request_id_canary)
        .expect("request-id canary encodes")
        .trim_matches('"')
        .to_owned();
    let privacy_canaries = [
        "127.0.0.1",
        server_spiffe.as_str(),
        client_spiffe.as_str(),
        "prewarm-server",
        "prewarm-client",
        scope_debug_canary.as_str(),
        scope_wire_canary.as_str(),
        request_id_debug_canary.as_str(),
        request_id_wire_canary.as_str(),
    ];

    let initial_diagnostics = client.diagnostics().await;
    assert_fixed_zero_diagnostics(initial_diagnostics);
    let diagnostics_debug = format!("{initial_diagnostics:?}");
    for canary in privacy_canaries {
        assert!(
            !diagnostics_debug.contains(canary),
            "fixed numeric diagnostics must not render endpoint, identity, scope, or request data"
        );
    }

    assert_eq!(
        client
            .prewarm()
            .await
            .expect("prewarm")
            .ready_request_connections,
        LANES
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        LANES,
        "prewarm opens exactly the fixed lane count"
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        0,
        "prewarm authenticates capacity without application traffic"
    );
    let mut warm_call_micros = Vec::with_capacity(16);
    for _ in 0..16 {
        let call_started = Instant::now();
        assert_eq!(
            client.capabilities().await,
            Ok(BackendCapabilities::all_enabled())
        );
        warm_call_micros.push(call_started.elapsed().as_micros());
    }
    println!("synthetic_warm_call_samples_micros={warm_call_micros:?}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        LANES,
        "serial warm calls reuse authenticated lanes"
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, LANES as u64);
    assert_eq!(diagnostics.idle, LANES as u64);
    assert!(diagnostics.reused >= 16);
    let debug = format!("{client:?}");
    for canary in privacy_canaries {
        assert!(
            !debug.contains(canary),
            "persistent client Debug must not render endpoint, identity, scope, or request data"
        );
    }

    let report = client.shutdown().await;
    assert_eq!(report.drained_calls, 0);
    assert_eq!(report.forced_calls, 0);
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_pools_derived_from_one_stateless_lineage_share_physical_admission() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("lineage-cap-server");
    let client_spiffe = spiffe("lineage-cap-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start lineage-cap listener");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let proxy = listener.local_addr().expect("proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept consumer TCP");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    else {
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                });
            }
        })
    };
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    let full_pool = PersistentSessionConsumerClient::try_from_stateless(
        stateless.clone(),
        config(PHYSICAL_CAP, 0, 1),
    )
    .expect("full persistent pool");
    let second_pool =
        PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
            .expect("second persistent pool");

    assert_eq!(
        full_pool
            .prewarm()
            .await
            .expect("first pool reaches the fixed physical cap")
            .ready_request_connections,
        PHYSICAL_CAP
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        second_pool.prewarm().await,
        Err(SessionConsumerClientError::Overloaded),
        "a second pool from one stateless clone lineage cannot start a seventeenth connection"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    full_pool.shutdown().await;
    assert_eq!(
        second_pool
            .prewarm()
            .await
            .expect("releasing the first pool admits a fresh connection")
            .ready_request_connections,
        1
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP + 1);

    second_pool.shutdown().await;
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_watch_preserves_typed_overload_from_shared_physical_admission() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("lineage-watch-cap-server");
    let client_spiffe = spiffe("lineage-watch-cap-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start lineage-watch-cap listener");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let proxy = listener.local_addr().expect("proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted = Arc::clone(&accepted);
        let active = Arc::clone(&active);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept consumer TCP");
                accepted.fetch_add(1, Ordering::SeqCst);
                active.fetch_add(1, Ordering::SeqCst);
                let active = Arc::clone(&active);
                tokio::spawn(async move {
                    if let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    {
                        let _ =
                            tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream)
                                .await;
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        })
    };
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    let persistent =
        PersistentSessionConsumerClient::try_from_stateless(stateless.clone(), config(1, 0, 1))
            .expect("persistent client");

    let mut held = Vec::with_capacity(PHYSICAL_CAP);
    for _ in 0..PHYSICAL_CAP {
        held.push(
            stateless
                .watch(0)
                .await
                .expect("stateless watch reaches shared physical cap"),
        );
    }
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(active.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);

    assert!(matches!(
        persistent.open_watch(0).await,
        Err(SessionConsumerClientError::Overloaded)
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);
    let overloaded = persistent.diagnostics().await;
    assert_eq!(overloaded.setup_attempts, 1);
    assert_eq!(overloaded.setup_failures, 1);
    assert_eq!(overloaded.failures, 1);
    assert_eq!(overloaded.not_transmitted, 1);
    assert_eq!(overloaded.overload, 1);
    assert_eq!(overloaded.watch_active, 0);

    drop(held.pop().expect("one held stateless watch"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) == PHYSICAL_CAP {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reader-owned physical watch permit is released within the fixed bound");
    let replacement = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match persistent.open_watch(0).await {
                Ok(watch) => break watch,
                Err(SessionConsumerClientError::Overloaded) => tokio::task::yield_now().await,
                Err(error) => panic!("replacement watch failed outside overload: {error}"),
            }
        }
    })
    .await
    .expect("released physical capacity becomes observable within the fixed bound");
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP + 1);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP + 1);

    drop(replacement);
    drop(held);
    persistent.shutdown().await;
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn lane_retires_before_the_4097th_call_and_correlation_restarts_on_replacement() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("rollover-server");
    let client_spiffe = spiffe("rollover-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    client.prewarm().await.expect("prewarm one lane");
    for _ in 0..=opc_session_net::MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
        assert_eq!(
            client.capabilities().await,
            Ok(BackendCapabilities::all_enabled())
        );
    }
    let diagnostics = client.diagnostics().await;
    assert_eq!(
        diagnostics.setup_successes, 2,
        "the call after the fixed correlation window uses one replacement lane"
    );
    assert_eq!(diagnostics.idle, 1);
    assert!(diagnostics.reconnects >= 1);
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        opc_session_net::MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION + 1
    );

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn one_lane_dispatches_twelve_bounded_waiters_in_admission_order() {
    const WAITERS: usize = 12;
    let pki = TestPki::new();
    let server_spiffe = spiffe("fair-server");
    let client_spiffe = spiffe("fair-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.arm_blocks(1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, WAITERS, 1),
    );

    let request_ids = (0..=WAITERS)
        .map(|index| {
            opc_session_store::SessionConsumerRequestId::from_bytes(
                [u8::try_from(index + 1).expect("bounded test index"); 16],
            )
        })
        .collect::<Vec<_>>();
    let first = {
        let client = client.clone();
        let request_id = request_ids[0];
        tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                request_id,
                SessionConsumerOperation::Capabilities,
            );
            client.execute(&request).await
        })
    };
    service.wait_until_entered(1).await;

    let mut queued = Vec::with_capacity(WAITERS);
    for (index, request_id) in request_ids.iter().copied().skip(1).enumerate() {
        let queued_client = client.clone();
        queued.push(tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                request_id,
                SessionConsumerOperation::Capabilities,
            );
            queued_client.execute(&request).await
        }));
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.diagnostics().await.queued < (index + 1) as u64 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("caller reaches the bounded fair lane queue");
    }

    service.release();
    assert!(first.await.expect("first task").is_ok());
    for caller in queued {
        assert!(caller.await.expect("queued task").is_ok());
    }
    assert!(
        service.request_order() == request_ids,
        "the bounded lane semaphore must preserve admission order"
    );
    assert_eq!(client.diagnostics().await.pool_wait_max, WAITERS as u64);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn slow_lane_does_not_serialize_sixteen_callers_and_watch_capacity_is_isolated() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("parallel-server");
    let client_spiffe = spiffe("parallel-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(4, 16, 1),
    );
    client.prewarm().await.expect("prewarm");

    service.arm_blocks(1);
    let slow = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    service.wait_until_entered(1).await;
    let callers = (0..15)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.capabilities().await })
        })
        .collect::<Vec<_>>();
    // Only the first of the sixteen calls is held. Prove other request
    // capacity reaches dispatch before releasing it; this is deterministic
    // evidence that clones are not globally serialized behind the slow call.
    tokio::time::timeout(Duration::from_millis(250), service.wait_until_entered(4))
        .await
        .expect("other request capacity dispatches while one lane remains slow");
    assert!(
        !slow.is_finished(),
        "the deliberately slow lane is still held"
    );
    service.release();
    for (index, caller) in callers.into_iter().enumerate() {
        let result = tokio::time::timeout(Duration::from_millis(800), caller)
            .await
            .expect("unblocked caller must not serialize behind slow lane")
            .expect("caller task");
        assert_eq!(
            result,
            Ok(BackendCapabilities::all_enabled()),
            "caller {index} failed; diagnostics={:?}",
            client.diagnostics().await,
        );
    }
    assert_eq!(service.calls.load(Ordering::SeqCst), 16);
    assert_eq!(
        slow.await.expect("slow task"),
        Ok(BackendCapabilities::all_enabled())
    );

    let watch = client
        .open_watch(0)
        .await
        .expect("first isolated watch slot");
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    assert!(matches!(
        client.open_watch(0).await,
        Err(SessionConsumerClientError::Overloaded)
    ));
    drop(watch);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if client.diagnostics().await.watch_active == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the receiver stops its reader and releases the watch slot");
    let replacement_watch = client
        .open_watch(0)
        .await
        .expect("dropping a watch releases only its watch slot");
    drop(replacement_watch);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if client.diagnostics().await.watch_active == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the replacement receiver releases its watch slot");
    let diagnostics = client.diagnostics().await;
    assert!(diagnostics.max_active >= 2);
    assert_eq!(diagnostics.max_watch_active, 1);
    let report = client.shutdown().await;
    assert_eq!(report.drained_watches, 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn admitted_call_drains_across_rotation_and_hard_deadline_releases_its_lane() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("drain-server");
    let client_spiffe = spiffe("drain-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(2),
        Duration::from_millis(100),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .expect("short deterministic drain policy");
    let server_rotation = SessionReauthenticationControl::new();
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_connection_lifecycle(lifecycle)
    .with_reauthentication_control(server_rotation.clone())
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1))
    .with_connection_lifecycle(lifecycle);
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
        .expect("persistent client");
    client.prewarm().await.expect("initial prewarm");

    service.arm_blocks(1);
    let completing_id = opc_session_store::SessionConsumerRequestId::new();
    let completing = {
        let client = client.clone();
        tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                completing_id,
                SessionConsumerOperation::Capabilities,
            );
            client.execute(&request).await
        })
    };
    service.wait_until_entered(1).await;
    assert!(
        !client.readiness().await.ready,
        "a leased request lane is not idle authenticated readiness"
    );
    client
        .request_reauthentication()
        .expect("begin graceful connection drain");
    server_rotation
        .request_reauthentication()
        .expect("begin graceful server drain");
    service.release();
    assert_eq!(
        completing.await.expect("completing task"),
        Ok(SessionConsumerResponse::Capabilities(
            BackendCapabilities::all_enabled()
        )),
        "already-admitted work may finish inside the rotation drain window"
    );

    assert!(client.prewarm().await.expect("replacement prewarm").ready);
    service.arm_blocks(1);
    let forced_id = opc_session_store::SessionConsumerRequestId::new();
    let forced = {
        let client = client.clone();
        tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                forced_id,
                SessionConsumerOperation::Capabilities,
            );
            client.execute(&request).await
        })
    };
    service.wait_until_entered(2).await;
    let drain_started = Instant::now();
    client
        .request_reauthentication()
        .expect("begin bounded hard drain");
    server_rotation
        .request_reauthentication()
        .expect("begin bounded server hard drain");
    let error = tokio::time::timeout(Duration::from_millis(500), forced)
        .await
        .expect("hard deadline bounds the active call")
        .expect("forced task")
        .expect_err("hard retirement is outcome-ambiguous");
    assert!(
        matches!(
            error,
            PersistentSessionConsumerExecuteError::OutcomeUnknown { request_id }
                if request_id == forced_id
        ),
        "post-write hard retirement preserves the exact request ID"
    );
    assert!(drain_started.elapsed() >= Duration::from_millis(75));
    assert_eq!(client.diagnostics().await.active, 0);
    assert_eq!(service.calls.load(Ordering::SeqCst), 2, "no blind replay");
    service.release();

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn saturated_watch_queue_and_server_write_release_on_bounded_rotation() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-drain-server");
    let client_spiffe = spiffe("watch-drain-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.repeat_watch_entry(large_watch_change());
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(2),
        Duration::from_millis(100),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .expect("short deterministic drain policy");
    let server_rotation = SessionReauthenticationControl::new();
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(1)
    .with_operation_timeout(Duration::from_secs(2))
    .with_connection_lifecycle(lifecycle)
    .with_reauthentication_control(server_rotation.clone())
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start single-slot consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let stale_watch = client.open_watch(0).await.expect("open pressure watch");
    let pressure_deadline = Instant::now() + Duration::from_secs(1);
    let mut prior = 0;
    let mut unchanged_samples = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let emitted = service.watch_emitted.load(Ordering::SeqCst);
        unchanged_samples = if emitted >= 2 && emitted == prior {
            unchanged_samples + 1
        } else {
            0
        };
        if unchanged_samples >= 3 {
            break;
        }
        assert!(
            Instant::now() < pressure_deadline,
            "watch writer did not reach bounded backpressure"
        );
        prior = emitted;
    }
    assert_eq!(client.diagnostics().await.watch_active, 1);

    server_rotation
        .request_reauthentication()
        .expect("rotate the backpressured server connection");
    let replacement = tokio::time::timeout(Duration::from_millis(500), client.prewarm())
        .await
        .expect("server hard deadline releases its sole connection slot")
        .expect("replacement prewarm");
    assert!(replacement.ready);
    assert_eq!(
        client.diagnostics().await.watch_active,
        1,
        "the unpolled byte-saturated local queue still owns its isolated slot"
    );

    client
        .request_reauthentication()
        .expect("rotate the saturated local watch reader");
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rotation interrupts byte-budget acquisition and releases the watch slot");
    drop(stale_watch);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn rotation_releases_an_unpolled_full_small_item_watch_queue() {
    const WATCH_QUEUE_ITEMS: usize = 64;
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-small-queue-server");
    let client_spiffe = spiffe("watch-small-queue-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.repeat_watch_entry(small_watch_change());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let stale_watch = client.open_watch(0).await.expect("open queued watch");
    let pressure_deadline = Instant::now() + Duration::from_secs(1);
    let mut previous = 0;
    let mut unchanged_samples = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let emitted = service.watch_emitted.load(Ordering::SeqCst);
        unchanged_samples = if emitted > WATCH_QUEUE_ITEMS && emitted == previous {
            unchanged_samples + 1
        } else {
            0
        };
        if unchanged_samples >= 3 {
            break;
        }
        assert!(
            Instant::now() < pressure_deadline,
            "the unpolled watch did not fill its fixed 64-item queue"
        );
        previous = emitted;
    }
    assert_eq!(client.diagnostics().await.watch_active, 1);

    // Do not poll or drop `stale_watch`: the physical reader, not caller
    // polling, owns the fixed lease and must release it on rotation.
    client
        .request_reauthentication()
        .expect("retire the full unpolled watch queue");
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rotation releases the stale fixed watch lease");
    let replacement = client
        .open_watch(0)
        .await
        .expect("released slot admits a replacement watch");
    drop(replacement);
    drop(stale_watch);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn peer_terminal_releases_an_unpolled_full_small_item_watch_queue() {
    const WATCH_QUEUE_ITEMS: usize = 64;
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-peer-terminal-server");
    let client_spiffe = spiffe("watch-peer-terminal-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_close(small_watch_change(), WATCH_QUEUE_ITEMS);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let stale_watch = client.open_watch(0).await.expect("open finite watch");
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.watch_emitted.load(Ordering::SeqCst) < WATCH_QUEUE_ITEMS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server emits exactly enough entries to fill the item queue");
    tokio::time::timeout(Duration::from_millis(500), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer terminal releases the fixed watch lease without caller polling");

    // Keep `stale_watch` unpolled and alive while proving that its full local
    // queue cannot retain either the isolated watch slot or physical permit.
    let replacement = tokio::time::timeout(Duration::from_millis(500), client.open_watch(0))
        .await
        .expect("replacement watch admission remains bounded")
        .expect("released peer-terminal slot admits a replacement watch");
    assert!(service.calls.load(Ordering::SeqCst) >= 2);
    drop(replacement);
    drop(stale_watch);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn saturation_cancellation_and_reauthentication_replace_only_stale_lanes() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("replacement-server");
    let client_spiffe = spiffe("replacement-client");
    let (first_authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let first_service = Arc::new(ControlledConsumer::default());
    let (first_handle, first_address) = SessionQuorumConsumerServer::new(
        first_service.clone(),
        pki.server_config(&server_spiffe),
        first_authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("first listen address"),
    )
    .await
    .expect("start first listener");
    let resolved = Arc::new(RwLock::new(first_address));
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolved = Arc::clone(&resolved);
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolved = Arc::clone(&resolved);
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(*resolved.read().expect("resolver address lock"))
            })
        })
    };
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 1, 1),
    );
    client.prewarm().await.expect("one lane prewarm");

    first_service.arm_blocks(1);
    let active = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    first_service.wait_until_entered(1).await;
    assert!(
        !client.readiness().await.ready,
        "readiness must not count the checked-out lane as idle"
    );
    let queued = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    tokio::time::timeout(Duration::from_millis(200), async {
        while client.diagnostics().await.queued != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second caller must occupy the bounded queue");
    let started = tokio::time::Instant::now();
    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Overloaded)
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "saturated admission fails promptly"
    );
    queued.abort();
    active.abort();
    assert!(queued.await.is_err(), "queued cancellation completes");
    assert!(active.await.is_err(), "active cancellation completes");
    tokio::time::timeout(Duration::from_millis(200), async {
        while client.diagnostics().await.queued != 0 || client.diagnostics().await.active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("caller cancellation releases admission and active bounds");
    first_service.release();
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled()),
        "released bounds admit a new call and retain an idle lane for reauthentication"
    );
    let after_cancellation = client.diagnostics().await;
    assert_eq!(
        after_cancellation.setup_successes, 2,
        "caller cancellation discards its checked-out lane and the next caller opens one replacement"
    );
    assert_eq!(
        after_cancellation.reconnects, 1,
        "caller cancellation records exactly one discarded-lane reconnect"
    );

    first_handle.abort_and_wait().await;
    let (second_authorizer, second_scope) = authorizer_and_scope(&client_spiffe).await;
    assert!(
        scope == second_scope,
        "replacement retains the exact consumer scope"
    );
    let second_service = Arc::new(ControlledConsumer::default());
    let (second_handle, second_address) = SessionQuorumConsumerServer::new(
        second_service.clone(),
        pki.server_config(&server_spiffe),
        second_authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("second listen address"),
    )
    .await
    .expect("start replacement listener");
    *resolved.write().expect("resolver address lock") = second_address;
    client.request_reauthentication().expect("drain stale lane");
    assert_eq!(
        client.capabilities().await,
        Ok(BackendCapabilities::all_enabled())
    );
    assert_eq!(second_service.calls.load(Ordering::SeqCst), 1);
    assert!(
        resolutions.load(Ordering::SeqCst) >= 2,
        "only a replacement connection resolves again"
    );
    let diagnostics = client.diagnostics().await;
    assert!(diagnostics.overload >= 1);
    assert!(diagnostics.reconnects >= 1);

    // The physical reader owns the watch slot. Rotation must release that
    // slot even when the caller retains the old handle without polling it.
    let stale_watch = client.open_watch(0).await.expect("open stale watch");
    client
        .request_reauthentication()
        .expect("retire unpolled watch transport");
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rotation releases an unpolled watch slot");
    let replacement_watch = client
        .open_watch(0)
        .await
        .expect("rotation admits a replacement watch");
    drop(replacement_watch);
    drop(stale_watch);
    let report = client.shutdown().await;
    assert_eq!(report.drained_calls, 0);
    second_handle.abort_and_wait().await;
}

#[tokio::test]
async fn forced_shutdown_stops_admission_and_bounds_active_calls_and_watches() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("shutdown-server");
    let client_spiffe = spiffe("shutdown-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 1, 1),
    );
    service.arm_blocks(1);
    let active = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    service.wait_until_entered(1).await;
    let watch = client.open_watch(0).await.expect("open pending watch");
    let report = tokio::time::timeout(Duration::from_millis(1_500), client.shutdown())
        .await
        .expect("shutdown drain is bounded");
    assert!(report.forced_calls >= 1);
    assert!(report.forced_watches >= 1);
    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::ShuttingDown)
    );
    drop(watch);
    active.abort();
    let _ = active.await;
    service.release();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn consumer_listener_rejects_unbounded_config_and_reaps_a_tls_blackhole() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("bounded-listener-server");
    let client_spiffe = spiffe("bounded-listener-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let occupied = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve an address");
    let occupied_address = occupied.local_addr().expect("reserved address");

    let error = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_max_connections(257)
    .listen(occupied_address)
    .await
    .expect_err("the fixed 256-listener-task ceiling is enforced before bind");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let error = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_idle_timeout(Duration::MAX)
    .listen(occupied_address)
    .await
    .expect_err("an unbounded pre-authentication timeout is rejected before bind");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    drop(occupied);

    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .with_max_connections(1)
            .with_idle_timeout(Duration::from_millis(100))
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start bounded listener");
    let blackhole = tokio::net::TcpStream::connect(address)
        .await
        .expect("open silent unauthenticated connection");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(750), client.capabilities())
            .await
            .expect("the silent peer releases the sole listener permit"),
        Ok(BackendCapabilities::all_enabled())
    );

    drop(blackhole);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_setup_preserves_the_shorter_stateless_pre_request_budget() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("setup-budget-server");
    let client_spiffe = spiffe("setup-budget-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolves = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolves = Arc::clone(&resolves);
        Arc::new(move || {
            let resolves = Arc::clone(&resolves);
            Box::pin(async move {
                resolves.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(75)).await;
                Ok(address)
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(25))
    .with_operation_timeout(Duration::from_secs(1));
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
        .expect("persistent client");
    let request = SessionConsumerRequest::new(
        scope,
        opc_session_store::SessionConsumerRequestId::from_bytes([91; 16]),
        SessionConsumerOperation::AcquireLease {
            key: SessionKey {
                tenant: TenantId::new("setup-budget").expect("test tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"opaque-setup-budget")
                    .try_into()
                    .expect("bounded stable ID"),
            },
            owner: opc_session_store::OwnerId::new("setup-budget-owner").expect("test owner"),
            ttl: Duration::from_secs(30),
        },
    );

    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(500), client.execute(&request))
            .await
            .expect("the inherited setup budget is finite"),
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        })
    ));
    assert!((1..=2).contains(&resolves.load(Ordering::SeqCst)));
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);

    client.shutdown().await;
    handle.abort_and_wait().await;
}
