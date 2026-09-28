//! A consensus client that abandons work already sent to a server must not
//! make that server record a transport failure.
//!
//! A client deadline, cancellation of the caller's future, or a local
//! reauthentication that supersedes a connection being set up is a local
//! outcome. The server still completes its side of the exchange. Before #1005
//! the client dropped the socket at once, so the server's next read or write
//! failed. The server then recorded `connection_failure_transport` although no
//! transport had failed.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};

use async_trait::async_trait;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_redaction::metrics::METRICS;
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId,
    SessionConfigurationEpoch, SessionConfigurationGeneration, SessionConsensusServer,
    SessionReplicationManifest,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use tokio::sync::Notify;

const CLIENT_REPLICA: u16 = 1;
const SERVER_REPLICA: u16 = 2;
/// The held call never completes inside this transport deadline: the server
/// handler is released only after the caller has given up.
const CALLER_DEADLINE: Duration = Duration::from_secs(1);
const OUTCOME_DEADLINE: Duration = Duration::from_secs(10);

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("generate test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.distinguished_name.push(
            rcgen::DnType::CommonName,
            "abandoned consensus call test CA",
        );
        let ca = rcgen::CertifiedIssuer::self_signed(parameters, ca_key).expect("sign test CA");
        Self { ca }
    }

    fn identity_state(&self, replica: u16) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("replica-{replica}"));
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(replica_spiffe(replica)).expect("SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("generate leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("sign leaf certificate");
        let certificates = parse_certs_pem(&(certificate.pem() + &self.ca.pem()))
            .expect("parse certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("parse private key");
        let mut trust_bundles = opc_identity::TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test-domain").expect("trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("parse CA"),
        });
        build_identity_state(certificates, private_key, trust_bundles)
            .expect("build identity state")
    }

    fn client_config(
        &self,
        replica: u16,
    ) -> (
        tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
        AuthenticatedClientConfig,
    ) {
        let (sender, receiver) = tokio::sync::watch::channel(Some(self.identity_state(replica)));
        let config = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("authenticated client config");
        (sender, config)
    }

    fn server_config(
        &self,
        replica: u16,
    ) -> (
        tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
        AuthenticatedServerConfig,
    ) {
        let (sender, receiver) = tokio::sync::watch::channel(Some(self.identity_state(replica)));
        let config = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("authenticated server config");
        (sender, config)
    }
}

fn replica_id(replica: u16) -> ReplicaId {
    ReplicaId::new(format!("replica-{replica}")).expect("replica ID")
}

fn replica_spiffe(replica: u16) -> String {
    format!("spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/{replica}")
}

fn descriptor(replica: u16) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(replica),
        ReplicaEndpoint::new(format!("replica-{replica}.session.invalid"), 7443)
            .expect("replica endpoint"),
        ReplicaTlsIdentity::new(replica_spiffe(replica)).expect("replica TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{replica}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{replica}")).expect("backing identity"),
    )
}

fn manifest() -> Arc<SessionReplicationManifest> {
    Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("abandoned-consensus-call").expect("cluster ID"),
            SessionConfigurationGeneration::new("generation-1").expect("generation"),
            SessionConfigurationEpoch::new(1).expect("configuration epoch"),
            vec![descriptor(CLIENT_REPLICA), descriptor(SERVER_REPLICA)],
        )
        .expect("session replication manifest"),
    )
}

fn resolver(address: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(address) }))
}

fn lifecycle_policy() -> ConnectionLifecyclePolicy {
    ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(30),
        Duration::from_secs(2),
        Duration::from_millis(2),
        Duration::from_millis(10),
        Duration::ZERO,
    )
    .expect("test lifecycle policy")
}

/// Echoes the payload. A `held` request is answered only after the test
/// releases it, so the caller always abandons it while it is executing.
#[derive(Debug, Default)]
struct HeldEchoHandler {
    held_started: Notify,
    release: Notify,
    completed: AtomicUsize,
}

#[async_trait]
impl SessionConsensusRpcHandler for HeldEchoHandler {
    async fn handle(
        &self,
        _authenticated_sender: opc_session_store::SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.payload == b"held" {
            self.held_started.notify_one();
            self.release.notified().await;
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Outcomes {
    attempts: u64,
    successes: u64,
    transport: u64,
    authentication: u64,
    timeout: u64,
    superseded: u64,
    abandoned: u64,
    protocol: u64,
    backend: u64,
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::SeqCst)
}

impl Outcomes {
    fn capture() -> Self {
        Self {
            attempts: load(&METRICS.session_net_connection_attempts),
            successes: load(&METRICS.session_net_connection_successes),
            transport: load(&METRICS.session_net_connection_failure_transport),
            authentication: load(&METRICS.session_net_connection_failure_authentication),
            timeout: load(&METRICS.session_net_connection_failure_timeout),
            superseded: load(&METRICS.session_net_connection_superseded),
            abandoned: load(&METRICS.session_net_connection_abandoned),
            protocol: load(&METRICS.session_net_connection_failure_protocol),
            backend: load(&METRICS.session_net_connection_failure_backend),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            attempts: self.attempts - before.attempts,
            successes: self.successes - before.successes,
            transport: self.transport - before.transport,
            authentication: self.authentication - before.authentication,
            timeout: self.timeout - before.timeout,
            superseded: self.superseded - before.superseded,
            abandoned: self.abandoned - before.abandoned,
            protocol: self.protocol - before.protocol,
            backend: self.backend - before.backend,
        }
    }

    fn terminal(self) -> u64 {
        self.successes
            + self.transport
            + self.authentication
            + self.timeout
            + self.superseded
            + self.abandoned
            + self.protocol
            + self.backend
    }
}

/// Wait until exactly `expected_attempts` physical attempts (client cold
/// connections and server accepted connections) started in this interval and
/// `expected_terminal` of them recorded their one terminal outcome, then
/// return that ledger.
async fn settled_outcomes(
    before: Outcomes,
    expected_attempts: u64,
    expected_terminal: u64,
) -> Outcomes {
    tokio::time::timeout(OUTCOME_DEADLINE, async {
        loop {
            let delta = Outcomes::capture().since(before);
            if delta.attempts == expected_attempts && delta.terminal() == expected_terminal {
                return delta;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("every settled connection end must record its terminal outcome")
}

#[derive(Clone, Copy, Debug)]
enum Abandonment {
    /// The transport's own per-call deadline expires first.
    TransportDeadline,
    /// The caller drops the call future, as an outer operation deadline does.
    CallerCancellation,
}

fn request(
    binding: &opc_session_net::RemoteReplicaBinding,
    payload: &[u8],
) -> SessionConsensusWireRequest {
    SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        SessionConsensusRpcFamily::AppendEntries,
        payload.to_vec(),
    )
    .expect("bounded consensus request")
}

async fn assert_abandoned_call_is_not_a_server_transport_failure(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
    abandonment: Abandonment,
) {
    let (_server_source, server_config) = pki.server_config(SERVER_REPLICA);
    let handler = Arc::new(HeldEchoHandler::default());
    let server_binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("consensus server binding");
    let (handle, address) =
        SessionConsensusServer::new(handler.clone(), server_config, server_binding)
            .with_connection_lifecycle(lifecycle_policy())
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("start consensus server");
    let (_client_source, client_config) = pki.client_config(CLIENT_REPLICA);
    let binding = manifest
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let warm = request(&binding, b"warm");
    let held = request(&binding, b"held");
    let fresh = request(&binding, b"fresh");
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        binding,
        resolver(address),
        client_config,
        Some(Duration::from_secs(5)),
    )
    .with_connection_lifecycle(lifecycle_policy());

    let before = Outcomes::capture();
    // Establish and cache one authenticated connection, so that the held
    // request is written at once on it.
    assert_eq!(
        peer.call(warm).await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"warm".to_vec()),
        })
    );
    match abandonment {
        Abandonment::TransportDeadline => {
            assert_eq!(
                peer.call_with_timeout(held, CALLER_DEADLINE).await,
                Err(SessionConsensusPeerError::Timeout),
                "the caller's own transport deadline expires while the server executes the call"
            );
        }
        Abandonment::CallerCancellation => {
            tokio::select! {
                outcome = peer.call(held) => {
                    panic!("the held call cannot complete before release: {outcome:?}")
                }
                () = handler.held_started.notified() => {}
            }
        }
    }
    assert_eq!(
        handler.completed.load(Ordering::SeqCst),
        1,
        "only the warm-up call has completed; the abandoned call is still executing"
    );

    // The server now finishes the abandoned call and writes its response.
    // That exchange and both ends of the connection must settle without any
    // failure outcome.
    handler.release.notify_one();
    let delta = settled_outcomes(before, 2, 2).await;
    assert_eq!(
        handler.completed.load(Ordering::SeqCst),
        2,
        "the server completed the abandoned call"
    );
    assert_eq!(
        delta,
        Outcomes {
            attempts: 2,
            successes: 2,
            transport: 0,
            authentication: 0,
            timeout: 0,
            superseded: 0,
            abandoned: 0,
            protocol: 0,
            backend: 0,
        },
        "{abandonment:?}: a caller abandoning an in-flight call is not a transport, \
         timeout or abandoned-attempt failure on either connection end"
    );

    // The late response of the abandoned call is never exposed to a later
    // call: the next call gets its own exact response.
    assert_eq!(
        peer.call(fresh).await,
        Ok(SessionConsensusWireResponse {
            result: Ok(b"fresh".to_vec()),
        }),
        "{abandonment:?}: the next call receives its own response"
    );
    assert_eq!(handler.completed.load(Ordering::SeqCst), 3);
    drop(peer);
    handle.abort_and_wait().await;
}

/// A TCP relay to one upstream. On its first connection it forwards client
/// bytes at once but holds every server byte until released, which stops a
/// client's TLS setup at a known point. Later connections are relayed in both
/// directions without delay.
struct HeldRelay {
    address: SocketAddr,
    connected: Arc<Notify>,
    release: Arc<Notify>,
}

async fn relay_connection(client: TcpStream, upstream: SocketAddr, hold: Option<Arc<Notify>>) {
    let server = TcpStream::connect(upstream)
        .await
        .expect("connect relay upstream");
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let to_server = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
        let _ = server_write.shutdown().await;
    });
    if let Some(hold) = hold {
        hold.notified().await;
    }
    let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
    let _ = client_write.shutdown().await;
    let _ = to_server.await;
}

async fn held_relay(upstream: SocketAddr) -> HeldRelay {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind held relay");
    let address = listener.local_addr().expect("held relay address");
    let connected = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (relay_connected, relay_release) = (Arc::clone(&connected), Arc::clone(&release));
    tokio::spawn(async move {
        let mut hold = Some(relay_release);
        loop {
            let (client, _) = listener.accept().await.expect("accept relay client");
            let held = hold.take();
            let first = held.is_some();
            tokio::spawn(relay_connection(client, upstream, held));
            if first {
                relay_connected.notify_one();
            }
        }
    });
    HeldRelay {
        address,
        connected,
        release,
    }
}

async fn assert_superseded_setup_is_not_a_server_transport_failure(
    pki: &TestPki,
    manifest: &Arc<SessionReplicationManifest>,
) {
    let (_server_source, server_config) = pki.server_config(SERVER_REPLICA);
    let handler = Arc::new(HeldEchoHandler::default());
    let server_binding = manifest
        .bind_local(replica_id(SERVER_REPLICA))
        .expect("consensus server binding");
    let (handle, server_address) =
        SessionConsensusServer::new(handler.clone(), server_config, server_binding)
            .with_connection_lifecycle(lifecycle_policy())
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("start consensus server");
    let relay = held_relay(server_address).await;
    let (_client_source, client_config) = pki.client_config(CLIENT_REPLICA);
    let binding = manifest
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    let superseded = request(&binding, b"superseded");
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        binding,
        resolver(relay.address),
        client_config,
        Some(Duration::from_secs(5)),
    )
    .with_connection_lifecycle(lifecycle_policy());
    let reauthentication = peer.reauthentication_control();

    let before = Outcomes::capture();
    {
        let call = peer.call(superseded);
        tokio::pin!(call);
        tokio::select! {
            outcome = &mut call => panic!("setup cannot finish while the relay holds it: {outcome:?}"),
            () = relay.connected.notified() => {}
        }
        // A local reauthentication supersedes the first connection while its
        // TLS setup is in flight. The caller then completes on a fresh
        // connection that the relay does not hold.
        reauthentication
            .request_reauthentication()
            .expect("request local reauthentication");
        assert_eq!(
            call.await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"superseded".to_vec()),
            }),
            "the caller completes on a fresh connection"
        );
    }
    relay.release.notify_one();

    // Four connection ends start: the superseded client setup, the fresh
    // client setup, and the server end of each. All but the cached fresh
    // server end settle now; the superseded server end must settle cleanly.
    let delta = settled_outcomes(before, 4, 3).await;
    assert_eq!(
        delta,
        Outcomes {
            attempts: 4,
            successes: 2,
            transport: 0,
            authentication: 0,
            timeout: 0,
            superseded: 1,
            abandoned: 0,
            protocol: 0,
            backend: 0,
        },
        "a locally superseded setup is one superseded client attempt and one clean \
         server connection, never a server transport failure"
    );
    assert_eq!(handler.completed.load(Ordering::SeqCst), 1);
    drop(peer);
    handle.abort_and_wait().await;
}

#[test]
fn abandoned_consensus_call_is_not_a_server_transport_failure() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("abandoned-call test runtime");
    runtime.block_on(async {
        let pki = TestPki::new();
        let manifest = manifest();
        assert_abandoned_call_is_not_a_server_transport_failure(
            &pki,
            &manifest,
            Abandonment::TransportDeadline,
        )
        .await;
        assert_abandoned_call_is_not_a_server_transport_failure(
            &pki,
            &manifest,
            Abandonment::CallerCancellation,
        )
        .await;
        assert_superseded_setup_is_not_a_server_transport_failure(&pki, &manifest).await;
    });
}
