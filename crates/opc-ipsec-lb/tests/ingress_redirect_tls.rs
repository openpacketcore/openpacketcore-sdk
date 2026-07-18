use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_identity::{build_identity_state, IdentityState, TrustBundle, TrustBundleSet};
use opc_ipsec_lb::{
    establish_ingress_redirect_client, establish_ingress_redirect_server,
    rotate_ingress_redirect_client, rotate_ingress_redirect_server, DestinationContext,
    EspEncapsulationKind, EspOwnershipKey, EspSpi, InMemoryIngressRedirectDatagram,
    IngressRedirectDatagram, IngressRedirectDatagramError, IngressRedirectDeliveryReceiver,
    IngressRedirectEndpoint, IngressRedirectError, IngressRedirectInboundOutcome,
    IngressRedirectOperation, IngressRedirectOperationOutcome, IngressRedirectPacketTooBigEvent,
    IngressRedirectPacketTooBigReportError, IngressRedirectPacketTooBigReporter,
    IngressRedirectPeerExpectation, IngressRedirectPeerManifest, IngressRedirectPeerSession,
    IngressRedirectProfile, IngressRedirectProtectionEpoch, IngressRedirectReceiptCode, IpAddress,
    RoutingDomainTag, SessionOwnershipKey,
};
use opc_session_store::{
    Clock, FakeSessionBackend, FencedOwnershipCache, FencedOwnershipCacheConfig,
    FencedOwnershipCacheSeed, FencedOwnershipGeneration, FencedOwnershipKey,
    FencedOwnershipMetadata, FencedOwnershipMutationId, FencedOwnershipNamespace,
    FencedOwnershipStore, OwnerId, TokioVirtualClock,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder,
    TlsMaterialAvailability, TlsMaterialEpoch, TlsMaterialStatusReceiver,
};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::sync::{watch, Notify};

const CLIENT_ID: &str =
    "spiffe://redirect.test/tenant/acme/ns/core/sa/epdg/nf/epdg/instance/client-0";
const SERVER_ID: &str =
    "spiffe://redirect.test/tenant/acme/ns/core/sa/epdg/nf/epdg/instance/server-0";

struct TestPki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new(label: &str) -> Self {
        let key = rcgen::KeyPair::generate().expect("generate test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("ingress redirect test CA {label}"),
        );
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::hours(1);
        parameters.not_after = now + time::Duration::days(2);
        let issuer = rcgen::CertifiedIssuer::self_signed(parameters, key).expect("sign test CA");
        Self { issuer }
    }

    fn trust_bundles(trusted_issuers: &[&Self]) -> TrustBundleSet {
        let mut bundles = TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("redirect.test")
                .expect("valid trust domain"),
            certificates: trusted_issuers
                .iter()
                .map(|issuer| issuer.issuer.der().clone())
                .collect(),
        });
        bundles
    }

    fn identity_state(&self, spiffe_id: &str, trusted_issuers: &[&Self]) -> IdentityState {
        let key = rcgen::KeyPair::generate().expect("generate leaf key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("valid test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::minutes(1);
        parameters.not_after = now + time::Duration::hours(1);
        let certificate = parameters
            .signed_by(&key, &self.issuer)
            .expect("sign leaf certificate");
        build_identity_state(
            vec![certificate.der().clone(), self.issuer.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            Self::trust_bundles(trusted_issuers),
        )
        .expect("valid identity state")
    }

    fn replace_trust_bundles(mut state: IdentityState, trusted_issuers: &[&Self]) -> IdentityState {
        state.trust_bundles = Self::trust_bundles(trusted_issuers);
        state
    }
}

struct GatedDatagram {
    inner: InMemoryIngressRedirectDatagram,
    gate_armed: AtomicBool,
    send_blocked: AtomicBool,
    send_released: AtomicBool,
    gate_changed: Notify,
    release_changed: Notify,
}

impl GatedDatagram {
    fn pair(
        first_endpoint: SocketAddr,
        second_endpoint: SocketAddr,
        profile: IngressRedirectProfile,
    ) -> (Arc<Self>, Arc<Self>) {
        let (first, second) = InMemoryIngressRedirectDatagram::pair(
            first_endpoint,
            second_endpoint,
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .expect("valid in-memory redirect pair");
        (Arc::new(Self::new(first)), Arc::new(Self::new(second)))
    }

    fn new(inner: InMemoryIngressRedirectDatagram) -> Self {
        Self {
            inner,
            gate_armed: AtomicBool::new(false),
            send_blocked: AtomicBool::new(false),
            send_released: AtomicBool::new(false),
            gate_changed: Notify::new(),
            release_changed: Notify::new(),
        }
    }

    fn arm_next_send(&self) {
        assert!(!self.gate_armed.swap(true, Ordering::AcqRel));
        self.send_blocked.store(false, Ordering::Release);
        self.send_released.store(false, Ordering::Release);
    }

    async fn wait_until_send_blocked(&self) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let changed = self.gate_changed.notified();
                if self.send_blocked.load(Ordering::Acquire) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("endpoint reached gated send");
    }

    fn release_send(&self) {
        assert!(self.send_blocked.load(Ordering::Acquire));
        self.send_released.store(true, Ordering::Release);
        self.release_changed.notify_waiters();
    }
}

impl fmt::Debug for GatedDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatedDatagram")
            .field("endpoints", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl IngressRedirectDatagram for GatedDatagram {
    async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
        if self.gate_armed.swap(false, Ordering::AcqRel) {
            self.send_blocked.store(true, Ordering::Release);
            self.gate_changed.notify_waiters();
            loop {
                let released = self.release_changed.notified();
                if self.send_released.load(Ordering::Acquire) {
                    break;
                }
                released.await;
            }
        }
        self.inner.send(datagram).await
    }

    async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
        self.inner.receive().await
    }

    fn local_endpoint(&self) -> SocketAddr {
        self.inner.local_endpoint()
    }

    fn peer_endpoint(&self) -> SocketAddr {
        self.inner.peer_endpoint()
    }

    fn maximum_receive_datagram_size(&self) -> usize {
        self.inner.maximum_receive_datagram_size()
    }

    fn maximum_send_datagram_size(&self) -> usize {
        self.inner.maximum_send_datagram_size()
    }
}

#[derive(Debug)]
struct TestPacketTooBigReporter;

#[async_trait]
impl IngressRedirectPacketTooBigReporter for TestPacketTooBigReporter {
    async fn report(
        &self,
        _event: IngressRedirectPacketTooBigEvent<'_>,
    ) -> Result<(), IngressRedirectPacketTooBigReportError> {
        Ok(())
    }
}

fn authenticated_client_config(
    initial: IdentityState,
) -> (
    watch::Sender<Option<IdentityState>>,
    AuthenticatedClientConfig,
) {
    let (sender, receiver) = watch::channel(Some(initial));
    let config = TlsConfigBuilder::new(receiver)
        .with_local_spiffe_id(SpiffeId::new(CLIENT_ID).expect("valid client SPIFFE identity"))
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("authenticated client config");
    (sender, config)
}

fn authenticated_server_config(
    initial: IdentityState,
) -> (
    watch::Sender<Option<IdentityState>>,
    AuthenticatedServerConfig,
) {
    let (sender, receiver) = watch::channel(Some(initial));
    let config = TlsConfigBuilder::new(receiver)
        .with_local_spiffe_id(SpiffeId::new(SERVER_ID).expect("valid server SPIFFE identity"))
        .allow_any_trusted_peer()
        .build_authenticated_server_config()
        .expect("authenticated server config");
    (sender, config)
}

async fn publish_material(
    source: &watch::Sender<Option<IdentityState>>,
    changes: &mut TlsMaterialStatusReceiver,
    previous_epoch: TlsMaterialEpoch,
    candidate: IdentityState,
) -> TlsMaterialEpoch {
    drop(source.send_replace(Some(candidate)));
    let status = tokio::time::timeout(Duration::from_secs(1), changes.changed())
        .await
        .expect("TLS material publication timeout")
        .expect("TLS material source remains open");
    assert_eq!(status.availability(), TlsMaterialAvailability::Ready);
    assert!(status.epoch() > previous_epoch);
    status.epoch()
}

fn redirect_profile() -> IngressRedirectProfile {
    IngressRedirectProfile::production(1_500)
        .and_then(|profile| profile.with_rotation_overlap(Duration::from_secs(5)))
        .and_then(|profile| profile.with_receipt_policy(Duration::from_millis(250), 2))
        .expect("valid redirect profile")
}

fn manifest(identity: &str, owner: &str, endpoint: SocketAddr) -> IngressRedirectPeerManifest {
    IngressRedirectPeerManifest::new(
        SpiffeId::new(identity).expect("valid SPIFFE identity"),
        OwnerId::new(owner).expect("valid owner"),
        endpoint,
        redirect_profile(),
        [RoutingDomainTag::new(7)],
    )
    .expect("valid manifest")
}

fn expectation(
    identity: &str,
    owner: &str,
    endpoint: SocketAddr,
) -> IngressRedirectPeerExpectation {
    IngressRedirectPeerExpectation::new(
        SpiffeId::new(identity).expect("valid SPIFFE identity"),
        OwnerId::new(owner).expect("valid owner"),
        endpoint,
    )
    .expect("valid expectation")
}

fn server_name() -> ServerName<'static> {
    ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into())
}

fn ownership_key() -> SessionOwnershipKey {
    SessionOwnershipKey::Esp(EspOwnershipKey::new(
        DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(7)),
        EspEncapsulationKind::Native,
        EspSpi::new(0x0102_0304).expect("valid test SPI"),
    ))
}

fn synthetic_native_esp_packet(sequence: u32) -> Vec<u8> {
    let mut packet = vec![0x5a_u8; 64];
    let packet_len = u16::try_from(packet.len()).expect("bounded test packet length");
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[4..8].fill(0);
    packet[8] = 64;
    packet[9] = 50;
    packet[10..12].fill(0);
    packet[12..16].copy_from_slice(&[198, 51, 100, 7]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
    packet[20..24].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet
}

async fn ownership_cache(
    claimed_owner: &str,
    mutation: u8,
) -> (
    Arc<FencedOwnershipCache<TokioVirtualClock>>,
    FencedOwnershipGeneration,
) {
    let namespace = FencedOwnershipNamespace::new(
        TenantId::new(format!("redirect-tls-{claimed_owner}"))
            .expect("valid test tenant identifier"),
        NetworkFunctionKind::new("epdg").expect("valid NF kind"),
    );
    let clock = TokioVirtualClock::new();
    let store =
        FencedOwnershipStore::new(FakeSessionBackend::new(), namespace.clone(), clock.clone());
    let key = FencedOwnershipKey::new(ownership_key().to_canonical_bytes())
        .expect("valid canonical ownership key");
    let record = store
        .claim(
            FencedOwnershipMutationId::from_bytes([mutation; 16]),
            key,
            OwnerId::new(claimed_owner).expect("valid claimed owner"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim test ownership")
        .into_inner();
    let generation = record.generation();
    let cache = FencedOwnershipCache::new(
        namespace.clone(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(30),
            max_entries: 8,
            max_retained_bytes: 8 * 1_024,
        },
    )
    .expect("construct ownership cache");
    let seed = FencedOwnershipCacheSeed::from_caller_proven_snapshot(
        namespace,
        [record],
        0,
        clock.now_utc(),
    )
    .expect("construct coherent ownership seed");
    cache.seed(seed).expect("seed ownership cache");
    (Arc::new(cache), generation)
}

async fn establish_pair(
    client_config: &AuthenticatedClientConfig,
    server_config: &AuthenticatedServerConfig,
    client_manifest: &IngressRedirectPeerManifest,
    server_manifest: &IngressRedirectPeerManifest,
    expected_server: &IngressRedirectPeerExpectation,
    expected_client: &IngressRedirectPeerExpectation,
) -> (
    Result<IngressRedirectPeerSession, IngressRedirectError>,
    Result<IngressRedirectPeerSession, IngressRedirectError>,
) {
    let client_handshake = client_config
        .begin_handshake()
        .expect("client material snapshot");
    let server_handshake = server_config
        .begin_handshake()
        .expect("server material snapshot");
    let (client_io, server_io) = tokio::io::duplex(128 * 1024);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            establish_ingress_redirect_client(
                client_io,
                server_name(),
                client_handshake,
                client_manifest,
                expected_server,
            ),
            establish_ingress_redirect_server(
                server_io,
                server_handshake,
                server_manifest,
                expected_client,
            )
        )
    })
    .await
    .expect("initial control handshake timeout")
}

async fn rotate_pair(
    client_config: &AuthenticatedClientConfig,
    server_config: &AuthenticatedServerConfig,
    client_manifest: &IngressRedirectPeerManifest,
    server_manifest: &IngressRedirectPeerManifest,
    expected_server: &IngressRedirectPeerExpectation,
    expected_client: &IngressRedirectPeerExpectation,
    sessions: (&IngressRedirectPeerSession, &IngressRedirectPeerSession),
) -> IngressRedirectProtectionEpoch {
    let (client, server) = sessions;
    let client_handshake = client_config
        .begin_handshake()
        .expect("rotated client material snapshot");
    let server_handshake = server_config
        .begin_handshake()
        .expect("rotated server material snapshot");
    let (client_io, server_io) = tokio::io::duplex(128 * 1024);
    let rotated = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            rotate_ingress_redirect_client(
                client_io,
                server_name(),
                client_handshake,
                client_manifest,
                expected_server,
                client,
            ),
            rotate_ingress_redirect_server(
                server_io,
                server_handshake,
                server_manifest,
                expected_client,
                server,
            )
        )
    })
    .await
    .expect("rotation control handshake timeout");
    let client_epoch = rotated.0.expect("rotate client session");
    let server_epoch = rotated.1.expect("rotate server session");
    assert_eq!(client_epoch, server_epoch);
    client_epoch
}

async fn wait_for_previous_epoch_retirement(
    client: &IngressRedirectPeerSession,
    server: &IngressRedirectPeerSession,
) {
    tokio::time::sleep(
        client
            .profile()
            .rotation_overlap()
            .saturating_add(Duration::from_millis(10)),
    )
    .await;
    assert_eq!(
        client
            .rotation_status()
            .expect("client rotation status after overlap")
            .previous_receive(),
        None
    );
    assert_eq!(
        server
            .rotation_status()
            .expect("server rotation status after overlap")
            .previous_receive(),
        None
    );
}

async fn assert_operation_and_delivery(
    operation: &mut IngressRedirectOperation,
    receiver: &mut IngressRedirectDeliveryReceiver,
    expected_packet: &[u8],
    expected_generation: FencedOwnershipGeneration,
) {
    let outcome = tokio::time::timeout(Duration::from_secs(5), operation.wait())
        .await
        .expect("redirect operation completed");
    assert_eq!(
        outcome,
        IngressRedirectOperationOutcome::AuthenticatedReceipt(
            IngressRedirectReceiptCode::Delivered
        )
    );
    let delivered = tokio::time::timeout(Duration::from_secs(5), receiver.receive())
        .await
        .expect("redirect delivery completed")
        .expect("redirect delivery remained available");
    let IngressRedirectInboundOutcome::Delivered(delivered) = delivered else {
        panic!("expected exact-owner delivery")
    };
    assert_eq!(delivered.packet(), expected_packet);
    assert_eq!(delivered.ownership_key(), ownership_key());
    assert_eq!(delivered.ownership_generation(), expected_generation);
    assert_eq!(delivered.hop_count(), 1);
}

async fn assert_bidirectional_redirects(
    client_endpoint: &IngressRedirectEndpoint<TokioVirtualClock>,
    client_receiver: &mut IngressRedirectDeliveryReceiver,
    client_generation: FencedOwnershipGeneration,
    server_endpoint: &IngressRedirectEndpoint<TokioVirtualClock>,
    server_receiver: &mut IngressRedirectDeliveryReceiver,
    server_generation: FencedOwnershipGeneration,
    first_sequence: u32,
) {
    let client_packet = synthetic_native_esp_packet(first_sequence);
    let mut client_operation = client_endpoint
        .begin_redirect(&client_packet, ownership_key(), server_generation)
        .expect("begin client-to-server redirect");
    assert_operation_and_delivery(
        &mut client_operation,
        server_receiver,
        &client_packet,
        server_generation,
    )
    .await;

    let server_packet = synthetic_native_esp_packet(
        first_sequence
            .checked_add(1)
            .expect("bounded test packet sequence"),
    );
    let mut server_operation = server_endpoint
        .begin_redirect(&server_packet, ownership_key(), client_generation)
        .expect("begin server-to-client redirect");
    assert_operation_and_delivery(
        &mut server_operation,
        client_receiver,
        &server_packet,
        client_generation,
    )
    .await;
}

#[tokio::test]
async fn mtls_leaf_key_and_trust_bundle_rotation_is_seamless() {
    let ca_a = TestPki::new("A");
    let ca_b = TestPki::new("B");

    let client_a_only = ca_a.identity_state(CLIENT_ID, &[&ca_a]);
    let server_a_only = ca_a.identity_state(SERVER_ID, &[&ca_a]);
    let client_a_overlap = TestPki::replace_trust_bundles(client_a_only.clone(), &[&ca_a, &ca_b]);
    let server_a_overlap = TestPki::replace_trust_bundles(server_a_only.clone(), &[&ca_a, &ca_b]);
    let client_b_overlap = ca_b.identity_state(CLIENT_ID, &[&ca_a, &ca_b]);
    let server_b_overlap = ca_b.identity_state(SERVER_ID, &[&ca_a, &ca_b]);
    let client_b_only = TestPki::replace_trust_bundles(client_b_overlap.clone(), &[&ca_b]);
    let server_b_only = TestPki::replace_trust_bundles(server_b_overlap.clone(), &[&ca_b]);

    let (client_source, client_config) = authenticated_client_config(client_a_only);
    let (server_source, server_config) = authenticated_server_config(server_a_only);
    let mut client_changes = client_config.subscribe_material_changes();
    let mut server_changes = server_config.subscribe_material_changes();
    let initial_client_material = client_config.material_status();
    let initial_server_material = server_config.material_status();
    assert_eq!(
        initial_client_material.availability(),
        TlsMaterialAvailability::Ready
    );
    assert_eq!(
        initial_server_material.availability(),
        TlsMaterialAvailability::Ready
    );

    let client_endpoint: SocketAddr = "127.0.0.1:37441".parse().expect("client endpoint");
    let server_endpoint: SocketAddr = "127.0.0.1:37442".parse().expect("server endpoint");
    let client_manifest = manifest(CLIENT_ID, "owner-client", client_endpoint);
    let server_manifest = manifest(SERVER_ID, "owner-server", server_endpoint);
    let expected_server = expectation(SERVER_ID, "owner-server", server_endpoint);
    let expected_client = expectation(CLIENT_ID, "owner-client", client_endpoint);

    let initial = establish_pair(
        &client_config,
        &server_config,
        &client_manifest,
        &server_manifest,
        &expected_server,
        &expected_client,
    )
    .await;
    let client = Arc::new(initial.0.expect("establish client session"));
    let server = Arc::new(initial.1.expect("establish server session"));
    let (client_ownership, client_generation) = ownership_cache("owner-client", 1).await;
    let (server_ownership, server_generation) = ownership_cache("owner-server", 2).await;
    let (client_datagram, server_datagram) =
        GatedDatagram::pair(client_endpoint, server_endpoint, redirect_profile());
    let (client_redirect, mut client_delivery) = IngressRedirectEndpoint::start(
        Arc::clone(&client),
        client_ownership,
        client_datagram.clone(),
        Arc::new(TestPacketTooBigReporter),
    )
    .expect("start client redirect endpoint");
    let (server_redirect, mut server_delivery) = IngressRedirectEndpoint::start(
        Arc::clone(&server),
        server_ownership,
        server_datagram.clone(),
        Arc::new(TestPacketTooBigReporter),
    )
    .expect("start server redirect endpoint");
    let initial_client_status = client
        .authentication_status()
        .expect("client authentication status");
    let initial_server_status = server
        .authentication_status()
        .expect("server authentication status");
    let initial_epoch = initial_client_status.epoch();
    assert_eq!(initial_epoch, initial_server_status.epoch());
    assert_eq!(
        initial_client_status.local_material_epoch(),
        initial_client_material.epoch()
    );
    assert_eq!(
        initial_server_status.local_material_epoch(),
        initial_server_material.epoch()
    );
    assert!(initial_client_status.reauthenticate_after() > Duration::ZERO);
    assert_bidirectional_redirects(
        &client_redirect,
        &mut client_delivery,
        client_generation,
        &server_redirect,
        &mut server_delivery,
        server_generation,
        1,
    )
    .await;

    // First publish both roots without changing either leaf. The already
    // admitted exporter remains usable while trust is widened.
    let client_overlap_epoch = publish_material(
        &client_source,
        &mut client_changes,
        initial_client_material.epoch(),
        client_a_overlap.clone(),
    )
    .await;
    let server_overlap_epoch = publish_material(
        &server_source,
        &mut server_changes,
        initial_server_material.epoch(),
        server_a_overlap.clone(),
    )
    .await;
    assert_bidirectional_redirects(
        &client_redirect,
        &mut client_delivery,
        client_generation,
        &server_redirect,
        &mut server_delivery,
        server_generation,
        10,
    )
    .await;

    // Stop each endpoint at its next datagram send after admission and sealing.
    // Releasing these operations after rotation proves old-epoch frames through
    // the public endpoint boundary rather than exposing raw crypto primitives.
    client_datagram.arm_next_send();
    server_datagram.arm_next_send();
    let delayed_client_packet = synthetic_native_esp_packet(20);
    let delayed_server_packet = synthetic_native_esp_packet(21);
    let mut delayed_client_operation = client_redirect
        .begin_redirect(&delayed_client_packet, ownership_key(), server_generation)
        .expect("begin delayed client redirect");
    let mut delayed_server_operation = server_redirect
        .begin_redirect(&delayed_server_packet, ownership_key(), client_generation)
        .expect("begin delayed server redirect");
    tokio::join!(
        client_datagram.wait_until_send_blocked(),
        server_datagram.wait_until_send_blocked()
    );

    // Rotate only the client leaf and private key first. The server still
    // presents A while both peers trust {A,B}, proving mixed generations.
    let client_b_overlap_epoch = publish_material(
        &client_source,
        &mut client_changes,
        client_overlap_epoch,
        client_b_overlap.clone(),
    )
    .await;
    let mixed_epoch = rotate_pair(
        &client_config,
        &server_config,
        &client_manifest,
        &server_manifest,
        &expected_server,
        &expected_client,
        (&client, &server),
    )
    .await;
    assert_ne!(mixed_epoch, initial_epoch);
    assert_eq!(
        client
            .authentication_status()
            .expect("mixed client status")
            .local_material_epoch(),
        client_b_overlap_epoch
    );
    assert_eq!(
        server
            .authentication_status()
            .expect("mixed server status")
            .local_material_epoch(),
        server_overlap_epoch
    );
    client_datagram.release_send();
    server_datagram.release_send();
    assert_operation_and_delivery(
        &mut delayed_client_operation,
        &mut server_delivery,
        &delayed_client_packet,
        server_generation,
    )
    .await;
    assert_operation_and_delivery(
        &mut delayed_server_operation,
        &mut client_delivery,
        &delayed_server_packet,
        client_generation,
    )
    .await;
    assert_bidirectional_redirects(
        &client_redirect,
        &mut client_delivery,
        client_generation,
        &server_redirect,
        &mut server_delivery,
        server_generation,
        30,
    )
    .await;

    // Do not replace a still-live previous receive epoch. Traffic remains
    // available throughout the overlap; the next rotation starts only after
    // the bounded old-epoch acceptance window retires.
    wait_for_previous_epoch_retirement(&client, &server).await;

    // Move the server leaf and key to B while overlap trust is still active.
    let server_b_overlap_epoch = publish_material(
        &server_source,
        &mut server_changes,
        server_overlap_epoch,
        server_b_overlap.clone(),
    )
    .await;
    let both_b_overlap_epoch = rotate_pair(
        &client_config,
        &server_config,
        &client_manifest,
        &server_manifest,
        &expected_server,
        &expected_client,
        (&client, &server),
    )
    .await;
    assert_ne!(both_b_overlap_epoch, mixed_epoch);
    assert_eq!(
        client
            .authentication_status()
            .expect("B-overlap client status")
            .local_material_epoch(),
        client_b_overlap_epoch
    );
    assert_eq!(
        server
            .authentication_status()
            .expect("B-overlap server status")
            .local_material_epoch(),
        server_b_overlap_epoch
    );
    assert_bidirectional_redirects(
        &client_redirect,
        &mut client_delivery,
        client_generation,
        &server_redirect,
        &mut server_delivery,
        server_generation,
        40,
    )
    .await;

    wait_for_previous_epoch_retirement(&client, &server).await;

    // Remove A from both trust bundles only after both peers present B.
    let client_b_only_epoch = publish_material(
        &client_source,
        &mut client_changes,
        client_b_overlap_epoch,
        client_b_only,
    )
    .await;
    let server_b_only_epoch = publish_material(
        &server_source,
        &mut server_changes,
        server_b_overlap_epoch,
        server_b_only,
    )
    .await;

    // Negative controls isolate each B-only verifier. The opposite endpoint
    // presents an A leaf while trusting both roots, so the B-only side is the
    // side that must reject the old root.
    let (_old_server_source, old_server_config) = authenticated_server_config(server_a_overlap);
    let rejected_by_client = establish_pair(
        &client_config,
        &old_server_config,
        &client_manifest,
        &server_manifest,
        &expected_server,
        &expected_client,
    )
    .await;
    assert!(matches!(
        rejected_by_client.0,
        Err(IngressRedirectError::TlsBootstrapFailed)
    ));

    let (_old_client_source, old_client_config) = authenticated_client_config(client_a_overlap);
    let rejected_by_server = establish_pair(
        &old_client_config,
        &server_config,
        &client_manifest,
        &server_manifest,
        &expected_server,
        &expected_client,
    )
    .await;
    assert!(matches!(
        rejected_by_server.1,
        Err(IngressRedirectError::TlsBootstrapFailed)
    ));

    let final_epoch = rotate_pair(
        &client_config,
        &server_config,
        &client_manifest,
        &server_manifest,
        &expected_server,
        &expected_client,
        (&client, &server),
    )
    .await;
    assert_ne!(final_epoch, both_b_overlap_epoch);
    assert_eq!(
        client
            .authentication_status()
            .expect("B-only client status")
            .local_material_epoch(),
        client_b_only_epoch
    );
    assert_eq!(
        server
            .authentication_status()
            .expect("B-only server status")
            .local_material_epoch(),
        server_b_only_epoch
    );
    assert_bidirectional_redirects(
        &client_redirect,
        &mut client_delivery,
        client_generation,
        &server_redirect,
        &mut server_delivery,
        server_generation,
        50,
    )
    .await;
    let (client_shutdown, server_shutdown) =
        tokio::join!(client_redirect.shutdown(), server_redirect.shutdown());
    client_shutdown.expect("shut down client redirect endpoint");
    server_shutdown.expect("shut down server redirect endpoint");
}
