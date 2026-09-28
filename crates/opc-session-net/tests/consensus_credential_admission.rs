//! A consensus peer reports whether its local credentials can admit a new
//! authenticated connection. The consensus store suspends a voter's timer
//! elections while they cannot (#1005).
//!
//! Credentials admit connections only while the material is usable and the
//! local certificate has not entered its rotation drain window. A connection
//! established inside that window would be retired as soon as it is admitted.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    ConnectionLifecyclePolicy, RemoteAddrResolver, RemoteSessionConsensusPeer, SessionClusterId,
    SessionConfigurationEpoch, SessionConfigurationGeneration, SessionReplicationManifest,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionConsensusPeer,
};
use opc_tls::{AuthenticatedClientConfig, TlsConfigBuilder};

const CLIENT_REPLICA: u16 = 1;
const SERVER_REPLICA: u16 = 2;
const DRAIN_WINDOW: Duration = Duration::from_secs(30);

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

    fn identity_state(
        &self,
        replica: u16,
        not_after: time::OffsetDateTime,
    ) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("replica-{replica}"));
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(replica_spiffe(replica)).expect("SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = not_after;
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
        identity: Option<opc_identity::IdentityState>,
    ) -> (
        tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
        Option<AuthenticatedClientConfig>,
    ) {
        let (sender, receiver) = tokio::sync::watch::channel(identity);
        let config = TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .ok();
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
            SessionClusterId::new("consensus-credential-admission").expect("cluster ID"),
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
        Duration::from_secs(30 * 60),
        DRAIN_WINDOW,
        Duration::from_millis(2),
        Duration::from_millis(10),
        Duration::ZERO,
    )
    .expect("test lifecycle policy")
}

fn peer(config: AuthenticatedClientConfig) -> RemoteSessionConsensusPeer {
    let binding = manifest()
        .bind_local(replica_id(CLIENT_REPLICA))
        .expect("client binding")
        .bind_remote(replica_id(SERVER_REPLICA))
        .expect("remote binding");
    RemoteSessionConsensusPeer::new_with_resolver(
        binding,
        resolver("127.0.0.1:9".parse().expect("unused address")),
        config,
        Some(Duration::from_secs(5)),
    )
    .with_connection_lifecycle(lifecycle_policy())
}

#[tokio::test]
async fn local_credentials_admit_connections_only_outside_the_drain_window() {
    let pki = TestPki::new();
    let now = time::OffsetDateTime::now_utc();

    let (_long_lived_source, long_lived) = pki.client_config(Some(
        pki.identity_state(CLIENT_REPLICA, now + time::Duration::days(1)),
    ));
    assert!(
        peer(long_lived.expect("long-lived client config")).local_credentials_admit_connections(),
        "unexpired material far from its drain window admits connections"
    );

    let (_draining_source, draining) = pki.client_config(Some(
        pki.identity_state(CLIENT_REPLICA, now + time::Duration::seconds(10)),
    ));
    assert!(
        !peer(draining.expect("draining client config")).local_credentials_admit_connections(),
        "material inside its rotation drain window admits no usable connection"
    );

    let (_absent_source, absent) = pki.client_config(None);
    let absent = absent.expect("client config awaiting its first material");
    assert!(
        !peer(absent).local_credentials_admit_connections(),
        "material that has not been accepted admits no connection"
    );
}
