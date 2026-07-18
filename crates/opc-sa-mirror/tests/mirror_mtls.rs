//! End-to-end mirror path over real mTLS on loopback: producer client →
//! receiving server → in-memory standby holder → validated live-mirrored
//! takeover.

use std::sync::Arc;
use std::time::Duration;

use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_ipsec_lb::{
    ResumeKeySource, SaId, SendIvCounterMode, SendIvForwardJump, MIN_SEND_IV_FORWARD_JUMP,
};
use opc_sa_mirror::{
    InMemoryStandbyHolder, KeyEpoch, KeymatFormat, MirroredSaKeymat, RemoteMirrorProducer,
    RepinTakeoverParams, SaCounterCheckpoint, SaMirrorError, SaMirrorInstall, SaMirrorProducer,
    SaMirrorReceiver, StandbyKeymatSource,
};
use opc_tls::TlsConfigBuilder;
use zeroize::Zeroizing;

struct TestMtls {
    server_config: Arc<opc_tls::ServerConfig>,
    client_config: Arc<opc_tls::ClientConfig>,
}

fn mtls_configs() -> TestMtls {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "SA Mirror Test CA");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca cert");

    let (server_cert, server_key) = signed_leaf(
        &ca,
        "Mirror Standby",
        "spiffe://test-domain/tenant/test/ns/default/sa/mirror-standby/nf/epdg/instance/1",
    );
    let (client_cert, client_key) = signed_leaf(
        &ca,
        "Mirror Owner",
        "spiffe://test-domain/tenant/test/ns/default/sa/mirror-owner/nf/epdg/instance/0",
    );
    let server_state = identity_state_from_pem(
        &(server_cert.pem() + &ca.pem()),
        &server_key.serialize_pem(),
        &ca.pem(),
    );
    let client_state = identity_state_from_pem(
        &(client_cert.pem() + &ca.pem()),
        &client_key.serialize_pem(),
        &ca.pem(),
    );
    let (_server_tx, server_rx) = tokio::sync::watch::channel(Some(server_state));
    let (_client_tx, client_rx) = tokio::sync::watch::channel(Some(client_state));
    let server_config = TlsConfigBuilder::new(server_rx)
        .allow_any_trusted_peer()
        .build_server_config()
        .expect("server tls config");
    let client_config = TlsConfigBuilder::new(client_rx)
        .allow_any_trusted_peer()
        .build_client_config()
        .expect("client tls config");

    TestMtls {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
    }
}

fn signed_leaf(
    issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
    common_name: &str,
    spiffe_id: &str,
) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("spiffe id"),
    ));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(1);

    let key = rcgen::KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, issuer).expect("leaf cert");
    (cert, key)
}

fn identity_state_from_pem(
    cert_chain_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> opc_identity::IdentityState {
    let ca_certs = parse_certs_pem(ca_pem).expect("ca pem");
    let cert_chain = parse_certs_pem(cert_chain_pem).expect("cert chain pem");
    let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain,
        certificates: ca_certs,
    });
    let private_key = parse_key_pem(key_pem).expect("key pem");
    build_identity_state(cert_chain, private_key, trust_bundles).expect("identity state")
}

fn install(sa: SaId, epoch: u64, bytes: &[u8]) -> SaMirrorInstall {
    SaMirrorInstall {
        sa,
        epoch: KeyEpoch::new(epoch).expect("epoch"),
        keymat: MirroredSaKeymat::new(
            KeymatFormat::new(7).expect("format"),
            Zeroizing::new(bytes.to_vec()),
        )
        .expect("keymat"),
        send_iv_next: 100,
        replay_highest_accepted: 20,
    }
}

fn esp_params() -> RepinTakeoverParams {
    RepinTakeoverParams {
        forward_jump: SendIvForwardJump {
            forward_jump: MIN_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        },
        max_reopened_packets: 64,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn producer_mirrors_over_mtls_and_standby_yields_a_validated_takeover() {
    let mtls = mtls_configs();
    let holder = Arc::new(InMemoryStandbyHolder::new());
    let receiver = SaMirrorReceiver::new(holder.clone(), mtls.server_config.clone());
    let (handle, addr) = receiver
        .listen("127.0.0.1:0".parse().expect("bind addr"))
        .await
        .expect("listen");

    let producer = RemoteMirrorProducer::new(
        addr,
        mtls.client_config.clone(),
        Some(Duration::from_secs(5)),
    );

    let sa = SaId::Esp { spi: 0x1122_3344 };
    producer
        .mirror_install(install(sa, 1, &[0xA5; 36]))
        .await
        .expect("install");
    producer
        .mirror_checkpoint(SaCounterCheckpoint {
            sa,
            epoch: KeyEpoch::new(1).expect("epoch"),
            send_iv_next: 7_000,
            replay_highest_accepted: 6_500,
        })
        .await
        .expect("checkpoint");

    // Rejections travel back as typed errors, not free text.
    assert!(matches!(
        producer.mirror_install(install(sa, 1, &[0x5A; 36])).await,
        Err(SaMirrorError::Conflict { .. })
    ));

    // A checkpoint for an SA the standby does not hold reports NotFound so
    // the producer knows to re-install.
    assert!(matches!(
        producer
            .mirror_checkpoint(SaCounterCheckpoint {
                sa: SaId::Esp { spi: 99 },
                epoch: KeyEpoch::new(1).expect("epoch"),
                send_iv_next: 5,
                replay_highest_accepted: 0,
            })
            .await,
        Err(SaMirrorError::NotFound)
    ));

    // Owner loss: standby yields the exact mirrored keymat with validated
    // live-mirrored resume evidence.
    let takeover = holder.take_for_repin(sa, esp_params()).expect("takeover");
    assert_eq!(takeover.resume.key_source, ResumeKeySource::LiveMirrored);
    assert_eq!(takeover.resume.checkpointed_send_iv_next, 7_000);
    assert_eq!(
        takeover.resume.restored_send_iv_next,
        7_000 + MIN_SEND_IV_FORWARD_JUMP
    );
    assert_eq!(takeover.keymat.expose_secret_bytes(), &[0xA5; 36]);
    takeover
        .resume
        .validate_for_repin(sa)
        .expect("valid resume");

    // Teardown withdraw of an already-taken SA is idempotent.
    producer
        .mirror_withdraw(sa, KeyEpoch::new(1).expect("epoch"))
        .await
        .expect("withdraw");

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_clients_cannot_reach_the_sink() {
    let mtls = mtls_configs();
    let holder = Arc::new(InMemoryStandbyHolder::new());
    let receiver = SaMirrorReceiver::new(holder.clone(), mtls.server_config.clone())
        .with_idle_timeout(Duration::from_millis(200));
    let (handle, addr) = receiver
        .listen("127.0.0.1:0".parse().expect("bind addr"))
        .await
        .expect("listen");

    // A raw TCP writer that never speaks TLS is reaped without any frame
    // reaching the sink.
    use tokio::io::AsyncWriteExt;
    let mut plain = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let _ = plain.write_all(b"not a tls client hello").await;
    let sa = SaId::Esp { spi: 1 };
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(holder.held_epoch(sa), None);
    assert!(matches!(
        holder.take_for_repin(sa, esp_params()),
        Err(SaMirrorError::NotFound)
    ));

    handle.abort();
}
