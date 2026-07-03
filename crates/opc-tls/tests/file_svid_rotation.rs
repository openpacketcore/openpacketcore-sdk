use opc_identity::FileSvidSource;
use opc_tls::TlsConfigBuilder;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn generate_identity_files(
    dir: &std::path::Path,
    spiffe_id: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    prefix: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Workload");
    params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).unwrap(),
    ));

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(1);

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();

    let cert_path = dir.join(format!("{prefix}-cert.pem"));
    let key_path = dir.join(format!("{prefix}-key.pem"));
    let bundle_path = dir.join("bundle.pem");

    fs::write(&cert_path, cert.pem() + &ca_cert.pem()).unwrap();
    fs::write(&key_path, key.serialize_pem()).unwrap();
    fs::write(&bundle_path, ca_cert.pem()).unwrap();

    (cert_path, key_path, bundle_path)
}

async fn do_handshake(client_config: rustls::ClientConfig, server_config: rustls::ServerConfig) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        tls.write_all(b"pong").await.unwrap();
    });

    let client_handle = tokio::spawn(async move {
        let connector = TlsConnector::from(std::sync::Arc::new(client_config));
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let mut tls = connector
            .connect("localhost".try_into().unwrap(), stream)
            .await
            .unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    });

    timeout(Duration::from_secs(5), async {
        let _ = server_handle.await;
        let _ = client_handle.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn test_file_svid_source_rotates_tls_identity() {
    let dir =
        std::env::temp_dir().join(format!("opc-tls-file-svid-rotation-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let spiffe1 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/0";
    let (cert_path, key_path, bundle_path) =
        generate_identity_files(&dir, spiffe1, &ca_cert, &ca_key, "id");

    let source = FileSvidSource::new(
        &cert_path,
        &key_path,
        vec![&bundle_path],
        Some(Duration::from_millis(100)),
    );

    timeout(Duration::from_secs(5), async {
        let rx = source.subscribe();
        loop {
            if rx.borrow().is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("initial identity should be observed within timeout");

    let state_rx = source.subscribe();

    let client_config = TlsConfigBuilder::new(state_rx.clone())
        .allow_any_trusted_peer()
        .build_client_config()
        .unwrap();
    let server_config = TlsConfigBuilder::new(state_rx)
        .allow_any_trusted_peer()
        .build_server_config()
        .unwrap();

    // Handshake with initial identity.
    do_handshake(client_config, server_config).await;

    // Rotate to a new identity (different SPIFFE ID).
    let spiffe2 = "spiffe://test-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1";
    let (cert_path2, key_path2, bundle_path2) =
        generate_identity_files(&dir, spiffe2, &ca_cert, &ca_key, "id2");

    // Overwrite the original files so FileSvidSource picks up the change.
    fs::copy(&cert_path2, &cert_path).unwrap();
    fs::copy(&key_path2, &key_path).unwrap();
    if bundle_path2 != bundle_path {
        fs::copy(&bundle_path2, &bundle_path).unwrap();
    }

    // Wait for the rotation to be observed.
    let mut event_rx = source.subscribe_events();
    let rx = source.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_event = None;
    let updated = loop {
        while let Ok(event) = event_rx.try_recv() {
            last_event = Some(event);
        }
        if let Some(state) = rx.borrow().clone() {
            if state.identity.spiffe_id.as_str() == spiffe2 {
                break state;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "rotation should be observed within timeout; last event: {last_event:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert_eq!(updated.identity.spiffe_id.as_str(), spiffe2);

    // Perform a second handshake; the new certs must be usable.
    let state_rx2 = source.subscribe();
    let client_config2 = TlsConfigBuilder::new(state_rx2.clone())
        .allow_any_trusted_peer()
        .build_client_config()
        .unwrap();
    let server_config2 = TlsConfigBuilder::new(state_rx2)
        .allow_any_trusted_peer()
        .build_server_config()
        .unwrap();

    do_handshake(client_config2, server_config2).await;

    let _ = fs::remove_dir_all(&dir);
}
