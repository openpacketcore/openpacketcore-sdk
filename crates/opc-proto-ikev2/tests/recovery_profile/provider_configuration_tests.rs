//! A live provider-channel failure is not evidence for erasing a recovery row.

use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use opc_key::{KeyError, KeyId, KeyProvider, KmsKeyProvider};

use super::{
    authority::{EpochOwners, Transport},
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    ke,
    lifecycle::matrix,
    module,
    remedy::{self, Recovery},
    store::CasStore,
};

fn check_recovery(error: KeyError, tag: u64) {
    matrix(tag, |row| {
        let provider = Provider::new();
        let mut store = CasStore::new(7);
        let owners = EpochOwners::new(7);
        let initial = driver::create(&provider, &mut store, &row).unwrap();
        let mut runtime = Runtime::restore(
            &provider,
            &owners,
            &store.fenced_read(&initial, row.key).unwrap(),
            false,
        )
        .unwrap();
        runtime
            .reserve(
                &provider,
                &mut store,
                19,
                3,
                100,
                Cut::Complete,
                Cut::Complete,
            )
            .unwrap();
        let operation = ke::draft(&runtime.row, 19, ke::KINDS[0]);
        assert!(ke::persist_ke(
            &mut runtime,
            &provider,
            &mut store,
            operation,
            Cut::Complete
        )
        .unwrap());
        drop(runtime);

        let stored = store.inspect(row.key).unwrap().clone();
        let before = (store.dispatches, store.publications, module::counts());
        let calls = provider.calls();
        provider.inject_key_error(Some(error.clone()));
        // No plaintext is returned even though the ciphertext remains valid.
        assert!(envelope::unseal(&provider, row.key, &stored).is_err());
        let result = remedy::recover(
            &provider,
            &owners,
            store.fenced_read(&initial, row.key).unwrap(),
        );
        let backpressured = matches!(
            &result,
            Err(driver::Error::Key(envelope::Error::Backpressure))
        );
        let mut transport = Transport::default();
        match result {
            Ok(Recovery::Terminal(mut cleanup)) => {
                // Exercise the real consumer decision, exposing accidental erasure.
                cleanup.commit(&mut store, Cut::Complete).unwrap();
            }
            Ok(Recovery::Runtime(mut runtime)) => {
                runtime.dispatch_replay(&mut transport).unwrap();
            }
            Err(_) => {}
        }
        assert_eq!(
            (store.dispatches, store.publications, module::counts()),
            before,
            "an unusable provider must not authorize cleanup or a new crypto effect"
        );
        assert!(transport.submitted.is_empty(), "no packet may be released");
        assert!(
            backpressured,
            "provider configuration requires backpressure"
        );
        let current = store.inspect(row.key).expect("retain the recovery row");
        assert_eq!(current.version, stored.version);
        assert_eq!(current.envelope.as_slice(), stored.envelope.as_slice());
        assert_eq!(provider.calls(), (calls.0, calls.1 + 2), "no retry loop");

        // Repair the provider without altering the row; its exact replay survives.
        provider.inject_key_error(None);
        let Recovery::Runtime(mut runtime) = remedy::recover(
            &provider,
            &owners,
            store.fenced_read(&initial, row.key).unwrap(),
        )
        .unwrap() else {
            panic!("provider repair must restore the original row")
        };
        assert!(runtime.dispatch_replay(&mut transport).unwrap());
        assert_eq!(transport.submitted.len(), 1);
    });
}

#[tokio::test]
async fn kms_certificate_configuration_during_recovery_deletes_and_releases_nothing() {
    use tokio_rustls::rustls;
    let generated = rcgen::generate_simple_self_signed(vec!["kms.example".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(crypto.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key.into())
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        assert!(tokio_rustls::TlsAcceptor::from(Arc::new(server))
            .accept(stream)
            .await
            .is_err());
    });
    let provider = KmsKeyProvider::new(
        endpoint,
        Some(tokio_rustls::TlsConnector::from(Arc::new(client))),
        Duration::from_secs(2),
    )
    .with_server_name("kms.example");
    let error = provider
        .get_key_by_id(&KeyId::new("recovery-fixture-envelope").unwrap())
        .await
        .expect_err("the certificate is untrusted");
    server.await.unwrap();
    check_recovery(error, 2_680_000);
}

#[tokio::test]
async fn kms_permission_configuration_during_recovery_deletes_and_releases_nothing() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "kms-perm-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0)).unwrap();
    let denied = std::os::unix::net::UnixStream::connect(&path).unwrap_err();
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    let provider = KmsKeyProvider::new(path.display().to_string(), None, Duration::from_secs(2));
    let error = provider
        .get_key_by_id(&KeyId::new("recovery-fixture-envelope").unwrap())
        .await
        .expect_err("the socket denies access");
    drop(listener);
    std::fs::remove_file(path).unwrap();
    check_recovery(error, 2_690_000);
}

#[tokio::test]
async fn kms_endpoint_configuration_during_recovery_deletes_and_releases_nothing() {
    let provider = KmsKeyProvider::new("unix://".into(), None, Duration::from_secs(2));
    let error = provider
        .get_key_by_id(&KeyId::new("recovery-fixture-envelope").unwrap())
        .await
        .expect_err("the endpoint has no path");
    check_recovery(error, 2_700_000);
}
