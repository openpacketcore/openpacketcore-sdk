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

fn provider_error_cases() -> Vec<(KeyError, bool)> {
    use opc_key::KeyCustodyOperationError as C;
    let mut cases = vec![
        (KeyError::Unavailable, false),
        (KeyError::ProviderUnusable, false),
        (KeyError::NotFound, true),
        (KeyError::OperationFailed, true),
        (
            KeyError::DuplicateKeyId {
                key_id: KeyId::new("duplicate").unwrap(),
            },
            false,
        ),
        (
            KeyError::InvalidMetadata {
                field: "scope",
                message: "invalid".into(),
            },
            false,
        ),
        (
            KeyError::InvalidKeyId {
                message: "wrong provider".into(),
            },
            false,
        ),
        (KeyError::InvalidAlgorithm { id: 99 }, false),
        (KeyError::RotationFailed, false),
    ];
    cases.extend(
        [
            C::NotInstalled,
            C::IdentityChanged,
            C::ValidationChanged,
            C::CapabilityNotAdmitted,
            C::CapabilityWithdrawn,
            C::ProviderOperationFailed,
            C::InvalidProviderOutput,
        ]
        .into_iter()
        .map(|error| (KeyError::CustodyOperation(error), false)),
    );
    cases
}

#[test]
fn every_nonverdict_provider_error_retains_recovery_rows() {
    let mut failures = Vec::new();
    for (index, (error, definitive)) in provider_error_cases().into_iter().enumerate() {
        if !definitive
            && std::panic::catch_unwind(|| {
                check_recovery(error.clone(), 40_000_000 + index as u64 * 10_000)
            })
            .is_err()
        {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "nonverdict errors erased recovery state: {failures:?}"
    );
}

#[test]
fn positive_key_and_ciphertext_verdicts_authorize_terminal_cleanup() {
    for (index, error) in [KeyError::NotFound, KeyError::OperationFailed]
        .into_iter()
        .enumerate()
    {
        matrix(41_000_000 + index as u64 * 10_000, |row| {
            let provider = Provider::new();
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            let initial = driver::create(&provider, &mut store, &row).unwrap();
            provider.inject_key_error(Some(error.clone()));
            let Recovery::Terminal(mut cleanup) = remedy::recover(
                &provider,
                &owners,
                store.fenced_read(&initial, row.key).unwrap(),
            )
            .unwrap() else {
                panic!("a positive verdict must authorize cleanup");
            };
            cleanup.commit(&mut store, Cut::Complete).unwrap();
            assert!(store.inspect(row.key).is_none());
        });
    }
}

#[tokio::test]
async fn kms_unclassified_error_replies_retain_recovery_rows() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut failures = Vec::new();
    for (index, message) in [
        "access denied",
        "authentication failed",
        "internal server error",
        "route not found",
        "",
        "client certificate not found",
    ]
    .into_iter()
    .enumerate()
    {
        let path =
            std::env::temp_dir().join(format!("recovery-reply-{}-{index}", std::process::id()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let reply = format!(r#"{{"status":"error","error_message":"{message}"}}"#);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let size = stream.read_u32().await.unwrap();
            let mut request = vec![0; size as usize];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_u32(reply.len() as u32).await.unwrap();
            stream.write_all(reply.as_bytes()).await.unwrap();
        });
        let provider =
            KmsKeyProvider::new(path.display().to_string(), None, Duration::from_secs(2));
        let error = provider
            .get_key_by_id(&KeyId::new("recovery-fixture-envelope").unwrap())
            .await
            .unwrap_err();
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
        if std::panic::catch_unwind(|| {
            check_recovery(error.clone(), 42_000_000 + index as u64 * 10_000)
        })
        .is_err()
        {
            failures.push((message, error));
        }
    }
    assert!(
        failures.is_empty(),
        "unclassified replies erased recovery state: {failures:?}"
    );
}

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
        let policy = match &result {
            Err(driver::Error::Key(error)) => error.retry_policy(),
            _ => None,
        };
        let expected_policy = if error == KeyError::Unavailable {
            envelope::RetryPolicy::BoundedBackoff
        } else {
            envelope::RetryPolicy::AwaitProviderRepair
        };
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
        assert_eq!(
            policy,
            Some(expected_policy),
            "retain the provider retry policy"
        );
        assert!(
            !expected_policy.may_retry(0, 3, false, true),
            "repair does not bypass backoff"
        );
        assert!(
            !expected_policy.may_retry(3, 3, true, true),
            "repair does not extend the budget"
        );
        assert_eq!(
            expected_policy.may_retry(0, 3, true, false),
            error == KeyError::Unavailable,
            "configuration retries wait for repair"
        );
        let current = store.inspect(row.key).expect("retain the recovery row");
        assert_eq!(current.version, stored.version);
        assert_eq!(current.envelope.as_slice(), stored.envelope.as_slice());
        assert_eq!(provider.calls(), (calls.0, calls.1 + 2), "no retry loop");

        // Repair the provider without altering the row; its exact replay survives.
        provider.inject_key_error(None);
        assert!(expected_policy.may_retry(0, 3, true, true));
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
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
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
    check_recovery(error, 2_730_000);
}
