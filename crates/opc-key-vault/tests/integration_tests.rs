use std::str::FromStr;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use opc_key::{errors::KeyError, scope::KeyPurpose, KeyProvider};
use opc_key_vault::VaultKeyProvider;
use opc_types::TenantId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

struct MockResponse {
    status: u16,
    body: String,
}

struct MockVault {
    url: url::Url,
    /// Request lines (`POST /v1/... HTTP/1.1`) seen by the mock, in order.
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockVault {
    async fn new(responses: Arc<Mutex<Vec<MockResponse>>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };

                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request_line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                seen.lock().await.push(request_line);

                let resp = {
                    let mut lock = responses.lock().await;
                    if lock.is_empty() {
                        MockResponse {
                            status: 500,
                            body: r#"{"errors":[]}"#.into(),
                        }
                    } else {
                        lock.remove(0)
                    }
                };

                let reason = match resp.status {
                    200 => "OK",
                    403 => "Forbidden",
                    500 => "Internal Server Error",
                    _ => "Unknown",
                };

                let http = format!(
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    resp.status,
                    reason,
                    resp.body.len(),
                    resp.body
                );

                let _ = stream.write_all(http.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        Self {
            url: url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            requests,
        }
    }

    async fn request_paths(&self) -> Vec<String> {
        self.requests.lock().await.clone()
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("valid tenant")
}

/// A fixed Transit-wrapped data-key blob the mock hands out; the provider
/// treats it as opaque, so any bytes work as long as datakey and decrypt
/// responses agree.
const WRAPPED_DEK: [u8; 60] = [0x77; 60];

fn vault_ciphertext() -> String {
    format!("vault:v1:{}", BASE64.encode(WRAPPED_DEK))
}

/// Response of `datakey/plaintext/<name>`: fresh plaintext plus the wrapped copy.
fn datakey_response(plaintext: &[u8; 32]) -> String {
    format!(
        r#"{{"data":{{"plaintext":"{}","ciphertext":"{}"}}}}"#,
        BASE64.encode(plaintext),
        vault_ciphertext()
    )
}

/// Response of `decrypt/<name>`: the unwrapped data key.
fn decrypt_response(plaintext: &[u8; 32]) -> String {
    format!(
        r#"{{"data":{{"plaintext":"{}"}}}}"#,
        BASE64.encode(plaintext)
    )
}

#[tokio::test]
async fn success_round_trip() {
    let responses = Arc::new(Mutex::new(vec![MockResponse {
        status: 200,
        body: datakey_response(&[0xab; 32]),
    }]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let handle = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .expect("get active key");

    assert_eq!(handle.purpose(), KeyPurpose::Config);
    assert_eq!(handle.tenant(), &tenant());
    assert!(handle
        .key_id()
        .as_str()
        .starts_with("vault:tenant-a_config:1:"));

    // Encrypt/decrypt round-trip via KeyHandle
    let aad = opc_key::EnvelopeAad::config(
        tenant(),
        1,
        opc_key::ConfigAad::new(
            opc_types::TxId::from_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            None,
            opc_types::Timestamp::from_str("2026-05-28T08:30:00Z").unwrap(),
            "principal",
            opc_types::SchemaDigest::from_str(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            "running",
        )
        .unwrap(),
    );

    let nonce = [0u8; 12];
    let plaintext = b"hello world";

    let encrypted = handle
        .encrypt_payload(&aad, plaintext, nonce)
        .expect("encrypt");

    let decrypted = handle
        .decrypt_payload(&aad, &encrypted.aad, &encrypted.ciphertext_and_tag, nonce)
        .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn auth_failure_403() {
    let responses = Arc::new(Mutex::new(vec![MockResponse {
        status: 403,
        body: r#"{"errors":["permission denied"]}"#.into(),
    }]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "bad-token".into(), "transit".into());

    let err = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .expect_err("should fail");

    assert_eq!(err, KeyError::Unavailable);
}

#[tokio::test]
async fn server_error_500() {
    let responses = Arc::new(Mutex::new(vec![MockResponse {
        status: 500,
        body: r#"{"errors":["internal error"]}"#.into(),
    }]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let err = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .expect_err("should fail");

    assert_eq!(err, KeyError::Unavailable);
}

#[tokio::test]
async fn malformed_json_response() {
    let responses = Arc::new(Mutex::new(vec![MockResponse {
        status: 200,
        body: "not-json".into(),
    }]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let err = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .expect_err("should fail");

    assert_eq!(err, KeyError::Unavailable);
}

/// `get_key_by_id` must recover the SAME material the active key was issued
/// with, by unwrapping the ciphertext embedded in the key id via Transit
/// `decrypt` — this is what makes envelope decryption work after restart.
#[tokio::test]
async fn get_key_by_id_recovers_same_material() {
    let dek = [0xcd_u8; 32];
    let responses = Arc::new(Mutex::new(vec![
        MockResponse {
            status: 200,
            body: datakey_response(&dek),
        },
        MockResponse {
            status: 200,
            body: decrypt_response(&dek),
        },
    ]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let active = provider
        .get_active_key(KeyPurpose::Config, &tenant())
        .await
        .expect("get active key");

    let by_id = provider
        .get_key_by_id(active.key_id())
        .await
        .expect("get key by id");

    assert_eq!(by_id.key_id(), active.key_id());
    assert_eq!(by_id.purpose(), KeyPurpose::Config);
    assert_eq!(by_id.tenant(), &tenant());

    // Same material ⇒ identical keyed digests.
    assert_eq!(
        active.keyed_digest(b"test-domain", b"probe"),
        by_id.keyed_digest(b"test-domain", b"probe"),
    );

    // The lookup must have gone through the Transit decrypt endpoint.
    let paths = mock.request_paths().await;
    assert_eq!(paths.len(), 2);
    assert!(paths[0].starts_with("POST /v1/transit/datakey/plaintext/tenant-a_config "));
    assert!(paths[1].starts_with("POST /v1/transit/decrypt/tenant-a_config "));
}

#[tokio::test]
async fn get_key_by_id_rejects_foreign_ids() {
    let responses = Arc::new(Mutex::new(vec![]));
    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let key_id = opc_key::KeyId::new("tenant-a_config").unwrap();
    let err = provider
        .get_key_by_id(&key_id)
        .await
        .expect_err("should reject non-vault key id");
    assert!(matches!(err, KeyError::InvalidKeyId { .. }));

    // Must fail locally without ever calling Vault.
    assert!(mock.request_paths().await.is_empty());
}

#[tokio::test]
async fn rotate_key_rotates_and_returns_fresh_id() {
    let responses = Arc::new(Mutex::new(vec![
        MockResponse {
            status: 200,
            body: r#"{}"#.into(),
        },
        MockResponse {
            status: 200,
            body: datakey_response(&[0xef; 32]),
        },
    ]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let key_id = provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotate key");

    assert!(key_id.as_str().starts_with("vault:tenant-a_session:1:"));

    let paths = mock.request_paths().await;
    assert_eq!(paths.len(), 2);
    assert!(paths[0].starts_with("POST /v1/transit/keys/tenant-a_session/rotate "));
    assert!(paths[1].starts_with("POST /v1/transit/datakey/plaintext/tenant-a_session "));
}

#[tokio::test]
async fn rotate_key_failure_maps_to_rotation_failed() {
    let responses = Arc::new(Mutex::new(vec![MockResponse {
        status: 500,
        body: r#"{"errors":["rotation denied"]}"#.into(),
    }]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let err = provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect_err("should fail");
    assert_eq!(err, KeyError::RotationFailed);
}

/// Full envelope round trip through `opc-crypto`, exercising the realistic
/// Vault flow: encrypt uses a fresh data key; decrypt unwraps the wrapped
/// copy embedded in the envelope's key id.
#[tokio::test]
async fn golden_envelope_round_trip() {
    let dek = [0x42_u8; 32];
    let responses = Arc::new(Mutex::new(vec![
        MockResponse {
            status: 200,
            body: datakey_response(&dek),
        },
        MockResponse {
            status: 200,
            body: decrypt_response(&dek),
        },
    ]));

    let mock = MockVault::new(responses).await;
    let provider = VaultKeyProvider::new(mock.url.clone(), "token".into(), "transit".into());

    let aad = opc_key::EnvelopeAad::config(
        tenant(),
        1,
        opc_key::ConfigAad::new(
            opc_types::TxId::from_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            None,
            opc_types::Timestamp::from_str("2026-05-28T08:30:00Z").unwrap(),
            "principal",
            opc_types::SchemaDigest::from_str(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            "running",
        )
        .unwrap(),
    );

    let plaintext = b"golden payload";
    let envelope = opc_crypto::encrypt_envelope(&provider, &aad, plaintext)
        .await
        .expect("encrypt envelope");

    let decrypted = opc_crypto::decrypt_envelope(&provider, &aad, &envelope)
        .await
        .expect("decrypt envelope");

    assert_eq!(decrypted.as_slice(), plaintext);

    let paths = mock.request_paths().await;
    assert!(paths[0].contains("/datakey/plaintext/"));
    assert!(paths[1].contains("/decrypt/"));
}
