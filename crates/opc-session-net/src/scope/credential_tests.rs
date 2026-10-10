use super::{credential::*, proof::BootObservation};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opc_tls::AuthenticationTimeInterval;
use opc_types::Timestamp;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const ISSUER: &str = "https://cluster.example.test";
const JWKS: &str = "https://cluster.example.test/openid/v1/jwks";
struct Source {
    keys: Mutex<Vec<u8>>,
    reads: AtomicUsize,
    unavailable: bool,
}
#[async_trait::async_trait]
impl IssuerKeySource for Source {
    async fn discovery(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        if self.unavailable {
            return Err(BootstrapCredentialError::Unavailable);
        }
        Ok(serde_json::to_vec(&json!({"issuer":ISSUER,"jwks_uri":JWKS})).unwrap())
    }
    async fn jwks(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.keys.lock().unwrap().clone())
    }
}
fn observation() -> BootObservation {
    BootObservation {
        namespace: "test".into(),
        pod_name: "worker-0".into(),
        pod_uid: [0x22; 16],
        service_account: "worker".into(),
        service_account_uid: [0x33; 16],
        container_name: "worker".into(),
        container_id: "cri-o://exact-container".into(),
        started_at: "2026-10-01T00:00:00Z".into(),
    }
}
fn claims() -> Value {
    json!({
        "iss":ISSUER, "aud":["openpacketcore-scope-bootstrap"],
        "sub":"system:serviceaccount:test:worker", "iat":100, "nbf":100,"exp":200,
        "kubernetes.io":{"namespace":"test", "pod":{"name":"worker-0", "uid":uuid::Uuid::from_bytes([0x22;16]).to_string()},
            "serviceaccount":{"name":"worker","uid":uuid::Uuid::from_bytes([0x33;16]).to_string()}}
    })
}
fn key(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 32]).unwrap()
}
fn jwks(key: &SigningKey, kid: &str) -> Vec<u8> {
    let point = key.verifying_key().to_sec1_point(false);
    serde_json::to_vec(&json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":kid,
        "x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..])}]})).unwrap()
}
fn token(key: &SigningKey, header: Value, claims: Value) -> Vec<u8> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())).into_bytes()
}
fn bounds(earliest: i64, latest: i64) -> AuthenticationTimeInterval {
    let timestamp = |seconds| {
        Timestamp::from_offset_datetime(time::OffsetDateTime::from_unix_timestamp(seconds).unwrap())
    };
    AuthenticationTimeInterval::new(timestamp(earliest), timestamp(latest)).unwrap()
}
async fn verifier() -> (BootstrapCredentialVerifier, Arc<Source>) {
    let source = Arc::new(Source {
        keys: Mutex::new(jwks(&key(1), "one")),
        reads: AtomicUsize::new(0),
        unavailable: false,
    });
    let verifier =
        BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), source.clone())
            .await
            .unwrap();
    (verifier, source)
}
#[tokio::test(start_paused = true)]
async fn preflight_distinguishes_temporary_discovery_failure() {
    let source = Arc::new(Source {
        keys: Mutex::new(vec![]),
        reads: AtomicUsize::new(0),
        unavailable: true,
    });
    assert!(matches!(
        BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), source.clone()).await,
        Err(BootstrapCredentialError::Unavailable)
    ));
    assert_eq!(source.reads.load(Ordering::SeqCst), 0);
    let (_, source) = verifier().await;
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
}

struct FlakyDiscovery {
    attempts: AtomicUsize,
    failures: usize,
    error: BootstrapCredentialError,
    timeout: bool,
}
#[async_trait::async_trait]
impl IssuerKeySource for FlakyDiscovery {
    async fn discovery(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) < self.failures {
            if self.timeout {
                return std::future::pending().await;
            }
            return Err(self.error);
        }
        Ok(serde_json::to_vec(&json!({"issuer":ISSUER,"jwks_uri":JWKS})).unwrap())
    }
    async fn jwks(&self) -> Result<Vec<u8>, BootstrapCredentialError> {
        Ok(jwks(&key(1), "one"))
    }
}
#[tokio::test(start_paused = true)]
async fn activation_retries_transient_discovery_with_backoff_but_not_a_binding_refusal() {
    let source = Arc::new(FlakyDiscovery {
        attempts: AtomicUsize::new(0),
        failures: 2,
        error: BootstrapCredentialError::Unavailable,
        timeout: false,
    });
    let start = tokio::time::Instant::now();
    assert!(
        BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), source.clone())
            .await
            .is_ok()
    );
    assert_eq!(source.attempts.load(Ordering::SeqCst), 3);
    assert!(start.elapsed() >= std::time::Duration::from_millis(300));
    let refused = Arc::new(FlakyDiscovery {
        attempts: AtomicUsize::new(0),
        failures: usize::MAX,
        error: BootstrapCredentialError::UnsupportedPrerequisite,
        timeout: false,
    });
    assert!(matches!(
        BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), refused.clone()).await,
        Err(BootstrapCredentialError::UnsupportedPrerequisite)
    ));
    assert_eq!(refused.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn activation_retries_a_discovery_timeout_without_declaring_unsupported() {
    let source = Arc::new(FlakyDiscovery {
        attempts: AtomicUsize::new(0),
        failures: 1,
        error: BootstrapCredentialError::Unavailable,
        timeout: true,
    });
    let start = tokio::time::Instant::now();
    assert!(
        BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), source.clone())
            .await
            .is_ok()
    );
    assert_eq!(source.attempts.load(Ordering::SeqCst), 2);
    assert!(start.elapsed() >= std::time::Duration::from_millis(5100));
}

#[tokio::test(start_paused = true)]
async fn known_kid_signature_failure_refreshes_keys_with_a_shared_rate_limit() {
    let (verifier, source) = verifier().await;
    *source.keys.lock().unwrap() = jwks(&key(2), "one");
    let new = token(&key(2), json!({"alg":"ES256","kid":"one"}), claims());
    verifier
        .verify(&new, &observation(), bounds(100, 199))
        .await
        .unwrap();
    let refreshed = source.reads.load(Ordering::SeqCst);
    assert_eq!(refreshed, 2);
    let old = token(&key(1), json!({"alg":"ES256","kid":"one"}), claims());
    let unknown = token(&key(1), json!({"alg":"ES256","kid":"unknown"}), claims());
    for _ in 0..8 {
        for invalid in [&old, &unknown] {
            assert!(verifier
                .verify(invalid, &observation(), bounds(100, 199))
                .await
                .is_err());
        }
    }
    assert_eq!(source.reads.load(Ordering::SeqCst), refreshed);
    *source.keys.lock().unwrap() = jwks(&key(3), "one");
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let next = token(&key(3), json!({"alg":"ES256","kid":"one"}), claims());
    verifier
        .verify(&next, &observation(), bounds(100, 199))
        .await
        .unwrap();
    assert_eq!(source.reads.load(Ordering::SeqCst), refreshed + 1);
}
#[tokio::test]
async fn slots_sharing_a_service_account_still_require_their_exact_pod_name_and_uid() {
    let (verifier, _) = verifier().await;
    let first = observation();
    let mut second = observation();
    second.pod_name = "worker-1".into();
    second.pod_uid = [0x33; 16];
    let first_token = token(&key(1), json!({"alg":"ES256","kid":"one"}), claims());
    let mut second_claims = claims();
    second_claims["kubernetes.io"]["pod"]["name"] = json!(second.pod_name);
    second_claims["kubernetes.io"]["pod"]["uid"] =
        json!(uuid::Uuid::from_bytes(second.pod_uid).to_string());
    let second_token = token(&key(1), json!({"alg":"ES256","kid":"one"}), second_claims);
    verifier
        .verify(&first_token, &first, bounds(100, 199))
        .await
        .unwrap();
    verifier
        .verify(&second_token, &second, bounds(100, 199))
        .await
        .unwrap();
    assert!(verifier
        .verify(&first_token, &second, bounds(100, 199))
        .await
        .is_err());
    assert!(verifier
        .verify(&second_token, &first, bounds(100, 199))
        .await
        .is_err());
    for other in [
        super::proof::BootObservation {
            pod_name: second.pod_name.clone(),
            ..observation()
        },
        super::proof::BootObservation {
            pod_uid: second.pod_uid,
            ..observation()
        },
    ] {
        assert!(verifier
            .verify(&first_token, &other, bounds(100, 199))
            .await
            .is_err());
    }
}

#[tokio::test]
async fn pod_bound_signature_claims_and_entire_time_interval_are_required() {
    let (verifier, _) = verifier().await;
    let header = json!({"alg":"ES256","kid":"one","typ":"JWT"});
    let valid = token(&key(1), header.clone(), claims());
    verifier
        .verify(&valid, &observation(), bounds(100, 199))
        .await
        .unwrap();
    for time in [bounds(99, 101), bounds(190, 200), bounds(90, 201)] {
        assert!(verifier.verify(&valid, &observation(), time).await.is_err());
    }
    for pointer in [
        "/iss",
        "/aud/0",
        "/sub",
        "/kubernetes.io/namespace",
        "/kubernetes.io/pod/name",
        "/kubernetes.io/pod/uid",
        "/kubernetes.io/serviceaccount/name",
        "/kubernetes.io/serviceaccount/uid",
    ] {
        let mut bad = claims();
        *bad.pointer_mut(pointer).unwrap() = json!("forged");
        assert!(
            verifier
                .verify(
                    &token(&key(1), header.clone(), bad),
                    &observation(),
                    bounds(100, 199)
                )
                .await
                .is_err(),
            "{pointer}"
        );
    }
    let mut extra = claims();
    extra["aud"] = json!(["openpacketcore-scope-bootstrap", "other"]);
    assert!(verifier
        .verify(
            &token(&key(1), header.clone(), extra),
            &observation(),
            bounds(100, 199)
        )
        .await
        .is_err());
    assert!(verifier
        .verify(
            &token(&key(2), header, claims()),
            &observation(),
            bounds(100, 199)
        )
        .await
        .is_err());
}
#[tokio::test(start_paused = true)]
async fn attacker_key_urls_algorithm_confusion_and_unknown_kid_never_admit() {
    let (verifier, source) = verifier().await;
    for header in [
        json!({"alg":"ES256","kid":"one","jku":"https://attacker.test/key"}),
        json!({"alg":"HS256","kid":"one"}),
        json!({"alg":"none","kid":"one"}),
        json!({"alg":"ES256","kid":"one","crit":["unimplemented"]}),
    ] {
        assert!(verifier
            .verify(
                &token(&key(1), header, claims()),
                &observation(),
                bounds(100, 199)
            )
            .await
            .is_err());
    }
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    let unknown = token(&key(2), json!({"alg":"ES256","kid":"two"}), claims());
    assert!(verifier
        .verify(&unknown, &observation(), bounds(100, 199))
        .await
        .is_err());
    let after_refresh = source.reads.load(Ordering::SeqCst);
    for _ in 0..8 {
        assert!(verifier
            .verify(&unknown, &observation(), bounds(100, 199))
            .await
            .is_err());
    }
    assert_eq!(source.reads.load(Ordering::SeqCst), after_refresh);
    *source.keys.lock().unwrap() = jwks(&key(2), "two");
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    verifier
        .verify(&unknown, &observation(), bounds(100, 199))
        .await
        .unwrap();
}

#[tokio::test]
async fn independently_signed_rs256_fixture_is_accepted_and_signature_changes_fail() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/scope-bootstrap-rs256.json"
    ))
    .unwrap();
    let source = Arc::new(Source {
        keys: Mutex::new(serde_json::to_vec(&fixture["jwks"]).unwrap()),
        reads: AtomicUsize::new(0),
        unavailable: false,
    });
    let verifier = BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), source)
        .await
        .unwrap();
    let token = fixture["jwt"].as_str().unwrap();
    verifier
        .verify(token.as_bytes(), &observation(), bounds(100, 199))
        .await
        .unwrap();
    let mut segments = token.rsplitn(2, '.');
    let mut signature = URL_SAFE_NO_PAD.decode(segments.next().unwrap()).unwrap();
    let prefix = segments.next().unwrap();
    signature[30] ^= 1;
    let forged = format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(signature));
    assert!(verifier
        .verify(forged.as_bytes(), &observation(), bounds(100, 199))
        .await
        .is_err());
}

#[tokio::test]
async fn activation_rejects_malformed_public_keys_before_bootstrap() {
    let valid: Value = serde_json::from_slice(&jwks(&key(1), "one")).unwrap();
    let rsa: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/scope-bootstrap-rs256.json"
    ))
    .unwrap();
    let mut malformed = Vec::new();
    let mut off_curve = valid.clone();
    off_curve["keys"][0]["x"] = json!(URL_SAFE_NO_PAD.encode([0; 32]));
    off_curve["keys"][0]["y"] = json!(URL_SAFE_NO_PAD.encode([0; 32]));
    malformed.push(off_curve);
    let mut short = valid.clone();
    short["keys"][0]["x"] = json!(URL_SAFE_NO_PAD.encode([1; 31]));
    malformed.push(short);
    let mut padded = valid.clone();
    padded["keys"][0]["x"] = json!(format!("{}=", padded["keys"][0]["x"].as_str().unwrap()));
    malformed.push(padded);
    for exponent in [vec![0, 1, 0, 1], vec![2], vec![1]] {
        let mut bad = rsa["jwks"].clone();
        bad["keys"][0]["e"] = json!(URL_SAFE_NO_PAD.encode(exponent));
        malformed.push(bad);
    }
    for (case, keys) in malformed.into_iter().enumerate() {
        let source = Arc::new(Source {
            keys: Mutex::new(serde_json::to_vec(&keys).unwrap()),
            reads: AtomicUsize::new(0),
            unavailable: false,
        });
        assert!(
            matches!(
                BootstrapCredentialVerifier::activate(ISSUER.into(), JWKS.into(), source).await,
                Err(BootstrapCredentialError::Rejected)
            ),
            "malformed key case {case}"
        );
    }
}
