use http::StatusCode;
use opc_sbi::{
    auth::{ClientTokenCache, SbiAuth, SbiAuthRequest, SbiJwtValidator, TokenProvider},
    client::{builder::SbiClientBuilder, CircuitState},
    retry::{Jitter, RetryPolicy},
    server::builder::SbiServerBuilder,
    testkit::{generate_test_token, MockConsumer, MockJwksResolver, MockProducer, TokenFixtures},
};
use opc_types::{NfInstanceId, NfType, SpiffeId, TenantId};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_mock_producer_consumer_roundtrip() {
    let producer = MockProducer::start().await;
    let consumer = MockConsumer::new();

    let mut headers = HashMap::new();
    headers.insert("x-test-header".to_string(), "test-value".to_string());

    // Set response override on producer
    let body_bytes = b"hello openpacketcore".to_vec();
    producer.set_override(
        "/hello",
        StatusCode::OK,
        headers.clone(),
        body_bytes.clone(),
    );

    let url = format!("{}/hello", producer.url());
    let (status, resp_headers, resp_body) = consumer.send_get(&url, HashMap::new()).await.unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        resp_headers.get("x-test-header").map(|s| s.as_str()),
        Some("test-value")
    );
    assert_eq!(resp_body, body_bytes);

    // Verify request was recorded
    let reqs = producer.get_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/hello");
}

#[tokio::test]
async fn test_client_body_limit_violation() {
    let producer = MockProducer::start().await;

    // Configure response override with a 500-byte body
    let large_body = vec![b'A'; 500];
    producer.set_override("/large", StatusCode::OK, HashMap::new(), large_body);

    // Build client with a 100-byte body limit
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_body_limit(100)
        .build()
        .unwrap();
    let consumer = MockConsumer::with_client(client);

    let url = format!("{}/large", producer.url());
    let result = consumer.send_get(&url, HashMap::new()).await;

    // Must fail due to body limit
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("limit exceeded"));
}

#[tokio::test]
async fn test_server_admission_control_overload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // SbiServerBuilder with max_concurrency = 0 to reject everything
    let server = SbiServerBuilder::new(addr).with_max_concurrency(0);

    let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));

    let server_task = tokio::spawn(async move {
        let _ = server.run_with_listener(listener, app).await;
    });

    // This test verifies the first overload response. Retrying a deliberate
    // 503 would honor the server's `Retry-After: 30` header twice and turn an
    // immediate assertion into a deterministic 60-second workspace stall.
    let retry_policy = RetryPolicy::new(1, Duration::ZERO, Duration::ZERO, Jitter::None);
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_retry_policy(retry_policy)
        .build()
        .unwrap();
    let consumer = MockConsumer::with_client(client);

    let url = format!("http://{addr}");
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        consumer.send_get(&url, HashMap::new()),
    )
    .await;

    server_task.abort();
    let server_exit = server_task.await;
    assert!(matches!(server_exit, Err(error) if error.is_cancelled()));

    let (status, headers, body) = response
        .expect("overload response must be bounded")
        .expect("overload response must be returned");

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers.get("retry-after").map(|s| s.as_str()), Some("30"));

    // Verify response body is a valid ProblemDetails
    let details: opc_sbi::problem::ProblemDetails = serde_json::from_slice(&body).unwrap();
    assert_eq!(details.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(details.detail.as_deref(), Some("server overloaded"));
}

#[tokio::test]
async fn test_client_circuit_breaker_flow() {
    let producer = MockProducer::start().await;

    // Set 500 error on producer
    producer.set_override(
        "/fail",
        StatusCode::INTERNAL_SERVER_ERROR,
        HashMap::new(),
        Vec::new(),
    );

    // Build client with circuit breaker: 3 failures to open
    let breakers = Arc::new(opc_sbi::client::circuit_breaker::CircuitBreakers::new(
        3,
        Duration::from_secs(10),
        1,
    ));
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_circuit_breakers(breakers)
        .build()
        .unwrap();
    let consumer = MockConsumer::with_client(client);
    let url = format!("{}/fail", producer.url());

    // Trigger 3 failures
    for _ in 0..3 {
        let (status, _, _) = consumer.send_get(&url, HashMap::new()).await.unwrap();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // 4th request must fail closed immediately (circuit open)
    let result = consumer.send_get(&url, HashMap::new()).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Circuit breaker is open"));
}

#[tokio::test]
async fn test_client_records_one_breaker_failure_per_logical_send() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Keep the address reserved while closing every accepted connection, so
    // each retry gets a deterministic transport failure without a port race.
    let rejected_connections = Arc::new(AtomicUsize::new(0));
    let rejected_by_server = rejected_connections.clone();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
    let rejecting_server = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    rejected_by_server.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            }
        }
    });

    let breakers = Arc::new(opc_sbi::client::circuit_breaker::CircuitBreakers::new(
        2,
        Duration::from_secs(10),
        1,
    ));
    let retry_policy = RetryPolicy::new(
        3,
        Duration::from_millis(1),
        Duration::from_millis(1),
        Jitter::None,
    );
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_connect_timeout(Duration::from_millis(20))
        .with_request_timeout(Duration::from_millis(20))
        .with_retry_policy(retry_policy)
        .with_circuit_breakers(breakers.clone())
        .build()
        .unwrap();
    let uri = format!("http://{addr}/nnrf-disc/v1/nf-instances");
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(Vec::new())
        .unwrap();

    let result = client.send(request).await;
    stop_tx.send(()).unwrap();
    rejecting_server.await.unwrap();

    assert!(result.is_err());
    assert_eq!(rejected_connections.load(Ordering::SeqCst), 3);

    let breaker = breakers.get("127.0.0.1", "nnrf-disc");
    let state = breaker.lock().unwrap().state();
    assert_eq!(state, CircuitState::Closed);
}

#[tokio::test]
async fn test_jwt_svid_validation_success_and_failures() {
    let resolver = Arc::new(MockJwksResolver::new());
    let validator = SbiJwtValidator::new(
        resolver,
        Duration::from_secs(60),
        "amf-audience".to_string(),
        "nrf-issuer".to_string(),
        true,  // production_mode = true
        false, // bypass_verification_in_dev = false
    );

    // 1. Success case: Valid token
    let sub = "spiffe://example.com/tenant/default/ns/core/sa/default/nf/amf/instance/amf-01";
    let token_str = TokenFixtures::valid(sub, "amf-audience", "nrf-issuer", "nnrf-disc");
    let bearer = opc_sbi::headers::BearerToken::new(token_str).unwrap();

    let req = SbiAuthRequest {
        method: http::Method::GET,
        path: "/nnrf-disc/v1/nf-instances".to_string(),
        headers: opc_sbi::headers::SbiHeaders::default(),
        bearer_token: Some(bearer),
        // mTLS peer identity matching the token subject, so the token-binding
        // check passes (the failure cases below reuse this peer but are denied
        // earlier, at signature/audience/nbf/layout validation).
        peer: opc_sbi::auth::SbiPeer {
            spiffe: SpiffeId::new(sub).ok(),
            nf_instance_id: NfInstanceId::new("amf-01").ok(),
            nf_type: NfType::new("amf").ok(),
            tenant: TenantId::new("default").unwrap(),
            plmn: None,
            snssai: None,
        },
    };

    let context = validator.authorize(&req).await.unwrap();
    assert_eq!(context.peer.tenant, TenantId::new("default").unwrap());
    assert_eq!(
        context.peer.nf_instance_id.as_ref().map(|id| id.as_str()),
        Some("amf-01")
    );
    assert_eq!(
        context.peer.nf_type.as_ref().map(|t| t.as_str()),
        Some("amf")
    );
    assert_eq!(context.scopes, vec!["nnrf-disc".to_string()]);

    // 2. Failure case: Expired token
    let expired_str = TokenFixtures::expired(sub, "amf-audience", "nrf-issuer");
    let bearer_expired = opc_sbi::headers::BearerToken::new(expired_str).unwrap();
    let req_expired = SbiAuthRequest {
        bearer_token: Some(bearer_expired),
        ..req.clone()
    };
    let err_expired = validator.authorize(&req_expired).await.unwrap_err();
    assert!(matches!(
        err_expired,
        opc_sbi::auth::SbiAuthError::Denied { .. }
    ));

    // 3. Failure case: Wrong audience
    let bad_aud_str = TokenFixtures::bad_audience(sub, "nrf-issuer");
    let bearer_bad_aud = opc_sbi::headers::BearerToken::new(bad_aud_str).unwrap();
    let req_bad_aud = SbiAuthRequest {
        bearer_token: Some(bearer_bad_aud),
        ..req.clone()
    };
    let err_bad_aud = validator.authorize(&req_bad_aud).await.unwrap_err();
    assert!(matches!(
        err_bad_aud,
        opc_sbi::auth::SbiAuthError::Denied { .. }
    ));

    // 4. Failure case: token is not valid yet
    let future_nbf_str = opc_sbi::testkit::generate_test_token_with_nbf_offset(
        sub,
        "amf-audience",
        "nrf-issuer",
        None,
        3600,
        3600,
    );
    let bearer_future = opc_sbi::headers::BearerToken::new(future_nbf_str).unwrap();
    let req_future = SbiAuthRequest {
        bearer_token: Some(bearer_future),
        ..req.clone()
    };
    assert!(matches!(
        validator.authorize(&req_future).await.unwrap_err(),
        opc_sbi::auth::SbiAuthError::Denied { .. }
    ));

    // 5. Failure case: SPIFFE subject has unrecognized trailing segments
    let bad_sub =
        "spiffe://example.com/tenant/default/ns/core/sa/default/nf/amf/instance/amf-01/extra";
    let bad_sub_token = TokenFixtures::valid(bad_sub, "amf-audience", "nrf-issuer", "nnrf-disc");
    let bearer_bad_sub = opc_sbi::headers::BearerToken::new(bad_sub_token).unwrap();
    let req_bad_sub = SbiAuthRequest {
        bearer_token: Some(bearer_bad_sub),
        ..req
    };
    assert!(matches!(
        validator.authorize(&req_bad_sub).await.unwrap_err(),
        opc_sbi::auth::SbiAuthError::Denied { .. }
    ));
}

struct TestTokenProvider {
    call_counter: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl TokenProvider for TestTokenProvider {
    async fn get_token(&self, _scopes: &[String]) -> Result<opc_sbi::headers::BearerToken, String> {
        self.call_counter.fetch_add(1, Ordering::SeqCst);
        let token_str = generate_test_token(
            "spiffe://example.com/tenant/default/ns/core/sa/default/nf/amf/instance/amf-01",
            "aud",
            "iss",
            None,
            3600,
        );
        Ok(opc_sbi::headers::BearerToken::new(token_str).unwrap())
    }
}

#[tokio::test]
async fn test_client_token_cache() {
    let call_counter = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(TestTokenProvider {
        call_counter: call_counter.clone(),
    });

    let cache = ClientTokenCache::new(provider);
    let scopes = vec!["nnrf-nfm".to_string()];

    // First request - should fetch
    let t1 = cache.get_token(&scopes).await.unwrap();
    assert_eq!(call_counter.load(Ordering::SeqCst), 1);

    // Second request - should hit cache
    let t2 = cache.get_token(&scopes).await.unwrap();
    assert_eq!(call_counter.load(Ordering::SeqCst), 1);
    assert_eq!(t1.expose(), t2.expose());
}

#[test]
fn test_production_client_rejects_plaintext_configuration() {
    let result = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_production_mode(true)
        .build();
    let err = match result {
        Ok(_) => panic!("production client accepted plaintext configuration"),
        Err(err) => err,
    };

    assert!(err.contains("requires TLS"));
}

#[tokio::test]
async fn test_production_server_rejects_missing_tls_and_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = SbiServerBuilder::new(addr).with_production_mode(true);
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));

    let err = server.run_with_listener(listener, app).await.unwrap_err();
    assert!(err.contains("requires TLS"));
}

#[tokio::test]
async fn client_errors_do_not_trip_the_circuit_breaker() {
    let producer = MockProducer::start().await;
    producer.set_override(
        "/nnrf-disc/missing",
        StatusCode::NOT_FOUND,
        HashMap::new(),
        Vec::new(),
    );
    let breakers = Arc::new(opc_sbi::client::circuit_breaker::CircuitBreakers::new(
        1,
        Duration::from_secs(30),
        1,
    ));
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_circuit_breakers(breakers.clone())
        .build()
        .unwrap();
    let consumer = MockConsumer::with_client(client);
    for _ in 0..3 {
        let (status, _, _) = consumer
            .send_get(
                &format!("{}/nnrf-disc/missing", producer.url()),
                HashMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    assert_eq!(
        breakers
            .get("127.0.0.1", "nnrf-disc")
            .lock()
            .unwrap()
            .state(),
        CircuitState::Closed
    );
}

struct RejectAuth(opc_sbi::auth::SbiAuthError);

#[async_trait::async_trait]
impl SbiAuth for RejectAuth {
    async fn authorize(
        &self,
        _: &SbiAuthRequest,
    ) -> Result<opc_sbi::auth::SbiAuthContext, opc_sbi::auth::SbiAuthError> {
        Err(self.0.clone())
    }
}

#[tokio::test]
async fn auth_failures_include_safe_bearer_challenges_and_problem_media_type() {
    use opc_sbi::auth::SbiAuthError;
    for (error, expected_status, challenge) in [
        (
            SbiAuthError::MissingBearerToken,
            StatusCode::UNAUTHORIZED,
            Some("Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\""),
        ),
        (
            SbiAuthError::Denied {
                reason: "private-token-detail".into(),
            },
            StatusCode::UNAUTHORIZED,
            Some("Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\", error=\"invalid_token\""),
        ),
        (
            SbiAuthError::TokenBindingMismatch,
            StatusCode::UNAUTHORIZED,
            Some("Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\", error=\"invalid_token\""),
        ),
        (
            SbiAuthError::MissingPeerBinding,
            StatusCode::UNAUTHORIZED,
            Some("Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\", error=\"invalid_token\""),
        ),
        (
            SbiAuthError::InsufficientScope,
            StatusCode::FORBIDDEN,
            Some("Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\", error=\"insufficient_scope\", scope=\"nnrf-disc\""),
        ),
        (
            SbiAuthError::Internal {
                reason: "private-key-fetch-detail".into(),
            },
            StatusCode::SERVICE_UNAVAILABLE,
            None,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = SbiServerBuilder::new(addr)
            .with_auth_policy(Arc::new(RejectAuth(error)))
            .with_auth_service(
                "https://nrf.example.test/nnrf-disc/v1".parse().unwrap(),
                vec!["nnrf-disc".into()],
            );
        let app = axum::Router::new().route(
            "/nnrf-disc/v1/test",
            axum::routing::get(|| async { "unexpected admission" }),
        );
        let task = tokio::spawn(async move { server.run_with_listener(listener, app).await });
        let client = SbiClientBuilder::new()
            .with_http2_only(false)
            .with_retry_policy(RetryPolicy::new(
                1,
                Duration::ZERO,
                Duration::ZERO,
                Jitter::None,
            ))
            .build()
            .unwrap();
        let consumer = MockConsumer::with_client(client);
        let response = consumer
            .send_get(&format!("http://{addr}/nnrf-disc/v1/test"), HashMap::from([("host".into(), "untrusted.example".into())]))
            .await;
        task.abort();
        let _ = task.await;
        let (status, headers, body) = response.unwrap();
        assert_eq!(status, expected_status);
        assert_eq!(
            headers.get("www-authenticate").map(String::as_str),
            challenge
        );
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/problem+json")
        );
        assert!(!String::from_utf8_lossy(&body).contains("private-"));
    }
}

#[tokio::test]
async fn auth_challenges_omit_error_for_empty_and_non_bearer_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let validator = SbiJwtValidator::new(
        Arc::new(MockJwksResolver::new()),
        Duration::from_secs(60),
        "test-audience".into(),
        "test-issuer".into(),
        false,
        false,
    );
    let server = SbiServerBuilder::new(addr)
        .with_auth_policy(Arc::new(validator))
        .with_auth_service(
            "https://nrf.example.test/nnrf-disc/v1".parse().unwrap(),
            vec!["nnrf-disc".into()],
        );
    let app = axum::Router::new().fallback(|| async { "unexpected admission" });
    let task = tokio::spawn(server.run_with_listener(listener, app));
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_retry_policy(RetryPolicy::new(
            1,
            Duration::ZERO,
            Duration::ZERO,
            Jitter::None,
        ))
        .build()
        .unwrap();
    let mut responses = Vec::new();
    let mut expected = Vec::new();
    for (value, challenge) in [
        (
            "Negotiate",
            "Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\"",
        ),
        (
            "Digest username=\"u\", realm=\"r\"",
            "Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\"",
        ),
        ("", "Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\""),
        (
            "Basic dXNlcjpwYXNz",
            "Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\"",
        ),
        (
            "Bearer",
            "Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\", error=\"invalid_token\"",
        ),
        (
            "bEaReR private-token!",
            "Bearer realm=\"https://nrf.example.test/nnrf-disc/v1\", error=\"invalid_token\"",
        ),
    ] {
        let response = client
            .send(
                http::Request::builder()
                    .uri(format!("http://{addr}/nnrf-disc/v1/test"))
                    .header("authorization", value)
                    .body(Vec::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        responses.push((
            response.status(),
            response.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .to_owned(),
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .to_owned(),
        ));
        expected.push((
            StatusCode::UNAUTHORIZED,
            challenge.to_owned(),
            "application/problem+json".to_owned(),
        ));
    }
    task.abort();
    let _ = task.await;
    assert_eq!(responses, expected);
}

#[tokio::test]
async fn auth_challenges_select_trusted_api_and_scope_without_reflecting_request_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = SbiServerBuilder::new(addr)
        .with_auth_policy(Arc::new(RejectAuth(
            opc_sbi::auth::SbiAuthError::InsufficientScope,
        )))
        .with_auth_service(
            "https://nrf.example.test/nnrf-disc/v1".parse().unwrap(),
            vec!["nnrf-disc".into()],
        )
        .with_auth_service(
            "https://nrf.example.test/nnrf-nfm/v1".parse().unwrap(),
            vec!["nnrf-nfm".into(), "nnrf-nfm:read".into()],
        );
    let app = axum::Router::new().fallback(|| async { "unexpected admission" });
    let task = tokio::spawn(server.run_with_listener(listener, app));
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .with_retry_policy(RetryPolicy::new(
            1,
            Duration::ZERO,
            Duration::ZERO,
            Jitter::None,
        ))
        .build()
        .unwrap();
    for (path, scope) in [
        ("/nnrf-disc/v1", Some("nnrf-disc")),
        ("/nnrf-nfm/v1", Some("nnrf-nfm nnrf-nfm:read")),
        ("/nnrf-disc/v10", None),
    ] {
        let response = client
            .send(
                http::Request::builder()
                    .uri(format!("http://{addr}{path}/test"))
                    .header("host", "untrusted.example")
                    .body(Vec::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        if let Some(scope) = scope {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()["www-authenticate"],
                format!("Bearer realm=\"https://nrf.example.test{path}\", error=\"insufficient_scope\", scope=\"{scope}\""));
        } else {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(!response.headers().contains_key("www-authenticate"));
        }
    }
    let mut responses = Vec::new();
    let mut expected = Vec::new();
    for path in ["/nnrf-disc/v1", "/nnrf-nfm/v1"] {
        for (values, status, error) in [
            (vec!["Bearer"], StatusCode::UNAUTHORIZED, "invalid_token"),
            (
                vec!["Bearer private-token!"],
                StatusCode::UNAUTHORIZED,
                "invalid_token",
            ),
            (
                vec!["Bearer private-token extra"],
                StatusCode::UNAUTHORIZED,
                "invalid_token",
            ),
            (
                vec!["Bearer one", "Bearer two"],
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                vec!["Bearer", "Bearer private-token", "Bearer three"],
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
        ] {
            let mut request = http::Request::builder()
                .uri(format!("http://{addr}{path}/test"))
                .header("host", "untrusted.example");
            for value in values {
                request = request.header("authorization", value);
            }
            let response = client
                .send(request.body(Vec::new()).unwrap())
                .await
                .unwrap();
            responses.push((
                response.status(),
                response
                    .headers()
                    .get("www-authenticate")
                    .map(|value| value.to_str().unwrap().to_owned()),
            ));
            expected.push((
                status,
                Some(format!(
                    "Bearer realm=\"https://nrf.example.test{path}\", error=\"{error}\""
                )),
            ));
            assert_eq!(
                response.headers()["content-type"],
                "application/problem+json"
            );
            assert!(!String::from_utf8_lossy(response.body()).contains("private-token"));
        }
    }
    task.abort();
    let _ = task.await;
    assert_eq!(
        responses
            .iter()
            .map(|(_, challenge)| challenge)
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|(_, challenge)| challenge)
            .collect::<Vec<_>>(),
        "authentication replies: {responses:?}"
    );
    assert_eq!(
        responses
            .iter()
            .map(|(status, _)| status)
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|(status, _)| status)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn unprotected_paths_do_not_interpret_authorization_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = SbiServerBuilder::new(addr);
    let app = axum::Router::new().fallback(|| async { "public response" });
    let task = tokio::spawn(server.run_with_listener(listener, app));
    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .build()
        .unwrap();
    for values in [vec!["Bearer"], vec!["Bearer one", "Bearer two"]] {
        let mut request = http::Request::builder().uri(format!("http://{addr}/public"));
        for value in values {
            request = request.header("authorization", value);
        }
        let response = client
            .send(request.body(Vec::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("www-authenticate"));
        assert_eq!(response.body().as_ref(), b"public response");
    }
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn tls_client_requires_negotiated_h2_before_sending_requests() {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::pki_types::PrivatePkcs8KeyDer;

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "::1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    for (host, alpn) in ["127.0.0.1", "::1"].into_iter().flat_map(|host| {
        [Some(b"h2".as_slice()), None, Some(b"http/1.1".as_slice())]
            .into_iter()
            .map(move |alpn| (host, alpn))
    }) {
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        server_config.alpn_protocols = alpn.into_iter().map(<[u8]>::to_vec).collect();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let server_received = received.clone();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            if let Ok(tls) = acceptor.accept(tcp).await {
                let handler = hyper::service::service_fn(move |_| {
                    server_received.fetch_add(1, Ordering::SeqCst);
                    async {
                        Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                            Bytes::new(),
                        )))
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), handler)
                    .await;
            }
        });
        let client = SbiClientBuilder::new()
            .with_tls(config.clone())
            .with_retry_policy(RetryPolicy::new(
                1,
                Duration::ZERO,
                Duration::ZERO,
                Jitter::None,
            ))
            .build()
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client.send(
                http::Request::builder()
                    .uri(format!("https://{addr}/nnrf-disc/test"))
                    .body(Vec::new())
                    .unwrap(),
            ),
        )
        .await;
        task.abort();
        let _ = task.await;
        let response = response.expect("TLS negotiation must be bounded");
        if alpn == Some(b"h2") {
            assert_eq!(response.unwrap().status(), StatusCode::OK);
            assert_eq!(received.load(Ordering::SeqCst), 1);
        } else {
            assert!(response.is_err());
            assert_eq!(received.load(Ordering::SeqCst), 0);
        }
    }
    assert!(
        config.alpn_protocols.is_empty(),
        "caller TLS config remains unchanged"
    );
}
