use http::StatusCode;
use opc_sbi::{
    auth::{ClientTokenCache, SbiAuth, SbiAuthRequest, SbiJwtValidator, TokenProvider},
    client::builder::SbiClientBuilder,
    server::builder::SbiServerBuilder,
    testkit::{generate_test_token, MockConsumer, MockJwksResolver, MockProducer, TokenFixtures},
};
use opc_types::TenantId;
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

    tokio::spawn(async move {
        let _ = server.run_with_listener(listener, app).await;
    });

    let client = SbiClientBuilder::new()
        .with_http2_only(false)
        .build()
        .unwrap();
    let consumer = MockConsumer::with_client(client);

    let url = format!("http://{}", addr);
    let (status, headers, body) = consumer.send_get(&url, HashMap::new()).await.unwrap();

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
        peer: opc_sbi::auth::SbiPeer {
            spiffe: None,
            nf_instance_id: None,
            nf_type: None,
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
