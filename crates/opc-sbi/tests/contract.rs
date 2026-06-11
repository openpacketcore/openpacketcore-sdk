use http::{HeaderValue, Request, StatusCode, Uri};
use opc_sbi::{
    extract_bearer_token, AuthorizationHeader, CauseCode, ClientMiddlewareShell, ErasedAuthContext,
    HeaderParseError, InvalidParam, Jitter, ProblemDetails, RequestDeadline, RetryAfter,
    RetryOutcome, RetryPolicy, SbiAuthContext, SbiAuthError, SbiAuthRequest, SbiExtractor,
    SbiHeaders, SbiPeer, ServerMiddlewareShell, HEADER_AUTHORIZATION, HEADER_BINDING,
    HEADER_CORRELATION_INFO, HEADER_DEADLINE_HINT_MS, HEADER_IDEMPOTENCY_KEY, HEADER_LOCATION,
    HEADER_MESSAGE_PRIORITY, HEADER_RETRY_AFTER, HEADER_ROUTING_BINDING, HEADER_TARGET_API_ROOT,
};
use opc_types::{NfInstanceId, NfType, PlmnId, Snssai, SpiffeId, TenantId};
use std::{
    str::FromStr,
    time::{Duration, Instant},
};

#[test]
fn problem_details_json_round_trips_with_typed_status_and_cause() {
    let mut details = ProblemDetails::new(StatusCode::BAD_REQUEST);
    details.cause = Some(CauseCode::new("MANDATORY_IE_INCORRECT").unwrap());
    details.title = Some("Bad Request".into());
    details.detail = Some("nfInstanceId is missing".into());
    details.instance = Some("/nnrf-nfm/v1/nf-instances".into());
    details.invalid_params = vec![InvalidParam::new("nfInstanceId", Some("missing".into()))];
    details.supported_features = Some("v1".into());

    let json = serde_json::to_value(&details).unwrap();
    assert_eq!(json["status"], 400);
    assert_eq!(json["cause"], "MANDATORY_IE_INCORRECT");
    assert_eq!(json["invalidParams"][0]["param"], "nfInstanceId");
    assert_eq!(json["supportedFeatures"], "v1");

    let round_trip: ProblemDetails = serde_json::from_value(json).unwrap();
    assert_eq!(round_trip, details);

    let invalid = serde_json::json!({ "status": 99 });
    let err = serde_json::from_value::<ProblemDetails>(invalid).unwrap_err();
    assert!(err.to_string().contains("invalid status code"));
}

#[test]
fn sbi_headers_parse_render_and_redact_sensitive_values() {
    let mut raw = http::HeaderMap::new();
    raw.insert(HEADER_MESSAGE_PRIORITY, "5".parse().unwrap());
    raw.insert(HEADER_CORRELATION_INFO, "trace=abc123".parse().unwrap());
    raw.insert(
        HEADER_BINDING,
        "https://producer.example/bind".parse().unwrap(),
    );
    raw.insert(
        HEADER_ROUTING_BINDING,
        "https://scp.example/route".parse().unwrap(),
    );
    raw.insert(
        HEADER_TARGET_API_ROOT,
        "https://nrf.example/nnrf-disc/v1".parse().unwrap(),
    );
    raw.insert(HEADER_RETRY_AFTER, "30".parse().unwrap());
    raw.insert(
        HEADER_LOCATION,
        "https://nrf.example/nnrf-nfm/v1/nf-instances/abc"
            .parse()
            .unwrap(),
    );
    raw.insert(
        HEADER_AUTHORIZATION,
        "Bearer super-secret-token".parse().unwrap(),
    );

    let parsed = SbiHeaders::parse(&raw).unwrap();
    assert_eq!(parsed.message_priority, Some(5));
    assert_eq!(parsed.correlation_info.as_deref(), Some("trace=abc123"));
    assert_eq!(
        parsed.binding.as_deref(),
        Some("https://producer.example/bind")
    );
    assert_eq!(
        parsed.routing_binding.as_deref(),
        Some("https://scp.example/route")
    );
    assert_eq!(
        parsed.target_api_root,
        Some(Uri::from_static("https://nrf.example/nnrf-disc/v1"))
    );
    assert_eq!(parsed.retry_after, Some(RetryAfter::DelaySeconds(30)));
    assert_eq!(
        parsed.location,
        Some(Uri::from_static(
            "https://nrf.example/nnrf-nfm/v1/nf-instances/abc"
        ))
    );
    assert!(
        parsed.authorization.is_some(),
        "authorization should be parsed"
    );

    let debug = format!("{parsed:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(!debug.contains("https://nrf.example/nnrf-disc/v1"));
    assert!(debug.contains("<redacted>"));

    let rendered = parsed.render().unwrap();
    assert_eq!(
        rendered
            .get(HEADER_AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer super-secret-token"
    );
    assert_eq!(
        rendered.get(HEADER_BINDING).unwrap().to_str().unwrap(),
        "https://producer.example/bind"
    );
    assert_eq!(
        rendered
            .get(HEADER_ROUTING_BINDING)
            .unwrap()
            .to_str()
            .unwrap(),
        "https://scp.example/route"
    );
    assert_eq!(
        rendered.get(HEADER_LOCATION).unwrap().to_str().unwrap(),
        "https://nrf.example/nnrf-nfm/v1/nf-instances/abc"
    );
    assert_eq!(
        rendered
            .get(HEADER_TARGET_API_ROOT)
            .unwrap()
            .to_str()
            .unwrap(),
        "https://nrf.example/nnrf-disc/v1"
    );
    assert_eq!(
        rendered
            .get(HEADER_CORRELATION_INFO)
            .unwrap()
            .to_str()
            .unwrap(),
        "trace=abc123"
    );
}

#[test]
fn bearer_token_extraction_is_case_insensitive_and_safe() {
    let lower = extract_bearer_token("bearer alpha-token").unwrap();
    assert_eq!(lower.unwrap().expose(), "alpha-token");

    let upper = extract_bearer_token("BEARER omega-token").unwrap();
    assert_eq!(upper.unwrap().expose(), "omega-token");

    let none = extract_bearer_token("Digest abc123").unwrap();
    assert!(none.is_none());

    let err = extract_bearer_token("Bearer one two").unwrap_err();
    let message = err.to_string();
    assert!(!message.contains("one"));
    assert!(!message.contains("two"));
    assert!(matches!(err, HeaderParseError::InvalidValue { .. }));

    let auth = AuthorizationHeader::parse("Bearer hidden-token").unwrap();
    let debug = format!("{auth:?}");
    assert!(!debug.contains("hidden-token"));
    assert!(debug.contains("<redacted>"));

    for invalid in ["Bearer abc,def", "Bearer \"quoted\"", "Bearer abc:def"] {
        let err = extract_bearer_token(invalid).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("abc"));
        assert!(!message.contains("def"));
        assert!(!message.contains("quoted"));
        assert!(matches!(err, HeaderParseError::InvalidValue { .. }));
    }
}

#[test]
fn authorization_header_opaque_variant_parse_render_debug() {
    let auth = AuthorizationHeader::parse("Digest abc123").unwrap();
    let AuthorizationHeader::Opaque {
        scheme,
        credentials,
    } = &auth
    else {
        panic!("expected Opaque variant, got Bearer");
    };
    assert_eq!(scheme, "Digest");
    assert_eq!(credentials.expose(), "abc123");

    let rendered = auth.render();
    assert_eq!(rendered, "Digest abc123");

    let debug = format!("{auth:?}");
    assert!(debug.contains("Digest"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("abc123"));
}

#[test]
fn auth_debug_output_redacts_network_sensitive_identity_and_tokens() {
    let peer = sample_peer();
    let context = SbiAuthContext {
        peer: peer.clone(),
        scopes: vec!["nnrf-disc".into(), "nnrf-nfm".into()],
        access_token: Some(extract_bearer_token("Bearer token-123").unwrap().unwrap()),
    };
    let erased = ErasedAuthContext::from(&context);

    let peer_debug = format!("{peer:?}");
    let context_debug = format!("{context:?}");
    let erased_debug = format!("{erased:?}");

    for debug in [peer_debug, context_debug, erased_debug] {
        assert!(!debug.contains("amf"));
        assert!(!debug.contains("tenant-a"));
        assert!(!debug.contains("amf-instance-01"));
        assert!(!debug.contains("spiffe://"));
        assert!(!debug.contains("token-123"));
        assert!(debug.contains("<redacted>"));
    }

    let request = SbiAuthRequest {
        method: http::Method::GET,
        path: "/nnrf-disc/v1/subscribers/imsi-001010123456789".into(),
        headers: SbiHeaders::default(),
        bearer_token: Some(extract_bearer_token("Bearer token-123").unwrap().unwrap()),
        peer,
    };
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains("imsi-001010123456789"));
    assert!(!request_debug.contains("/nnrf-disc"));
    assert!(!request_debug.contains("token-123"));
    assert!(request_debug.contains("<redacted>"));

    let auth_error = SbiAuthError::Denied {
        reason: "tenant-a token-123".into(),
    };
    let error_debug = format!("{auth_error:?}");
    assert!(!error_debug.contains("tenant-a"));
    assert!(!error_debug.contains("token-123"));
    assert!(error_debug.contains("<redacted>"));
}

#[test]
fn deadline_shell_propagates_extension_and_timeout_hint() {
    let client = ClientMiddlewareShell::new();
    let server = ServerMiddlewareShell;
    let now = Instant::now();
    let deadline = RequestDeadline::after(now, Duration::from_millis(1500));

    let mut request = Request::builder()
        .method("GET")
        .uri("/nnrf-disc/v1/nf-instances")
        .body(())
        .unwrap();

    client.apply_deadline(&mut request, deadline, now).unwrap();
    assert_eq!(
        request
            .headers()
            .get(HEADER_DEADLINE_HINT_MS)
            .unwrap()
            .to_str()
            .unwrap(),
        "1500"
    );

    let context = SbiAuthContext {
        peer: sample_peer(),
        scopes: vec!["nnrf-disc".into()],
        access_token: None,
    };
    server.install_auth_context(&mut request, &context);

    let extracted = server.extract(&request).unwrap();
    assert_eq!(extracted.deadline, Some(deadline));
    assert_eq!(extracted.timeout_hint, Some(Duration::from_millis(1500)));
    assert!(extracted.auth_context.is_some());
}

#[test]
fn retry_policy_parses_strictly_and_honors_post_idempotency_keys() {
    let policy = RetryPolicy::from_str(
        "max_attempts=3;base_delay_ms=100;max_delay_ms=1000;jitter=full;retry_on_status=429,503;retry_on_transport_error=true",
    )
    .unwrap();

    assert_eq!(policy.max_attempts, 3);
    assert_eq!(policy.base_delay, Duration::from_millis(100));
    assert_eq!(policy.max_delay, Duration::from_millis(1000));
    assert_eq!(policy.jitter, Jitter::Full);
    assert_eq!(
        policy.retry_on_status,
        vec![
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE
        ]
    );
    assert!(policy.retry_on_transport_error);

    let request = Request::builder()
        .method("POST")
        .uri("/nnrf-disc/v1/search")
        .body(())
        .unwrap();
    assert!(!policy.should_retry(
        &request,
        1,
        RetryOutcome::Status(StatusCode::SERVICE_UNAVAILABLE)
    ));

    let keyed = Request::builder()
        .method("POST")
        .uri("/nnrf-disc/v1/search")
        .header(HEADER_IDEMPOTENCY_KEY, "abc-123")
        .body(())
        .unwrap();
    assert!(policy.should_retry(
        &keyed,
        1,
        RetryOutcome::Status(StatusCode::SERVICE_UNAVAILABLE)
    ));
    assert!(policy.should_retry(&keyed, 1, RetryOutcome::TransportError));

    let invalid_bool = RetryPolicy::from_str(
        "max_attempts=3;base_delay_ms=100;max_delay_ms=1000;jitter=none;retry_on_status=503;retry_on_transport_error=notabool",
    )
    .unwrap_err();
    assert!(invalid_bool.to_string().contains("true' or 'false"));

    let invalid_status = RetryPolicy::from_str(
        "max_attempts=3;base_delay_ms=100;max_delay_ms=1000;jitter=none;retry_on_status=abc;retry_on_transport_error=true",
    )
    .unwrap_err();
    assert!(invalid_status.to_string().contains("abc"));
}

#[test]
fn extractor_public_header_map_entrypoint_parses_auth_and_deadline_hint() {
    let mut headers = http::HeaderMap::new();
    headers.insert(HEADER_AUTHORIZATION, "Bearer abc123".parse().unwrap());
    headers.insert(HEADER_DEADLINE_HINT_MS, "250".parse().unwrap());

    let extracted = SbiExtractor::extract_from_header_map(&headers).unwrap();
    assert_eq!(extracted.bearer_token.unwrap().expose(), "abc123");
    assert_eq!(extracted.timeout_hint, Some(Duration::from_millis(250)));
}

#[test]
fn retry_after_rejects_invalid_dates_and_accepts_http_date() {
    let valid = RetryAfter::parse("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
    assert_eq!(
        valid,
        RetryAfter::HttpDate("Sun, 06 Nov 1994 08:49:37 GMT".into())
    );

    let err = RetryAfter::parse("tomorrow").unwrap_err();
    assert!(matches!(err, HeaderParseError::InvalidValue { .. }));
    assert!(err.to_string().contains("IMF-fixdate"));
}

#[test]
fn duplicate_singleton_headers_fail_closed() {
    let mut duplicate_auth = http::HeaderMap::new();
    duplicate_auth.append(HEADER_AUTHORIZATION, "Bearer first".parse().unwrap());
    duplicate_auth.append(HEADER_AUTHORIZATION, "Bearer second".parse().unwrap());

    let auth_err = SbiHeaders::parse(&duplicate_auth).unwrap_err();
    assert_eq!(
        auth_err,
        HeaderParseError::Duplicate {
            header: HEADER_AUTHORIZATION
        }
    );

    let mut duplicate_retry_after = http::HeaderMap::new();
    duplicate_retry_after.append(HEADER_RETRY_AFTER, "30".parse().unwrap());
    duplicate_retry_after.append(HEADER_RETRY_AFTER, "31".parse().unwrap());

    let retry_after_err = SbiHeaders::parse(&duplicate_retry_after).unwrap_err();
    assert_eq!(
        retry_after_err,
        HeaderParseError::Duplicate {
            header: HEADER_RETRY_AFTER
        }
    );
}

#[test]
fn bearer_token_rejects_padding_only_credentials() {
    for invalid in ["Bearer =", "Bearer ==", "Bearer ===", "Bearer =abc"] {
        let err = extract_bearer_token(invalid).unwrap_err();
        let message = err.to_string();
        // Credential contents must never leak into error messages.
        assert!(
            !message.contains("="),
            "error must not echo credential: {message}"
        );
        assert!(matches!(err, HeaderParseError::InvalidValue { .. }));
    }
}

#[test]
fn header_values_reject_invalid_utf8_bytes() {
    let mut headers = http::HeaderMap::new();
    // Invalid UTF-8 byte in correlation-info — should fail at the UTF-8 layer.
    headers.insert(
        HEADER_CORRELATION_INFO,
        HeaderValue::from_bytes(b"caf\xff").unwrap(),
    );
    let err = SbiHeaders::parse(&headers).unwrap_err();
    assert!(matches!(err, HeaderParseError::NonUtf8 { .. }));
}

#[test]
fn auth_error_display_redacts_reason() {
    let denied = SbiAuthError::Denied {
        reason: "secret-reason".into(),
    };
    let display = denied.to_string();
    assert!(!display.contains("secret-reason"));
    assert_eq!(display, "authorization denied");

    let internal = SbiAuthError::Internal {
        reason: "kms-down".into(),
    };
    let display = internal.to_string();
    assert!(!display.contains("kms-down"));
    assert_eq!(display, "internal auth failure");
}

fn sample_peer() -> SbiPeer {
    SbiPeer {
        spiffe: Some(
            SpiffeId::new(
                "spiffe://example.test/tenant/tenant-a/ns/core/sa/amf/nf/amf/instance/amf-instance-01",
            )
            .unwrap(),
        ),
        nf_instance_id: Some(NfInstanceId::new("amf-instance-01").unwrap()),
        nf_type: Some(NfType::new("AMF".to_ascii_lowercase()).unwrap()),
        tenant: TenantId::new("tenant-a").unwrap(),
        plmn: Some(PlmnId::new("001", "01").unwrap()),
        snssai: Some(Snssai::new(1, Some("010203")).unwrap()),
    }
}
