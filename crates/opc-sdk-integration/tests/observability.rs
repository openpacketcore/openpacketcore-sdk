//! Observability and Observability label-safety Integration Tests.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

use opc_runtime::admin::start_admin_server;
use opc_runtime::metrics::METRICS;
use opc_runtime::profile::{RuntimeMode, RuntimeProfile};
use opc_runtime::Builder;

use opc_alarm::{
    AffectedObject, AlarmAction, AlarmActionContext, AlarmActionScope, AlarmAuditEvent,
    AlarmDetails, AlarmManager, AlarmOpResult, InMemoryStore, ProbableCause, RedactedText,
    Severity,
};
use opc_nacm::{
    ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, NacmRule, PolicyVersion, YangPath,
    YangPathPattern,
};

/// Serializes the tests in this binary: every test resets and asserts on the
/// process-global `METRICS`, so parallel execution races `reset_all()`
/// against another test's increments (observed as intermittent `left: 0`
/// assertion failures). A tokio mutex is used so async tests may hold the
/// guard across await points; unlike `std::sync::Mutex` it does not poison,
/// so one test's panic cannot cascade into the others.
static METRICS_TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "current_thread")]
async fn test_nacm_eval_metrics() {
    let _guard = METRICS_TEST_GUARD.lock().await;
    METRICS.reset_all();

    let mut modules = ModuleRegistry::new();
    modules.register_module("ietf-interfaces", "if").unwrap();

    let path_allow = YangPath::parse("/if:interfaces/interface/config/name", &modules).unwrap();
    let path_deny = YangPath::parse("/if:interfaces/interface/state/counters", &modules).unwrap();

    let rule_allow = NacmRule::allow(
        NacmAction::Read,
        YangPathPattern::parse("/if:interfaces/interface/config/**", &modules).unwrap(),
    );

    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(rule_allow)
        .build();

    let mut evaluator = NacmEvaluator::new();

    // 1. Allowed evaluation
    let dec_allow = evaluator.evaluate(&policy, &path_allow, NacmAction::Read);
    assert!(dec_allow.is_allowed());
    assert_eq!(METRICS.nacm_eval_allow.load(Ordering::Relaxed), 1);

    // 2. Denied evaluation (default-deny)
    let dec_deny = evaluator.evaluate(&policy, &path_deny, NacmAction::Read);
    assert!(!dec_deny.is_allowed());
    assert_eq!(METRICS.nacm_eval_deny.load(Ordering::Relaxed), 1);
    assert_eq!(METRICS.nacm_default_deny.load(Ordering::Relaxed), 1);
}

struct TestAuthorizer;
impl opc_alarm::AlarmActionAuthorizer for TestAuthorizer {
    fn authorize_alarm_action(
        &self,
        _action: AlarmAction,
        _alarm: &opc_alarm::Alarm,
        _context: &opc_alarm::AlarmActionContext,
    ) -> Result<(), opc_alarm::AlarmActionDenied> {
        Ok(())
    }
    fn allow_security_critical_suppression(
        &self,
        _alarm: &opc_alarm::Alarm,
        _context: &opc_alarm::AlarmActionContext,
    ) -> bool {
        true
    }
}

struct FailingAuditSink;
impl opc_alarm::AlarmAuditSink for FailingAuditSink {
    fn record_alarm_action(&mut self, _event: AlarmAuditEvent) -> Result<(), String> {
        Err("Audit sink offline".to_string())
    }
}

struct SuccessAuditSink {
    events: Vec<AlarmAuditEvent>,
}
impl opc_alarm::AlarmAuditSink for SuccessAuditSink {
    fn record_alarm_action(&mut self, event: AlarmAuditEvent) -> Result<(), String> {
        self.events.push(event);
        Ok(())
    }
}

async fn send_admin_request(addr: SocketAddr, path: &str, token: Option<&str>) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let auth_hdr = match token {
        Some(tok) => format!("Authorization: Bearer {}\r\n", tok),
        None => String::new(),
    };
    let req = format!(
        "GET {} HTTP/1.1\r\n{}Host: localhost\r\nConnection: close\r\n\r\n",
        path, auth_hdr
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    String::from_utf8(resp).unwrap()
}

#[test]
fn test_alarm_audit_and_active_metrics() {
    let _guard = METRICS_TEST_GUARD.blocking_lock();
    METRICS.reset_all();

    let store = InMemoryStore::new();
    let mut manager = AlarmManager::new(store);

    // 1. Raise alarm -> updates active count
    let res = manager.raise(
        opc_alarm::AlarmType::new("communications-alarm"),
        Severity::Critical,
        ProbableCause::BackendTimeout,
        AffectedObject::Tenant {
            tenant: "tenant-a".to_string(),
        },
        Some("tenant-a".to_string()),
        None,
        None,
        RedactedText::new("Cable disconnected"),
        AlarmDetails::empty(),
    );
    assert!(matches!(res, AlarmOpResult::Raised { .. }));

    // Verify active count metric
    let active_map = METRICS.alarm_active_count.lock().unwrap();
    let key = ("critical".to_string(), "backend-timeout".to_string());
    assert_eq!(active_map.get(&key), Some(&1));
    drop(active_map);

    // 2. Perform action with failing audit sink -> increments failure metric
    let alarm_id = match res {
        AlarmOpResult::Raised { alarm } => alarm.alarm_id,
        _ => unreachable!(),
    };
    let context = AlarmActionContext::new("admin-a", "maintenance", AlarmActionScope::Global);
    let mut failing_sink = FailingAuditSink;

    let op_res =
        manager.acknowledge_with_policy(&alarm_id, &context, &TestAuthorizer, &mut failing_sink);
    assert!(matches!(op_res, AlarmOpResult::AuditFailed { .. }));
    assert_eq!(METRICS.alarm_audit_failure.load(Ordering::Relaxed), 1);

    // 3. Perform action with successful audit sink -> increments success metric
    let mut success_sink = SuccessAuditSink { events: Vec::new() };
    let op_res_ok =
        manager.acknowledge_with_policy(&alarm_id, &context, &TestAuthorizer, &mut success_sink);
    assert!(matches!(op_res_ok, AlarmOpResult::Acknowledged { .. }));
    assert_eq!(METRICS.alarm_audit_success.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn test_admin_http_routes() {
    let _guard = METRICS_TEST_GUARD.lock().await;
    METRICS.reset_all();

    // Start conformance runtime
    let profile = RuntimeProfile::conformance("observability-test-nf");
    let runtime = Builder::new(profile)
            .with_init(|supervisor, _shutdown| {
                Box::pin(async move {
                    supervisor
                        .register(
                            opc_runtime::TaskName::new("dummy"),
                            opc_runtime::TaskKind::Listener,
                            opc_runtime::Criticality::Fatal,
                            opc_runtime::RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();
                    supervisor
                        .spawn(
                            opc_runtime::TaskName::new("dummy"),
                            opc_runtime::TaskKind::Listener,
                            opc_runtime::Criticality::Fatal,
                            opc_runtime::RestartPolicy::no_restart(),
                            || {
                                Box::pin(async {
                                    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                                    Ok(())
                                })
                            },
                        )
                        .await
                        .unwrap();

                    // Failing task to test task error redaction and task debug output
                    supervisor
                        .register(
                            opc_runtime::TaskName::new("failing_task"),
                            opc_runtime::TaskKind::Listener,
                            opc_runtime::Criticality::BestEffort,
                            opc_runtime::RestartPolicy::no_restart(),
                        )
                        .await
                        .unwrap();
                    supervisor
                        .spawn(
                            opc_runtime::TaskName::new("failing_task"),
                            opc_runtime::TaskKind::Listener,
                            opc_runtime::Criticality::BestEffort,
                            opc_runtime::RestartPolicy::no_restart(),
                            || {
                                Box::pin(async {
                                    let err_src = std::io::Error::other(
                                        "database SQLite file spiffe://amf.openpacketcore.local/var/lib/secret.key failed",
                                    );
                                    Err(opc_runtime::TaskError::Failed(
                                        "failing_task".to_string(),
                                        std::sync::Arc::new(err_src),
                                    ))
                                })
                            },
                        )
                        .await
                        .unwrap();
                })
            })
            .build()
            .await
            .unwrap();

    // Set mock health states
    METRICS.runtime_health_live.store(1, Ordering::Relaxed);
    METRICS.runtime_health_ready.store(1, Ordering::Relaxed);
    METRICS.runtime_health_startup.store(1, Ordering::Relaxed);

    // Bind to random port
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    drop(listener); // Let start_admin_server re-bind to this port

    let runtime_clone = runtime.clone();
    let auth_token = Some("supersecrettoken123".to_string());

    // Spawn server in background
    let token_clone = auth_token.clone();
    tokio::spawn(async move {
        start_admin_server(
            runtime_clone,
            local_addr,
            RuntimeMode::Production,
            token_clone,
        )
        .await
        .unwrap();
    });

    // Wait a brief moment for the server to bind and the failing task to fail
    sleep(Duration::from_millis(200)).await;

    // 1. Production routes require the configured bearer token.
    let readyz_unauth = send_admin_request(local_addr, "/readyz", None).await;
    assert!(readyz_unauth.contains("HTTP/1.1 401 Unauthorized"));

    let readyz_auth = send_admin_request(local_addr, "/readyz", Some("supersecrettoken123")).await;
    assert!(readyz_auth.contains("HTTP/1.1 200 OK"));
    assert!(readyz_auth.contains("OK"));

    let livez_auth = send_admin_request(local_addr, "/livez", Some("supersecrettoken123")).await;
    assert!(livez_auth.contains("HTTP/1.1 200 OK"));
    assert!(livez_auth.contains("OK"));

    let startupz_auth =
        send_admin_request(local_addr, "/startupz", Some("supersecrettoken123")).await;
    assert!(startupz_auth.contains("HTTP/1.1 200 OK"));
    assert!(startupz_auth.contains("OK"));

    // 2. Metrics authorized access
    let metrics_auth =
        send_admin_request(local_addr, "/metrics", Some("supersecrettoken123")).await;
    assert!(metrics_auth.contains("HTTP/1.1 200 OK"));
    assert!(metrics_auth.contains("opc_runtime_health_live 1"));

    // 3. Debug routes authorized access
    let runtime_auth =
        send_admin_request(local_addr, "/debug/runtime", Some("supersecrettoken123")).await;
    assert!(runtime_auth.contains("HTTP/1.1 200 OK"));
    assert!(runtime_auth.contains("\"startup_phase\":\"Ready\""));
    assert!(runtime_auth.contains("\"readiness\":\"ready\""));

    let tasks_auth =
        send_admin_request(local_addr, "/debug/tasks", Some("supersecrettoken123")).await;
    assert!(tasks_auth.contains("HTTP/1.1 200 OK"));
    assert!(tasks_auth.contains("\"name\":\"dummy\""));
    assert!(tasks_auth.contains("\"name\":\"failing_task\""));
    assert!(tasks_auth.contains("\"current_state\":\"failed\""));
    assert!(tasks_auth.contains("\"last_failure_class\":\"failed\""));
    assert!(tasks_auth.contains("\"last_error\":\"<redacted>\""));
    assert!(!tasks_auth.contains("spiffe://"));
    assert!(!tasks_auth.contains("SQLite"));
    assert!(!tasks_auth.contains("secret.key"));

    let config_auth = send_admin_request(
        local_addr,
        "/debug/config-version",
        Some("supersecrettoken123"),
    )
    .await;
    assert!(config_auth.contains("HTTP/1.1 200 OK"));
    assert!(config_auth.contains("\"current_version\":null"));

    // Update config version metadata
    let config_metadata = opc_runtime::ConfigVersionMetadata {
        current_version: Some("tx-/var/lib/secret.key".to_string()),
        schema_digest: Some("sha256:digest-abcde".to_string()),
        state: Some("confirmed".to_string()),
    };
    runtime.update_config_version(config_metadata).await;

    let config_updated = send_admin_request(
        local_addr,
        "/debug/config-version",
        Some("supersecrettoken123"),
    )
    .await;
    assert!(config_updated.contains("\"current_version\":\"<redacted>\""));
    assert!(config_updated.contains("\"schema_digest\":\"sha256:digest-abcde\""));
    assert!(config_updated.contains("\"state\":\"confirmed\""));
    assert!(!config_updated.contains("/var/lib"));
    assert!(!config_updated.contains("secret.key"));

    // 4. Debug routes unauthorized access
    let runtime_unauth = send_admin_request(local_addr, "/debug/runtime", None).await;
    assert!(runtime_unauth.contains("HTTP/1.1 401 Unauthorized"));

    // 5. Unsupported method (405 Method Not Allowed)
    let mut stream_405 = tokio::net::TcpStream::connect(local_addr).await.unwrap();
    stream_405
        .write_all(b"POST /livez HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut resp_405 = Vec::new();
    stream_405.read_to_end(&mut resp_405).await.unwrap();
    let resp_405_str = String::from_utf8(resp_405).unwrap();
    assert!(resp_405_str.contains("HTTP/1.1 405 Method Not Allowed"));

    // 6. Unknown route (404 Not Found)
    let unknown_auth = send_admin_request(
        local_addr,
        "/debug/secret-token/path",
        Some("supersecrettoken123"),
    )
    .await;
    assert!(unknown_auth.contains("HTTP/1.1 404 Not Found"));

    // 7. Malformed request (400 Bad Request)
    let mut stream_400 = tokio::net::TcpStream::connect(local_addr).await.unwrap();
    stream_400
        .write_all(b"GARBAGE_REQUEST\r\n\r\n")
        .await
        .unwrap();
    let mut resp_400 = Vec::new();
    stream_400.read_to_end(&mut resp_400).await.unwrap();
    let resp_400_str = String::from_utf8(resp_400).unwrap();
    assert!(resp_400_str.contains("HTTP/1.1 400 Bad Request"));

    // 8. Request header size bound (431 Request Header Fields Too Large)
    let mut stream_431 = tokio::net::TcpStream::connect(local_addr).await.unwrap();
    let long_headers = "A".repeat(9 * 1024);
    let req_431 = format!(
        "GET /livez HTTP/1.1\r\nHost: localhost\r\n{}: value\r\n\r\n",
        long_headers
    );
    stream_431.write_all(req_431.as_bytes()).await.unwrap();
    let mut resp_431 = Vec::new();
    let _ = stream_431.read_to_end(&mut resp_431).await;
    let resp_431_str = String::from_utf8(resp_431).unwrap();
    assert!(resp_431_str.contains("HTTP/1.1 431 Request Header Fields Too Large"));

    // 9. Dev mode behavior allows bypass of token
    let dev_listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let dev_addr = dev_listener.local_addr().unwrap();
    drop(dev_listener);

    let runtime_dev = runtime.clone();
    tokio::spawn(async move {
        start_admin_server(runtime_dev, dev_addr, RuntimeMode::Dev, None)
            .await
            .unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    let dev_readyz = send_admin_request(dev_addr, "/readyz", None).await;
    assert!(dev_readyz.contains("HTTP/1.1 200 OK"));

    // 10. Metrics increment correctly
    let metrics_text =
        send_admin_request(local_addr, "/metrics", Some("supersecrettoken123")).await;
    assert!(metrics_text.contains("opc_admin_requests_total{route=\"readyz\",status=\"200\"}"));
    assert!(metrics_text.contains("opc_admin_requests_total{route=\"unknown\",status=\"404\"}"));
    assert!(!metrics_text.contains("secret-token"));
    assert!(!metrics_text.contains("route=\"redacted\",status=\"404\""));
    assert!(metrics_text.contains("opc_admin_auth_failures_total 2")); // 1 from /readyz unauth, 1 from /debug/runtime unauth
    assert!(metrics_text.contains("opc_admin_malformed_requests_total 2")); // 1 from garbage, 1 from too large
    assert!(metrics_text.contains("opc_admin_redaction_events_total 2")); // task error + unsafe config metadata
    assert!(metrics_text.contains("opc_admin_request_latency_seconds_count{route=\"livez\"}"));

    // 11. Production/Lab admin surfaces fail closed when no token is configured.
    let no_token_listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let no_token_addr = no_token_listener.local_addr().unwrap();
    drop(no_token_listener);

    let runtime_clone2 = runtime.clone();
    tokio::spawn(async move {
        start_admin_server(runtime_clone2, no_token_addr, RuntimeMode::Production, None)
            .await
            .unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    let no_token_metrics =
        send_admin_request(no_token_addr, "/metrics", Some("supersecrettoken123")).await;
    assert!(no_token_metrics.contains("HTTP/1.1 401 Unauthorized"));

    // Shutdown the runtime and verify server stops accepting
    runtime.shutdown().await;
}
