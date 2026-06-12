//! Authorized admin/probe routes and HTTP metrics server.
//!
//! Provides standardized HTTP routes `/metrics`, `/livez`, `/readyz`, and
//! `/startupz` along with debug/admin routes `/debug/runtime`, `/debug/tasks`,
//! and `/debug/config-version` with production token authorization and path/error redaction.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::metrics::METRICS;
use crate::profile::RuntimeMode;
use crate::RuntimeHandle;

use serde::{Deserialize, Serialize};

const MAX_ADMIN_REQUEST_BYTES: usize = 8 * 1024;
const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Config version metadata for visibility.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigVersionMetadata {
    /// Identifier of the currently applied config version/transaction (e.g.
    /// `tx-...`); `None` until the NF reports one through
    /// `RuntimeHandle::update_config_version`.
    pub current_version: Option<String>,
    /// Digest of the config schema the version was validated against, e.g.
    /// `sha256:...`; `None` when not yet reported.
    pub schema_digest: Option<String>,
    /// Commit lifecycle state of the version per RFC 001 (e.g. `confirmed`);
    /// `None` when not yet reported.
    pub state: Option<String>,
}

#[derive(Serialize)]
struct TaskView {
    name: String,
    criticality: String,
    restart_policy: RestartPolicyView,
    current_state: &'static str,
    restart_count: u32,
    last_failure_class: Option<String>,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct RestartPolicyView {
    max_restarts: u32,
    window_secs: u64,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    jitter: f64,
}

#[derive(Serialize)]
struct RuntimeView {
    mode: String,
    startup_phase: String,
    readiness: &'static str,
    liveness: bool,
    shutdown_phase: String,
    task_counts: TaskCountsView,
    uptime_seconds: u64,
    admin_server_version: &'static str,
}

#[derive(Serialize)]
struct TaskCountsView {
    total: usize,
    fatal: TaskStateCounts,
    degrade: TaskStateCounts,
    best_effort: TaskStateCounts,
}

#[derive(Serialize)]
struct TaskStateCounts {
    running: usize,
    failed: usize,
}

/// Drain status returned by `/debug/drain`.
#[derive(Serialize)]
struct DrainStatus {
    phase: &'static str,
    sessions_remaining: u64,
    started_at: Option<String>,
}

/// Starts a production-safe HTTP admin/probe server listening on the specified address.
///
/// In Production/Lab mode, requests to all endpoints must include a matching
/// `Authorization: Bearer <token>` header. If no non-empty token is configured,
/// the server fails closed by returning `401 Unauthorized` for every route.
pub async fn start_admin_server(
    handle: RuntimeHandle,
    addr: SocketAddr,
    mode: RuntimeMode,
    auth_token: Option<String>,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Admin HTTP server listening on http://{}", addr);

    loop {
        tokio::select! {
            _ = handle.shutdown_token().shutdown_acknowledged() => {
                tracing::info!("Admin HTTP server shutting down");
                break;
            }
            conn_res = listener.accept() => {
                match conn_res {
                    Ok((stream, _)) => {
                        let handle_clone = handle.clone();
                        let token_clone = auth_token.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_client(stream, handle_clone, mode, token_clone).await {
                                tracing::debug!("Error handling admin connection: {:?}", err);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to accept admin connection: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    handle: RuntimeHandle,
    mode: RuntimeMode,
    auth_token: Option<String>,
) -> Result<(), std::io::Error> {
    let mut req = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        let n = match timeout(ADMIN_REQUEST_TIMEOUT, stream.read(&mut buf)).await {
            Ok(read_res) => read_res?,
            Err(_) => {
                METRICS
                    .admin_malformed_requests_total
                    .fetch_add(1, Ordering::Relaxed);
                record_admin_request("unknown", 408);
                stream
                    .write_all(
                        b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\nRequest Timeout",
                    )
                    .await?;
                return Ok(());
            }
        };
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
        if req.len() > MAX_ADMIN_REQUEST_BYTES {
            METRICS
                .admin_malformed_requests_total
                .fetch_add(1, Ordering::Relaxed);
            record_admin_request("unknown", 431);
            stream
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\nRequest Header Fields Too Large",
                )
                .await?;
            return Ok(());
        }
        if req.windows(4).any(|w| w == b"\r\n\r\n") || req.windows(2).any(|w| w == b"\n\n") {
            break;
        }
    }

    if req.is_empty() {
        return Ok(());
    }

    let req_str = match std::str::from_utf8(&req) {
        Ok(s) => s,
        Err(_) => {
            METRICS
                .admin_malformed_requests_total
                .fetch_add(1, Ordering::Relaxed);
            record_admin_request("unknown", 400);
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBad Request")
                .await?;
            return Ok(());
        }
    };

    let mut lines = req_str.lines();
    let Some(req_line) = lines.next() else {
        METRICS
            .admin_malformed_requests_total
            .fetch_add(1, Ordering::Relaxed);
        record_admin_request("unknown", 400);
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBad Request")
            .await?;
        return Ok(());
    };

    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() != 3 || !parts[2].starts_with("HTTP/1.") {
        METRICS
            .admin_malformed_requests_total
            .fetch_add(1, Ordering::Relaxed);
        record_admin_request("unknown", 400);
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBad Request")
            .await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];
    let route = admin_route_label(path);

    if method != "GET" && !(method == "POST" && path == "/debug/drain") {
        record_admin_request(route, 405);
        stream
            .write_all(
                b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\nMethod Not Allowed",
            )
            .await?;
        return Ok(());
    }

    let start_time = handle.clock.monotonic();

    // Extract authorization header
    let mut authorized = true;
    if mode == RuntimeMode::Production || mode == RuntimeMode::Lab {
        authorized = false;
        if let Some(token) = auth_token.as_deref().filter(|t| !t.is_empty()) {
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                if !name.trim().eq_ignore_ascii_case("authorization") {
                    continue;
                }
                let mut auth_parts = value.split_whitespace();
                let scheme = auth_parts.next();
                let presented = auth_parts.next();
                if auth_parts.next().is_none()
                    && scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
                    && presented.is_some_and(|presented| constant_time_eq(presented, token))
                {
                    authorized = true;
                    break;
                }
            }
        }
    }

    if !authorized {
        METRICS
            .admin_auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
        record_admin_request(route, 401);
        stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nUnauthorized").await?;
        return Ok(());
    }

    let result = match path {
        "/metrics" => {
            let metrics_body = opc_redaction::metrics::export_prometheus_text();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                metrics_body.len(),
                metrics_body
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(200)
        }
        "/livez" => {
            let is_live = {
                let phase = handle.phase.read().await;
                *phase != crate::RuntimePhase::Stopped
            };
            if is_live {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK").await?;
                Ok(200)
            } else {
                stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot OK").await?;
                Ok(503)
            }
        }
        "/readyz" => {
            let ready = handle.readiness().await;
            if ready.can_serve() {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK").await?;
                Ok(200)
            } else {
                stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot OK").await?;
                Ok(503)
            }
        }
        "/startupz" => {
            let startup_complete = {
                let phase = handle.phase.read().await;
                *phase >= crate::RuntimePhase::Ready && *phase < crate::RuntimePhase::Stopped
            };
            if startup_complete {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK").await?;
                Ok(200)
            } else {
                stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot OK").await?;
                Ok(503)
            }
        }
        "/debug/runtime" => {
            let ready = handle.readiness().await;
            let readiness_str = if ready.can_serve() {
                "ready"
            } else if ready == crate::Readiness::Draining {
                "draining"
            } else if ready == crate::Readiness::Degraded {
                "degraded"
            } else {
                "not-ready"
            };

            let phase = handle.phase().await;
            let liveness = phase != crate::RuntimePhase::Stopped;
            let shutdown_phase = *handle.shutdown_token().subscribe().borrow();

            let mut total = 0;
            let mut fatal_running = 0;
            let mut fatal_failed = 0;
            let mut degrade_running = 0;
            let mut degrade_failed = 0;
            let mut best_effort_running = 0;
            let mut best_effort_failed = 0;

            {
                let tasks = handle.supervisor().tasks.read().await;
                for state in tasks.values() {
                    total += 1;
                    let is_running = state.handle.as_ref().is_some_and(|h| h.is_running());
                    let is_failed = state.is_failed;
                    match state.metadata.criticality {
                        crate::task::Criticality::Fatal => {
                            if is_running {
                                fatal_running += 1;
                            }
                            if is_failed {
                                fatal_failed += 1;
                            }
                        }
                        crate::task::Criticality::Degrade => {
                            if is_running {
                                degrade_running += 1;
                            }
                            if is_failed {
                                degrade_failed += 1;
                            }
                        }
                        crate::task::Criticality::BestEffort => {
                            if is_running {
                                best_effort_running += 1;
                            }
                            if is_failed {
                                best_effort_failed += 1;
                            }
                        }
                    }
                }
            }

            let uptime = handle.started_at.elapsed().as_secs();

            let runtime_data = RuntimeView {
                mode: format!("{mode:?}").to_lowercase(),
                startup_phase: format!("{phase}"),
                readiness: readiness_str,
                liveness,
                shutdown_phase: format!("{shutdown_phase}"),
                task_counts: TaskCountsView {
                    total,
                    fatal: TaskStateCounts {
                        running: fatal_running,
                        failed: fatal_failed,
                    },
                    degrade: TaskStateCounts {
                        running: degrade_running,
                        failed: degrade_failed,
                    },
                    best_effort: TaskStateCounts {
                        running: best_effort_running,
                        failed: best_effort_failed,
                    },
                },
                uptime_seconds: uptime,
                admin_server_version: "1.0.0",
            };

            write_json_response(&mut stream, &runtime_data).await
        }
        "/debug/tasks" => {
            let mut views = Vec::new();
            {
                let tasks = handle.supervisor().tasks.read().await;
                for (name, state) in tasks.iter() {
                    let is_running = state.handle.as_ref().is_some_and(|h| h.is_running());
                    let current_state = if is_running {
                        "running"
                    } else if state.is_failed {
                        "failed"
                    } else {
                        "stopped"
                    };

                    let (last_failure_class, last_error) = if let Some(ref err) = state.last_error {
                        match err {
                            crate::task::TaskError::Failed(_, source) => (
                                Some("failed".to_string()),
                                Some(redact_error_msg(&source.to_string())),
                            ),
                            crate::task::TaskError::Aborted(_) => (
                                Some("aborted".to_string()),
                                Some("task was aborted".to_string()),
                            ),
                            crate::task::TaskError::Panicked(_, msg) => {
                                (Some("panicked".to_string()), Some(redact_error_msg(msg)))
                            }
                        }
                    } else {
                        (None, None)
                    };

                    views.push(TaskView {
                        name: redact_debug_value(&name.to_string()),
                        criticality: format!("{}", state.metadata.criticality),
                        restart_policy: RestartPolicyView {
                            max_restarts: state.metadata.restart.max_restarts,
                            window_secs: state.metadata.restart.window_secs,
                            base_backoff_ms: state.metadata.restart.base_backoff_ms,
                            max_backoff_ms: state.metadata.restart.max_backoff_ms,
                            jitter: state.metadata.restart.jitter,
                        },
                        current_state,
                        restart_count: state.failures_in_window,
                        last_failure_class,
                        last_error,
                    });
                }
            }

            write_json_response(&mut stream, &views).await
        }
        "/debug/config-version" => {
            let metadata = handle.config_version().await;
            let metadata = sanitized_config_metadata(metadata);
            write_json_response(&mut stream, &metadata).await
        }
        "/debug/drain" => {
            if method == "POST" {
                handle.shutdown_token().request_shutdown();
            }
            let shutdown_phase = *handle.shutdown_token().subscribe().borrow();
            let readiness = handle.readiness().await;
            let phase = if readiness == crate::Readiness::Draining {
                "InProgress"
            } else if shutdown_phase == crate::shutdown::ShutdownPhase::Stopped {
                "Complete"
            } else if shutdown_phase > crate::shutdown::ShutdownPhase::Running {
                "InProgress"
            } else {
                "Failed"
            };
            let status = DrainStatus {
                phase,
                sessions_remaining: 0,
                started_at: None,
            };
            write_json_response(&mut stream, &status).await
        }
        _ => {
            stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot Found").await?;
            Ok(404)
        }
    };

    let elapsed = handle
        .clock
        .monotonic()
        .duration_since(start_time)
        .as_secs_f64();
    if let Ok(status_code) = result {
        record_admin_request(route, status_code);
        match route {
            "livez" => METRICS.admin_latency_livez.observe(elapsed),
            "readyz" => METRICS.admin_latency_readyz.observe(elapsed),
            "startupz" => METRICS.admin_latency_startupz.observe(elapsed),
            "metrics" => METRICS.admin_latency_metrics.observe(elapsed),
            "debug_runtime" => METRICS.admin_latency_debug_runtime.observe(elapsed),
            "debug_tasks" => METRICS.admin_latency_debug_tasks.observe(elapsed),
            "debug_config_version" => METRICS.admin_latency_debug_config_version.observe(elapsed),
            _ => {}
        }
    }

    Ok(())
}

fn admin_route_label(path: &str) -> &'static str {
    match path {
        "/livez" => "livez",
        "/readyz" => "readyz",
        "/startupz" => "startupz",
        "/metrics" => "metrics",
        "/debug/runtime" => "debug_runtime",
        "/debug/tasks" => "debug_tasks",
        "/debug/config-version" => "debug_config_version",
        "/debug/drain" => "debug_drain",
        _ => "unknown",
    }
}

fn record_admin_request(route: &str, status: u16) {
    let mut reqs = METRICS.admin_requests_total.lock().unwrap();
    let count = reqs
        .entry((route.to_string(), status.to_string()))
        .or_insert(0);
    *count += 1;
}

async fn write_json_response<T: Serialize>(
    stream: &mut tokio::net::TcpStream,
    data: &T,
) -> Result<u16, std::io::Error> {
    let body = match serde_json::to_string(data) {
        Ok(b) => b,
        Err(_) => {
            stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSerialization error").await?;
            return Ok(500);
        }
    };

    if body.len() > MAX_RESPONSE_BODY_BYTES {
        stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nResponse size limit exceeded").await?;
        return Ok(500);
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(200)
}

fn redact_error_msg(msg: &str) -> String {
    redact_sensitive_debug_string(msg, true)
}

fn redact_debug_value(value: &str) -> String {
    redact_sensitive_debug_string(value, false)
}

fn redact_sensitive_debug_string(value: &str, redact_colon: bool) -> String {
    let lower = value.to_lowercase();
    let contains_path_like_colon = redact_colon && lower.contains(':');
    let contains_uri = lower.contains("://");
    if lower.contains("spiffe://")
        || lower.contains("-----begin")
        || lower.contains('/')
        || lower.contains('\\')
        || lower.contains('@')
        || contains_path_like_colon
        || lower.contains('=')
        || lower.contains(',')
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("password")
        || lower.contains("sqlite")
        || lower.contains("database")
        || lower.contains("db")
        || lower.contains("select")
        || lower.contains("insert")
        || lower.contains("update")
        || lower.contains("delete")
        || lower.contains("pem")
        || lower.contains("cert")
        || lower.contains("gpsi")
        || lower.contains("supi")
        || lower.contains("imsi")
        || lower.contains("msisdn")
        || lower.contains("guti")
        || lower.contains("pei")
        || contains_uri
        || looks_like_ipv4_contains(&lower)
        || has_8_digits(&lower)
    {
        METRICS
            .admin_redaction_events_total
            .fetch_add(1, Ordering::Relaxed);
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

fn sanitized_config_metadata(metadata: ConfigVersionMetadata) -> ConfigVersionMetadata {
    ConfigVersionMetadata {
        current_version: metadata.current_version.map(|v| redact_debug_value(&v)),
        schema_digest: metadata.schema_digest.map(|v| redact_debug_value(&v)),
        state: metadata.state.map(|v| redact_debug_value(&v)),
    }
}

fn looks_like_ipv4_contains(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut j = i;
            let mut dot_count = 0;
            let mut digits = 0;
            while j < bytes.len() {
                if bytes[j].is_ascii_digit() {
                    digits += 1;
                    if digits > 3 {
                        break;
                    }
                } else if bytes[j] == b'.' {
                    if digits == 0 {
                        break;
                    }
                    dot_count += 1;
                    digits = 0;
                } else {
                    break;
                }
                j += 1;
            }
            if dot_count == 3 && digits > 0 && digits <= 3 {
                return true;
            }
        }
    }
    false
}

fn has_8_digits(s: &str) -> bool {
    let mut consecutive = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            consecutive += 1;
            if consecutive >= 8 {
                return true;
            }
        } else {
            consecutive = 0;
        }
    }
    false
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..max_len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(av ^ bv);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{admin_route_label, constant_time_eq, DrainStatus};

    #[test]
    fn token_compare_checks_full_value() {
        assert!(constant_time_eq(
            "supersecrettoken123",
            "supersecrettoken123"
        ));
        assert!(!constant_time_eq(
            "supersecrettoken123",
            "supersecrettoken124"
        ));
        assert!(!constant_time_eq("short", "shorter"));
    }

    #[test]
    fn admin_route_label_includes_drain() {
        assert_eq!(admin_route_label("/debug/drain"), "debug_drain");
    }

    #[test]
    fn drain_status_serializes() {
        let s = DrainStatus {
            phase: "InProgress",
            sessions_remaining: 0,
            started_at: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"phase\":\"InProgress\""));
    }
}
