use crate::client::circuit_breaker::CircuitBreakers;
use crate::redact::{safe_metric_label, sanitize_error_message};
use crate::retry::{RetryOutcome, RetryPolicy};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Production HTTP/2 SBI Client
#[derive(Clone)]
pub struct SbiClient {
    tls_config: Option<Arc<rustls::ClientConfig>>,
    connect_timeout: Duration,
    request_timeout: Duration,
    retry_policy: RetryPolicy,
    circuit_breakers: Arc<CircuitBreakers>,
    body_limit: usize,
    http2_only: bool,
    max_pool_entries: usize,
    pool: Arc<Mutex<HashMap<String, hyper::client::conn::http2::SendRequest<Full<Bytes>>>>>,
}

impl SbiClient {
    pub async fn send(&self, request: Request<Vec<u8>>) -> Result<Response<Bytes>, String> {
        let uri = request.uri().clone();
        let host = uri
            .host()
            .ok_or_else(|| "Missing host in URI".to_string())?;
        let port = uri.port_u16().unwrap_or(443);
        let addr = format!("{}:{}", host, port);

        let path = uri.path();
        let service_name = safe_metric_label(path.split('/').nth(1).unwrap_or("unknown"));
        let method_label = safe_metric_label(request.method().as_str());

        if request.body().len() > self.body_limit {
            return Err("request body limit exceeded".to_string());
        }

        // 1. Circuit Breaker Guard
        let cb = self.circuit_breakers.get(host, &service_name);
        {
            let mut cb_lock = cb.lock().unwrap();
            if !cb_lock.allow_request(Instant::now()) {
                // Return consistent 503
                return Err("Circuit breaker is open".to_string());
            }
        }

        // 2. Execute Request with Retry Policy
        let mut attempt = 1;
        let body_bytes = Bytes::from(request.body().clone());
        let (parts, _) = request.into_parts();

        loop {
            let req_full = Request::from_parts(parts.clone(), Full::new(body_bytes.clone()));
            let start = Instant::now();

            let res = self.send_single_attempt(&addr, host, req_full).await;
            let duration = start.elapsed();

            // Record duration metrics
            opc_redaction::metrics::METRICS
                .sbi_request_duration_seconds
                .lock()
                .unwrap()
                .entry((service_name.clone(), method_label.clone()))
                .or_default()
                .observe(duration.as_secs_f64());

            let outcome = match &res {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        cb.lock().unwrap().record_success(host, &service_name);
                        // Record success metrics
                        opc_redaction::metrics::METRICS
                            .sbi_requests_total
                            .lock()
                            .unwrap()
                            .entry((
                                "client".to_string(),
                                service_name.clone(),
                                method_label.clone(),
                                "success".to_string(),
                            ))
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                        return Ok(resp.clone());
                    } else {
                        RetryOutcome::Status(status)
                    }
                }
                Err(_) => RetryOutcome::TransportError,
            };

            // Record failure to circuit breaker
            cb.lock()
                .unwrap()
                .record_failure(host, &service_name, Instant::now());

            // Record failure metrics
            let outcome_str = match &outcome {
                RetryOutcome::Status(s) => s.as_str().to_string(),
                RetryOutcome::TransportError => "transport_error".to_string(),
            };
            opc_redaction::metrics::METRICS
                .sbi_requests_total
                .lock()
                .unwrap()
                .entry((
                    "client".to_string(),
                    service_name.clone(),
                    method_label.clone(),
                    outcome_str,
                ))
                .and_modify(|c| *c += 1)
                .or_insert(1);

            let dummy_req = Request::from_parts(parts.clone(), ());
            if self.retry_policy.should_retry(&dummy_req, attempt, outcome) {
                attempt += 1;
                let delay = self.retry_policy.backoff_delay(attempt);
                tokio::time::sleep(delay).await;
            } else {
                return res.map_err(|e| {
                    format!(
                        "request failed after retries: {}",
                        sanitize_error_message(e)
                    )
                });
            }
        }
    }

    async fn send_single_attempt(
        &self,
        addr: &str,
        host: &str,
        req: Request<Full<Bytes>>,
    ) -> Result<Response<Bytes>, String> {
        // 1. Get or create connection
        let mut send_request = self.get_connection(addr, host).await?;

        // 2. Send request with timeout
        let res_fut = send_request.send_request(req);

        let response = match tokio::time::timeout(self.request_timeout, res_fut).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => return Err("HTTP/2 send error".to_string()),
            Err(_) => return Err("Request timeout".to_string()),
        };

        // 3. Read body with limit
        let (parts, body) = response.into_parts();
        let mut body_bytes = Vec::new();
        let mut pin_body = Box::pin(body);

        while let Some(frame_res) = pin_body.frame().await {
            let frame = frame_res.map_err(|e| sanitize_error_message(e.to_string()))?;
            if let Some(data) = frame.data_ref() {
                if body_bytes.len() + data.len() > self.body_limit {
                    return Err("Response body limit exceeded".to_string());
                }
                body_bytes.extend_from_slice(data);
            }
        }

        Ok(Response::from_parts(parts, Bytes::from(body_bytes)))
    }

    async fn get_connection(
        &self,
        addr: &str,
        host: &str,
    ) -> Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>, String> {
        {
            let pool = self.pool.lock().unwrap();
            if let Some(send_req) = pool.get(addr) {
                if send_req.is_ready() {
                    return Ok(send_req.clone());
                }
            }
        }

        // Establish connection
        let tcp = tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| "Connection timeout".to_string())?
            .map_err(|_| "TCP connect failed".to_string())?;

        tcp.set_nodelay(true).ok();

        let send_req = if let Some(ref tls) = self.tls_config {
            let connector = TlsConnector::from(tls.clone());
            let server_name = rustls_pki_types::ServerName::try_from(host)
                .map_err(|_| "Invalid server name".to_string())?
                .to_owned();
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|_| "TLS handshake failed".to_string())?;

            let io = TokioIo::new(tls_stream);
            let (send_req, conn) =
                hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .handshake(io)
                    .await
                    .map_err(|_| "HTTP/2 handshake failed".to_string())?;

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::debug!("HTTP/2 connection error: {:?}", err);
                }
            });
            send_req
        } else {
            if self.http2_only {
                return Err("HTTP/2 required but TLS is not configured".to_string());
            }
            let io = TokioIo::new(tcp);
            let (send_req, conn) =
                hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .handshake(io)
                    .await
                    .map_err(|_| "HTTP/2 handshake failed".to_string())?;

            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::debug!("HTTP/2 connection error: {:?}", err);
                }
            });
            send_req
        };

        {
            let mut pool = self.pool.lock().unwrap();
            if pool.len() >= self.max_pool_entries {
                if let Some(first_key) = pool.keys().next().cloned() {
                    pool.remove(&first_key);
                }
            }
            pool.insert(addr.to_string(), send_req.clone());
        }
        Ok(send_req)
    }
}

/// Builder for SbiClient
pub struct SbiClientBuilder {
    tls_config: Option<Arc<rustls::ClientConfig>>,
    connect_timeout: Duration,
    request_timeout: Duration,
    retry_policy: Option<RetryPolicy>,
    circuit_breakers: Option<Arc<CircuitBreakers>>,
    body_limit: usize,
    http2_only: bool,
    production_mode: bool,
    max_pool_entries: usize,
}

impl Default for SbiClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SbiClientBuilder {
    pub fn new() -> Self {
        Self {
            tls_config: None,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            retry_policy: None,
            circuit_breakers: None,
            body_limit: 1024 * 1024 * 8, // 8 MiB default
            http2_only: true,
            production_mode: false,
            max_pool_entries: 256,
        }
    }

    pub fn with_tls(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = Some(policy);
        self
    }

    pub fn with_circuit_breakers(mut self, breakers: Arc<CircuitBreakers>) -> Self {
        self.circuit_breakers = Some(breakers);
        self
    }

    pub fn with_body_limit(mut self, limit: usize) -> Self {
        self.body_limit = limit;
        self
    }

    pub fn with_http2_only(mut self, enabled: bool) -> Self {
        self.http2_only = enabled;
        self
    }

    pub fn with_production_mode(mut self, enabled: bool) -> Self {
        self.production_mode = enabled;
        self
    }

    pub fn with_max_pool_entries(mut self, max: usize) -> Self {
        self.max_pool_entries = max;
        self
    }

    pub fn build(self) -> Result<SbiClient, String> {
        if self.body_limit == 0 {
            return Err("SBI client body limit must be greater than zero".to_string());
        }
        if self.connect_timeout.is_zero() || self.request_timeout.is_zero() {
            return Err("SBI client timeouts must be greater than zero".to_string());
        }
        if self.max_pool_entries == 0 {
            return Err("SBI client connection pool limit must be greater than zero".to_string());
        }
        if self.production_mode {
            if self.tls_config.is_none() {
                return Err("production SBI client requires TLS configuration".to_string());
            }
            if !self.http2_only {
                return Err("production SBI client requires HTTP/2-only mode".to_string());
            }
        }

        let retry_policy = self.retry_policy.unwrap_or_else(|| {
            RetryPolicy::new(
                3,
                Duration::from_millis(100),
                Duration::from_secs(1),
                crate::retry::Jitter::Full,
            )
        });
        let circuit_breakers = self
            .circuit_breakers
            .unwrap_or_else(|| Arc::new(CircuitBreakers::new(5, Duration::from_secs(30), 3)));

        Ok(SbiClient {
            tls_config: self.tls_config,
            connect_timeout: self.connect_timeout,
            request_timeout: self.request_timeout,
            retry_policy,
            circuit_breakers,
            body_limit: self.body_limit,
            http2_only: self.http2_only,
            max_pool_entries: self.max_pool_entries,
            pool: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}
