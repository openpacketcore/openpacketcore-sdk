//! Mock SBI producer and consumer for integration tests.
//!
//! `MockProducer` runs a real `SbiServerBuilder` HTTP/2 server on an
//! ephemeral loopback port, records every request it receives, and replays
//! configurable per-path response overrides. `MockConsumer` wraps a
//! plaintext-capable `SbiClient` for driving requests at it (or at any
//! other server) from tests.

use axum::{
    extract::{Request, State},
    response::Response,
    routing::any,
    Router,
};
use http::StatusCode;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// One request captured by `MockProducer`, in the order received, for test
/// assertions. Values are stored raw (including any `Authorization`
/// header), so recorded requests must stay inside test code.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// HTTP method as an uppercase string (e.g. `"GET"`).
    pub method: String,
    /// Request path only (no scheme/authority/query).
    pub path: String,
    /// Request headers; values that are not valid UTF-8 are silently
    /// dropped. Duplicate header names keep only the last value.
    pub headers: HashMap<String, String>,
    /// Raw request body bytes, fully buffered.
    pub body: Vec<u8>,
}

#[derive(Clone)]
struct MockState {
    inner: Arc<Mutex<MockProducerInner>>,
}

#[allow(clippy::type_complexity)]
struct MockProducerInner {
    requests: Vec<RecordedRequest>,
    overrides: HashMap<String, (StatusCode, HashMap<String, String>, Vec<u8>)>,
}

/// In-process mock SBI producer backed by the real `SbiServerBuilder`
/// HTTP/2 stack (plaintext, non-production defaults).
///
/// Catches all paths: requests are recorded, then answered with the
/// matching path override if one was set, otherwise an empty `200 OK`.
/// The server task is aborted when the producer is dropped.
pub struct MockProducer {
    addr: SocketAddr,
    state: MockState,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockProducer {
    /// Bind an ephemeral `127.0.0.1` port and start serving in a spawned
    /// background task; returns once the listener is bound, so requests
    /// can be sent immediately.
    pub async fn start() -> Self {
        let state = MockState {
            inner: Arc::new(Mutex::new(MockProducerInner {
                requests: Vec::new(),
                overrides: HashMap::new(),
            })),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new()
            .route("/{*path}", any(handle_request))
            .with_state(state.clone());

        // Run SbiServerBuilder
        let server = crate::server::builder::SbiServerBuilder::new(addr);
        let handle = tokio::spawn(async move {
            let _ = server.run_with_listener(listener, app).await;
        });

        Self {
            addr,
            state,
            _handle: handle,
        }
    }

    /// The bound loopback socket address (with the actual ephemeral port).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Base URL of the producer (`http://127.0.0.1:<port>`); plaintext, as
    /// the mock never configures TLS.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Snapshot of every request received so far, in arrival order.
    /// Includes requests answered by overrides.
    pub fn get_requests(&self) -> Vec<RecordedRequest> {
        let lock = self.state.inner.lock().unwrap();
        lock.requests.clone()
    }

    /// Discard all recorded requests (overrides are left in place), so a
    /// test can assert only on traffic after a known point.
    pub fn clear_requests(&self) {
        let mut lock = self.state.inner.lock().unwrap();
        lock.requests.clear();
    }

    /// Make every subsequent request whose path equals `path` (exact
    /// match, no patterns) receive this status, headers, and body instead
    /// of the default empty `200 OK`. Setting the same path again replaces
    /// the previous override.
    pub fn set_override(
        &self,
        path: &str,
        status: StatusCode,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) {
        let mut lock = self.state.inner.lock().unwrap();
        lock.overrides
            .insert(path.to_string(), (status, headers, body));
    }

    /// Remove every path override, restoring the default empty `200 OK`
    /// for all paths.
    pub fn clear_overrides(&self) {
        let mut lock = self.state.inner.lock().unwrap();
        lock.overrides.clear();
    }
}

async fn handle_request(State(state): State<MockState>, req: Request) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let mut headers = HashMap::new();
    for (k, v) in req.headers() {
        if let Ok(val) = v.to_str() {
            headers.insert(k.to_string(), val.to_string());
        }
    }

    // Read body
    let mut body = req.into_body();
    let mut body_bytes = Vec::new();
    while let Some(frame_res) = body.frame().await {
        if let Ok(frame) = frame_res {
            if let Some(data) = frame.data_ref() {
                body_bytes.extend_from_slice(data);
            }
        }
    }

    // Record request
    {
        let mut lock = state.inner.lock().unwrap();
        lock.requests.push(RecordedRequest {
            method,
            path: path.clone(),
            headers,
            body: body_bytes,
        });
    }

    // Check overrides
    let lock = state.inner.lock().unwrap();
    if let Some((status, resp_headers, body_content)) = lock.overrides.get(&path) {
        let mut builder = Response::builder().status(*status);
        for (k, v) in resp_headers {
            builder = builder.header(k, v);
        }
        builder
            .body(axum::body::Body::from(body_content.clone()))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::empty())
            .unwrap()
    }
}

/// Test-side SBI consumer: a thin wrapper over `SbiClient` that flattens
/// responses into `(status, headers, body)` tuples convenient for
/// assertions.
pub struct MockConsumer {
    client: crate::client::builder::SbiClient,
}

impl Default for MockConsumer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockConsumer {
    /// Build a consumer around a default `SbiClient` with `http2_only`
    /// disabled, so it can speak plaintext HTTP/2 to `MockProducer`.
    /// Deliberately non-production-grade; tests needing TLS or custom
    /// retry behavior should use `with_client`.
    pub fn new() -> Self {
        let client = crate::client::builder::SbiClientBuilder::new()
            .with_http2_only(false)
            .build()
            .expect("testkit mock consumer uses explicit non-production plaintext");
        Self { client }
    }

    /// Build a consumer around a caller-configured `SbiClient` (e.g. with
    /// TLS, a custom retry policy, or shared circuit breakers).
    pub fn with_client(client: crate::client::builder::SbiClient) -> Self {
        Self { client }
    }

    /// Send a `GET` with the given extra headers and return
    /// `(status, headers, body)`. Goes through the full `SbiClient::send`
    /// stack (circuit breaker, retries, body limits); response headers
    /// with non-UTF-8 values are dropped from the returned map.
    pub async fn send_get(
        &self,
        url: &str,
        headers: HashMap<String, String>,
    ) -> Result<(StatusCode, HashMap<String, String>, Vec<u8>), String> {
        let mut req_builder = http::Request::builder().method("GET").uri(url);
        for (k, v) in headers {
            req_builder = req_builder.header(k, v);
        }
        let req = req_builder.body(Vec::new()).map_err(|e| e.to_string())?;
        let resp = self.client.send(req).await?;
        let (parts, body) = resp.into_parts();

        let mut resp_headers = HashMap::new();
        for (k, v) in parts.headers {
            if let Some(k_str) = k {
                if let Ok(val) = v.to_str() {
                    resp_headers.insert(k_str.to_string(), val.to_string());
                }
            }
        }
        Ok((parts.status, resp_headers, body.to_vec()))
    }

    /// Send a `POST` with the given extra headers and body and return
    /// `(status, headers, body)`. Note: a plain POST is not retryable
    /// under the default retry policy unless an `idempotency-key` header
    /// is included in `headers`.
    pub async fn send_post(
        &self,
        url: &str,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Result<(StatusCode, HashMap<String, String>, Vec<u8>), String> {
        let mut req_builder = http::Request::builder().method("POST").uri(url);
        for (k, v) in headers {
            req_builder = req_builder.header(k, v);
        }
        let req = req_builder.body(body).map_err(|e| e.to_string())?;
        let resp = self.client.send(req).await?;
        let (parts, body_bytes) = resp.into_parts();

        let mut resp_headers = HashMap::new();
        for (k, v) in parts.headers {
            if let Some(k_str) = k {
                if let Ok(val) = v.to_str() {
                    resp_headers.insert(k_str.to_string(), val.to_string());
                }
            }
        }
        Ok((parts.status, resp_headers, body_bytes.to_vec()))
    }
}
