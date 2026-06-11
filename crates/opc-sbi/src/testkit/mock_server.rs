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

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
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

pub struct MockProducer {
    addr: SocketAddr,
    state: MockState,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockProducer {
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

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn get_requests(&self) -> Vec<RecordedRequest> {
        let lock = self.state.inner.lock().unwrap();
        lock.requests.clone()
    }

    pub fn clear_requests(&self) {
        let mut lock = self.state.inner.lock().unwrap();
        lock.requests.clear();
    }

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

pub struct MockConsumer {
    client: crate::client::builder::SbiClient,
}

impl Default for MockConsumer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockConsumer {
    pub fn new() -> Self {
        let client = crate::client::builder::SbiClientBuilder::new()
            .with_http2_only(false)
            .build()
            .expect("testkit mock consumer uses explicit non-production plaintext");
        Self { client }
    }

    pub fn with_client(client: crate::client::builder::SbiClient) -> Self {
        Self { client }
    }

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
