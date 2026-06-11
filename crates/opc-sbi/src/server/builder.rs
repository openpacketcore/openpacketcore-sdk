use crate::auth::SbiAuth;
use crate::problem::ProblemDetails;
use crate::redact::{safe_metric_label, sanitize_error_message};
use axum::{
    extract::State,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use http::StatusCode;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use opc_identity::TrustBundleSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// Production HTTP/2 SBI Server Builder
pub struct SbiServerBuilder {
    addr: SocketAddr,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    trust_bundles: Option<Arc<TrustBundleSet>>,
    body_limit: usize,
    request_timeout: Duration,
    auth_policy: Option<Arc<dyn SbiAuth>>,
    max_concurrency: usize,
    concurrency_counter: Arc<AtomicUsize>,
    production_mode: bool,
}

impl SbiServerBuilder {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls_config: None,
            trust_bundles: None,
            body_limit: 1024 * 1024 * 8, // 8 MiB default
            request_timeout: Duration::from_secs(10),
            auth_policy: None,
            max_concurrency: 1000,
            concurrency_counter: Arc::new(AtomicUsize::new(0)),
            production_mode: false,
        }
    }

    pub fn with_tls(mut self, config: Arc<rustls::ServerConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub fn with_trust_bundles(mut self, bundles: Arc<TrustBundleSet>) -> Self {
        self.trust_bundles = Some(bundles);
        self
    }

    pub fn with_body_limit(mut self, limit: usize) -> Self {
        self.body_limit = limit;
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn with_auth_policy(mut self, policy: Arc<dyn SbiAuth>) -> Self {
        self.auth_policy = Some(policy);
        self
    }

    pub fn with_max_concurrency(mut self, max: usize) -> Self {
        self.max_concurrency = max;
        self
    }

    pub fn with_production_mode(mut self, enabled: bool) -> Self {
        self.production_mode = enabled;
        self
    }

    fn validate(&self) -> Result<(), String> {
        if self.body_limit == 0 {
            return Err("SBI server body limit must be greater than zero".to_string());
        }
        if self.request_timeout.is_zero() {
            return Err("SBI server request timeout must be greater than zero".to_string());
        }
        if self.production_mode {
            if self.max_concurrency == 0 {
                return Err(
                    "production SBI server concurrency limit must be greater than zero".to_string(),
                );
            }
            if self.tls_config.is_none() {
                return Err("production SBI server requires TLS configuration".to_string());
            }
            if self.auth_policy.is_none() {
                return Err("production SBI server requires an auth policy".to_string());
            }
            let trust_bundle_missing = match self.trust_bundles.as_ref() {
                Some(bundles) => bundles.bundles.is_empty(),
                None => true,
            };
            if trust_bundle_missing {
                return Err("production SBI server requires trust bundles".to_string());
            }
        }
        Ok(())
    }

    pub async fn run_with_listener(
        self,
        listener: TcpListener,
        router: Router,
    ) -> Result<(), String> {
        self.validate()?;
        let auth_state = (self.auth_policy.clone(), self.production_mode);
        let trust_bundles = self.trust_bundles.clone();
        let concurrency_state = (self.max_concurrency, self.concurrency_counter.clone());

        // Build middleware stack
        let app = router
            .layer(middleware::from_fn_with_state(auth_state, auth_middleware))
            .layer(middleware::from_fn_with_state(
                concurrency_state,
                admission_middleware,
            ))
            .layer(middleware::from_fn(catch_panic_middleware))
            .layer(axum::extract::DefaultBodyLimit::max(self.body_limit))
            .layer(tower_http::timeout::TimeoutLayer::with_status_code(
                StatusCode::GATEWAY_TIMEOUT,
                self.request_timeout,
            ));

        if let Some(ref tls) = self.tls_config {
            let acceptor = TlsAcceptor::from(tls.clone());
            loop {
                let (stream, _peer_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                let trust_bundles = trust_bundles.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    // Retrieve peer client identity from TLS stream
                    let (_, connection) = tls_stream.get_ref();
                    let peer = connection
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .and_then(|cert| {
                            let bundles = trust_bundles.as_ref()?;
                            let id = opc_identity::WorkloadIdentity::from_cert_der(
                                cert.as_ref(),
                                bundles.as_ref(),
                            )
                            .ok()?;
                            let spiffe_str = format!(
                                "spiffe://{}/tenant/{}/ns/core/sa/default/nf/{}/instance/{}",
                                id.trust_domain, id.tenant, id.nf_kind, id.instance
                            );
                            Some(crate::auth::SbiPeer {
                                spiffe: opc_types::SpiffeId::new(spiffe_str).ok(),
                                nf_instance_id: opc_types::NfInstanceId::new(id.instance.as_str())
                                    .ok(),
                                nf_type: opc_types::NfType::new(id.nf_kind.as_str()).ok(),
                                tenant: id.tenant,
                                plmn: None,
                                snssai: None,
                            })
                        });

                    let tower_service =
                        tower::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                            let app = app.clone();
                            let peer = peer.clone();
                            async move {
                                let mut req = req.map(axum::body::Body::new);
                                if let Some(p) = peer {
                                    req.extensions_mut().insert(p);
                                }
                                app.oneshot(req).await
                            }
                        });

                    let io = TokioIo::new(tls_stream);
                    let hyper_service = TowerToHyperService::new(tower_service);
                    if let Err(err) = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, hyper_service)
                    .await
                    {
                        tracing::debug!("error serving HTTP/2 SBI connection: {:?}", err);
                    }
                });
            }
        } else {
            // Unencrypted HTTP/2 server for local/test profiles only.
            loop {
                let (stream, _peer_addr) = match listener.accept().await {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let hyper_app = TowerToHyperService::new(app);
                    if let Err(err) = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, hyper_app)
                    .await
                    {
                        tracing::debug!("error serving HTTP/2 SBI connection: {:?}", err);
                    }
                });
            }
        }
    }

    pub async fn run(self, router: Router) -> Result<(), String> {
        self.validate()?;
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(|e| sanitize_error_message(format!("Failed to bind port: {}", e)))?;
        self.run_with_listener(listener, router).await
    }
}

async fn auth_middleware(
    State((auth_policy, production_mode)): State<(Option<Arc<dyn SbiAuth>>, bool)>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, Response> {
    if let Some(ref policy) = auth_policy {
        let headers = req.headers();
        let sbi_headers = crate::headers::SbiHeaders::parse(headers).map_err(|_| {
            let details = ProblemDetails::new(StatusCode::BAD_REQUEST);
            (StatusCode::BAD_REQUEST, axum::Json(details)).into_response()
        })?;

        let bearer_token =
            crate::headers::extract_bearer_token_from_headers(headers).map_err(|_| {
                let details = ProblemDetails::new(StatusCode::BAD_REQUEST);
                (StatusCode::BAD_REQUEST, axum::Json(details)).into_response()
            })?;

        let peer = match req.extensions().get::<crate::auth::SbiPeer>().cloned() {
            Some(peer) => peer,
            None if production_mode => {
                let mut details = ProblemDetails::new(StatusCode::UNAUTHORIZED);
                details.detail = Some("peer identity required".to_string());
                return Err((StatusCode::UNAUTHORIZED, axum::Json(details)).into_response());
            }
            None => crate::auth::SbiPeer {
                spiffe: None,
                nf_instance_id: None,
                nf_type: None,
                tenant: opc_types::TenantId::new("default").expect("static tenant is valid"),
                plmn: None,
                snssai: None,
            },
        };

        let auth_req = crate::auth::SbiAuthRequest {
            method: req.method().clone(),
            path: req.uri().path().to_string(),
            headers: sbi_headers,
            bearer_token,
            peer,
        };

        match policy.authorize(&auth_req).await {
            Ok(context) => {
                req.extensions_mut()
                    .insert(crate::auth::ErasedAuthContext::from(&context));
                req.extensions_mut().insert(context);
            }
            Err(err) => {
                let status = match err {
                    crate::auth::SbiAuthError::MissingBearerToken => StatusCode::UNAUTHORIZED,
                    _ => StatusCode::FORBIDDEN,
                };
                let mut details = ProblemDetails::new(status);
                details.detail = Some("authorization failed".to_string());
                return Err((status, axum::Json(details)).into_response());
            }
        }
    }
    Ok(next.run(req).await)
}

async fn admission_middleware(
    State((max, counter)): State<(usize, Arc<AtomicUsize>)>,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, Response> {
    let current = counter.fetch_add(1, Ordering::Relaxed);
    if current >= max {
        counter.fetch_sub(1, Ordering::Relaxed);

        let path = req.uri().path();
        let service_name = safe_metric_label(path.split('/').nth(1).unwrap_or("unknown"));

        opc_redaction::metrics::METRICS
            .sbi_overload_rejections_total
            .lock()
            .unwrap()
            .entry((service_name, "concurrency_limit".to_string()))
            .and_modify(|c| *c += 1)
            .or_insert(1);

        let mut details = ProblemDetails::new(StatusCode::SERVICE_UNAVAILABLE);
        details.detail = Some("server overloaded".to_string());

        let response = problem_response(StatusCode::SERVICE_UNAVAILABLE, &details, Some("30"));
        return Err(response);
    }

    let response = next.run(req).await;
    counter.fetch_sub(1, Ordering::Relaxed);
    Ok(response)
}

async fn catch_panic_middleware(req: axum::extract::Request, next: Next) -> Response {
    let fut = std::panic::AssertUnwindSafe(next.run(req));
    match futures_util::FutureExt::catch_unwind(fut).await {
        Ok(res) => res,
        Err(_) => {
            let mut details = ProblemDetails::new(StatusCode::INTERNAL_SERVER_ERROR);
            details.detail = Some("internal server error".to_string());
            problem_response(StatusCode::INTERNAL_SERVER_ERROR, &details, None)
        }
    }
}

fn problem_response(
    status: StatusCode,
    details: &ProblemDetails,
    retry_after: Option<&'static str>,
) -> Response {
    let body = serde_json::to_vec(details).unwrap_or_else(|_| b"{}".to_vec());
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if let Some(value) = retry_after {
        builder = builder.header("retry-after", value);
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()))
}
