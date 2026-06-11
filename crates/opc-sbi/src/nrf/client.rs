//! TS 29.510 NRF client (NFManagement registration/heartbeat and
//! NFDiscovery), the periodic heartbeat driver, and the cache-fronted
//! discovery client with stale-if-error and production fail-closed rules.

use crate::nrf::{CacheLookup, DiscoveryCache, DiscoveryQuery, DiscoveryResult, NfProfile};
use crate::redact::{safe_metric_label, sanitize_error_message};
use async_trait::async_trait;
use opc_types::NfInstanceId;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// NRF service client operations
#[async_trait]
pub trait NrfOperations: Send + Sync {
    /// Register (or re-register) the NF profile with the NRF
    /// (TS 29.510 NFManagement `PUT .../nf-instances/{nfInstanceId}`).
    ///
    /// On success returns the heartbeat interval the NF must honor: the
    /// NRF-supplied `heartbeatTimer` (in seconds) when present, otherwise
    /// the implementation's default (30 s for `NrfClient`).
    async fn register(&self, profile: &NfProfile) -> Result<Duration, String>;
    /// Remove the NF instance from the NRF (TS 29.510 `DELETE`), making it
    /// undiscoverable; used for graceful shutdown.
    async fn deregister(&self, instance_id: &NfInstanceId) -> Result<(), String>;
    /// Send a keep-alive heartbeat (TS 29.510 `PATCH` of `nfStatus`).
    ///
    /// Returns the interval to wait before the next heartbeat — the NRF may
    /// re-negotiate it on every response.
    async fn heartbeat(&self, instance_id: &NfInstanceId) -> Result<Duration, String>;
    /// Query the NRF for NF instances matching `query` (TS 29.510
    /// NFDiscovery).
    ///
    /// NRF-level outcomes (found / not-found / NRF error) are reported in
    /// the `DiscoveryResult`; `Err` is reserved for failures to reach or
    /// speak to the NRF at all.
    async fn discover(&self, query: &DiscoveryQuery) -> Result<DiscoveryResult, String>;
}

/// NrfClient implementing HTTP/2 operations
pub struct NrfClient {
    client: crate::client::SbiClient,
    nrf_uri: String,
}

impl NrfClient {
    /// Wrap an `SbiClient` targeting the NRF at `nrf_uri` (scheme +
    /// authority, no trailing slash — paths like `/nnrf-nfm/v1/...` are
    /// appended verbatim). Retry, TLS, and circuit-breaking behavior come
    /// from the supplied client.
    pub fn new(client: crate::client::SbiClient, nrf_uri: String) -> Self {
        Self { client, nrf_uri }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NrfHeartbeatResponse {
    pub heartbeat_timer: Option<u32>,
}

#[async_trait]
impl NrfOperations for NrfClient {
    async fn register(&self, profile: &NfProfile) -> Result<Duration, String> {
        let uri = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri,
            profile.nf_instance_id.as_str()
        );

        let body =
            serde_json::to_vec(profile).map_err(|_| "failed to encode NRF profile".to_string())?;

        let request = http::Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/json")
            .body(body)
            .map_err(|_| "failed to build NRF registration request".to_string())?;

        let response = self.client.send(request).await?;

        if response.status().is_success() {
            // Parse heartbeat timer
            let body_bytes = response.into_body();
            if let Ok(res) = serde_json::from_slice::<NrfHeartbeatResponse>(&body_bytes) {
                if let Some(secs) = res.heartbeat_timer {
                    return Ok(Duration::from_secs(secs as u64));
                }
            }
            Ok(Duration::from_secs(30))
        } else {
            Err(format!(
                "NRF registration failed with status {}",
                response.status()
            ))
        }
    }

    async fn deregister(&self, instance_id: &NfInstanceId) -> Result<(), String> {
        let uri = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri,
            instance_id.as_str()
        );

        let request = http::Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Vec::new())
            .map_err(|_| "failed to build NRF deregistration request".to_string())?;

        let response = self.client.send(request).await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "NRF deregistration failed with status {}",
                response.status()
            ))
        }
    }

    async fn heartbeat(&self, instance_id: &NfInstanceId) -> Result<Duration, String> {
        let uri = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.nrf_uri,
            instance_id.as_str()
        );

        // standard heartbeat PATCH
        let patch_body = r#"[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]"#;

        let request = http::Request::builder()
            .method("PATCH")
            .uri(uri)
            .header("content-type", "application/json-patch+json")
            .body(patch_body.as_bytes().to_vec())
            .map_err(|_| "failed to build NRF heartbeat request".to_string())?;

        let response = self.client.send(request).await?;

        if response.status().is_success() {
            let body_bytes = response.into_body();
            if let Ok(res) = serde_json::from_slice::<NrfHeartbeatResponse>(&body_bytes) {
                if let Some(secs) = res.heartbeat_timer {
                    return Ok(Duration::from_secs(secs as u64));
                }
            }
            Ok(Duration::from_secs(30))
        } else {
            Err(format!(
                "NRF heartbeat failed with status {}",
                response.status()
            ))
        }
    }

    async fn discover(&self, query: &DiscoveryQuery) -> Result<DiscoveryResult, String> {
        // Construct query parameters
        let mut uri = format!(
            "{}/nnrf-disc/v1/nf-instances?target-nf-type={}",
            self.nrf_uri,
            percent_encode(query.target_nf_type.as_str())
        );
        if let Some(ref plmn) = query.plmn {
            let encoded = serde_json::to_string(plmn)
                .map(|value| percent_encode(&value))
                .map_err(|_| "failed to encode NRF discovery PLMN".to_string())?;
            uri.push_str("&target-plmn=");
            uri.push_str(&encoded);
        }
        for svc in &query.service_names {
            uri.push_str("&service-names=");
            uri.push_str(&percent_encode(svc));
        }

        let request = http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(Vec::new())
            .map_err(|_| "failed to build NRF discovery request".to_string())?;

        let response = self.client.send(request).await?;

        if response.status().is_success() {
            let body_bytes = response.into_body();
            // Parse NF profiles
            #[derive(Deserialize)]
            struct DiscoveryResponse {
                pub nf_instances: Vec<NfProfile>,
            }
            if let Ok(res) = serde_json::from_slice::<DiscoveryResponse>(&body_bytes) {
                Ok(DiscoveryResult::Found(res.nf_instances))
            } else {
                Ok(DiscoveryResult::NotFound)
            }
        } else if response.status() == http::StatusCode::NOT_FOUND {
            Ok(DiscoveryResult::NotFound)
        } else {
            Ok(DiscoveryResult::Error(format!(
                "NRF error: {}",
                response.status()
            )))
        }
    }
}

/// Periodic heartbeat task driver
pub struct HeartbeatDriver {
    nrf_client: Arc<dyn NrfOperations>,
    nf_instance_id: NfInstanceId,
    default_interval: Duration,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    degraded_tx: tokio::sync::watch::Sender<bool>,
}

impl HeartbeatDriver {
    /// Assemble a driver (it does nothing until `run` is awaited).
    ///
    /// `default_interval` is used until the NRF returns its own heartbeat
    /// timer; `shutdown_rx` flipping to `true` stops the loop (after a
    /// best-effort deregistration); `degraded_tx` is the channel on which
    /// the driver publishes the NF's degraded/healthy state to the rest of
    /// the process.
    pub fn new(
        nrf_client: Arc<dyn NrfOperations>,
        nf_instance_id: NfInstanceId,
        default_interval: Duration,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
        degraded_tx: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self {
            nrf_client,
            nf_instance_id,
            default_interval,
            shutdown_rx,
            degraded_tx,
        }
    }

    /// Run the heartbeat loop until shutdown is signalled.
    ///
    /// Each tick sends up to 3 heartbeat attempts with 1 s doubling backoff
    /// capped at 5 s between them. A successful heartbeat adopts the
    /// NRF-returned interval for the next tick and clears the degraded
    /// flag. After 3 consecutive fully failed ticks the driver publishes
    /// `degraded = true` on the watch channel — per RFC 007 §10.2 the NF
    /// keeps serving existing traffic while degraded; it is marked, not
    /// killed. On shutdown it deregisters from the NRF best-effort before
    /// returning. Outcomes are counted in `sbi_nrf_heartbeat_total`.
    pub async fn run(mut self) {
        let mut interval = self.default_interval;
        let mut consecutive_failures = 0;
        let max_failures = 3;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let mut backoff = Duration::from_secs(1);
                    let mut success = false;

                    for attempt in 1..=3 {
                        match self.nrf_client.heartbeat(&self.nf_instance_id).await {
                            Ok(new_interval) => {
                                interval = new_interval;
                                consecutive_failures = 0;
                                let _ = self.degraded_tx.send(false);
                                success = true;
                                opc_redaction::metrics::METRICS
                                    .sbi_nrf_heartbeat_total
                                    .lock()
                                    .unwrap()
                                    .entry("success".to_string())
                                    .and_modify(|c| *c += 1)
                                    .or_insert(1);
                                break;
                            }
                            Err(_) => {
                                opc_redaction::metrics::METRICS
                                    .sbi_nrf_heartbeat_total
                                    .lock()
                                    .unwrap()
                                    .entry("failure".to_string())
                                    .and_modify(|c| *c += 1)
                                    .or_insert(1);

                                if attempt < 3 {
                                    tokio::time::sleep(backoff).await;
                                    backoff = (backoff * 2).min(Duration::from_secs(5));
                                }
                            }
                        }
                    }

                    if !success {
                        consecutive_failures += 1;
                        if consecutive_failures >= max_failures {
                            let _ = self.degraded_tx.send(true);
                        }
                    }
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        // shutdown: deregister on exit
                        let _ = self.nrf_client.deregister(&self.nf_instance_id).await;
                        break;
                    }
                }
            }
        }
    }
}

/// Cached Discovery Client which performs discovery caching and enforces production boundaries
pub struct CachedDiscoveryClient {
    nrf_client: Arc<dyn NrfOperations>,
    cache: Arc<Mutex<DiscoveryCache>>,
    production_mode: bool,
}

impl CachedDiscoveryClient {
    /// Front `nrf_client` with `cache`. The cache is shared via
    /// `Arc<Mutex<..>>` so several consumers (and config-invalidation
    /// paths) can use one cache. `production_mode` switches stale handling
    /// for security-sensitive NF types from fail-open to fail-closed (see
    /// `discover`).
    pub fn new(
        nrf_client: Arc<dyn NrfOperations>,
        cache: Arc<Mutex<DiscoveryCache>>,
        production_mode: bool,
    ) -> Self {
        Self {
            nrf_client,
            cache,
            production_mode,
        }
    }

    /// Resolve `query` through the cache, falling back to the NRF.
    ///
    /// Behavior by cache state:
    /// - **Hit** (within TTL): served without touching the NRF.
    /// - **Stale** (TTL expired, within the stale-if-error window): a fresh
    ///   NRF lookup is attempted. On failure, non-sensitive targets fall
    ///   back to the stale profiles (fail-open, keeps routing alive while
    ///   the NRF is down); but in production mode, targets `UDM`, `AUSF`,
    ///   `NRF`, and `PCF` are fail-closed — stale data is rejected and an
    ///   error returned, so authentication/policy paths never run on
    ///   possibly revoked topology.
    /// - **Negative**: a cached NotFound is returned as an error without
    ///   re-querying (protects a struggling NRF from repeat misses).
    /// - **Miss**: the NRF is queried; Found results populate the cache,
    ///   NotFound is negatively cached and reported as an error.
    ///
    /// Every path increments a distinct `sbi_nrf_discovery_total` outcome
    /// label; error strings are sanitized before being returned.
    pub async fn discover(&self, query: &DiscoveryQuery) -> Result<Vec<NfProfile>, String> {
        let key = query.to_cache_key();

        let lookup = {
            let cache_lock = self.cache.lock().unwrap();
            cache_lock.lookup(&key)
        };

        match lookup {
            CacheLookup::Hit(profiles) => {
                opc_redaction::metrics::METRICS
                    .sbi_nrf_discovery_total
                    .lock()
                    .unwrap()
                    .entry("cache_hit".to_string())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                Ok(profiles)
            }
            CacheLookup::Stale(profiles) => {
                let is_sensitive = matches!(
                    query.target_nf_type.as_str().to_uppercase().as_str(),
                    "UDM" | "AUSF" | "NRF" | "PCF"
                );

                if self.production_mode && is_sensitive {
                    // Fail-closed for sensitive paths: do not silently use stale
                    match self.nrf_client.discover(query).await {
                        Ok(DiscoveryResult::Found(fresh_profiles)) => {
                            let mut cache_lock = self.cache.lock().unwrap();
                            cache_lock.insert(key, fresh_profiles.clone());
                            opc_redaction::metrics::METRICS
                                .sbi_nrf_discovery_total
                                .lock()
                                .unwrap()
                                .entry("refresh_success".to_string())
                                .and_modify(|c| *c += 1)
                                .or_insert(1);
                            Ok(fresh_profiles)
                        }
                        _ => {
                            opc_redaction::metrics::METRICS
                                .sbi_nrf_discovery_total
                                .lock()
                                .unwrap()
                                .entry("fail_closed".to_string())
                                .and_modify(|c| *c += 1)
                                .or_insert(1);
                            Err("NRF lookup failed for security-sensitive path (stale cache rejected in Production)".into())
                        }
                    }
                } else {
                    // Try to refresh, fall back to stale
                    match self.nrf_client.discover(query).await {
                        Ok(DiscoveryResult::Found(fresh_profiles)) => {
                            let mut cache_lock = self.cache.lock().unwrap();
                            cache_lock.insert(key, fresh_profiles.clone());
                            opc_redaction::metrics::METRICS
                                .sbi_nrf_discovery_total
                                .lock()
                                .unwrap()
                                .entry("refresh_success".to_string())
                                .and_modify(|c| *c += 1)
                                .or_insert(1);
                            Ok(fresh_profiles)
                        }
                        _ => {
                            opc_redaction::metrics::METRICS
                                .sbi_nrf_discovery_total
                                .lock()
                                .unwrap()
                                .entry("stale_fallback".to_string())
                                .and_modify(|c| *c += 1)
                                .or_insert(1);
                            Ok(profiles)
                        }
                    }
                }
            }
            CacheLookup::Negative => Err("Discovery cached negative result (NotFound)".into()),
            CacheLookup::Miss => match self.nrf_client.discover(query).await {
                Ok(DiscoveryResult::Found(profiles)) => {
                    let mut cache_lock = self.cache.lock().unwrap();
                    cache_lock.insert(key, profiles.clone());
                    opc_redaction::metrics::METRICS
                        .sbi_nrf_discovery_total
                        .lock()
                        .unwrap()
                        .entry("miss_found".to_string())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    opc_redaction::metrics::METRICS
                        .sbi_nrf_cache_entries
                        .lock()
                        .unwrap()
                        .insert(
                            safe_metric_label(query.target_nf_type.as_str()),
                            cache_lock.len() as u64,
                        );
                    Ok(profiles)
                }
                Ok(DiscoveryResult::NotFound) => {
                    let mut cache_lock = self.cache.lock().unwrap();
                    cache_lock.insert_negative(key);
                    opc_redaction::metrics::METRICS
                        .sbi_nrf_discovery_total
                        .lock()
                        .unwrap()
                        .entry("miss_not_found".to_string())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    Err("Discovery returned NotFound".into())
                }
                Ok(DiscoveryResult::Error(e)) => Err(format!(
                    "NRF discovery error: {}",
                    sanitize_error_message(e)
                )),
                Err(e) => Err(format!("NRF query failed: {}", sanitize_error_message(e))),
            },
        }
    }
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}
