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
    async fn register(&self, profile: &NfProfile) -> Result<Duration, String>;
    async fn deregister(&self, instance_id: &NfInstanceId) -> Result<(), String>;
    async fn heartbeat(&self, instance_id: &NfInstanceId) -> Result<Duration, String>;
    async fn discover(&self, query: &DiscoveryQuery) -> Result<DiscoveryResult, String>;
}

/// NrfClient implementing HTTP/2 operations
pub struct NrfClient {
    client: crate::client::SbiClient,
    nrf_uri: String,
}

impl NrfClient {
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
