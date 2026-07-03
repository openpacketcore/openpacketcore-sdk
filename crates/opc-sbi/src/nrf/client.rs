//! TS 29.510 NRF client (NFManagement registration/heartbeat and
//! NFDiscovery), the periodic heartbeat driver, and the cache-fronted
//! discovery client with stale-if-error and production fail-closed rules.

use crate::lock_or_recover;
use crate::nrf::{
    CacheLookup, DiscoveryCache, DiscoveryQuery, DiscoveryResult, NfProfile, NrfDeregNotifier,
};
use crate::redact::{safe_metric_label, sanitize_error_message};
use async_trait::async_trait;
use opc_types::NfInstanceId;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const MAX_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3600);
const NRF_HEARTBEAT_NOT_FOUND: &str = "nrf_heartbeat_not_found";

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

    /// Create an NRF client using the default plain-HTTP SBI client.
    ///
    /// For TLS or custom timeouts, use [`NrfClient::new`] with a configured
    /// [`crate::client::SbiClientBuilder`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use opc_sbi::nrf::NrfClient;
    ///
    /// let client = NrfClient::with_default_client("http://127.0.0.1:8000".to_string())
    ///     .expect("valid default client");
    /// ```
    pub fn with_default_client(nrf_uri: String) -> Result<Self, String> {
        let client = crate::client::SbiClientBuilder::new()
            .with_http2_only(false)
            .build()?;
        Ok(Self::new(client, nrf_uri))
    }
}

#[async_trait]
impl NrfDeregNotifier for NrfClient {
    async fn deregister(
        &self,
        nf_instance_id: &NfInstanceId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        <Self as NrfOperations>::deregister(self, nf_instance_id)
            .await
            .map_err(|e| {
                Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send + Sync>
            })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NrfHeartbeatResponse {
    pub heartbeat_timer: Option<u32>,
}

fn clamp_heartbeat_interval(interval: Duration) -> Duration {
    interval.clamp(MIN_HEARTBEAT_INTERVAL, MAX_HEARTBEAT_INTERVAL)
}

fn heartbeat_interval_from_timer(secs: Option<u32>) -> Duration {
    secs.map(|secs| clamp_heartbeat_interval(Duration::from_secs(secs as u64)))
        .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL)
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
                return Ok(heartbeat_interval_from_timer(res.heartbeat_timer));
            }
            Ok(DEFAULT_HEARTBEAT_INTERVAL)
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
                return Ok(heartbeat_interval_from_timer(res.heartbeat_timer));
            }
            Ok(DEFAULT_HEARTBEAT_INTERVAL)
        } else if response.status() == http::StatusCode::NOT_FOUND {
            Err(NRF_HEARTBEAT_NOT_FOUND.to_string())
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
    nf_profile: Option<NfProfile>,
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
            nf_profile: None,
            default_interval,
            shutdown_rx,
            degraded_tx,
        }
    }

    /// Assemble a driver that can re-register the NF if the NRF reports the
    /// heartbeat target is no longer known.
    pub fn new_with_profile(
        nrf_client: Arc<dyn NrfOperations>,
        nf_profile: NfProfile,
        default_interval: Duration,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
        degraded_tx: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self {
            nrf_client,
            nf_instance_id: nf_profile.nf_instance_id.clone(),
            nf_profile: Some(nf_profile),
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
        let mut interval = clamp_heartbeat_interval(self.default_interval);
        let mut consecutive_failures = 0;
        let max_failures = 3;

        loop {
            let shutdown = *self.shutdown_rx.borrow();
            if shutdown {
                let _ = self.nrf_client.deregister(&self.nf_instance_id).await;
                break;
            }

            tokio::select! {
                _ = tokio::time::sleep(clamp_heartbeat_interval(interval)) => {
                    self.run_heartbeat_tick(&mut interval, &mut consecutive_failures, max_failures).await;
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

    async fn run_heartbeat_tick(
        &mut self,
        interval: &mut Duration,
        consecutive_failures: &mut u32,
        max_failures: u32,
    ) {
        let mut backoff = Duration::from_secs(1);
        let mut success = false;

        for attempt in 1..=3 {
            match self.nrf_client.heartbeat(&self.nf_instance_id).await {
                Ok(new_interval) => {
                    *interval = clamp_heartbeat_interval(new_interval);
                    *consecutive_failures = 0;
                    let _ = self.degraded_tx.send(false);
                    success = true;
                    record_heartbeat_metric("success");
                    break;
                }
                Err(error) => {
                    record_heartbeat_metric("failure");
                    if is_heartbeat_not_found(&error) && self.try_reregister(interval).await {
                        *consecutive_failures = 0;
                        let _ = self.degraded_tx.send(false);
                        success = true;
                        break;
                    }

                    if attempt < 3 {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                    }
                }
            }
        }

        if !success {
            *consecutive_failures += 1;
            if *consecutive_failures >= max_failures {
                let _ = self.degraded_tx.send(true);
            }
        }
    }

    async fn try_reregister(&self, interval: &mut Duration) -> bool {
        let Some(profile) = self.nf_profile.clone() else {
            return false;
        };
        match self.nrf_client.register(&profile).await {
            Ok(new_interval) => {
                *interval = clamp_heartbeat_interval(new_interval);
                record_heartbeat_metric("reregister_success");
                true
            }
            Err(_) => {
                record_heartbeat_metric("reregister_failure");
                false
            }
        }
    }
}

fn is_heartbeat_not_found(error: &str) -> bool {
    error == NRF_HEARTBEAT_NOT_FOUND || error.to_ascii_lowercase().contains("not found")
}

fn record_heartbeat_metric(outcome: &'static str) {
    lock_or_recover(&opc_redaction::metrics::METRICS.sbi_nrf_heartbeat_total)
        .entry(outcome.to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);
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
            let cache_lock = lock_or_recover(&self.cache);
            cache_lock.lookup(&key)
        };

        match lookup {
            CacheLookup::Hit(profiles) => {
                lock_or_recover(&opc_redaction::metrics::METRICS.sbi_nrf_discovery_total)
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
                            let mut cache_lock = lock_or_recover(&self.cache);
                            cache_lock.insert(key, fresh_profiles.clone());
                            lock_or_recover(
                                &opc_redaction::metrics::METRICS.sbi_nrf_discovery_total,
                            )
                            .entry("refresh_success".to_string())
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                            Ok(fresh_profiles)
                        }
                        _ => {
                            lock_or_recover(
                                &opc_redaction::metrics::METRICS.sbi_nrf_discovery_total,
                            )
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
                            let mut cache_lock = lock_or_recover(&self.cache);
                            cache_lock.insert(key, fresh_profiles.clone());
                            lock_or_recover(
                                &opc_redaction::metrics::METRICS.sbi_nrf_discovery_total,
                            )
                            .entry("refresh_success".to_string())
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                            Ok(fresh_profiles)
                        }
                        _ => {
                            lock_or_recover(
                                &opc_redaction::metrics::METRICS.sbi_nrf_discovery_total,
                            )
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
                    let mut cache_lock = lock_or_recover(&self.cache);
                    cache_lock.insert(key, profiles.clone());
                    lock_or_recover(&opc_redaction::metrics::METRICS.sbi_nrf_discovery_total)
                        .entry("miss_found".to_string())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    lock_or_recover(&opc_redaction::metrics::METRICS.sbi_nrf_cache_entries).insert(
                        safe_metric_label(query.target_nf_type.as_str()),
                        cache_lock.len() as u64,
                    );
                    Ok(profiles)
                }
                Ok(DiscoveryResult::NotFound) => {
                    let mut cache_lock = lock_or_recover(&self.cache);
                    cache_lock.insert_negative(key);
                    lock_or_recover(&opc_redaction::metrics::METRICS.sbi_nrf_discovery_total)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn heartbeat_timer_values_are_clamped() {
        assert_eq!(
            heartbeat_interval_from_timer(Some(0)),
            MIN_HEARTBEAT_INTERVAL
        );
        assert_eq!(
            heartbeat_interval_from_timer(Some(1)),
            MIN_HEARTBEAT_INTERVAL
        );
        assert_eq!(
            heartbeat_interval_from_timer(Some(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            heartbeat_interval_from_timer(Some(7200)),
            MAX_HEARTBEAT_INTERVAL
        );
        assert_eq!(
            heartbeat_interval_from_timer(None),
            DEFAULT_HEARTBEAT_INTERVAL
        );
    }

    #[test]
    fn heartbeat_driver_interval_clamp_rejects_zero_and_huge_values() {
        assert_eq!(
            clamp_heartbeat_interval(Duration::ZERO),
            MIN_HEARTBEAT_INTERVAL
        );
        assert_eq!(
            clamp_heartbeat_interval(Duration::from_secs(u64::MAX)),
            MAX_HEARTBEAT_INTERVAL
        );
    }

    #[derive(Default)]
    struct FakeNrfOperations {
        heartbeat_results: Mutex<Vec<Result<Duration, String>>>,
        register_calls: AtomicUsize,
        heartbeat_calls: AtomicUsize,
        deregister_calls: AtomicUsize,
    }

    impl FakeNrfOperations {
        fn with_heartbeat_results(results: Vec<Result<Duration, String>>) -> Self {
            Self {
                heartbeat_results: Mutex::new(results),
                register_calls: AtomicUsize::new(0),
                heartbeat_calls: AtomicUsize::new(0),
                deregister_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl NrfOperations for FakeNrfOperations {
        async fn register(&self, _profile: &NfProfile) -> Result<Duration, String> {
            self.register_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Duration::from_secs(7))
        }

        async fn deregister(&self, _instance_id: &NfInstanceId) -> Result<(), String> {
            self.deregister_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn heartbeat(&self, _instance_id: &NfInstanceId) -> Result<Duration, String> {
            self.heartbeat_calls.fetch_add(1, Ordering::SeqCst);
            let mut results = lock_or_recover(&self.heartbeat_results);
            if results.is_empty() {
                Ok(Duration::from_secs(5))
            } else {
                results.remove(0)
            }
        }

        async fn discover(&self, _query: &DiscoveryQuery) -> Result<DiscoveryResult, String> {
            Ok(DiscoveryResult::NotFound)
        }
    }

    fn test_profile(id: &str) -> NfProfile {
        NfProfile {
            nf_instance_id: NfInstanceId::new(id).unwrap(),
            nf_type: opc_types::NfType::new("amf").unwrap(),
            nf_status: crate::nrf::NfStatus::Registered,
            ipv4_addresses: vec!["127.0.0.1".to_string()],
            fqdn: None,
            plmn_list: vec![opc_types::PlmnId::new("001", "01").unwrap()],
            s_nssais: vec![opc_types::Snssai::new(1, Some("010203")).unwrap()],
            nf_services: vec![],
            priority: 10,
            capacity: 100,
        }
    }

    #[tokio::test]
    async fn heartbeat_tick_reregisters_after_not_found() {
        let ops = Arc::new(FakeNrfOperations::with_heartbeat_results(vec![Err(
            NRF_HEARTBEAT_NOT_FOUND.to_string(),
        )]));
        let profile = test_profile("amf-01");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (degraded_tx, degraded_rx) = tokio::sync::watch::channel(true);
        let mut driver = HeartbeatDriver::new_with_profile(
            ops.clone(),
            profile,
            Duration::from_secs(30),
            shutdown_rx,
            degraded_tx,
        );
        let mut interval = Duration::from_secs(30);
        let mut consecutive_failures = 2;

        driver
            .run_heartbeat_tick(&mut interval, &mut consecutive_failures, 3)
            .await;

        assert_eq!(ops.heartbeat_calls.load(Ordering::SeqCst), 1);
        assert_eq!(ops.register_calls.load(Ordering::SeqCst), 1);
        assert_eq!(consecutive_failures, 0);
        assert_eq!(interval, Duration::from_secs(7));
        assert!(!*degraded_rx.borrow());
    }

    #[tokio::test]
    async fn heartbeat_driver_deregisters_when_shutdown_already_true() {
        let ops = Arc::new(FakeNrfOperations::default());
        let id = NfInstanceId::new("amf-01").unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(true);
        let (degraded_tx, _degraded_rx) = tokio::sync::watch::channel(false);
        let driver = HeartbeatDriver::new(
            ops.clone(),
            id,
            Duration::from_secs(30),
            shutdown_rx,
            degraded_tx,
        );

        driver.run().await;

        assert_eq!(ops.deregister_calls.load(Ordering::SeqCst), 1);
        assert_eq!(ops.heartbeat_calls.load(Ordering::SeqCst), 0);
    }
}
