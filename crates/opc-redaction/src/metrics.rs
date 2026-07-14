//! Production-safe metrics label sanitization helper and registry.
//!
//! Enforces RFC 008, RFC 010 and security requirements by removing sensitive
//! identifiers (SUPI, GPSI, IMSI, PEI, IP addresses, paths, SQL errors, etc.)
//! from Prometheus metric labels, and provides a thread-safe registry.

use crate::TelcoIdentifier;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LABEL_VALUE_LEN: usize = 64;
const MAX_DYNAMIC_ADMIN_ROUTE_LABELS: usize = 128;
const DYNAMIC_ROUTE_OVERFLOW: &str = "other";

/// Checks if a string is safe to be used as a metric label. If unsafe, returns
/// a sanitized/redacted placeholder. Otherwise, returns the trimmed value.
pub fn metrics_label_safe(val: &str) -> String {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return "default".to_string();
    }

    if trimmed.len() > MAX_LABEL_VALUE_LEN {
        return "redacted".to_string();
    }

    let lower = trimmed.to_lowercase();

    // Check for forbidden patterns
    if trimmed.contains("spiffe://")
        || trimmed.contains("-----BEGIN")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains(':')
        || trimmed.contains('=')
        || trimmed.contains(',')
        || trimmed.contains(' ')
        || trimmed.contains('\t')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('"')
        || trimmed.contains('\'')
    {
        return "redacted".to_string();
    }

    if looks_like_ipv4(trimmed)
        || looks_like_jwt(trimmed)
        || contains_sensitive_id_marker(&lower)
        || TelcoIdentifier::classify(trimmed).is_some()
    {
        return "redacted".to_string();
    }

    // Check for subscriber IDs (purely digits, length >= 5) or matching IMSI/SUPI
    if trimmed.len() >= 5 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return "redacted".to_string();
    }

    // Check for hex strings (tx ID, key, etc.)
    // If it's pure hex and length is 8, 16, 32, 40, 64 etc.
    let is_hex = trimmed.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex
        && (trimmed.len() == 8
            || trimmed.len() == 16
            || trimmed.len() == 32
            || trimmed.len() == 40
            || trimmed.len() == 64)
    {
        return "redacted".to_string();
    }

    // Check for UUID shape
    if trimmed.len() == 36 {
        // e.g. 8-4-4-4-12
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
            && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        {
            return "redacted".to_string();
        }
    }

    // Check for SQL errors or path/cert leaks in general
    if lower.contains("select ")
        || lower.contains("insert ")
        || lower.contains("delete ")
        || lower.contains("update ")
        || lower.contains("table ")
        || lower.contains("sqlite")
        || lower.contains("database")
        || lower.contains("pem")
        || lower.contains("cert")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("key")
    {
        return "redacted".to_string();
    }

    // Only allow alphanumeric, underscores, hyphens, or dots
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return "redacted".to_string();
    }

    trimmed.to_string()
}

fn looks_like_ipv4(val: &str) -> bool {
    let mut parts = val.split('.');
    let Some(a) = parts.next() else {
        return false;
    };
    let Some(b) = parts.next() else {
        return false;
    };
    let Some(c) = parts.next() else {
        return false;
    };
    let Some(d) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    [a, b, c, d].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 3
            && part.chars().all(|c| c.is_ascii_digit())
            && part.parse::<u8>().is_ok()
    })
}

fn looks_like_jwt(val: &str) -> bool {
    let parts: Vec<&str> = val.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn contains_sensitive_id_marker(lower: &str) -> bool {
    const MARKERS: [&str; 6] = ["supi", "gpsi", "imsi", "msisdn", "guti", "pei"];
    MARKERS.iter().any(|marker| {
        lower == *marker
            || lower.starts_with(&format!("{marker}-"))
            || lower.starts_with(&format!("{marker}_"))
            || lower.starts_with(&format!("{marker}."))
            || lower
                .strip_prefix(marker)
                .and_then(|suffix| suffix.chars().next())
                .is_some_and(|c| c.is_ascii_digit())
    })
}

/// Prometheus default histogram latency buckets (in seconds).
pub const LATENCY_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A thread-safe latency histogram metric.
pub struct LatencyHistogram {
    pub sum_us: AtomicU64,
    pub count: AtomicU64,
    pub buckets: [AtomicU64; 11],
}

/// SDK-owned recorder for admin HTTP metric families.
///
/// This wrapper keeps products and runtime code away from the registry field
/// layout while preserving the existing Prometheus family names exported by
/// [`export_prometheus_text`].
pub struct AdminMetricsRecorder<'a> {
    metrics: &'a SdkMetrics,
}

impl AdminMetricsRecorder<'static> {
    /// Create a recorder backed by the global SDK metrics registry.
    #[must_use]
    pub fn global() -> Self {
        Self::new(&METRICS)
    }
}

impl<'a> AdminMetricsRecorder<'a> {
    /// Create a recorder backed by the supplied metrics registry.
    #[must_use]
    pub const fn new(metrics: &'a SdkMetrics) -> Self {
        Self { metrics }
    }

    /// Record one admin HTTP request for `route` and HTTP `status`.
    ///
    /// Known SDK admin paths such as `/readyz` are normalized to the stable
    /// route labels already used by the exporter. Unknown route names are
    /// sanitized through [`metrics_label_safe`] before they are stored.
    pub fn record_request(&self, route: &str, status: u16) {
        let route = admin_route_label_safe(route);
        let status = admin_status_label_safe(status);
        let mut reqs = lock_or_recover(&self.metrics.admin_requests_total);
        let route = bounded_request_route_label(route, &reqs);
        let count = reqs.entry((route, status)).or_insert(0);
        *count += 1;
    }

    /// Record one malformed admin request.
    pub fn record_malformed_request(&self) {
        self.metrics
            .admin_malformed_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one admin authentication failure.
    pub fn record_auth_failure(&self) {
        self.metrics
            .admin_auth_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one admin response redaction event.
    pub fn record_redaction_event(&self) {
        self.metrics
            .admin_redaction_events_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one admin route latency observation in seconds.
    ///
    /// Negative and non-finite values are ignored. Known SDK admin routes use
    /// the existing fixed histograms; other sanitized route labels are stored
    /// in a dynamic route histogram map exported under the same metric family.
    pub fn observe_route_latency(&self, route: &str, latency_seconds: f64) {
        if !latency_seconds.is_finite() || latency_seconds < 0.0 {
            return;
        }

        let route = admin_route_label_safe(route);
        match route.as_str() {
            "livez" => self.metrics.admin_latency_livez.observe(latency_seconds),
            "readyz" => self.metrics.admin_latency_readyz.observe(latency_seconds),
            "startupz" => self.metrics.admin_latency_startupz.observe(latency_seconds),
            "metrics" => self.metrics.admin_latency_metrics.observe(latency_seconds),
            "debug_runtime" => self
                .metrics
                .admin_latency_debug_runtime
                .observe(latency_seconds),
            "debug_tasks" => self
                .metrics
                .admin_latency_debug_tasks
                .observe(latency_seconds),
            "debug_config_version" => self
                .metrics
                .admin_latency_debug_config_version
                .observe(latency_seconds),
            _ => {
                let mut latencies = lock_or_recover(&self.metrics.admin_request_latency_seconds);
                let route = bounded_latency_route_label(route, &latencies);
                latencies.entry(route).or_default().observe(latency_seconds);
            }
        }
    }
}

impl Default for AdminMetricsRecorder<'static> {
    fn default() -> Self {
        Self::global()
    }
}

impl fmt::Debug for AdminMetricsRecorder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminMetricsRecorder")
            .finish_non_exhaustive()
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Normalize and sanitize an admin route label for metrics.
#[must_use]
pub fn admin_route_label_safe(route: &str) -> String {
    let route = route.trim();
    let normalized = match route {
        "" => "unknown",
        "/livez" | "livez" => "livez",
        "/readyz" | "readyz" => "readyz",
        "/startupz" | "startupz" => "startupz",
        "/metrics" | "metrics" => "metrics",
        "/debug/runtime" | "debug_runtime" => "debug_runtime",
        "/debug/tasks" | "debug_tasks" => "debug_tasks",
        "/debug/config-version" | "debug_config_version" => "debug_config_version",
        "/debug/drain" | "debug_drain" => "debug_drain",
        "unknown" => "unknown",
        other => return metrics_label_safe(other),
    };
    metrics_label_safe(normalized)
}

fn is_known_admin_route_label(route: &str) -> bool {
    matches!(
        route,
        "unknown"
            | "livez"
            | "readyz"
            | "startupz"
            | "metrics"
            | "debug_runtime"
            | "debug_tasks"
            | "debug_config_version"
            | "debug_drain"
    )
}

fn bounded_request_route_label(route: String, requests: &HashMap<(String, String), u64>) -> String {
    if is_known_admin_route_label(&route)
        || route == DYNAMIC_ROUTE_OVERFLOW
        || requests.keys().any(|(existing, _)| existing == &route)
    {
        return route;
    }

    let distinct_dynamic_routes: HashSet<&str> = requests
        .keys()
        .map(|(existing, _)| existing.as_str())
        .filter(|existing| {
            !is_known_admin_route_label(existing) && *existing != DYNAMIC_ROUTE_OVERFLOW
        })
        .collect();

    if distinct_dynamic_routes.len() >= MAX_DYNAMIC_ADMIN_ROUTE_LABELS {
        DYNAMIC_ROUTE_OVERFLOW.to_string()
    } else {
        route
    }
}

fn bounded_latency_route_label(
    route: String,
    latencies: &HashMap<String, LatencyHistogram>,
) -> String {
    if is_known_admin_route_label(&route)
        || route == DYNAMIC_ROUTE_OVERFLOW
        || latencies.contains_key(&route)
    {
        return route;
    }

    let distinct_dynamic_routes = latencies
        .keys()
        .filter(|existing| {
            !is_known_admin_route_label(existing) && existing.as_str() != DYNAMIC_ROUTE_OVERFLOW
        })
        .count();

    if distinct_dynamic_routes >= MAX_DYNAMIC_ADMIN_ROUTE_LABELS {
        DYNAMIC_ROUTE_OVERFLOW.to_string()
    } else {
        route
    }
}

/// Normalize and sanitize an admin HTTP status label for metrics.
#[must_use]
pub fn admin_status_label_safe(status: u16) -> String {
    if (100..=599).contains(&status) {
        metrics_label_safe(&status.to_string())
    } else {
        "invalid".to_string()
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    /// Create a new, empty latency histogram.
    pub const fn new() -> Self {
        Self {
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Record an observed latency in seconds.
    pub fn observe(&self, val_seconds: f64) {
        let us = (val_seconds * 1_000_000.0) as u64;
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        for (i, &bucket) in LATENCY_BUCKETS.iter().enumerate() {
            if val_seconds <= bucket {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Reset all values to zero.
    pub fn reset(&self) {
        self.sum_us.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        for b in &self.buckets {
            b.store(0, Ordering::Relaxed);
        }
    }
}

const SECURITY_ROTATION_KIND_COUNT: usize = 3;
const SECURITY_ROTATION_OUTCOME_COUNT: usize = 4;
const SECURITY_ROTATION_SERIES_COUNT: usize =
    SECURITY_ROTATION_KIND_COUNT * SECURITY_ROTATION_OUTCOME_COUNT;

/// Closed security-material class used by `opc_security_rotation_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityRotationKind {
    /// A coherent TLS material snapshot whose changed component is not known.
    TlsMaterial,
    /// An SVID chain or its matching private key.
    Svid,
    /// A projected trust bundle.
    TrustBundle,
}

impl SecurityRotationKind {
    const ALL: [Self; SECURITY_ROTATION_KIND_COUNT] =
        [Self::TlsMaterial, Self::Svid, Self::TrustBundle];

    /// Stable fixed-cardinality Prometheus label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TlsMaterial => "tls_material",
            Self::Svid => "svid",
            Self::TrustBundle => "trust_bundle",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::TlsMaterial => 0,
            Self::Svid => 1,
            Self::TrustBundle => 2,
        }
    }
}

/// Closed result used by `opc_security_rotation_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityRotationOutcome {
    /// A coherent material epoch was accepted.
    Success,
    /// A candidate was rejected while the prior unexpired epoch stayed active.
    RetainedLastGood,
    /// A candidate was rejected with no usable prior epoch.
    Rejected,
    /// An observed coherent source publication crossed its SVID-chain expiry.
    Expired,
}

impl SecurityRotationOutcome {
    const ALL: [Self; SECURITY_ROTATION_OUTCOME_COUNT] = [
        Self::Success,
        Self::RetainedLastGood,
        Self::Rejected,
        Self::Expired,
    ];

    /// Stable fixed-cardinality Prometheus label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::RetainedLastGood => "retained_last_good",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::RetainedLastGood => 1,
            Self::Rejected => 2,
            Self::Expired => 3,
        }
    }
}

#[derive(Debug)]
struct SecurityMetricsState {
    svid_expires_seconds: AtomicI64,
    bundle_version: AtomicU64,
    rotation: [AtomicU64; SECURITY_ROTATION_SERIES_COUNT],
    rotation_saturated: [AtomicBool; SECURITY_ROTATION_SERIES_COUNT],
    active_publication: Mutex<Option<Arc<Mutex<SecurityPublicationLifecycle>>>>,
}

impl Default for SecurityMetricsState {
    fn default() -> Self {
        Self {
            svid_expires_seconds: AtomicI64::new(0),
            bundle_version: AtomicU64::new(0),
            rotation: std::array::from_fn(|_| AtomicU64::new(0)),
            rotation_saturated: std::array::from_fn(|_| AtomicBool::new(false)),
            active_publication: Mutex::new(None),
        }
    }
}

/// Read-only access to fixed-cardinality security rotation metrics.
///
/// A reader cannot mutate or reset either an isolated registry or the
/// process-wide registry. In particular, the following does not compile:
///
/// ```compile_fail
/// use opc_redaction::metrics::SecurityMetricsReader;
///
/// let reader = SecurityMetricsReader::global();
/// reader.record_success(1, 1_900_000_000);
/// ```
#[derive(Clone, Debug)]
pub struct SecurityMetricsReader {
    state: Arc<SecurityMetricsState>,
}

/// Single-use authority for one security telemetry source/controller pair.
///
/// The authority is deliberately non-`Clone`. An isolated authority is useful
/// for deterministic tests and embedders. The process authority is claimed by
/// the production projected-SVID constructor and cannot be claimed twice.
/// These composition APIs are public because Rust has no cross-crate friend
/// visibility. Code running in the same trusted process can claim them first;
/// cryptographic/material validation and the TLS controller still own identity
/// and peer authorization. The ticket/permit is an internal publication-
/// integrity gate, but exported metric values are never read to authorize TLS,
/// readiness, or access.
///
/// ```compile_fail
/// use opc_redaction::metrics::SecurityMetricsAuthority;
///
/// let (authority, _reader) = SecurityMetricsAuthority::isolated();
/// let duplicate = authority.clone();
/// # let _ = duplicate;
/// ```
pub struct SecurityMetricsAuthority {
    state: Arc<SecurityMetricsState>,
}

impl fmt::Debug for SecurityMetricsAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityMetricsAuthority([opaque])")
    }
}

/// Failure to claim the sole process-wide security telemetry authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecurityMetricsAuthorityClaimError {
    /// Another projected source already owns the process authority.
    #[error("process security metrics authority is already claimed")]
    AlreadyClaimed,
}

/// Result of preparing one controller publication transition.
#[doc(hidden)]
#[derive(Debug)]
#[must_use]
pub enum SecurityMetricsAcceptance<'a> {
    /// The unexpired publication may be installed while this permit is held.
    Ready(SecurityMetricsAcceptancePermit<'a>),
    /// This publication was already accepted by this controller authority.
    AlreadyAccepted,
    /// The publication was expired at the serialized acceptance boundary.
    Expired,
    /// The publication belongs to another metrics registry.
    RegistryMismatch,
}

/// Non-cloneable transaction joining one TLS controller state update to its
/// publication lifecycle and metrics transition.
///
/// The permit contains no callback. The controller updates its already-locked
/// material state synchronously, then consumes the permit with [`Self::commit`].
/// Dropping it abandons the metrics transition and releases both registry locks.
/// The required lock order is controller state, publication lifecycle, then
/// active registry. Trusted composition code must not call another source or
/// controller metrics transition while a permit is live; deliberate reentry is
/// unsupported misuse of this doc-hidden cross-crate primitive.
#[doc(hidden)]
#[must_use]
pub struct SecurityMetricsAcceptancePermit<'a> {
    state: &'a SecurityMetricsState,
    publication_lifecycle: Arc<Mutex<SecurityPublicationLifecycle>>,
    active_publication: MutexGuard<'a, Option<Arc<Mutex<SecurityPublicationLifecycle>>>>,
    lifecycle: MutexGuard<'a, SecurityPublicationLifecycle>,
    bundle_version: u64,
    svid_expires_seconds: i64,
}

impl fmt::Debug for SecurityMetricsAcceptancePermit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityMetricsAcceptancePermit([opaque])")
    }
}

impl SecurityMetricsAcceptancePermit<'_> {
    /// Commit the already-installed controller state to the active registry.
    ///
    /// After validation and permit preparation this transition is infallible
    /// and performs only atomic stores/counter updates.
    pub fn commit(mut self) {
        self.lifecycle.controller_epoch = Some(self.bundle_version);
        *self.active_publication = Some(self.publication_lifecycle.clone());
        record_success(self.state, self.bundle_version, self.svid_expires_seconds);
    }
}

/// Source-side half of a security telemetry authority.
///
/// This type is public only so `opc-identity` can own the source half across a
/// crate boundary. Products should construct a projected source instead of
/// recording outcomes directly.
#[doc(hidden)]
#[derive(Clone)]
pub struct SecurityMetricsSource {
    state: Arc<SecurityMetricsState>,
}

impl fmt::Debug for SecurityMetricsSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityMetricsSource([opaque])")
    }
}

/// Controller-side half of a security telemetry authority.
///
/// The controller half is deliberately non-`Clone`; `opc-identity` moves it
/// into exactly one paired `opc-tls` controller.
#[doc(hidden)]
pub struct SecurityMetricsController {
    state: Arc<SecurityMetricsState>,
}

impl fmt::Debug for SecurityMetricsController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityMetricsController([opaque])")
    }
}

#[derive(Debug, Default)]
struct SecurityPublicationLifecycle {
    expired: bool,
    controller_epoch: Option<u64>,
}

/// Per-publication exact-once expiry coordination.
///
/// A ticket carries no mutation authority. It must be paired with the source
/// or controller half that created it, and both halves verify that registry
/// binding before changing metrics.
#[doc(hidden)]
#[derive(Clone)]
pub struct SecurityMetricsPublication {
    state: Arc<SecurityMetricsState>,
    lifecycle: Arc<Mutex<SecurityPublicationLifecycle>>,
}

impl fmt::Debug for SecurityMetricsPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecurityMetricsPublication([opaque])")
    }
}

/// Numeric snapshot of the fixed security rotation metric families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityMetricsSnapshot {
    svid_expires_seconds: i64,
    bundle_version: u64,
    rotation: [u64; SECURITY_ROTATION_SERIES_COUNT],
    rotation_saturated: [bool; SECURITY_ROTATION_SERIES_COUNT],
}

impl SecurityMetricsSnapshot {
    /// Effective configured/presented SVID-chain expiry as Unix seconds.
    ///
    /// Zero means no coherent, unexpired TLS material is currently available.
    pub const fn svid_expires_seconds(self) -> i64 {
        self.svid_expires_seconds
    }

    /// Last accepted opaque process-local coherent TLS-material epoch.
    ///
    /// The value remains available for correlation after the active ticket
    /// expires; `svid_expires_seconds == 0` carries unavailability.
    pub const fn bundle_version(self) -> u64 {
        self.bundle_version
    }

    /// Counter value for one closed kind/outcome pair.
    pub const fn rotation(
        self,
        kind: SecurityRotationKind,
        outcome: SecurityRotationOutcome,
    ) -> u64 {
        self.rotation[rotation_index(kind, outcome)]
    }

    /// Whether one fixed counter reached its `u64` representation ceiling.
    pub const fn rotation_saturated(
        self,
        kind: SecurityRotationKind,
        outcome: SecurityRotationOutcome,
    ) -> bool {
        self.rotation_saturated[rotation_index(kind, outcome)]
    }

    /// Number of fixed counter series at the representation ceiling.
    pub fn saturated_series(self) -> usize {
        self.rotation_saturated
            .into_iter()
            .filter(|saturated| *saturated)
            .count()
    }
}

impl SecurityMetricsReader {
    /// Return a read-only view of the process-wide security metrics registry.
    #[must_use]
    pub fn global() -> Self {
        Self {
            state: SECURITY_METRICS.clone(),
        }
    }

    /// Return whether two readers observe the same metrics registry.
    #[must_use]
    pub fn shares_registry(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    /// Read a consistent-enough numeric telemetry snapshot.
    ///
    /// Metrics atomics are intentionally relaxed: individual samples are
    /// independent observations and do not authorize TLS or rotation state.
    #[must_use]
    pub fn snapshot(&self) -> SecurityMetricsSnapshot {
        snapshot_security_metrics(&self.state)
    }
}

impl SecurityMetricsAuthority {
    /// Create a single-use isolated authority and its read-only view.
    #[must_use]
    pub fn isolated() -> (Self, SecurityMetricsReader) {
        let state = Arc::new(SecurityMetricsState::default());
        (
            Self {
                state: state.clone(),
            },
            SecurityMetricsReader { state },
        )
    }

    /// Claim the sole process-wide security telemetry authority.
    ///
    /// This is an SDK composition primitive used by `opc-identity`. A second
    /// claim fails closed and the claim is not reset during the process
    /// lifetime, so stale controllers cannot overlap a replacement authority.
    /// Rust cannot restrict this public function to a friend crate: all
    /// same-process callers are part of the trusted composition boundary.
    #[doc(hidden)]
    pub fn claim_process() -> Result<Self, SecurityMetricsAuthorityClaimError> {
        claim_security_metrics_authority(
            &SECURITY_METRICS_AUTHORITY_CLAIMED,
            SECURITY_METRICS.clone(),
        )
    }

    /// Consume this authority into its source and controller halves.
    #[doc(hidden)]
    pub fn split(self) -> (SecurityMetricsSource, SecurityMetricsController) {
        (
            SecurityMetricsSource {
                state: self.state.clone(),
            },
            SecurityMetricsController { state: self.state },
        )
    }
}

impl SecurityMetricsSource {
    /// Allocate exact-once lifecycle state for one successful publication.
    #[must_use]
    pub fn new_publication(&self) -> SecurityMetricsPublication {
        SecurityMetricsPublication {
            state: self.state.clone(),
            lifecycle: Arc::new(Mutex::new(SecurityPublicationLifecycle::default())),
        }
    }

    /// Record a rejected candidate while retaining the prior source epoch.
    pub fn record_retained_last_good(&self, kind: SecurityRotationKind) {
        record_rotation_count(
            &self.state,
            kind,
            SecurityRotationOutcome::RetainedLastGood,
            1,
        );
    }

    /// Record source-observed rejections without changing controller gauges.
    pub fn record_rejected_count(&self, kind: SecurityRotationKind, count: u64) {
        record_rotation_count(&self.state, kind, SecurityRotationOutcome::Rejected, count);
    }

    /// Record this publication's expiry for the first source/controller observer.
    ///
    /// Each observed registry-bound ticket can increment at most once. Only
    /// expiry of the currently accepted ticket may zero the expiry gauge;
    /// unaccepted and superseded observations preserve it, and supersession
    /// alone emits no expiry outcome.
    pub fn record_expired_once(&self, publication: &SecurityMetricsPublication) -> bool {
        record_publication_expired_once(&self.state, publication)
    }
}

impl SecurityMetricsController {
    /// Prepare an atomic unexpired-publication transition.
    ///
    /// A ready permit holds the publication and active-registry locks while the
    /// TLS controller synchronously installs its already validated state. The
    /// controller then commits the permit; no arbitrary callback runs under
    /// these locks. Dropping a permit abandons the transition.
    /// Effective expiry is compared with the current Unix second while both
    /// the ticket lifecycle and active-publication registry are locked.
    pub fn prepare_success_if_active<'a>(
        &'a self,
        publication: &'a SecurityMetricsPublication,
        bundle_version: u64,
        svid_expires_seconds: i64,
    ) -> SecurityMetricsAcceptance<'a> {
        self.prepare_success_if_active_with_clock(
            publication,
            bundle_version,
            svid_expires_seconds,
            current_unix_seconds,
        )
    }

    fn prepare_success_if_active_with_clock<'a>(
        &'a self,
        publication: &'a SecurityMetricsPublication,
        bundle_version: u64,
        svid_expires_seconds: i64,
        current_time: impl FnOnce() -> i64,
    ) -> SecurityMetricsAcceptance<'a> {
        if !Arc::ptr_eq(&self.state, &publication.state) {
            return SecurityMetricsAcceptance::RegistryMismatch;
        }
        let mut lifecycle = lock_or_recover(&publication.lifecycle);
        let mut active_publication = lock_or_recover(&self.state.active_publication);
        if lifecycle.expired {
            return SecurityMetricsAcceptance::Expired;
        }
        if lifecycle.controller_epoch.is_some() {
            return SecurityMetricsAcceptance::AlreadyAccepted;
        }
        if svid_expires_seconds <= current_time() {
            expire_publication_locked(
                &self.state,
                publication,
                &mut lifecycle,
                &mut active_publication,
            );
            return SecurityMetricsAcceptance::Expired;
        }
        SecurityMetricsAcceptance::Ready(SecurityMetricsAcceptancePermit {
            state: &self.state,
            publication_lifecycle: publication.lifecycle.clone(),
            lifecycle,
            active_publication,
            bundle_version,
            svid_expires_seconds,
        })
    }

    /// Record a rejected controller candidate while retaining the prior epoch.
    pub fn record_retained_last_good(&self, kind: SecurityRotationKind) {
        record_rotation_count(
            &self.state,
            kind,
            SecurityRotationOutcome::RetainedLastGood,
            1,
        );
    }

    /// Record an unavailable or rejected candidate with no usable prior epoch.
    pub fn record_rejected(&self, kind: SecurityRotationKind, bundle_version: u64) {
        let mut active_publication = lock_or_recover(&self.state.active_publication);
        *active_publication = None;
        self.state.svid_expires_seconds.store(0, Ordering::Relaxed);
        self.state
            .bundle_version
            .store(bundle_version, Ordering::Relaxed);
        record_rotation_count(&self.state, kind, SecurityRotationOutcome::Rejected, 1);
        drop(active_publication);
    }

    /// Record this publication's expiry for the first controller/source observer.
    pub fn record_expired_once(&self, publication: &SecurityMetricsPublication) -> bool {
        record_publication_expired_once(&self.state, publication)
    }
}

fn claim_security_metrics_authority(
    claimed: &AtomicBool,
    state: Arc<SecurityMetricsState>,
) -> Result<SecurityMetricsAuthority, SecurityMetricsAuthorityClaimError> {
    claimed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| SecurityMetricsAuthorityClaimError::AlreadyClaimed)?;
    Ok(SecurityMetricsAuthority { state })
}

fn snapshot_security_metrics(state: &SecurityMetricsState) -> SecurityMetricsSnapshot {
    SecurityMetricsSnapshot {
        svid_expires_seconds: state.svid_expires_seconds.load(Ordering::Relaxed),
        bundle_version: state.bundle_version.load(Ordering::Relaxed),
        rotation: std::array::from_fn(|index| state.rotation[index].load(Ordering::Relaxed)),
        rotation_saturated: std::array::from_fn(|index| {
            state.rotation_saturated[index].load(Ordering::Relaxed)
        }),
    }
}

fn record_success(state: &SecurityMetricsState, bundle_version: u64, svid_expires_seconds: i64) {
    state
        .svid_expires_seconds
        .store(svid_expires_seconds.max(0), Ordering::Relaxed);
    state
        .bundle_version
        .store(bundle_version, Ordering::Relaxed);
    record_rotation_count(
        state,
        SecurityRotationKind::TlsMaterial,
        SecurityRotationOutcome::Success,
        1,
    );
}

fn record_publication_expired_once(
    state: &Arc<SecurityMetricsState>,
    publication: &SecurityMetricsPublication,
) -> bool {
    if !Arc::ptr_eq(state, &publication.state) {
        return false;
    }
    let mut lifecycle = lock_or_recover(&publication.lifecycle);
    let mut active_publication = lock_or_recover(&state.active_publication);
    if lifecycle.expired {
        return false;
    }
    expire_publication_locked(state, publication, &mut lifecycle, &mut active_publication);
    true
}

fn expire_publication_locked(
    state: &SecurityMetricsState,
    publication: &SecurityMetricsPublication,
    lifecycle: &mut SecurityPublicationLifecycle,
    active_publication: &mut Option<Arc<Mutex<SecurityPublicationLifecycle>>>,
) {
    lifecycle.expired = true;
    let publication_is_active = active_publication
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(active, &publication.lifecycle));
    if publication_is_active {
        *active_publication = None;
        state.svid_expires_seconds.store(0, Ordering::Relaxed);
        state
            .bundle_version
            .store(lifecycle.controller_epoch.unwrap_or(0), Ordering::Relaxed);
    }
    record_rotation_count(
        state,
        SecurityRotationKind::Svid,
        SecurityRotationOutcome::Expired,
        1,
    );
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

fn record_rotation_count(
    state: &SecurityMetricsState,
    kind: SecurityRotationKind,
    outcome: SecurityRotationOutcome,
    count: u64,
) {
    let index = rotation_index(kind, outcome);
    add_saturating(
        &state.rotation[index],
        &state.rotation_saturated[index],
        count,
    );
}

const fn rotation_index(kind: SecurityRotationKind, outcome: SecurityRotationOutcome) -> usize {
    kind.index() * SECURITY_ROTATION_OUTCOME_COUNT + outcome.index()
}

fn add_saturating(counter: &AtomicU64, saturated: &AtomicBool, count: u64) {
    if count == 0 {
        return;
    }
    let previous = counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(count))
        })
        .unwrap_or_else(|value| value);
    if previous >= u64::MAX.saturating_sub(count) {
        saturated.store(true, Ordering::Relaxed);
    }
}

/// The global SDK metrics registry holding all atomic counters and gauges.
pub struct SdkMetrics {
    // === Config Bus ===
    pub config_bus_pending_commits: AtomicI64,
    pub break_glass_sessions_active: AtomicI64,
    pub config_bus_commit_confirmed_deadline_expiry: AtomicU64,
    pub config_bus_phase_latency_apply: LatencyHistogram,
    pub config_bus_phase_latency_validate: LatencyHistogram,
    pub config_bus_phase_latency_persist: LatencyHistogram,
    pub config_bus_phase_latency_notify: LatencyHistogram,
    pub config_bus_rollback_success: AtomicU64,
    pub config_bus_rollback_failure: AtomicU64,
    pub config_bus_recovery_fence_active: AtomicI64,
    pub config_bus_subscriber_notification_failures: AtomicU64,

    // === Persistence / HA ===
    pub persist_leader_term: AtomicU64,
    pub persist_commit_index: AtomicU64,
    pub persist_applied_index: AtomicU64,
    pub persist_snapshot_index: AtomicU64,
    pub persist_leader_changes: AtomicU64,
    pub persist_quorum_read_success: AtomicU64,
    pub persist_quorum_read_failure: AtomicU64,
    pub persist_quorum_write_success: AtomicU64,
    pub persist_quorum_write_failure: AtomicU64,
    pub persist_stale_leader_rejections: AtomicU64,
    pub persist_peer_replication_lag: Mutex<HashMap<usize, u64>>,
    pub persist_snapshot_install_failures: AtomicU64,
    pub persist_snapshot_verify_failures: AtomicU64,
    pub persist_rpc_auth_failures: AtomicU64,
    pub persist_audit_chain_verification_success: AtomicU64,
    pub persist_audit_chain_verification_failure: AtomicU64,
    pub persist_audit_write_failure: AtomicU64,
    pub persist_write_success: AtomicU64,
    pub persist_read_success: AtomicU64,
    pub persist_error: AtomicU64,

    // === Session Store ===
    pub session_quorum_read_success: AtomicU64,
    pub session_quorum_read_failure: AtomicU64,
    pub session_quorum_write_success: AtomicU64,
    pub session_quorum_write_failure: AtomicU64,
    pub session_committed_replication_sequence: AtomicU64,
    pub session_replica_repair: AtomicU64,
    pub session_replica_catchup: AtomicU64,
    pub session_failed_partial_write_rollback: AtomicU64,
    pub session_watch_resume_success: AtomicU64,
    pub session_watch_resume_failure: AtomicU64,
    pub session_lease_acquire: AtomicU64,
    pub session_lease_renew: AtomicU64,
    pub session_lease_release: AtomicU64,
    pub session_lease_delete: AtomicU64,
    pub session_durable_readiness_probe_success: AtomicU64,
    pub session_durable_readiness_probe_failure: AtomicU64,
    pub session_durable_readiness_ready: AtomicI64,
    pub session_durable_readiness_configured_voters: AtomicU64,
    pub session_durable_readiness_fresh_reachable_voters: AtomicU64,
    pub session_durable_readiness_agreeing_voters: AtomicU64,
    pub session_durable_readiness_required_quorum: AtomicU64,
    pub session_durable_readiness_majority_visible_prefix: AtomicU64,
    pub session_durable_readiness_timeout_failures: AtomicU64,
    pub session_durable_readiness_authentication_failures: AtomicU64,
    pub session_durable_readiness_transport_failures: AtomicU64,
    pub session_durable_readiness_divergent_failures: AtomicU64,
    pub session_durable_readiness_recovery_required_failures: AtomicU64,
    pub session_operator_recovery_attempts: AtomicU64,
    pub session_operator_recovery_failures: AtomicU64,
    pub session_operator_recovery_required: AtomicI64,
    pub session_operator_recovery_audit_pending: AtomicI64,
    pub session_operator_recovery_epoch: AtomicU64,
    pub session_operator_recovery_rejoins: AtomicU64,
    pub session_net_backend_queue_timeouts: AtomicU64,
    pub session_net_backend_execution_timeouts: AtomicU64,
    pub session_net_backend_cancellations: AtomicU64,
    pub session_net_backend_peer_disconnects: AtomicU64,
    pub session_net_backend_ambiguous_outcomes: AtomicU64,
    pub session_net_lifecycle_retirement_maximum_age: AtomicU64,
    pub session_net_lifecycle_retirement_local_leaf_expiry: AtomicU64,
    pub session_net_lifecycle_retirement_peer_leaf_expiry: AtomicU64,
    pub session_net_lifecycle_retirement_local_certificate_chain_expiry: AtomicU64,
    pub session_net_lifecycle_retirement_peer_certificate_chain_expiry: AtomicU64,
    pub session_net_lifecycle_retirement_material_epoch: AtomicU64,
    pub session_net_lifecycle_retirement_explicit: AtomicU64,
    pub session_net_lifecycle_retirement_idle_timeout: AtomicU64,
    pub session_net_lifecycle_active_connections: AtomicI64,
    pub session_net_lifecycle_draining_connections: AtomicI64,
    pub session_net_lifecycle_drain_started: AtomicU64,
    pub session_net_lifecycle_drain_completed: AtomicU64,
    pub session_net_lifecycle_drain_overruns: AtomicU64,
    pub session_net_connection_attempts: AtomicU64,
    pub session_net_connection_successes: AtomicU64,
    pub session_net_connection_failure_transport: AtomicU64,
    pub session_net_connection_failure_authentication: AtomicU64,
    pub session_net_connection_failure_timeout: AtomicU64,
    pub session_net_connection_failure_protocol: AtomicU64,
    pub session_net_connection_failure_backend: AtomicU64,
    pub session_net_reconnect_attempts: AtomicU64,
    pub session_net_reconnect_failures: AtomicU64,
    pub session_net_watch_slow_consumers: AtomicU64,

    // === NACM / Authz ===
    pub nacm_eval_allow: AtomicU64,
    pub nacm_eval_deny: AtomicU64,
    pub nacm_eval_error: AtomicU64,
    pub nacm_eval_latency: LatencyHistogram,
    pub nacm_default_deny: AtomicU64,

    // === Alarm / Runtime ===
    pub alarm_active_count: Mutex<HashMap<(String, String), i64>>,
    pub alarm_audit_success: AtomicU64,
    pub alarm_audit_failure: AtomicU64,
    pub runtime_health_live: AtomicI64,
    pub runtime_health_ready: AtomicI64,
    pub runtime_health_startup: AtomicI64,
    pub runtime_budget_exhausted: AtomicU64,

    // === Admin Server ===
    pub admin_requests_total: Mutex<HashMap<(String, String), u64>>,
    pub admin_auth_failures_total: AtomicU64,
    pub admin_malformed_requests_total: AtomicU64,
    pub admin_redaction_events_total: AtomicU64,
    pub admin_latency_livez: LatencyHistogram,
    pub admin_latency_readyz: LatencyHistogram,
    pub admin_latency_startupz: LatencyHistogram,
    pub admin_latency_metrics: LatencyHistogram,
    pub admin_latency_debug_runtime: LatencyHistogram,
    pub admin_latency_debug_tasks: LatencyHistogram,
    pub admin_latency_debug_config_version: LatencyHistogram,
    pub admin_request_latency_seconds: Mutex<HashMap<String, LatencyHistogram>>,

    // === SBI Metrics ===
    pub sbi_requests_total: Mutex<HashMap<(String, String, String, String), u64>>,
    pub sbi_request_duration_seconds: Mutex<HashMap<(String, String), LatencyHistogram>>,
    pub sbi_problem_details_total: Mutex<HashMap<(String, String, String), u64>>,
    pub sbi_oauth_validation_total: Mutex<HashMap<(String, String), u64>>,
    pub sbi_nrf_discovery_total: Mutex<HashMap<String, u64>>,
    pub sbi_nrf_cache_entries: Mutex<HashMap<String, u64>>,
    pub sbi_nrf_heartbeat_total: Mutex<HashMap<String, u64>>,
    pub sbi_circuit_state: Mutex<HashMap<(String, String, String), u64>>,
    pub sbi_overload_rejections_total: Mutex<HashMap<(String, String), u64>>,
    pub sbi_callback_delivery_total: Mutex<HashMap<(String, String), u64>>,

    // === gNMI Server (opc-gnmi-server) ===
    // These families are written by the gNMI server once it exists; until then
    // they export as empty metric families (no rows), which is honest. Label
    // values are sanitized via metrics_label_safe at export time.
    pub gnmi_rpc_requests_total: Mutex<HashMap<(String, String), u64>>,
    pub gnmi_rpc_errors_total: Mutex<HashMap<(String, String), u64>>,
    pub gnmi_rpc_seconds: Mutex<HashMap<String, LatencyHistogram>>,
    pub gnmi_set_commit_seconds: Mutex<HashMap<String, LatencyHistogram>>,
    pub gnmi_active_streams: Mutex<HashMap<String, i64>>,
    pub gnmi_sessions_active: Mutex<HashMap<String, i64>>,
    pub gnmi_listener_events_total: Mutex<HashMap<(String, String), u64>>,
    pub gnmi_subscription_events_total: Mutex<HashMap<(String, String), u64>>,
    pub gnmi_subscription_lag_total: Mutex<HashMap<String, u64>>,
    pub gnmi_nacm_denials_total: Mutex<HashMap<String, u64>>,
    pub gnmi_extensions_total: Mutex<HashMap<(String, String), u64>>,
    pub gnmi_arbitration_denials_total: Mutex<HashMap<String, u64>>,

    // === NETCONF Server (opc-netconf-server) ===
    pub netconf_sessions_active: Mutex<HashMap<String, i64>>,
    pub netconf_rpc_requests_total: Mutex<HashMap<(String, String), u64>>,
    pub netconf_rpc_errors_total: Mutex<HashMap<(String, String), u64>>,
    pub netconf_rpc_seconds: Mutex<HashMap<String, LatencyHistogram>>,
    pub netconf_commit_seconds: Mutex<HashMap<String, LatencyHistogram>>,
    pub netconf_locks_active: Mutex<HashMap<String, i64>>,
    pub netconf_notifications_total: Mutex<HashMap<(String, String), u64>>,
    pub netconf_nacm_denials_total: Mutex<HashMap<String, u64>>,
}

impl SdkMetrics {
    /// Create a new, initialized SdkMetrics registry.
    pub fn new() -> Self {
        Self {
            config_bus_pending_commits: AtomicI64::new(0),
            break_glass_sessions_active: AtomicI64::new(0),
            config_bus_commit_confirmed_deadline_expiry: AtomicU64::new(0),
            config_bus_phase_latency_apply: LatencyHistogram::new(),
            config_bus_phase_latency_validate: LatencyHistogram::new(),
            config_bus_phase_latency_persist: LatencyHistogram::new(),
            config_bus_phase_latency_notify: LatencyHistogram::new(),
            config_bus_rollback_success: AtomicU64::new(0),
            config_bus_rollback_failure: AtomicU64::new(0),
            config_bus_recovery_fence_active: AtomicI64::new(0),
            config_bus_subscriber_notification_failures: AtomicU64::new(0),

            persist_leader_term: AtomicU64::new(0),
            persist_commit_index: AtomicU64::new(0),
            persist_applied_index: AtomicU64::new(0),
            persist_snapshot_index: AtomicU64::new(0),
            persist_leader_changes: AtomicU64::new(0),
            persist_quorum_read_success: AtomicU64::new(0),
            persist_quorum_read_failure: AtomicU64::new(0),
            persist_quorum_write_success: AtomicU64::new(0),
            persist_quorum_write_failure: AtomicU64::new(0),
            persist_stale_leader_rejections: AtomicU64::new(0),
            persist_peer_replication_lag: Mutex::new(HashMap::new()),
            persist_snapshot_install_failures: AtomicU64::new(0),
            persist_snapshot_verify_failures: AtomicU64::new(0),
            persist_rpc_auth_failures: AtomicU64::new(0),
            persist_audit_chain_verification_success: AtomicU64::new(0),
            persist_audit_chain_verification_failure: AtomicU64::new(0),
            persist_audit_write_failure: AtomicU64::new(0),
            persist_write_success: AtomicU64::new(0),
            persist_read_success: AtomicU64::new(0),
            persist_error: AtomicU64::new(0),

            session_quorum_read_success: AtomicU64::new(0),
            session_quorum_read_failure: AtomicU64::new(0),
            session_quorum_write_success: AtomicU64::new(0),
            session_quorum_write_failure: AtomicU64::new(0),
            session_committed_replication_sequence: AtomicU64::new(0),
            session_replica_repair: AtomicU64::new(0),
            session_replica_catchup: AtomicU64::new(0),
            session_failed_partial_write_rollback: AtomicU64::new(0),
            session_watch_resume_success: AtomicU64::new(0),
            session_watch_resume_failure: AtomicU64::new(0),
            session_lease_acquire: AtomicU64::new(0),
            session_lease_renew: AtomicU64::new(0),
            session_lease_release: AtomicU64::new(0),
            session_lease_delete: AtomicU64::new(0),
            session_durable_readiness_probe_success: AtomicU64::new(0),
            session_durable_readiness_probe_failure: AtomicU64::new(0),
            session_durable_readiness_ready: AtomicI64::new(0),
            session_durable_readiness_configured_voters: AtomicU64::new(0),
            session_durable_readiness_fresh_reachable_voters: AtomicU64::new(0),
            session_durable_readiness_agreeing_voters: AtomicU64::new(0),
            session_durable_readiness_required_quorum: AtomicU64::new(0),
            session_durable_readiness_majority_visible_prefix: AtomicU64::new(0),
            session_durable_readiness_timeout_failures: AtomicU64::new(0),
            session_durable_readiness_authentication_failures: AtomicU64::new(0),
            session_durable_readiness_transport_failures: AtomicU64::new(0),
            session_durable_readiness_divergent_failures: AtomicU64::new(0),
            session_durable_readiness_recovery_required_failures: AtomicU64::new(0),
            session_operator_recovery_attempts: AtomicU64::new(0),
            session_operator_recovery_failures: AtomicU64::new(0),
            session_operator_recovery_required: AtomicI64::new(0),
            session_operator_recovery_audit_pending: AtomicI64::new(0),
            session_operator_recovery_epoch: AtomicU64::new(0),
            session_operator_recovery_rejoins: AtomicU64::new(0),
            session_net_backend_queue_timeouts: AtomicU64::new(0),
            session_net_backend_execution_timeouts: AtomicU64::new(0),
            session_net_backend_cancellations: AtomicU64::new(0),
            session_net_backend_peer_disconnects: AtomicU64::new(0),
            session_net_backend_ambiguous_outcomes: AtomicU64::new(0),
            session_net_lifecycle_retirement_maximum_age: AtomicU64::new(0),
            session_net_lifecycle_retirement_local_leaf_expiry: AtomicU64::new(0),
            session_net_lifecycle_retirement_peer_leaf_expiry: AtomicU64::new(0),
            session_net_lifecycle_retirement_local_certificate_chain_expiry: AtomicU64::new(0),
            session_net_lifecycle_retirement_peer_certificate_chain_expiry: AtomicU64::new(0),
            session_net_lifecycle_retirement_material_epoch: AtomicU64::new(0),
            session_net_lifecycle_retirement_explicit: AtomicU64::new(0),
            session_net_lifecycle_retirement_idle_timeout: AtomicU64::new(0),
            session_net_lifecycle_active_connections: AtomicI64::new(0),
            session_net_lifecycle_draining_connections: AtomicI64::new(0),
            session_net_lifecycle_drain_started: AtomicU64::new(0),
            session_net_lifecycle_drain_completed: AtomicU64::new(0),
            session_net_lifecycle_drain_overruns: AtomicU64::new(0),
            session_net_connection_attempts: AtomicU64::new(0),
            session_net_connection_successes: AtomicU64::new(0),
            session_net_connection_failure_transport: AtomicU64::new(0),
            session_net_connection_failure_authentication: AtomicU64::new(0),
            session_net_connection_failure_timeout: AtomicU64::new(0),
            session_net_connection_failure_protocol: AtomicU64::new(0),
            session_net_connection_failure_backend: AtomicU64::new(0),
            session_net_reconnect_attempts: AtomicU64::new(0),
            session_net_reconnect_failures: AtomicU64::new(0),
            session_net_watch_slow_consumers: AtomicU64::new(0),

            nacm_eval_allow: AtomicU64::new(0),
            nacm_eval_deny: AtomicU64::new(0),
            nacm_eval_error: AtomicU64::new(0),
            nacm_eval_latency: LatencyHistogram::new(),
            nacm_default_deny: AtomicU64::new(0),

            alarm_active_count: Mutex::new(HashMap::new()),
            alarm_audit_success: AtomicU64::new(0),
            alarm_audit_failure: AtomicU64::new(0),
            runtime_health_live: AtomicI64::new(0),
            runtime_health_ready: AtomicI64::new(0),
            runtime_health_startup: AtomicI64::new(0),
            runtime_budget_exhausted: AtomicU64::new(0),

            admin_requests_total: Mutex::new(HashMap::new()),
            admin_auth_failures_total: AtomicU64::new(0),
            admin_malformed_requests_total: AtomicU64::new(0),
            admin_redaction_events_total: AtomicU64::new(0),
            admin_latency_livez: LatencyHistogram::new(),
            admin_latency_readyz: LatencyHistogram::new(),
            admin_latency_startupz: LatencyHistogram::new(),
            admin_latency_metrics: LatencyHistogram::new(),
            admin_latency_debug_runtime: LatencyHistogram::new(),
            admin_latency_debug_tasks: LatencyHistogram::new(),
            admin_latency_debug_config_version: LatencyHistogram::new(),
            admin_request_latency_seconds: Mutex::new(HashMap::new()),

            // === SBI Metrics ===
            sbi_requests_total: Mutex::new(HashMap::new()),
            sbi_request_duration_seconds: Mutex::new(HashMap::new()),
            sbi_problem_details_total: Mutex::new(HashMap::new()),
            sbi_oauth_validation_total: Mutex::new(HashMap::new()),
            sbi_nrf_discovery_total: Mutex::new(HashMap::new()),
            sbi_nrf_cache_entries: Mutex::new(HashMap::new()),
            sbi_nrf_heartbeat_total: Mutex::new(HashMap::new()),
            sbi_circuit_state: Mutex::new(HashMap::new()),
            sbi_overload_rejections_total: Mutex::new(HashMap::new()),
            sbi_callback_delivery_total: Mutex::new(HashMap::new()),

            gnmi_rpc_requests_total: Mutex::new(HashMap::new()),
            gnmi_rpc_errors_total: Mutex::new(HashMap::new()),
            gnmi_rpc_seconds: Mutex::new(HashMap::new()),
            gnmi_set_commit_seconds: Mutex::new(HashMap::new()),
            gnmi_active_streams: Mutex::new(HashMap::new()),
            gnmi_sessions_active: Mutex::new(HashMap::new()),
            gnmi_listener_events_total: Mutex::new(HashMap::new()),
            gnmi_subscription_events_total: Mutex::new(HashMap::new()),
            gnmi_subscription_lag_total: Mutex::new(HashMap::new()),
            gnmi_nacm_denials_total: Mutex::new(HashMap::new()),
            gnmi_extensions_total: Mutex::new(HashMap::new()),
            gnmi_arbitration_denials_total: Mutex::new(HashMap::new()),

            netconf_sessions_active: Mutex::new(HashMap::new()),
            netconf_rpc_requests_total: Mutex::new(HashMap::new()),
            netconf_rpc_errors_total: Mutex::new(HashMap::new()),
            netconf_rpc_seconds: Mutex::new(HashMap::new()),
            netconf_commit_seconds: Mutex::new(HashMap::new()),
            netconf_locks_active: Mutex::new(HashMap::new()),
            netconf_notifications_total: Mutex::new(HashMap::new()),
            netconf_nacm_denials_total: Mutex::new(HashMap::new()),
        }
    }

    /// Reset all metrics to their default initial values.
    ///
    /// Process-wide security rotation evidence is deliberately excluded: a
    /// newly constructed `SdkMetrics` value must not be able to erase the sole
    /// TLS telemetry authority's monotonic counters or current gauges.
    pub fn reset_all(&self) {
        self.config_bus_pending_commits.store(0, Ordering::Relaxed);
        self.break_glass_sessions_active.store(0, Ordering::Relaxed);
        self.config_bus_commit_confirmed_deadline_expiry
            .store(0, Ordering::Relaxed);
        self.config_bus_phase_latency_apply.reset();
        self.config_bus_phase_latency_validate.reset();
        self.config_bus_phase_latency_persist.reset();
        self.config_bus_phase_latency_notify.reset();
        self.config_bus_rollback_success.store(0, Ordering::Relaxed);
        self.config_bus_rollback_failure.store(0, Ordering::Relaxed);
        self.config_bus_recovery_fence_active
            .store(0, Ordering::Relaxed);
        self.config_bus_subscriber_notification_failures
            .store(0, Ordering::Relaxed);

        self.persist_leader_term.store(0, Ordering::Relaxed);
        self.persist_commit_index.store(0, Ordering::Relaxed);
        self.persist_applied_index.store(0, Ordering::Relaxed);
        self.persist_snapshot_index.store(0, Ordering::Relaxed);
        self.persist_leader_changes.store(0, Ordering::Relaxed);
        self.persist_quorum_read_success.store(0, Ordering::Relaxed);
        self.persist_quorum_read_failure.store(0, Ordering::Relaxed);
        self.persist_quorum_write_success
            .store(0, Ordering::Relaxed);
        self.persist_quorum_write_failure
            .store(0, Ordering::Relaxed);
        self.persist_stale_leader_rejections
            .store(0, Ordering::Relaxed);
        if let Ok(mut lag) = self.persist_peer_replication_lag.lock() {
            lag.clear();
        }
        self.persist_snapshot_install_failures
            .store(0, Ordering::Relaxed);
        self.persist_snapshot_verify_failures
            .store(0, Ordering::Relaxed);
        self.persist_rpc_auth_failures.store(0, Ordering::Relaxed);
        self.persist_audit_chain_verification_success
            .store(0, Ordering::Relaxed);
        self.persist_audit_chain_verification_failure
            .store(0, Ordering::Relaxed);
        self.persist_audit_write_failure.store(0, Ordering::Relaxed);
        self.persist_write_success.store(0, Ordering::Relaxed);
        self.persist_read_success.store(0, Ordering::Relaxed);
        self.persist_error.store(0, Ordering::Relaxed);

        self.session_quorum_read_success.store(0, Ordering::Relaxed);
        self.session_quorum_read_failure.store(0, Ordering::Relaxed);
        self.session_quorum_write_success
            .store(0, Ordering::Relaxed);
        self.session_quorum_write_failure
            .store(0, Ordering::Relaxed);
        self.session_committed_replication_sequence
            .store(0, Ordering::Relaxed);
        self.session_replica_repair.store(0, Ordering::Relaxed);
        self.session_replica_catchup.store(0, Ordering::Relaxed);
        self.session_failed_partial_write_rollback
            .store(0, Ordering::Relaxed);
        self.session_watch_resume_success
            .store(0, Ordering::Relaxed);
        self.session_watch_resume_failure
            .store(0, Ordering::Relaxed);
        self.session_lease_acquire.store(0, Ordering::Relaxed);
        self.session_lease_renew.store(0, Ordering::Relaxed);
        self.session_lease_release.store(0, Ordering::Relaxed);
        self.session_lease_delete.store(0, Ordering::Relaxed);
        self.session_durable_readiness_probe_success
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_probe_failure
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_ready
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_configured_voters
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_fresh_reachable_voters
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_agreeing_voters
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_required_quorum
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_majority_visible_prefix
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_timeout_failures
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_authentication_failures
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_transport_failures
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_divergent_failures
            .store(0, Ordering::Relaxed);
        self.session_durable_readiness_recovery_required_failures
            .store(0, Ordering::Relaxed);
        self.session_operator_recovery_attempts
            .store(0, Ordering::Relaxed);
        self.session_operator_recovery_failures
            .store(0, Ordering::Relaxed);
        self.session_operator_recovery_required
            .store(0, Ordering::Relaxed);
        self.session_operator_recovery_audit_pending
            .store(0, Ordering::Relaxed);
        self.session_operator_recovery_epoch
            .store(0, Ordering::Relaxed);
        self.session_operator_recovery_rejoins
            .store(0, Ordering::Relaxed);
        self.session_net_backend_queue_timeouts
            .store(0, Ordering::Relaxed);
        self.session_net_backend_execution_timeouts
            .store(0, Ordering::Relaxed);
        self.session_net_backend_cancellations
            .store(0, Ordering::Relaxed);
        self.session_net_backend_peer_disconnects
            .store(0, Ordering::Relaxed);
        self.session_net_backend_ambiguous_outcomes
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_maximum_age
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_local_leaf_expiry
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_peer_leaf_expiry
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_local_certificate_chain_expiry
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_peer_certificate_chain_expiry
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_material_epoch
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_explicit
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_retirement_idle_timeout
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_active_connections
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_draining_connections
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_drain_started
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_drain_completed
            .store(0, Ordering::Relaxed);
        self.session_net_lifecycle_drain_overruns
            .store(0, Ordering::Relaxed);
        self.session_net_connection_attempts
            .store(0, Ordering::Relaxed);
        self.session_net_connection_successes
            .store(0, Ordering::Relaxed);
        self.session_net_connection_failure_transport
            .store(0, Ordering::Relaxed);
        self.session_net_connection_failure_authentication
            .store(0, Ordering::Relaxed);
        self.session_net_connection_failure_timeout
            .store(0, Ordering::Relaxed);
        self.session_net_connection_failure_protocol
            .store(0, Ordering::Relaxed);
        self.session_net_connection_failure_backend
            .store(0, Ordering::Relaxed);
        self.session_net_reconnect_attempts
            .store(0, Ordering::Relaxed);
        self.session_net_reconnect_failures
            .store(0, Ordering::Relaxed);
        self.session_net_watch_slow_consumers
            .store(0, Ordering::Relaxed);

        self.nacm_eval_allow.store(0, Ordering::Relaxed);
        self.nacm_eval_deny.store(0, Ordering::Relaxed);
        self.nacm_eval_error.store(0, Ordering::Relaxed);
        self.nacm_eval_latency.reset();
        self.nacm_default_deny.store(0, Ordering::Relaxed);

        if let Ok(mut alarms) = self.alarm_active_count.lock() {
            alarms.clear();
        }
        self.alarm_audit_success.store(0, Ordering::Relaxed);
        self.alarm_audit_failure.store(0, Ordering::Relaxed);
        self.runtime_health_live.store(0, Ordering::Relaxed);
        self.runtime_health_ready.store(0, Ordering::Relaxed);
        self.runtime_health_startup.store(0, Ordering::Relaxed);
        self.runtime_budget_exhausted.store(0, Ordering::Relaxed);

        if let Ok(mut reqs) = self.admin_requests_total.lock() {
            reqs.clear();
        }
        self.admin_auth_failures_total.store(0, Ordering::Relaxed);
        self.admin_malformed_requests_total
            .store(0, Ordering::Relaxed);
        self.admin_redaction_events_total
            .store(0, Ordering::Relaxed);
        self.admin_latency_livez.reset();
        self.admin_latency_readyz.reset();
        self.admin_latency_startupz.reset();
        self.admin_latency_metrics.reset();
        self.admin_latency_debug_runtime.reset();
        self.admin_latency_debug_tasks.reset();
        self.admin_latency_debug_config_version.reset();
        if let Ok(mut m) = self.admin_request_latency_seconds.lock() {
            m.clear();
        }

        if let Ok(mut m) = self.sbi_requests_total.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_request_duration_seconds.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_problem_details_total.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_oauth_validation_total.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_nrf_discovery_total.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_nrf_cache_entries.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_nrf_heartbeat_total.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_circuit_state.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_overload_rejections_total.lock() {
            m.clear();
        }
        if let Ok(mut m) = self.sbi_callback_delivery_total.lock() {
            m.clear();
        }

        for map in [
            &self.gnmi_rpc_requests_total,
            &self.gnmi_rpc_errors_total,
            &self.gnmi_listener_events_total,
            &self.gnmi_subscription_events_total,
            &self.gnmi_extensions_total,
            &self.netconf_rpc_requests_total,
            &self.netconf_rpc_errors_total,
            &self.netconf_notifications_total,
        ] {
            if let Ok(mut m) = map.lock() {
                m.clear();
            }
        }
        for map in [
            &self.gnmi_subscription_lag_total,
            &self.gnmi_nacm_denials_total,
            &self.gnmi_arbitration_denials_total,
            &self.netconf_nacm_denials_total,
        ] {
            if let Ok(mut m) = map.lock() {
                m.clear();
            }
        }
        for map in [
            &self.gnmi_active_streams,
            &self.gnmi_sessions_active,
            &self.netconf_sessions_active,
            &self.netconf_locks_active,
        ] {
            if let Ok(mut m) = map.lock() {
                m.clear();
            }
        }
        for map in [
            &self.gnmi_rpc_seconds,
            &self.gnmi_set_commit_seconds,
            &self.netconf_rpc_seconds,
            &self.netconf_commit_seconds,
        ] {
            if let Ok(mut m) = map.lock() {
                m.clear();
            }
        }
    }
}

impl Default for SdkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global static SDK metrics registry instance.
pub static METRICS: LazyLock<SdkMetrics> = LazyLock::new(SdkMetrics::new);

/// Private process-wide state for security-material telemetry.
static SECURITY_METRICS: LazyLock<Arc<SecurityMetricsState>> =
    LazyLock::new(|| Arc::new(SecurityMetricsState::default()));
static SECURITY_METRICS_AUTHORITY_CLAIMED: AtomicBool = AtomicBool::new(false);

fn write_metric(out: &mut String, name: &str, mtype: &str, help: &str, val: f64) {
    out.push_str(&format!(
        "# HELP {} {}\n",
        name,
        escape_prometheus_help(help)
    ));
    out.push_str(&format!("# TYPE {name} {mtype}\n"));
    out.push_str(&format!("{name} {val}\n"));
}

fn write_metric_u64(out: &mut String, name: &str, mtype: &str, help: &str, val: u64) {
    out.push_str(&format!(
        "# HELP {} {}\n",
        name,
        escape_prometheus_help(help)
    ));
    out.push_str(&format!("# TYPE {name} {mtype}\n"));
    out.push_str(&format!("{name} {val}\n"));
}

fn write_histogram_metadata(out: &mut String, name: &str, help: &str) {
    out.push_str(&format!(
        "# HELP {} {}\n",
        name,
        escape_prometheus_help(help)
    ));
    out.push_str(&format!("# TYPE {name} histogram\n"));
}

fn write_histogram_samples(
    out: &mut String,
    name: &str,
    hist: &LatencyHistogram,
    labels: &[(&str, &str)],
) {
    let count = hist.count.load(Ordering::Relaxed);
    let sum = hist.sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;

    for (i, &bucket) in LATENCY_BUCKETS.iter().enumerate() {
        let bval = hist.buckets[i].load(Ordering::Relaxed);
        let le = bucket.to_string();
        let mut bucket_labels = Vec::with_capacity(labels.len() + 1);
        bucket_labels.extend_from_slice(labels);
        bucket_labels.push(("le", le.as_str()));
        out.push_str(&format!(
            "{}_bucket{} {}\n",
            name,
            format_prometheus_labels(&bucket_labels),
            bval
        ));
    }

    let mut inf_labels = Vec::with_capacity(labels.len() + 1);
    inf_labels.extend_from_slice(labels);
    inf_labels.push(("le", "+Inf"));
    out.push_str(&format!(
        "{}_bucket{} {}\n",
        name,
        format_prometheus_labels(&inf_labels),
        count
    ));
    out.push_str(&format!(
        "{}_sum{} {}\n",
        name,
        format_prometheus_labels(labels),
        sum
    ));
    out.push_str(&format!(
        "{}_count{} {}\n",
        name,
        format_prometheus_labels(labels),
        count
    ));
}

fn format_prometheus_labels(labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }

    let rendered = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape_prometheus_label_value(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{rendered}}}")
}

fn escape_prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}

fn escape_prometheus_help(help: &str) -> String {
    help.replace('\\', r"\\").replace('\n', r"\n")
}

/// Render a single-label counter family from a locked map, sanitizing the label
/// value with [`metrics_label_safe`] and emitting rows in deterministic order.
fn write_labeled_counter_1(
    out: &mut String,
    name: &str,
    help: &str,
    map: &Mutex<HashMap<String, u64>>,
    label: &str,
) {
    out.push_str(&format!("# HELP {name} {}\n", escape_prometheus_help(help)));
    out.push_str(&format!("# TYPE {name} counter\n"));
    if let Ok(m) = map.lock() {
        let mut sorted: Vec<_> = m.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (k, &v) in sorted {
            let safe = metrics_label_safe(k);
            out.push_str(&format!("{name}{{{label}=\"{safe}\"}} {v}\n"));
        }
    }
}

/// Render a two-label counter family from a locked map, sanitizing both labels.
fn write_labeled_counter_2(
    out: &mut String,
    name: &str,
    help: &str,
    map: &Mutex<HashMap<(String, String), u64>>,
    l1: &str,
    l2: &str,
) {
    out.push_str(&format!("# HELP {name} {}\n", escape_prometheus_help(help)));
    out.push_str(&format!("# TYPE {name} counter\n"));
    if let Ok(m) = map.lock() {
        let mut sorted: Vec<_> = m.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (k, &v) in sorted {
            let s1 = metrics_label_safe(&k.0);
            let s2 = metrics_label_safe(&k.1);
            out.push_str(&format!("{name}{{{l1}=\"{s1}\",{l2}=\"{s2}\"}} {v}\n"));
        }
    }
}

/// Render a single-label gauge family from a locked map, sanitizing the label.
fn write_labeled_gauge_1(
    out: &mut String,
    name: &str,
    help: &str,
    map: &Mutex<HashMap<String, i64>>,
    label: &str,
) {
    out.push_str(&format!("# HELP {name} {}\n", escape_prometheus_help(help)));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    if let Ok(m) = map.lock() {
        let mut sorted: Vec<_> = m.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (k, &v) in sorted {
            let safe = metrics_label_safe(k);
            out.push_str(&format!("{name}{{{label}=\"{safe}\"}} {v}\n"));
        }
    }
}

/// Render a single-label histogram family from a locked map of histograms,
/// sanitizing the label and reusing [`write_histogram_samples`] per series.
fn write_labeled_histogram_1(
    out: &mut String,
    name: &str,
    help: &str,
    map: &Mutex<HashMap<String, LatencyHistogram>>,
    label: &str,
) {
    write_histogram_metadata(out, name, help);
    if let Ok(m) = map.lock() {
        let mut sorted: Vec<_> = m.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (k, hist) in sorted {
            let safe = metrics_label_safe(k);
            write_histogram_samples(out, name, hist, &[(label, &safe)]);
        }
    }
}

fn write_security_metrics(out: &mut String, reader: &SecurityMetricsReader) {
    let security = reader.snapshot();
    write_metric(
        out,
        "opc_security_svid_expires_seconds",
        "gauge",
        "Effective earliest configured/presented SVID-chain expiry as Unix seconds, or zero when unavailable",
        security.svid_expires_seconds() as f64,
    );
    write_metric_u64(
        out,
        "opc_security_bundle_version",
        "gauge",
        "Opaque process-local coherent TLS-material epoch",
        security.bundle_version(),
    );
    out.push_str(
        "# HELP opc_security_rotation_total Total count of coherent TLS-material rotation outcomes\n",
    );
    out.push_str("# TYPE opc_security_rotation_total counter\n");
    for kind in SecurityRotationKind::ALL {
        for outcome in SecurityRotationOutcome::ALL {
            let value = security.rotation(kind, outcome);
            out.push_str(&format!(
                "opc_security_rotation_total{{kind=\"{}\",outcome=\"{}\"}} {value}\n",
                kind.as_str(),
                outcome.as_str(),
            ));
        }
    }
    out.push_str(
        "# HELP opc_security_rotation_saturated Whether a fixed rotation counter reached its u64 representation ceiling\n",
    );
    out.push_str("# TYPE opc_security_rotation_saturated gauge\n");
    for kind in SecurityRotationKind::ALL {
        for outcome in SecurityRotationOutcome::ALL {
            let value = u8::from(security.rotation_saturated(kind, outcome));
            out.push_str(&format!(
                "opc_security_rotation_saturated{{kind=\"{}\",outcome=\"{}\"}} {value}\n",
                kind.as_str(),
                outcome.as_str(),
            ));
        }
    }
}

/// Export all SDK metrics in standard Prometheus text exposition format.
pub fn export_prometheus_text() -> String {
    let mut out = String::new();

    // --- Security / TLS material ---
    write_security_metrics(&mut out, &SecurityMetricsReader::global());

    // --- Config Bus ---
    let pending = METRICS.config_bus_pending_commits.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_config_bus_pending_commits",
        "gauge",
        "Number of config commits pending in the queue",
        pending as f64,
    );

    let break_glass = METRICS.break_glass_sessions_active.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_break_glass_sessions_active",
        "gauge",
        "Number of active break-glass sessions",
        break_glass as f64,
    );

    let expiry = METRICS
        .config_bus_commit_confirmed_deadline_expiry
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_config_bus_commit_confirmed_deadline_expiry_total",
        "counter",
        "Number of expired commit-confirmed deadlines",
        expiry as f64,
    );

    write_histogram_metadata(
        &mut out,
        "opc_config_bus_phase_latency_seconds",
        "Phase latency for config bus operations",
    );
    write_histogram_samples(
        &mut out,
        "opc_config_bus_phase_latency_seconds",
        &METRICS.config_bus_phase_latency_apply,
        &[("phase", "apply")],
    );
    write_histogram_samples(
        &mut out,
        "opc_config_bus_phase_latency_seconds",
        &METRICS.config_bus_phase_latency_validate,
        &[("phase", "validate")],
    );
    write_histogram_samples(
        &mut out,
        "opc_config_bus_phase_latency_seconds",
        &METRICS.config_bus_phase_latency_persist,
        &[("phase", "persist")],
    );
    write_histogram_samples(
        &mut out,
        "opc_config_bus_phase_latency_seconds",
        &METRICS.config_bus_phase_latency_notify,
        &[("phase", "notify")],
    );

    let rollback_success = METRICS.config_bus_rollback_success.load(Ordering::Relaxed);
    out.push_str("# HELP opc_config_bus_rollback_total Total count of config rollbacks\n");
    out.push_str("# TYPE opc_config_bus_rollback_total counter\n");
    out.push_str(&format!(
        "opc_config_bus_rollback_total{{status=\"success\"}} {rollback_success}\n"
    ));
    let rollback_failure = METRICS.config_bus_rollback_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_config_bus_rollback_total{{status=\"failure\"}} {rollback_failure}\n"
    ));

    let fence = METRICS
        .config_bus_recovery_fence_active
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_config_bus_recovery_fence_active",
        "gauge",
        "Whether the recovery fence is active (1) or not (0)",
        fence as f64,
    );

    let notify_fail = METRICS
        .config_bus_subscriber_notification_failures
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_config_bus_subscriber_notification_failures_total",
        "counter",
        "Total count of subscriber notification failures",
        notify_fail as f64,
    );

    // --- Persistence / HA ---
    let term = METRICS.persist_leader_term.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_leader_term",
        "gauge",
        "Current HA consensus leader term",
        term as f64,
    );

    let commit_idx = METRICS.persist_commit_index.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_commit_index",
        "gauge",
        "Current HA consensus commit index",
        commit_idx as f64,
    );

    let applied_idx = METRICS.persist_applied_index.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_applied_index",
        "gauge",
        "Current HA consensus applied index",
        applied_idx as f64,
    );

    let snap_idx = METRICS.persist_snapshot_index.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_snapshot_index",
        "gauge",
        "Current HA consensus snapshot index",
        snap_idx as f64,
    );

    let leader_changes = METRICS.persist_leader_changes.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_leader_changes_total",
        "counter",
        "Total count of consensus leadership changes",
        leader_changes as f64,
    );

    let quorum_r_succ = METRICS.persist_quorum_read_success.load(Ordering::Relaxed);
    out.push_str("# HELP opc_persist_quorum_total Total count of consensus quorum actions\n");
    out.push_str("# TYPE opc_persist_quorum_total counter\n");
    out.push_str(&format!(
        "opc_persist_quorum_total{{op=\"read\",status=\"success\"}} {quorum_r_succ}\n"
    ));
    let quorum_r_fail = METRICS.persist_quorum_read_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_persist_quorum_total{{op=\"read\",status=\"failure\"}} {quorum_r_fail}\n"
    ));
    let quorum_w_succ = METRICS.persist_quorum_write_success.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_persist_quorum_total{{op=\"write\",status=\"success\"}} {quorum_w_succ}\n"
    ));
    let quorum_w_fail = METRICS.persist_quorum_write_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_persist_quorum_total{{op=\"write\",status=\"failure\"}} {quorum_w_fail}\n"
    ));

    let stale_leader = METRICS
        .persist_stale_leader_rejections
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_stale_leader_rejections_total",
        "counter",
        "Total count of stale leader rejections",
        stale_leader as f64,
    );

    out.push_str(
        "# HELP opc_persist_peer_replication_lag Replication lag of HA peers in log entries\n",
    );
    out.push_str("# TYPE opc_persist_peer_replication_lag gauge\n");
    if let Ok(lag_map) = METRICS.persist_peer_replication_lag.lock() {
        let mut sorted_lag: Vec<_> = lag_map.iter().collect();
        sorted_lag.sort_by_key(|k| k.0);
        for (&peer, &lag) in sorted_lag {
            out.push_str(&format!(
                "opc_persist_peer_replication_lag{{peer=\"{peer}\"}} {lag}\n"
            ));
        }
    }

    let snap_inst_fail = METRICS
        .persist_snapshot_install_failures
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_snapshot_install_failures_total",
        "counter",
        "Total count of snapshot install failures",
        snap_inst_fail as f64,
    );

    let snap_ver_fail = METRICS
        .persist_snapshot_verify_failures
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_snapshot_verify_failures_total",
        "counter",
        "Total count of snapshot verification failures",
        snap_ver_fail as f64,
    );

    let rpc_auth_fail = METRICS.persist_rpc_auth_failures.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_rpc_auth_failures_total",
        "counter",
        "Total count of RPC/auth failures",
        rpc_auth_fail as f64,
    );

    let audit_chain_succ = METRICS
        .persist_audit_chain_verification_success
        .load(Ordering::Relaxed);
    out.push_str("# HELP opc_persist_audit_chain_verification_total Total count of audit-chain verifications\n");
    out.push_str("# TYPE opc_persist_audit_chain_verification_total counter\n");
    out.push_str(&format!(
        "opc_persist_audit_chain_verification_total{{status=\"success\"}} {audit_chain_succ}\n"
    ));
    let audit_chain_fail = METRICS
        .persist_audit_chain_verification_failure
        .load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_persist_audit_chain_verification_total{{status=\"failure\"}} {audit_chain_fail}\n"
    ));

    let audit_write_fail = METRICS.persist_audit_write_failure.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_audit_write_failure_total",
        "counter",
        "Total count of failed required audit writes",
        audit_write_fail as f64,
    );

    let p_write = METRICS.persist_write_success.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_write_total",
        "counter",
        "Total count of successful persistence writes",
        p_write as f64,
    );
    let p_read = METRICS.persist_read_success.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_read_total",
        "counter",
        "Total count of successful persistence reads",
        p_read as f64,
    );
    let p_err = METRICS.persist_error.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_persist_error_total",
        "counter",
        "Total count of persistence errors",
        p_err as f64,
    );

    // --- Session Store ---
    let s_quorum_r_succ = METRICS.session_quorum_read_success.load(Ordering::Relaxed);
    out.push_str(
        "# HELP opc_session_store_quorum_total Total count of session store quorum actions\n",
    );
    out.push_str("# TYPE opc_session_store_quorum_total counter\n");
    out.push_str(&format!(
        "opc_session_store_quorum_total{{op=\"read\",status=\"success\"}} {s_quorum_r_succ}\n"
    ));
    let s_quorum_r_fail = METRICS.session_quorum_read_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_quorum_total{{op=\"read\",status=\"failure\"}} {s_quorum_r_fail}\n"
    ));
    let s_quorum_w_succ = METRICS.session_quorum_write_success.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_quorum_total{{op=\"write\",status=\"success\"}} {s_quorum_w_succ}\n"
    ));
    let s_quorum_w_fail = METRICS.session_quorum_write_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_quorum_total{{op=\"write\",status=\"failure\"}} {s_quorum_w_fail}\n"
    ));

    let s_seq = METRICS
        .session_committed_replication_sequence
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_committed_replication_sequence",
        "gauge",
        "Session store committed replication sequence number",
        s_seq as f64,
    );

    let s_repair = METRICS.session_replica_repair.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_replica_repair_total",
        "counter",
        "Total count of replica repair operations",
        s_repair as f64,
    );
    let s_catchup = METRICS.session_replica_catchup.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_replica_catchup_total",
        "counter",
        "Total count of replica catch-up operations",
        s_catchup as f64,
    );
    let s_rollback = METRICS
        .session_failed_partial_write_rollback
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_failed_partial_write_rollback_total",
        "counter",
        "Total count of failed partial-write rollbacks",
        s_rollback as f64,
    );

    let s_watch_succ = METRICS.session_watch_resume_success.load(Ordering::Relaxed);
    out.push_str(
        "# HELP opc_session_store_watch_resume_total Total count of watch resume operations\n",
    );
    out.push_str("# TYPE opc_session_store_watch_resume_total counter\n");
    out.push_str(&format!(
        "opc_session_store_watch_resume_total{{status=\"success\"}} {s_watch_succ}\n"
    ));
    let s_watch_fail = METRICS.session_watch_resume_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_watch_resume_total{{status=\"failure\"}} {s_watch_fail}\n"
    ));

    let s_lease_acq = METRICS.session_lease_acquire.load(Ordering::Relaxed);
    out.push_str("# HELP opc_session_store_lease_ops_total Total count of lease operations\n");
    out.push_str("# TYPE opc_session_store_lease_ops_total counter\n");
    out.push_str(&format!(
        "opc_session_store_lease_ops_total{{op=\"acquire\"}} {s_lease_acq}\n"
    ));
    let s_lease_ren = METRICS.session_lease_renew.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_lease_ops_total{{op=\"renew\"}} {s_lease_ren}\n"
    ));
    let s_lease_rel = METRICS.session_lease_release.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_lease_ops_total{{op=\"release\"}} {s_lease_rel}\n"
    ));
    let s_lease_del = METRICS.session_lease_delete.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_session_store_lease_ops_total{{op=\"delete\"}} {s_lease_del}\n"
    ));

    let readiness_probe_success = METRICS
        .session_durable_readiness_probe_success
        .load(Ordering::Relaxed);
    let readiness_probe_failure = METRICS
        .session_durable_readiness_probe_failure
        .load(Ordering::Relaxed);
    out.push_str(
        "# HELP opc_session_store_durable_readiness_probe_total Total count of fresh durable-readiness probes\n",
    );
    out.push_str("# TYPE opc_session_store_durable_readiness_probe_total counter\n");
    out.push_str(&format!(
        "opc_session_store_durable_readiness_probe_total{{status=\"success\"}} {readiness_probe_success}\n"
    ));
    out.push_str(&format!(
        "opc_session_store_durable_readiness_probe_total{{status=\"failure\"}} {readiness_probe_failure}\n"
    ));

    let readiness_ready = METRICS
        .session_durable_readiness_ready
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_durable_readiness_ready",
        "gauge",
        "Whether the most recent durable-readiness probe succeeded (1) or not (0)",
        readiness_ready as f64,
    );

    let readiness_configured_voters = METRICS
        .session_durable_readiness_configured_voters
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_durable_readiness_configured_voters",
        "gauge",
        "Configured distinct session-store voters in the most recent durable-readiness probe",
        readiness_configured_voters as f64,
    );

    let readiness_fresh_reachable_voters = METRICS
        .session_durable_readiness_fresh_reachable_voters
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_durable_readiness_fresh_reachable_voters",
        "gauge",
        "Minimum session-store voters whose reachability was proven by the latest Openraft barrier",
        readiness_fresh_reachable_voters as f64,
    );

    let readiness_agreeing_voters = METRICS
        .session_durable_readiness_agreeing_voters
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_durable_readiness_agreeing_voters",
        "gauge",
        "Minimum session-store voters whose agreement was proven by the latest Openraft commit barrier",
        readiness_agreeing_voters as f64,
    );

    let readiness_required_quorum = METRICS
        .session_durable_readiness_required_quorum
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_durable_readiness_required_quorum",
        "gauge",
        "Distinct voter acknowledgements required for session-store durable readiness",
        readiness_required_quorum as f64,
    );

    let readiness_majority_visible_prefix = METRICS
        .session_durable_readiness_majority_visible_prefix
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_durable_readiness_majority_visible_prefix",
        "gauge",
        "Openraft committed barrier index from the latest ready probe (compatibility metric name)",
        readiness_majority_visible_prefix as f64,
    );

    let readiness_timeout_failures = METRICS
        .session_durable_readiness_timeout_failures
        .load(Ordering::Relaxed);
    let readiness_authentication_failures = METRICS
        .session_durable_readiness_authentication_failures
        .load(Ordering::Relaxed);
    let readiness_transport_failures = METRICS
        .session_durable_readiness_transport_failures
        .load(Ordering::Relaxed);
    let readiness_divergent_failures = METRICS
        .session_durable_readiness_divergent_failures
        .load(Ordering::Relaxed);
    let readiness_recovery_required_failures = METRICS
        .session_durable_readiness_recovery_required_failures
        .load(Ordering::Relaxed);
    out.push_str(
        "# HELP opc_session_store_durable_readiness_failures_total Total count of durable-readiness failures by bounded reason\n",
    );
    out.push_str("# TYPE opc_session_store_durable_readiness_failures_total counter\n");
    out.push_str(&format!(
        "opc_session_store_durable_readiness_failures_total{{reason=\"timeout\"}} {readiness_timeout_failures}\n"
    ));
    out.push_str(&format!(
        "opc_session_store_durable_readiness_failures_total{{reason=\"authentication\"}} {readiness_authentication_failures}\n"
    ));
    out.push_str(&format!(
        "opc_session_store_durable_readiness_failures_total{{reason=\"transport\"}} {readiness_transport_failures}\n"
    ));
    out.push_str(&format!(
        "opc_session_store_durable_readiness_failures_total{{reason=\"divergent\"}} {readiness_divergent_failures}\n"
    ));
    out.push_str(&format!(
        "opc_session_store_durable_readiness_failures_total{{reason=\"recovery_required\"}} {readiness_recovery_required_failures}\n"
    ));

    let operator_recovery_attempts = METRICS
        .session_operator_recovery_attempts
        .load(Ordering::Relaxed);
    let operator_recovery_failures = METRICS
        .session_operator_recovery_failures
        .load(Ordering::Relaxed);
    let operator_recovery_required = METRICS
        .session_operator_recovery_required
        .load(Ordering::Relaxed);
    let operator_recovery_audit_pending = METRICS
        .session_operator_recovery_audit_pending
        .load(Ordering::Relaxed);
    let operator_recovery_epoch = METRICS
        .session_operator_recovery_epoch
        .load(Ordering::Relaxed);
    let operator_recovery_rejoins = METRICS
        .session_operator_recovery_rejoins
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_session_store_operator_recovery_attempts_total",
        "counter",
        "Authorized operator recovery actions attempted",
        operator_recovery_attempts as f64,
    );
    write_metric(
        &mut out,
        "opc_session_store_operator_recovery_failures_total",
        "counter",
        "Operator recovery actions that failed closed",
        operator_recovery_failures as f64,
    );
    write_metric(
        &mut out,
        "opc_session_store_operator_recovery_required",
        "gauge",
        "Whether an operator recovery workflow is blocking readiness",
        operator_recovery_required as f64,
    );
    write_metric(
        &mut out,
        "opc_session_store_operator_recovery_audit_pending",
        "gauge",
        "Whether successful operator recovery is blocked on durable audit",
        operator_recovery_audit_pending as f64,
    );
    write_metric(
        &mut out,
        "opc_session_store_operator_recovery_epoch",
        "gauge",
        "Latest Openraft-committed operator recovery epoch",
        operator_recovery_epoch as f64,
    );
    write_metric(
        &mut out,
        "opc_session_store_operator_recovery_rejoins_total",
        "counter",
        "Operator recovery workflows that completed a fresh rejoin barrier",
        operator_recovery_rejoins as f64,
    );

    let backend_queue_timeouts = METRICS
        .session_net_backend_queue_timeouts
        .load(Ordering::Relaxed);
    let backend_execution_timeouts = METRICS
        .session_net_backend_execution_timeouts
        .load(Ordering::Relaxed);
    let backend_cancellations = METRICS
        .session_net_backend_cancellations
        .load(Ordering::Relaxed);
    let backend_peer_disconnects = METRICS
        .session_net_backend_peer_disconnects
        .load(Ordering::Relaxed);
    let backend_ambiguous_outcomes = METRICS
        .session_net_backend_ambiguous_outcomes
        .load(Ordering::Relaxed);
    out.push_str(
        "# HELP opc_session_net_backend_lifetime_events_total Bounded session backend lifetime events by fixed outcome\n",
    );
    out.push_str("# TYPE opc_session_net_backend_lifetime_events_total counter\n");
    out.push_str(&format!(
        "opc_session_net_backend_lifetime_events_total{{event=\"queue_timeout\"}} {backend_queue_timeouts}\n"
    ));
    out.push_str(&format!(
        "opc_session_net_backend_lifetime_events_total{{event=\"execution_timeout\"}} {backend_execution_timeouts}\n"
    ));
    out.push_str(&format!(
        "opc_session_net_backend_lifetime_events_total{{event=\"cancellation\"}} {backend_cancellations}\n"
    ));
    out.push_str(&format!(
        "opc_session_net_backend_lifetime_events_total{{event=\"peer_disconnect\"}} {backend_peer_disconnects}\n"
    ));
    out.push_str(&format!(
        "opc_session_net_backend_lifetime_events_total{{event=\"ambiguous_outcome\"}} {backend_ambiguous_outcomes}\n"
    ));

    out.push_str(
        "# HELP opc_session_net_connection_retirements_total Session connection retirements by fixed reason\n",
    );
    out.push_str("# TYPE opc_session_net_connection_retirements_total counter\n");
    for (reason, value) in [
        (
            "maximum_age",
            METRICS
                .session_net_lifecycle_retirement_maximum_age
                .load(Ordering::Relaxed),
        ),
        (
            "local_leaf_expiry",
            METRICS
                .session_net_lifecycle_retirement_local_leaf_expiry
                .load(Ordering::Relaxed),
        ),
        (
            "peer_leaf_expiry",
            METRICS
                .session_net_lifecycle_retirement_peer_leaf_expiry
                .load(Ordering::Relaxed),
        ),
        (
            "local_certificate_chain_expiry",
            METRICS
                .session_net_lifecycle_retirement_local_certificate_chain_expiry
                .load(Ordering::Relaxed),
        ),
        (
            "peer_certificate_chain_expiry",
            METRICS
                .session_net_lifecycle_retirement_peer_certificate_chain_expiry
                .load(Ordering::Relaxed),
        ),
        (
            "material_epoch",
            METRICS
                .session_net_lifecycle_retirement_material_epoch
                .load(Ordering::Relaxed),
        ),
        (
            "explicit",
            METRICS
                .session_net_lifecycle_retirement_explicit
                .load(Ordering::Relaxed),
        ),
        (
            "idle_timeout",
            METRICS
                .session_net_lifecycle_retirement_idle_timeout
                .load(Ordering::Relaxed),
        ),
    ] {
        out.push_str(&format!(
            "opc_session_net_connection_retirements_total{{reason=\"{reason}\"}} {value}\n"
        ));
    }
    out.push_str(
        "# HELP opc_session_net_connection_lifecycle Current authenticated session connections by fixed lifecycle state\n",
    );
    out.push_str("# TYPE opc_session_net_connection_lifecycle gauge\n");
    for (state, value) in [
        (
            "active",
            METRICS
                .session_net_lifecycle_active_connections
                .load(Ordering::Relaxed),
        ),
        (
            "draining",
            METRICS
                .session_net_lifecycle_draining_connections
                .load(Ordering::Relaxed),
        ),
    ] {
        out.push_str(&format!(
            "opc_session_net_connection_lifecycle{{state=\"{state}\"}} {value}\n"
        ));
    }
    out.push_str(
        "# HELP opc_session_net_connection_drain_events_total Authentication drain transitions by fixed outcome\n",
    );
    out.push_str("# TYPE opc_session_net_connection_drain_events_total counter\n");
    for (event, value) in [
        (
            "started",
            METRICS
                .session_net_lifecycle_drain_started
                .load(Ordering::Relaxed),
        ),
        (
            "completed",
            METRICS
                .session_net_lifecycle_drain_completed
                .load(Ordering::Relaxed),
        ),
        (
            "overrun",
            METRICS
                .session_net_lifecycle_drain_overruns
                .load(Ordering::Relaxed),
        ),
    ] {
        out.push_str(&format!(
            "opc_session_net_connection_drain_events_total{{event=\"{event}\"}} {value}\n"
        ));
    }
    out.push_str(
        "# HELP opc_session_net_connection_attempts_total Session connection attempts by fixed transport/control outcome; success includes an authenticated pre-admission retirement control exchange\n",
    );
    out.push_str("# TYPE opc_session_net_connection_attempts_total counter\n");
    for (outcome, value) in [
        (
            "started",
            METRICS
                .session_net_connection_attempts
                .load(Ordering::Relaxed),
        ),
        (
            "success",
            METRICS
                .session_net_connection_successes
                .load(Ordering::Relaxed),
        ),
        (
            "transport_failure",
            METRICS
                .session_net_connection_failure_transport
                .load(Ordering::Relaxed),
        ),
        (
            "authentication_or_trust_failure",
            METRICS
                .session_net_connection_failure_authentication
                .load(Ordering::Relaxed),
        ),
        (
            "timeout",
            METRICS
                .session_net_connection_failure_timeout
                .load(Ordering::Relaxed),
        ),
        (
            "protocol_failure",
            METRICS
                .session_net_connection_failure_protocol
                .load(Ordering::Relaxed),
        ),
        (
            "backend_failure",
            METRICS
                .session_net_connection_failure_backend
                .load(Ordering::Relaxed),
        ),
    ] {
        out.push_str(&format!(
            "opc_session_net_connection_attempts_total{{outcome=\"{outcome}\"}} {value}\n"
        ));
    }
    out.push_str(
        "# HELP opc_session_net_reconnect_events_total Session replacement connection activity by fixed outcome\n",
    );
    out.push_str("# TYPE opc_session_net_reconnect_events_total counter\n");
    out.push_str(&format!(
        "opc_session_net_reconnect_events_total{{outcome=\"attempt\"}} {}\n",
        METRICS
            .session_net_reconnect_attempts
            .load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "opc_session_net_reconnect_events_total{{outcome=\"failure\"}} {}\n",
        METRICS
            .session_net_reconnect_failures
            .load(Ordering::Relaxed)
    ));
    write_metric(
        &mut out,
        "opc_session_net_watch_slow_consumers_total",
        "counter",
        "Watch streams closed because the bounded caller queue was full",
        METRICS
            .session_net_watch_slow_consumers
            .load(Ordering::Relaxed) as f64,
    );

    // --- NACM / Authz ---
    let nacm_allow = METRICS.nacm_eval_allow.load(Ordering::Relaxed);
    out.push_str("# HELP opc_nacm_eval_total Total count of NACM policy evaluations\n");
    out.push_str("# TYPE opc_nacm_eval_total counter\n");
    out.push_str(&format!(
        "opc_nacm_eval_total{{action=\"allow\"}} {nacm_allow}\n"
    ));
    let nacm_deny = METRICS.nacm_eval_deny.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_nacm_eval_total{{action=\"deny\"}} {nacm_deny}\n"
    ));
    let nacm_error = METRICS.nacm_eval_error.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_nacm_eval_total{{action=\"error\"}} {nacm_error}\n"
    ));

    write_histogram_metadata(
        &mut out,
        "opc_nacm_eval_latency_seconds",
        "Latency of NACM evaluations",
    );
    write_histogram_samples(
        &mut out,
        "opc_nacm_eval_latency_seconds",
        &METRICS.nacm_eval_latency,
        &[],
    );

    let nacm_def_deny = METRICS.nacm_default_deny.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_nacm_default_deny_total",
        "counter",
        "Total count of default-deny occurrences",
        nacm_def_deny as f64,
    );

    // --- Alarm / Runtime ---
    out.push_str("# HELP opc_alarm_active_count Number of active alarms by severity and cause\n");
    out.push_str("# TYPE opc_alarm_active_count gauge\n");
    if let Ok(active_map) = METRICS.alarm_active_count.lock() {
        let mut sorted_alarms: Vec<_> = active_map.iter().collect();
        sorted_alarms.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (key, &val) in sorted_alarms {
            let safe_sev = metrics_label_safe(&key.0);
            let safe_cause = metrics_label_safe(&key.1);
            out.push_str(&format!(
                "opc_alarm_active_count{{severity=\"{safe_sev}\",cause=\"{safe_cause}\"}} {val}\n"
            ));
        }
    }

    let alarm_aud_succ = METRICS.alarm_audit_success.load(Ordering::Relaxed);
    out.push_str("# HELP opc_alarm_audit_total Total count of alarm audits\n");
    out.push_str("# TYPE opc_alarm_audit_total counter\n");
    out.push_str(&format!(
        "opc_alarm_audit_total{{status=\"success\"}} {alarm_aud_succ}\n"
    ));
    let alarm_aud_fail = METRICS.alarm_audit_failure.load(Ordering::Relaxed);
    out.push_str(&format!(
        "opc_alarm_audit_total{{status=\"failure\"}} {alarm_aud_fail}\n"
    ));

    let hl = METRICS.runtime_health_live.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_runtime_health_live",
        "gauge",
        "Process liveness status",
        hl as f64,
    );
    let hr = METRICS.runtime_health_ready.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_runtime_health_ready",
        "gauge",
        "Process readiness status",
        hr as f64,
    );
    let hs = METRICS.runtime_health_startup.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_runtime_health_startup",
        "gauge",
        "Process startup completion status",
        hs as f64,
    );
    let budget_exhausted = METRICS.runtime_budget_exhausted.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_runtime_budget_exhausted_total",
        "counter",
        "Number of runtime resource-budget admission failures",
        budget_exhausted as f64,
    );

    // --- Admin Server ---
    out.push_str(
        "# HELP opc_admin_requests_total Total count of admin HTTP requests by route and status\n",
    );
    out.push_str("# TYPE opc_admin_requests_total counter\n");
    if let Ok(reqs) = METRICS.admin_requests_total.lock() {
        let mut sorted_reqs: Vec<_> = reqs.iter().collect();
        sorted_reqs.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (key, &val) in sorted_reqs {
            let safe_route = metrics_label_safe(&key.0);
            let safe_status = metrics_label_safe(&key.1);
            out.push_str(&format!(
                "opc_admin_requests_total{{route=\"{safe_route}\",status=\"{safe_status}\"}} {val}\n"
            ));
        }
    }

    let auth_fail = METRICS.admin_auth_failures_total.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_admin_auth_failures_total",
        "counter",
        "Total count of admin authentication failures",
        auth_fail as f64,
    );

    let malformed = METRICS
        .admin_malformed_requests_total
        .load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_admin_malformed_requests_total",
        "counter",
        "Total count of malformed admin requests",
        malformed as f64,
    );

    let redaction_events = METRICS.admin_redaction_events_total.load(Ordering::Relaxed);
    write_metric(
        &mut out,
        "opc_admin_redaction_events_total",
        "counter",
        "Total count of admin response redaction events",
        redaction_events as f64,
    );

    write_histogram_metadata(
        &mut out,
        "opc_admin_request_latency_seconds",
        "Latency of admin HTTP requests by route",
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_livez,
        &[("route", "livez")],
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_readyz,
        &[("route", "readyz")],
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_startupz,
        &[("route", "startupz")],
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_metrics,
        &[("route", "metrics")],
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_debug_runtime,
        &[("route", "debug_runtime")],
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_debug_tasks,
        &[("route", "debug_tasks")],
    );
    write_histogram_samples(
        &mut out,
        "opc_admin_request_latency_seconds",
        &METRICS.admin_latency_debug_config_version,
        &[("route", "debug_config_version")],
    );
    if let Ok(map) = METRICS.admin_request_latency_seconds.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (route, hist) in sorted {
            let safe_route = metrics_label_safe(route);
            write_histogram_samples(
                &mut out,
                "opc_admin_request_latency_seconds",
                hist,
                &[("route", &safe_route)],
            );
        }
    }

    // === SBI Metrics ===
    out.push_str("# HELP opc_sbi_requests_total Total count of SBI requests by nf, service, operation, and outcome\n");
    out.push_str("# TYPE opc_sbi_requests_total counter\n");
    if let Ok(map) = METRICS.sbi_requests_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let nf = metrics_label_safe(&k.0);
            let service = metrics_label_safe(&k.1);
            let operation = metrics_label_safe(&k.2);
            let outcome = metrics_label_safe(&k.3);
            out.push_str(&format!(
                "opc_sbi_requests_total{{nf=\"{nf}\",service=\"{service}\",operation=\"{operation}\",outcome=\"{outcome}\"}} {v}\n"
            ));
        }
    }

    write_histogram_metadata(
        &mut out,
        "opc_sbi_request_duration_seconds",
        "SBI request duration in seconds",
    );
    if let Ok(map) = METRICS.sbi_request_duration_seconds.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, hist) in sorted {
            let service = metrics_label_safe(&k.0);
            let operation = metrics_label_safe(&k.1);
            write_histogram_samples(
                &mut out,
                "opc_sbi_request_duration_seconds",
                hist,
                &[("service", &service), ("operation", &operation)],
            );
        }
    }

    out.push_str("# HELP opc_sbi_problem_details_total Total count of ProblemDetails returned by service, cause, and status\n");
    out.push_str("# TYPE opc_sbi_problem_details_total counter\n");
    if let Ok(map) = METRICS.sbi_problem_details_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let service = metrics_label_safe(&k.0);
            let cause = metrics_label_safe(&k.1);
            let status = metrics_label_safe(&k.2);
            out.push_str(&format!(
                "opc_sbi_problem_details_total{{service=\"{service}\",cause=\"{cause}\",status=\"{status}\"}} {v}\n"
            ));
        }
    }

    out.push_str("# HELP opc_sbi_oauth_validation_total Total count of OAuth validation events by outcome and reason\n");
    out.push_str("# TYPE opc_sbi_oauth_validation_total counter\n");
    if let Ok(map) = METRICS.sbi_oauth_validation_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let outcome = metrics_label_safe(&k.0);
            let reason = metrics_label_safe(&k.1);
            out.push_str(&format!(
                "opc_sbi_oauth_validation_total{{outcome=\"{outcome}\",reason=\"{reason}\"}} {v}\n"
            ));
        }
    }

    out.push_str("# HELP opc_sbi_nrf_discovery_total Total count of NRF discoveries by outcome\n");
    out.push_str("# TYPE opc_sbi_nrf_discovery_total counter\n");
    if let Ok(map) = METRICS.sbi_nrf_discovery_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let outcome = metrics_label_safe(k);
            out.push_str(&format!(
                "opc_sbi_nrf_discovery_total{{outcome=\"{outcome}\"}} {v}\n"
            ));
        }
    }

    out.push_str("# HELP opc_sbi_nrf_cache_entries Total count of NRF cache entries by service\n");
    out.push_str("# TYPE opc_sbi_nrf_cache_entries gauge\n");
    if let Ok(map) = METRICS.sbi_nrf_cache_entries.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let service = metrics_label_safe(k);
            out.push_str(&format!(
                "opc_sbi_nrf_cache_entries{{service=\"{service}\"}} {v}\n"
            ));
        }
    }

    out.push_str("# HELP opc_sbi_nrf_heartbeat_total Total count of NRF heartbeats by outcome\n");
    out.push_str("# TYPE opc_sbi_nrf_heartbeat_total counter\n");
    if let Ok(map) = METRICS.sbi_nrf_heartbeat_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let outcome = metrics_label_safe(k);
            out.push_str(&format!(
                "opc_sbi_nrf_heartbeat_total{{outcome=\"{outcome}\"}} {v}\n"
            ));
        }
    }

    out.push_str(
        "# HELP opc_sbi_circuit_state Circuit breaker state events by peer, service, and state\n",
    );
    out.push_str("# TYPE opc_sbi_circuit_state counter\n");
    if let Ok(map) = METRICS.sbi_circuit_state.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let peer = metrics_label_safe(&k.0);
            let service = metrics_label_safe(&k.1);
            let state = metrics_label_safe(&k.2);
            out.push_str(&format!(
                "opc_sbi_circuit_state{{peer=\"{peer}\",service=\"{service}\",state=\"{state}\"}} {v}\n"
            ));
        }
    }

    out.push_str("# HELP opc_sbi_overload_rejections_total Total count of SBI overload rejections by service and reason\n");
    out.push_str("# TYPE opc_sbi_overload_rejections_total counter\n");
    if let Ok(map) = METRICS.sbi_overload_rejections_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let service = metrics_label_safe(&k.0);
            let reason = metrics_label_safe(&k.1);
            out.push_str(&format!(
                "opc_sbi_overload_rejections_total{{service=\"{service}\",reason=\"{reason}\"}} {v}\n"
            ));
        }
    }

    out.push_str("# HELP opc_sbi_callback_delivery_total Total count of callback deliveries by target and outcome\n");
    out.push_str("# TYPE opc_sbi_callback_delivery_total counter\n");
    if let Ok(map) = METRICS.sbi_callback_delivery_total.lock() {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by(|a, b| (&a.0).cmp(&b.0));
        for (k, &v) in sorted {
            let target = metrics_label_safe(&k.0);
            let outcome = metrics_label_safe(&k.1);
            out.push_str(&format!(
                "opc_sbi_callback_delivery_total{{target=\"{target}\",outcome=\"{outcome}\"}} {v}\n"
            ));
        }
    }

    // === gNMI Server ===
    write_labeled_counter_2(
        &mut out,
        "opc_gnmi_rpc_requests_total",
        "Total gNMI RPC requests by RPC and outcome",
        &METRICS.gnmi_rpc_requests_total,
        "rpc",
        "outcome",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_gnmi_rpc_errors_total",
        "Total gNMI RPC errors by RPC and status code",
        &METRICS.gnmi_rpc_errors_total,
        "rpc",
        "code",
    );
    write_labeled_histogram_1(
        &mut out,
        "opc_gnmi_rpc_seconds",
        "gNMI RPC latency in seconds by RPC",
        &METRICS.gnmi_rpc_seconds,
        "rpc",
    );
    write_labeled_histogram_1(
        &mut out,
        "opc_gnmi_set_commit_seconds",
        "gNMI Set commit latency in seconds by operation",
        &METRICS.gnmi_set_commit_seconds,
        "operation",
    );
    write_labeled_gauge_1(
        &mut out,
        "opc_gnmi_active_streams",
        "Active gNMI subscription streams by mode",
        &METRICS.gnmi_active_streams,
        "mode",
    );
    write_labeled_gauge_1(
        &mut out,
        "opc_gnmi_sessions_active",
        "Active gNMI sessions by transport",
        &METRICS.gnmi_sessions_active,
        "transport",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_gnmi_listener_events_total",
        "Total gNMI listener events by transport and event",
        &METRICS.gnmi_listener_events_total,
        "transport",
        "event",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_gnmi_subscription_events_total",
        "Total gNMI subscription events by mode and event",
        &METRICS.gnmi_subscription_events_total,
        "mode",
        "event",
    );
    write_labeled_counter_1(
        &mut out,
        "opc_gnmi_subscription_lag_total",
        "Total gNMI subscription lag events by lag policy",
        &METRICS.gnmi_subscription_lag_total,
        "policy",
    );
    write_labeled_counter_1(
        &mut out,
        "opc_gnmi_nacm_denials_total",
        "Total gNMI NACM denials by action",
        &METRICS.gnmi_nacm_denials_total,
        "action",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_gnmi_extensions_total",
        "Total gNMI extension outcomes by extension and outcome",
        &METRICS.gnmi_extensions_total,
        "extension",
        "outcome",
    );
    write_labeled_counter_1(
        &mut out,
        "opc_gnmi_arbitration_denials_total",
        "Total gNMI arbitration write denials by reason",
        &METRICS.gnmi_arbitration_denials_total,
        "reason",
    );

    // === NETCONF Server ===
    write_labeled_gauge_1(
        &mut out,
        "opc_netconf_sessions_active",
        "Active NETCONF sessions by transport",
        &METRICS.netconf_sessions_active,
        "transport",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_netconf_rpc_requests_total",
        "Total NETCONF RPC requests by operation and outcome",
        &METRICS.netconf_rpc_requests_total,
        "operation",
        "outcome",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_netconf_rpc_errors_total",
        "Total NETCONF RPC errors by operation and error tag",
        &METRICS.netconf_rpc_errors_total,
        "operation",
        "error_tag",
    );
    write_labeled_histogram_1(
        &mut out,
        "opc_netconf_rpc_seconds",
        "NETCONF RPC latency in seconds by operation",
        &METRICS.netconf_rpc_seconds,
        "operation",
    );
    write_labeled_histogram_1(
        &mut out,
        "opc_netconf_commit_seconds",
        "NETCONF commit latency in seconds by target datastore",
        &METRICS.netconf_commit_seconds,
        "target",
    );
    write_labeled_gauge_1(
        &mut out,
        "opc_netconf_locks_active",
        "Active NETCONF datastore locks by datastore",
        &METRICS.netconf_locks_active,
        "datastore",
    );
    write_labeled_counter_2(
        &mut out,
        "opc_netconf_notifications_total",
        "Total NETCONF notifications by stream and outcome",
        &METRICS.netconf_notifications_total,
        "stream",
        "outcome",
    );
    write_labeled_counter_1(
        &mut out,
        "opc_netconf_nacm_denials_total",
        "Total NETCONF NACM denials by action",
        &METRICS.netconf_nacm_denials_total,
        "action",
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_ready(acceptance: SecurityMetricsAcceptance<'_>) {
        match acceptance {
            SecurityMetricsAcceptance::Ready(permit) => permit.commit(),
            other => panic!("expected ready security metrics permit, got {other:?}"),
        }
    }

    #[test]
    fn test_metrics_label_safe_valid() {
        assert_eq!(metrics_label_safe("critical"), "critical");
        assert_eq!(metrics_label_safe("ConfigBootstrap"), "ConfigBootstrap");
        assert_eq!(
            metrics_label_safe("some-metric_value.1"),
            "some-metric_value.1"
        );
        assert_eq!(metrics_label_safe("  spaces_trimmed  "), "spaces_trimmed");
    }

    #[test]
    fn test_metrics_label_safe_redacted() {
        // Paths
        assert_eq!(metrics_label_safe("/etc/hosts"), "redacted");
        assert_eq!(metrics_label_safe("C:\\Windows"), "redacted");

        // SPIFFE
        assert_eq!(metrics_label_safe("spiffe://test/trust-domain"), "redacted");

        // PEM
        assert_eq!(
            metrics_label_safe("-----BEGIN CERTIFICATE-----"),
            "redacted"
        );

        // Emails / Special chars
        assert_eq!(metrics_label_safe("user@host"), "redacted");
        assert_eq!(metrics_label_safe("a=b"), "redacted");

        // Subscriber IDs
        assert_eq!(metrics_label_safe("12345"), "redacted");
        assert_eq!(metrics_label_safe("4567890123"), "redacted");
        assert_eq!(metrics_label_safe("imsi-001010123456789"), "redacted");
        assert_eq!(metrics_label_safe("supi001010123456789"), "redacted");
        assert_eq!(metrics_label_safe("msisdn_15551234567"), "redacted");

        // IP addresses and bearer/JWT-like material
        assert_eq!(metrics_label_safe("10.0.0.1"), "redacted");
        assert_eq!(metrics_label_safe("192.168.10.42"), "redacted");
        assert_eq!(metrics_label_safe("aaa.bbb.ccc"), "redacted");
        assert_eq!(
            metrics_label_safe("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "redacted"
        );

        // Hex / Tx IDs
        assert_eq!(
            metrics_label_safe("aabbccddeeff00112233445566778899"),
            "redacted"
        );

        // UUID
        assert_eq!(
            metrics_label_safe("123e4567-e89b-12d3-a456-426614174000"),
            "redacted"
        );

        // SQL
        assert_eq!(metrics_label_safe("SELECT * FROM users"), "redacted");
        assert_eq!(metrics_label_safe("database is locked"), "redacted");

        // Telco identifiers introduced by this task.
        assert_eq!(metrics_label_safe("li-id-target-42"), "redacted");
        assert_eq!(metrics_label_safe("li_id_target_42"), "redacted");
        assert_eq!(metrics_label_safe("li-warrant-id-war-42"), "redacted");
        assert_eq!(metrics_label_safe("li-correlation-id-corr-42"), "redacted");
        assert_eq!(metrics_label_safe("delivery-address-mdf"), "redacted");
        assert_eq!(metrics_label_safe("apn-internet.operator.com"), "redacted");
        assert_eq!(metrics_label_safe("dnn-internet"), "redacted");
        assert_eq!(metrics_label_safe("dnn_internet"), "redacted");
        assert_eq!(metrics_label_safe("teid-0x12345678"), "redacted");
        assert_eq!(metrics_label_safe("spi-0x9abcdef0"), "redacted");
        assert_eq!(
            metrics_label_safe("diameter-session-id-op.example.com;123;0"),
            "redacted"
        );
    }

    #[test]
    fn test_metric_registration_and_export() {
        METRICS.reset_all();
        let admin = AdminMetricsRecorder::global();
        admin.record_request("/readyz", 200);
        admin.record_request("spiffe://example.org/leak", 999);
        admin.record_auth_failure();
        admin.record_malformed_request();
        admin.record_redaction_event();
        admin.observe_route_latency("/readyz", 0.025);
        admin.observe_route_latency("product_status", 0.01);
        admin.observe_route_latency("product_status", -1.0);
        METRICS
            .config_bus_pending_commits
            .store(3, Ordering::Relaxed);
        METRICS
            .break_glass_sessions_active
            .store(1, Ordering::Relaxed);
        METRICS.config_bus_phase_latency_apply.observe(0.025);
        METRICS.persist_leader_term.store(10, Ordering::Relaxed);
        METRICS.runtime_budget_exhausted.store(2, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_probe_success
            .store(11, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_probe_failure
            .store(12, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_ready
            .store(1, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_configured_voters
            .store(3, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_fresh_reachable_voters
            .store(2, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_agreeing_voters
            .store(2, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_required_quorum
            .store(2, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_majority_visible_prefix
            .store(42, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_timeout_failures
            .store(13, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_authentication_failures
            .store(14, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_transport_failures
            .store(15, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_divergent_failures
            .store(16, Ordering::Relaxed);
        METRICS
            .session_durable_readiness_recovery_required_failures
            .store(17, Ordering::Relaxed);
        METRICS
            .session_net_backend_queue_timeouts
            .store(18, Ordering::Relaxed);
        METRICS
            .session_net_backend_execution_timeouts
            .store(19, Ordering::Relaxed);
        METRICS
            .session_net_backend_cancellations
            .store(20, Ordering::Relaxed);
        METRICS
            .session_net_backend_peer_disconnects
            .store(21, Ordering::Relaxed);
        METRICS
            .session_net_backend_ambiguous_outcomes
            .store(22, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_maximum_age
            .store(23, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_local_leaf_expiry
            .store(24, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_peer_leaf_expiry
            .store(25, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_local_certificate_chain_expiry
            .store(43, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_peer_certificate_chain_expiry
            .store(44, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_material_epoch
            .store(26, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_explicit
            .store(27, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_retirement_idle_timeout
            .store(45, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_active_connections
            .store(28, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_draining_connections
            .store(29, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_drain_started
            .store(30, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_drain_completed
            .store(31, Ordering::Relaxed);
        METRICS
            .session_net_lifecycle_drain_overruns
            .store(32, Ordering::Relaxed);
        METRICS
            .session_net_connection_attempts
            .store(33, Ordering::Relaxed);
        METRICS
            .session_net_connection_successes
            .store(34, Ordering::Relaxed);
        METRICS
            .session_net_connection_failure_transport
            .store(35, Ordering::Relaxed);
        METRICS
            .session_net_connection_failure_authentication
            .store(36, Ordering::Relaxed);
        METRICS
            .session_net_connection_failure_timeout
            .store(37, Ordering::Relaxed);
        METRICS
            .session_net_connection_failure_protocol
            .store(38, Ordering::Relaxed);
        METRICS
            .session_net_connection_failure_backend
            .store(39, Ordering::Relaxed);
        METRICS
            .session_net_reconnect_attempts
            .store(40, Ordering::Relaxed);
        METRICS
            .session_net_reconnect_failures
            .store(41, Ordering::Relaxed);
        METRICS
            .session_net_watch_slow_consumers
            .store(42, Ordering::Relaxed);

        if let Ok(mut lag) = METRICS.persist_peer_replication_lag.lock() {
            lag.insert(1, 42);
        }

        if let Ok(mut alarms) = METRICS.alarm_active_count.lock() {
            alarms.insert(("critical".to_string(), "cpu_high".to_string()), 1);
            // Sensitive alarm details that should be redacted
            alarms.insert(("warning".to_string(), "spiffe://test/leak".to_string()), 2);
        }

        // --- Management-plane (gNMI / NETCONF) families ---
        if let Ok(mut m) = METRICS.gnmi_rpc_requests_total.lock() {
            m.insert(("Get".to_string(), "ok".to_string()), 5);
        }
        if let Ok(mut m) = METRICS.gnmi_active_streams.lock() {
            m.insert("stream".to_string(), 2);
        }
        if let Ok(mut m) = METRICS.gnmi_sessions_active.lock() {
            m.insert("gnmi-tls".to_string(), 1);
        }
        if let Ok(mut m) = METRICS.gnmi_listener_events_total.lock() {
            m.insert(("gnmi-tls".to_string(), "start".to_string()), 1);
            m.insert(("spiffe://test/leak".to_string(), "failure".to_string()), 7);
        }
        if let Ok(mut m) = METRICS.gnmi_nacm_denials_total.lock() {
            m.insert("read".to_string(), 1);
            // A path-shaped label value must be sanitized, not leaked, in export.
            m.insert("/secret/path".to_string(), 9);
        }
        if let Ok(mut m) = METRICS.gnmi_rpc_seconds.lock() {
            let hist = LatencyHistogram::new();
            hist.observe(0.025);
            m.insert("Set".to_string(), hist);
        }
        if let Ok(mut m) = METRICS.netconf_sessions_active.lock() {
            m.insert("netconf-tls".to_string(), 3);
        }
        if let Ok(mut m) = METRICS.netconf_rpc_errors_total.lock() {
            m.insert(("edit-config".to_string(), "access-denied".to_string()), 4);
        }

        let exported = export_prometheus_text();
        assert!(exported.contains("opc_config_bus_pending_commits 3\n"));
        assert!(exported.contains("opc_break_glass_sessions_active 1\n"));
        assert!(exported.contains(
            "opc_config_bus_phase_latency_seconds_bucket{phase=\"apply\",le=\"0.025\"} 1\n"
        ));
        assert!(exported.contains("opc_config_bus_phase_latency_seconds_sum{phase=\"apply\"} "));
        assert!(exported.contains("opc_nacm_eval_latency_seconds_count 0\n"));
        assert!(!exported.contains("{ }"));
        assert!(exported.contains("opc_persist_leader_term 10\n"));
        assert!(exported.contains("opc_runtime_budget_exhausted_total 2\n"));
        assert!(exported
            .contains("opc_session_store_durable_readiness_probe_total{status=\"success\"} 11\n"));
        assert!(exported
            .contains("opc_session_store_durable_readiness_probe_total{status=\"failure\"} 12\n"));
        assert!(exported.contains("opc_session_store_durable_readiness_ready 1\n"));
        assert!(exported.contains("opc_session_store_durable_readiness_configured_voters 3\n"));
        assert!(exported.contains("opc_session_store_durable_readiness_fresh_reachable_voters 2\n"));
        assert!(exported.contains("opc_session_store_durable_readiness_agreeing_voters 2\n"));
        assert!(exported.contains("opc_session_store_durable_readiness_required_quorum 2\n"));
        assert!(exported.contains(
            "# HELP opc_session_store_durable_readiness_majority_visible_prefix Openraft committed barrier index from the latest ready probe (compatibility metric name)\n"
        ));
        assert!(
            exported.contains("opc_session_store_durable_readiness_majority_visible_prefix 42\n")
        );
        assert!(exported.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"timeout\"} 13\n"
        ));
        assert!(exported.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"authentication\"} 14\n"
        ));
        assert!(exported.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"transport\"} 15\n"
        ));
        assert!(exported.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"divergent\"} 16\n"
        ));
        assert!(exported.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"recovery_required\"} 17\n"
        ));
        assert!(exported.contains(
            "opc_session_net_backend_lifetime_events_total{event=\"queue_timeout\"} 18\n"
        ));
        assert!(exported.contains(
            "opc_session_net_backend_lifetime_events_total{event=\"execution_timeout\"} 19\n"
        ));
        assert!(exported.contains(
            "opc_session_net_backend_lifetime_events_total{event=\"cancellation\"} 20\n"
        ));
        assert!(exported.contains(
            "opc_session_net_backend_lifetime_events_total{event=\"peer_disconnect\"} 21\n"
        ));
        assert!(exported.contains(
            "opc_session_net_backend_lifetime_events_total{event=\"ambiguous_outcome\"} 22\n"
        ));
        assert!(exported
            .contains("opc_session_net_connection_retirements_total{reason=\"maximum_age\"} 23\n"));
        assert!(exported.contains(
            "opc_session_net_connection_retirements_total{reason=\"local_leaf_expiry\"} 24\n"
        ));
        assert!(exported.contains(
            "opc_session_net_connection_retirements_total{reason=\"peer_leaf_expiry\"} 25\n"
        ));
        assert!(exported.contains(
            "opc_session_net_connection_retirements_total{reason=\"local_certificate_chain_expiry\"} 43\n"
        ));
        assert!(exported.contains(
            "opc_session_net_connection_retirements_total{reason=\"peer_certificate_chain_expiry\"} 44\n"
        ));
        assert!(exported.contains(
            "opc_session_net_connection_retirements_total{reason=\"material_epoch\"} 26\n"
        ));
        assert!(exported
            .contains("opc_session_net_connection_retirements_total{reason=\"explicit\"} 27\n"));
        assert!(exported.contains(
            "opc_session_net_connection_retirements_total{reason=\"idle_timeout\"} 45\n"
        ));
        assert!(exported.contains("opc_session_net_connection_lifecycle{state=\"active\"} 28\n"));
        assert!(exported.contains("opc_session_net_connection_lifecycle{state=\"draining\"} 29\n"));
        assert!(exported
            .contains("opc_session_net_connection_drain_events_total{event=\"started\"} 30\n"));
        assert!(exported
            .contains("opc_session_net_connection_drain_events_total{event=\"completed\"} 31\n"));
        assert!(exported
            .contains("opc_session_net_connection_drain_events_total{event=\"overrun\"} 32\n"));
        assert!(exported
            .contains("opc_session_net_connection_attempts_total{outcome=\"started\"} 33\n"));
        assert!(exported
            .contains("opc_session_net_connection_attempts_total{outcome=\"success\"} 34\n"));
        assert!(exported.contains(
            "opc_session_net_connection_attempts_total{outcome=\"transport_failure\"} 35\n"
        ));
        assert!(exported.contains(
            "opc_session_net_connection_attempts_total{outcome=\"authentication_or_trust_failure\"} 36\n"
        ));
        assert!(exported
            .contains("opc_session_net_connection_attempts_total{outcome=\"timeout\"} 37\n"));
        assert!(exported.contains(
            "opc_session_net_connection_attempts_total{outcome=\"protocol_failure\"} 38\n"
        ));
        assert!(exported.contains(
            "opc_session_net_connection_attempts_total{outcome=\"backend_failure\"} 39\n"
        ));
        assert!(
            exported.contains("opc_session_net_reconnect_events_total{outcome=\"attempt\"} 40\n")
        );
        assert!(
            exported.contains("opc_session_net_reconnect_events_total{outcome=\"failure\"} 41\n")
        );
        assert!(exported.contains("opc_session_net_watch_slow_consumers_total 42\n"));
        assert!(exported.contains("opc_admin_requests_total{route=\"readyz\",status=\"200\"} 1\n"));
        assert!(exported
            .contains("opc_admin_requests_total{route=\"redacted\",status=\"invalid\"} 1\n"));
        assert!(exported.contains("opc_admin_auth_failures_total 1\n"));
        assert!(exported.contains("opc_admin_malformed_requests_total 1\n"));
        assert!(exported.contains("opc_admin_redaction_events_total 1\n"));
        assert!(exported.contains(
            "opc_admin_request_latency_seconds_bucket{route=\"readyz\",le=\"0.025\"} 1\n"
        ));
        assert!(exported
            .contains("opc_admin_request_latency_seconds_count{route=\"product_status\"} 1\n"));
        assert!(exported.contains("opc_persist_peer_replication_lag{peer=\"1\"} 42\n"));
        assert!(exported
            .contains("opc_alarm_active_count{severity=\"critical\",cause=\"cpu_high\"} 1\n"));
        assert!(exported
            .contains("opc_alarm_active_count{severity=\"warning\",cause=\"redacted\"} 2\n"));

        // Management-plane families export with sanitized labels.
        assert!(exported.contains("opc_gnmi_rpc_requests_total{rpc=\"Get\",outcome=\"ok\"} 5\n"));
        assert!(exported.contains("opc_gnmi_active_streams{mode=\"stream\"} 2\n"));
        assert!(exported.contains("opc_gnmi_sessions_active{transport=\"gnmi-tls\"} 1\n"));
        assert!(exported.contains(
            "opc_gnmi_listener_events_total{transport=\"gnmi-tls\",event=\"start\"} 1\n"
        ));
        assert!(exported.contains(
            "opc_gnmi_listener_events_total{transport=\"redacted\",event=\"failure\"} 7\n"
        ));
        assert!(exported.contains("opc_gnmi_nacm_denials_total{action=\"read\"} 1\n"));
        // Path-shaped label value must be redacted, never leaked verbatim.
        assert!(exported.contains("opc_gnmi_nacm_denials_total{action=\"redacted\"} 9\n"));
        assert!(!exported.contains("/secret/path"));
        assert!(exported.contains("# TYPE opc_gnmi_rpc_seconds histogram\n"));
        assert!(exported.contains("opc_gnmi_rpc_seconds_bucket{rpc=\"Set\",le=\"0.025\"} 1\n"));
        // Histogram families with no observations still emit TYPE metadata.
        assert!(exported.contains("# TYPE opc_gnmi_set_commit_seconds histogram\n"));
        assert!(exported.contains("opc_netconf_sessions_active{transport=\"netconf-tls\"} 3\n"));
        assert!(exported.contains(
            "opc_netconf_rpc_errors_total{operation=\"edit-config\",error_tag=\"access-denied\"} 4\n"
        ));

        // reset_all clears the management-plane families too.
        METRICS.reset_all();
        let after = export_prometheus_text();
        assert!(!after.contains("opc_gnmi_rpc_requests_total{rpc=\"Get\""));
        assert!(!after.contains("opc_gnmi_sessions_active{transport=\"gnmi-tls\""));
        assert!(!after.contains("opc_gnmi_listener_events_total{transport=\"gnmi-tls\""));
        assert!(!after.contains("opc_netconf_sessions_active{transport=\"netconf-tls\""));
        assert!(!after.contains("opc_admin_requests_total{route=\"readyz\""));
        assert!(!after.contains("opc_admin_request_latency_seconds_count{route=\"product_status\""));
        assert!(after
            .contains("opc_session_store_durable_readiness_probe_total{status=\"success\"} 0\n"));
        assert!(after.contains("opc_session_store_durable_readiness_ready 0\n"));
        assert!(after.contains("opc_session_store_durable_readiness_configured_voters 0\n"));
        assert!(after.contains("opc_session_store_durable_readiness_fresh_reachable_voters 0\n"));
        assert!(after.contains("opc_session_store_durable_readiness_agreeing_voters 0\n"));
        assert!(after.contains("opc_session_store_durable_readiness_required_quorum 0\n"));
        assert!(after.contains("opc_session_store_durable_readiness_majority_visible_prefix 0\n"));
        assert!(after.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"divergent\"} 0\n"
        ));
        assert!(after.contains(
            "opc_session_store_durable_readiness_failures_total{reason=\"recovery_required\"} 0\n"
        ));
        assert!(after.contains(
            "opc_session_net_backend_lifetime_events_total{event=\"ambiguous_outcome\"} 0\n"
        ));
        assert!(after.contains(
            "opc_session_net_connection_retirements_total{reason=\"material_epoch\"} 0\n"
        ));
        assert!(after
            .contains("opc_session_net_connection_retirements_total{reason=\"idle_timeout\"} 0\n"));
        assert!(after.contains("opc_session_net_connection_lifecycle{state=\"active\"} 0\n"));
        assert!(
            after.contains("opc_session_net_connection_drain_events_total{event=\"overrun\"} 0\n")
        );
        assert!(after.contains(
            "opc_session_net_connection_attempts_total{outcome=\"authentication_or_trust_failure\"} 0\n"
        ));
        assert!(after.contains("opc_session_net_reconnect_events_total{outcome=\"failure\"} 0\n"));
        assert!(after.contains("opc_session_net_watch_slow_consumers_total 0\n"));
    }

    #[test]
    fn session_net_lifecycle_metrics_initialize_and_reset() {
        let metrics = SdkMetrics::new();
        let counters = [
            &metrics.session_net_lifecycle_retirement_maximum_age,
            &metrics.session_net_lifecycle_retirement_local_leaf_expiry,
            &metrics.session_net_lifecycle_retirement_peer_leaf_expiry,
            &metrics.session_net_lifecycle_retirement_local_certificate_chain_expiry,
            &metrics.session_net_lifecycle_retirement_peer_certificate_chain_expiry,
            &metrics.session_net_lifecycle_retirement_material_epoch,
            &metrics.session_net_lifecycle_retirement_explicit,
            &metrics.session_net_lifecycle_retirement_idle_timeout,
            &metrics.session_net_lifecycle_drain_started,
            &metrics.session_net_lifecycle_drain_completed,
            &metrics.session_net_lifecycle_drain_overruns,
            &metrics.session_net_connection_attempts,
            &metrics.session_net_connection_successes,
            &metrics.session_net_connection_failure_transport,
            &metrics.session_net_connection_failure_authentication,
            &metrics.session_net_connection_failure_timeout,
            &metrics.session_net_connection_failure_protocol,
            &metrics.session_net_connection_failure_backend,
            &metrics.session_net_reconnect_attempts,
            &metrics.session_net_reconnect_failures,
            &metrics.session_net_watch_slow_consumers,
        ];
        let gauges = [
            &metrics.session_net_lifecycle_active_connections,
            &metrics.session_net_lifecycle_draining_connections,
        ];

        assert!(counters
            .iter()
            .all(|metric| metric.load(Ordering::Relaxed) == 0));
        assert!(gauges
            .iter()
            .all(|metric| metric.load(Ordering::Relaxed) == 0));

        for metric in counters {
            metric.store(1, Ordering::Relaxed);
        }
        for metric in gauges {
            metric.store(1, Ordering::Relaxed);
        }
        metrics.reset_all();

        let reset_counters = [
            &metrics.session_net_lifecycle_retirement_maximum_age,
            &metrics.session_net_lifecycle_retirement_local_leaf_expiry,
            &metrics.session_net_lifecycle_retirement_peer_leaf_expiry,
            &metrics.session_net_lifecycle_retirement_local_certificate_chain_expiry,
            &metrics.session_net_lifecycle_retirement_peer_certificate_chain_expiry,
            &metrics.session_net_lifecycle_retirement_material_epoch,
            &metrics.session_net_lifecycle_retirement_explicit,
            &metrics.session_net_lifecycle_retirement_idle_timeout,
            &metrics.session_net_lifecycle_drain_started,
            &metrics.session_net_lifecycle_drain_completed,
            &metrics.session_net_lifecycle_drain_overruns,
            &metrics.session_net_connection_attempts,
            &metrics.session_net_connection_successes,
            &metrics.session_net_connection_failure_transport,
            &metrics.session_net_connection_failure_authentication,
            &metrics.session_net_connection_failure_timeout,
            &metrics.session_net_connection_failure_protocol,
            &metrics.session_net_connection_failure_backend,
            &metrics.session_net_reconnect_attempts,
            &metrics.session_net_reconnect_failures,
            &metrics.session_net_watch_slow_consumers,
        ];
        let reset_gauges = [
            &metrics.session_net_lifecycle_active_connections,
            &metrics.session_net_lifecycle_draining_connections,
        ];
        assert!(reset_counters
            .iter()
            .all(|metric| metric.load(Ordering::Relaxed) == 0));
        assert!(reset_gauges
            .iter()
            .all(|metric| metric.load(Ordering::Relaxed) == 0));
    }

    #[test]
    fn durable_readiness_metrics_initialize_and_reset() {
        let metrics = SdkMetrics::new();
        let counters_and_gauges = [
            &metrics.session_durable_readiness_probe_success,
            &metrics.session_durable_readiness_probe_failure,
            &metrics.session_durable_readiness_configured_voters,
            &metrics.session_durable_readiness_fresh_reachable_voters,
            &metrics.session_durable_readiness_agreeing_voters,
            &metrics.session_durable_readiness_required_quorum,
            &metrics.session_durable_readiness_majority_visible_prefix,
            &metrics.session_durable_readiness_timeout_failures,
            &metrics.session_durable_readiness_authentication_failures,
            &metrics.session_durable_readiness_transport_failures,
            &metrics.session_durable_readiness_divergent_failures,
            &metrics.session_durable_readiness_recovery_required_failures,
        ];

        assert!(counters_and_gauges
            .iter()
            .all(|metric| metric.load(Ordering::Relaxed) == 0));
        assert_eq!(
            metrics
                .session_durable_readiness_ready
                .load(Ordering::Relaxed),
            0
        );

        for metric in counters_and_gauges {
            metric.store(1, Ordering::Relaxed);
        }
        metrics
            .session_durable_readiness_ready
            .store(1, Ordering::Relaxed);

        metrics.reset_all();

        let reset_counters_and_gauges = [
            &metrics.session_durable_readiness_probe_success,
            &metrics.session_durable_readiness_probe_failure,
            &metrics.session_durable_readiness_configured_voters,
            &metrics.session_durable_readiness_fresh_reachable_voters,
            &metrics.session_durable_readiness_agreeing_voters,
            &metrics.session_durable_readiness_required_quorum,
            &metrics.session_durable_readiness_majority_visible_prefix,
            &metrics.session_durable_readiness_timeout_failures,
            &metrics.session_durable_readiness_authentication_failures,
            &metrics.session_durable_readiness_transport_failures,
            &metrics.session_durable_readiness_divergent_failures,
            &metrics.session_durable_readiness_recovery_required_failures,
        ];
        assert!(reset_counters_and_gauges
            .iter()
            .all(|metric| metric.load(Ordering::Relaxed) == 0));
        assert_eq!(
            metrics
                .session_durable_readiness_ready
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn security_metrics_export_has_only_the_fixed_rotation_series() {
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let publication = source.new_publication();
        commit_ready(controller.prepare_success_if_active(&publication, u64::MAX, 1_900_000_000));
        source.record_retained_last_good(SecurityRotationKind::Svid);
        controller.record_rejected(SecurityRotationKind::TrustBundle, u64::MAX);
        assert!(controller.record_expired_once(&publication));

        let mut exported = String::new();
        write_security_metrics(&mut exported, &reader);
        assert!(exported.contains("opc_security_svid_expires_seconds 0\n"));
        assert!(exported.contains(&format!("opc_security_bundle_version {}\n", u64::MAX)));
        assert!(exported.contains(
            "opc_security_rotation_total{kind=\"tls_material\",outcome=\"success\"} 1\n"
        ));
        assert!(exported.contains(
            "opc_security_rotation_total{kind=\"svid\",outcome=\"retained_last_good\"} 1\n"
        ));
        assert!(exported.contains(
            "opc_security_rotation_total{kind=\"trust_bundle\",outcome=\"rejected\"} 1\n"
        ));
        assert!(
            exported.contains("opc_security_rotation_total{kind=\"svid\",outcome=\"expired\"} 1\n")
        );

        let rotation_rows = exported
            .lines()
            .filter(|line| line.starts_with("opc_security_rotation_total{"))
            .collect::<Vec<_>>();
        assert_eq!(rotation_rows.len(), SECURITY_ROTATION_SERIES_COUNT);
        assert!(rotation_rows.iter().all(|row| {
            SecurityRotationKind::ALL
                .iter()
                .any(|kind| row.contains(&format!("kind=\"{}\"", kind.as_str())))
                && SecurityRotationOutcome::ALL
                    .iter()
                    .any(|outcome| row.contains(&format!("outcome=\"{}\"", outcome.as_str())))
        }));
        let saturation_rows = exported
            .lines()
            .filter(|line| line.starts_with("opc_security_rotation_saturated{"))
            .collect::<Vec<_>>();
        assert_eq!(saturation_rows.len(), SECURITY_ROTATION_SERIES_COUNT);
        assert!(saturation_rows.iter().all(|row| row.ends_with(" 0")));
        assert!(!exported.contains("spiffe://"));
        assert!(!exported.contains("BEGIN"));
        assert!(!exported.contains("/var/run"));
    }

    #[test]
    fn security_rotation_counters_signal_saturation_without_wrapping() {
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, _controller) = authority.split();
        let kind = SecurityRotationKind::Svid;
        let outcome = SecurityRotationOutcome::Rejected;
        let index = rotation_index(kind, outcome);
        reader.state.rotation[index].store(u64::MAX - 1, Ordering::Relaxed);

        source.record_rejected_count(kind, 2);
        source.record_rejected_count(kind, 1);

        let snapshot = reader.snapshot();
        assert_eq!(snapshot.rotation(kind, outcome), u64::MAX);
        assert!(snapshot.rotation_saturated(kind, outcome));
        assert_eq!(snapshot.saturated_series(), 1);
        assert_eq!(snapshot.svid_expires_seconds(), 0);
        assert_eq!(snapshot.bundle_version(), 0);

        let mut exported = String::new();
        write_security_metrics(&mut exported, &reader);
        assert!(exported
            .contains("opc_security_rotation_saturated{kind=\"svid\",outcome=\"rejected\"} 1\n"));
    }

    #[test]
    fn security_export_uses_read_only_global_or_isolated_registry() {
        let (authority, injected) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let publication = source.new_publication();
        commit_ready(controller.prepare_success_if_active(&publication, u64::MAX, 1_900_000_000));
        for _ in 0..64 {
            source.record_retained_last_good(SecurityRotationKind::Svid);
        }
        let mut injected_export = String::new();
        write_security_metrics(&mut injected_export, &injected);
        assert!(injected_export.contains(&format!("opc_security_bundle_version {}\n", u64::MAX)));
        assert!(injected_export.contains(
            "opc_security_rotation_total{kind=\"svid\",outcome=\"retained_last_good\"} 64\n"
        ));

        let global = SecurityMetricsReader::global();
        assert!(Arc::ptr_eq(&global.state, &SECURITY_METRICS));
        assert!(!injected.shares_registry(&global));
        let global_export = export_prometheus_text();
        assert!(global_export.contains("# TYPE opc_security_bundle_version gauge\n"));
    }

    #[test]
    fn sdk_metrics_reset_cannot_erase_security_evidence() {
        let metrics = SdkMetrics::new();
        let authority =
            claim_security_metrics_authority(&AtomicBool::new(false), SECURITY_METRICS.clone())
                .expect("test-only process-registry authority");
        let reader = SecurityMetricsReader::global();
        let (source, controller) = authority.split();
        let publication = source.new_publication();
        commit_ready(controller.prepare_success_if_active(&publication, 9, 1_900_000_000));
        source.record_rejected_count(SecurityRotationKind::TrustBundle, 3);
        let before = reader.snapshot();

        metrics.reset_all();
        assert_eq!(reader.snapshot(), before);
    }

    #[test]
    fn security_authority_claim_is_one_shot() {
        let claimed = AtomicBool::new(false);
        let state = Arc::new(SecurityMetricsState::default());
        assert!(claim_security_metrics_authority(&claimed, state.clone()).is_ok());
        assert!(matches!(
            claim_security_metrics_authority(&claimed, state),
            Err(SecurityMetricsAuthorityClaimError::AlreadyClaimed)
        ));
    }

    #[test]
    fn publication_expiry_is_exact_once_across_source_and_controller() {
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let publication = source.new_publication();
        commit_ready(controller.prepare_success_if_active(&publication, 17, 1_900_000_000));

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let source = source.clone();
                let publication = publication.clone();
                scope.spawn(move || {
                    source.record_expired_once(&publication);
                });
            }
            scope.spawn(|| {
                controller.record_expired_once(&publication);
            });
        });

        let snapshot = reader.snapshot();
        assert_eq!(
            snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired),
            1
        );
        assert_eq!(snapshot.bundle_version(), 17);
        assert_eq!(snapshot.svid_expires_seconds(), 0);

        let next = source.new_publication();
        assert!(source.record_expired_once(&next));
        assert!(matches!(
            controller.prepare_success_if_active(&next, 18, 1_900_000_100),
            SecurityMetricsAcceptance::Expired
        ));
        let snapshot = reader.snapshot();
        assert_eq!(
            snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired),
            2
        );
        assert_eq!(snapshot.bundle_version(), 17);
        assert_eq!(snapshot.svid_expires_seconds(), 0);
    }

    #[test]
    fn expired_unaccepted_publication_preserves_active_gauges_at_exact_boundary() {
        const NOW: i64 = 1_000;
        const ACTIVE_EXPIRY: i64 = NOW + 100;
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let active = source.new_publication();
        commit_ready(controller.prepare_success_if_active_with_clock(
            &active,
            41,
            ACTIVE_EXPIRY,
            || NOW,
        ));

        let expired_candidate = source.new_publication();
        assert!(matches!(
            controller.prepare_success_if_active_with_clock(&expired_candidate, 42, NOW, || NOW,),
            SecurityMetricsAcceptance::Expired
        ));
        assert!(!source.record_expired_once(&expired_candidate));

        let snapshot = reader.snapshot();
        assert_eq!(snapshot.bundle_version(), 41);
        assert_eq!(snapshot.svid_expires_seconds(), ACTIVE_EXPIRY);
        assert_eq!(
            snapshot.rotation(
                SecurityRotationKind::TlsMaterial,
                SecurityRotationOutcome::Success,
            ),
            1
        );
        assert_eq!(
            snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired),
            1
        );
    }

    #[test]
    fn superseded_publication_expiry_cannot_clear_the_new_active_gauges() {
        const NOW: i64 = 1_000;
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let first = source.new_publication();
        let second = source.new_publication();
        commit_ready(controller.prepare_success_if_active_with_clock(
            &first,
            71,
            NOW + 100,
            || NOW,
        ));
        commit_ready(controller.prepare_success_if_active_with_clock(
            &second,
            72,
            NOW + 200,
            || NOW,
        ));

        assert!(source.record_expired_once(&first));
        let after_superseded_expiry = reader.snapshot();
        assert_eq!(after_superseded_expiry.bundle_version(), 72);
        assert_eq!(after_superseded_expiry.svid_expires_seconds(), NOW + 200);

        assert!(controller.record_expired_once(&second));
        let after_active_expiry = reader.snapshot();
        assert_eq!(after_active_expiry.bundle_version(), 72);
        assert_eq!(after_active_expiry.svid_expires_seconds(), 0);
        assert_eq!(
            after_active_expiry
                .rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired,),
            2
        );
    }

    #[test]
    fn abandoned_acceptance_permit_is_retryable_and_releases_followup_transitions() {
        const NOW: i64 = 1_000;
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let publication = source.new_publication();

        let abandoned =
            controller.prepare_success_if_active_with_clock(&publication, 91, NOW + 100, || NOW);
        let SecurityMetricsAcceptance::Ready(abandoned) = abandoned else {
            panic!("first acceptance must be ready");
        };
        drop(abandoned);
        assert_eq!(reader.snapshot().bundle_version(), 0);
        assert_eq!(reader.snapshot().svid_expires_seconds(), 0);

        commit_ready(controller.prepare_success_if_active_with_clock(
            &publication,
            91,
            NOW + 100,
            || NOW,
        ));
        assert!(source.record_expired_once(&publication));
        controller.record_rejected(SecurityRotationKind::TlsMaterial, 92);

        let snapshot = reader.snapshot();
        assert_eq!(snapshot.bundle_version(), 92);
        assert_eq!(snapshot.svid_expires_seconds(), 0);
        assert_eq!(
            snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired),
            1
        );
        assert_eq!(
            snapshot.rotation(
                SecurityRotationKind::TlsMaterial,
                SecurityRotationOutcome::Rejected,
            ),
            1
        );
    }

    #[test]
    fn acceptance_expiry_and_rejection_race_keeps_marker_and_gauges_consistent() {
        const NOW: i64 = 1_000;
        let (authority, reader) = SecurityMetricsAuthority::isolated();
        let (source, controller) = authority.split();
        let publication = source.new_publication();
        let acceptance =
            controller.prepare_success_if_active_with_clock(&publication, 101, NOW + 100, || NOW);
        let SecurityMetricsAcceptance::Ready(permit) = acceptance else {
            panic!("acceptance race permit must be ready");
        };
        let barrier = std::sync::Barrier::new(3);

        std::thread::scope(|scope| {
            let source = source.clone();
            let source_publication = publication.clone();
            let source_barrier = &barrier;
            scope.spawn(move || {
                source_barrier.wait();
                source.record_expired_once(&source_publication)
            });
            let rejection_barrier = &barrier;
            scope.spawn(|| {
                rejection_barrier.wait();
                controller.record_rejected(SecurityRotationKind::TrustBundle, 102);
            });
            barrier.wait();
            permit.commit();
        });

        let active_publication = lock_or_recover(&reader.state.active_publication);
        let snapshot = reader.snapshot();
        assert!(active_publication.is_none());
        assert_eq!(snapshot.bundle_version(), 102);
        assert_eq!(snapshot.svid_expires_seconds(), 0);
        assert_eq!(
            snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired),
            1
        );
        assert_eq!(
            snapshot.rotation(
                SecurityRotationKind::TlsMaterial,
                SecurityRotationOutcome::Success,
            ),
            1
        );
        assert_eq!(
            snapshot.rotation(
                SecurityRotationKind::TrustBundle,
                SecurityRotationOutcome::Rejected,
            ),
            1
        );
    }

    #[test]
    fn admin_metrics_recorder_sanitizes_without_exporter_dependency() {
        let metrics = SdkMetrics::new();
        let recorder = AdminMetricsRecorder::new(&metrics);

        recorder.record_request("/debug/config-version", 200);
        recorder.record_request("imsi-001010123456789", 42);
        recorder.record_malformed_request();
        recorder.record_auth_failure();
        recorder.record_redaction_event();
        recorder.observe_route_latency("/debug/drain", 0.01);
        recorder.observe_route_latency("custom-route", f64::NAN);

        let reqs = metrics.admin_requests_total.lock().unwrap();
        assert_eq!(
            reqs.get(&("debug_config_version".to_string(), "200".to_string())),
            Some(&1)
        );
        assert_eq!(
            reqs.get(&("redacted".to_string(), "invalid".to_string())),
            Some(&1)
        );
        drop(reqs);

        assert_eq!(
            metrics
                .admin_malformed_requests_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.admin_auth_failures_total.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.admin_redaction_events_total.load(Ordering::Relaxed),
            1
        );

        let dynamic_latency = metrics.admin_request_latency_seconds.lock().unwrap();
        let debug_drain = dynamic_latency
            .get("debug_drain")
            .expect("debug drain latency");
        assert_eq!(debug_drain.count.load(Ordering::Relaxed), 1);
        assert!(!dynamic_latency.contains_key("custom-route"));

        let debug = format!("{recorder:?}");
        assert!(!debug.contains("imsi"));
        assert!(!debug.contains("debug_config_version"));
    }

    #[test]
    fn admin_metrics_recorder_caps_dynamic_route_labels() {
        let metrics = SdkMetrics::new();
        let recorder = AdminMetricsRecorder::new(&metrics);

        for i in 0..(MAX_DYNAMIC_ADMIN_ROUTE_LABELS + 8) {
            let route = format!("tenant-route-{i}");
            recorder.record_request(&route, 200);
            recorder.observe_route_latency(&route, 0.01);
        }

        let reqs = metrics.admin_requests_total.lock().unwrap();
        let dynamic_request_routes: std::collections::HashSet<_> = reqs
            .keys()
            .map(|(route, _status)| route.as_str())
            .filter(|route| !is_known_admin_route_label(route) && *route != DYNAMIC_ROUTE_OVERFLOW)
            .collect();
        assert_eq!(dynamic_request_routes.len(), MAX_DYNAMIC_ADMIN_ROUTE_LABELS);
        assert_eq!(
            reqs.get(&(DYNAMIC_ROUTE_OVERFLOW.to_string(), "200".to_string())),
            Some(&8)
        );
        drop(reqs);

        let latencies = metrics.admin_request_latency_seconds.lock().unwrap();
        let dynamic_latency_routes: std::collections::HashSet<_> = latencies
            .keys()
            .map(String::as_str)
            .filter(|route| !is_known_admin_route_label(route) && *route != DYNAMIC_ROUTE_OVERFLOW)
            .collect();
        assert_eq!(dynamic_latency_routes.len(), MAX_DYNAMIC_ADMIN_ROUTE_LABELS);
        assert_eq!(
            latencies
                .get(DYNAMIC_ROUTE_OVERFLOW)
                .expect("overflow latency bucket")
                .count
                .load(Ordering::Relaxed),
            8
        );
    }
}
