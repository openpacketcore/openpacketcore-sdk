//! Health model and probe endpoints per RFC 008 section 11.

use serde::ser::SerializeMap;
use std::collections::BTreeMap;

// =============================================================================
// ENUM DEFINITIONS
// =============================================================================

/// Readiness state for `/readyz` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Readiness {
    /// CNF is not ready to serve traffic.
    #[default]
    NotReady,
    /// CNF is ready but operating with reduced capacity.
    Degraded,
    /// CNF is fully ready.
    Ready,
    /// CNF is draining (shutdown in progress).
    Draining,
}

impl Readiness {
    /// Returns true if the CNF can serve traffic.
    pub fn can_serve(&self) -> bool {
        matches!(self, Readiness::Ready | Readiness::Degraded)
    }

    /// Returns the Kubernetes-ready condition value.
    pub fn as_k8s_condition(&self) -> &'static str {
        match self {
            Readiness::NotReady => "False",
            Readiness::Degraded => "True",
            Readiness::Ready => "True",
            Readiness::Draining => "False",
        }
    }

    /// Returns the reason string for Kubernetes conditions.
    pub fn as_k8s_reason(&self) -> &'static str {
        match self {
            Readiness::NotReady => "StartupIncomplete",
            Readiness::Degraded => "Degraded",
            Readiness::Ready => "Ready",
            Readiness::Draining => "Draining",
        }
    }
}

impl std::fmt::Display for Readiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Readiness::NotReady => write!(f, "NotReady"),
            Readiness::Degraded => write!(f, "Degraded"),
            Readiness::Ready => write!(f, "Ready"),
            Readiness::Draining => write!(f, "Draining"),
        }
    }
}

/// Startup phase for `/startupz` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartupPhase {
    /// Startup has not begun.
    #[default]
    Pending,
    /// In progress — maps to RuntimePhase enum values.
    InProgress(&'static str),
    /// Startup completed successfully.
    Complete,
    /// Startup failed.
    Failed(&'static str),
}

impl std::fmt::Display for StartupPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupPhase::Pending => write!(f, "Pending"),
            StartupPhase::InProgress(s) => write!(f, "InProgress({s})"),
            StartupPhase::Complete => write!(f, "Complete"),
            StartupPhase::Failed(s) => write!(f, "Failed({s})"),
        }
    }
}

// =============================================================================
// NAMED HEALTH GATES
// =============================================================================

/// How a named health gate influences overall readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateImpact {
    /// The gate is reported in health details but does not affect readiness.
    #[default]
    Informational,
    /// A non-passing gate blocks readiness entirely.
    BlocksReadiness,
    /// A non-passing gate downgrades readiness to [`Readiness::Degraded`].
    DegradesReadiness,
}

/// Current status of a named health gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// The gate has not yet reported a status.
    #[default]
    Unknown,
    /// The gate is healthy and does not block or degrade readiness.
    Passing,
    /// The gate is unhealthy at a level that degrades (but may still allow)
    /// serving traffic, depending on its [`GateImpact`].
    Degraded,
    /// The gate is unhealthy at a level that blocks serving traffic, depending
    /// on its [`GateImpact`].
    Failing,
}

/// A human-readable gate identifier.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct GateName(String);

impl GateName {
    /// Create a gate name from any string-like value.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow the underlying name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the gate name and return the owned string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<&str> for GateName {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for GateName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for GateName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Standard, reusable gate names for CNFs mapping their own policy onto the
/// generic [`HealthGateSet`]. Products may use these constants or define their
/// own names; the SDK does not encode product-specific readiness policy.
pub mod known_gates {
    /// Configuration has been loaded and applied.
    pub const CONFIG: &str = "config";
    /// Critical supervised tasks are healthy.
    pub const CRITICAL_TASKS: &str = "critical_tasks";
    /// Required listeners have bound their sockets.
    pub const LISTENERS: &str = "listeners";
    /// Identity, trust, and security material is valid.
    pub const SECURITY_MATERIAL: &str = "security_material";
    /// Cryptographic provider capability admission evidence.
    ///
    /// Observability only: attach the admission outcome — for example a
    /// serialized `opc-crypto-provider` `CapabilityReport`, whose bounded
    /// JSON form (at most 2 KiB) fits comfortably in
    /// [`HealthGate::with_details`](super::HealthGate::with_details) — so
    /// operators can see which module was admitted and with which effective
    /// capabilities. Enforcement lives elsewhere: the `SecurityInit` startup
    /// callback (`StartupPhases::init_security`) fails `Builder::build`
    /// before any listener binds. This gate never prevents traffic by itself.
    pub const CRYPTO_PROVIDER: &str = "crypto_provider";
    /// Reachability of a generic external peer.
    pub const EXTERNAL_PEER: &str = "external_peer";
    /// Diameter peer connectivity.
    pub const DIAMETER_PEER: &str = "diameter_peer";
    /// SCTP association health.
    pub const SCTP_ASSOCIATION: &str = "sctp_association";
    /// Session store availability.
    pub const SESSION_STORE: &str = "session_store";
    /// Data replication health.
    pub const REPLICATION: &str = "replication";
    /// Kernel dataplane readiness.
    pub const DATAPLANE_KERNEL: &str = "dataplane_kernel";
    /// Linux XFRM / IPsec transform interface availability.
    pub const XFRM: &str = "xfrm";
    /// GTP-U user-plane path health.
    pub const GTP_USER_PATH: &str = "gtp_user_path";
    /// Charging peer (CGF/CHF) reachability.
    pub const CHARGING_PEER: &str = "charging_peer";
    /// Lawful-intercept delivery path health.
    pub const LI_DELIVERY: &str = "li_delivery";
    /// Certificate revocation evidence availability.
    pub const CERTIFICATE_REVOCATION: &str = "certificate_revocation";
    /// Drain state: whether the CNF is still accepting new work.
    pub const DRAIN: &str = "drain";
}

/// A single named readiness/degradation gate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HealthGate {
    /// Gate identifier.
    pub name: GateName,
    /// Current gate status.
    pub status: GateStatus,
    /// How this gate influences overall readiness.
    pub impact: GateImpact,
    /// Optional human-readable explanation of the current status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Optional opaque product-specific details (must not contain secrets).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl HealthGate {
    /// Create a gate with the given name and impact. Status defaults to
    /// [`GateStatus::Unknown`].
    pub fn new(name: impl Into<GateName>, impact: GateImpact) -> Self {
        Self {
            name: name.into(),
            status: GateStatus::Unknown,
            impact,
            message: None,
            details: None,
        }
    }

    /// Set the gate status.
    pub fn with_status(mut self, status: GateStatus) -> Self {
        self.status = status;
        self
    }

    /// Set an explanatory message.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set opaque details.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Value view of a [`HealthGate`] used when serializing a [`HealthGateSet`] as a
/// map keyed by gate name. The name is omitted from the value to avoid
/// duplication.
#[derive(serde::Serialize)]
struct HealthGateValue<'a> {
    status: &'a GateStatus,
    impact: &'a GateImpact,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: &'a Option<serde_json::Value>,
}

impl<'a> From<&'a HealthGate> for HealthGateValue<'a> {
    fn from(gate: &'a HealthGate) -> Self {
        Self {
            status: &gate.status,
            impact: &gate.impact,
            message: &gate.message,
            details: &gate.details,
        }
    }
}

/// Owned value view of a [`HealthGate`] used when deserializing a
/// [`HealthGateSet`] map.
#[derive(serde::Deserialize)]
struct HealthGateValueOwned {
    status: GateStatus,
    impact: GateImpact,
    message: Option<String>,
    details: Option<serde_json::Value>,
}

impl HealthGateValueOwned {
    fn into_gate(self, name: GateName) -> HealthGate {
        HealthGate {
            name,
            status: self.status,
            impact: self.impact,
            message: self.message,
            details: self.details,
        }
    }
}

/// A reusable, named set of readiness/degradation gates.
///
/// CNFs insert gates that map to their own policy and then aggregate them into
/// a [`Readiness`] verdict. The set serializes as a JSON map keyed by gate name,
/// making it suitable for detailed health responses without breaking the cheap
/// probe variants that omit details.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthGateSet {
    gates: BTreeMap<GateName, HealthGate>,
}

impl HealthGateSet {
    /// Create an empty gate set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a gate, returning the previous gate if any.
    pub fn insert(&mut self, gate: HealthGate) -> Option<HealthGate> {
        self.gates.insert(gate.name.clone(), gate)
    }

    /// Fluent variant of [`Self::insert`].
    pub fn with_gate(mut self, gate: HealthGate) -> Self {
        self.insert(gate);
        self
    }

    /// Remove a gate by name.
    pub fn remove(&mut self, name: &GateName) -> Option<HealthGate> {
        self.gates.remove(name)
    }

    /// Borrow a gate by name.
    pub fn get(&self, name: &GateName) -> Option<&HealthGate> {
        self.gates.get(name)
    }

    /// Update the status of an existing gate. Returns `true` if the gate existed.
    pub fn set_status(&mut self, name: &GateName, status: GateStatus) -> bool {
        if let Some(gate) = self.gates.get_mut(name) {
            gate.status = status;
            true
        } else {
            false
        }
    }

    /// Returns true when no gates are registered.
    pub fn is_empty(&self) -> bool {
        self.gates.is_empty()
    }

    /// Number of registered gates.
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    /// Iterate over registered gates in name order.
    pub fn iter(&self) -> impl Iterator<Item = &HealthGate> {
        self.gates.values()
    }

    /// Aggregate the gate set into a readiness verdict.
    ///
    /// Fail-closed semantics: an unknown status is treated as non-passing.
    pub fn readiness(&self) -> Readiness {
        let mut blocks = false;
        let mut degrades = false;
        for gate in self.gates.values() {
            if gate.status == GateStatus::Passing {
                continue;
            }
            match gate.impact {
                GateImpact::Informational => {}
                GateImpact::BlocksReadiness => blocks = true,
                GateImpact::DegradesReadiness => degrades = true,
            }
        }
        if blocks {
            Readiness::NotReady
        } else if degrades {
            Readiness::Degraded
        } else {
            Readiness::Ready
        }
    }
}

impl serde::Serialize for HealthGateSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.gates.len()))?;
        for (name, gate) in &self.gates {
            map.serialize_entry(name.as_str(), &HealthGateValue::from(gate))?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for HealthGateSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct HealthGateSetVisitor;

        impl<'de> Visitor<'de> for HealthGateSetVisitor {
            type Value = HealthGateSet;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map from gate name to HealthGate")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut gates = BTreeMap::new();
                while let Some((name, value)) =
                    map.next_entry::<GateName, HealthGateValueOwned>()?
                {
                    gates.insert(name.clone(), value.into_gate(name));
                }
                Ok(HealthGateSet { gates })
            }
        }

        deserializer.deserialize_map(HealthGateSetVisitor)
    }
}

// =============================================================================
// HEALTH MODEL
// =============================================================================

/// Health model aggregating all health signals per RFC 008 section 11.2.
///
/// The `/readyz` endpoint aggregates:
/// - Config applied
/// - Critical tasks healthy
/// - Required listeners bound
/// - Required security material valid
/// - Required backends reachable
#[derive(Debug, Clone, Default)]
pub struct HealthModel {
    /// Readiness state.
    pub readiness: Readiness,
    /// Startup phase.
    pub startup: StartupPhase,
    /// Config applied.
    pub config_applied: bool,
    /// Critical tasks healthy.
    pub critical_tasks_healthy: bool,
    /// Listeners bound.
    pub listeners_bound: bool,
    /// Security material valid.
    pub security_material_valid: bool,
    /// Backends reachable (per NF policy).
    pub backends_reachable: bool,
    /// Named readiness/degradation gates. Empty by default so existing cheap
    /// probe output is preserved.
    pub gates: HealthGateSet,
}

impl HealthModel {
    /// Create a new health model in pending state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update readiness based on all aggregated signals, including named gates.
    pub fn compute_readiness(&self) -> Readiness {
        if !matches!(self.startup, StartupPhase::Complete) {
            return Readiness::NotReady;
        }

        if !self.config_applied
            || !self.critical_tasks_healthy
            || !self.listeners_bound
            || !self.security_material_valid
        {
            return Readiness::NotReady;
        }

        let base = if !self.backends_reachable {
            Readiness::Degraded
        } else {
            Readiness::Ready
        };

        match (base, self.gates.readiness()) {
            (Readiness::NotReady, _) | (_, Readiness::NotReady) => Readiness::NotReady,
            (Readiness::Degraded, _) | (_, Readiness::Degraded) => Readiness::Degraded,
            _ => Readiness::Ready,
        }
    }

    /// Check liveness — process event loop is alive.
    pub fn is_alive(&self) -> bool {
        // Liveness does not depend on external peers per RFC 008.
        // It only checks that the runtime is running.
        true
    }

    /// Check startup completion.
    pub fn is_startup_complete(&self) -> bool {
        matches!(self.startup, StartupPhase::Complete)
    }

    /// Mark config as applied.
    pub fn set_config_applied(&mut self, applied: bool) {
        self.config_applied = applied;
        self.readiness = self.compute_readiness();
    }

    /// Mark critical tasks health.
    pub fn set_critical_tasks_healthy(&mut self, healthy: bool) {
        self.critical_tasks_healthy = healthy;
        self.readiness = self.compute_readiness();
    }

    /// Mark listeners as bound.
    pub fn set_listeners_bound(&mut self, bound: bool) {
        self.listeners_bound = bound;
        self.readiness = self.compute_readiness();
    }

    /// Mark security material as valid.
    pub fn set_security_material_valid(&mut self, valid: bool) {
        self.security_material_valid = valid;
        self.readiness = self.compute_readiness();
    }

    /// Mark backends as reachable.
    pub fn set_backends_reachable(&mut self, reachable: bool) {
        self.backends_reachable = reachable;
        self.readiness = self.compute_readiness();
    }

    /// Mark startup as complete.
    pub fn set_startup_complete(&mut self) {
        self.startup = StartupPhase::Complete;
        self.readiness = self.compute_readiness();
    }

    /// Mark startup as failed.
    pub fn set_startup_failed(&mut self, reason: &'static str) {
        self.startup = StartupPhase::Failed(reason);
        self.readiness = self.compute_readiness();
    }

    /// Mark startup as in progress.
    pub fn set_startup_in_progress(&mut self, phase: &'static str) {
        self.startup = StartupPhase::InProgress(phase);
        self.readiness = self.compute_readiness();
    }

    /// Insert or replace a named gate and recompute readiness.
    ///
    /// Note: this recomputes readiness from the model's signals. It does not
    /// preserve an externally-imposed [`Readiness::Draining`] state; callers
    /// should avoid mutating gates while the runtime is draining.
    pub fn set_gate(&mut self, gate: HealthGate) {
        self.gates.insert(gate);
        self.readiness = self.compute_readiness();
    }

    /// Update the status of an existing named gate and recompute readiness.
    ///
    /// Returns `true` if the gate existed.
    ///
    /// Note: this recomputes readiness from the model's signals. It does not
    /// preserve an externally-imposed [`Readiness::Draining`] state; callers
    /// should avoid mutating gates while the runtime is draining.
    pub fn update_gate_status(&mut self, name: &GateName, status: GateStatus) -> bool {
        if self.gates.set_status(name, status) {
            self.readiness = self.compute_readiness();
            true
        } else {
            false
        }
    }

    /// Remove a named gate and recompute readiness.
    ///
    /// Note: this recomputes readiness from the model's signals. It does not
    /// preserve an externally-imposed [`Readiness::Draining`] state; callers
    /// should avoid mutating gates while the runtime is draining.
    pub fn remove_gate(&mut self, name: &GateName) -> Option<HealthGate> {
        let removed = self.gates.remove(name);
        if removed.is_some() {
            self.readiness = self.compute_readiness();
        }
        removed
    }
}

// =============================================================================
// HEALTH RESPONSES
// =============================================================================

/// Standardized health check response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    /// Overall verdict: `"ok"`, `"degraded"`, or `"not_ok"`.
    pub status: &'static str,
    /// Short machine-readable cause for a non-ok status (e.g. a failed
    /// startup phase name); omitted from JSON when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// Per-signal breakdown backing the verdict; omitted from JSON when
    /// `None` (the cheap probe variants skip it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HealthDetails>,
}

/// Per-signal health snapshot embedded in detailed probe responses.
///
/// Mirrors the `HealthModel` aggregation signals, with enum states rendered
/// as their `Display` strings for JSON serialization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthDetails {
    /// Readiness state rendered as text: `NotReady`, `Degraded`, `Ready`, or
    /// `Draining`.
    pub readiness: String,
    /// Startup phase rendered as text, e.g. `Pending`, `InProgress(ConfigBootstrap)`,
    /// `Complete`, or `Failed(...)`.
    pub startup: String,
    /// True once the initial configuration has been loaded and applied.
    pub config_applied: bool,
    /// True while no fatal/degrade-criticality task is in a failed state.
    pub critical_tasks_healthy: bool,
    /// True once all required listeners have bound their sockets.
    pub listeners_bound: bool,
    /// True while identity/trust material (certificates, keys) is present and
    /// unexpired.
    pub security_material_valid: bool,
    /// True while required backends are reachable per NF policy; false here
    /// downgrades readiness to `Degraded` rather than `NotReady`.
    pub backends_reachable: bool,
    /// Named gate details. Omitted when no gates are registered so cheap
    /// probe output is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gates: Option<HealthGateSet>,
}

fn health_details_from_model(model: &HealthModel) -> HealthDetails {
    HealthDetails {
        readiness: model.readiness.to_string(),
        startup: model.startup.to_string(),
        config_applied: model.config_applied,
        critical_tasks_healthy: model.critical_tasks_healthy,
        listeners_bound: model.listeners_bound,
        security_material_valid: model.security_material_valid,
        backends_reachable: model.backends_reachable,
        gates: if model.gates.is_empty() {
            None
        } else {
            Some(model.gates.clone())
        },
    }
}

impl HealthResponse {
    /// Create a healthy response.
    pub fn ok() -> Self {
        Self {
            status: "ok",
            reason: None,
            details: None,
        }
    }

    /// Create a healthy response with details.
    pub fn ok_with_details(model: &HealthModel) -> Self {
        Self {
            status: "ok",
            reason: None,
            details: Some(health_details_from_model(model)),
        }
    }

    /// Create a unhealthy response.
    pub fn not_ok(reason: &'static str) -> Self {
        Self {
            status: "not_ok",
            reason: Some(reason),
            details: None,
        }
    }

    /// Create a degraded response with details.
    pub fn degraded_with_details(reason: &'static str, model: &HealthModel) -> Self {
        Self {
            status: "degraded",
            reason: Some(reason),
            details: Some(health_details_from_model(model)),
        }
    }

    /// Create a unhealthy response with details.
    pub fn not_ok_with_details(reason: &'static str, model: &HealthModel) -> Self {
        Self {
            status: "not_ok",
            reason: Some(reason),
            details: Some(health_details_from_model(model)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readiness_defaults() {
        let r = Readiness::default();
        assert_eq!(r, Readiness::NotReady);
    }

    #[test]
    fn test_readiness_can_serve() {
        assert!(!Readiness::NotReady.can_serve());
        assert!(Readiness::Degraded.can_serve());
        assert!(Readiness::Ready.can_serve());
        assert!(!Readiness::Draining.can_serve());
    }

    #[test]
    fn test_readiness_k8s_mapping() {
        assert_eq!(Readiness::NotReady.as_k8s_condition(), "False");
        assert_eq!(Readiness::Degraded.as_k8s_condition(), "True");
        assert_eq!(Readiness::Ready.as_k8s_condition(), "True");
        assert_eq!(Readiness::Draining.as_k8s_condition(), "False");
    }

    #[test]
    fn test_health_model_readiness_aggregation() {
        let mut model = HealthModel::new();

        // All signals false -> NotReady
        assert_eq!(model.compute_readiness(), Readiness::NotReady);

        // Startup in progress -> NotReady
        model.set_startup_in_progress("ConfigBootstrap");
        assert_eq!(model.compute_readiness(), Readiness::NotReady);

        // Startup complete, all signals true -> Ready
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);
        assert_eq!(model.compute_readiness(), Readiness::Ready);

        // Backends unreachable -> Degraded
        model.set_backends_reachable(false);
        assert_eq!(model.compute_readiness(), Readiness::Degraded);
    }

    #[test]
    fn test_startup_phase_transitions() {
        let mut model = HealthModel::new();

        assert!(!model.is_startup_complete());

        model.set_startup_in_progress("TelemetryInit");
        assert!(!model.is_startup_complete());

        model.set_startup_complete();
        assert!(model.is_startup_complete());

        // Failed state
        let mut model2 = HealthModel::new();
        model2.set_startup_failed("ConfigBootstrap");
        assert!(!model2.is_startup_complete());
        assert_eq!(model2.compute_readiness(), Readiness::NotReady);
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));

        let mut model = HealthModel::new();
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);

        let response = HealthResponse::ok_with_details(&model);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"readiness\":\"Ready\""));
    }
}

#[cfg(test)]
mod health_gate_tests {
    use super::known_gates;
    use super::*;

    #[test]
    fn health_gate_set_empty_is_ready() {
        let gates = HealthGateSet::new();
        assert_eq!(gates.readiness(), Readiness::Ready);
        assert!(gates.is_empty());
    }

    #[test]
    fn health_gate_blocking_failure_not_ready() {
        let gates = HealthGateSet::new().with_gate(
            HealthGate::new(known_gates::DIAMETER_PEER, GateImpact::BlocksReadiness)
                .with_status(GateStatus::Failing)
                .with_message("no reachable peer"),
        );
        assert_eq!(gates.readiness(), Readiness::NotReady);
    }

    #[test]
    fn health_gate_blocking_degraded_not_ready() {
        let gates = HealthGateSet::new().with_gate(
            HealthGate::new(known_gates::SECURITY_MATERIAL, GateImpact::BlocksReadiness)
                .with_status(GateStatus::Degraded),
        );
        assert_eq!(gates.readiness(), Readiness::NotReady);
    }

    #[test]
    fn health_gate_unknown_blocking_is_not_ready() {
        let gates = HealthGateSet::new().with_gate(HealthGate::new(
            known_gates::XFRM,
            GateImpact::BlocksReadiness,
        ));
        assert_eq!(gates.readiness(), Readiness::NotReady);
    }

    #[test]
    fn health_gate_degrading_failure_degraded() {
        let gates = HealthGateSet::new().with_gate(
            HealthGate::new(known_gates::CHARGING_PEER, GateImpact::DegradesReadiness)
                .with_status(GateStatus::Failing),
        );
        assert_eq!(gates.readiness(), Readiness::Degraded);
    }

    #[test]
    fn health_gate_degrading_unknown_degraded() {
        let gates = HealthGateSet::new().with_gate(HealthGate::new(
            known_gates::EXTERNAL_PEER,
            GateImpact::DegradesReadiness,
        ));
        assert_eq!(gates.readiness(), Readiness::Degraded);
    }

    #[test]
    fn health_gate_informational_does_not_affect_readiness() {
        let gates = HealthGateSet::new().with_gate(
            HealthGate::new(
                known_gates::CERTIFICATE_REVOCATION,
                GateImpact::Informational,
            )
            .with_status(GateStatus::Failing),
        );
        assert_eq!(gates.readiness(), Readiness::Ready);
    }

    #[test]
    fn health_gate_blocking_overrides_degrading() {
        let gates = HealthGateSet::new()
            .with_gate(
                HealthGate::new(known_gates::LISTENERS, GateImpact::DegradesReadiness)
                    .with_status(GateStatus::Failing),
            )
            .with_gate(
                HealthGate::new(known_gates::CONFIG, GateImpact::BlocksReadiness)
                    .with_status(GateStatus::Failing),
            );
        assert_eq!(gates.readiness(), Readiness::NotReady);
    }

    #[test]
    fn health_gate_set_status_updates_readiness() {
        let mut gates = HealthGateSet::new().with_gate(HealthGate::new(
            known_gates::GTP_USER_PATH,
            GateImpact::BlocksReadiness,
        ));
        assert_eq!(gates.readiness(), Readiness::NotReady);

        assert!(gates.set_status(&known_gates::GTP_USER_PATH.into(), GateStatus::Passing));
        assert_eq!(gates.readiness(), Readiness::Ready);
    }

    #[test]
    fn health_gate_details_map_serialization() {
        let gates = HealthGateSet::new()
            .with_gate(
                HealthGate::new(known_gates::CONFIG, GateImpact::BlocksReadiness)
                    .with_status(GateStatus::Passing),
            )
            .with_gate(
                HealthGate::new(known_gates::SESSION_STORE, GateImpact::DegradesReadiness)
                    .with_status(GateStatus::Failing)
                    .with_message("replica lag high")
                    .with_details(serde_json::json!({ "lag_ms": 2500 })),
            );

        let json = serde_json::to_string(&gates).unwrap();
        assert!(json.contains("\"config\":{\"status\":\"passing\""));
        assert!(json.contains("\"session_store\":"));
        assert!(json.contains("\"status\":\"failing\""));
        assert!(json.contains("\"impact\":\"degrades_readiness\""));
        assert!(json.contains("\"lag_ms\":2500"));
        // Name should not be duplicated as a value field.
        assert!(!json.contains("\"name\":\"config\""));

        let round_trip: HealthGateSet = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip.len(), gates.len());
        assert_eq!(
            round_trip.get(&known_gates::CONFIG.into()).unwrap().status,
            GateStatus::Passing
        );
    }

    #[test]
    fn health_gate_empty_set_serializes_as_empty_object() {
        let gates = HealthGateSet::new();
        let json = serde_json::to_string(&gates).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn health_model_backward_compatibility_no_gates() {
        let mut model = HealthModel::new();
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);

        assert_eq!(model.readiness, Readiness::Ready);
        assert!(model.gates.is_empty());

        let response = HealthResponse::ok_with_details(&model);
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("\"gates\""));
    }

    #[test]
    fn health_model_with_gate_set_aggregation() {
        let mut model = HealthModel::new();
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);

        model.set_gate(HealthGate::new(
            known_gates::XFRM,
            GateImpact::BlocksReadiness,
        ));
        assert_eq!(model.readiness, Readiness::NotReady);

        model.update_gate_status(&known_gates::XFRM.into(), GateStatus::Passing);
        assert_eq!(model.readiness, Readiness::Ready);

        model.set_gate(
            HealthGate::new(known_gates::CHARGING_PEER, GateImpact::DegradesReadiness)
                .with_status(GateStatus::Failing),
        );
        assert_eq!(model.readiness, Readiness::Degraded);

        let response = HealthResponse::degraded_with_details("charging_peer_failing", &model);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"gates\":"));
        assert!(json.contains("\"charging_peer\":"));
    }

    #[test]
    fn health_model_gate_remove_recomputes_readiness() {
        let mut model = HealthModel::new();
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);

        let gate_name: GateName = known_gates::DRAIN.into();
        model.set_gate(
            HealthGate::new(gate_name.clone(), GateImpact::BlocksReadiness)
                .with_status(GateStatus::Failing),
        );
        assert_eq!(model.readiness, Readiness::NotReady);

        model.remove_gate(&gate_name);
        assert_eq!(model.readiness, Readiness::Ready);
    }

    #[test]
    fn health_gate_set_status_missing_returns_false_and_leaves_readiness() {
        let mut gates = HealthGateSet::new().with_gate(HealthGate::new(
            known_gates::CONFIG,
            GateImpact::BlocksReadiness,
        ));
        let before = gates.readiness();
        let missing_name: GateName = "missing".into();

        assert!(!gates.set_status(&missing_name, GateStatus::Passing));
        assert_eq!(gates.readiness(), before);
        assert!(gates.get(&known_gates::CONFIG.into()).unwrap().status == GateStatus::Unknown);
    }

    #[test]
    fn health_gate_set_remove_missing_returns_none_and_leaves_readiness() {
        let mut gates = HealthGateSet::new().with_gate(HealthGate::new(
            known_gates::CONFIG,
            GateImpact::BlocksReadiness,
        ));
        let before = gates.readiness();
        let missing_name: GateName = "missing".into();

        assert!(gates.remove(&missing_name).is_none());
        assert_eq!(gates.readiness(), before);
        assert_eq!(gates.len(), 1);
    }

    #[test]
    fn health_model_update_gate_status_missing_returns_false_and_leaves_readiness() {
        let mut model = HealthModel::new();
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);

        // Seed a non-computed readiness sentinel so the assertion proves the
        // missing-gate path does not recompute readiness.
        model.readiness = Readiness::Draining;
        let before = model.readiness;
        let missing_name: GateName = "missing".into();

        assert!(!model.update_gate_status(&missing_name, GateStatus::Passing));
        assert_eq!(model.readiness, before);
    }

    #[test]
    fn health_model_remove_gate_missing_returns_none_and_leaves_readiness() {
        let mut model = HealthModel::new();
        model.set_startup_complete();
        model.set_config_applied(true);
        model.set_critical_tasks_healthy(true);
        model.set_listeners_bound(true);
        model.set_security_material_valid(true);
        model.set_backends_reachable(true);

        // Seed a non-computed readiness sentinel so the assertion proves the
        // missing-gate path does not recompute readiness.
        model.readiness = Readiness::Draining;
        let before = model.readiness;
        let missing_name: GateName = "missing".into();

        assert!(model.remove_gate(&missing_name).is_none());
        assert_eq!(model.readiness, before);
    }

    #[test]
    fn health_gate_set_iterates_in_name_order() {
        let gates = HealthGateSet::new()
            .with_gate(HealthGate::new("z", GateImpact::Informational))
            .with_gate(HealthGate::new("a", GateImpact::Informational))
            .with_gate(HealthGate::new("m", GateImpact::Informational));

        let names: Vec<&str> = gates.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn crypto_provider_gate_unknown_or_failing_blocks_readiness() {
        for status in [GateStatus::Unknown, GateStatus::Failing] {
            let gates = HealthGateSet::new().with_gate(
                HealthGate::new(known_gates::CRYPTO_PROVIDER, GateImpact::BlocksReadiness)
                    .with_status(status),
            );
            assert_eq!(
                gates.readiness(),
                Readiness::NotReady,
                "crypto provider gate with status {status:?} must aggregate to NotReady"
            );
        }
    }

    #[test]
    fn crypto_provider_gate_passing_with_report_details_is_ready() {
        let gates = HealthGateSet::new().with_gate(
            HealthGate::new(known_gates::CRYPTO_PROVIDER, GateImpact::BlocksReadiness)
                .with_status(GateStatus::Passing)
                .with_message("module admitted")
                .with_details(serde_json::json!({ "effective": ["tls"] })),
        );
        assert_eq!(gates.readiness(), Readiness::Ready);

        let json = serde_json::to_string(&gates).unwrap();
        assert!(json.contains("\"crypto_provider\":"));
        assert!(json.contains("\"effective\":[\"tls\"]"));
    }
}
