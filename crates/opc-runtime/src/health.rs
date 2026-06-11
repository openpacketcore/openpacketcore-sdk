//! Health model and probe endpoints per RFC 008 section 11.

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
            StartupPhase::InProgress(s) => write!(f, "InProgress({})", s),
            StartupPhase::Complete => write!(f, "Complete"),
            StartupPhase::Failed(s) => write!(f, "Failed({})", s),
        }
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
}

impl HealthModel {
    /// Create a new health model in pending state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update readiness based on all aggregated signals.
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

        if !self.backends_reachable {
            return Readiness::Degraded;
        }

        Readiness::Ready
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
}

// =============================================================================
// HEALTH RESPONSES
// =============================================================================

/// Standardized health check response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HealthDetails>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthDetails {
    pub readiness: String,
    pub startup: String,
    pub config_applied: bool,
    pub critical_tasks_healthy: bool,
    pub listeners_bound: bool,
    pub security_material_valid: bool,
    pub backends_reachable: bool,
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
            details: Some(HealthDetails {
                readiness: model.readiness.to_string(),
                startup: model.startup.to_string(),
                config_applied: model.config_applied,
                critical_tasks_healthy: model.critical_tasks_healthy,
                listeners_bound: model.listeners_bound,
                security_material_valid: model.security_material_valid,
                backends_reachable: model.backends_reachable,
            }),
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
            details: Some(HealthDetails {
                readiness: model.readiness.to_string(),
                startup: model.startup.to_string(),
                config_applied: model.config_applied,
                critical_tasks_healthy: model.critical_tasks_healthy,
                listeners_bound: model.listeners_bound,
                security_material_valid: model.security_material_valid,
                backends_reachable: model.backends_reachable,
            }),
        }
    }

    /// Create a unhealthy response with details.
    pub fn not_ok_with_details(reason: &'static str, model: &HealthModel) -> Self {
        Self {
            status: "not_ok",
            reason: Some(reason),
            details: Some(HealthDetails {
                readiness: model.readiness.to_string(),
                startup: model.startup.to_string(),
                config_applied: model.config_applied,
                critical_tasks_healthy: model.critical_tasks_healthy,
                listeners_bound: model.listeners_bound,
                security_material_valid: model.security_material_valid,
                backends_reachable: model.backends_reachable,
            }),
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
