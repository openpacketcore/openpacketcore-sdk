#![forbid(unsafe_code)]

//! Toy OpenPacketCore integration crate.
//!
//! This crate demonstrates how a small NF can compose the shared runtime,
//! config bus, alarm subsystem, and testbed/evidence layers into a single
//! integration surface suitable for conformance-style tests.

use opc_alarm::{
    AffectedObject, Alarm, AlarmDetails, AlarmOpResult, AlarmType, ProbableCause, ReadinessImpact,
    RedactedText, Severity, SharedAlarmManager,
};
use opc_config_bus::{
    ConfigBus, ConfigEvent, MockManagedDatastore, PublishedSnapshot, SubscriberLagPolicy,
};
use opc_config_model::{
    CommitRequest, ConfigError, ConfigOperation, OpcConfig, RequestId, RequestSource,
    TransportType, TrustedPrincipal, ValidationContext, ValidationError, ValueError,
    WorkloadIdentity, YangPath,
};
use opc_runtime::{
    health::HealthResponse, Builder, Criticality, HealthModel, Readiness, RestartPolicy,
    RuntimeError, RuntimeHandle, RuntimePhase, RuntimeProfile, ShutdownToken, Supervisor, TaskKind,
    TaskName,
};
use opc_testbed::{
    evaluate, simulators::fake::FakeSimulator, AssertionOutcome, Scenario, ScenarioEvidence,
    ScenarioOutcome, Step, VirtualClock,
};
use opc_types::{ConfigVersion, ParseError, SchemaDigest, TenantId, Timestamp};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    io,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{Barrier, Notify, RwLock};

/// Artifact path for the serialized health snapshot emitted by [`ToyNetworkFunction::run_scenario`].
pub const HEALTH_ARTIFACT: &str = "artifacts/health.json";
/// Artifact path for the serialized alarm history emitted by [`ToyNetworkFunction::run_scenario`].
pub const ALARMS_ARTIFACT: &str = "artifacts/alarms.json";
/// Artifact path for the serialized scenario state emitted by [`ToyNetworkFunction::run_scenario`].
pub const SCENARIO_STATE_ARTIFACT: &str = "artifacts/scenario-state.json";

const TOY_SCHEMA_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOY_START_TIMESTAMP: &str = "2026-01-01T00:00:00Z";
const TOY_ALARM_TYPE: &str = "toy-nf.peer.connectivity";
const TOY_ALARM_KIND: &str = "toy-nf";
const TOY_ALARM_INSTANCE: &str = "toy-nf-1";
const TOY_ALARM_TENANT: &str = "system";

/// Minimal toy NF configuration loaded through the RFC 001 config bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToyConfig {
    /// Hostname published by the toy NF runtime.
    pub hostname: String,
    /// Synthetic NRF-style endpoint consumed during semantic validation.
    pub peer_endpoint: String,
}

impl Default for ToyConfig {
    fn default() -> Self {
        Self::new("toy-bootstrap", "nrf://bootstrap")
    }
}

impl ToyConfig {
    /// Creates a validated toy configuration candidate.
    pub fn new(hostname: impl Into<String>, peer_endpoint: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            peer_endpoint: peer_endpoint.into(),
        }
    }
}

impl OpcConfig for ToyConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str(TOY_SCHEMA_DIGEST).expect("toy integration schema digest is valid")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        let mut deltas = Vec::new();
        if self.hostname != previous.hostname {
            deltas.push(format!("replace:/toy/hostname={}", self.hostname));
        }
        if self.peer_endpoint != previous.peer_endpoint {
            deltas.push(format!("replace:/toy/peer-endpoint={}", self.peer_endpoint));
        }
        Ok(deltas)
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        deltas
            .iter()
            .map(|delta| {
                let encoded_path = delta.strip_prefix("replace:").ok_or_else(|| {
                    ConfigError::new("changed-path", "unsupported delta operation")
                })?;
                let path = encoded_path
                    .split_once('=')
                    .map(|(path, _)| path)
                    .unwrap_or(encoded_path);
                YangPath::new(path).map_err(|err| ConfigError::new("changed-path", err.message()))
            })
            .collect()
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        let (path, value) = delta
            .strip_prefix("replace:")
            .and_then(|delta| delta.split_once('='))
            .ok_or_else(|| ConfigError::new("delta", "unsupported toy delta encoding"))?;

        match path {
            "/toy/hostname" => self.hostname = value.to_string(),
            "/toy/peer-endpoint" => self.peer_endpoint = value.to_string(),
            _ => return Err(ConfigError::new("delta", "unknown toy config path")),
        }

        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.hostname.trim().is_empty() {
            return Err(ValidationError::syntax("hostname must not be empty"));
        }

        if self.peer_endpoint.trim().is_empty() {
            return Err(ValidationError::syntax("peer_endpoint must not be empty"));
        }

        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        if !self.peer_endpoint.starts_with("nrf://") {
            return Err(ValidationError::semantics(
                "peer_endpoint must use the nrf:// scheme",
            ));
        }

        Ok(())
    }
}

/// Snapshot of the currently published running configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToyObservedConfig {
    /// Monotonic config version published by the config bus.
    pub version: u64,
    /// Applied hostname.
    pub hostname: String,
    /// Applied peer endpoint.
    pub peer_endpoint: String,
}

/// Health view combining runtime readiness and toy NF state.
#[derive(Debug, Clone, Serialize)]
pub struct ToyHealthSnapshot {
    /// Current [`RuntimePhase`] rendered as text.
    pub runtime_phase: String,
    /// Current runtime readiness rendered as text.
    pub runtime_readiness: String,
    /// Latest observed running config.
    pub config: ToyObservedConfig,
    /// Number of active alarms held by the toy alarm manager.
    pub active_alarm_count: usize,
    /// RFC 008-style health response payload.
    pub response: HealthResponse,
}

/// Result bundle produced by a toy scenario execution.
#[derive(Debug, Clone)]
pub struct ScenarioRunOutput {
    /// Parsed scenario document that was executed.
    pub scenario: Scenario,
    /// Structured RFC 012/RFC 006 evidence record.
    pub evidence: ScenarioEvidence,
    /// Pretty-printed JSON representation of [`Self::evidence`].
    pub evidence_json: String,
    /// Pretty-printed artifact payloads keyed by artifact path.
    pub artifacts: BTreeMap<String, String>,
}

/// Error returned by toy NF integration helpers.
#[derive(Debug, Error)]
pub enum ToyIntegrationError {
    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),

    #[error("config store error: {0}")]
    Store(#[from] opc_config_bus::StoreError),

    #[error("config commit error: {0}")]
    Commit(#[from] opc_config_model::CommitError),

    #[error("config model parse error: {0}")]
    Value(#[from] ValueError),

    #[error("identifier parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("scenario error: {0}")]
    Testbed(#[from] opc_testbed::TestbedError),

    #[error("serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("missing simulator for step target '{0}'")]
    MissingSimulator(String),

    #[error(
        "toy scenario runner does not observe {step_kind} traffic, so step targeting '{target}' cannot be validated"
    )]
    UnsupportedExpectationStep {
        step_kind: &'static str,
        target: String,
    },

    #[error("toy scenario runner does not support NGAP message '{0}'")]
    UnsupportedNgapMessage(String),

    #[error("unsupported scenario step")]
    UnsupportedScenarioStep,

    #[error("unexpected alarm manager outcome while raising the toy alarm: {0:?}")]
    UnexpectedAlarmOutcome(Box<AlarmOpResult>),

    #[error("timeout waiting for {0}")]
    Timeout(&'static str),
}

struct ToyState {
    config: ToyConfig,
    version: ConfigVersion,
    health: HealthModel,
}

impl ToyState {
    fn new(initial_config: ToyConfig) -> Self {
        let mut health = HealthModel::new();
        health.set_startup_in_progress("ConfigBootstrap");
        health.set_config_applied(true);

        Self {
            config: initial_config,
            version: ConfigVersion::INITIAL,
            health,
        }
    }

    fn observed_config(&self) -> ToyObservedConfig {
        ToyObservedConfig {
            version: self.version.get(),
            hostname: self.config.hostname.clone(),
            peer_endpoint: self.config.peer_endpoint.clone(),
        }
    }
}

#[derive(Clone, Copy)]
enum WaitNotifies<'a> {
    One(&'a Notify),
    Two(&'a Notify, &'a Notify),
}

/// In-process toy NF that wires the shared OpenPacketCore crates together.
pub struct ToyNetworkFunction {
    runtime: RuntimeHandle,
    config_bus: ConfigBus<ToyConfig>,
    state: Arc<RwLock<ToyState>>,
    state_notify: Arc<Notify>,
    phase_notify: Arc<Notify>,
    alarms: SharedAlarmManager,
}

impl ToyNetworkFunction {
    /// Starts the toy runtime, config bus, readiness-gated health listener, and alarm manager.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo() -> Result<(), opc_sdk_integration::ToyIntegrationError> {
    /// use opc_sdk_integration::{ToyConfig, ToyNetworkFunction};
    ///
    /// let toy = ToyNetworkFunction::start(ToyConfig::default()).await?;
    /// toy.shutdown().await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(initial_config: ToyConfig) -> Result<Self, ToyIntegrationError> {
        let alarms = SharedAlarmManager::default();
        let config_bus = ConfigBus::new_with_alarm_manager_dev_only(
            initial_config.clone(),
            MockManagedDatastore::new(),
            alarms.clone(),
        )
        .await?;
        let state = Arc::new(RwLock::new(ToyState::new(initial_config)));
        let state_notify = Arc::new(Notify::new());
        let phase_notify = Arc::new(Notify::new());

        let runtime = build_runtime(
            config_bus.clone(),
            Arc::clone(&state),
            &state_notify,
            &phase_notify,
            alarms.clone(),
            true,
        )
        .await?;

        let toy = Self {
            runtime,
            config_bus,
            state,
            state_notify,
            phase_notify,
            alarms,
        };

        toy.complete_startup(Duration::from_secs(1)).await
    }

    /// Waits until the runtime reaches [`RuntimePhase::Ready`] and reports [`Readiness::Ready`].
    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<(), ToyIntegrationError> {
        self.wait_for_ready_inner(timeout, None).await
    }

    /// Returns the current runtime phase.
    pub async fn phase(&self) -> RuntimePhase {
        self.runtime.phase().await
    }

    /// Returns the current runtime readiness.
    pub async fn readiness(&self) -> Readiness {
        self.runtime.readiness().await
    }

    /// Returns a reference to the underlying runtime supervisor.
    pub fn supervisor(&self) -> &opc_runtime::Supervisor {
        self.runtime.supervisor()
    }

    /// Builds a health snapshot combining runtime state, config state, and active alarm count.
    pub async fn health(&self) -> Result<ToyHealthSnapshot, ToyIntegrationError> {
        let runtime_phase = self.runtime.phase().await;
        let runtime_readiness = self.runtime.readiness().await;
        let (config, mut health_model) = {
            let state = self.state.read().await;
            (state.observed_config(), state.health.clone())
        };
        let (active_alarm_count, readiness_impact) = {
            let active_alarms = self.alarms.active_alarms();
            let readiness_impact =
                active_alarms
                    .iter()
                    .fold(ReadinessImpact::NoImpact, |impact, alarm| {
                        match (impact, alarm.readiness_impact()) {
                            (ReadinessImpact::ForceNotReady, _)
                            | (_, ReadinessImpact::ForceNotReady) => ReadinessImpact::ForceNotReady,
                            (ReadinessImpact::DegradedOnly, _)
                            | (_, ReadinessImpact::DegradedOnly) => ReadinessImpact::DegradedOnly,
                            _ => ReadinessImpact::NoImpact,
                        }
                    });
            (active_alarms.len(), readiness_impact)
        };

        health_model.readiness =
            apply_alarm_readiness_impact(health_model.readiness, readiness_impact);

        let aggregate_readiness = match (runtime_readiness, health_model.readiness) {
            (Readiness::NotReady, _) | (_, Readiness::NotReady) => Readiness::NotReady,
            (Readiness::Degraded, _) | (_, Readiness::Degraded) => Readiness::Degraded,
            (Readiness::Ready, Readiness::Ready) => Readiness::Ready,
            _ => Readiness::NotReady,
        };

        let response = if runtime_phase >= RuntimePhase::Draining {
            HealthResponse::not_ok("draining")
        } else if runtime_phase < RuntimePhase::Ready || !health_model.is_startup_complete() {
            HealthResponse::not_ok("startup_incomplete")
        } else if matches!(aggregate_readiness, Readiness::Ready) {
            HealthResponse::ok_with_details(&health_model)
        } else if matches!(aggregate_readiness, Readiness::Degraded) {
            let reason = if active_alarm_count > 0 {
                "active_alarm"
            } else {
                "degraded"
            };
            HealthResponse::degraded_with_details(reason, &health_model)
        } else if matches!(readiness_impact, ReadinessImpact::ForceNotReady) {
            HealthResponse::not_ok_with_details("active_alarm", &health_model)
        } else {
            HealthResponse::not_ok("startup_incomplete")
        };

        Ok(ToyHealthSnapshot {
            runtime_phase: runtime_phase.to_string(),
            runtime_readiness: runtime_readiness.to_string(),
            config,
            active_alarm_count,
            response,
        })
    }

    /// Commits a new toy config candidate through the config bus and waits for publication.
    pub async fn commit_config(
        &self,
        candidate: ToyConfig,
    ) -> Result<opc_config_model::CommitResult, ToyIntegrationError> {
        let current = self.state.read().await.observed_config();
        let principal = toy_principal()?;
        let changed_paths = toy_changed_paths(&current, &candidate)?;
        let request = CommitRequest::commit(
            RequestId::new(),
            principal,
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            candidate,
            changed_paths,
            Instant::now() + Duration::from_secs(1),
        )
        .with_base_version(ConfigVersion::new(current.version));

        let result = self.config_bus.submit(request).await?;
        if let Some(version) = result.new_version {
            let _ = self
                .wait_for_config_version(version, Duration::from_secs(1))
                .await?;
        }

        Ok(result)
    }

    /// Waits for the config watcher to observe at least the requested running-config version.
    pub async fn wait_for_config_version(
        &self,
        expected: ConfigVersion,
        timeout: Duration,
    ) -> Result<ToyObservedConfig, ToyIntegrationError> {
        self.wait_for_config_version_inner(expected, timeout, None)
            .await
    }

    /// Raises a redacted major alarm representing peer connectivity loss.
    pub fn raise_redacted_alarm(&self) -> Result<Alarm, ToyIntegrationError> {
        let result = self.alarms.raise(
            AlarmType::new(TOY_ALARM_TYPE),
            Severity::Major,
            ProbableCause::PeerUnreachable,
            AffectedObject::NfInstance {
                kind: TOY_ALARM_KIND.to_string(),
                instance: TOY_ALARM_INSTANCE.to_string(),
            },
            Some(TOY_ALARM_TENANT.to_string()),
            None,
            None,
            RedactedText::new("Toy NF registration path for subscriber [redacted] timed out"),
            AlarmDetails::with_value(serde_json::json!({
                "boundary": "control-plane",
                "peer": "nrf-sim"
            })),
        );

        match result {
            AlarmOpResult::Raised { alarm } | AlarmOpResult::Updated { alarm } => Ok(alarm),
            other => Err(ToyIntegrationError::UnexpectedAlarmOutcome(Box::new(other))),
        }
    }

    /// Clears the redacted major alarm representing peer connectivity loss.
    pub fn clear_redacted_alarm(&self) -> Result<(), ToyIntegrationError> {
        let result = self.alarms.clear(
            &AlarmType::new(TOY_ALARM_TYPE),
            ProbableCause::PeerUnreachable,
            &AffectedObject::NfInstance {
                kind: TOY_ALARM_KIND.to_string(),
                instance: TOY_ALARM_INSTANCE.to_string(),
            },
            Some(TOY_ALARM_TENANT),
            None,
            None,
        );

        match result {
            AlarmOpResult::Cleared { .. } => Ok(()),
            other => Err(ToyIntegrationError::UnexpectedAlarmOutcome(Box::new(other))),
        }
    }

    /// Returns the retained alarm history for the toy NF.
    pub fn alarm_history(&self) -> Vec<Alarm> {
        self.alarms.all_alarms()
    }

    /// Injects a fatal runtime task failure through the toy NF's real runtime/alarm wiring.
    ///
    /// The helper spawns a fatal supervised task, waits for the runtime to record
    /// the fatal failure, marks critical task health false, and raises the
    /// corresponding critical alarm in the toy NF's shared alarm manager.
    pub async fn inject_runtime_task_failure(
        &self,
        timeout: Duration,
    ) -> Result<Alarm, ToyIntegrationError> {
        let task_name = TaskName::new("toy-fault-injected-runtime-task");
        self.runtime
            .supervisor()
            .spawn(
                task_name.clone(),
                TaskKind::ProtocolWorker,
                Criticality::Fatal,
                RestartPolicy::no_restart(),
                || {
                    Box::pin(async {
                        Err(opc_runtime::task::TaskError::Failed(
                            "runtime task fault".to_string(),
                            Arc::new(io::Error::other("simulated runtime fault")),
                        ))
                    })
                },
            )
            .await?;

        let (failed_task, _error) = tokio::time::timeout(
            timeout,
            wait_for_fatal_task_failure(self.runtime.supervisor(), self.runtime.shutdown_token()),
        )
        .await
        .map_err(|_| ToyIntegrationError::Timeout("runtime task failure"))?;

        {
            let mut state = self.state.write().await;
            state.health.set_critical_tasks_healthy(false);
        }
        self.state_notify.notify_waiters();

        let failed_task_name = failed_task.to_string();
        self.alarms
            .active_alarms()
            .into_iter()
            .find(|alarm| {
                alarm.probable_cause == ProbableCause::Other("opc-runtime.task-failure".to_string())
                    && alarm
                        .details
                        .as_value()
                        .and_then(|details| details.get("runtime_task"))
                        .and_then(serde_json::Value::as_str)
                        == Some(failed_task_name.as_str())
            })
            .ok_or(ToyIntegrationError::Timeout("runtime task alarm"))
    }

    /// Executes a toy scenario and emits deterministic health/alarm/state artifacts plus evidence JSON.
    ///
    /// The toy runner only supports steps it can actually observe. `expect_sbi`
    /// and `expect_ngap` are rejected instead of being treated as implicit
    /// success, because this crate does not model real traffic capture.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn demo() -> Result<(), opc_sdk_integration::ToyIntegrationError> {
    /// use opc_sdk_integration::{ToyConfig, ToyNetworkFunction};
    ///
    /// let toy = ToyNetworkFunction::start(ToyConfig::default()).await?;
    /// let _run = toy
    ///     .run_scenario(
    ///         r#"schema_version: "0.1.0"
    /// id: TOY-NF-EXAMPLE
    /// title: Toy scenario
    /// requirements:
    ///   - REQ-3GPP-TS23502-R17-4.2.2-001
    /// topology:
    ///   nfs:
    ///     toy-nf:
    ///       simulator: "fake"
    /// steps:
    ///   - kind: send_ngap
    ///     from: ran-1
    ///     to: toy-nf
    ///     message: registration
    /// assertions:
    ///   - expr: "toy-nf.state == REGISTERED"
    /// "#,
    ///     )
    ///     .await?;
    /// toy.shutdown().await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_scenario(
        &self,
        scenario_yaml: &str,
    ) -> Result<ScenarioRunOutput, ToyIntegrationError> {
        let scenario = Scenario::from_yaml(scenario_yaml)?;
        scenario.validate()?;

        let start = Timestamp::from_str(TOY_START_TIMESTAMP)?;
        let mut clock = VirtualClock::new(start);
        let started_at = *clock.now().as_offset_datetime();

        let mut simulators = BTreeMap::new();
        for (name, spec) in &scenario.topology.nfs {
            if spec.simulator.is_some() {
                simulators.insert(name.clone(), FakeSimulator::from_spec(name, spec)?);
            }
        }

        let mut state = HashMap::new();
        for step in &scenario.steps {
            apply_step(step, &mut simulators, &mut state)?;
            clock.advance(time::Duration::seconds(1));
        }

        for (name, simulator) in &simulators {
            if let Some(current_state) = simulator.get_state("state") {
                state.insert(format!("{name}.state"), current_state.to_string());
            }
        }

        let outcome = scenario_outcome(&scenario, &state);
        let finished_at = *clock.now().as_offset_datetime();
        let artifact_state: BTreeMap<_, _> = state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            HEALTH_ARTIFACT.to_string(),
            serde_json::to_string_pretty(&self.health().await?)?,
        );
        artifacts.insert(
            ALARMS_ARTIFACT.to_string(),
            serde_json::to_string_pretty(&self.alarm_history())?,
        );
        artifacts.insert(
            SCENARIO_STATE_ARTIFACT.to_string(),
            serde_json::to_string_pretty(&artifact_state)?,
        );

        let mut evidence = ScenarioEvidence::new(scenario.id.clone(), outcome);
        evidence.requirements = scenario.requirements.clone();
        evidence.mode = Some("in-process".to_string());
        evidence.seed = scenario.seed;
        evidence.artifacts = vec![
            HEALTH_ARTIFACT.to_string(),
            ALARMS_ARTIFACT.to_string(),
            SCENARIO_STATE_ARTIFACT.to_string(),
        ];
        evidence.started_at = Some(started_at);
        evidence.finished_at = Some(finished_at);

        let evidence_json = serde_json::to_string_pretty(&evidence)?;

        Ok(ScenarioRunOutput {
            scenario,
            evidence,
            evidence_json,
            artifacts,
        })
    }

    /// Initiates a graceful drain/shutdown of the toy runtime.
    pub async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    async fn complete_startup(self, timeout: Duration) -> Result<Self, ToyIntegrationError> {
        if let Err(err) = self.wait_for_ready(timeout).await {
            self.runtime.shutdown().await;
            return Err(err);
        }
        {
            let mut state = self.state.write().await;
            state.health.set_startup_complete();
        }
        self.state_notify.notify_waiters();

        Ok(self)
    }

    async fn wait_for_ready_inner(
        &self,
        timeout: Duration,
        after_register: Option<Arc<Barrier>>,
    ) -> Result<(), ToyIntegrationError> {
        wait_for_observation(
            WaitNotifies::Two(&self.phase_notify, &self.state_notify),
            timeout,
            "runtime readiness",
            after_register,
            || async {
                let phase = self.runtime.phase().await;
                let readiness = self.runtime.readiness().await;
                (phase == RuntimePhase::Ready && matches!(readiness, Readiness::Ready))
                    .then_some(())
            },
        )
        .await
    }

    async fn wait_for_config_version_inner(
        &self,
        expected: ConfigVersion,
        timeout: Duration,
        after_register: Option<Arc<Barrier>>,
    ) -> Result<ToyObservedConfig, ToyIntegrationError> {
        wait_for_observation(
            WaitNotifies::One(&self.state_notify),
            timeout,
            "config application",
            after_register,
            || async {
                let state = self.state.read().await;
                (state.version >= expected).then(|| state.observed_config())
            },
        )
        .await
    }
}

fn apply_alarm_readiness_impact(readiness: Readiness, impact: ReadinessImpact) -> Readiness {
    match (readiness, impact) {
        (_, ReadinessImpact::ForceNotReady) => Readiness::NotReady,
        (Readiness::Ready, ReadinessImpact::DegradedOnly) => Readiness::Degraded,
        _ => readiness,
    }
}

async fn wait_for_observation<T, Check, Fut>(
    wait_notifies: WaitNotifies<'_>,
    timeout: Duration,
    timeout_label: &'static str,
    after_register: Option<Arc<Barrier>>,
    check: Check,
) -> Result<T, ToyIntegrationError>
where
    Check: Fn() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut after_register = after_register;

    loop {
        match wait_notifies {
            WaitNotifies::One(notify) => {
                let notified = notify.notified();

                if let Some(barrier) = after_register.take() {
                    barrier.wait().await;
                }

                if let Some(value) = check().await {
                    return Ok(value);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(ToyIntegrationError::Timeout(timeout_label));
                }

                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(ToyIntegrationError::Timeout(timeout_label));
                    }
                }
            }
            WaitNotifies::Two(primary, secondary) => {
                let primary_notified = primary.notified();
                let secondary_notified = secondary.notified();

                if let Some(barrier) = after_register.take() {
                    barrier.wait().await;
                }

                if let Some(value) = check().await {
                    return Ok(value);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(ToyIntegrationError::Timeout(timeout_label));
                }

                tokio::select! {
                    _ = primary_notified => {}
                    _ = secondary_notified => {}
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(ToyIntegrationError::Timeout(timeout_label));
                    }
                }
            }
        }
    }
}

async fn build_runtime(
    config_bus: ConfigBus<ToyConfig>,
    state: Arc<RwLock<ToyState>>,
    state_notify: &Arc<Notify>,
    phase_notify: &Arc<Notify>,
    alarm_manager: SharedAlarmManager,
    listener_ready_on_start: bool,
) -> Result<RuntimeHandle, ToyIntegrationError> {
    let config_bus_for_init = config_bus.clone();
    let state_for_init = Arc::clone(&state);
    let state_notify_for_init = Arc::clone(state_notify);
    let phase_notify_for_builder = Arc::clone(phase_notify);

    Builder::new(RuntimeProfile::conformance("toy-nf"))
        .with_alarm_manager(alarm_manager)
        .with_phase_observer(move |_| phase_notify_for_builder.notify_waiters())
        .with_init(move |supervisor, shutdown| {
            let config_bus = config_bus_for_init.clone();
            let state = Arc::clone(&state_for_init);
            let state_notify = Arc::clone(&state_notify_for_init);
            let listener_ready_on_start = listener_ready_on_start;

            Box::pin(async move {
                spawn_config_watcher(
                    &supervisor,
                    &shutdown,
                    config_bus,
                    Arc::clone(&state),
                    Arc::clone(&state_notify),
                )
                .await
                .expect("toy config watcher registration succeeds");
                spawn_health_listener(&supervisor, &shutdown, state, listener_ready_on_start)
                    .await
                    .expect("toy health listener registration succeeds");
            })
        })
        .build()
        .await
        .map_err(Into::into)
}

async fn spawn_config_watcher(
    supervisor: &Supervisor,
    shutdown: &ShutdownToken,
    config_bus: ConfigBus<ToyConfig>,
    state: Arc<RwLock<ToyState>>,
    state_notify: Arc<Notify>,
) -> Result<(), RuntimeError> {
    let shutdown = shutdown.clone();

    supervisor
        .spawn(
            TaskName::new("config-fixture-watcher"),
            TaskKind::Watcher,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
            move || {
                let config_bus = config_bus.clone();
                let shutdown = shutdown.clone();
                let state = Arc::clone(&state);
                let state_notify = Arc::clone(&state_notify);

                Box::pin(async move {
                    let receiver = config_bus.subscribe(SubscriberLagPolicy::DropOldest, 8);
                    update_config_state(&state, &state_notify, config_bus.current_snapshot()).await;

                    loop {
                        tokio::select! {
                            _ = shutdown.shutdown_acknowledged() => return Ok(()),
                            event = receiver.recv() => match event {
                                Some(ConfigEvent::Change(change)) => {
                                    update_config_state_from_parts(
                                        &state,
                                        &state_notify,
                                        change.version,
                                        change.current.as_ref().clone(),
                                    ).await;
                                }
                                Some(ConfigEvent::ResyncRequired { .. }) => {
                                    update_config_state(
                                        &state,
                                        &state_notify,
                                        config_bus.current_snapshot(),
                                    ).await;
                                }
                                None => return Ok(()),
                            }
                        }
                    }
                })
            },
        )
        .await?;

    Ok(())
}

async fn spawn_health_listener(
    supervisor: &Supervisor,
    shutdown: &ShutdownToken,
    state: Arc<RwLock<ToyState>>,
    listener_ready_on_start: bool,
) -> Result<(), RuntimeError> {
    let supervisor_for_task = supervisor.clone();
    let shutdown = shutdown.clone();
    let task_name = TaskName::new("toy-health-listener");
    let task_kind = TaskKind::Listener;
    let criticality = Criticality::Degrade;
    let restart = RestartPolicy::no_restart();
    supervisor
        .register(task_name.clone(), task_kind, criticality, restart)
        .await?;
    supervisor.set_readiness_gated(&task_name, true).await;

    supervisor
        .spawn(
            task_name.clone(),
            // spawn() reuses the metadata from register(), so these values are
            // intentionally shared locals rather than independent settings.
            task_kind,
            criticality,
            restart,
            move || {
                let supervisor = supervisor_for_task.clone();
                let shutdown = shutdown.clone();
                let state = Arc::clone(&state);
                let task_name = task_name.clone();
                let listener_ready_on_start = listener_ready_on_start;

                Box::pin(async move {
                    {
                        let mut state = state.write().await;
                        state.health.set_listeners_bound(true);
                        state.health.set_security_material_valid(true);
                        state.health.set_backends_reachable(true);
                        state.health.set_critical_tasks_healthy(true);
                    }

                    if listener_ready_on_start {
                        supervisor.set_task_ready(&task_name, true).await;
                    }
                    shutdown.shutdown_acknowledged().await;
                    Ok(())
                })
            },
        )
        .await?;

    Ok(())
}

async fn update_config_state(
    state: &Arc<RwLock<ToyState>>,
    state_notify: &Arc<Notify>,
    snapshot: PublishedSnapshot<ToyConfig>,
) {
    update_config_state_from_parts(
        state,
        state_notify,
        snapshot.version,
        snapshot.config.as_ref().clone(),
    )
    .await;
}

async fn update_config_state_from_parts(
    state: &Arc<RwLock<ToyState>>,
    state_notify: &Arc<Notify>,
    version: ConfigVersion,
    config: ToyConfig,
) {
    {
        let mut state = state.write().await;
        state.version = version;
        state.config = config;
        state.health.set_config_applied(true);
    }
    state_notify.notify_waiters();
}

fn toy_principal() -> Result<TrustedPrincipal, ParseError> {
    Ok(TrustedPrincipal::new(
        WorkloadIdentity::Internal("toy-orchestrator".to_string()),
        TenantId::new("system")?,
    ))
}

fn toy_changed_paths(
    current: &ToyObservedConfig,
    candidate: &ToyConfig,
) -> Result<Vec<YangPath>, ToyIntegrationError> {
    let mut paths = Vec::new();

    if current.hostname != candidate.hostname {
        paths.push(YangPath::new("/toy/hostname")?);
    }
    if current.peer_endpoint != candidate.peer_endpoint {
        paths.push(YangPath::new("/toy/peer-endpoint")?);
    }

    if paths.is_empty() {
        paths.push(YangPath::new("/toy")?);
    }

    Ok(paths)
}

fn apply_step(
    step: &Step,
    simulators: &mut BTreeMap<String, FakeSimulator>,
    state: &mut HashMap<String, String>,
) -> Result<(), ToyIntegrationError> {
    match step {
        Step::SendNgap { to, message, .. } => {
            let simulator = simulators
                .get_mut(to)
                .ok_or_else(|| ToyIntegrationError::MissingSimulator(to.clone()))?;
            simulator.handle_step(simulator_step_kind(message)?)?;
            state.insert(format!("{to}.last_ngap"), message.clone());
        }
        Step::ExpectSbi { to, .. } => {
            return Err(ToyIntegrationError::UnsupportedExpectationStep {
                step_kind: "expect_sbi",
                target: to.clone(),
            });
        }
        Step::ExpectNgap { to, .. } => {
            return Err(ToyIntegrationError::UnsupportedExpectationStep {
                step_kind: "expect_ngap",
                target: to.clone(),
            });
        }
        Step::Other
        | Step::SendIkev2(_)
        | Step::ExpectIkev2(_)
        | Step::SendDiameter(_)
        | Step::ExpectDiameter(_)
        | Step::SendGtpv2c(_)
        | Step::ExpectGtpv2c(_)
        | Step::SendGtpu(_)
        | Step::ExpectGtpu(_)
        | Step::ExpectEsp(_)
        | Step::PeerUnavailable { .. }
        | Step::PeerDown { .. }
        | Step::Timeout { .. }
        | Step::Retransmission { .. }
        | Step::PacketLoss { .. }
        | Step::DuplicatePacket { .. }
        | Step::DelayedResponse { .. }
        | Step::MalformedResponse { .. }
        | Step::DependencyTimeout { .. }
        | Step::ClockJump { .. }
        | Step::ProcessRestart { .. }
        | Step::NetworkPartition { .. } => {
            return Err(ToyIntegrationError::UnsupportedScenarioStep)
        }
    }

    Ok(())
}

fn simulator_step_kind(message: &str) -> Result<&'static str, ToyIntegrationError> {
    match message.trim().to_ascii_lowercase().as_str() {
        "registration" | "initialuemessage.registration_request" => Ok("registration"),
        "session"
        | "pdusessionresourcesetup.session_establishment"
        | "pdusessionresourcesetuprequest.session_establishment" => Ok("session"),
        _ => Err(ToyIntegrationError::UnsupportedNgapMessage(
            message.to_string(),
        )),
    }
}

fn scenario_outcome(scenario: &Scenario, state: &HashMap<String, String>) -> ScenarioOutcome {
    let mut skipped = false;

    for assertion in &scenario.assertions {
        match evaluate(assertion, state) {
            AssertionOutcome::Pass => {}
            AssertionOutcome::Fail { .. } => return ScenarioOutcome::Fail,
            AssertionOutcome::Skipped => skipped = true,
        }
    }

    if skipped {
        ScenarioOutcome::Error
    } else {
        ScenarioOutcome::Pass
    }
}

async fn wait_for_fatal_task_failure(
    supervisor: &Supervisor,
    shutdown: &ShutdownToken,
) -> (TaskName, opc_runtime::task::TaskError) {
    wait_for_fatal_task_failure_with(|| supervisor.fatal_task_failure(), shutdown).await
}

async fn wait_for_fatal_task_failure_with<F, Fut, T>(
    mut fatal_task_failure: F,
    shutdown: &ShutdownToken,
) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    loop {
        if let Some(fatal) = fatal_task_failure().await {
            return fatal;
        }

        tokio::select! {
            _ = shutdown.shutdown_acknowledged() => {
                if let Some(fatal) = fatal_task_failure().await {
                    return fatal;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::task::JoinHandle;

    #[tokio::test(flavor = "current_thread")]
    async fn startup_timeout_shuts_runtime_down_before_returning_error() {
        let initial_config = ToyConfig::default();
        let alarms = SharedAlarmManager::default();
        let config_bus = ConfigBus::new_with_alarm_manager_dev_only(
            initial_config.clone(),
            MockManagedDatastore::new(),
            alarms.clone(),
        )
        .await
        .expect("config bus starts");
        let state = Arc::new(RwLock::new(ToyState::new(initial_config)));
        let state_notify = Arc::new(Notify::new());
        let phase_notify = Arc::new(Notify::new());

        let runtime = build_runtime(
            config_bus.clone(),
            Arc::clone(&state),
            &state_notify,
            &phase_notify,
            alarms.clone(),
            false,
        )
        .await
        .expect("runtime starts");
        let runtime_probe = runtime.clone();

        let toy = ToyNetworkFunction {
            runtime,
            config_bus,
            state,
            state_notify,
            phase_notify,
            alarms,
        };

        let err = match toy.complete_startup(Duration::from_millis(50)).await {
            Ok(_) => panic!("startup should time out when listener readiness is withheld"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ToyIntegrationError::Timeout("runtime readiness")
        ));
        assert!(runtime_probe.is_stopped().await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_observation_single_notify_handles_transition_after_registration() {
        let observed = Arc::new(RwLock::new(0_u64));
        let notify = Arc::new(Notify::new());
        let barrier = Arc::new(Barrier::new(2));

        let waiter: JoinHandle<Result<u64, ToyIntegrationError>> = {
            let observed = Arc::clone(&observed);
            let notify = Arc::clone(&notify);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                wait_for_observation(
                    WaitNotifies::One(&notify),
                    Duration::from_millis(50),
                    "test value",
                    Some(barrier),
                    || {
                        let observed = Arc::clone(&observed);
                        async move {
                            let value = *observed.read().await;
                            (value >= 1).then_some(value)
                        }
                    },
                )
                .await
            })
        };

        barrier.wait().await;
        *observed.write().await = 1;
        notify.notify_waiters();

        assert_eq!(
            waiter
                .await
                .expect("waiter task joins")
                .expect("value observed"),
            1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_observation_dual_notify_handles_transition_after_registration() {
        let ready = Arc::new(RwLock::new(false));
        let phase_notify = Arc::new(Notify::new());
        let state_notify = Arc::new(Notify::new());
        let barrier = Arc::new(Barrier::new(2));

        let waiter: JoinHandle<Result<(), ToyIntegrationError>> = {
            let ready = Arc::clone(&ready);
            let phase_notify = Arc::clone(&phase_notify);
            let state_notify = Arc::clone(&state_notify);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                wait_for_observation(
                    WaitNotifies::Two(&phase_notify, &state_notify),
                    Duration::from_millis(50),
                    "test readiness",
                    Some(barrier),
                    || {
                        let ready = Arc::clone(&ready);
                        async move { (*ready.read().await).then_some(()) }
                    },
                )
                .await
            })
        };

        barrier.wait().await;
        *ready.write().await = true;
        phase_notify.notify_waiters();

        waiter
            .await
            .expect("waiter task joins")
            .expect("readiness observed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_fatal_task_failure_observes_delayed_failure_without_shutdown() {
        let shutdown = ShutdownToken::new();
        let fatal_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiter = {
            let shutdown = shutdown.clone();
            let fatal_ready = Arc::clone(&fatal_ready);
            tokio::spawn(async move {
                wait_for_fatal_task_failure_with(
                    move || {
                        let fatal_ready = Arc::clone(&fatal_ready);
                        async move {
                            fatal_ready
                                .load(std::sync::atomic::Ordering::SeqCst)
                                .then_some("fatal")
                        }
                    },
                    &shutdown,
                )
                .await
            })
        };

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        fatal_ready.store(true, std::sync::atomic::Ordering::SeqCst);

        let observed = tokio::time::timeout(Duration::from_millis(50), waiter)
            .await
            .expect("fatal failure should surface before shutdown is requested")
            .expect("waiter task joins");

        assert_eq!(observed, "fatal");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_fatal_task_failure_observes_delayed_failure_after_shutdown_request() {
        let shutdown = ShutdownToken::new();
        shutdown.request_shutdown();
        let fatal_ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fatal_checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waiter = {
            let shutdown = shutdown.clone();
            let fatal_ready = Arc::clone(&fatal_ready);
            let fatal_checks = Arc::clone(&fatal_checks);
            tokio::spawn(async move {
                wait_for_fatal_task_failure_with(
                    move || {
                        let fatal_ready = Arc::clone(&fatal_ready);
                        let fatal_checks = Arc::clone(&fatal_checks);
                        async move {
                            fatal_checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            fatal_ready
                                .load(std::sync::atomic::Ordering::SeqCst)
                                .then_some("fatal")
                        }
                    },
                    &shutdown,
                )
                .await
            })
        };

        tokio::time::sleep(Duration::from_millis(5)).await;
        fatal_ready.store(true, std::sync::atomic::Ordering::SeqCst);

        let observed = tokio::time::timeout(Duration::from_millis(50), waiter)
            .await
            .expect("fatal failure should surface even after shutdown is requested")
            .expect("waiter task joins");

        assert_eq!(observed, "fatal");
        assert!(
            fatal_checks.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "shutdown polling should re-check for a delayed fatal failure"
        );
    }
}
