//! Reusable test fixtures and builders for opc-amf-lite network functions.
//!
//! Provides standardised test fixtures, config setups, and validation boundaries.

use std::sync::Arc;

use opc_alarm::SharedAlarmManager;
use opc_alarm_testkit::AlarmAsserter;
use opc_nacm::{ModuleRegistry, NacmPolicy, PolicyVersion};
use opc_runtime::{ResourceBudget, RuntimeMode, RuntimeProfile};
use opc_testbed::VirtualClock;
use opc_types::Timestamp;

/// Reusable AMF-lite test fixture orchestrating configuration, policy, and timers.
pub struct AmfTestFixture {
    pub runtime_profile: RuntimeProfile,
    pub alarm_manager: SharedAlarmManager,
    pub nacm_policy: Arc<NacmPolicy>,
    pub modules: Arc<ModuleRegistry>,
    pub clock: VirtualClock,
}

impl Default for AmfTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl AmfTestFixture {
    /// Creates a default AMF-lite test fixture in `Lab` mode.
    pub fn new() -> Self {
        let budget = ResourceBudget {
            max_tasks: 100,
            max_queue_bytes: 1024 * 1024,
            max_heap_bytes: Some(1024 * 1024 * 1024),
            max_open_files: 1024,
            ..ResourceBudget::default()
        };
        let runtime_profile = RuntimeProfile {
            mode: RuntimeMode::Lab,
            budget: Some(budget),
            ..RuntimeProfile::default()
        };

        Self {
            runtime_profile,
            alarm_manager: SharedAlarmManager::default(),
            nacm_policy: Arc::new(NacmPolicy::empty(PolicyVersion::new(1))),
            modules: Arc::new(ModuleRegistry::default()),
            clock: VirtualClock::new(Timestamp::now_utc()),
        }
    }

    /// Sets the runtime mode.
    pub fn with_runtime_mode(mut self, mode: RuntimeMode) -> Self {
        self.runtime_profile.mode = mode;
        self
    }

    /// Sets the security / NACM policy.
    pub fn with_nacm_policy(mut self, policy: NacmPolicy) -> Self {
        self.nacm_policy = Arc::new(policy);
        self
    }

    /// Exposes a fluent alarm asserter.
    pub fn assert_alarms<'a>(&self, alarms: &'a [opc_alarm::Alarm]) -> AlarmAsserter<'a> {
        AlarmAsserter::new(alarms)
    }
}

/// A documented pattern for future CNF testkits (e.g. SMF, UPF).
/// These will be created when their respective production CNFs are introduced.
pub struct CnfTestkitPatternDoc;

impl CnfTestkitPatternDoc {
    pub fn pattern_description() -> &'static str {
        "Downstream CNF testkits (such as opc-smf-testkit and opc-upf-testkit) should follow the AmfTestFixture pattern:\n\
         1. Expose standard builders for RuntimeProfile and ResourceBudget.\n\
         2. Expose a helper to fetch/wire the SharedAlarmManager.\n\
         3. Integrate alarm validation using opc-alarm-testkit's assert_redacted and AlarmAsserter.\n\
         4. Do not invent standalone mock datastores; use the testbed simulators and quorum session replicas."
    }
}
