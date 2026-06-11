use std::sync::{Arc, Mutex, MutexGuard};

pub mod admin;
pub mod audit;
pub mod metrics;
pub mod security;
pub mod state;

#[cfg(test)]
mod tests;

pub use admin::{
    AlarmAction, AlarmActionContext, AlarmActionDenied, AlarmActionScope, SuppressionAuth,
};
pub use audit::{AlarmAuditEvent, AlarmAuditOutcome, AlarmAuditSink};
pub use security::AlarmActionAuthorizer;
pub use state::{AlarmManager, AlarmOpResult, AlarmStore, InMemoryStore, DEFAULT_HISTORY_LIMIT};

use crate::model::{
    AffectedObject, Alarm, AlarmDetails, AlarmType, ProbableCause, RedactedText, RegionId, Severity,
};

/// Thread-safe shared in-memory alarm manager for runtime-wide alarm plumbing.
#[derive(Clone)]
pub struct SharedAlarmManager {
    inner: Arc<Mutex<AlarmManager<InMemoryStore>>>,
}

impl std::fmt::Debug for SharedAlarmManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedAlarmManager").finish_non_exhaustive()
    }
}

impl Default for SharedAlarmManager {
    fn default() -> Self {
        Self::new(AlarmManager::new(InMemoryStore::new()))
    }
}

impl SharedAlarmManager {
    pub fn new(manager: AlarmManager<InMemoryStore>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(manager)),
        }
    }

    pub fn in_memory() -> Self {
        Self::default()
    }

    pub fn lock(&self) -> MutexGuard<'_, AlarmManager<InMemoryStore>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn raise(
        &self,
        alarm_type: AlarmType,
        severity: Severity,
        probable_cause: ProbableCause,
        affected_object: AffectedObject,
        tenant: Option<String>,
        slice: Option<String>,
        region: Option<RegionId>,
        text: RedactedText,
        details: AlarmDetails,
    ) -> AlarmOpResult {
        self.lock().raise(
            alarm_type,
            severity,
            probable_cause,
            affected_object,
            tenant,
            slice,
            region,
            text,
            details,
        )
    }

    pub fn clear(
        &self,
        alarm_type: &AlarmType,
        probable_cause: ProbableCause,
        affected_object: &AffectedObject,
        tenant: Option<&str>,
        slice: Option<&str>,
        region: Option<&str>,
    ) -> AlarmOpResult {
        self.lock().clear(
            alarm_type,
            probable_cause,
            affected_object,
            tenant,
            slice,
            region,
        )
    }

    pub fn active_alarms(&self) -> Vec<Alarm> {
        self.lock().active_alarms()
    }

    pub fn active_count(&self) -> usize {
        self.lock().active_count()
    }

    pub fn all_alarms(&self) -> Vec<Alarm> {
        self.lock().all_alarms()
    }

    pub fn alarm_history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        self.lock().alarm_history_by_scope(tenant, slice)
    }
}
