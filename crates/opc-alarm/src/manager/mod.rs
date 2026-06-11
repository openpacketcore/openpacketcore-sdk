//! Alarm manager: dedup-driven raise/update/clear plus authorized,
//! audited acknowledge/suppress per RFC 013 §8–§10.
//!
//! Submodules:
//!
//! - `state` — manager core, the pluggable `AlarmStore` trait, and the
//!   bounded `InMemoryStore`.
//! - `admin` — acknowledgement/suppression request types (action, scope,
//!   context, denial).
//! - `security` — authorization policy hooks; security-critical alarms are
//!   non-suppressible by default.
//! - `audit` — fail-closed audit events for admin actions.
//! - `metrics` — global active-alarm gauges and audit counters.

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
    /// Wraps an existing manager in `Arc<Mutex<_>>` so clones can be handed to
    /// independent tasks; all clones operate on the same alarm state.
    pub fn new(manager: AlarmManager<InMemoryStore>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(manager)),
        }
    }

    /// Creates a shared manager over a fresh `InMemoryStore` with the default
    /// history limit (`DEFAULT_HISTORY_LIMIT`).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Locks the inner manager for multi-step operations (e.g. acknowledge
    /// with policy and audit). A poisoned mutex is recovered rather than
    /// propagated, since alarm state mutations are self-contained. Keep the
    /// guard short-lived: raising alarms is meant to stay cheap and
    /// non-blocking per RFC 013 §3.2.
    pub fn lock(&self) -> MutexGuard<'_, AlarmManager<InMemoryStore>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Raises a new alarm or updates the active alarm with the same dedup key
    /// (`alarm_type`/`probable_cause`/`affected_object`/`tenant`/`slice`/
    /// `region`). Locks the shared manager for the duration of the single
    /// call; see `AlarmManager::raise` for the lifecycle semantics.
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

    /// Clears the active alarm matching the recomputed dedup key, if any.
    /// A clear with no matching active alarm is a recorded no-op
    /// (`AlarmOpResult::ClearWithoutActive`), never an error, per RFC 013 §8.
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

    /// Returns a point-in-time snapshot of all active (raised, updated,
    /// acknowledged, or suppressed) alarms. Suppressed alarms are included:
    /// suppression affects presentation, not activeness.
    pub fn active_alarms(&self) -> Vec<Alarm> {
        self.lock().active_alarms()
    }

    /// Returns the number of currently active alarms without cloning them.
    pub fn active_count(&self) -> usize {
        self.lock().active_count()
    }

    /// Returns the retained lifecycle history (active and terminal records),
    /// bounded by the store's history limit — older entries may already have
    /// been evicted.
    pub fn all_alarms(&self) -> Vec<Alarm> {
        self.lock().all_alarms()
    }

    /// Returns history filtered by tenant and/or slice. A `None` filter
    /// matches every alarm; a `Some` filter matches only alarms whose
    /// corresponding scope field equals the given value (alarms without that
    /// scope are excluded).
    pub fn alarm_history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        self.lock().alarm_history_by_scope(tenant, slice)
    }
}
