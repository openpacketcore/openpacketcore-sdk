use std::collections::{HashMap, VecDeque};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::manager::admin::{AlarmAction, AlarmActionContext, SuppressionAuth};
use crate::manager::audit::{AlarmAuditEvent, AlarmAuditOutcome, AlarmAuditSink};
use crate::manager::security::{alarm_requires_explicit_suppression_policy, AlarmActionAuthorizer};
use crate::model::{
    AffectedObject, Alarm, AlarmDetails, AlarmId, AlarmState, AlarmType, DedupKey, ProbableCause,
    RedactedText, RegionId, Severity,
};

pub const DEFAULT_HISTORY_LIMIT: usize = 4_096;

/// Result of a manager operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmOpResult {
    /// Alarm was raised (new active active alarm created).
    Raised { alarm: Alarm },
    /// Alarm was updated (existing alarm modified).
    Updated { alarm: Alarm },
    /// Alarm was cleared.
    Cleared { alarm_id: AlarmId },
    /// Clear requested but no matching active alarm exists.
    ClearWithoutActive {
        dedup_key: DedupKey,
        cause: ProbableCause,
    },
    /// Alarm was suppressed.
    Suppressed { alarm: Alarm },
    /// Alarm was acknowledged.
    Acknowledged { alarm: Alarm },
    /// Operation denied due to authorization failure.
    Unauthorized { message: String },
    /// Operation was authorized but could not be durably audited.
    AuditFailed { message: String },
    /// Alarm ID not found in the store.
    NotFound { alarm_id: AlarmId },
}

/// Alarm store trait for dependency injection.
pub trait AlarmStore {
    fn insert(&mut self, alarm: Alarm);
    fn update(&mut self, alarm: Alarm);
    fn get_by_id(&self, alarm_id: &AlarmId) -> Option<Alarm>;
    fn get_by_dedup_key(&self, dedup_key: &DedupKey) -> Option<Alarm>;
    fn active_alarms(&self) -> Vec<Alarm>;
    fn all(&self) -> Vec<Alarm>;
    fn history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        self.all()
            .into_iter()
            .filter(|alarm| alarm_matches_scope(alarm, tenant, slice))
            .collect()
    }
    fn active_count(&self) -> usize {
        self.active_alarms().len()
    }
}

/// Alarm manager holding active alarms and handling raise/update/clear.
pub struct AlarmManager<S: AlarmStore> {
    pub(crate) store: S,
}

impl<S: AlarmStore> AlarmManager<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub(crate) fn update_global_metrics(&self) {
        crate::manager::metrics::update_global_metrics(&self.store.active_alarms());
    }

    /// Raises or updates an alarm based on deduplication.
    #[allow(clippy::too_many_arguments)]
    pub fn raise(
        &mut self,
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
        let dedup_key = DedupKey::compute(
            &alarm_type,
            &probable_cause,
            &affected_object,
            tenant.as_deref(),
            slice.as_deref(),
            region.as_ref().map(|r| r.as_str()),
        );

        let now = OffsetDateTime::now_utc();

        let res = if let Some(existing) = self.store.get_by_dedup_key(&dedup_key) {
            if !existing.state.is_active() {
                let alarm = Self::new_alarm(
                    alarm_type,
                    severity,
                    probable_cause,
                    affected_object,
                    tenant,
                    slice,
                    region,
                    text,
                    details,
                    now,
                );
                self.store.insert(alarm.clone());
                AlarmOpResult::Raised { alarm }
            } else {
                let mut updated = existing.clone();
                updated.severity = severity;
                updated.text = text;
                updated.details = details;
                updated.updated_at = now;
                updated.state = match existing.state {
                    AlarmState::Acknowledged => AlarmState::Acknowledged,
                    AlarmState::Suppressed => AlarmState::Suppressed,
                    AlarmState::Raised | AlarmState::Updated => AlarmState::Updated,
                    AlarmState::Cleared | AlarmState::Expired => {
                        unreachable!("inactive alarms are handled before active updates")
                    }
                };

                self.store.update(updated.clone());
                AlarmOpResult::Updated { alarm: updated }
            }
        } else {
            let alarm = Self::new_alarm(
                alarm_type,
                severity,
                probable_cause,
                affected_object,
                tenant,
                slice,
                region,
                text,
                details,
                now,
            );

            self.store.insert(alarm.clone());
            AlarmOpResult::Raised { alarm }
        };

        self.update_global_metrics();
        res
    }

    /// Clears an alarm by dedup key.
    pub fn clear(
        &mut self,
        alarm_type: &AlarmType,
        probable_cause: ProbableCause,
        affected_object: &AffectedObject,
        tenant: Option<&str>,
        slice: Option<&str>,
        region: Option<&str>,
    ) -> AlarmOpResult {
        let dedup_key = DedupKey::compute(
            alarm_type,
            &probable_cause,
            affected_object,
            tenant,
            slice,
            region,
        );

        let res = if let Some(mut alarm) = self.store.get_by_dedup_key(&dedup_key) {
            if !alarm.state.is_active() {
                AlarmOpResult::ClearWithoutActive {
                    dedup_key,
                    cause: probable_cause,
                }
            } else {
                let now = OffsetDateTime::now_utc();
                alarm.state = AlarmState::Cleared;
                alarm.cleared_at = Some(now);
                alarm.updated_at = now;
                alarm.severity = Severity::Cleared;

                self.store.update(alarm.clone());
                AlarmOpResult::Cleared {
                    alarm_id: alarm.alarm_id,
                }
            }
        } else {
            AlarmOpResult::ClearWithoutActive {
                dedup_key,
                cause: probable_cause,
            }
        };

        self.update_global_metrics();
        res
    }

    pub fn acknowledge(&mut self, alarm_id: &AlarmId, auth: &SuppressionAuth) -> AlarmOpResult {
        if !auth.authorized {
            return AlarmOpResult::Unauthorized {
                message: "acknowledge not authorized".to_string(),
            };
        }

        if let Some(mut alarm) = self.store.get_by_id(alarm_id) {
            if !alarm.state.is_active() {
                return AlarmOpResult::NotFound {
                    alarm_id: alarm_id.clone(),
                };
            }
            alarm.state = AlarmState::Acknowledged;
            alarm.updated_at = OffsetDateTime::now_utc();
            self.store.update(alarm.clone());
            AlarmOpResult::Acknowledged { alarm }
        } else {
            AlarmOpResult::NotFound {
                alarm_id: alarm_id.clone(),
            }
        }
    }

    pub fn acknowledge_with_policy<A, T>(
        &mut self,
        alarm_id: &AlarmId,
        context: &AlarmActionContext,
        authorizer: &A,
        audit_sink: &mut T,
    ) -> AlarmOpResult
    where
        A: AlarmActionAuthorizer,
        T: AlarmAuditSink,
    {
        self.apply_admin_action(
            alarm_id,
            AlarmAction::Acknowledge,
            context,
            authorizer,
            audit_sink,
        )
    }

    pub fn suppress(&mut self, alarm_id: &AlarmId, auth: &SuppressionAuth) -> AlarmOpResult {
        if !auth.authorized {
            return AlarmOpResult::Unauthorized {
                message: "suppress not authorized".to_string(),
            };
        }

        if let Some(mut alarm) = self.store.get_by_id(alarm_id) {
            if !alarm.state.is_active() {
                return AlarmOpResult::NotFound {
                    alarm_id: alarm_id.clone(),
                };
            }
            alarm.state = AlarmState::Suppressed;
            alarm.updated_at = OffsetDateTime::now_utc();
            self.store.update(alarm.clone());
            AlarmOpResult::Suppressed { alarm }
        } else {
            AlarmOpResult::NotFound {
                alarm_id: alarm_id.clone(),
            }
        }
    }

    pub fn suppress_with_policy<A, T>(
        &mut self,
        alarm_id: &AlarmId,
        context: &AlarmActionContext,
        authorizer: &A,
        audit_sink: &mut T,
    ) -> AlarmOpResult
    where
        A: AlarmActionAuthorizer,
        T: AlarmAuditSink,
    {
        self.apply_admin_action(
            alarm_id,
            AlarmAction::Suppress,
            context,
            authorizer,
            audit_sink,
        )
    }

    fn apply_admin_action<A, T>(
        &mut self,
        alarm_id: &AlarmId,
        action: AlarmAction,
        context: &AlarmActionContext,
        authorizer: &A,
        audit_sink: &mut T,
    ) -> AlarmOpResult
    where
        A: AlarmActionAuthorizer,
        T: AlarmAuditSink,
    {
        let Some(mut alarm) = self.store.get_by_id(alarm_id) else {
            return AlarmOpResult::NotFound {
                alarm_id: alarm_id.clone(),
            };
        };

        if !alarm.state.is_active() {
            return AlarmOpResult::NotFound {
                alarm_id: alarm_id.clone(),
            };
        }

        if action == AlarmAction::Suppress
            && alarm_requires_explicit_suppression_policy(&alarm)
            && !authorizer.allow_security_critical_suppression(&alarm, context)
        {
            let message =
                "security-critical alarm suppression requires explicit policy override".to_string();
            let res = audit_sink.record_alarm_action(AlarmAuditEvent::from_action(
                action,
                AlarmAuditOutcome::Denied,
                &alarm,
                context,
            ));
            if res.is_ok() {
                crate::manager::metrics::record_audit_success();
            } else {
                crate::manager::metrics::record_audit_failure();
            }
            return AlarmOpResult::Unauthorized { message };
        }

        if let Err(denied) = authorizer.authorize_alarm_action(action, &alarm, context) {
            let res = audit_sink.record_alarm_action(AlarmAuditEvent::from_action(
                action,
                AlarmAuditOutcome::Denied,
                &alarm,
                context,
            ));
            if res.is_ok() {
                crate::manager::metrics::record_audit_success();
            } else {
                crate::manager::metrics::record_audit_failure();
            }
            return AlarmOpResult::Unauthorized {
                message: denied.message,
            };
        }

        if let Err(message) = audit_sink.record_alarm_action(AlarmAuditEvent::from_action(
            action,
            AlarmAuditOutcome::Authorized,
            &alarm,
            context,
        )) {
            crate::manager::metrics::record_audit_failure();
            return AlarmOpResult::AuditFailed { message };
        }
        crate::manager::metrics::record_audit_success();

        alarm.state = match action {
            AlarmAction::Acknowledge => AlarmState::Acknowledged,
            AlarmAction::Suppress => AlarmState::Suppressed,
        };
        alarm.updated_at = OffsetDateTime::now_utc();
        self.store.update(alarm.clone());
        self.update_global_metrics();

        match action {
            AlarmAction::Acknowledge => AlarmOpResult::Acknowledged { alarm },
            AlarmAction::Suppress => AlarmOpResult::Suppressed { alarm },
        }
    }

    pub fn active_alarms(&self) -> Vec<Alarm> {
        self.store.active_alarms()
    }

    pub fn active_count(&self) -> usize {
        self.store.active_count()
    }

    pub fn active_by_severity(&self, severity: Severity) -> Vec<Alarm> {
        self.store
            .active_alarms()
            .into_iter()
            .filter(|a| a.severity == severity)
            .collect()
    }

    pub fn all_alarms(&self) -> Vec<Alarm> {
        self.store.all()
    }

    pub fn alarm_history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        self.store.history_by_scope(tenant, slice)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_alarm(
        alarm_type: AlarmType,
        severity: Severity,
        probable_cause: ProbableCause,
        affected_object: AffectedObject,
        tenant: Option<String>,
        slice: Option<String>,
        region: Option<RegionId>,
        text: RedactedText,
        details: AlarmDetails,
        now: OffsetDateTime,
    ) -> Alarm {
        Alarm {
            alarm_id: AlarmId::new(Uuid::new_v4().to_string()),
            alarm_type,
            severity,
            probable_cause,
            affected_object,
            tenant,
            slice,
            region,
            text,
            details,
            state: AlarmState::Raised,
            raised_at: now,
            updated_at: now,
            cleared_at: None,
            correlation_id: None,
        }
    }
}

/// In-memory alarm store used by tests and simple CNF deployments.
pub struct InMemoryStore {
    pub(crate) by_id: HashMap<AlarmId, Alarm>,
    pub(crate) by_dedup_key: HashMap<DedupKey, AlarmId>,
    pub(crate) history: VecDeque<Alarm>,
    pub(crate) history_limit: usize,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::new_with_history_limit(DEFAULT_HISTORY_LIMIT)
    }

    pub fn new_with_history_limit(history_limit: usize) -> Self {
        assert!(
            history_limit > 0,
            "InMemoryStore history_limit must be greater than zero"
        );
        Self {
            by_id: HashMap::new(),
            by_dedup_key: HashMap::new(),
            history: VecDeque::with_capacity(history_limit),
            history_limit,
        }
    }

    fn reindex(&mut self, alarm: &Alarm) {
        let dedup_key = alarm.dedup_key();
        self.by_dedup_key.insert(dedup_key, alarm.alarm_id.clone());
    }

    pub(crate) fn insert(&mut self, alarm: Alarm) {
        if alarm.state.is_active() {
            let alarm_id = alarm.alarm_id.clone();
            self.reindex(&alarm);
            self.by_id.insert(alarm_id, alarm.clone());
        }
        self.record_history(alarm);
    }

    pub(crate) fn update(&mut self, alarm: Alarm) {
        let dedup_key = alarm.dedup_key();
        let alarm_id = alarm.alarm_id.clone();
        if alarm.state.is_active() {
            let replaced = self.by_id.insert(alarm.alarm_id.clone(), alarm.clone());
            debug_assert!(
                replaced.is_some(),
                "InMemoryStore::update called for unknown active alarm_id {}",
                alarm.alarm_id
            );
            self.by_dedup_key.insert(dedup_key, alarm_id);
        } else {
            let removed = self.by_id.remove(&alarm.alarm_id);
            debug_assert!(
                removed.is_some(),
                "InMemoryStore::update called for unknown terminal alarm_id {}",
                alarm.alarm_id
            );
            self.by_dedup_key.remove(&dedup_key);
        }
        self.record_history(alarm);
    }

    pub(crate) fn get_by_id(&self, alarm_id: &AlarmId) -> Option<Alarm> {
        self.by_id.get(alarm_id).cloned()
    }

    pub(crate) fn get_by_dedup_key(&self, dedup_key: &DedupKey) -> Option<Alarm> {
        self.by_dedup_key
            .get(dedup_key)
            .and_then(|id| self.by_id.get(id))
            .cloned()
    }

    pub(crate) fn active_alarms(&self) -> Vec<Alarm> {
        self.by_id.values().cloned().collect()
    }

    pub(crate) fn all(&self) -> Vec<Alarm> {
        self.history.iter().cloned().collect()
    }

    pub(crate) fn history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        self.history
            .iter()
            .filter(|alarm| alarm_matches_scope(alarm, tenant, slice))
            .cloned()
            .collect()
    }

    fn record_history(&mut self, alarm: Alarm) {
        if self
            .history
            .back()
            .is_some_and(|last| same_history_identity(last, &alarm))
        {
            if let Some(last) = self.history.back_mut() {
                *last = alarm;
            }
            return;
        }

        if self.history.len() == self.history_limit {
            self.history.pop_front();
        }
        self.history.push_back(alarm);
    }

    pub(crate) fn active_count(&self) -> usize {
        self.by_id.len()
    }
}

impl AlarmStore for InMemoryStore {
    fn insert(&mut self, alarm: Alarm) {
        InMemoryStore::insert(self, alarm);
    }

    fn update(&mut self, alarm: Alarm) {
        InMemoryStore::update(self, alarm);
    }

    fn get_by_id(&self, alarm_id: &AlarmId) -> Option<Alarm> {
        InMemoryStore::get_by_id(self, alarm_id)
    }

    fn get_by_dedup_key(&self, dedup_key: &DedupKey) -> Option<Alarm> {
        InMemoryStore::get_by_dedup_key(self, dedup_key)
    }

    fn active_alarms(&self) -> Vec<Alarm> {
        InMemoryStore::active_alarms(self)
    }

    fn all(&self) -> Vec<Alarm> {
        InMemoryStore::all(self)
    }

    fn history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        InMemoryStore::history_by_scope(self, tenant, slice)
    }

    fn active_count(&self) -> usize {
        InMemoryStore::active_count(self)
    }
}

fn alarm_matches_scope(alarm: &Alarm, tenant: Option<&str>, slice: Option<&str>) -> bool {
    let tenant_matches = tenant.map_or(true, |expected| alarm.tenant.as_deref() == Some(expected));
    let slice_matches = slice.map_or(true, |expected| alarm.slice.as_deref() == Some(expected));
    tenant_matches && slice_matches
}

fn same_history_identity(left: &Alarm, right: &Alarm) -> bool {
    left.alarm_id == right.alarm_id
        && left.alarm_type == right.alarm_type
        && left.severity == right.severity
        && left.probable_cause == right.probable_cause
        && left.affected_object == right.affected_object
        && left.tenant == right.tenant
        && left.slice == right.slice
        && left.region == right.region
        && left.state == right.state
}
