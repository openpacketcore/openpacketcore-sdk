//! Alarm manager core: dedup-keyed raise/update/clear semantics, the
//! pluggable `AlarmStore` abstraction, and a bounded in-memory store whose
//! history ring evicts the oldest record on overflow.

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

/// Default bound on the `InMemoryStore` history ring (4096 lifecycle
/// records). When the ring is full, the oldest history entry is evicted to
/// admit the newest one; active-alarm indexes are unaffected by eviction, so
/// alarm storms cannot grow memory without bound (RFC 013 §19.4).
pub const DEFAULT_HISTORY_LIMIT: usize = 4_096;

/// Result of a manager operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmOpResult {
    /// Alarm was raised (new active active alarm created).
    Raised {
        /// Snapshot of the newly created alarm (state `Raised`, fresh id).
        alarm: Alarm,
    },
    /// Alarm was updated (existing alarm modified).
    Updated {
        /// Post-update snapshot: same alarm id, refreshed severity, text,
        /// details, and `updated_at`.
        alarm: Alarm,
    },
    /// Alarm was cleared.
    Cleared {
        /// Id of the alarm that transitioned to the terminal `Cleared` state.
        alarm_id: AlarmId,
    },
    /// Clear requested but no matching active alarm exists.
    ClearWithoutActive {
        /// Dedup key computed from the clear request, for which no active
        /// alarm was found.
        dedup_key: DedupKey,
        /// Probable cause from the clear request, kept so callers can emit
        /// the clear-without-active no-op metric per RFC 013 §8/§16.
        cause: ProbableCause,
    },
    /// Alarm was suppressed.
    Suppressed {
        /// Snapshot of the alarm after entering the `Suppressed` state; the
        /// alarm remains active and its history is preserved.
        alarm: Alarm,
    },
    /// Alarm was acknowledged.
    Acknowledged {
        /// Snapshot of the alarm after entering the `Acknowledged` state;
        /// acknowledgement does not clear the fault.
        alarm: Alarm,
    },
    /// Operation denied due to authorization failure.
    Unauthorized {
        /// Human-readable denial reason; no state change was applied, and on
        /// the policy paths the denial itself has been audited.
        message: String,
    },
    /// Operation was authorized but could not be durably audited.
    AuditFailed {
        /// Reason the audit record could not be written. The state change was
        /// abandoned: admin actions are fail-closed on audit failure.
        message: String,
    },
    /// Alarm ID not found in the store.
    NotFound {
        /// The requested id; either unknown or referring to an alarm that is
        /// no longer active (terminal alarms cannot be acknowledged or
        /// suppressed).
        alarm_id: AlarmId,
    },
}

/// Alarm store trait for dependency injection.
pub trait AlarmStore {
    /// Stores a newly raised alarm and appends it to history. When the alarm
    /// is active, the implementation must also index it by dedup key so later
    /// raises with the same identity merge into it.
    fn insert(&mut self, alarm: Alarm);
    /// Replaces the stored record for an existing alarm id and appends the
    /// new revision to history. A transition to a terminal state
    /// (cleared/expired) must remove the alarm from the active set and the
    /// dedup index so a future raise creates a fresh alarm.
    fn update(&mut self, alarm: Alarm);
    /// Looks up an *active* alarm by id. Terminal alarms return `None`; they
    /// are only reachable through history queries.
    fn get_by_id(&self, alarm_id: &AlarmId) -> Option<Alarm>;
    /// Looks up the active alarm carrying this dedup key — the identity the
    /// manager uses to decide between raise (new alarm) and update (existing
    /// alarm), and to resolve clears.
    fn get_by_dedup_key(&self, dedup_key: &DedupKey) -> Option<Alarm>;
    /// Returns a snapshot of every active alarm (raised, updated,
    /// acknowledged, or suppressed). Ordering is implementation-defined.
    fn active_alarms(&self) -> Vec<Alarm>;
    /// Returns the retained lifecycle history (active and terminal records),
    /// bounded by the implementation's retention policy.
    fn all(&self) -> Vec<Alarm>;
    /// Returns history filtered by tenant and/or slice; `None` acts as a
    /// wildcard, while `Some(v)` matches only alarms whose scope field equals
    /// `v`. The default implementation filters the result of `all`.
    fn history_by_scope(&self, tenant: Option<&str>, slice: Option<&str>) -> Vec<Alarm> {
        self.all()
            .into_iter()
            .filter(|alarm| alarm_matches_scope(alarm, tenant, slice))
            .collect()
    }
    /// Returns the number of active alarms. The default implementation counts
    /// the `active_alarms` snapshot; implementations should override it with a
    /// cheaper counter where possible.
    fn active_count(&self) -> usize {
        self.active_alarms().len()
    }
}

/// Alarm manager holding active alarms and handling raise/update/clear.
pub struct AlarmManager<S: AlarmStore> {
    pub(crate) store: S,
}

impl<S: AlarmStore> AlarmManager<S> {
    /// Creates a manager over the given store. The store defines retention
    /// and indexing; the manager layers RFC 013 lifecycle semantics (dedup,
    /// update-in-place, terminal clears, authorized admin actions) on top.
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

    /// Acknowledges an active alarm. Acknowledgement marks the alarm as seen
    /// by an operator but does not clear the fault (RFC 013 §8); the alarm
    /// stays active and later raises keep it in the acknowledged state.
    ///
    /// This path trusts the caller-asserted `SuppressionAuth` flag and writes
    /// no audit record. Production callers should prefer
    /// `acknowledge_with_policy`, which evaluates an authorizer and fails
    /// closed if the action cannot be audited. Returns `Unauthorized` when
    /// `auth.authorized` is false, and `NotFound` for unknown or no longer
    /// active alarm ids.
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

    /// Acknowledges an alarm through the full policy path required for
    /// production (RFC 013 §10): the authorizer decides whether `context` may
    /// acknowledge this alarm, both denials and authorizations are written to
    /// the audit sink, and an authorized action whose audit record cannot be
    /// persisted is abandoned (`AuditFailed`) — no unaudited admin action can
    /// take effect.
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

    /// Suppresses an active alarm (e.g. for a maintenance window). The alarm
    /// stays active and keeps its full history — suppression hides it from
    /// normal presentation, it does not delete anything (RFC 013 §10).
    ///
    /// This path trusts the caller-asserted `SuppressionAuth` flag: it writes
    /// no audit record and does **not** apply the security-critical
    /// suppression policy (critical severity / security causes). Production
    /// callers should use `suppress_with_policy`, which enforces both.
    /// Returns `Unauthorized` when `auth.authorized` is false, and `NotFound`
    /// for unknown or no longer active alarm ids.
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

    /// Suppresses an alarm through the full policy path required for
    /// production (RFC 013 §10). In addition to the regular authorization and
    /// fail-closed audit performed by `acknowledge_with_policy`,
    /// security-critical alarms (critical severity, or causes such as
    /// expired certificates, unavailable identity/keys, invalid authorization
    /// policy, broken audit chains, and privacy violations) are denied unless
    /// the authorizer explicitly allows security-critical suppression; the
    /// denial itself is audited.
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

    /// Returns a snapshot of all active alarms (raised, updated,
    /// acknowledged, or suppressed). Suppressed alarms are included because
    /// suppression affects presentation, not activeness.
    pub fn active_alarms(&self) -> Vec<Alarm> {
        self.store.active_alarms()
    }

    /// Returns the number of active alarms without cloning them.
    pub fn active_count(&self) -> usize {
        self.store.active_count()
    }

    /// Returns active alarms whose *current* severity equals `severity`
    /// exactly (no "at least this severe" semantics — use the `Ord` impl on
    /// `Severity` for ranked filtering). Note that updates rewrite severity
    /// in place, so an alarm raised as major and upgraded to critical only
    /// matches `Critical`.
    pub fn active_by_severity(&self, severity: Severity) -> Vec<Alarm> {
        self.store
            .active_alarms()
            .into_iter()
            .filter(|a| a.severity == severity)
            .collect()
    }

    /// Returns the retained lifecycle history (active and terminal records),
    /// bounded by the store's retention; the oldest records may already have
    /// been evicted.
    pub fn all_alarms(&self) -> Vec<Alarm> {
        self.store.all()
    }

    /// Returns history filtered by tenant and/or slice. `None` matches
    /// everything; `Some(v)` matches only alarms whose corresponding scope
    /// field is exactly `v` (alarms without that scope are excluded).
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
    /// Creates a store with the default history bound
    /// (`DEFAULT_HISTORY_LIMIT`, 4096 records).
    pub fn new() -> Self {
        Self::new_with_history_limit(DEFAULT_HISTORY_LIMIT)
    }

    /// Creates a store whose history ring retains at most `history_limit`
    /// lifecycle records; when full, the oldest record is evicted to admit
    /// the newest. Consecutive history entries with identical identity
    /// (same alarm id, taxonomy fields, scope, severity, and state) are
    /// coalesced in place, so a duplicate-raise storm does not consume the
    /// ring. Active-alarm indexes are unbounded by this limit.
    ///
    /// # Panics
    ///
    /// Panics if `history_limit` is zero.
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
