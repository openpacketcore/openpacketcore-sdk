//! NACM-backed authorization for alarm admin actions (enabled by the `nacm`
//! feature). Maps acknowledge/suppress to stable `ietf-alarms` YANG action
//! paths and evaluates them against an `opc_nacm` policy, layered on top of
//! an explicit allow-list of alarm-admin principals and scope/tenant checks.

use crate::manager::{AlarmAction, AlarmActionAuthorizer, AlarmActionContext, AlarmActionDenied};
use crate::model::Alarm;
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, YangPath};
use std::{
    collections::BTreeSet,
    sync::{Mutex, MutexGuard},
};

/// A NACM-backed authorizer implementing [`AlarmActionAuthorizer`].
///
/// It evaluates alarm admin actions (acknowledgement and suppression)
/// against a [`NacmPolicy`] using stable canonical YANG paths.
#[derive(Debug)]
pub struct NacmAlarmAuthorizer {
    policy: NacmPolicy,
    registry: ModuleRegistry,
    allowed_principals: BTreeSet<String>,
    evaluator: Mutex<NacmEvaluator>,
}

impl NacmAlarmAuthorizer {
    /// Create a new authorizer with the given policy and module registry.
    ///
    /// This constructor defaults to no admitted principals. Production callers
    /// should use [`Self::with_allowed_principals`] after mapping their
    /// authenticated operator identity into stable principal strings.
    pub fn new(policy: NacmPolicy, registry: ModuleRegistry) -> Self {
        Self::with_allowed_principals(policy, registry, std::iter::empty::<String>())
    }

    /// Create a new authorizer with the given policy, module registry, and
    /// explicit alarm-admin principals.
    ///
    /// The canonical module name `ietf-alarms` will be registered with prefix `ietf-alarms`
    /// if it is not already present, to ensure stable path parsing.
    pub fn with_allowed_principals<I, P>(
        policy: NacmPolicy,
        mut registry: ModuleRegistry,
        principals: I,
    ) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        if registry.modules_for_prefix("ietf-alarms").is_none() {
            let _ = registry.register_module("ietf-alarms", "ietf-alarms");
        }
        let allowed_principals = principals
            .into_iter()
            .map(Into::into)
            .map(|principal| principal.trim().to_string())
            .filter(|principal| !principal.is_empty())
            .collect();
        Self {
            policy,
            registry,
            allowed_principals,
            evaluator: Mutex::new(NacmEvaluator::new()),
        }
    }

    fn principal_allowed(&self, context: &AlarmActionContext) -> bool {
        self.allowed_principals.contains(context.principal.trim())
    }

    fn lock_evaluator(&self) -> Result<MutexGuard<'_, NacmEvaluator>, AlarmActionDenied> {
        self.evaluator
            .lock()
            .map_err(|_| AlarmActionDenied::new("NACM evaluator unavailable after prior panic"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::AlarmActionScope;
    use crate::model::{
        AffectedObject, AlarmDetails, AlarmId, AlarmState, AlarmType, ProbableCause, RedactedText,
        Severity,
    };
    use opc_nacm::{NacmRule, PolicyVersion, YangPathPattern};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use time::OffsetDateTime;

    fn make_registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry
            .register_module("ietf-alarms", "ietf-alarms")
            .expect("register ietf-alarms");
        registry
    }

    fn make_alarm() -> Alarm {
        let now = OffsetDateTime::now_utc();
        Alarm {
            alarm_id: AlarmId::new("alarm-1"),
            alarm_type: AlarmType::new("link.down"),
            severity: Severity::Major,
            probable_cause: ProbableCause::PeerUnreachable,
            affected_object: AffectedObject::NfInstance {
                kind: "upf".to_string(),
                instance: "upf-1".to_string(),
            },
            tenant: Some("tenant-a".to_string()),
            slice: None,
            region: None,
            text: RedactedText::new("Link down"),
            details: AlarmDetails::empty(),
            state: AlarmState::Raised,
            raised_at: now,
            updated_at: now,
            cleared_at: None,
            correlation_id: None,
        }
    }

    fn make_context(alarm_id: &AlarmId) -> AlarmActionContext {
        AlarmActionContext::new(
            "admin-user",
            "maintenance",
            AlarmActionScope::Alarm {
                alarm_id: alarm_id.clone(),
            },
        )
        .with_tenant("tenant-a")
    }

    #[test]
    fn nacm_authorizer_denies_after_poisoned_evaluator_mutex() {
        let registry = make_registry();
        let pattern = YangPathPattern::parse(
            "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
            &registry,
        )
        .expect("parse path pattern");
        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(NacmAction::Exec, pattern))
            .build();
        let authorizer =
            NacmAlarmAuthorizer::with_allowed_principals(policy, registry, ["admin-user"]);
        let alarm = make_alarm();
        let context = make_context(&alarm.alarm_id);

        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = authorizer.evaluator.lock().expect("lock evaluator");
            panic!("poison evaluator mutex");
        }));

        let result = authorizer.authorize_alarm_action(AlarmAction::Acknowledge, &alarm, &context);
        assert!(
            result.is_err(),
            "poisoned evaluator must fail closed with a denial"
        );
        assert!(
            !authorizer.allow_security_critical_suppression(&alarm, &make_context(&alarm.alarm_id))
        );
    }
}

impl AlarmActionAuthorizer for NacmAlarmAuthorizer {
    fn authorize_alarm_action(
        &self,
        action: AlarmAction,
        alarm: &Alarm,
        context: &AlarmActionContext,
    ) -> Result<(), AlarmActionDenied> {
        // 1. Validate principal identity is not empty
        if context.principal.trim().is_empty() {
            return Err(AlarmActionDenied::new("principal identity cannot be empty"));
        }
        if !self.principal_allowed(context) {
            return Err(AlarmActionDenied::new(format!(
                "principal '{}' is not allowed to administer alarms",
                context.principal
            )));
        }

        // 2. Validate action scope matches the targeted alarm
        match &context.scope {
            crate::manager::AlarmActionScope::Alarm { alarm_id } => {
                if alarm_id != &alarm.alarm_id {
                    return Err(AlarmActionDenied::new(format!(
                        "Scope alarm_id '{}' does not match target alarm_id '{}'",
                        alarm_id, alarm.alarm_id
                    )));
                }
            }
            crate::manager::AlarmActionScope::Tenant { tenant } => {
                if alarm.tenant.as_deref() != Some(tenant) {
                    return Err(AlarmActionDenied::new(format!(
                        "Scope tenant '{}' does not match target alarm tenant '{:?}'",
                        tenant, alarm.tenant
                    )));
                }
            }
            crate::manager::AlarmActionScope::Global => {
                // Global action scope allows targeting any alarm, but still evaluated below
            }
        }

        // 3. Validate tenant alignment
        if let (Some(context_tenant), Some(alarm_tenant)) = (&context.tenant, &alarm.tenant) {
            if context_tenant != alarm_tenant {
                return Err(AlarmActionDenied::new(format!(
                    "Tenant mismatch: context tenant '{context_tenant}' does not match alarm tenant '{alarm_tenant}'"
                )));
            }
        } else if let (Some(context_tenant), None) = (&context.tenant, &alarm.tenant) {
            return Err(AlarmActionDenied::new(format!(
                "Tenant mismatch: tenant-scoped context '{context_tenant}' cannot touch global alarm"
            )));
        }

        // 4. Map Action to YANG path
        let path_str = match action {
            AlarmAction::Acknowledge => "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
            AlarmAction::Suppress => "/ietf-alarms:alarms/alarm-list/alarm/suppress-alarm",
        };

        let path = YangPath::parse(path_str, &self.registry)
            .map_err(|e| AlarmActionDenied::new(format!("Failed to parse action path: {e}")))?;

        // 5. Evaluate policy
        let mut eval = self.lock_evaluator()?;
        let decision = eval.evaluate(&self.policy, &path, NacmAction::Exec);

        if decision.is_allowed() {
            Ok(())
        } else {
            Err(AlarmActionDenied::new(format!(
                "Authorization denied for principal '{}': no matching allow rule for action '{:?}'",
                context.principal, action
            )))
        }
    }

    fn allow_security_critical_suppression(
        &self,
        _alarm: &Alarm,
        context: &AlarmActionContext,
    ) -> bool {
        if context.principal.trim().is_empty() || !self.principal_allowed(context) {
            return false;
        }

        let path_str = "/ietf-alarms:alarms/alarm-list/alarm/security-critical-suppression";
        let Ok(path) = YangPath::parse(path_str, &self.registry) else {
            return false;
        };

        let Ok(mut eval) = self.lock_evaluator() else {
            return false;
        };
        let decision = eval.evaluate(&self.policy, &path, NacmAction::Exec);
        decision.is_allowed()
    }
}
