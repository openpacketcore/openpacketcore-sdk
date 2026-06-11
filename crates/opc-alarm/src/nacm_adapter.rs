use crate::manager::{AlarmAction, AlarmActionAuthorizer, AlarmActionContext, AlarmActionDenied};
use crate::model::Alarm;
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, YangPath};
use std::{collections::BTreeSet, sync::Mutex};

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
                    "Tenant mismatch: context tenant '{}' does not match alarm tenant '{}'",
                    context_tenant, alarm_tenant
                )));
            }
        } else if let (Some(context_tenant), None) = (&context.tenant, &alarm.tenant) {
            return Err(AlarmActionDenied::new(format!(
                "Tenant mismatch: tenant-scoped context '{}' cannot touch global alarm",
                context_tenant
            )));
        }

        // 4. Map Action to YANG path
        let path_str = match action {
            AlarmAction::Acknowledge => "/ietf-alarms:alarms/alarm-list/alarm/acknowledge-alarm",
            AlarmAction::Suppress => "/ietf-alarms:alarms/alarm-list/alarm/suppress-alarm",
        };

        let path = YangPath::parse(path_str, &self.registry)
            .map_err(|e| AlarmActionDenied::new(format!("Failed to parse action path: {}", e)))?;

        // 5. Evaluate policy
        let mut eval = self.evaluator.lock().unwrap();
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

        let mut eval = self.evaluator.lock().unwrap();
        let decision = eval.evaluate(&self.policy, &path, NacmAction::Exec);
        decision.is_allowed()
    }
}
