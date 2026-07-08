//! Read-side NACM authorization facade for the OpenPacketCore management plane.
//!
//! `opc-config-bus` enforces NACM on the write path, but reads from a published
//! snapshot are raw. The gNMI `Get`/`Subscribe` and NETCONF `<get>`/`<get-config>`
//! paths must authorize reads themselves, default-deny, and omit subtrees the
//! caller may not see. [`ReadAuthorizer`] is that facade: it selects the active
//! compiled NACM policy via a pluggable [`PolicySource`], maps each schema path
//! to a normalized NACM path using a [`ModuleRegistry`] built from the schema
//! registry's served models, and evaluates `read`/`subscribe` per path with the
//! principal's signed NACM groups.
//!
//! Everything fails closed: a path that does not resolve through the schema
//! registry denies; a tenant whose policy is empty default-denies (NACM has no
//! rule -> deny); and a genuinely unavailable policy store surfaces as `Err`,
//! which the caller maps to a denied/`UNAVAILABLE` response (never an allow).
//!
//! NACM in this SDK is schema-node scoped (it collapses list instances), so this
//! facade authorizes at the schema-node level, not per list instance.
//!
//! The crate also exposes [`ConfigWriteAuthorizer`] for config-bus commit
//! admission and [`ExecAuthorizer`] for management RPC/action execution checks
//! such as future NETCONF `<kill-session>`. These facades are deliberately
//! separate so read paths cannot accidentally exercise write/exec NACM actions.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use opc_config_bus::{AuthorizationContext, AuthorizationError, ConfigAuthorizer};
use opc_config_model::{ConfigOperation, YangPath as ConfigYangPath};
use opc_config_model::{TrustedPrincipal, WorkloadIdentity};
use opc_mgmt_schema::{ModelData, SchemaRegistry};
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy, YangPath};
use thiserror::Error;

const INVALID_SCHEMA_PATH: &str = "<invalid>";

/// A read-class NACM action. Constraining the facade to these two actions keeps
/// write actions (create/update/replace/delete) out of the read path; those are
/// authorized on the commit path by a `ConfigAuthorizer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAction {
    /// gNMI `Get` / NETCONF `<get>`/`<get-config>` data-node read.
    Read,
    /// gNMI `Subscribe` / NETCONF `<create-subscription>` stream.
    Subscribe,
}

impl ReadAction {
    fn to_nacm(self) -> NacmAction {
        match self {
            Self::Read => NacmAction::Read,
            Self::Subscribe => NacmAction::Subscribe,
        }
    }
}

/// Source of the active, compiled NACM policy for a tenant.
///
/// Implementations adapt the SDK policy datastore (e.g. `opc-persist`'s
/// `SqliteSecurityPolicyService::get_active_policy_compiled`). Contract:
///
/// - a tenant with **no** configured policy MUST return an empty policy
///   ([`NacmPolicy::empty`]) - which default-denies every path - never an error;
/// - reserve `Err` for a genuinely unavailable/erroring policy store, in which
///   case the caller fails closed (denies / returns `UNAVAILABLE`).
pub trait PolicySource: Send + Sync {
    /// Returns the active compiled NACM policy for `tenant`.
    fn active_policy(&self, tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError>;

    /// Returns the active compiled NACM policy for a fully resolved principal.
    ///
    /// The default preserves the existing tenant-only behavior. Implementations
    /// that store per-principal or per-group policy overlays can override this
    /// method; authorizers always call this principal-aware entry point so
    /// identity, roles, and signed groups remain available to the policy source.
    fn active_policy_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<Arc<NacmPolicy>, AuthzError> {
        self.active_policy(principal.tenant.as_str())
    }

    /// Returns the active policy plus the effective principal to evaluate.
    ///
    /// The default preserves the existing behavior by evaluating the original
    /// principal. Grant-backed sources can override this method to attach
    /// signed roles/groups before NACM evaluation and decision tracing. The
    /// effective principal must keep the authenticated identity and tenant; only
    /// signed authorization metadata such as roles/groups should be added.
    fn active_policy_context_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<ResolvedPolicy, AuthzError> {
        Ok(ResolvedPolicy::new(
            self.active_policy_for_principal(principal)?,
            principal.clone(),
        ))
    }
}

impl<T> PolicySource for &T
where
    T: PolicySource + ?Sized,
{
    fn active_policy(&self, tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        (*self).active_policy(tenant)
    }

    fn active_policy_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<Arc<NacmPolicy>, AuthzError> {
        (*self).active_policy_for_principal(principal)
    }

    fn active_policy_context_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<ResolvedPolicy, AuthzError> {
        (*self).active_policy_context_for_principal(principal)
    }
}

impl<T> PolicySource for Arc<T>
where
    T: PolicySource + ?Sized,
{
    fn active_policy(&self, tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        self.as_ref().active_policy(tenant)
    }

    fn active_policy_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<Arc<NacmPolicy>, AuthzError> {
        self.as_ref().active_policy_for_principal(principal)
    }

    fn active_policy_context_for_principal(
        &self,
        principal: &TrustedPrincipal,
    ) -> Result<ResolvedPolicy, AuthzError> {
        self.as_ref().active_policy_context_for_principal(principal)
    }
}

/// Active policy selection and effective principal used for one authorization.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Compiled NACM policy selected for the principal.
    pub policy: Arc<NacmPolicy>,
    /// Principal after any signed authorization grants have been attached.
    pub principal: TrustedPrincipal,
    /// Optional implementation-specific policy mode for operator diagnostics.
    pub mode: Option<String>,
}

impl ResolvedPolicy {
    pub fn new(policy: Arc<NacmPolicy>, principal: TrustedPrincipal) -> Self {
        Self {
            policy,
            principal,
            mode: None,
        }
    }

    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = Some(mode.into());
        self
    }
}

/// A read-authorization failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthzError {
    /// The schema registry's served models could not be registered (e.g. a
    /// module name/prefix that is not a valid YANG identifier).
    #[error("schema module registry error: {0}")]
    Schema(String),
    /// The policy store is unavailable or errored; the caller must fail closed.
    ///
    /// This variant intentionally carries no backend detail. Policy-store
    /// errors can contain database paths, tenant identifiers, or storage-layer
    /// internals that must not cross the management-plane boundary.
    #[error("policy source unavailable")]
    PolicyUnavailable,
}

/// The authorization outcome for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDecision {
    /// The predicate-free schema path that was evaluated. Invalid/unresolvable
    /// input paths use a fixed marker so key values are not echoed.
    pub path: String,
    /// Whether the principal may perform the requested read action on it.
    pub allowed: bool,
}

/// The authorization outcome for one changed config path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePathDecision {
    /// The predicate-free schema path that was evaluated. Invalid/unresolvable
    /// input paths use a fixed marker so key values are not echoed.
    pub path: String,
    /// NACM write action selected from the config-bus operation.
    pub action: NacmAction,
    /// Whether the principal may perform the requested write action on it.
    pub allowed: bool,
}

/// Read-side NACM authorizer over a schema registry and a tenant policy source.
pub struct ReadAuthorizer<'r, P: PolicySource> {
    registry: &'r dyn SchemaRegistry,
    modules: ModuleRegistry,
    source: P,
    evaluator: Mutex<NacmEvaluator>,
    #[cfg(test)]
    cache_hits: AtomicUsize,
}

impl<'r, P: PolicySource> ReadAuthorizer<'r, P> {
    /// Builds the authorizer, registering every served model's name/prefix into a
    /// NACM [`ModuleRegistry`] once. Fails if a served model is not a valid YANG
    /// identifier (a generation defect that must not be silently ignored).
    pub fn new(registry: &'r dyn SchemaRegistry, source: P) -> Result<Self, AuthzError> {
        let modules = module_registry_from_models(registry.served_models())?;
        Ok(Self {
            registry,
            modules,
            source,
            evaluator: Mutex::new(NacmEvaluator::new()),
            #[cfg(test)]
            cache_hits: AtomicUsize::new(0),
        })
    }

    /// Returns the schema registry this authorizer was built over.
    pub fn registry(&self) -> &'r dyn SchemaRegistry {
        self.registry
    }

    /// Returns the policy source used by this authorizer.
    pub fn policy_source(&self) -> &P {
        &self.source
    }

    #[cfg(test)]
    fn cache_hits(&self) -> usize {
        self.cache_hits.load(Ordering::Relaxed)
    }

    /// Authorizes a read action against each path for the principal's tenant.
    ///
    /// Returns one [`PathDecision`] per input path, preserving order. A path that
    /// does not resolve through the schema registry, or does not parse against
    /// the served NACM modules, is denied (fail closed). Returns `Err` only if
    /// the policy store itself is unavailable.
    pub fn authorize(
        &self,
        principal: &TrustedPrincipal,
        action: ReadAction,
        paths: &[&str],
    ) -> Result<Vec<PathDecision>, AuthzError> {
        let resolved = self.source.active_policy_context_for_principal(principal)?;
        let policy = &resolved.policy;
        let authz_principal = &resolved.principal;
        let nacm_action = action.to_nacm();
        let mut evaluator = lock_evaluator(&self.evaluator);

        let decisions: Vec<_> = paths
            .iter()
            .map(|&path| {
                let Some(node) = self.registry.node(path) else {
                    return PathDecision {
                        path: INVALID_SCHEMA_PATH.to_string(),
                        allowed: false,
                    };
                };
                let schema_path = node.path.to_string();
                let allowed = match YangPath::parse(node.path, &self.modules) {
                    Ok(parsed) => {
                        let decision = evaluator.evaluate_for_groups(
                            policy,
                            &parsed,
                            nacm_action,
                            &authz_principal.groups,
                        );
                        #[cfg(test)]
                        if decision.cache_hit() {
                            self.cache_hits.fetch_add(1, Ordering::Relaxed);
                        }
                        decision.is_allowed()
                    }
                    // Unparseable / unknown-prefix canonical path: deny.
                    Err(_) => false,
                };
                PathDecision {
                    path: schema_path,
                    allowed,
                }
            })
            .collect();
        trace_read_decisions(
            authz_principal,
            policy,
            resolved.mode.as_deref(),
            nacm_action,
            &decisions,
        );
        Ok(decisions)
    }

    /// Convenience single-path check.
    pub fn may(
        &self,
        principal: &TrustedPrincipal,
        action: ReadAction,
        path: &str,
    ) -> Result<bool, AuthzError> {
        Ok(self
            .authorize(principal, action, &[path])?
            .first()
            .map(|decision| decision.allowed)
            .unwrap_or(false))
    }
}

/// NACM authorizer for config-bus commit admission.
///
/// The config bus remains the write enforcement point: it computes
/// authoritative changed paths from the candidate diff, then calls this
/// `ConfigAuthorizer` before persistence or publication. This adapter maps the
/// high-level config operation to a NACM write action and requires every
/// changed path to be allowed by the tenant's active policy. Empty path batches
/// are allowed so no-op commits and pre-authorized rollback admission can
/// proceed to the later computed-path authorization pass.
pub struct ConfigWriteAuthorizer<'r, P: PolicySource> {
    registry: &'r dyn SchemaRegistry,
    modules: ModuleRegistry,
    source: P,
    evaluator: Mutex<NacmEvaluator>,
}

impl<'r, P: PolicySource> ConfigWriteAuthorizer<'r, P> {
    /// Builds a config-bus write authorizer over the generated schema registry
    /// and the tenant policy source.
    pub fn new(registry: &'r dyn SchemaRegistry, source: P) -> Result<Self, AuthzError> {
        let modules = module_registry_from_models(registry.served_models())?;
        Ok(Self {
            registry,
            modules,
            source,
            evaluator: Mutex::new(NacmEvaluator::new()),
        })
    }

    /// Returns the schema registry this authorizer was built over.
    pub fn registry(&self) -> &'r dyn SchemaRegistry {
        self.registry
    }

    /// Returns the policy source used by this authorizer.
    pub fn policy_source(&self) -> &P {
        &self.source
    }

    /// Authorizes one config-bus write context and returns per-path decisions.
    ///
    /// Returns `Err` only if the policy source is unavailable. Unknown schema
    /// paths, unparseable generated paths, and missing policy rules are returned
    /// as denied decisions so callers can fail closed without echoing sensitive
    /// key predicates.
    pub fn authorize_context(
        &self,
        ctx: &AuthorizationContext,
    ) -> Result<Vec<WritePathDecision>, AuthzError> {
        self.authorize_paths(
            &ctx.principal,
            ctx.operation,
            ctx.changed_paths.iter().collect::<Vec<_>>().as_slice(),
        )
    }

    /// Authorizes the supplied changed paths for the principal and operation.
    pub fn authorize_paths(
        &self,
        principal: &TrustedPrincipal,
        operation: ConfigOperation,
        paths: &[&ConfigYangPath],
    ) -> Result<Vec<WritePathDecision>, AuthzError> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let resolved = self.source.active_policy_context_for_principal(principal)?;
        let policy = &resolved.policy;
        let authz_principal = &resolved.principal;
        let nacm_action = primary_write_action_for_operation(operation);
        let required_actions = write_actions_for_operation(operation);
        let mut evaluator = lock_evaluator(&self.evaluator);

        let decisions: Vec<_> = paths
            .iter()
            .map(|path| {
                let Some(node) = self.registry.node(path.as_str()) else {
                    return WritePathDecision {
                        path: INVALID_SCHEMA_PATH.to_string(),
                        action: nacm_action,
                        allowed: false,
                    };
                };
                let schema_path = node.path.to_string();
                let allowed = match YangPath::parse(node.path, &self.modules) {
                    Ok(parsed) => required_actions.iter().all(|action| {
                        evaluator
                            .evaluate_for_groups(policy, &parsed, *action, &authz_principal.groups)
                            .is_allowed()
                    }),
                    Err(_) => false,
                };
                WritePathDecision {
                    path: schema_path,
                    action: nacm_action,
                    allowed,
                }
            })
            .collect();
        trace_write_decisions(
            authz_principal,
            policy,
            resolved.mode.as_deref(),
            operation,
            nacm_action,
            &decisions,
        );
        Ok(decisions)
    }

    /// Convenience single-path check.
    pub fn may_write(
        &self,
        principal: &TrustedPrincipal,
        operation: ConfigOperation,
        path: &ConfigYangPath,
    ) -> Result<bool, AuthzError> {
        Ok(self
            .authorize_paths(principal, operation, &[path])?
            .first()
            .map(|decision| decision.allowed)
            .unwrap_or(false))
    }
}

#[async_trait]
impl<P> ConfigAuthorizer for ConfigWriteAuthorizer<'_, P>
where
    P: PolicySource,
{
    async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
        let decisions = self
            .authorize_context(ctx)
            .map_err(|_| AuthorizationError::new("NACM write policy unavailable"))?;

        if decisions.iter().all(|decision| decision.allowed) {
            return Ok(());
        }

        Err(AuthorizationError::new("NACM write authorization denied"))
    }
}

/// NACM authorizer for management RPC/action execution.
///
/// Callers provide the YANG modules that define the operations they plan to
/// authorize, then check static operation paths such as `/nc:kill-session`.
/// Invalid or unparseable operation paths deny fail-closed. Policy-store errors
/// still surface as [`AuthzError::PolicyUnavailable`] so callers can return a
/// transport-appropriate unavailable/resource-denied result without granting
/// access.
pub struct ExecAuthorizer<P: PolicySource> {
    modules: ModuleRegistry,
    source: P,
    evaluator: Mutex<NacmEvaluator>,
}

impl<P: PolicySource> ExecAuthorizer<P> {
    /// Builds an exec authorizer from the YANG modules that define the RPC/action
    /// nodes being checked.
    pub fn new(models: &[ModelData], source: P) -> Result<Self, AuthzError> {
        Ok(Self {
            modules: module_registry_from_models(models)?,
            source,
            evaluator: Mutex::new(NacmEvaluator::new()),
        })
    }

    /// Returns the policy source used by this authorizer.
    pub fn policy_source(&self) -> &P {
        &self.source
    }

    /// Checks whether the principal may execute the operation at `operation_path`.
    ///
    /// The path is expected to be a static, predicate-free YANG RPC/action path
    /// defined by the caller's operation module registry. If it does not parse
    /// against that registry, authorization denies fail-closed.
    pub fn may_exec(
        &self,
        principal: &TrustedPrincipal,
        operation_path: &str,
    ) -> Result<bool, AuthzError> {
        let resolved = self.source.active_policy_context_for_principal(principal)?;
        let policy = &resolved.policy;
        let authz_principal = &resolved.principal;
        let Ok(path) = YangPath::parse(operation_path, &self.modules) else {
            trace_exec_decision(
                authz_principal,
                policy,
                resolved.mode.as_deref(),
                INVALID_SCHEMA_PATH,
                false,
            );
            return Ok(false);
        };
        let mut evaluator = lock_evaluator(&self.evaluator);
        let allowed = evaluator
            .evaluate_for_groups(policy, &path, NacmAction::Exec, &authz_principal.groups)
            .is_allowed();
        trace_exec_decision(
            authz_principal,
            policy,
            resolved.mode.as_deref(),
            operation_path,
            allowed,
        );
        Ok(allowed)
    }
}

const PATCH_WRITE_ACTIONS: &[NacmAction] = &[NacmAction::Create, NacmAction::Update];
const REPLACE_WRITE_ACTIONS: &[NacmAction] = &[NacmAction::Replace];
const DELETE_WRITE_ACTIONS: &[NacmAction] = &[NacmAction::Delete];

fn write_actions_for_operation(operation: ConfigOperation) -> &'static [NacmAction] {
    match operation {
        ConfigOperation::Replace => REPLACE_WRITE_ACTIONS,
        ConfigOperation::Patch => PATCH_WRITE_ACTIONS,
        ConfigOperation::Delete => DELETE_WRITE_ACTIONS,
        ConfigOperation::Rollback => REPLACE_WRITE_ACTIONS,
    }
}

fn primary_write_action_for_operation(operation: ConfigOperation) -> NacmAction {
    match operation {
        ConfigOperation::Replace => NacmAction::Replace,
        ConfigOperation::Patch => NacmAction::Update,
        ConfigOperation::Delete => NacmAction::Delete,
        ConfigOperation::Rollback => NacmAction::Replace,
    }
}

fn lock_evaluator(evaluator: &Mutex<NacmEvaluator>) -> MutexGuard<'_, NacmEvaluator> {
    evaluator
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn module_registry_from_models(models: &[ModelData]) -> Result<ModuleRegistry, AuthzError> {
    let mut modules = ModuleRegistry::new();
    let mut prefix_owners = BTreeMap::new();
    for model in models {
        if let Some(existing) = prefix_owners.insert(model.prefix, model.name) {
            if existing != model.name {
                return Err(AuthzError::Schema(format!(
                    "schema module prefix '{}' is shared by '{}' and '{}'",
                    model.prefix, existing, model.name
                )));
            }
        }
        modules
            .register_module(model.name, model.prefix)
            .map_err(|err| AuthzError::Schema(err.to_string()))?;
    }
    Ok(modules)
}

fn trace_read_decisions(
    principal: &TrustedPrincipal,
    policy: &NacmPolicy,
    policy_mode: Option<&str>,
    action: NacmAction,
    decisions: &[PathDecision],
) {
    let identity = TraceIdentity::from_principal(principal);
    for decision in decisions {
        tracing::debug!(
            target: "opc_mgmt_authz",
            event = "mgmt.authz.read",
            principal_kind = identity.kind,
            tenant = principal.tenant.as_str(),
            groups = ?principal.groups,
            spiffe_trust_domain = identity.spiffe_trust_domain,
            spiffe_tenant = identity.spiffe_tenant,
            spiffe_namespace = identity.spiffe_namespace,
            spiffe_service_account = identity.spiffe_service_account,
            spiffe_nf_kind = identity.spiffe_nf_kind,
            policy_version = policy.version().get(),
            policy_mode = policy_mode.unwrap_or("unspecified"),
            action = action.as_str(),
            path = decision.path.as_str(),
            allowed = decision.allowed,
            "management authorization decision"
        );
    }
}

fn trace_write_decisions(
    principal: &TrustedPrincipal,
    policy: &NacmPolicy,
    policy_mode: Option<&str>,
    operation: ConfigOperation,
    action: NacmAction,
    decisions: &[WritePathDecision],
) {
    let identity = TraceIdentity::from_principal(principal);
    for decision in decisions {
        tracing::debug!(
            target: "opc_mgmt_authz",
            event = "mgmt.authz.write",
            principal_kind = identity.kind,
            tenant = principal.tenant.as_str(),
            groups = ?principal.groups,
            spiffe_trust_domain = identity.spiffe_trust_domain,
            spiffe_tenant = identity.spiffe_tenant,
            spiffe_namespace = identity.spiffe_namespace,
            spiffe_service_account = identity.spiffe_service_account,
            spiffe_nf_kind = identity.spiffe_nf_kind,
            policy_version = policy.version().get(),
            policy_mode = policy_mode.unwrap_or("unspecified"),
            operation = ?operation,
            action = action.as_str(),
            path = decision.path.as_str(),
            allowed = decision.allowed,
            "management authorization decision"
        );
    }
}

fn trace_exec_decision(
    principal: &TrustedPrincipal,
    policy: &NacmPolicy,
    policy_mode: Option<&str>,
    operation_path: &str,
    allowed: bool,
) {
    let identity = TraceIdentity::from_principal(principal);
    tracing::debug!(
        target: "opc_mgmt_authz",
        event = "mgmt.authz.exec",
        principal_kind = identity.kind,
        tenant = principal.tenant.as_str(),
        groups = ?principal.groups,
        spiffe_trust_domain = identity.spiffe_trust_domain,
        spiffe_tenant = identity.spiffe_tenant,
        spiffe_namespace = identity.spiffe_namespace,
        spiffe_service_account = identity.spiffe_service_account,
        spiffe_nf_kind = identity.spiffe_nf_kind,
        policy_version = policy.version().get(),
        policy_mode = policy_mode.unwrap_or("unspecified"),
        action = NacmAction::Exec.as_str(),
        path = operation_path,
        allowed,
        "management authorization decision"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraceIdentity<'a> {
    kind: &'static str,
    spiffe_trust_domain: Option<&'a str>,
    spiffe_tenant: Option<&'a str>,
    spiffe_namespace: Option<&'a str>,
    spiffe_service_account: Option<&'a str>,
    spiffe_nf_kind: Option<&'a str>,
}

impl<'a> TraceIdentity<'a> {
    fn from_principal(principal: &'a TrustedPrincipal) -> Self {
        match &principal.identity {
            WorkloadIdentity::Spiffe(spiffe) => {
                let parts = SpiffeTraceParts::from_path(spiffe.path());
                Self {
                    kind: "spiffe",
                    spiffe_trust_domain: Some(spiffe.trust_domain()),
                    spiffe_tenant: parts.tenant,
                    spiffe_namespace: parts.namespace,
                    spiffe_service_account: parts.service_account,
                    spiffe_nf_kind: parts.nf_kind,
                }
            }
            WorkloadIdentity::User(_) => Self::non_spiffe("user"),
            WorkloadIdentity::Internal(_) => Self::non_spiffe("internal"),
        }
    }

    fn non_spiffe(kind: &'static str) -> Self {
        Self {
            kind,
            spiffe_trust_domain: None,
            spiffe_tenant: None,
            spiffe_namespace: None,
            spiffe_service_account: None,
            spiffe_nf_kind: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SpiffeTraceParts<'a> {
    tenant: Option<&'a str>,
    namespace: Option<&'a str>,
    service_account: Option<&'a str>,
    nf_kind: Option<&'a str>,
}

impl<'a> SpiffeTraceParts<'a> {
    fn from_path(path: &'a str) -> Self {
        let mut segments = path.trim_start_matches('/').split('/');
        let mut first = segments.next();
        if first == Some("trust-domain") {
            first = segments.next();
        }
        if first != Some("tenant") {
            return Self::default();
        }
        let tenant = segments.next();
        if segments.next() != Some("ns") {
            return Self {
                tenant,
                ..Self::default()
            };
        }
        let namespace = segments.next();
        if segments.next() != Some("sa") {
            return Self {
                tenant,
                namespace,
                ..Self::default()
            };
        }
        let service_account = segments.next();
        if segments.next() != Some("nf") {
            return Self {
                tenant,
                namespace,
                service_account,
                ..Self::default()
            };
        }
        let nf_kind = segments.next();
        Self {
            tenant,
            namespace,
            service_account,
            nf_kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::{ConfigOperation, TrustedPrincipal, WorkloadIdentity};
    use opc_mgmt_schema::{DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry};
    use opc_nacm::{NacmPolicy, NacmRule, NacmRuleList, PolicyVersion, YangPathPattern};
    use opc_types::{SpiffeId, TenantId};
    use std::sync::Arc;

    struct TestReg;

    static MODELS: &[ModelData] = &[ModelData {
        name: "demo-system",
        revision: "2026-06-13",
        namespace: "urn:opc:demo",
        prefix: "sys",
    }];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["demo-system"],
    }];

    static NETCONF_MODELS: &[ModelData] = &[ModelData {
        name: "ietf-netconf",
        revision: "2011-06-01",
        namespace: "urn:ietf:params:xml:ns:netconf:base:1.0",
        prefix: "nc",
    }];

    const fn leaf(path: &'static str, data_class: DataClass) -> NodeMeta {
        NodeMeta {
            path,
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        }
    }

    static NODES: &[NodeMeta] = &[
        NodeMeta {
            path: "/sys:system",
            module: "demo-system",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &["/sys:system/sys:hostname", "/sys:system/sys:secret"],
        },
        leaf("/sys:system/sys:hostname", DataClass::Public),
        leaf("/sys:system/sys:secret", DataClass::SecuritySecret),
    ];

    impl SchemaRegistry for TestReg {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:0"
        }
        fn served_models(&self) -> &'static [ModelData] {
            MODELS
        }
        fn nodes(&self) -> &'static [NodeMeta] {
            NODES
        }
        fn origins(&self) -> &'static [OriginEntry] {
            ORIGINS
        }
    }

    /// Builds a `ModuleRegistry` matching the served models, for authoring test
    /// policy patterns.
    fn module_registry() -> ModuleRegistry {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("register module");
        modules
    }

    fn netconf_module_registry() -> ModuleRegistry {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("ietf-netconf", "nc")
            .expect("register module");
        modules
    }

    /// A policy source returning a fixed policy.
    struct FixedPolicy(NacmPolicy);
    impl PolicySource for FixedPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
            Ok(Arc::new(self.0.clone()))
        }
    }

    /// A policy source that always errors (store unavailable).
    struct BrokenPolicy;
    impl PolicySource for BrokenPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
            Err(AuthzError::PolicyUnavailable)
        }
    }

    struct SharedPolicy(Arc<NacmPolicy>);
    impl PolicySource for SharedPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
            Ok(Arc::clone(&self.0))
        }
    }

    /// A source that only grants policy through the principal-aware hook. Tests
    /// using this source fail if an authorizer regresses to tenant-only lookup.
    struct PrincipalAwarePolicy;
    impl PolicySource for PrincipalAwarePolicy {
        fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
            Ok(Arc::new(NacmPolicy::empty(PolicyVersion::new(1))))
        }

        fn active_policy_for_principal(
            &self,
            principal: &TrustedPrincipal,
        ) -> Result<Arc<NacmPolicy>, AuthzError> {
            if principal.groups.iter().any(|group| group == "selected") {
                Ok(Arc::new(allow_writes(
                    &[NacmAction::Create, NacmAction::Update],
                    "/sys:system/sys:hostname",
                )))
            } else {
                Ok(Arc::new(NacmPolicy::empty(PolicyVersion::new(1))))
            }
        }
    }

    /// A source that attaches signed groups in the resolved-policy context.
    /// Tests using this source fail if an authorizer evaluates the original
    /// transport principal instead of the effective signed-grant principal.
    struct ResolvedGroupPolicy;
    impl PolicySource for ResolvedGroupPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
            Ok(Arc::new(NacmPolicy::empty(PolicyVersion::new(1))))
        }

        fn active_policy_context_for_principal(
            &self,
            principal: &TrustedPrincipal,
        ) -> Result<ResolvedPolicy, AuthzError> {
            Ok(ResolvedPolicy::new(
                Arc::new(group_writes(
                    "resolved-writer",
                    &[NacmAction::Create, NacmAction::Update],
                    "/sys:system/sys:hostname",
                )),
                principal.clone().with_groups(["resolved-writer"]),
            )
            .with_mode("production-write"))
        }
    }

    fn principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::Internal("tester".into()),
            TenantId::from_static("acme"),
        )
    }

    fn principal_with_groups(groups: impl IntoIterator<Item = &'static str>) -> TrustedPrincipal {
        principal().with_groups(groups)
    }

    fn spiffe_principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::Spiffe(
                SpiffeId::new(
                    "spiffe://epdg-lab/tenant/mgmt-client/ns/epdg-gateway/sa/mgmt/nf/epdg/instance/lab",
                )
                .expect("valid SPIFFE ID"),
            ),
            TenantId::from_static("mgmt-client"),
        )
    }

    #[test]
    fn trace_identity_redacts_raw_spiffe_and_exposes_selector_segments() {
        let principal = spiffe_principal();

        let trace = TraceIdentity::from_principal(&principal);

        assert_eq!(trace.kind, "spiffe");
        assert_eq!(trace.spiffe_trust_domain, Some("epdg-lab"));
        assert_eq!(trace.spiffe_tenant, Some("mgmt-client"));
        assert_eq!(trace.spiffe_namespace, Some("epdg-gateway"));
        assert_eq!(trace.spiffe_service_account, Some("mgmt"));
        assert_eq!(trace.spiffe_nf_kind, Some("epdg"));
    }

    #[test]
    fn trace_identity_omits_user_and_internal_names() {
        let user = TrustedPrincipal::new(
            WorkloadIdentity::User("secret-admin@example.org".to_string()),
            TenantId::from_static("mgmt-client"),
        );
        let internal = principal();

        let user_trace = TraceIdentity::from_principal(&user);
        let internal_trace = TraceIdentity::from_principal(&internal);

        assert_eq!(user_trace.kind, "user");
        assert_eq!(internal_trace.kind, "internal");
        assert_eq!(user_trace.spiffe_trust_domain, None);
        assert_eq!(internal_trace.spiffe_trust_domain, None);
    }

    fn allow_read(pattern: &str) -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse(pattern, &modules).expect("pattern"),
            ))
            .build()
    }

    fn allow_subscribe(pattern: &str) -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Subscribe,
                YangPathPattern::parse(pattern, &modules).expect("pattern"),
            ))
            .build()
    }

    fn allow_exec(pattern: &str) -> NacmPolicy {
        let modules = netconf_module_registry();
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Exec,
                YangPathPattern::parse(pattern, &modules).expect("pattern"),
            ))
            .build()
    }

    fn group_read(group: &'static str, pattern: &str) -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule_list(
                NacmRuleList::new(
                    "readers",
                    [group],
                    vec![NacmRule::allow(
                        NacmAction::Read,
                        YangPathPattern::parse(pattern, &modules).expect("pattern"),
                    )],
                )
                .expect("rule-list"),
            )
            .build()
    }

    fn group_writes(group: &'static str, actions: &[NacmAction], pattern: &str) -> NacmPolicy {
        let modules = module_registry();
        let pattern = YangPathPattern::parse(pattern, &modules).expect("pattern");
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule_list(
                NacmRuleList::new(
                    "writers",
                    [group],
                    actions
                        .iter()
                        .map(|action| NacmRule::allow(*action, pattern.clone()))
                        .collect(),
                )
                .expect("rule-list"),
            )
            .build()
    }

    fn group_exec(group: &'static str, pattern: &str) -> NacmPolicy {
        let modules = netconf_module_registry();
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule_list(
                NacmRuleList::new(
                    "operators",
                    [group],
                    vec![NacmRule::allow(
                        NacmAction::Exec,
                        YangPathPattern::parse(pattern, &modules).expect("pattern"),
                    )],
                )
                .expect("rule-list"),
            )
            .build()
    }

    fn allow_write(action: NacmAction, pattern: &str) -> NacmPolicy {
        let modules = module_registry();
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                action,
                YangPathPattern::parse(pattern, &modules).expect("pattern"),
            ))
            .build()
    }

    fn allow_writes(actions: &[NacmAction], pattern: &str) -> NacmPolicy {
        let modules = module_registry();
        let pattern = YangPathPattern::parse(pattern, &modules).expect("pattern");
        let mut builder = NacmPolicy::builder(PolicyVersion::new(1));
        for action in actions {
            builder = builder.add_rule(NacmRule::allow(*action, pattern.clone()));
        }
        builder.build()
    }

    fn config_path(path: &str) -> ConfigYangPath {
        ConfigYangPath::new(path).expect("config path")
    }

    #[test]
    fn allows_matching_read_and_denies_others() {
        let authz = ReadAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_read("/sys:system/sys:hostname")),
        )
        .expect("authorizer");
        let decisions = authz
            .authorize(
                &principal(),
                ReadAction::Read,
                &["/sys:system/sys:hostname", "/sys:system/sys:secret"],
            )
            .expect("authorize");
        assert!(decisions[0].allowed); // explicitly allowed
        assert!(!decisions[1].allowed); // no rule -> default deny
        assert_eq!(decisions[0].path, "/sys:system/sys:hostname");
    }

    #[test]
    fn empty_policy_default_denies_everything() {
        let authz = ReadAuthorizer::new(
            &TestReg,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(1))),
        )
        .expect("authorizer");
        assert!(!authz
            .may(&principal(), ReadAction::Read, "/sys:system/sys:hostname")
            .expect("may"));
    }

    #[test]
    fn subtree_rule_authorizes_descendants() {
        let authz = ReadAuthorizer::new(&TestReg, FixedPolicy(allow_read("/sys:system/**")))
            .expect("authorizer");
        let decisions = authz
            .authorize(
                &principal(),
                ReadAction::Read,
                &["/sys:system/sys:hostname", "/sys:system/sys:secret"],
            )
            .expect("authorize");
        assert!(decisions.iter().all(|d| d.allowed));
    }

    #[test]
    fn unparseable_path_denies_fail_closed() {
        let authz = ReadAuthorizer::new(&TestReg, FixedPolicy(allow_read("/sys:system/**")))
            .expect("authorizer");
        // Unknown prefix 'bad:' does not resolve against served models -> deny.
        assert!(!authz
            .may(&principal(), ReadAction::Read, "/bad:system/bad:hostname")
            .expect("may"));
    }

    #[test]
    fn unknown_schema_path_denies_even_under_subtree_allow() {
        let authz = ReadAuthorizer::new(&TestReg, FixedPolicy(allow_read("/sys:system/**")))
            .expect("authorizer");
        let decisions = authz
            .authorize(&principal(), ReadAction::Read, &["/sys:system/sys:nope"])
            .expect("authorize");

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].path, INVALID_SCHEMA_PATH);
        assert!(!decisions[0].allowed);
    }

    #[test]
    fn bare_paths_are_canonicalized_before_nacm_eval() {
        let authz = ReadAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_read("/sys:system/sys:hostname")),
        )
        .expect("authorizer");
        let decisions = authz
            .authorize(&principal(), ReadAction::Read, &["/system/hostname"])
            .expect("authorize");

        assert_eq!(decisions[0].path, "/sys:system/sys:hostname");
        assert!(decisions[0].allowed);
    }

    #[test]
    fn subscribe_action_is_evaluated_distinctly() {
        // Policy only grants Read; a Subscribe request is therefore denied.
        let authz = ReadAuthorizer::new(&TestReg, FixedPolicy(allow_read("/sys:system/**")))
            .expect("authorizer");
        assert!(!authz
            .may(
                &principal(),
                ReadAction::Subscribe,
                "/sys:system/sys:hostname"
            )
            .expect("may"));
    }

    #[test]
    fn subscribe_action_can_be_allowed_explicitly() {
        let authz = ReadAuthorizer::new(&TestReg, FixedPolicy(allow_subscribe("/sys:system/**")))
            .expect("authorizer");
        assert!(authz
            .may(
                &principal(),
                ReadAction::Subscribe,
                "/sys:system/sys:hostname"
            )
            .expect("may"));
    }

    #[test]
    fn decision_paths_never_echo_invalid_key_values() {
        let authz = ReadAuthorizer::new(&TestReg, FixedPolicy(allow_read("/sys:system/**")))
            .expect("authorizer");
        let decisions = authz
            .authorize(
                &principal(),
                ReadAction::Read,
                &["/sys:system/sys:missing[sys:name='super-secret-supi']"],
            )
            .expect("authorize");

        assert_eq!(decisions[0].path, INVALID_SCHEMA_PATH);
        assert!(!decisions[0].path.contains("super-secret-supi"));
        assert!(!decisions[0].allowed);
    }

    #[test]
    fn unavailable_policy_store_errors_so_caller_fails_closed() {
        let authz = ReadAuthorizer::new(&TestReg, BrokenPolicy).expect("authorizer");
        let result = authz.may(&principal(), ReadAction::Read, "/sys:system/sys:hostname");
        assert!(matches!(result, Err(AuthzError::PolicyUnavailable)));
    }

    #[test]
    fn policy_unavailable_error_is_payload_free() {
        let error = AuthzError::PolicyUnavailable;

        assert_eq!(error.to_string(), "policy source unavailable");
        assert!(!error.to_string().contains("db"));
    }

    #[test]
    fn authorizer_can_borrow_policy_source_for_secondary_registries() {
        let source = FixedPolicy(allow_read("/sys:system/sys:hostname"));
        let authz = ReadAuthorizer::new(&TestReg, &source).expect("authorizer");

        assert!(authz
            .may(&principal(), ReadAction::Read, "/sys:system/sys:hostname")
            .expect("may"));
        assert!(!authz
            .may(&principal(), ReadAction::Read, "/sys:system/sys:secret")
            .expect("may"));
    }

    #[test]
    fn policy_source_returns_shared_policy_arc() {
        let source = SharedPolicy(Arc::new(allow_read("/sys:system/sys:hostname")));
        let policy = source.active_policy("acme").expect("policy");
        let _: Arc<NacmPolicy> = policy;
    }

    #[test]
    fn read_authorizer_reuses_evaluator_cache_across_calls() {
        let authz = ReadAuthorizer::new(
            &TestReg,
            SharedPolicy(Arc::new(allow_read("/sys:system/sys:hostname"))),
        )
        .expect("authorizer");

        assert_eq!(authz.cache_hits(), 0);
        assert!(authz
            .may(&principal(), ReadAction::Read, "/sys:system/sys:hostname")
            .expect("first may"));
        assert_eq!(authz.cache_hits(), 0);
        assert!(authz
            .may(&principal(), ReadAction::Read, "/sys:system/sys:hostname")
            .expect("second may"));
        assert_eq!(authz.cache_hits(), 1);
    }

    #[test]
    fn read_authorizer_enforces_signed_group_rule_lists() {
        let authz = ReadAuthorizer::new(
            &TestReg,
            FixedPolicy(group_read("telco-reader", "/sys:system/sys:hostname")),
        )
        .expect("authorizer");

        assert!(!authz
            .may(&principal(), ReadAction::Read, "/sys:system/sys:hostname")
            .expect("principal without group must deny"));
        assert!(authz
            .may(
                &principal_with_groups(["telco-reader"]),
                ReadAction::Read,
                "/sys:system/sys:hostname"
            )
            .expect("principal with group must allow"));
    }

    #[test]
    fn config_write_authorizer_allows_matching_changed_path() {
        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_writes(
                &[NacmAction::Create, NacmAction::Update],
                "/sys:system/sys:hostname",
            )),
        )
        .expect("write authorizer");

        let path = config_path("/sys:system/sys:hostname");
        let decisions = authz
            .authorize_paths(&principal(), ConfigOperation::Patch, &[&path])
            .expect("authorize write");

        assert_eq!(
            decisions,
            vec![WritePathDecision {
                path: "/sys:system/sys:hostname".to_string(),
                action: NacmAction::Update,
                allowed: true,
            }]
        );
    }

    #[test]
    fn config_write_authorizer_requires_create_and_update_for_patch() {
        let update_only = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_write(NacmAction::Update, "/sys:system/sys:hostname")),
        )
        .expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        assert!(!update_only
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("update-only patch authorization"));

        let create_and_update = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_writes(
                &[NacmAction::Create, NacmAction::Update],
                "/sys:system/sys:hostname",
            )),
        )
        .expect("write authorizer");

        assert!(create_and_update
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("create-and-update patch authorization"));
    }

    #[test]
    fn config_write_authorizer_enforces_signed_group_rule_lists() {
        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(group_writes(
                "telco-writer",
                &[NacmAction::Create, NacmAction::Update],
                "/sys:system/sys:hostname",
            )),
        )
        .expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        assert!(!authz
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("principal without group must deny"));
        assert!(authz
            .may_write(
                &principal_with_groups(["telco-writer"]),
                ConfigOperation::Patch,
                &path
            )
            .expect("principal with group must allow"));
    }

    #[test]
    fn config_write_authorizer_evaluates_resolved_signed_groups() {
        let authz =
            ConfigWriteAuthorizer::new(&TestReg, ResolvedGroupPolicy).expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        assert!(authz
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("resolved signed group must allow"));
    }

    #[test]
    fn config_write_authorizer_uses_principal_aware_policy_source() {
        let authz =
            ConfigWriteAuthorizer::new(&TestReg, PrincipalAwarePolicy).expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        assert!(!authz
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("principal without selected policy must deny"));
        assert!(authz
            .may_write(
                &principal_with_groups(["selected"]),
                ConfigOperation::Patch,
                &path
            )
            .expect("principal-aware source must see signed groups"));
    }

    #[test]
    fn config_write_authorizer_canonicalizes_bare_paths() {
        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_writes(
                &[NacmAction::Create, NacmAction::Update],
                "/sys:system/sys:hostname",
            )),
        )
        .expect("write authorizer");

        let path = config_path("/system/hostname");

        assert!(authz
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("may write"));
    }

    #[test]
    fn config_write_authorizer_denies_unknown_path_without_echoing_keys() {
        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_write(NacmAction::Update, "/**")),
        )
        .expect("write authorizer");
        let path = config_path("/sys:system/sys:missing[sys:name='secret-supi']");

        let decisions = authz
            .authorize_paths(&principal(), ConfigOperation::Patch, &[&path])
            .expect("authorize write");

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].path, INVALID_SCHEMA_PATH);
        assert!(!decisions[0].path.contains("secret-supi"));
        assert!(!decisions[0].allowed);
    }

    #[test]
    fn config_write_authorizer_default_denies_empty_policy() {
        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(1))),
        )
        .expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        assert!(!authz
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("may write"));
    }

    #[test]
    fn config_write_actions_are_distinct_from_read_and_each_other() {
        let read_only = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_read("/sys:system/sys:hostname")),
        )
        .expect("write authorizer");
        let delete_only = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_write(NacmAction::Delete, "/sys:system/sys:hostname")),
        )
        .expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        assert!(!read_only
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("read rule must not grant write"));
        assert!(!delete_only
            .may_write(&principal(), ConfigOperation::Patch, &path)
            .expect("delete rule must not grant update"));
        assert!(delete_only
            .may_write(&principal(), ConfigOperation::Delete, &path)
            .expect("delete rule grants delete"));
    }

    #[test]
    fn config_write_authorizer_allows_empty_changed_path_batches() {
        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(1))),
        )
        .expect("write authorizer");

        let decisions = authz
            .authorize_paths(&principal(), ConfigOperation::Patch, &[])
            .expect("empty batches are no-op authorization");

        assert!(decisions.is_empty());
    }

    #[test]
    fn config_write_authorizer_surfaces_policy_unavailable_without_backend_detail() {
        let authz = ConfigWriteAuthorizer::new(&TestReg, BrokenPolicy).expect("write authorizer");
        let path = config_path("/sys:system/sys:hostname");

        let err = authz
            .authorize_paths(&principal(), ConfigOperation::Patch, &[&path])
            .expect_err("policy source unavailable");

        assert_eq!(err, AuthzError::PolicyUnavailable);
        assert_eq!(err.to_string(), "policy source unavailable");
    }

    #[test]
    fn config_write_authorizer_implements_config_bus_authorizer() {
        fn assert_config_authorizer<T: ConfigAuthorizer>(_value: &T) {}

        let authz = ConfigWriteAuthorizer::new(
            &TestReg,
            FixedPolicy(allow_write(NacmAction::Update, "/sys:system/**")),
        )
        .expect("write authorizer");

        assert_config_authorizer(&authz);
    }

    #[test]
    fn exec_authorizer_allows_matching_operation_and_denies_others() {
        let authz =
            ExecAuthorizer::new(NETCONF_MODELS, FixedPolicy(allow_exec("/nc:kill-session")))
                .expect("exec authorizer");

        assert!(authz
            .may_exec(&principal(), "/nc:kill-session")
            .expect("may exec"));
        assert!(!authz
            .may_exec(&principal(), "/nc:commit")
            .expect("may exec"));
    }

    #[test]
    fn exec_authorizer_default_denies_empty_policy() {
        let authz = ExecAuthorizer::new(
            NETCONF_MODELS,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(1))),
        )
        .expect("exec authorizer");

        assert!(!authz
            .may_exec(&principal(), "/nc:kill-session")
            .expect("may exec"));
    }

    #[test]
    fn read_rule_does_not_grant_exec() {
        let modules = netconf_module_registry();
        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/nc:kill-session", &modules).expect("pattern"),
            ))
            .build();
        let authz =
            ExecAuthorizer::new(NETCONF_MODELS, FixedPolicy(policy)).expect("exec authorizer");

        assert!(!authz
            .may_exec(&principal(), "/nc:kill-session")
            .expect("may exec"));
    }

    #[test]
    fn exec_authorizer_enforces_signed_group_rule_lists() {
        let authz = ExecAuthorizer::new(
            NETCONF_MODELS,
            FixedPolicy(group_exec("netconf-ops", "/nc:kill-session")),
        )
        .expect("exec authorizer");

        assert!(!authz
            .may_exec(&principal(), "/nc:kill-session")
            .expect("principal without group must deny"));
        assert!(authz
            .may_exec(&principal_with_groups(["netconf-ops"]), "/nc:kill-session")
            .expect("principal with group must allow"));
    }

    #[test]
    fn invalid_exec_operation_path_denies_fail_closed() {
        let authz =
            ExecAuthorizer::new(NETCONF_MODELS, FixedPolicy(allow_exec("/nc:kill-session")))
                .expect("exec authorizer");

        assert!(!authz
            .may_exec(&principal(), "/bad:kill-session")
            .expect("may exec"));
        assert!(!authz
            .may_exec(
                &principal(),
                "/nc:kill-session[nc:session-id='super-secret']"
            )
            .expect("may exec"));
    }

    #[test]
    fn exec_policy_store_error_surfaces_for_fail_closed_caller() {
        let authz = ExecAuthorizer::new(NETCONF_MODELS, BrokenPolicy).expect("exec authorizer");

        let result = authz.may_exec(&principal(), "/nc:kill-session");

        assert!(matches!(result, Err(AuthzError::PolicyUnavailable)));
    }

    #[test]
    fn exec_authorizer_rejects_invalid_module_registration() {
        static BAD_MODELS: &[ModelData] = &[ModelData {
            name: "ietf netconf",
            revision: "2011-06-01",
            namespace: "urn:ietf:params:xml:ns:netconf:base:1.0",
            prefix: "nc",
        }];

        let Err(err) = ExecAuthorizer::new(BAD_MODELS, FixedPolicy(allow_exec("/nc:kill-session")))
        else {
            panic!("invalid model should fail");
        };

        assert!(matches!(err, AuthzError::Schema(_)));
    }

    #[test]
    fn authorizers_reject_ambiguous_module_prefixes_at_startup() {
        static AMBIGUOUS_MODELS: &[ModelData] = &[
            ModelData {
                name: "module-a",
                revision: "2026-06-13",
                namespace: "urn:opc:a",
                prefix: "dup",
            },
            ModelData {
                name: "module-b",
                revision: "2026-06-13",
                namespace: "urn:opc:b",
                prefix: "dup",
            },
        ];

        let err = module_registry_from_models(AMBIGUOUS_MODELS).expect_err("ambiguous prefix");

        assert!(matches!(err, AuthzError::Schema(_)));
        assert!(err.to_string().contains("shared"));
    }
}
