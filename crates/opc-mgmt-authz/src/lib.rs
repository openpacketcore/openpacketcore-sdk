//! Read-side NACM authorization facade for the OpenPacketCore management plane.
//!
//! `opc-config-bus` enforces NACM on the write path, but reads from a published
//! snapshot are raw. The gNMI `Get`/`Subscribe` and NETCONF `<get>`/`<get-config>`
//! paths must authorize reads themselves, default-deny, and omit subtrees the
//! caller may not see. [`ReadAuthorizer`] is that facade: it selects the tenant's
//! active compiled NACM policy via a pluggable [`PolicySource`], maps each schema
//! path to a normalized NACM path using a [`ModuleRegistry`] built from the schema
//! registry's served models, and evaluates `read`/`subscribe` per path.
//!
//! Everything fails closed: a path that does not resolve through the schema
//! registry denies; a tenant whose policy is empty default-denies (NACM has no
//! rule -> deny); and a genuinely unavailable policy store surfaces as `Err`,
//! which the caller maps to a denied/`UNAVAILABLE` response (never an allow).
//!
//! NACM in this SDK is schema-node scoped (it collapses list instances), so this
//! facade authorizes at the schema-node level, not per list instance.
//!
//! The crate also exposes [`ExecAuthorizer`] for management RPC/action
//! execution checks such as future NETCONF `<kill-session>`. This is deliberately
//! separate from [`ReadAuthorizer`] so read paths cannot accidentally exercise
//! write/exec NACM actions.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use opc_config_model::TrustedPrincipal;
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
    fn active_policy(&self, tenant: &str) -> Result<NacmPolicy, AuthzError>;
}

impl<T> PolicySource for &T
where
    T: PolicySource + ?Sized,
{
    fn active_policy(&self, tenant: &str) -> Result<NacmPolicy, AuthzError> {
        (*self).active_policy(tenant)
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

/// Read-side NACM authorizer over a schema registry and a tenant policy source.
pub struct ReadAuthorizer<'r, P: PolicySource> {
    registry: &'r dyn SchemaRegistry,
    modules: ModuleRegistry,
    source: P,
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
        let policy = self.source.active_policy(principal.tenant.as_str())?;
        let nacm_action = action.to_nacm();
        // A fresh evaluator per call: caches within this batch and stays `&self`
        // / Send-friendly for a concurrent server.
        let mut evaluator = NacmEvaluator::new();

        let decisions = paths
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
                    Ok(parsed) => evaluator
                        .evaluate(&policy, &parsed, nacm_action)
                        .is_allowed(),
                    // Unparseable / unknown-prefix canonical path: deny.
                    Err(_) => false,
                };
                PathDecision {
                    path: schema_path,
                    allowed,
                }
            })
            .collect();
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
}

impl<P: PolicySource> ExecAuthorizer<P> {
    /// Builds an exec authorizer from the YANG modules that define the RPC/action
    /// nodes being checked.
    pub fn new(models: &[ModelData], source: P) -> Result<Self, AuthzError> {
        Ok(Self {
            modules: module_registry_from_models(models)?,
            source,
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
        let policy = self.source.active_policy(principal.tenant.as_str())?;
        let Ok(path) = YangPath::parse(operation_path, &self.modules) else {
            return Ok(false);
        };
        let mut evaluator = NacmEvaluator::new();
        Ok(evaluator
            .evaluate(&policy, &path, NacmAction::Exec)
            .is_allowed())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::{TrustedPrincipal, WorkloadIdentity};
    use opc_mgmt_schema::{DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry};
    use opc_nacm::{NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
    use opc_types::TenantId;

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
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Ok(self.0.clone())
        }
    }

    /// A policy source that always errors (store unavailable).
    struct BrokenPolicy;
    impl PolicySource for BrokenPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Err(AuthzError::PolicyUnavailable)
        }
    }

    fn principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::Internal("tester".into()),
            TenantId::from_static("acme"),
        )
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
