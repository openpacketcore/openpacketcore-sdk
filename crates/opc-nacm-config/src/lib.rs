//! Typed northbound NACM datastore model.
//!
//! `opc-nacm` evaluates compiled authorization policy. This crate models the
//! operator-facing `/nacm` datastore, validates the RFC 8341-style group and
//! rule-list structure, compiles it into [`opc_nacm::NacmPolicy`], and resolves
//! signed NACM groups for verified management principals.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use opc_config_model::{
    ConfigError, OpcConfig, ValidationContext, ValidationError, WorkloadIdentity,
    YangPath as ConfigYangPath,
};
use opc_mgmt_principal::{GrantResolutionError, SignedGrantSource, SignedPrincipalGrants};
use opc_mgmt_schema::{
    DataClass, EnumValueMeta, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
};
use opc_nacm::{
    ModuleRegistry, NacmAction, NacmEffect, NacmPolicy, NacmRule, NacmRuleList, PolicyVersion,
    YangPathPattern,
};
use opc_types::SchemaDigest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const ALL_USERS_GROUP: &str = "*";
const NACM_SCHEMA_PATH: &str = "/nacm:nacm";
const NACM_SCHEMA_DIGEST_BYTES: [u8; 32] = [
    0x6e, 0x61, 0x63, 0x6d, 0x2d, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2d, 0x76, 0x31, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2d, 0x73, 0x64, 0x6b, 0x2d, 0x6e, 0x61, 0x63, 0x6d, 0x00, 0x00, 0x00, 0x01,
];

/// Operator-facing NACM datastore rooted at `/nacm:nacm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NacmConfig {
    /// Whether NACM is enabled.
    ///
    /// OpenPacketCore keeps fail-closed semantics even when this is `false`:
    /// compilation yields an empty policy that denies by default instead of
    /// bypassing authorization.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Configured NACM groups and their signed-principal membership rules.
    #[serde(default)]
    pub groups: Vec<NacmGroup>,
    /// RFC 8341-style group-scoped rule-lists.
    #[serde(default, rename = "rule-list")]
    pub rule_lists: Vec<NacmConfigRuleList>,
}

impl NacmConfig {
    /// Creates an enabled NACM config from groups and rule-lists.
    pub fn new(groups: Vec<NacmGroup>, rule_lists: Vec<NacmConfigRuleList>) -> Self {
        Self {
            enabled: true,
            groups,
            rule_lists,
        }
    }

    /// Validates names, references, selectors, access operations, and paths.
    pub fn validate(&self) -> Result<(), NacmConfigError> {
        let group_names = validate_groups(&self.groups)?;
        validate_rule_lists(&self.rule_lists, &group_names)?;
        validate_rule_paths(&self.rule_lists)?;
        Ok(())
    }

    /// Compiles this datastore into an immutable NACM policy.
    pub fn compile_policy(&self, version: PolicyVersion) -> Result<NacmPolicy, NacmConfigError> {
        self.validate()?;
        if !self.enabled {
            return Ok(NacmPolicy::empty(version));
        }

        let mut registry = ModuleRegistry::new();
        register_builtin_modules(&mut registry)?;
        for rule_list in &self.rule_lists {
            for rule in &rule_list.rules {
                register_path_modules(&mut registry, &rule.path);
            }
        }

        let mut builder = NacmPolicy::builder(version);
        for rule_list in &self.rule_lists {
            let mut compiled_rules = Vec::new();
            for rule in &rule_list.rules {
                let path = YangPathPattern::parse(&rule.path, &registry).map_err(|source| {
                    NacmConfigError::policy(
                        "rule path",
                        format!(
                            "rule '{}' has invalid path: {}",
                            rule.name,
                            source.message()
                        ),
                    )
                })?;
                for action in rule.expanded_actions()? {
                    compiled_rules.push(NacmRule::new(action, rule.effect.into(), path.clone()));
                }
            }

            let compiled_list = NacmRuleList::new(
                rule_list.name.clone(),
                rule_list.groups.clone(),
                compiled_rules,
            )
            .map_err(|source| {
                NacmConfigError::policy(
                    "rule-list",
                    format!(
                        "rule-list '{}' failed engine validation: {}",
                        rule_list.name,
                        source.message()
                    ),
                )
            })?;
            builder = builder.add_rule_list(compiled_list);
        }

        Ok(builder.build())
    }

    fn matching_groups(&self, principal: &opc_config_model::TrustedPrincipal) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let mut groups = BTreeSet::new();
        for group in &self.groups {
            if group.matches_principal(principal) {
                groups.insert(group.name.clone());
            }
        }
        groups.into_iter().collect()
    }
}

impl Default for NacmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            groups: Vec::new(),
            rule_lists: Vec::new(),
        }
    }
}

impl SignedGrantSource for NacmConfig {
    fn signed_grants_for(
        &self,
        principal: &opc_config_model::TrustedPrincipal,
    ) -> Result<SignedPrincipalGrants, GrantResolutionError> {
        Ok(SignedPrincipalGrants::new(
            Vec::<String>::new(),
            self.matching_groups(principal),
        ))
    }
}

impl OpcConfig for NacmConfig {
    type Delta = NacmConfigDelta;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes(NACM_SCHEMA_DIGEST_BYTES)
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self == previous {
            Ok(Vec::new())
        } else {
            Ok(vec![NacmConfigDelta::Replace(self.clone())])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<ConfigYangPath>, ConfigError> {
        if deltas.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(vec![ConfigYangPath::new(NACM_SCHEMA_PATH).map_err(
                |err| ConfigError::new("nacm config", err.to_string()),
            )?])
        }
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        match delta {
            NacmConfigDelta::Replace(next) => {
                *self = next;
                Ok(())
            }
        }
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        self.validate()
            .map_err(|err| ValidationError::syntax(err.to_string()))
    }

    fn validate_semantics(&self, _ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

/// Full-replace delta for the standalone `/nacm` datastore model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NacmConfigDelta {
    /// Replace the full `/nacm:nacm` subtree.
    Replace(NacmConfig),
}

/// NACM group definition and signed-principal membership rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NacmGroup {
    /// RFC 8341 group name.
    pub name: String,
    /// Exact principal user names.
    ///
    /// SSH users use the authenticated username, SPIFFE workloads use the full
    /// `spiffe://...` URI, and internal principals use `internal:<name>`.
    #[serde(default, rename = "user-name")]
    pub user_names: Vec<String>,
    /// OpenPacketCore extension for matching verified SPIFFE workload IDs.
    #[serde(default, rename = "spiffe-selector")]
    pub spiffe_selectors: Vec<SpiffeWorkloadSelector>,
}

impl NacmGroup {
    /// Creates a group with exact user-name membership.
    pub fn new(name: impl Into<String>, user_names: Vec<String>) -> Self {
        Self {
            name: name.into(),
            user_names,
            spiffe_selectors: Vec::new(),
        }
    }

    /// Adds SPIFFE workload selectors to the group.
    pub fn with_spiffe_selectors(
        mut self,
        selectors: impl IntoIterator<Item = SpiffeWorkloadSelector>,
    ) -> Self {
        self.spiffe_selectors.extend(selectors);
        self
    }

    fn matches_principal(&self, principal: &opc_config_model::TrustedPrincipal) -> bool {
        if self
            .user_names
            .iter()
            .any(|user_name| user_name == principal_user_name(&principal.identity).as_str())
        {
            return true;
        }

        let WorkloadIdentity::Spiffe(spiffe_id) = &principal.identity else {
            return false;
        };
        let parts = SpiffeParts::from_spiffe_id(spiffe_id);
        self.spiffe_selectors
            .iter()
            .any(|selector| selector.matches(&parts, principal.tenant.as_str()))
    }
}

/// OpenPacketCore SPIFFE workload selector attached to a NACM group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SpiffeWorkloadSelector {
    /// Operator-visible selector name.
    pub name: String,
    /// SPIFFE trust domain.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "trust-domain"
    )]
    pub trust_domain: Option<String>,
    /// Tenant segment in the canonical SPIFFE path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Kubernetes namespace segment in the canonical SPIFFE path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Kubernetes service account segment in the canonical SPIFFE path.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "service-account"
    )]
    pub service_account: Option<String>,
    /// Network-function kind segment in the canonical SPIFFE path.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "nf-kind")]
    pub nf_kind: Option<String>,
    /// Workload instance segment in the canonical SPIFFE path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl SpiffeWorkloadSelector {
    /// Creates a named selector with no criteria.
    ///
    /// Callers must populate at least one criterion before validation.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            trust_domain: None,
            tenant: None,
            namespace: None,
            service_account: None,
            nf_kind: None,
            instance: None,
        }
    }

    /// Sets the SPIFFE trust domain criterion.
    pub fn trust_domain(mut self, value: impl Into<String>) -> Self {
        self.trust_domain = Some(value.into());
        self
    }

    /// Sets the tenant criterion.
    pub fn tenant(mut self, value: impl Into<String>) -> Self {
        self.tenant = Some(value.into());
        self
    }

    /// Sets the namespace criterion.
    pub fn namespace(mut self, value: impl Into<String>) -> Self {
        self.namespace = Some(value.into());
        self
    }

    /// Sets the service-account criterion.
    pub fn service_account(mut self, value: impl Into<String>) -> Self {
        self.service_account = Some(value.into());
        self
    }

    /// Sets the network-function kind criterion.
    pub fn nf_kind(mut self, value: impl Into<String>) -> Self {
        self.nf_kind = Some(value.into());
        self
    }

    /// Sets the workload instance criterion.
    pub fn instance(mut self, value: impl Into<String>) -> Self {
        self.instance = Some(value.into());
        self
    }

    fn matches(&self, parts: &SpiffeParts<'_>, principal_tenant: &str) -> bool {
        if parts.tenant != principal_tenant {
            return false;
        }

        optional_matches(self.trust_domain.as_deref(), parts.trust_domain)
            && optional_matches(self.tenant.as_deref(), parts.tenant)
            && optional_matches(self.namespace.as_deref(), parts.namespace)
            && optional_matches(self.service_account.as_deref(), parts.service_account)
            && optional_matches(self.nf_kind.as_deref(), parts.nf_kind)
            && optional_matches(self.instance.as_deref(), parts.instance)
    }
}

/// Group-scoped NACM rule-list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NacmConfigRuleList {
    /// Rule-list name.
    pub name: String,
    /// NACM groups this list applies to. The special group `*` applies to all
    /// authenticated principals.
    #[serde(default)]
    pub groups: Vec<String>,
    /// First-match rules evaluated in list order.
    #[serde(default)]
    pub rules: Vec<NacmConfigRule>,
}

impl NacmConfigRuleList {
    /// Creates a group-scoped rule-list.
    pub fn new(name: impl Into<String>, groups: Vec<String>, rules: Vec<NacmConfigRule>) -> Self {
        Self {
            name: name.into(),
            groups,
            rules,
        }
    }
}

/// Single operator-authored NACM rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NacmConfigRule {
    /// Rule name unique within its rule-list.
    pub name: String,
    /// Access operations this rule applies to.
    #[serde(default, rename = "access-operations")]
    pub access_operations: Vec<NacmAccessOperation>,
    /// Rule effect.
    pub effect: NacmConfigEffect,
    /// NACM YANG path pattern. Supports exact paths, `*`, `prefix:*`, and
    /// trailing `/**` subtree matches.
    pub path: String,
}

impl NacmConfigRule {
    /// Creates a rule from typed access operations, effect, and path pattern.
    pub fn new(
        name: impl Into<String>,
        access_operations: Vec<NacmAccessOperation>,
        effect: NacmConfigEffect,
        path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            access_operations,
            effect,
            path: path.into(),
        }
    }

    fn expanded_actions(&self) -> Result<Vec<NacmAction>, NacmConfigError> {
        if self.access_operations.is_empty() {
            return Err(NacmConfigError::invalid_field(
                "access-operations",
                format!(
                    "rule '{}' must name at least one access operation",
                    self.name
                ),
            ));
        }

        let mut actions = BTreeSet::new();
        for operation in &self.access_operations {
            match operation {
                NacmAccessOperation::All => {
                    actions.extend(NacmAction::ALL);
                }
                other => {
                    actions.insert((*other).into());
                }
            }
        }
        Ok(actions.into_iter().collect())
    }
}

/// Access operation names supported by the SDK NACM engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NacmAccessOperation {
    /// All supported operations.
    #[serde(rename = "*")]
    All,
    /// Read data.
    Read,
    /// Create data.
    Create,
    /// Update data.
    Update,
    /// Replace data.
    Replace,
    /// Delete data.
    Delete,
    /// Execute an RPC/action.
    Exec,
    /// Subscribe to notifications or telemetry.
    Subscribe,
    /// Administer security/NACM policy.
    SecurityAdmin,
    /// Request a guarded operation.
    Request,
    /// Approve a guarded operation.
    Approve,
    /// Activate a guarded operation.
    Activate,
    /// Revoke a guarded operation.
    Revoke,
}

impl From<NacmAccessOperation> for NacmAction {
    fn from(value: NacmAccessOperation) -> Self {
        match value {
            NacmAccessOperation::All => NacmAction::Read,
            NacmAccessOperation::Read => NacmAction::Read,
            NacmAccessOperation::Create => NacmAction::Create,
            NacmAccessOperation::Update => NacmAction::Update,
            NacmAccessOperation::Replace => NacmAction::Replace,
            NacmAccessOperation::Delete => NacmAction::Delete,
            NacmAccessOperation::Exec => NacmAction::Exec,
            NacmAccessOperation::Subscribe => NacmAction::Subscribe,
            NacmAccessOperation::SecurityAdmin => NacmAction::SecurityAdmin,
            NacmAccessOperation::Request => NacmAction::Request,
            NacmAccessOperation::Approve => NacmAction::Approve,
            NacmAccessOperation::Activate => NacmAction::Activate,
            NacmAccessOperation::Revoke => NacmAction::Revoke,
        }
    }
}

/// NACM rule effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NacmConfigEffect {
    /// Permit matching access.
    Allow,
    /// Deny matching access.
    Deny,
}

impl From<NacmConfigEffect> for NacmEffect {
    fn from(value: NacmConfigEffect) -> Self {
        match value {
            NacmConfigEffect::Allow => NacmEffect::Allow,
            NacmConfigEffect::Deny => NacmEffect::Deny,
        }
    }
}

/// NACM datastore validation or compile error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NacmConfigError {
    /// A field failed local validation.
    #[error("{field}: {message}")]
    InvalidField {
        /// Stable field label.
        field: &'static str,
        /// Human-readable reason.
        message: String,
    },
    /// A named list contains duplicate keys.
    #[error("duplicate {field} '{name}'")]
    DuplicateName {
        /// Duplicate field/list key label.
        field: &'static str,
        /// Duplicate name.
        name: String,
    },
    /// A rule-list references a group that is not configured.
    #[error("rule-list '{rule_list}' references unknown group '{group}'")]
    UnknownGroup {
        /// Rule-list name.
        rule_list: String,
        /// Unknown group name.
        group: String,
    },
    /// Policy compiler rejected a rule-list or rule.
    #[error("{field}: {message}")]
    Policy {
        /// Stable field label.
        field: &'static str,
        /// Human-readable reason.
        message: String,
    },
}

impl NacmConfigError {
    fn invalid_field(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            message: message.into(),
        }
    }

    fn duplicate(field: &'static str, name: impl Into<String>) -> Self {
        Self::DuplicateName {
            field,
            name: name.into(),
        }
    }

    fn policy(field: &'static str, message: impl Into<String>) -> Self {
        Self::Policy {
            field,
            message: message.into(),
        }
    }
}

/// Returns the static schema registry for the standalone `/nacm` model.
pub fn schema_registry() -> &'static dyn SchemaRegistry {
    &NACM_SCHEMA_REGISTRY
}

#[derive(Debug)]
struct NacmSchemaRegistry;

impl SchemaRegistry for NacmSchemaRegistry {
    fn schema_digest(&self) -> &'static str {
        "fnv1a64:opc-nacm-config-v1"
    }

    fn served_models(&self) -> &'static [ModelData] {
        SERVED_MODELS
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        NODES
    }

    fn origins(&self) -> &'static [OriginEntry] {
        ORIGINS
    }
}

fn default_enabled() -> bool {
    true
}

fn validate_groups(groups: &[NacmGroup]) -> Result<BTreeSet<String>, NacmConfigError> {
    let mut group_names = BTreeSet::new();
    for group in groups {
        validate_label("group name", &group.name)?;
        if group.name == ALL_USERS_GROUP {
            return Err(NacmConfigError::invalid_field(
                "group name",
                "configured groups must not use the '*' all-users sentinel",
            ));
        }
        if !group_names.insert(group.name.clone()) {
            return Err(NacmConfigError::duplicate("group", group.name.clone()));
        }

        validate_unique_values("user-name", &group.user_names)?;
        for user_name in &group.user_names {
            validate_member_value("user-name", user_name)?;
        }

        let mut selector_names = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        for selector in &group.spiffe_selectors {
            validate_label("spiffe-selector name", &selector.name)?;
            if !selector_names.insert(selector.name.clone()) {
                return Err(NacmConfigError::duplicate(
                    "spiffe-selector",
                    selector.name.clone(),
                ));
            }
            if !selectors.insert(selector.clone()) {
                return Err(NacmConfigError::duplicate(
                    "spiffe-selector",
                    selector.name.clone(),
                ));
            }
            validate_selector(selector)?;
        }
    }
    Ok(group_names)
}

fn validate_rule_lists(
    rule_lists: &[NacmConfigRuleList],
    group_names: &BTreeSet<String>,
) -> Result<(), NacmConfigError> {
    let mut list_names = BTreeSet::new();
    for rule_list in rule_lists {
        validate_label("rule-list name", &rule_list.name)?;
        if !list_names.insert(rule_list.name.clone()) {
            return Err(NacmConfigError::duplicate(
                "rule-list",
                rule_list.name.clone(),
            ));
        }
        if rule_list.groups.is_empty() {
            return Err(NacmConfigError::invalid_field(
                "rule-list groups",
                format!(
                    "rule-list '{}' must name at least one group",
                    rule_list.name
                ),
            ));
        }

        validate_unique_values("rule-list group", &rule_list.groups)?;
        for group in &rule_list.groups {
            validate_label("rule-list group", group)?;
            if group != ALL_USERS_GROUP && !group_names.contains(group) {
                return Err(NacmConfigError::UnknownGroup {
                    rule_list: rule_list.name.clone(),
                    group: group.clone(),
                });
            }
        }

        if rule_list.rules.is_empty() {
            return Err(NacmConfigError::invalid_field(
                "rule-list rules",
                format!(
                    "rule-list '{}' must contain at least one rule",
                    rule_list.name
                ),
            ));
        }

        let mut rule_names = BTreeSet::new();
        for rule in &rule_list.rules {
            validate_label("rule name", &rule.name)?;
            if !rule_names.insert(rule.name.clone()) {
                return Err(NacmConfigError::duplicate("rule", rule.name.clone()));
            }
            let expanded = rule.expanded_actions()?;
            if expanded.is_empty() {
                return Err(NacmConfigError::invalid_field(
                    "access-operations",
                    format!(
                        "rule '{}' must name at least one access operation",
                        rule.name
                    ),
                ));
            }
            validate_member_value("path", &rule.path)?;
        }
    }
    Ok(())
}

fn validate_rule_paths(rule_lists: &[NacmConfigRuleList]) -> Result<(), NacmConfigError> {
    let mut registry = ModuleRegistry::new();
    register_builtin_modules(&mut registry)?;
    for rule_list in rule_lists {
        for rule in &rule_list.rules {
            register_path_modules(&mut registry, &rule.path);
        }
    }

    for rule_list in rule_lists {
        for rule in &rule_list.rules {
            YangPathPattern::parse(&rule.path, &registry).map_err(|source| {
                NacmConfigError::policy(
                    "rule path",
                    format!(
                        "rule '{}' has invalid path: {}",
                        rule.name,
                        source.message()
                    ),
                )
            })?;
        }
    }
    Ok(())
}

fn validate_selector(selector: &SpiffeWorkloadSelector) -> Result<(), NacmConfigError> {
    let criteria = [
        ("trust-domain", selector.trust_domain.as_deref()),
        ("tenant", selector.tenant.as_deref()),
        ("namespace", selector.namespace.as_deref()),
        ("service-account", selector.service_account.as_deref()),
        ("nf-kind", selector.nf_kind.as_deref()),
        ("instance", selector.instance.as_deref()),
    ];

    if criteria.iter().all(|(_, value)| value.is_none()) {
        return Err(NacmConfigError::invalid_field(
            "spiffe-selector",
            format!(
                "selector '{}' must set at least one SPIFFE criterion",
                selector.name
            ),
        ));
    }

    for (field, value) in criteria {
        if let Some(value) = value {
            validate_member_value(field, value)?;
        }
    }
    Ok(())
}

fn validate_unique_values(field: &'static str, values: &[String]) -> Result<(), NacmConfigError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(NacmConfigError::duplicate(field, value.clone()));
        }
    }
    Ok(())
}

fn validate_label(field: &'static str, value: &str) -> Result<(), NacmConfigError> {
    validate_member_value(field, value)
}

fn validate_member_value(field: &'static str, value: &str) -> Result<(), NacmConfigError> {
    if value.is_empty() {
        return Err(NacmConfigError::invalid_field(field, "must not be empty"));
    }
    if value.trim() != value {
        return Err(NacmConfigError::invalid_field(
            field,
            "must not contain leading or trailing whitespace",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(NacmConfigError::invalid_field(
            field,
            "must not contain control characters",
        ));
    }
    Ok(())
}

fn register_builtin_modules(registry: &mut ModuleRegistry) -> Result<(), NacmConfigError> {
    registry
        .register_module("ietf-netconf-acm", "nacm")
        .map_err(|err| NacmConfigError::policy("schema module", err.message().to_owned()))?;
    registry
        .register_module("openpacketcore-nacm", "opc-nacm")
        .map_err(|err| NacmConfigError::policy("schema module", err.message().to_owned()))?;
    Ok(())
}

fn register_path_modules(registry: &mut ModuleRegistry, path: &str) {
    for segment in path.split('/') {
        if let Some((prefix, _)) = segment.split_once(':') {
            if !prefix.is_empty() && prefix != "*" && prefix != "nacm" && prefix != "opc-nacm" {
                let _ = registry.register_module(prefix, prefix);
            }
        }
    }
}

fn principal_user_name(identity: &WorkloadIdentity) -> String {
    match identity {
        WorkloadIdentity::Spiffe(spiffe_id) => spiffe_id.as_str().to_owned(),
        WorkloadIdentity::User(user) => user.clone(),
        WorkloadIdentity::Internal(name) => format!("internal:{name}"),
    }
}

fn optional_matches(expected: Option<&str>, actual: &str) -> bool {
    expected.is_none_or(|expected| expected == actual)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpiffeParts<'a> {
    trust_domain: &'a str,
    tenant: &'a str,
    namespace: &'a str,
    service_account: &'a str,
    nf_kind: &'a str,
    instance: &'a str,
}

impl<'a> SpiffeParts<'a> {
    fn from_spiffe_id(spiffe_id: &'a opc_types::SpiffeId) -> Self {
        let mut segments = spiffe_id.path().trim_start_matches('/').split('/');
        let mut first = segments
            .next()
            .expect("validated SPIFFE IDs always contain path segments");
        if first == "trust-domain" {
            first = segments
                .next()
                .expect("validated SPIFFE IDs always contain tenant after trust-domain label");
        }
        debug_assert_eq!(first, "tenant");
        let tenant = segments
            .next()
            .expect("validated SPIFFE IDs always contain tenant id");
        // Consume each fixed label segment into a binding BEFORE asserting on it.
        // `debug_assert_eq!(segments.next(), …)` elides its argument in release
        // builds, so the iterator would NOT advance there — shifting every field
        // by one (service_account would read the namespace value) and silently
        // breaking SPIFFE selector matching in production. Bind-then-assert
        // consumes identically in both profiles.
        let ns_label = segments.next();
        debug_assert_eq!(ns_label, Some("ns"));
        let namespace = segments
            .next()
            .expect("validated SPIFFE IDs always contain namespace");
        let sa_label = segments.next();
        debug_assert_eq!(sa_label, Some("sa"));
        let service_account = segments
            .next()
            .expect("validated SPIFFE IDs always contain service account");
        let nf_label = segments.next();
        debug_assert_eq!(nf_label, Some("nf"));
        let nf_kind = segments
            .next()
            .expect("validated SPIFFE IDs always contain NF kind");
        let instance_label = segments.next();
        debug_assert_eq!(instance_label, Some("instance"));
        let instance = segments
            .next()
            .expect("validated SPIFFE IDs always contain instance id");

        Self {
            trust_domain: spiffe_id.trust_domain(),
            tenant,
            namespace,
            service_account,
            nf_kind,
            instance,
        }
    }
}

static NACM_SCHEMA_REGISTRY: NacmSchemaRegistry = NacmSchemaRegistry;

const SERVED_MODELS: &[ModelData] = &[
    ModelData {
        name: "ietf-netconf-acm",
        revision: "2018-02-14",
        namespace: "urn:ietf:params:xml:ns:yang:ietf-netconf-acm",
        prefix: "nacm",
    },
    ModelData {
        name: "openpacketcore-nacm",
        revision: "2026-07-05",
        namespace: "urn:openpacketcore:params:xml:ns:yang:openpacketcore-nacm",
        prefix: "opc-nacm",
    },
];

const ORIGINS: &[OriginEntry] = &[OriginEntry {
    origin: "nacm",
    modules: &["ietf-netconf-acm", "openpacketcore-nacm"],
}];

const EFFECT_VALUES: &[EnumValueMeta] = &[
    EnumValueMeta {
        name: "allow",
        description: Some("Permit matching access."),
    },
    EnumValueMeta {
        name: "deny",
        description: Some("Deny matching access."),
    },
];

const ACCESS_OPERATION_VALUES: &[EnumValueMeta] = &[
    EnumValueMeta {
        name: "*",
        description: Some("All supported operations."),
    },
    EnumValueMeta {
        name: "activate",
        description: Some("Activate a guarded operation."),
    },
    EnumValueMeta {
        name: "approve",
        description: Some("Approve a guarded operation."),
    },
    EnumValueMeta {
        name: "create",
        description: Some("Create data."),
    },
    EnumValueMeta {
        name: "delete",
        description: Some("Delete data."),
    },
    EnumValueMeta {
        name: "exec",
        description: Some("Execute an RPC/action."),
    },
    EnumValueMeta {
        name: "read",
        description: Some("Read data."),
    },
    EnumValueMeta {
        name: "replace",
        description: Some("Replace data."),
    },
    EnumValueMeta {
        name: "request",
        description: Some("Request a guarded operation."),
    },
    EnumValueMeta {
        name: "revoke",
        description: Some("Revoke a guarded operation."),
    },
    EnumValueMeta {
        name: "security-admin",
        description: Some("Administer security policy."),
    },
    EnumValueMeta {
        name: "subscribe",
        description: Some("Subscribe to telemetry."),
    },
    EnumValueMeta {
        name: "update",
        description: Some("Update data."),
    },
];

const ROOT_CHILDREN: &[&str] = &[
    "/nacm:nacm/nacm:enable-nacm",
    "/nacm:nacm/nacm:groups",
    "/nacm:nacm/nacm:rule-list",
];
const GROUPS_CHILDREN: &[&str] = &["/nacm:nacm/nacm:groups/nacm:group"];
const GROUP_CHILDREN: &[&str] = &[
    "/nacm:nacm/nacm:groups/nacm:group/nacm:name",
    "/nacm:nacm/nacm:groups/nacm:group/nacm:user-name",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector",
];
const SPIFFE_SELECTOR_CHILDREN: &[&str] = &[
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:instance",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:name",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:namespace",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:nf-kind",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:service-account",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:tenant",
    "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:trust-domain",
];
const RULE_LIST_CHILDREN: &[&str] = &[
    "/nacm:nacm/nacm:rule-list/nacm:group",
    "/nacm:nacm/nacm:rule-list/nacm:name",
    "/nacm:nacm/nacm:rule-list/nacm:rule",
];
const RULE_CHILDREN: &[&str] = &[
    "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:access-operations",
    "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:action",
    "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:name",
    "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:path",
];
const EMPTY_CHILDREN: &[&str] = &[];
const GROUP_KEY: &[&str] = &["name"];
const RULE_LIST_KEY: &[&str] = &["name"];
const RULE_KEY: &[&str] = &["name"];
const SELECTOR_KEY: &[&str] = &["name"];
const EMPTY_KEYS: &[&str] = &[];

const NODES: &[NodeMeta] = &[
    NodeMeta {
        path: "/nacm:nacm",
        module: "ietf-netconf-acm",
        kind: NodeKind::Container,
        config: true,
        leaf_type: None,
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: ROOT_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:enable-nacm",
        module: "ietf-netconf-acm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::Boolean),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: Some("true"),
        has_default: true,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups",
        module: "ietf-netconf-acm",
        kind: NodeKind::Container,
        config: true,
        leaf_type: None,
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: GROUPS_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group",
        module: "ietf-netconf-acm",
        kind: NodeKind::List,
        config: true,
        leaf_type: None,
        key_leaves: GROUP_KEY,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: GROUP_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/nacm:name",
        module: "ietf-netconf-acm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/nacm:user-name",
        module: "ietf-netconf-acm",
        kind: NodeKind::LeafList,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector",
        module: "openpacketcore-nacm",
        kind: NodeKind::List,
        config: true,
        leaf_type: None,
        key_leaves: SELECTOR_KEY,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: SPIFFE_SELECTOR_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:instance",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:name",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:namespace",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:nf-kind",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:service-account",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:tenant",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector/opc-nacm:trust-domain",
        module: "openpacketcore-nacm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list",
        module: "ietf-netconf-acm",
        kind: NodeKind::List,
        config: true,
        leaf_type: None,
        key_leaves: RULE_LIST_KEY,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: RULE_LIST_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:group",
        module: "ietf-netconf-acm",
        kind: NodeKind::LeafList,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:name",
        module: "ietf-netconf-acm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:rule",
        module: "ietf-netconf-acm",
        kind: NodeKind::List,
        config: true,
        leaf_type: None,
        key_leaves: RULE_KEY,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: RULE_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:access-operations",
        module: "ietf-netconf-acm",
        kind: NodeKind::LeafList,
        config: true,
        leaf_type: Some(LeafType::Enumeration {
            values: ACCESS_OPERATION_VALUES,
        }),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:action",
        module: "ietf-netconf-acm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::Enumeration {
            values: EFFECT_VALUES,
        }),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:name",
        module: "ietf-netconf-acm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
    NodeMeta {
        path: "/nacm:nacm/nacm:rule-list/nacm:rule/nacm:path",
        module: "ietf-netconf-acm",
        kind: NodeKind::Leaf,
        config: true,
        leaf_type: Some(LeafType::String),
        key_leaves: EMPTY_KEYS,
        data_class: DataClass::AuditRegulated,
        default: None,
        has_default: false,
        presence: false,
        child_paths: EMPTY_CHILDREN,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::{AuthStrength, TrustedPrincipal};
    use opc_mgmt_principal::attach_signed_grants_from_source;
    use opc_mgmt_schema::check_registry;
    use opc_nacm::{NacmEvaluator, YangPath};
    use opc_types::{SpiffeId, TenantId};

    fn sample_config() -> NacmConfig {
        NacmConfig::new(
            vec![
                NacmGroup::new("ops-readers", vec!["operator@example.org".to_string()]),
                NacmGroup::new("amf-writers", Vec::new()).with_spiffe_selectors([
                    SpiffeWorkloadSelector::new("amf-service-account")
                        .trust_domain("example.org")
                        .tenant("acme")
                        .namespace("core")
                        .service_account("amf")
                        .nf_kind("amf"),
                ]),
            ],
            vec![
                NacmConfigRuleList::new(
                    "readers",
                    vec!["ops-readers".to_string()],
                    vec![NacmConfigRule::new(
                        "read-system",
                        vec![NacmAccessOperation::Read],
                        NacmConfigEffect::Allow,
                        "/sys:system/**",
                    )],
                ),
                NacmConfigRuleList::new(
                    "writers",
                    vec!["amf-writers".to_string()],
                    vec![NacmConfigRule::new(
                        "write-system",
                        vec![NacmAccessOperation::Create, NacmAccessOperation::Update],
                        NacmConfigEffect::Allow,
                        "/sys:system/sys:hostname",
                    )],
                ),
            ],
        )
    }

    fn spiffe_principal(spiffe: &str) -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::Spiffe(SpiffeId::new(spiffe).expect("valid SPIFFE ID")),
            TenantId::from_static("acme"),
        )
        .with_auth_strength(AuthStrength::MutualTls)
    }

    fn user_principal(username: &str) -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::User(username.to_string()),
            TenantId::from_static("acme"),
        )
        .with_auth_strength(AuthStrength::SshPublicKey)
    }

    fn registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry
            .register_module("sys", "sys")
            .expect("register system module");
        registry
    }

    #[test]
    fn compiles_group_scoped_rule_lists() {
        let policy = sample_config()
            .compile_policy(PolicyVersion::new(7))
            .expect("compile NACM policy");
        assert_eq!(policy.version(), PolicyVersion::new(7));
        assert_eq!(policy.rule_lists().len(), 2);
        assert_eq!(
            policy.rule_lists()[0].groups(),
            &["ops-readers".to_string()]
        );
    }

    #[test]
    fn evaluates_compiled_policy_with_signed_groups() {
        let config = sample_config();
        let principal =
            attach_signed_grants_from_source(user_principal("operator@example.org"), &config)
                .expect("attach grants");
        assert_eq!(principal.groups, vec!["ops-readers".to_string()]);

        let policy = config
            .compile_policy(PolicyVersion::new(1))
            .expect("compile policy");
        let path = YangPath::parse("/sys:system/sys:hostname", &registry()).expect("request path");
        let mut evaluator = NacmEvaluator::new();

        let read =
            evaluator.evaluate_for_groups(&policy, &path, NacmAction::Read, &principal.groups);
        let update =
            evaluator.evaluate_for_groups(&policy, &path, NacmAction::Update, &principal.groups);

        assert!(read.is_allowed());
        assert!(!update.is_allowed());
    }

    #[test]
    fn resolves_spiffe_selector_membership_from_signed_config() {
        let config = sample_config();
        let principal = attach_signed_grants_from_source(
            spiffe_principal("spiffe://example.org/tenant/acme/ns/core/sa/amf/nf/amf/instance/i1"),
            &config,
        )
        .expect("attach grants");

        assert_eq!(principal.groups, vec!["amf-writers".to_string()]);
    }

    // Regression: a selector scoped on namespace + service_account (the path
    // segments AFTER the tenant) must match a full canonical SPIFFE path in BOTH
    // debug and release. `SpiffeParts::from_spiffe_id` previously advanced the
    // path iterator inside `debug_assert_eq!(segments.next(), …)`, which is elided
    // in release — shifting service_account to read the namespace value and
    // silently denying every otherwise-authorized writer in production builds.
    // Run this under `cargo test --release` to guard the release path.
    #[test]
    fn namespace_and_service_account_scoped_selector_matches_full_path() {
        let config = NacmConfig::new(
            vec![
                NacmGroup::new("core-amf-writers", Vec::new()).with_spiffe_selectors([
                    SpiffeWorkloadSelector::new("core-amf")
                        .trust_domain("example.org")
                        .tenant("acme")
                        .namespace("core")
                        .service_account("amf"),
                ]),
            ],
            Vec::new(),
        );
        let principal = attach_signed_grants_from_source(
            spiffe_principal("spiffe://example.org/tenant/acme/ns/core/sa/amf/nf/amf/instance/i1"),
            &config,
        )
        .expect("attach grants");

        assert_eq!(
            principal.groups,
            vec!["core-amf-writers".to_string()],
            "namespace+service_account selector must resolve on a full canonical \
             SPIFFE path in release as well as debug"
        );
    }

    #[test]
    fn selector_tenant_must_match_principal_and_spiffe_path() {
        let config = sample_config();
        let principal = TrustedPrincipal::new(
            WorkloadIdentity::Spiffe(
                SpiffeId::new("spiffe://example.org/tenant/acme/ns/core/sa/amf/nf/amf/instance/i1")
                    .expect("valid SPIFFE ID"),
            ),
            TenantId::from_static("other"),
        );

        let granted = attach_signed_grants_from_source(principal, &config).expect("grants");

        assert!(granted.groups.is_empty());
    }

    #[test]
    fn selector_without_tenant_still_requires_principal_tenant_consistency() {
        let config = NacmConfig::new(
            vec![
                NacmGroup::new("amf-writers", Vec::new()).with_spiffe_selectors([
                    SpiffeWorkloadSelector::new("amf-service-account")
                        .trust_domain("example.org")
                        .namespace("core")
                        .service_account("amf"),
                ]),
            ],
            Vec::new(),
        );
        let principal = TrustedPrincipal::new(
            WorkloadIdentity::Spiffe(
                SpiffeId::new("spiffe://example.org/tenant/acme/ns/core/sa/amf/nf/amf/instance/i1")
                    .expect("valid SPIFFE ID"),
            ),
            TenantId::from_static("other"),
        );

        let granted = attach_signed_grants_from_source(principal, &config).expect("grants");

        assert!(granted.groups.is_empty());
    }

    #[test]
    fn missing_group_membership_fails_closed() {
        let config = sample_config();
        let principal =
            attach_signed_grants_from_source(user_principal("other@example.org"), &config)
                .expect("attach grants");
        let policy = config
            .compile_policy(PolicyVersion::new(1))
            .expect("compile policy");
        let path = YangPath::parse("/sys:system/sys:hostname", &registry()).expect("request path");

        let decision = NacmEvaluator::new().evaluate_for_groups(
            &policy,
            &path,
            NacmAction::Read,
            &principal.groups,
        );

        assert!(principal.groups.is_empty());
        assert!(!decision.is_allowed());
        assert_eq!(decision.matched_rule_index(), None);
    }

    #[test]
    fn disabled_config_yields_empty_default_deny_policy_and_no_grants() {
        let mut config = sample_config();
        config.enabled = false;

        let principal =
            attach_signed_grants_from_source(user_principal("operator@example.org"), &config)
                .expect("attach grants");
        let policy = config
            .compile_policy(PolicyVersion::new(1))
            .expect("compile policy");

        assert!(principal.groups.is_empty());
        assert!(policy.rule_lists().is_empty());
        assert!(policy.rules().is_empty());
    }

    #[test]
    fn wildcard_access_operation_expands_to_all_engine_actions() {
        let config = NacmConfig::new(
            vec![NacmGroup::new("everyone", Vec::new())],
            vec![NacmConfigRuleList::new(
                "all",
                vec![ALL_USERS_GROUP.to_string()],
                vec![NacmConfigRule::new(
                    "all-access",
                    vec![NacmAccessOperation::All],
                    NacmConfigEffect::Allow,
                    "/sys:system/**",
                )],
            )],
        );

        let policy = config
            .compile_policy(PolicyVersion::new(1))
            .expect("compile policy");

        assert_eq!(policy.rule_lists()[0].rules().len(), NacmAction::ALL.len());
    }

    #[test]
    fn nacm_self_admin_path_uses_builtin_prefix_without_ambiguity() {
        let config = NacmConfig::new(
            vec![NacmGroup::new("security-admins", Vec::new())],
            vec![NacmConfigRuleList::new(
                "security-admins",
                vec!["security-admins".to_string()],
                vec![NacmConfigRule::new(
                    "admin-nacm",
                    vec![NacmAccessOperation::SecurityAdmin],
                    NacmConfigEffect::Allow,
                    "/nacm:nacm/**",
                )],
            )],
        );

        let policy = config
            .compile_policy(PolicyVersion::new(1))
            .expect("compile NACM self-admin policy");

        assert_eq!(
            policy.rule_lists()[0].rules()[0].path().to_string(),
            "/ietf-netconf-acm:nacm/**"
        );
    }

    #[test]
    fn rejects_unknown_rule_list_group() {
        let config = NacmConfig::new(
            Vec::new(),
            vec![NacmConfigRuleList::new(
                "writers",
                vec!["missing".to_string()],
                vec![NacmConfigRule::new(
                    "write",
                    vec![NacmAccessOperation::Update],
                    NacmConfigEffect::Allow,
                    "/sys:system/**",
                )],
            )],
        );

        let err = config.validate().expect_err("unknown group must fail");

        assert!(matches!(err, NacmConfigError::UnknownGroup { .. }));
    }

    #[test]
    fn rejects_duplicate_group_names() {
        let config = NacmConfig::new(
            vec![
                NacmGroup::new("ops", Vec::new()),
                NacmGroup::new("ops", Vec::new()),
            ],
            Vec::new(),
        );

        let err = config.validate().expect_err("duplicate must fail");

        assert!(matches!(
            err,
            NacmConfigError::DuplicateName { field: "group", .. }
        ));
    }

    #[test]
    fn rejects_empty_selector_that_would_match_all_spiffe_ids() {
        let config = NacmConfig::new(
            vec![NacmGroup::new("ops", Vec::new())
                .with_spiffe_selectors([SpiffeWorkloadSelector::new("too-wide")])],
            Vec::new(),
        );

        let err = config.validate().expect_err("empty selector must fail");

        assert!(err.to_string().contains("at least one SPIFFE criterion"));
    }

    #[test]
    fn rejects_rule_without_access_operations() {
        let config = NacmConfig::new(
            vec![NacmGroup::new("ops", Vec::new())],
            vec![NacmConfigRuleList::new(
                "ops",
                vec!["ops".to_string()],
                vec![NacmConfigRule::new(
                    "bad",
                    Vec::new(),
                    NacmConfigEffect::Allow,
                    "/sys:system/**",
                )],
            )],
        );

        let err = config.validate().expect_err("empty operations must fail");

        assert!(err.to_string().contains("at least one access operation"));
    }

    #[test]
    fn rejects_invalid_path_during_compile() {
        let config = NacmConfig::new(
            vec![NacmGroup::new("ops", Vec::new())],
            vec![NacmConfigRuleList::new(
                "ops",
                vec!["ops".to_string()],
                vec![NacmConfigRule::new(
                    "bad-path",
                    vec![NacmAccessOperation::Read],
                    NacmConfigEffect::Allow,
                    "sys:system",
                )],
            )],
        );

        let err = config
            .compile_policy(PolicyVersion::new(1))
            .expect_err("bad path must fail");

        assert!(err.to_string().contains("paths must start with '/'"));
    }

    #[test]
    fn disabled_config_still_rejects_invalid_rule_path() {
        let mut config = NacmConfig::new(
            vec![NacmGroup::new("ops", Vec::new())],
            vec![NacmConfigRuleList::new(
                "ops",
                vec!["ops".to_string()],
                vec![NacmConfigRule::new(
                    "bad-path",
                    vec![NacmAccessOperation::Read],
                    NacmConfigEffect::Allow,
                    "sys:system",
                )],
            )],
        );
        config.enabled = false;

        let err = config
            .compile_policy(PolicyVersion::new(1))
            .expect_err("disabled bad path must still fail");

        assert!(err.to_string().contains("paths must start with '/'"));
    }

    #[test]
    fn opc_config_diff_reports_nacm_root() {
        let previous = NacmConfig::default();
        let next = sample_config();
        let deltas = next.diff(&previous).expect("diff");
        let paths = next
            .changed_paths(&previous, &deltas)
            .expect("changed paths");

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].as_str(), NACM_SCHEMA_PATH);
    }

    #[test]
    fn schema_registry_is_self_consistent_and_resolves_nacm_paths() {
        let registry = schema_registry();
        check_registry(registry.nodes()).expect("schema registry is valid");

        assert_eq!(registry.served_models().len(), 2);
        assert!(registry.is_config_path("/nacm:nacm/nacm:rule-list/nacm:rule/nacm:path"));
        assert_eq!(
            registry.key_leaves("/nacm:nacm/nacm:groups/nacm:group"),
            Some(GROUP_KEY)
        );
        assert_eq!(
            registry.key_leaves("/nacm:nacm/nacm:groups/nacm:group/opc-nacm:spiffe-selector"),
            Some(SELECTOR_KEY)
        );
    }
}
