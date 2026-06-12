//! Toy generated-like configuration fixture for OpenPacketCore.
//!
//! This crate demonstrates what a YANG-projection-generated root config looks
//! like: a strongly typed struct with per-field deltas, redacted secrets, and
//! a full [`OpcConfig`] implementation.
//!
//! # Redaction model
//!
//! Sensitive fields (`admin_password`, `tls_pre_shared_key`) are wrapped in
//! [`Redacted<T>`][opc_types::Redacted].  This guarantees that `Debug` and
//! `Display` never leak the inner value, and forces callers to explicitly
//! `expose()` the secret when they need the plaintext.
//!
//! # Constructing candidates
//!
//! All fields are private.  The only supported mutation path is
//! [`ToyConfig::from_previous`], which computes the actual diff and stores it
//! as `applied_deltas`.  This ensures that `validate_semantics` can enforce
//! the security-admin role only for secret-field modifications.  Direct
//! clone-and-mutate is intentionally not supported because the validator
//! cannot distinguish "changing a secret" from "carrying forward an existing
//! secret" without explicit delta metadata.

#![forbid(unsafe_code)]

use opc_config_model::{ConfigError, OpcConfig, RequestSource, ValidationContext, ValidationError};
use opc_types::{Redacted, SchemaDigest};
use std::{
    fmt,
    str::FromStr,
    sync::{Arc, OnceLock},
};

/// Fixed schema digest for the toy configuration model.
///
/// In a real generated crate this would be derived from the canonical YANG
/// module lockfile.
const TOY_SCHEMA_DIGEST: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Lazily parsed [`SchemaDigest`] so the hot path does not re-parse hex on
/// every call.
static TOY_SCHEMA_DIGEST_PARSED: OnceLock<SchemaDigest> = OnceLock::new();

/// Classification of a toy config field for redaction and policy use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToyFieldClassification {
    /// Ordinary leaf that may appear in logs and audit trails.
    Public,
    /// Sensitive leaf that must be redacted in all observability surfaces.
    Secret,
}

impl ToyFieldClassification {
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::Secret)
    }
}

/// A toy generated-like root configuration representing a simplified system
/// management model.
///
/// Demonstrates generated patterns: structured fields, optional leaves,
/// redacted secrets, and a typed delta enum.
///
/// # Equality and cloning
///
/// `PartialEq` compares only the visible configuration fields (hostname,
/// domain_name, etc.).  The transient `applied_deltas` metadata is excluded so
/// that two configs with identical visible state but different construction
/// history compare as equal.
///
/// `Clone` produces a copy with `applied_deltas` cleared to `Some([])`.  This
/// prevents stale delta metadata from propagating into published snapshots or
/// new candidates that are built by cloning a running config.  It also means
/// restored / fingerprinted configs (which are cloned during config-bus
/// restore) carry empty delta metadata and therefore pass semantic validation
/// for non-secret fields without requiring the security-admin role.
pub struct ToyConfig {
    hostname: String,
    domain_name: Option<String>,
    admin_password: Redacted<String>,
    tls_pre_shared_key: Redacted<Vec<u8>>,
    max_sessions: u32,
    enabled: bool,
    /// Transient delta metadata used by `validate_semantics` to distinguish
    /// secret-field changes from secret-field carry-forward.
    ///
    /// * `None` — fresh candidate constructed with `new()` or bare setters.
    ///   `validate_semantics` treats this as a full-replace and requires
    ///   security-admin whenever secrets are present.
    /// * `Some(deltas)` — candidate built via `from_previous`.  The validator
    ///   checks only the listed deltas for secret changes.
    ///
    /// `Clone` always resets this to `Some([])` so published snapshots do not
    /// retain stale change metadata.
    applied_deltas: Option<Arc<[ToyDelta]>>,
}

impl ToyConfig {
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            domain_name: None,
            admin_password: Redacted::new(String::new()),
            tls_pre_shared_key: Redacted::new(Vec::new()),
            max_sessions: 10,
            enabled: true,
            applied_deltas: None,
        }
    }

    // ------------------------------------------------------------------
    // Getters
    // ------------------------------------------------------------------

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn domain_name(&self) -> Option<&str> {
        self.domain_name.as_deref()
    }

    pub fn admin_password(&self) -> &Redacted<String> {
        &self.admin_password
    }

    pub fn tls_pre_shared_key(&self) -> &Redacted<Vec<u8>> {
        &self.tls_pre_shared_key
    }

    pub fn max_sessions(&self) -> u32 {
        self.max_sessions
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    // ------------------------------------------------------------------
    // Setters (for initial construction only; each resets applied_deltas)
    // ------------------------------------------------------------------

    pub fn with_domain_name(mut self, domain_name: impl Into<String>) -> Self {
        self.domain_name = Some(domain_name.into());
        self.applied_deltas = None;
        self
    }

    pub fn with_admin_password(mut self, password: impl Into<String>) -> Self {
        self.admin_password = Redacted::new(password.into());
        self.applied_deltas = None;
        self
    }

    pub fn with_tls_psk(mut self, psk: impl Into<Vec<u8>>) -> Self {
        self.tls_pre_shared_key = Redacted::new(psk.into());
        self.applied_deltas = None;
        self
    }

    pub fn with_max_sessions(mut self, max_sessions: u32) -> Self {
        self.max_sessions = max_sessions;
        self.applied_deltas = None;
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self.applied_deltas = None;
        self
    }

    /// Build a candidate configuration by applying `deltas` to `previous`.
    ///
    /// After applying the deltas, the candidate stores the *actual* diff
    /// (computed with [`OpcConfig::diff`]) as `applied_deltas`.  This guarantees
    /// that the transient metadata is consistent with the real field changes.
    pub fn from_previous(previous: &ToyConfig, deltas: Vec<ToyDelta>) -> Result<Self, ConfigError> {
        let mut candidate = previous.clone();
        // Consuming iteration avoids cloning each ToyDelta (which wraps heap-
        // allocated String/Vec fields) when apply_delta takes ownership anyway.
        for delta in deltas {
            candidate.apply_delta(delta)?;
        }
        let actual_deltas = candidate.diff(previous).map_err(|e| {
            ConfigError::new(
                "from_previous",
                format!("diff after apply: {}", e.message()),
            )
        })?;
        candidate.applied_deltas = Some(Arc::from(actual_deltas));
        Ok(candidate)
    }

    /// Return the transient delta metadata, if any.
    pub fn applied_deltas(&self) -> Option<&[ToyDelta]> {
        self.applied_deltas.as_deref()
    }
}

impl PartialEq for ToyConfig {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname
            && self.domain_name == other.domain_name
            && self.admin_password == other.admin_password
            && self.tls_pre_shared_key == other.tls_pre_shared_key
            && self.max_sessions == other.max_sessions
            && self.enabled == other.enabled
    }
}

impl Clone for ToyConfig {
    fn clone(&self) -> Self {
        Self {
            hostname: self.hostname.clone(),
            domain_name: self.domain_name.clone(),
            admin_password: self.admin_password.clone(),
            tls_pre_shared_key: self.tls_pre_shared_key.clone(),
            max_sessions: self.max_sessions,
            enabled: self.enabled,
            // Clear transient delta metadata on clone so that published
            // snapshots and direct clones do not carry stale change state.
            // This is load-bearing for correctness: restore_validation_context
            // clones stored configs before re-validation, and the empty
            // delta list lets fingerprinted startup configs with existing
            // secrets pass semantic validation without requiring the
            // security-admin role (source=StartupRecovery already exempts,
            // but Northbound-restored configs also rely on this).
            applied_deltas: Some(EMPTY_DELTAS.get_or_init(|| Arc::new([])).clone()),
        }
    }
}

impl fmt::Debug for ToyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToyConfig")
            .field("hostname", &self.hostname)
            .field("domain_name", &self.domain_name)
            .field("admin_password", &self.admin_password)
            .field("tls_pre_shared_key", &self.tls_pre_shared_key)
            .field("max_sessions", &self.max_sessions)
            .field("enabled", &self.enabled)
            .field("applied_deltas", &self.applied_deltas)
            .finish()
    }
}

/// Per-field delta emitted by [`ToyConfig::diff`] and consumed by
/// [`ToyConfig::apply_delta`].
///
/// This enum shape is representative of generated delta types: one variant
/// per mutable leaf with the new value as payload.
#[derive(Clone, Debug, PartialEq)]
pub enum ToyDelta {
    Hostname(String),
    DomainName(Option<String>),
    AdminPassword(Redacted<String>),
    TlsPreSharedKey(Redacted<Vec<u8>>),
    MaxSessions(u32),
    Enabled(bool),
}

impl ToyDelta {
    /// Canonical YANG path for the leaf this delta touches.
    pub fn yang_path(&self) -> &'static str {
        match self {
            ToyDelta::Hostname(_) => "/toy:system/toy:hostname",
            ToyDelta::DomainName(_) => "/toy:system/toy:domain-name",
            ToyDelta::AdminPassword(_) => "/toy:system/toy:admin-password",
            ToyDelta::TlsPreSharedKey(_) => "/toy:system/toy:tls-pre-shared-key",
            ToyDelta::MaxSessions(_) => "/toy:system/toy:max-sessions",
            ToyDelta::Enabled(_) => "/toy:system/toy:enabled",
        }
    }

    /// Redaction classification for the affected field.
    pub fn classification(&self) -> ToyFieldClassification {
        match self {
            ToyDelta::Hostname(_) => ToyFieldClassification::Public,
            ToyDelta::DomainName(_) => ToyFieldClassification::Public,
            ToyDelta::AdminPassword(_) => ToyFieldClassification::Secret,
            ToyDelta::TlsPreSharedKey(_) => ToyFieldClassification::Secret,
            ToyDelta::MaxSessions(_) => ToyFieldClassification::Public,
            ToyDelta::Enabled(_) => ToyFieldClassification::Public,
        }
    }

    pub fn is_secret(&self) -> bool {
        self.classification().is_secret()
    }
}

/// Shared empty delta slice used as the clone sentinel so that every
/// `ToyConfig::clone()` does not allocate a fresh empty `Vec`.
static EMPTY_DELTAS: OnceLock<Arc<[ToyDelta]>> = OnceLock::new();

impl OpcConfig for ToyConfig {
    type Delta = ToyDelta;

    fn schema_digest(&self) -> SchemaDigest {
        *TOY_SCHEMA_DIGEST_PARSED
            .get_or_init(|| SchemaDigest::from_str(TOY_SCHEMA_DIGEST).expect("static digest"))
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        let mut deltas = Vec::with_capacity(6);

        if self.hostname != previous.hostname {
            deltas.push(ToyDelta::Hostname(self.hostname.clone()));
        }
        if self.domain_name != previous.domain_name {
            deltas.push(ToyDelta::DomainName(self.domain_name.clone()));
        }
        if self.admin_password != previous.admin_password {
            deltas.push(ToyDelta::AdminPassword(self.admin_password.clone()));
        }
        if self.tls_pre_shared_key != previous.tls_pre_shared_key {
            deltas.push(ToyDelta::TlsPreSharedKey(self.tls_pre_shared_key.clone()));
        }
        if self.max_sessions != previous.max_sessions {
            deltas.push(ToyDelta::MaxSessions(self.max_sessions));
        }
        if self.enabled != previous.enabled {
            deltas.push(ToyDelta::Enabled(self.enabled));
        }

        Ok(deltas)
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<opc_config_model::YangPath>, ConfigError> {
        deltas
            .iter()
            .map(|delta| {
                opc_config_model::YangPath::new(delta.yang_path())
                    .map_err(|err| ConfigError::new("changed-path", err.message()))
            })
            .collect()
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        // Invalidate transient delta metadata so any direct mutation forces the
        // full-replace validation path (None branch in validate_semantics).
        // This closes the clone-and-mutate bypass:
        //   clone bus.load()  → applied_deltas=Some([])
        //   apply_delta(secret) → must clear metadata → None
        //   submit → validate_semantics sees None → requires security-admin.
        // Safe for from_previous(): it recomputes and overwrites applied_deltas
        // after calling apply_delta (line 186).
        self.applied_deltas = None;
        match delta {
            ToyDelta::Hostname(v) => self.hostname = v,
            ToyDelta::DomainName(v) => self.domain_name = v,
            ToyDelta::AdminPassword(v) => self.admin_password = v,
            ToyDelta::TlsPreSharedKey(v) => self.tls_pre_shared_key = v,
            ToyDelta::MaxSessions(v) => self.max_sessions = v,
            ToyDelta::Enabled(v) => self.enabled = v,
        }
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.hostname.trim().is_empty() {
            return Err(ValidationError::syntax("hostname must not be empty"));
        }
        if self.max_sessions == 0 {
            return Err(ValidationError::syntax(
                "max_sessions must be greater than 0",
            ));
        }
        Ok(())
    }

    fn validate_semantics(
        &self,
        ctx: &ValidationContext<ToyConfig>,
    ) -> Result<(), ValidationError> {
        // Startup recovery is always allowed; the persisted config was already
        // authorized when it was originally committed.
        if ctx.source == RequestSource::StartupRecovery {
            return Ok(());
        }

        // Determine whether this commit is changing a secret field.
        let secrets_changing = match self.applied_deltas() {
            // Fresh candidate (full replace, e.g. built via ToyConfig::new or
            // builder setters).  We must detect both secret additions and
            // secret removals.  Additions are caught by checking whether the
            // candidate carries non-empty secrets.  Removals are caught by
            // consulting the running config in ctx.previous:
            //   - if running had a non-empty secret AND candidate has it empty
            //     → a security-admin role is required to clear it.
            None => {
                let adding_secrets = !self.admin_password.expose().is_empty()
                    || !self.tls_pre_shared_key.expose().is_empty();
                let removing_secrets = ctx
                    .previous
                    .as_ref()
                    .map(|prev| {
                        // Secret removal = running had a non-empty secret that the
                        // candidate is clearing (leaving empty).
                        (!prev.admin_password.expose().is_empty()
                            && self.admin_password.expose().is_empty())
                            || (!prev.tls_pre_shared_key.expose().is_empty()
                                && self.tls_pre_shared_key.expose().is_empty())
                    })
                    .unwrap_or(false);
                adding_secrets || removing_secrets
            }
            // Candidate built via from_previous.  Require security-admin only
            // when the actual delta list includes a secret field.
            Some(deltas) => deltas.iter().any(|d| d.is_secret()),
        };

        if secrets_changing {
            let has_security_admin = ctx.principal.roles.iter().any(|r| r == "security-admin");
            if !has_security_admin {
                return Err(ValidationError::semantics(
                    "principal lacks security-admin role required to change secret fields",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_secrets_never_leak_in_debug() {
        let config = ToyConfig::new("router-1").with_admin_password("hunter2");
        let debug = format!("{config:?}");
        assert!(debug.contains("router-1"));
        assert!(!debug.contains("hunter2"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn syntax_rejects_empty_hostname() {
        let config = ToyConfig::new("");
        assert!(config.validate_syntax().is_err());
    }

    #[test]
    fn syntax_rejects_zero_max_sessions() {
        let config = ToyConfig::new("router-1").with_max_sessions(0);
        assert!(config.validate_syntax().is_err());
    }

    #[test]
    fn diff_emits_only_changed_fields() {
        let previous = ToyConfig::new("router-1").with_max_sessions(10);
        let current = ToyConfig::new("router-1")
            .with_max_sessions(20)
            .with_enabled(false);
        let deltas = current.diff(&previous).expect("diff");
        assert_eq!(deltas.len(), 2);
        assert!(deltas.contains(&ToyDelta::MaxSessions(20)));
        assert!(deltas.contains(&ToyDelta::Enabled(false)));
    }

    #[test]
    fn apply_delta_round_trips() {
        let mut config = ToyConfig::new("router-1");
        config
            .apply_delta(ToyDelta::Hostname("router-2".into()))
            .expect("apply");
        assert_eq!(config.hostname(), "router-2");
    }

    #[test]
    fn clone_clears_applied_deltas() {
        let prev = ToyConfig::new("router-1");
        let cand = ToyConfig::from_previous(&prev, vec![ToyDelta::Hostname("r2".into())])
            .expect("from_previous");
        assert_eq!(cand.applied_deltas().unwrap().len(), 1);

        let cloned = cand.clone();
        assert!(cloned.applied_deltas().unwrap().is_empty());
    }

    #[test]
    fn partial_eq_ignores_applied_deltas() {
        let a = ToyConfig::new("router-1").with_max_sessions(10);
        let b = ToyConfig::new("router-1").with_max_sessions(10);
        let c =
            ToyConfig::from_previous(&a, vec![ToyDelta::Hostname("router-1".into())]).expect("fp");
        assert_eq!(a, b);
        // `c` has identical visible fields but different applied_deltas;
        // PartialEq should treat them as equal.
        assert_eq!(a, c);
    }

    #[test]
    fn semantic_validation_allows_empty_secrets_without_role() {
        let config = ToyConfig::new("router-1");
        let ctx = ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal: opc_config_model::TrustedPrincipal::new(
                opc_config_model::WorkloadIdentity::Internal("system".into()),
                opc_types::TenantId::new("tenant-a").expect("tenant"),
            ),
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: None,
        };
        assert!(config.validate_semantics(&ctx).is_ok());
    }

    #[test]
    fn semantic_validation_rejects_fresh_secrets_without_security_admin() {
        let config = ToyConfig::new("router-1").with_admin_password("secret");
        let ctx = ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal: opc_config_model::TrustedPrincipal::new(
                opc_config_model::WorkloadIdentity::Internal("system".into()),
                opc_types::TenantId::new("tenant-a").expect("tenant"),
            ),
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: None,
        };
        assert!(config.validate_semantics(&ctx).is_err());
    }

    #[test]
    fn semantic_validation_allows_public_edit_while_secrets_preserved() {
        let previous = ToyConfig::new("router-1").with_admin_password("secret");
        let candidate =
            ToyConfig::from_previous(&previous, vec![ToyDelta::Hostname("router-2".into())])
                .expect("from_previous");

        let ctx = ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal: opc_config_model::TrustedPrincipal::new(
                opc_config_model::WorkloadIdentity::Internal("operator".into()),
                opc_types::TenantId::new("tenant-a").expect("tenant"),
            ),
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: None,
        };
        assert!(candidate.validate_semantics(&ctx).is_ok());
    }

    #[test]
    fn semantic_validation_rejects_secret_edit_without_security_admin() {
        let previous = ToyConfig::new("router-1").with_admin_password("secret");
        let candidate = ToyConfig::from_previous(
            &previous,
            vec![ToyDelta::AdminPassword(Redacted::new("new-secret".into()))],
        )
        .expect("from_previous");

        let ctx = ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal: opc_config_model::TrustedPrincipal::new(
                opc_config_model::WorkloadIdentity::Internal("operator".into()),
                opc_types::TenantId::new("tenant-a").expect("tenant"),
            ),
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: None,
        };
        assert!(candidate.validate_semantics(&ctx).is_err());
    }

    #[test]
    fn semantic_validation_rejects_secret_clear_without_security_admin() {
        // Simulate the round-6 attack: a fresh candidate (built via ToyConfig::new,
        // not from_previous) that clears a secret that was set in the running config.
        // With ctx.previous pointing at a config that had a non-empty secret, the
        // validator must detect the removal and demand the security-admin role.
        let previous_with_secret =
            ToyConfig::new("router-1").with_admin_password("existing-secret");
        let prev_arc = std::sync::Arc::new(previous_with_secret);

        // Fresh candidate built via ToyConfig::new (no applied_deltas), simulating
        // a northbound full-replace that omits the admin-password leaf.
        let fresh_candidate = ToyConfig::new("router-1");
        assert!(fresh_candidate.admin_password.expose().is_empty());

        let ctx = ValidationContext {
            request_id: opc_config_model::RequestId::new(),
            principal: opc_config_model::TrustedPrincipal::new(
                opc_config_model::WorkloadIdentity::Internal("operator".into()),
                opc_types::TenantId::new("tenant-a").expect("tenant"),
            ),
            transport: opc_config_model::TransportType::Internal,
            source: opc_config_model::RequestSource::Northbound,
            operation: opc_config_model::ConfigOperation::Replace,
            mode: opc_config_model::CommitMode::Commit,
            base_version: opc_types::ConfigVersion::INITIAL,
            previous: Some(prev_arc),
        };
        // Must reject: the fresh candidate is clearing a previously-set secret.
        assert!(fresh_candidate.validate_semantics(&ctx).is_err());
    }

    #[test]
    fn delta_yang_paths_are_canonical() {
        assert_eq!(
            ToyDelta::Hostname("x".into()).yang_path(),
            "/toy:system/toy:hostname"
        );
        assert_eq!(
            ToyDelta::AdminPassword(Redacted::new("x".into())).yang_path(),
            "/toy:system/toy:admin-password"
        );
    }

    #[test]
    fn delta_classifications_match_secrets() {
        assert!(!ToyDelta::Hostname("x".into()).is_secret());
        assert!(ToyDelta::AdminPassword(Redacted::new("x".into())).is_secret());
        assert!(ToyDelta::TlsPreSharedKey(Redacted::new(vec![1])).is_secret());
    }

    #[test]
    fn schema_digest_is_cached() {
        let a = ToyConfig::new("a").schema_digest();
        let b = ToyConfig::new("b").schema_digest();
        assert_eq!(a, b);
    }

    #[test]
    fn from_previous_stores_computed_deltas() {
        // ToyConfig::diff is infallible in the current implementation (field
        // comparisons only), so the error-propagation branch in from_previous
        // cannot be exercised without an error-injectable diff path.  This test
        // documents the happy-path contract: from_previous must store the
        // recomputed diff as applied_deltas so validate_semantics can audit it.
        let prev = ToyConfig::new("router-1");
        let cand = ToyConfig::from_previous(&prev, vec![ToyDelta::Hostname("r2".into())]);
        assert!(cand.is_ok());
        assert_eq!(cand.unwrap().applied_deltas().unwrap().len(), 1);
    }
}
