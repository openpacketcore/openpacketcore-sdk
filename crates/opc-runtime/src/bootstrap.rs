//! Bootstrap — CLI/env/profile loading per RFC 008 section 13.

use crate::profile::{RuntimeMode, RuntimeProfile};
use std::sync::{Mutex, Once, OnceLock};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PanicHookMetadata {
    pub(crate) nf_kind: String,
    pub(crate) instance_id: uuid::Uuid,
}

impl PanicHookMetadata {
    pub(crate) fn from_profile(profile: &RuntimeProfile) -> Self {
        Self {
            nf_kind: profile.nf_kind.clone(),
            instance_id: profile.instance_id,
        }
    }
}

static PANIC_HOOK_METADATA: OnceLock<Mutex<PanicHookMetadata>> = OnceLock::new();
static PANIC_HOOK_INSTALL: Once = Once::new();

#[cfg(test)]
static PANIC_HOOK_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn panic_hook_test_guard() -> std::sync::MutexGuard<'static, ()> {
    PANIC_HOOK_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Errors raised while bootstrapping a CNF process (CLI/env parsing, config
/// loading, signal registration, drain-hook and budget validation).
///
/// During `Builder::build` these convert into `RuntimeError::Bootstrap`. In
/// fail-closed modes (Production, Conformance) they abort startup; Dev and
/// Lab downgrade some of them to warnings.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Command-line argument parsing failed; wraps the parser's error.
    #[error("CLI parse error: {0}")]
    Cli(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A bootstrap environment variable was missing or malformed; wraps the
    /// underlying error.
    #[error("environment error: {0}")]
    Env(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Loading the initial configuration from the bootstrap `ConfigSource`
    /// failed; wraps the underlying error.
    #[error("config error: {0}")]
    Config(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Registering an OS signal stream failed. Fatal in fail-closed modes for
    /// SIGTERM (and for SIGINT when explicitly requested); otherwise the
    /// runtime continues with a warning and without that handler.
    #[error("signal registration failed for {signal}: {source}")]
    SignalRegistration {
        /// Signal that could not be registered, e.g. `"SIGTERM"` or `"SIGINT"`.
        signal: &'static str,
        /// I/O error returned by the OS when installing the signal stream.
        #[source]
        source: std::io::Error,
    },

    /// Required security material is absent, so the process must fail closed;
    /// also raised when production mode starts without an explicit config
    /// source. The message names the missing requirement.
    #[error("security material unavailable: {0}")]
    SecurityUnavailable(String),

    /// A drain hook required by the profile (e.g. `"NrfDrainHook"` for
    /// AMF/SMF/UPF) was not registered before `Builder::build`. Fatal in
    /// fail-closed modes; logged as a warning otherwise.
    #[error("missing required drain hook: {0}")]
    MissingRequiredDrainHook(String),

    /// `RuntimeProfile`/`ResourceBudget` validation failed; the message names
    /// the offending limit and its allowed range.
    #[error("resource budget validation failed: {0}")]
    InvalidResourceBudget(String),
}

impl From<BootstrapError> for crate::task::RuntimeError {
    fn from(e: BootstrapError) -> Self {
        crate::task::RuntimeError::Bootstrap(Box::new(e))
    }
}

/// Bootstrap configuration from CLI and environment.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Profile derived from CLI/env.
    pub profile: RuntimeProfile,
    /// Admin bind address.
    pub admin_bind: String,
    /// Management bind address.
    pub management_bind: Option<String>,
    /// Config bootstrap source.
    pub config_source: ConfigSource,
    /// Tracing exporter endpoint.
    pub tracing_endpoint: Option<String>,
    /// Initial log level.
    pub log_level: String,
    /// Feature gates for explicit waivers.
    pub feature_gates: Vec<String>,
}

/// Configuration bootstrap source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Local file.
    File(String),
    /// Kubernetes configmap.
    ConfigMap,
    /// Remote server.
    Remote(String),
    /// No config (minimal mode).
    None,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            profile: RuntimeProfile::default(),
            admin_bind: "127.0.0.1:8080".to_string(),
            management_bind: None,
            config_source: ConfigSource::None,
            tracing_endpoint: None,
            log_level: "info".to_string(),
            feature_gates: Vec::new(),
        }
    }
}

impl BootstrapConfig {
    /// Bootstrap from environment variables only.
    pub fn from_env() -> Result<Self, BootstrapError> {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    fn from_env_with<F>(get_var: F) -> Result<Self, BootstrapError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config = BootstrapConfig::default();

        if let Some(nf_kind) = get_var("NF_KIND") {
            config.profile.nf_kind = nf_kind;
        }

        if let Some(instance_id) = get_var("INSTANCE_ID") {
            if let Ok(uuid) = instance_id.parse() {
                config.profile.instance_id = uuid;
            }
        }

        if let Some(mode) = get_var("RUNTIME_MODE") {
            config.profile.mode = match mode.to_lowercase().as_str() {
                "dev" => RuntimeMode::Dev,
                "lab" => RuntimeMode::Lab,
                "production" => RuntimeMode::Production,
                "conformance" => RuntimeMode::Conformance,
                "perf" => RuntimeMode::Perf,
                _ => RuntimeMode::Production,
            };
        }

        if let Some(admin_bind) = get_var("ADMIN_BIND") {
            config.admin_bind = admin_bind;
        }

        if let Some(log_level) = get_var("LOG_LEVEL") {
            config.log_level = log_level;
        }

        if let Some(config_source) = get_var("CONFIG_SOURCE") {
            config.config_source = if config_source.starts_with('/') {
                ConfigSource::File(config_source)
            } else if config_source == "configmap" {
                ConfigSource::ConfigMap
            } else if config_source.starts_with("http://") || config_source.starts_with("https://")
            {
                ConfigSource::Remote(config_source)
            } else {
                ConfigSource::None
            };
        }

        Ok(config)
    }

    /// Apply production fail-closed policy.
    pub fn apply_fail_closed(&self) -> Result<(), BootstrapError> {
        if self.profile.mode == RuntimeMode::Production {
            // In production, require explicit config source
            if self.config_source == ConfigSource::None {
                return Err(BootstrapError::SecurityUnavailable(
                    "production mode requires explicit config source".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Install the panic hook with redaction per RFC 008 section 12.1.
pub(crate) fn install_panic_hook(metadata: PanicHookMetadata) {
    update_panic_hook_metadata(metadata);

    PANIC_HOOK_INSTALL.call_once(|| {
        std::panic::set_hook(Box::new(|panic_info| {
            let location = panic_info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown".to_string());

            let raw_payload = panic_payload_message(panic_info);
            let redacted_payload = redact_panic_payload(&raw_payload);
            let current_thread = std::thread::current();
            let thread_name = current_thread.name().unwrap_or("unnamed");
            let metadata = current_panic_hook_metadata().unwrap_or(PanicHookMetadata {
                nf_kind: "unknown".to_string(),
                instance_id: uuid::Uuid::nil(),
            });

            tracing::error!(
                nf_kind = %metadata.nf_kind,
                instance_id = %metadata.instance_id,
                thread = %thread_name,
                location = %location,
                panic_payload = %redacted_payload,
                "runtime panic"
            );
        }));
    });
}

#[allow(deprecated)]
fn panic_payload_message(panic_info: &std::panic::PanicInfo<'_>) -> String {
    if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn redact_panic_payload(payload: &str) -> String {
    let payload_len = payload.chars().count();
    if payload_len == 0 {
        "panic payload redacted".to_string()
    } else {
        format!("panic payload redacted ({payload_len} chars)")
    }
}

fn update_panic_hook_metadata(metadata: PanicHookMetadata) {
    let cell = PANIC_HOOK_METADATA.get_or_init(|| Mutex::new(metadata.clone()));
    let mut guard = cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = metadata;
}

/// Returns the most recent panic-hook metadata set by [`install_panic_hook`].
///
/// **Note:** Under concurrent [`Builder::build`] calls, this reflects the _last_ caller's
/// metadata — it is best-effort diagnostics only and must not be used in production logic
/// that requires a specific runtime's identity.
pub(super) fn current_panic_hook_metadata() -> Option<PanicHookMetadata> {
    let cell = PANIC_HOOK_METADATA.get()?;
    match cell.try_lock() {
        Ok(guard) => Some(guard.clone()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config_default() {
        let config = BootstrapConfig::default();
        assert_eq!(config.profile.mode, RuntimeMode::Production);
        assert_eq!(config.admin_bind, "127.0.0.1:8080");
        assert_eq!(config.config_source, ConfigSource::None);
    }

    #[test]
    fn test_bootstrap_from_env_not_set() {
        let config = BootstrapConfig::from_env_with(|_| None).unwrap();
        assert_eq!(config.profile.nf_kind, "unknown");
        assert_eq!(config.profile.mode, RuntimeMode::Production);
    }

    #[test]
    fn test_bootstrap_from_env_mode() {
        let config = BootstrapConfig::from_env_with(|key| {
            if key == "RUNTIME_MODE" {
                Some("dev".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(config.profile.mode, RuntimeMode::Dev);
    }

    #[test]
    fn test_config_source_parsing() {
        let config = BootstrapConfig::from_env_with(|key| {
            if key == "CONFIG_SOURCE" {
                Some("/etc/config.yaml".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            config.config_source,
            ConfigSource::File("/etc/config.yaml".to_string())
        );

        let config = BootstrapConfig::from_env_with(|key| {
            if key == "CONFIG_SOURCE" {
                Some("https://config.example.com/config".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            config.config_source,
            ConfigSource::Remote("https://config.example.com/config".to_string())
        );
    }

    #[test]
    fn test_fail_closed_production() {
        let config = BootstrapConfig {
            profile: RuntimeProfile {
                mode: RuntimeMode::Production,
                ..Default::default()
            },
            config_source: ConfigSource::None,
            ..Default::default()
        };

        let result = config.apply_fail_closed();
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_closed_production_with_config() {
        let config = BootstrapConfig {
            profile: RuntimeProfile {
                mode: RuntimeMode::Production,
                ..Default::default()
            },
            config_source: ConfigSource::File("/etc/config.yaml".to_string()),
            ..Default::default()
        };

        let result = config.apply_fail_closed();
        assert!(result.is_ok());
    }

    #[test]
    fn test_redact_panic_payload_hides_raw_contents() {
        let raw = "Authorization: Bearer super-secret-token";
        let redacted = redact_panic_payload(raw);

        assert!(redacted.contains("redacted"));
        assert!(!redacted.contains("super-secret-token"));
        assert!(!redacted.contains("Authorization"));
    }

    #[test]
    fn test_bootstrap_from_env_comprehensive() {
        let uuid_str = "676a9902-cdec-4971-9a8f-cead3079bd1a";
        let valid_uuid = uuid::Uuid::parse_str(uuid_str).unwrap();

        let config = BootstrapConfig::from_env_with(|key| match key {
            "NF_KIND" => Some("upf".to_string()),
            "INSTANCE_ID" => Some(uuid_str.to_string()),
            "ADMIN_BIND" => Some("0.0.0.0:9090".to_string()),
            "LOG_LEVEL" => Some("debug".to_string()),
            "CONFIG_SOURCE" => Some("configmap".to_string()),
            _ => None,
        })
        .unwrap();

        assert_eq!(config.profile.nf_kind, "upf");
        assert_eq!(config.profile.instance_id, valid_uuid);
        assert_eq!(config.admin_bind, "0.0.0.0:9090");
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.config_source, ConfigSource::ConfigMap);

        let config_invalid_uuid = BootstrapConfig::from_env_with(|key| match key {
            "INSTANCE_ID" => Some("not-a-uuid".to_string()),
            _ => None,
        })
        .unwrap();
        assert_ne!(
            config_invalid_uuid.profile.instance_id.to_string(),
            "not-a-uuid"
        );
        assert!(!config_invalid_uuid.profile.instance_id.is_nil());

        let config_remote = BootstrapConfig::from_env_with(|key| match key {
            "CONFIG_SOURCE" => Some("https://bootstrap.example.net/config".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            config_remote.config_source,
            ConfigSource::Remote("https://bootstrap.example.net/config".to_string())
        );

        let config_lab = BootstrapConfig::from_env_with(|key| match key {
            "RUNTIME_MODE" => Some("lab".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(config_lab.profile.mode, RuntimeMode::Lab);

        let config_conformance = BootstrapConfig::from_env_with(|key| match key {
            "RUNTIME_MODE" => Some("conformance".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(config_conformance.profile.mode, RuntimeMode::Conformance);

        let config_perf = BootstrapConfig::from_env_with(|key| match key {
            "RUNTIME_MODE" => Some("perf".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(config_perf.profile.mode, RuntimeMode::Perf);

        let config_unrecognized = BootstrapConfig::from_env_with(|key| match key {
            "RUNTIME_MODE" => Some("invalid-mode-name".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(config_unrecognized.profile.mode, RuntimeMode::Production);
    }

    #[test]
    fn test_install_panic_hook_updates_metadata() {
        let _guard = panic_hook_test_guard();
        let instance_id = uuid::Uuid::new_v4();
        let metadata = PanicHookMetadata::from_profile(&RuntimeProfile {
            nf_kind: "smf".to_string(),
            instance_id,
            ..Default::default()
        });
        let expected = metadata.clone();

        install_panic_hook(metadata);

        let current = current_panic_hook_metadata().expect("panic hook metadata should exist");
        assert_eq!(current, expected);
    }
}
